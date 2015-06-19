#!/usr/bin/env python
from __future__ import absolute_import, print_function
from ctypes import (
    CDLL, create_string_buffer, c_int, c_size_t, c_ssize_t, c_void_p,
    get_errno)
from ctypes.util import find_library
from errno import EIO
from getopt import getopt, GetoptError
from os import O_RDWR, O_SYNC, open as os_open
from multiprocessing import Process
from six.moves import cStringIO
from select import poll, POLLIN, POLLOUT
from socket import AF_INET, socket, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from sys import argv, exit, stderr, stdout
from ublkdev import (
    UserBlockDevice, UBDHeader, UBDRequest, UBDReply,
    UBD_MSGTYPE_READ_REQUEST, UBD_MSGTYPE_WRITE_REQUEST,
    UBD_MSGTYPE_DISCARD_REQUEST, UBD_MSGTYPE_READ_REPLY,
    UBD_MSGTYPE_WRITE_REPLY, UBD_MSGTYPE_DISCARD_REPLY)

DEFAULT_PORT = 12000
DEFAULT_BUFFER_SIZE = 65536

libc = CDLL(find_library("c"), use_errno=True)
libc.pread.argtypes = (c_int, c_void_p, c_size_t, c_ssize_t)
libc.pread.restype = c_ssize_t
libc.pwrite.argtypes = (c_int, c_void_p, c_size_t, c_ssize_t)
libc.pwrite.restype = c_ssize_t

class UBDNetServer(object):
    def __init__(self, filename, interface="", port=DEFAULT_PORT,
                 buffer_size=DEFAULT_BUFFER_SIZE):
        super(UBDNetServer, self).__init__()
        self.fd = os_open(filename, O_RDWR | O_SYNC)
        self.server = socket(AF_INET, SOCK_STREAM)
        self.server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.server.bind((interface, port))
        self.server.listen(5)
        self.buffer_size = buffer_size
        self.child_processes = []
        return

    def serve_forever(self):
        poller = poll()
        poller.register(self.server, POLLIN)

        while True:
            if len(self.child_processes) == 0:
                timeout = -1
            else:
                timeout = 1000

            print("Polling for %d ms" % timeout)
                
            ready = poller.poll(timeout)
            if len(ready):
                self.handle_client()

            still_active = []
            print("%d child processes registered" % len(self.child_processes))
            for child in self.child_processes:
                if not child.is_alive():
                    print("Child %d is dead" % child.pid)
                    child.join()
                else:
                    still_active.append(child)

            self.child_processes = still_active

    def handle_client(self):
        client, client_address = self.server.accept()
        # Client connection
        handler = UBDNetHandler(self.fd, client, client_address,
                                self.buffer_size)
        handler.start()
        self.child_processes.append(handler)
        
        client.close()
        return

    def close(self):
        self.server.close()
        for child in self.child_processes:
            child.terminate()
        return

class UBDNetHandler(Process):
    def __init__(self, fd, socket, client_address, buffer_size):
        super(UBDNetHandler, self).__init__()
        self.fd = fd
        self.socket = socket
        self.client_address = client_address
        self.in_buffer = cStringIO("")
        self.out_buffer = cStringIO()
        self.buffer_size = buffer_size
        self.in_poll = poll()
        self.in_poll.register(self.socket, POLLIN)
        self.out_poll = poll()
        self.out_poll.register(self.socket, POLLOUT)
        return

    def read(self, n_bytes):
        result = self.in_buffer.read(n_bytes)
        
        if len(result) < n_bytes:
            # Need more data from the driver
            if len(self.in_poll.poll(0)) == 0:
                # No data immediately available; flush the write side.
                self.flush()
            data = self.socket.recv(self.buffer_size)
            self.in_buffer = cStringIO(data)
            result += self.in_buffer.read(n_bytes - len(result))

        if len(result) == 0:
            raise StopIteration()
            
        return result

    def write(self, data):
        self.out_buffer.write(data)

        # Flush if we've accumulated too much data or if the socket is
        # immediately writable
        if (self.out_buffer.tell() >= self.buffer_size or
            len(self.out_poll.poll(0)) != 0):
            self.flush()
        return

    def flush(self):
        if self.out_buffer.tell() > 0:
            self.socket.send(self.out_buffer.getvalue())
            self.out_buffer.truncate(0)
        return

    def next(self):
        return UBDRequest.read_from(self)

    def __iter__(self):
        return self

    def run(self):
        for request in self:
            self.handle_request(request)

    def handle_request(self, request):
        first_sector = request.first_sector
        n_sectors = request.n_sectors
        start_pos = 512 * first_sector
        data_size = 512 * n_sectors
        end_pos = start_pos + data_size
        reply_type = request.msgtype | 0x80000000
        tag = request.tag
        

        reply_size = UBDHeader.size + UBDReply.size
        
        if request.msgtype == UBD_MSGTYPE_READ_REQUEST:
            sbuf = create_string_buffer(data_size)

            # FIXME: need to handle partial reads
            n_read = pread(self.fd, sbuf, start_pos, data_size)

            if n_read < 0:
                status = get_errno()
                reply = UBDReply(reply_type, reply_size, tag, -status, "")
            else:
                reply_size += data_size
                reply = UBDReply(
                    reply_type, reply_size, tag, n_sectors, sbuf.raw)
        elif request.msgtype == UBD_MSGTYPE_WRITE_REQUEST:
            n_written = pwrite(self.fd, request.data, start_pos, data_size)

            if n_written < 0:
                status = get_errno()
                reply = UBDReply(reply_type, reply_size, tag, -status, "")
            else:
                reply = UBDReply(reply_type, reply_size, tag, n_sectors, "")
        elif request.msgtype == UBD_MSGTYPE_DISCARD_REQUEST:
            # Can't actually discard.
            reply = UBDReply(reply_type, reply_size, tag, n_sectors, "")
        else:
            # Unknown request
            reply = UBDReply(reply_type, reply_size, tag, -EIO, "")

        reply.write_to(self)
        return

# end UBDNetHandler

def main(args):
    interface = ""
    port = DEFAULT_PORT
    buffer_size = DEFAULT_BUFFER_SIZE

    try:
        opts, args = getopt(args, "b:hi:p:",
                            ["buffer-size=", "help", "interface=", "port="])
    except GetoptError as e:
        print(str(e), file=stderr)
        usage()
        return 1

    for opt, value in opts:
        if opt in ("-b", "--buffer-size"):
            try:
                buffer_size = int(value)
                if buffer_size < 0:
                    raise ValueError()
            except ValueError:
                print("Invalid buffer size %r" % (value,), file=stderr)
                usage()
                return 1
        elif opt in ("-h", "--help"):
            usage(stdout)
            return 0
        elif opt in ("-i", "--interface"):
            interface = value
        elif opt in ("-p", "--port"):
            try:
                port = int(value)
                if port <= 0 or port >= 65536:
                    raise ValueError()
            except ValueError:
                print("Invalid port %r" % (value,), file=stderr)
                usage()
                return 1

    if len(args) == 0:
        print("Filename missing", file=stderr)
        usage()
        return 1

    if len(args) > 1:
        print("Unknown option %r" % args[1], file=stderr)
        usage()
        return 1

    filename = args[0]
    server = UBDNetServer(filename, interface, port, buffer_size)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    
    server.close()
    return 0

def usage(fd=stderr):
    fd.write("""\
Usage: ubdnet-server [options] <block-device-name>
Serve a block device over a socket.

Options:
    -b <size> | --buffer-size <size>
        Set the send/receive buffer sizes to <size>

    -h | --help
        Show this usage

    -i <ip-address> | --interface <ip-address>
        Listen on this interface.  Defaults to any address.

    -p <port> | --port <port>
        Listen on this TCP port.  Defaults to 12000.
""")
    fd.flush()
    return

if __name__ == "__main__":
    exit(main(argv[1:]))

