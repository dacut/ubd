#!/usr/bin/env python
from __future__ import absolute_import, print_function
from errno import EIO
from getopt import getopt, GetoptError
from select import poll, POLLIN, POLLOUT
from socket import AF_INET, gaierror, socket, SOCK_STREAM
from struct import unpack
from sys import argv, exit, stderr, stdout
from traceback import print_exc
from ublkdev import UserBlockDevice

DEFAULT_PORT = 12000

def net_transfer(ubd, s):
    poller = poll()
    poller.register(ubd.control, POLLIN)
    poller.register(s, POLLIN)

    done = False

    while not done:
        result = poller.poll()
        for ifd, event in result:
            if ifd is ubd.control:
                data = ubd.read(65536)
                if len(data) == 0:
                    done = True
                else:
                    s.send(data)
            else:
                data = s.recv(65536)
                if len(data) == 0:
                    done = True
                else:
                    ubd.write(data)
                    ubd.flush()
    return

def main(args):
    port = DEFAULT_PORT
    name = None
    
    try:
        opts, args = getopt(args, "hp:n:", ["help", "port=", "name="])
    except GetoptError as e:
        print(str(e), file=stderr)
        usage()
        return 1

    for opt, value in opts:
        if opt in ("-h", "--help"):
            usage(stdout)
            return 0
        elif opt in ("-p", "--port"):
            try:
                port = int(value)
                if port <= 0 or port >= 65536:
                    raise ValueError()
            except ValueError:
                print("Invalid port %r" % port, file=stderr)
                usage()
                return 1
        elif opt in ("-n", "--name"):
            name = value

    if len(args) == 0:
        print("Server name not specified", file=stderr)
        usage()
        return 1

    if len(args) > 1:
        print("Unknown argument %r" % args[1], file=stderr)
        usage()
        return 1

    server = args[0]

    if name is None:
        name = server.split(".", 1)[0]

    s = socket(AF_INET, SOCK_STREAM)
    try:
        s.connect((server, port))
    except gaierror:
        print("Unknown server %r" % server, file=stderr)
        return 1
    except IOError as e:
        if len(e.args) > 1:
            msg = e.args[1]
        else:
            msg = str(e)
            
        print("%s: %s" % (server, msg), file=stderr)
        return 1

    # FIXME: Handle short read
    version = unpack(">I", s.recv(4))[0]
    if version != 1:
        print("Unknown server protocol %d" % version)

    # FIXME: Handle short read
    size = unpack(">Q", s.recv(8))[0]

    ubd = UserBlockDevice()
    ubd.register(name, size / 512)

    try:
        net_transfer(ubd, s)
    except Exception as e:
        print_exc()
    finally:
        ubd.unregister()
        s.close()
    return 0

def usage(fd=stderr):
    fd.write("""\
Usage: ubdnet-client [options] <server>
Provide a local block device served by a remote server.

Options:
    -h | --help
        Show this usage

    -p <port> | --port <port>
        Connect on this TCP port.  Defaults to 12000.

    -n <name> | --name <name>
        Use the specified name as the device name.
""")
    fd.flush()
    return


if __name__ == "__main__":
    exit(main(argv[1:]))
