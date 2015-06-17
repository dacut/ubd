#!/usr/bin/env python
from __future__ import absolute_import, print_function
from cStringIO import StringIO
from errno import EINVAL, EIO
from getopt import getopt, GetoptError
from os import stat
from os.path import basename, exists
from re import match
from sys import argv, exit, stderr, stdin, stdout
from traceback import print_exc
from ublkdev import (
    UserBlockDevice, UBDHeader, UBDRequest, UBDReply,
    UBD_MSGTYPE_READ_REQUEST, UBD_MSGTYPE_WRITE_REQUEST,
    UBD_MSGTYPE_DISCARD_REQUEST, UBD_MSGTYPE_READ_REPLY,
    UBD_MSGTYPE_WRITE_REPLY, UBD_MSGTYPE_DISCARD_REPLY)
    

def file_backed_server(ubd, fd, size):
    for request in ubd:
        print("Got a request: %r" % request)
        start_pos = 512 * request.first_sector
        data_size = 512 * request.n_sectors
        end_pos = start_pos + data_size
        replytype = request.msgtype | 0x80000000

        reply_size = UBDHeader.size + UBDReply.size
        
        if end_pos > size:
            reply = UBDReply(replytype, reply_size, request.tag, -EINVAL,
                             "")
        elif request.msgtype == UBD_MSGTYPE_READ_REQUEST:
            fd.seek(start_pos)
            data = StringIO()
            while data.tell() < data_size:
                data.write(fd.read(data_size - data.tell()))

            reply_size += data_size

            reply = UBDReply(replytype, reply_size, request.tag,
                             request.n_sectors, data.getvalue())
        elif request.msgtype == UBD_MSGTYPE_WRITE_REQUEST:
            fd.seek(start_pos)
            fd.write(request.data)
            reply = UBDReply(replytype, reply_size, request.tag,
                             request.n_sectors, "")
        elif request.msgtype == UBD_MSGTYPE_DISCARD_REQUEST:
            # Can't actually discard.
            reply = UBDReply(replytype, reply_size, request.tag,
                             request.n_sectors, "")
        else:
            # Unknown request
            reply = UBDReply(replytype, reply_size, request.tag, -EIO, "")

        print("Sending reply: %r" % reply)

        ubd.reply(reply)

    print("File server done")
    return

def main(args):
    name = None
    size = None
    
    try:
        opts, args = getopt(args, "hn:s:", ["help", "name=", "size="])
    except GetoptError as e:
        print(str(e), file=stderr)
        return 1
    
    for opt, value in opts:
        if opt in ("-h", "--help",):
            usage(stdout)
            return 0
        elif opt in ("-n", "--name",):
            name = value
        elif opt in ("-s", "--size",):
            size = parse_size(value)

    if len(args) == 0:
        print("Missing filename to serve data from.", file=stderr)
        usage()
        return 1

    if len(args) > 1:
        print("Unknown argument %r." % args[1], file=stderr)
        usage()
        return 1

    filename = args[0]
    if size is None:
        if not exists(filename):
            print("Backing store %s does not exist; --size must be "
                  "specified." % filename, file=stderr)
            usage()
            return 1
        size = stat(filename).st_size
        
        # Round down to nearest multiple of 512 bytes.
        size -= size % 512

    if name is None:
        name = basename(filename)

    try:
        try:
            fd = open(filename, "r+")
        except IOError:
            try:
                fd = open(filename, "w+")
                fd.truncate(size)
            except IOError as e:
                print("Unable to open %s: %s", filename, e, file=stderr)
                return 1

        ubd = UserBlockDevice()
        ubd.register(name, size / 512)
        try:
            file_backed_server(ubd, fd, size)
        except Exception as e:
            print_exc()
        finally:
            ubd.unregister()
    finally:
        fd.close()

    return 0

def usage(fd=stderr):
    fd.write("""\
Usage: test-fileserver.py [options] <filename>

Serve a UBD mount point using a file as a backing store.

Options:
    -h | --help
        Show this usage message.

    -n <name> | --name=<name>
        Use <name> as the block device name.  Defaults to the basename of the
        file backing store.

    -s <int>[kMG] | --size=<int>[kMG]
        Set the size of the backing store to the specified size.  The units are
        required.  If omitted, this defaults to the size of the file (which
        must then exist).
""")
    fd.flush()
    return

def parse_size(value):
    m = match(r"^([1-9][0-9])*\s*([kMG])$", value)
    if m is None:
        raise ValueError("Invalid size: %r" % value)

    size = int(m.group(1))
    unit = m.group(2)

    if unit == "k":
        size <<= 10
    elif unit == "M":
        size <<= 20
    elif unit == "G":
        size <<= 30

    return size
    
if __name__ == "__main__":
    exit(main(argv[1:]))
