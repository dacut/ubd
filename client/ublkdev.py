from __future__ import absolute_import, print_function
from cStringIO import StringIO
import ctypes
import fcntl
import os
import select
import struct

DISK_NAME_LEN = 32

UBD_IOCREGISTER = 0xc038bfa0
UBD_IOCUNREGISTER = 0xbfa1
UBD_IOCGETCOUNT = 0x8004bfa2
UBD_IOCDESCRIBE = 0xc040bfa3

UBD_FL_READ_ONLY = 0x00000001
UBD_FL_REMOVABLE = 0x00000002

class UBDInfo(ctypes.Structure):
    _fields_ = [
        ("ubd_name", ctypes.c_char * DISK_NAME_LEN),
        ("ubd_flags", ctypes.c_uint32),
        ("ubd_nsectors", ctypes.c_uint64),
        ("ubd_major", ctypes.c_uint32),
        ("ubd_minor", ctypes.c_uint32),
    ]

class UBDDescribe(ctypes.Structure):
    _fields_ = [
        ("ubd_index", ctypes.c_size_t),
        ("ubd_info", UBDInfo),
    ]

UBD_MSGTYPE_READ_REQUEST = 0
UBD_MSGTYPE_WRITE_REQUEST = 1
UBD_MSGTYPE_DISCARD_REQUEST = 2
UBD_MSGTYPE_READ_REPLY = 0x80000000
UBD_MSGTYPE_WRITE_REPLY = 0x80000001
UBD_MSGTYPE_DISCARD_REPLY = 0x80000002

class UBDHeader(object):
    format = "=III"
    size = struct.calcsize(format)

    msgtype_map = {
        UBD_MSGTYPE_READ_REQUEST: "UBD_MSGTYPE_READ_REQUEST",
        UBD_MSGTYPE_WRITE_REQUEST: "UBD_MSGTYPE_WRITE_REQUEST",
        UBD_MSGTYPE_DISCARD_REQUEST: "UBD_MSGTYPE_DISCARD_REQUEST",
        UBD_MSGTYPE_READ_REPLY: "UBD_MSGTYPE_READ_REPLY",
        UBD_MSGTYPE_WRITE_REPLY: "UBD_MSGTYPE_WRITE_REPLY",
        UBD_MSGTYPE_DISCARD_REPLY: "UBD_MSGTYPE_DISCARD_REPLY"
    }
    
    def __init__(self, msgtype, size, tag):
        super(UBDHeader, self).__init__()
        self.msgtype = msgtype
        self.size = size
        self.tag = tag
        return

class UBDRequest(UBDHeader):
    format = "=IQ"
    size = struct.calcsize(format)
    
    def __init__(self, msgtype, size, tag, n_sectors, first_sector, data):
        super(UBDRequest, self).__init__(msgtype, size, tag)
        self.n_sectors = n_sectors
        self.first_sector = first_sector
        self.data = data
        return

    def __repr__(self):
        return ("UBDRequest(msgtype=%s, size=%d, tag=%d, n_sectors=%d, "
                "first_sector=%d, data=%d bytes)" %
                (self.msgtype_map.get(self.msgtype, "%x" % self.msgtype),
                 self.size, self.tag, self.n_sectors, self.first_sector,
                 len(self.data)))

class UBDReply(UBDHeader):
    format = "=I"
    size = struct.calcsize(format)
    
    def __init__(self, msgtype, size, tag, status, data):
        super(UBDReply, self).__init__(msgtype, size, tag)
        self.status = status
        self.data = data
        return

    def __repr__(self):
        return ("UBDReply(msgtype=%s, size=%d, tag=%d, status=%d, "
                "data=%d bytes)" % (
                    self.msgtype_map.get(self.msgtype, "%x" % self.msgtype),
                    self.size, self.tag, self.status, len(self.data)))
    
class UserBlockDevice(object):
    def __init__(self, control_endpoint="/dev/ubdctl", buffer_size=12):
        super(UserBlockDevice, self).__init__()
        self.control = os.open(control_endpoint, os.O_RDWR | os.O_SYNC | os.O_NONBLOCK)
        self.buffer_size = buffer_size
        self.in_buffer = StringIO("")
        self.out_buffer = StringIO()
        self.in_poll = select.poll()
        self.in_poll.register(self.control, select.POLLIN)
        self.always_flush = False
        return

    def register(self, name, n_sectors, read_only=False):
        ubd_info = UBDInfo()
        ubd_info.ubd_name = name
        ubd_info.ubd_nsectors = n_sectors
        ubd_info.ubd_flags = UBD_FL_READ_ONLY if read_only else 0
        ubd_info.ubd_major = 0
        ubd_info.ubd_minor = 0

        fcntl.ioctl(self.control, UBD_IOCREGISTER, ubd_info)
        return

    def unregister(self):
        fcntl.ioctl(self.control, UBD_IOCUNREGISTER)
        return

    @property
    def count(self):
        return fcntl.ioctl(self.control, UBD_IOCGETCOUNT)
        
    def describe(self, index):
        ubd_describe = UBDDescribe()
        ubd_describe.ubd_index = index
        fcntl.ioctl(self.control, UBD_IOCDESCRIBE, ubd_describe)
        return ubd_describe.ubd_info

    def _read(self, n_bytes):
        print("_read wants %d bytes" % n_bytes)
        result = self.in_buffer.read(n_bytes)
        if len(result) < n_bytes:
            # Need more data from the driver
            if len(self.in_poll.poll(0)) == 0:
                # No data immediately available; flush the write side.
                self._flush()
            print("os.read: %d" % self.buffer_size)
            data = os.read(self.control, self.buffer_size)
            print(" -> %d" % len(data))
            self.in_buffer = StringIO(data)
            result += self.in_buffer.read(n_bytes - len(result))

        return result

    def _flush(self):
        if self.out_buffer.tell() > 0:
            os.write(self.control, self.out_buffer.getvalue())
            self.out_buffer.truncate(0)
        return

    def _write(self, data):
        self.out_buffer.write(data)
        if self.out_buffer.tell() >= self.buffer_size:
            self._flush()
        return
    
    def get_request(self):
        """
        Returns the next request on this channel.
        """
        packet = StringIO()
        while packet.tell() < UBDHeader.size:
            packet.write(self._read(UBDHeader.size - packet.tell()))
            print("1: packet size is now %d", packet.tell())
            
        msgtype, size, tag = struct.unpack(UBDHeader.format, packet.getvalue())
        
        assert size >= UBDHeader.size + UBDRequest.size, (
            "size %d is smaller than %d" %
            (size, UBDHeader.size + UBDRequest.size))
        
        packet.truncate(0)
        while packet.tell() < UBDRequest.size:
            packet.write(self._read(UBDRequest.size - packet.tell()))

        n_sectors, first_sector = struct.unpack(
            UBDRequest.format, packet.getvalue())

        data_size = size - UBDHeader.size - UBDRequest.size
        packet.truncate(0)
        while packet.tell() < data_size:
            print("Reading %d bytes for data" % (data_size - packet.tell()))
            packet.write(self._read(data_size - packet.tell()))

        data = packet.getvalue()
        return UBDRequest(msgtype, size, tag, n_sectors, first_sector, data)

    def send_reply(self, reply):
        expected_size = UBDHeader.size + UBDReply.size + len(reply.data)
        assert reply.size == expected_size, (
            "size %d is not equal to header(%d) + reply(%d) + data(%d) "
            "sizes (%d)" % (reply.size, UBDHeader.size, UBDReply.size,
            len(self.data), expected_size))

        self._write(struct.pack(UBDHeader.format, reply.msgtype, reply.size,
                                reply.tag))
        self._write(struct.pack(UBDReply.format, reply.status))
        if len(reply.data) > 0:
            self._write(reply.data)
        return

        

    def next(self):
        return self.get_request()

    def __iter__(self):
        return self
    
