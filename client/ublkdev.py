from __future__ import absolute_import, print_function
import cStringIO
import ctypes
import fcntl
import os
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

    @classmethod
    def read_from(cls, fd):
        packet = cStringIO.StringIO()
        while packet.tell() < UBDHeader.size:
            packet.write(os.read(fd, UBDHeader.size - packet.tell()))
            
        msgtype, size, tag = struct.unpack(UBDHeader.format, packet.getvalue())
        
        assert size >= UBDHeader.size + UBDRequest.size, (
            "size %d is smaller than %d" %
            (size, UBDHeader.size + UBDRequest.size))
        
        packet.truncate(0)
        while packet.tell() < UBDRequest.size:
            packet.write(os.read(fd, UBDRequest.size - packet.tell()))

        n_sectors, first_sector = struct.unpack(
            UBDRequest.format, packet.getvalue())

        data_size = size - UBDHeader.size - UBDRequest.size
        packet.truncate(0)
        while packet.tell() < data_size:
            packet.write(os.read(fd, data_size - packet.tell()))

        data = packet.getvalue()
        return cls(msgtype, size, tag, n_sectors, first_sector, data)

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

    def write_to(self, fd):
        expected_size = UBDHeader.size + UBDReply.size + len(self.data)
        assert self.size == expected_size, (
            "size %d is not equal to header(%d) + reply(%d) + data(%d) "
            "sizes (%d)" % (self.size, UBDHeader.size, UBDReply.size,
            len(self.data), expected_size))

        payload = (
            struct.pack(UBDHeader.format, self.msgtype, self.size, self.tag) +
            struct.pack(UBDReply.format, self.status) +
            self.data)

        os.write(fd, payload)
        return

    def __repr__(self):
        return ("UBDReply(msgtype=%s, size=%d, tag=%d, status=%d, "
                "data=%d bytes)" % (
                    self.msgtype_map.get(self.msgtype, "%x" % self.msgtype),
                    self.size, self.tag, self.status, len(self.data)))
    
class UserBlockDevice(object):
    def __init__(self, control_endpoint="/dev/ubdctl"):
        super(UserBlockDevice, self).__init__()
        self.control = os.open(control_endpoint, os.O_RDWR | os.O_SYNC)
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
    
    def next(self):
        """
        Returns the next request on this channel.
        """
        print("next()")
        return UBDRequest.read_from(self.control)

    def reply(self, reply):
        """
        Sends the given reply to the channel.
        """
        reply.write_to(self.control)

    def __iter__(self):
        return self
    
