from __future__ import absolute_import, print_function
from cStringIO import StringIO
import ctypes
import fcntl
import logging
import os
import select
import struct
import sys
from .ioctl import _IO, _IOR, _IOW, _IOWR

log = logging.getLogger("ubddev.ubddev")

UBD_DISK_NAME_LEN = 32

UBD_FL_READ_ONLY = 0x00000001
UBD_FL_REMOVABLE = 0x00000002

class UBDInfo(ctypes.Structure):
    _fields_ = [
        ("ubd_name", ctypes.c_char * UBD_DISK_NAME_LEN),
        ("ubd_flags", ctypes.c_uint32),
        ("ubd_major", ctypes.c_uint32),
        ("ubd_nsectors", ctypes.c_uint64),
    ]

class UBDDescribe(ctypes.Structure):
    _fields_ = [
        ("ubd_index", ctypes.c_size_t),
        ("ubd_info", UBDInfo),
    ]

class UBDSectorsStatus(ctypes.Union):
    _fields_ = [
        ("ubd_nsectors", ctypes.c_uint32),
        ("ubd_status", ctypes.c_int32),
    ]

class UBDMessage(ctypes.Structure):
    _anonymous_ = ("ubd_secstat",)
    _fields_ = [
        ("ubd_msgtype", ctypes.c_uint32),
        ("ubd_tag", ctypes.c_uint32),
        ("ubd_secstat", UBDSectorsStatus),
        ("ubd_first_sector", ctypes.c_uint64),
        ("ubd_size", ctypes.c_uint32),
        ("ubd_data", ctypes.c_char_p),
    ]

    def __str__(self):
        return "[msgtype=%s tag=%d secstat=%d first=%d size=%d data=%s]" % (
            self.ubd_msgtype, self.ubd_tag, self.ubd_status,
            self.ubd_first_sector, self.ubd_size, self.ubd_data)

UBD_MSGTYPE_READ = 0
UBD_MSGTYPE_WRITE = 1
UBD_MSGTYPE_DISCARD = 2

UBD_IOC_MAGIC = 0xbf
UBD_IOCREGISTER = _IOWR(UBD_IOC_MAGIC, 0xa0, ctypes.sizeof(UBDInfo))
UBD_IOCUNREGISTER = _IOW(UBD_IOC_MAGIC, 0xa1, ctypes.sizeof(ctypes.c_int))
UBD_IOCGETCOUNT = _IOR(UBD_IOC_MAGIC, 0xa2, ctypes.sizeof(ctypes.c_int))
UBD_IOCDESCRIBE = _IOWR(UBD_IOC_MAGIC, 0xa3, ctypes.sizeof(UBDDescribe))
UBD_IOCTIE = _IOW(UBD_IOC_MAGIC, 0xa4, ctypes.sizeof(ctypes.c_int))
UBD_IOCGETREQUEST = _IOWR(UBD_IOC_MAGIC, 0xa5, ctypes.sizeof(UBDMessage))
UBD_IOCPUTREPLY = _IOW(UBD_IOC_MAGIC, 0xa6, ctypes.sizeof(UBDMessage))
UBD_IOCDEBUG = _IO(UBD_IOC_MAGIC, 0xa7)

assert UBD_IOCREGISTER == 0xc030bfa0
assert UBD_IOCUNREGISTER == 0x4004bfa1
assert UBD_IOCGETCOUNT == 0x8004bfa2
assert UBD_IOCDESCRIBE == 0xc038bfa3
assert UBD_IOCTIE == 0x4004bfa4
assert UBD_IOCGETREQUEST == 0xc028bfa5
assert UBD_IOCPUTREPLY == 0x4028bfa6

UBD_FL_READ_ONLY = 0x00000001
UBD_FL_REMOVABLE = 0x00000002

class UserBlockDevice(object):
    def __init__(self, control_endpoint="/dev/ubdctl", buffer_size=65536):
        super(UserBlockDevice, self).__init__()
        self.control = os.open(control_endpoint, os.O_RDWR | os.O_SYNC |
                               os.O_NONBLOCK)
        self.in_poll = select.poll()
        self.in_poll.register(self.control, select.POLLIN)
        return

    def register(self, name, n_sectors, read_only=False):
        ubd_info = UBDInfo()
        ubd_info.ubd_name = name
        ubd_info.ubd_nsectors = n_sectors
        ubd_info.ubd_flags = UBD_FL_READ_ONLY if read_only else 0
        ubd_info.ubd_major = 0
        ubd_info.ubd_minor = 0

        fcntl.ioctl(self.control, UBD_IOCREGISTER, ubd_info)
        return ubd_info

    def unregister(self, major):
        fcntl.ioctl(self.control, UBD_IOCUNREGISTER, major)
        return

    @property
    def count(self):
        return fcntl.ioctl(self.control, UBD_IOCGETCOUNT)
        
    def describe(self, index):
        ubd_describe = UBDDescribe()
        ubd_describe.ubd_index = index
        fcntl.ioctl(self.control, UBD_IOCDESCRIBE, ubd_describe)
        return ubd_describe.ubd_info

    def tie(self, major):
        fcntl.ioctl(self.control, UBD_IOCTIE, major)
        return

    def get_request(self, buf):
        msg = UBDMessage()
        msg.ubd_size = len(buf)
        msg.ubd_data = ctypes.cast(buf, ctypes.c_char_p)
        assert msg.ubd_size != 0
        fcntl.ioctl(self.control, UBD_IOCGETREQUEST, msg)
        return msg

    def put_reply(self, msg):
        fcntl.ioctl(self.control, UBD_IOCPUTREPLY, msg)
        return

    def debug(self):
        fcntl.ioctl(self.control, UBD_IOCDEBUG)

def unregister(args=None):
    if args is None:
        args = sys.argv[1:]

    if len(args) == 0:
        print("Usage: %s <device>" % sys.argv[0], file=sys.stderr)
        return 1

    try:
        ubd = UserBlockDevice()
    except OSError as e:
        print("Unable to open endpoint /dev/ubd: %s" % os.strerror(e.errno),
              file=sys.stderr)
        return 1

    errors = False
    for endpoint in args:
        try:
            major = os.stat(endpoint).st_rdev >> 8
            ubd.unregister(major)
        except (OSError, IOError) as e:
            print("%s: %s" % (endpoint, os.strerror(e.errno)), file=sys.stderr)
            errors = True

    return 0 if not errors else 1

def debug(args=None):
    UserBlockDevice().debug()
