from __future__ import absolute_import, print_function
import ctypes
import fcntl
import os

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

class UserBlockDevice(object):
    def __init__(self, control_endpoint="/dev/ubdctl"):
        super(UserBlockDevice, self).__init__()
        self.control = open(control_endpoint, "rw")
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
    
