#!/usr/bin/env python
from ublkdev import *
ubd = UserBlockDevice()
print ubd.count
ubd.register("foo", 1024)
