#!/usr/bin/env python
import sys
sys.path.append(".")

from ublkdev.ublkdev import *
ubd = UserBlockDevice()
print ubd.count
print ubd.unregister(1)
