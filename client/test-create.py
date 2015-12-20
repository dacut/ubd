#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import sys
sys.path.append(".")

from ublkdev.ublkdev import UserBlockDevice
ubd = UserBlockDevice()
ubd.register("foo", 1024)

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
