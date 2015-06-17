# Userspace Block Devices

This module is to block devices what [FUSE](http://fuse.sourceforge.net/) is
to filesystems: it provides a small translation layer that redirects block
device requests to a program running in userspace.

Right now, this code is **pre-alpha** quality.  As of this writing
(June 2015), I just fumbled my way through fixing up a bunch of locking
issues and got read requests working.  My main reference for developing this
is [*Linux Device Drivers, Third Edition*](https://lwn.net/Kernel/LDD3/) --
a well written but, unfortunately, equally well-dated reference book; blog
postings by Jonathan Corbet; reading/skimming through kernel source; and
trial and error.

If this doesn't scare you off production use... well, good luck with that.

The main purpose of this module is to make it easy to experiment with ideas
for virtual block devices without having to roll your own kernel module.
Go ahead, implement your own version of RAID 0 backed by Amazon S3, a floppy
drive, and Gmail.  (I don't recommend this, but if you do get it to work,
I'd love to see the results.)


# Building and Running

Currently tested only on Ubuntu 15.04 Server, but it's straightforward:

```
cd ubd/src
make
insmod ublkdev.ko
```


# Client Programs

The client-side library is still being worked out; only Python is available
for now.  `test-fileserver.py` gives a good example of a loop driver.

The smallest "hello world" example:

```
import ublkdev

ubd = ublkdev.UserBlockDevice()
ubd.register(name="hello", size=(1<<20)) # 1 MB
for request in ubd:
    replytype = request.msgtype | 0x80000000
    replysize = ublkdev.UBDHeader.size + ublkdev.UBDReply.size

    if request.msgtype == ublkdev.UBD_MSGTYPE_READ_REQUEST:
        data = "\0" * (512 * request.n_sectors)
        replysize += len(data)
    else:
        data = ""

    ubd.reply(ublkdev.UBDReply(replytype, replysize, request.tag,
                               request.n_sectors, data)
```


# Benchmarking

Right now, excessive logging prevents any serious performance.  But if you
want a good laugh, take a look at this output -- this is on a 2013 vintage
MacBook Pro with an SSD (with VMware running Ubuntu 15.04):

```
root@ubddev:~# dd if=/dev/ubd/foo of=/dev/null
20480+0 records in
20480+0 records out
10485760 bytes (10 MB) copied, 69.6044 s, 151 kB/s
```

Again, this is hampered by tons of logging; however, even when I get around
to fixing that, don't expect any breathtaking performance here.


# License

This code is licensed under the [BSD 2-Clause
License](http://opensource.org/licenses/BSD-2-Clause).

> Copyright (c) 2010-2015, David Cuthbert
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are
> met:
>
> 1. Redistributions of source code must retain the above copyright
> notice, this list of conditions and the following disclaimer.
>
> 2. Redistributions in binary form must reproduce the above copyright
> notice, this list of conditions and the following disclaimer in the
> documentation and/or other materials provided with the distribution.
> 
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
> "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
> LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
> A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
> HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
> SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
> LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
> DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
> THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
> (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
> OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
