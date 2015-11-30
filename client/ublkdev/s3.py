#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from base64 import b64decode, b64encode
from boto.exception import S3ResponseError
import boto.s3
from errno import EIO
from getopt import getopt, GetoptError
from json import dumps as json_dumps, loads as json_loads
from os import environ
from re import match
from six.moves.StringIO import cStringIO as StringIO
from struct import pack, unpack
from sys import argv, exit, stderr, stdin, stdout
from threading import Condition, Thread
from ublkdev import (
    UBD_MSGTYPE_READ_REQUEST, UBD_MSGTYPE_WRITE_REQUEST,
    UBD_MSGTYPE_DISCARD_REQUEST, UBD_MSGTYPE_READ_REPLY,
    UBD_MSGTYPE_WRITE_REPLY, UBD_MSGTYPE_DISCARD_REPLY,
    UBDRequest, UBDReply, UserBlockDevice)

suffix_shift = {
    'k': 10,
    'M': 20,
    'G': 30,
    'T': 40,
    'P': 50,
    'E': 60
}

class UBDS3Handler(Thread):
    def __init__(self, name, volume):
        super(UBDS3Handler, self).__init__(name=name)
        self.volume = volume
        self.bucket = volume.s3.get_bucket(volume.bucket_name)
        return

    def run(self):
        volume = self.volume

        while not volume.stop_requested:
            with volume.lock:
                try:
                    request = volume.request_queue.pop()
                except IndexError:
                    volume.lock.wait(1)
                    continue
            
            volume.handle_ubd_request(request)
        return

class UBDS3Volume(object):
    def __init__(self, bucket_name, devname, n_threads=1, **kw):
        super(UBDS3Volume, self).__init__()
        self.bucket_name = bucket_name
        self.devname = devname
        self.s3 = boto.s3.connect_to_region(region, **kw)
        self.ubd = None
        self.n_threads = n_threads

        self.block_size = None
        self.encryption = None
        self.policy = None
        self.size = None
        self.storage_class = None
        self.suffix = None

        self.request_queue = []
        self.lock = Condition()
        self.stop_requested = False
        return

    def register(self):
        """
        Register ourself with the UBD control endpoint.
        """
        self.ubd = UserBlockDevice()
        self.ubd.register(self.devname, self.size // 512)
        return

    def run(self):
        self.threads = [UBDS3Handler("handler-%d" % i, self)
                        for i in xrange(self.n_threads)]

        try:
            for thread in self.threads:
                thread.start()

            while not self.stop_requested:
                request = self.ubd.next()
                with self.lock:
                    self.request_queue.append(request)
                    self.lock.notify()
        finally:
            self.stop_requested = True
            for thread in self.threads:
                thread.join()

        return
        
    def read_volume_info(self):
        """
        Read the devname.volinfo file in the S3 bucket.
        """
        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.get_key(self.devname + ".volinfo")
        config = json_loads(key.get_contents_as_string())

        self.block_size = int(config.get("block-size", 4096))
        self.encryption = config.get("encryption")
        self.policy = config.get("policy", "private")
        self.size = int(config.get("size"))
        self.storage_class = config.get("storage_class", "standard")
        self.suffix = config.get("suffix", "." + self.devname)
        return

    def create_volume(self, block_size=4096, encryption="",
                      policy="private", size=None,
                      storage_class="standard", suffix=None):
        """
        Create the volume in the S3 bucket.
        """
        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.new_key(self.devname + ".volinfo")

        if size is None:
            raise ValueError("size must be specified")

        config = {
            'block-size': block_size,
            'policy': policy,
            'size': size,
            'storage-class': storage_class
        }

        if encryption:
            config['encryption'] = encryption

        if suffix:
            config['suffix'] = suffix

        key.set_contents_as_string(json_dumps(config))
        self.block_size = block_size
        self.encryption = encryption
        self.policy = policy
        self.size = size
        self.storage_class = storage_class
        self.suffix = suffix
        return

    def handle_ubd_request(self, bucket, req):
        """
        s3handler.handle_ubd_request(bucket, ubd_request)
        """
        req_type = req.msgtype
        reply_type = 0x80000000 | reqtype
        reply_data = ""
        offset = 512 * req.first_sector
        length = 512 * req.n_sectors
        reply_size = UBDHeader.size + UBDReply.size
        reply_status = req.n_sectors

        try:
            if req_type == UBD_MSGTYPE_READ_REQUEST:
                reply_data = self.read(bucket, offset, length)
                reply_size += length
            elif req_type == UBD_MSGTYPE_WRITE_REQUEST:
                self.write(bucket, offset, req.data)
            elif req_type == UBD_MSGTYPE_DISCARD_REQUEST:
                self.trim(bucket, offset, length)
        except OSError as e:
            reply_status = -e.errno

        reply = UBDReply(msgtype=reply_type, size=reply_size, tag=req.tag,
                         status=reply_status, data=reply_data)
        reply.write_to(self.ubd)
        return

    def read(self, bucket, offset, length):
        """
        s3handler.read(bucket, offset, length) -> str

        Read data from this volume from offset to offset + length.
        """
        start_block, start_offset = divmod(offset, self.block_size)
        end_block, end_offset = divmod(offset + length, self.block_size)

        if end_offset == 0:
            end_block -= 1
            end_offset = self.block_size

        result = StringIO()
        for block_id in xrange(start_block, end_block + 1):
            block_data = self.read_block(bucket, block_id)
            
            if block_id == start_block:
                # Trim the data to omit anything from before the start of the
                # read range.
                if block_id == end_block:
                    # And after the end, in this case.
                    result.write(block_data[start_offset:end_offset])
                else:
                    result.write(block_data[start_offset:])
            elif block_id == end_block:
                result.write(block_data[:end_offset])
            else:
                result.write(block_data)

        return result.getvalue()

    def write(self, bucket, offset, data):
        """
        s3handler.write(bucket, offset, data)

        Write data to this volume starting at offset.
        """
        start_block, start_offset = divmod(offset, self.block_size)
        end_block, end_offset = divmod(offset + len(data), self.block_size)

        if end_offset == 0:
            end_block -= 1
            end_offset = self.block_size
        
        to_write = StringIO(data)
        for block_id in xrange(start_block, end_block + 1):
            # Do we need a read-modify-write cycle?
            if ((block_id == start_block and start_offset != 0) or
                (block_id == end_block and
                 end_offset != self.block_size)):
                # Yes; get the existing data.
                block_data = self.read_block(bucket, block_id)
                    
                # Splice in the current data.
                start_pos = (0 if block_id != start_block else start_offset)
                end_pos = (self.block_size if block_id != end_block else
                           end_offset)
                splice_length = end_pos - start_pos

                spliced = to_write.read(end_pos - start_pos)
                block_data = (block_data[:start_pos] + spliced +
                              block_data[end_pos:])
            else:
                block_data = to_write.read(self.segment_size)

            self.write_block(bucket, block_id, block_data)

        return

    def trim(self, bucket, offset, length):
        """
        s3handler.trim(bucket, offset, length)

        Trim any full blocks of data from this volume starting at offset and
        extending to offset + length
        """
        start_block, start_offset = divmod(offset, self.block_size)
        end_block, end_offset = divmod(offset + len(data), self.block_size)

        if end_offset == 0:
            end_block -= 1
            end_offset = self.block_size
        
        to_write = StringIO(data)
        for block_id in xrange(start_block, end_block + 1):
            # Skip partial blocks
            if ((block_id != start_block or start_offset == 0) and
                (block_id != end_block or end_offset == self.block_size)):
                self.trim_block(bucket, block_id)

        return

    @staticmethod
    def block_to_prefix(block_index):
        """
        Convert a block index to an S3 key prefix.
        """
        return b64encode(pack("<Q", block_index))[:-1]

    @staticmethod
    def prefix_to_block(prefix):
        """
        Convert an S3 key prefix to a block index.
        """
        return unpack("<Q", b64decode(prefix + "="))[0]

    def get_key_for_block(self, bucket, block_id):
        """
        s3handler.get_key_for_block(bucket, block_id) -> key

        Return a Boto S3 key object for the given block.  The bucket must be
        a Boto S3 object; this is required for thread safety.
        """
        key_name = UBDS3Volume.prefix_to_block(block_id) + self.suffix
        return bucket.new_key(key_name)

    def read_block(self, bucket, block_id):
        """
        s3handler.read_block(bucket, block_id) -> str

        Read a block of data.  The bucket must be a Boto S3 object; this is
        required for thread safety.
        """
        key = self.get_key_for_block(bucket, block_id)

        try:
            block_data = key.read()
            if len(block_data) != self.block_size:
                raise OSError(
                    EIO, "Failed to read block %d: block truncated at %d "
                    "bytes instead of %d bytes" % (block_id, len(block_data),
                                                   self.block_size))
        except S3ResponseError as e:
            if e.status == 404:
                block_data = b"\0" * self.block_size
            else:
                raise OSError(EIO, str(e))

        return block_data

    def write_block(self, bucket, block_id, block_data):
        """
        s3handler.write_block(bucket, block_id, block_data)
        
        Write a block of data.  The bucket must be a Boto S3 object; this is
        required for thread safety.
        """
        key = self.get_key_for_block(bucket, block_id)

        if len(block_data) != self.block_size:
            raise OSError(
                EIO, "Failed to write block %d: block truncated at %d bytes "
                "instead of %d bytes" % (block_id, len(block_data),
                                         self.block_size))

        rr = (self.storage_class == 'reduced-redundancy')
        encrypt_key = (self.encryption == "sse-s3")
        
        try:
            key.set_contents_from_string(
                block_data, reduced_redundancy=rr, policy=self.policy,
                encrypt_key=encrypt_key)
        except S3ResponseError as e:
            raise OSError(EIO, str(e))

        return

    def trim_block(self, bucket, block_id):
        """
        s3handler.write_block(bucket, block_id, block_data)
        
        Trim a block of data.  The bucket must be a Boto S3 object; this is
        required for thread safety.
        """
        key = self.get_key_for_block(bucket, block_id)

        try:
            key.delete()
        except S3ResponseError as e:
            pass

        return

                

def parse_size(value, parameter_name, min=0, max=None):
    m = match(r"([0-9]+|0x[0-9a-fA-F]+)\s*"
              r"(k|kiB|M|MiB|G|GiB|T|TiB|P|PiB|E|EiB)?", value)
    if not m:
        raise GetoptError("Invalid %s value: %r" % (parameter_name, value))
    
    result = int(value[0])
    suffix = value[1][0]
    if suffix:
        result <<= suffix_shift[suffix]
    
    if min is not None and result < min:
        raise ValueError("Invalid %s value (must be at least %d): %r" %
                         (parameter_name, min, value))
    if max is not None and result > max:
        raise ValueError("Invalid %s value (cannot be greater than %d): %r" %
                         (parameter_name, max, value))

    return result

def main(args):
    bucket_name = block_size = encryption = profile = policy = region = None
    size = storage_class = suffix = None
    proxy_user = environ.get("PROXY_USER")
    proxy_password = environ.get("PROXY_PASSWORD")
    create = False
    threads = 4

    try:
        proxy_port = int(environ.get("PROXY_PORT", "0"))
    except ValueError:
        proxy_port = None

    try:
        opts, args = getopt(args, "b:B:cC:e:hp:P:r:s:S:t:",
                            ["bucket=", "block-size=", "create", "encryption=",
                             "help", "policy=", "profile=", "proxy-user=",
                             "proxy-password=", "proxy-port=", "region=",
                             "size=", "storage-class=", "suffix=", "threads="])

        for opt, value in opts:
            if opt in ("--bucket", "-b",):
                bucket_name = value
            elif opt in ("--block-size", "-B",):
                block_size = parse_size(value, "block size", min=512,
                                        max=(1<<30))
            elif opt in ("--create", "-c",):
                create = True
            elif opt in ("--encryption", "-e",):
                encryption = value
                if encryption != "sse-s3":
                    raise ValueError(
                        "Invalid encryption specification: %r" % value)
            elif opt in ("--help", "-h",):
                usage(stdout)
                return 0
            elif opt in ("--policy", "-P",):
                policy = value
                if policy not in ("private", "public-read", "public-read-write",
                                  "authenticated-read", "bucket-owner-read",
                                  "bucket-owner-full-control"):
                    raise ValueError("Invalid storage policy: %r" % policy)
            elif opt in ("--profile", "-p",):
                profile = value
            elif opt in ("--proxy-user",):
                proxy_user = value
            elif opt in ("--proxy-password",):
                proxy_password = value
            elif opt in ("--proxy-port",):
                try:
                    proxy_port = int(value)
                    if not (0 < proxy_port <= 65535):
                        raise ValueError()
                except ValueError:
                    raise ValueError("Invalid proxy port: %r" % value)
            elif opt in ("--region", "-r",):
                region = value
            elif opt in ("--size", "-s",):
                size = parse_size(value, "size", min=0, max=(1<<64))
            elif opt in ("--storage-class", "-s",):
                storage_class = value
                if storage_class not in ("standard", "reduced-redundancy",
                                         "infrequently-accessed"):
                    raise ValueError("Invalid storage class: %r" % value)
            elif opt in ("--suffix", "-S",):
                suffix = value
            elif opt in ("--threads", "-t",):
                threads = int(value)

        if bucket_name is None:
            raise GetoptErrror("--bucket-name is required")

        if not create:
            if block_size is not None:
                raise GetoptError("--block-size is valid only with --create")
            if encryption is not None:
                raise GetoptError("--encryption is valid only with --create")
            if policy is not None:
                raise GetoptError("--policy is valid only with --create")
            if size is not None:
                raise GetoptError("--size is valid only with --create")
            if storage_class is not None:
                raise GetoptError("--storage-class is valid only with --create")
            if suffix is not None:
                raise GetoptError("--suffix is valid only with --create")
        else:
            if block_size is None:
                block_size = 4096
            if policy is None:
                policy = 'private'
            if size is None:
                raise GetoptError("--size must be specified with --create")
            if storage_class is None:
                storage_class = "standard"

        if len(args) == 0:
            raise GetoptError("Missing device name")
        elif len(args) > 1:
            raise GetoptError("Unknown argument %r" % args[1])
        
        devname = args[0]
        if create and suffix is None:
            suffix = "." + devname
    except (GetoptError, ValueError) as e:
        print(str(e), file=stderr)
        usage()
        return 1

    volume = UBDS3Volume(bucket_name, devname, threads)
    if create:
        volume.create(block_size=block_size, encryption=encryption,
                      policy=policy, size=size, storage_class=storage_class,
                      suffix=suffix)
    else:
        volume.read_volume_info()

    volume.run()
    return 0

def usage(fd=stderr):
    fd.write("""\
Usage: ubds3 [options] <devname>

Create a block device backed by S3.  <devname> specifies the name of the
block device.

General options:
    --bucket <name> | -b <name>
        Use the specified S3 bucket.  This is required.

    --profile <name> | -p <name>
        Use the specified AWS profile for credentials.  This is stored in
        ~/.boto.

    --region <name> | -r <name>
        Connect to the S3 endpoint in the specified region.  This is required.

Creating a new block device:
    --create
        Required to create a new block device.  This creates an object
        in the S3 bucket named <devname>.volinfo storing the below
        configuration details.

    --encryption <policy> | -e <policy>
        Use the specified encryption policy.  Valid policies are:
           ss3-s3       S3-managed server-side encryption.

    --block-size <value>{k,M,G} | -B <value>{k,M,G}
        Use <value> as the size of block in S3.  This defaults to 4k.  The
        block size must be between 512 and 1G and must be a power of 2.
        The k, M, and G suffixes are base-2 (k == 2**10, M == 2**20,
        G == 2 ** 30).

    --policy <policy> | -p <policy>
        Use the specified ACL policy.  This defaults to 'private'.  Valid
        values are 'private', 'public-read', 'public-read-write' (DANGEROUS),
        'authenticated-read', 'bucket-owner-read', 'bucket-owner-full-control'.

    --storage-class <class> | -C <class>
        Store objects with the given storage class.  This defaults to
        'standard'.  Valid values are 'standard', 'reduced-redundancy', and
        'infrequently-accessed'.

    --size <value>{k,M,G,T,P,E} | -s <value>{k,M,G,T,P,E}
        Specifies the size of the volume.  This is required.  This must be a
        multiple of the block size; the maximum size is 16 EiB (2 ** 64 bytes).
        The suffixes are base-2.

    --suffix <string> | -S <string>
        Append the given suffix to object names.  This defaults to .<devname>.
        Object names are suffixed rather than prefixed to improve performance
        (due to the way S3 partitions the bucket keyspace).
""")

    fd.flush()

if __name__ == "__main__":
    exit(main(argv[1:]))
