#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from base64 import urlsafe_b64decode, urlsafe_b64encode
from boto.exception import S3ResponseError
import boto.s3
from concurrent.futures import ThreadPoolExecutor
from ctypes import create_string_buffer
from errno import EIO
from getopt import getopt, GetoptError
from json import dumps as json_dumps, loads as json_loads
import logging
from os import environ
from re import match
from six.moves import cStringIO as StringIO, range
from struct import pack, unpack
from sys import argv, exit, stderr, stdin, stdout
from threading import Condition, RLock, Thread
from time import sleep
from .ublkdev import (
    UBD_MSGTYPE_READ, UBD_MSGTYPE_WRITE, UBD_MSGTYPE_DISCARD,
    UBDMessage, UserBlockDevice)

suffix_shift = {
    'k': 10,
    'M': 20,
    'G': 30,
    'T': 40,
    'P': 50,
    'E': 60
}

log_format = ("%(threadName)s %(asctime)s %(filename)s:%(lineno)d "
              "[%(levelname)s]: %(message)s")

class UBDS3Handler(Thread):
    def __init__(self, name, volume):
        super(UBDS3Handler, self).__init__(name=name)
        self.volume = volume
        self.ubd = UserBlockDevice()
        self.ubd.tie(volume.major)
        self.buffer = create_string_buffer(4 << 20)
        return

    def run(self):
        volume = self.volume

        while not volume.stop_requested:
            ready_list = self.ubd.in_poll.poll(100)
            if ready_list:
                request = self.ubd.get_request(self.buffer)
                self.handle_ubd_request(request, self.buffer)
        return

    def handle_ubd_request(self, msg, buf):
        """
        s3handler.handle_ubd_request(ubd_request, buffer)
        """
        req_type = msg.ubd_msgtype
        req_tag = msg.ubd_tag
        offset = 512 * msg.ubd_first_sector
        length = 512 * msg.ubd_nsectors

        try:
            if req_type == UBD_MSGTYPE_READ:
                buf[:length] = self.volume.read(offset, length)
                msg.ubd_size = length
                msg.ubd_status = length
            elif req_type == UBD_MSGTYPE_WRITE:
                self.volume.write(offset, buf.raw[:length])
                msg.ubd_size = 0
                msg.ubd_status = length
            elif req_type == UBD_MSGTYPE_DISCARD:
                self.volume.trim(offset, length)
                msg.ubd_size = 0
                msg.ubd_status = length
        except OSError as e:
            reply_status = -e.errno

        self.ubd.put_reply(msg)
        return
# end UBDS3Handler

class S3Pool(object):
    def __init__(self, region, size, bucket_name, s3_kw={}):
        super(S3Pool, self).__init__()
        conns = [boto.s3.connect_to_region(region, **s3_kw)
                 for i in range(size)]
        if [conn for conn in conns if conn is None]:
            raise RuntimeError("Failed to connect to S3 region %r" % region)
        self.connections = [
            S3PoolConnection(self, conn, bucket_name) for conn in conns]
        self.lock = Condition()
        return

    def get_connection(self, timeout=None):
        with self.lock:
            while True:
                try:
                    return self.connections.pop()
                except IndexError:
                    self.lock.wait(timeout)
    
    def return_connection(self, conn):
        with self.lock:
            self.connections.append(conn)
            self.lock.notify()

class S3PoolConnection(object):
    def __init__(self, pool, s3, bucket_name):
        super(S3PoolConnection, self).__init__()
        self.pool = pool
        self.s3 = s3
        self.bucket = self.s3.get_bucket(bucket_name)
        return

    def __getattr__(self, name):
        return getattr(self.s3, name)
    
    def __setattr__(self, name, value):
        if name in ('pool', 's3', 'bucket'):
            self.__dict__[name] = value
        else:
            setattr(self.s3, name, value)

    def __delattr__(self, name):
        if name in ('pool', 's3', 'bucket'):
            del self.__dict__[name]
        else:
            return delattr(self.s3, name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.pool.return_connection(self)
        
class UBDS3Volume(object):
    """
    A userspace block driver volume handler for S3-backed volumes.
    """
    def __init__(self, bucket_name, devname, region, thread_count=1, s3_kw={}):
        """
        UBDS3Volume(bucket_name, devname, region, thread_count=1, s3_kw={})
              
        Create a new UBDS3Volume object.
        """
        super(UBDS3Volume, self).__init__()
        self.bucket_name = bucket_name
        self.devname = devname
        self.region = region
        self.ubd = None
        self.thread_count = thread_count
        self.block_size = None
        self.encryption = None
        self.policy = None
        self.size = None
        self.storage_class = None
        self.suffix = None

        self.stop_requested = False

        self.s3_pool = S3Pool(region, thread_count, bucket_name, s3_kw)
        return

    def register(self):
        """
        Register ourself with the UBD control endpoint.
        """
        n_sectors = self.size // 512

        log.info("Registering with UBD control endpoint as %r with %d sectors",
                 self.devname, n_sectors)

        self.ubd = UserBlockDevice()
        info = self.ubd.register(self.devname, n_sectors)
        self.major = info.ubd_major
        return

    def run(self):
        self.threads = [UBDS3Handler("handler-%d" % i, self)
                        for i in range(self.thread_count)]

        try:
            for thread in self.threads:
                log.debug("Starting thread %s", thread.name)
                thread.start()

            while not self.stop_requested:
                sleep(30)
        finally:
            log.debug("Stop requested.")
            self.stop_requested = True
            for thread in self.threads:
                thread.join()

        return
        
    def read_volume_info(self):
        """
        Read the devname.volinfo file in the S3 bucket.
        """
        with self.s3_pool.get_connection() as s3:
            bucket = s3.get_bucket(self.bucket_name)
            key = bucket.get_key(self.devname + ".volinfo")
            config = json_loads(key.get_contents_as_string())

            self.block_size = int(config.get("block-size", 4096))
            self.encryption = config.get("encryption")
            self.policy = config.get("policy", "private")
            self.size = int(config.get("size"))
            self.storage_class = config.get("storage-class", "standard")
            self.suffix = config.get("suffix", "." + self.devname)

        return

    def create_volume(self, block_size=4096, encryption="",
                      policy="private", size=None,
                      storage_class="standard", suffix=None):
        """
        Create the volume in the S3 bucket.
        """
        with self.s3_pool.get_connection() as s3:
            bucket = s3.get_bucket(self.bucket_name)
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

            key.set_contents_from_string(
                json_dumps(config), policy=self.policy)
            self.block_size = block_size
            self.encryption = encryption
            self.policy = policy
            self.size = size
            self.storage_class = storage_class
            self.suffix = suffix

        return

    def read(self, offset, length):
        """
        s3handler.read(offset, length) -> str

        Read data from this volume from offset to offset + length.
        """
        start_block, start_offset = divmod(offset, self.block_size)
        end_block, end_offset = divmod(offset + length, self.block_size)

        if end_offset == 0:
            end_block -= 1
            end_offset = self.block_size

        result = StringIO()
        for block_id in range(start_block, end_block + 1):
            block_data = self.read_block(block_id)
            
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

    def write(self, offset, data):
        """
        s3handler.write(offset, data)

        Write data to this volume starting at offset.
        """
        start_block, start_offset = divmod(offset, self.block_size)
        end_block, end_offset = divmod(offset + len(data), self.block_size)

        if end_offset == 0:
            end_block -= 1
            end_offset = self.block_size
        
        to_write = StringIO(data)
        for block_id in range(start_block, end_block + 1):
            # Do we need a read-modify-write cycle?
            if ((block_id == start_block and start_offset != 0) or
                (block_id == end_block and
                 end_offset != self.block_size)):
                # Yes; get the existing data.
                block_data = self.read_block(block_id)
                    
                # Splice in the current data.
                start_pos = (0 if block_id != start_block else start_offset)
                end_pos = (self.block_size if block_id != end_block else
                           end_offset)
                splice_length = end_pos - start_pos

                spliced = to_write.read(end_pos - start_pos)
                block_data = (block_data[:start_pos] + spliced +
                              block_data[end_pos:])
            else:
                block_data = to_write.read(self.block_size)

            self.write_block(block_id, block_data)

        return

    def trim(self, offset, length):
        """
        s3handler.trim(bucket, offset, length)

        Trim any full blocks of data from this volume starting at offset and
        extending to offset + length.
        """
        start_block, start_offset = divmod(offset, self.block_size)
        end_block, end_offset = divmod(offset + len(data), self.block_size)

        if end_offset == 0:
            end_block -= 1
            end_offset = self.block_size
        
        to_write = StringIO(data)
        for block_id in range(start_block, end_block + 1):
            # Skip partial blocks
            if ((block_id != start_block or start_offset == 0) and
                (block_id != end_block or end_offset == self.block_size)):
                self.trim_block(block_id)

        return

    @staticmethod
    def block_to_prefix(block_index):
        """
        Convert a block index to an S3 key prefix.
        """
        result = urlsafe_b64encode(pack("<Q", block_index))
        assert len(result) == 12
        assert result[-1] == '='
        return result[:-1]

    def get_key_for_block(self, bucket, block_id):
        """
        s3handler.get_key_for_block(bucket, block_id) -> key

        Return a Boto S3 key object for the given block.  The bucket must be
        a Boto S3 object; this is required for thread safety.
        """
        key_name = UBDS3Volume.block_to_prefix(block_id) + self.suffix
        return bucket.new_key(key_name)

    def read_block(self, block_id):
        """
        s3handler.read_block(bucket, block_id) -> str

        Read a block of data.  The bucket must be a Boto S3 object; this is
        required for thread safety.
        """
        with self.s3_pool.get_connection() as s3:
            key = self.get_key_for_block(s3.bucket, block_id)
            sleep_time = 0.1

            while True:
                try:
                    block_data = key.read()
                    if len(block_data) != self.block_size:
                        raise OSError(
                            EIO, "Failed to read block %d: block truncated "
                            "at %d bytes instead of %d bytes" % (
                                block_id, len(block_data), self.block_size))
                    return block_data
                except S3ResponseError as e:
                    if e.status == 404:
                        return b"\0" * self.block_size
                    elif e.status < 500:
                        log.warning("Received unexpected S3 error: %s", e,
                                    exc_info=True)
                        raise OSError(EIO, str(e))
                    log.info("S3 temporarily unavailable (%d): %s; still "
                             "trying", e.status, e)
                except EnvironmentError as e:
                    log.info("S3 temporarily unavailable (env): %s; still "
                             "trying", e)

                sleep(sleep_time)
                sleep_time = min(5.0, 1.5 * sleep_time)

    def write_block(self, block_id, block_data):
        """
        s3handler.write_block(bucket, block_id, block_data)
        
        Write a block of data.  The bucket must be a Boto S3 object; this is
        required for thread safety.
        """
        with self.s3_pool.get_connection() as s3:
            key = self.get_key_for_block(s3.bucket, block_id)

            if len(block_data) != self.block_size:
                raise OSError(
                    EIO, "Failed to write block %d: block truncated at %d "
                    "bytes instead of %d bytes" % (block_id, len(block_data),
                                                   self.block_size))

            rr = (self.storage_class == 'reduced-redundancy')
            encrypt_key = (self.encryption == "sse-s3")
            sleep_time = 0.1

            while True:
                try:
                    key.set_contents_from_string(
                        block_data, reduced_redundancy=rr,
                        policy=self.policy, encrypt_key=encrypt_key)

                    return
                except S3ResponseError as e:
                    if e.status < 500:
                        log.warning("Received unexpected S3 error: %s", e,
                                    exc_info=True)
                        raise OSError(EIO, str(e))
                    log.info("S3 temporarily unavailable (%d): %s; still "
                             "trying", e.status, e)
                except EnvironmentError as e:
                    log.info("S3 temporarily unavailable (env): %s; still "
                             "trying", e)

                sleep(sleep_time)
                sleep_time = min(5.0, 1.5 * sleep_time)

    def trim_block(self, block_id):
        sleep_time = 0.1
        with self.s3_pool.get_connection() as s3:
            key = self.get_key_for_block(s3.bucket, block_id)

            while True:
                # Delete the key if it exists
                try:
                    key.delete()
                except S3ResponseError as e:
                    if e.status == 404:
                        # Ignore
                        return
                    elif e.status < 500:
                        log.warning("Received unexpected S3 error: %s", e,
                                    exc_info=True)
                        raise OSError(EIO, str(e))
                    else:
                        log.info("S3 temporarily unavailable (%d): %s; still "
                                 "trying", e.status, e)
                except EnvironmentError as e:
                    log.info("S3 temporarily unavailable (env): %s; still "
                             "trying", e)

                sleep(sleep_time)
                sleep_time = min(5.0, 1.5 * sleep_time)
                
            
def parse_size(value, parameter_name, min=0, max=None):
    m = match(r"([0-9]+|0x[0-9a-fA-F]+)\s*"
              r"(k|kiB|M|MiB|G|GiB|T|TiB|P|PiB|E|EiB)?", value)
    if not m:
        raise GetoptError("Invalid %s value: %r" % (parameter_name, value))
    
    result = int(m.group(1))
    suffix = m.group(2)
    if suffix:
        result <<= suffix_shift[suffix[0]]
    
    if min is not None and result < min:
        raise ValueError("Invalid %s value (must be at least %d): %r" %
                         (parameter_name, min, value))
    if max is not None and result > max:
        raise ValueError("Invalid %s value (cannot be greater than %d): %r" %
                         (parameter_name, max, value))

    return result

def main(args=None):
    global log

    bucket_name = block_size = encryption = profile = policy = region = None
    size = storage_class = suffix = None
    proxy_user = environ.get("PROXY_USER")
    proxy_password = environ.get("PROXY_PASSWORD")
    create = False
    thread_count = 10

    if args is None:
        args = argv[1:]

    try:
        proxy_port = int(environ.get("PROXY_PORT", "0"))
    except ValueError:
        proxy_port = None

    try:
        opts, args = getopt(args, "b:B:cC:e:hp:P:r:s:S:t:",
                            ["bucket=", "block-size=", "create", "encryption=",
                             "help", "policy=",
                             "profile=", "proxy-user=", "proxy-password=",
                             "proxy-port=", "region=", "size=",
                             "storage-class=", "suffix=", "threads="])

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
            elif opt in ("--storage-class", "-C",):
                storage_class = value
                if storage_class not in ("standard", "reduced-redundancy",
                                         "infrequently-accessed"):
                    raise ValueError("Invalid storage class: %r" % value)
            elif opt in ("--suffix", "-S",):
                suffix = value
            elif opt in ("--threads",):
                thread_count = int(value)

        if bucket_name is None:
            raise GetoptError("--bucket-name is required")

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
                raise GetoptError("--storage-class is valid only with "
                                  "--create")
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

    logging.basicConfig(level=logging.DEBUG, stream=stderr,
                        format=log_format)
    log = logging.getLogger("ubds3")
    logging.getLogger("boto").setLevel(logging.INFO)

    volume = UBDS3Volume(bucket_name, devname, region=region,
                         thread_count=thread_count,
                         s3_kw={'profile_name': profile,
                                'proxy_user': proxy_user,
                                'proxy_pass': proxy_password,})
    if create:
        volume.create_volume(block_size=block_size, encryption=encryption,
                             policy=policy, size=size,
                             storage_class=storage_class,
                             suffix=suffix)
    else:
        volume.read_volume_info()

    volume.register()

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

    --threads <int>
        Create the specified number of threads to handle requests.
""")

    fd.flush()

