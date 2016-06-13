#include <cerrno>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <poll.h>
#include <ublkdev.hh>
#include <aws/core/Aws.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include "s3.hh"

#define INITIAL_BUFFER_SIZE (4096)

using std::chrono::milliseconds;
using std::chrono::seconds;

using Aws::S3::S3Client;
using Aws::S3::Model::DeleteObjectRequest;
using Aws::S3::Model::GetObjectRequest;
using Aws::S3::Model::ObjectCannedACL;
using Aws::S3::Model::ObjectCannedACLMapper::GetNameForObjectCannedACL;
using Aws::S3::Model::PutObjectRequest;
using Aws::S3::Model::ServerSideEncryption;
using Aws::S3::Model::ServerSideEncryptionMapper::GetNameForServerSideEncryption;
using Aws::S3::Model::StorageClass;
using Aws::S3::Model::StorageClassMapper::GetNameForStorageClass;

UBDS3Volume::UBDS3Volume(
    Aws::String const &bucket_name,
    Aws::String const &devname,
    Aws::String const &region,
    uint32_t thread_count) :
    m_ubd(NULL),
    m_bucket_name(bucket_name),
    m_devname(devname),
    m_region(region),
    m_thread_count(thread_count),
    m_block_size(-1),
    m_encryption(ServerSideEncryption::NOT_SET),
    m_policy(ObjectCannedACL::private_),
    m_storage_class(StorageClass::STANDARD),
    m_suffix(),
    m_size(0ull),
    m_major(0),
    m_stop_requested(false),
    m_threads(thread_count)
{
    return;
}

UBDS3Volume::~UBDS3Volume() {
    delete m_ubd;
    return;
}

void UBDS3Volume::registerVolume() {
    uint64_t n_sectors = m_size / 512;
    
    m_ubd = new UserBlockDevice();
    auto ui = m_ubd->registerEndpoint(m_devname.c_str(), n_sectors, false);
    m_major = ui.ubd_major;
    return;
}

void UBDS3Volume::run() {
    for (uint32_t i = 0; i < m_thread_count; ++i) {
        m_threads[i] = std::thread {UBDS3Handler(this)};
    }

    while (! m_stop_requested.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    for (uint32_t i = 0; i < m_thread_count; ++i) {
        m_threads[i].join();
    }

    return;
}

void UBDS3Volume::readVolumeInfo() {
    // XXX
}

void UBDS3Volume::createVolume(
    uint64_t size,
    uint32_t blockSize,
    ServerSideEncryption encryption,
    ObjectCannedACL policy,
    StorageClass storage_class,
    Aws::String const &suffix)
{
    std::shared_ptr<std::stringstream> config(new std::stringstream);
    milliseconds sleep_time(100);

    m_block_size = blockSize;
    m_encryption = encryption;
    m_policy = policy;
    m_storage_class = storage_class;

    *config << "{\"block-size\": " << blockSize
            << ", \"policy\": \"" << GetNameForObjectCannedACL(policy).c_str()
            << "\", \"size\": " << size
            << ", \"storage-class\": \""
            << GetNameForStorageClass(storage_class).c_str() << "\"";

    if (encryption != ServerSideEncryption::NOT_SET) {
        *config << ", \"encryption\": \""
                << GetNameForServerSideEncryption(encryption) << "\"";
    }

    if (suffix.length() > 0) {
        *config << ", \"suffix\": \"";

        for (auto c : suffix) {
            if (c == '"') {
                *config << "\\\"";
            }
            else if (c == '\\') {
                *config << "\\\\";
            }
            else if (c < ' ' || c >= '\x7f') {
                *config << "\\x" << std::setw(2) << std::setfill('0')
                        << std::hex << static_cast<unsigned int>(c);
            }
        }

        *config << "\"";
    }

    *config << "}";

    config->seekg(0);

    S3Client s3(getS3Configuration());
    PutObjectRequest req;
    req.SetBucket(m_bucket_name);
    req.SetKey(m_devname + ".volinfo");
    req.SetACL(m_policy);
    req.SetStorageClass(m_storage_class);
    req.SetBody(config);

    while (true) {
        auto outcome = s3.PutObject(req);
        if (outcome.IsSuccess()) {
            return;
        }

        auto &error = outcome.GetError();

        if (error.ShouldRetry()) {
            std::this_thread::sleep_for(sleep_time);
            sleep_time = sleep_time * 3 / 2;
            if (sleep_time > seconds(5)) {
                sleep_time = seconds(5);
            }

            continue;
        }

        throw UBDError(EIO);
    }
}

void UBDS3Volume::read(
    S3Client &s3,
    uint64_t offset,
    void *buffer /* OUT */,
    uint32_t length)
{
    uint64_t start_block = offset / m_block_size;
    uint64_t start_offset = offset % m_block_size;
    uint64_t end_block = (offset + length) / m_block_size;
    uint64_t end_offset = (offset + length) % m_block_size;
    uint8_t *p = static_cast<uint8_t *>(buffer);

    for (uint64_t i = start_block; i < end_block; ++i) {
        readBlock(s3, i, p);

        if (i == start_block && start_offset > 0) {
            // Trim the data to omit anything from before the start of the
            // read range.
            std::memmove(p, p + start_offset, m_block_size - start_offset);
            p += m_block_size - start_offset;
        } else {
            p += m_block_size;
        }
    }

    // While reading the last block, we may need to do a read shorter than the
    // buffer size.
    if (end_offset > 0) {
        std::unique_ptr<uint8_t[]> tmpbuf(new uint8_t[m_block_size]);
        readBlock(s3, end_block, tmpbuf.get());
        std::memcpy(p, tmpbuf.get(), end_offset);
    }

    return;
}

void UBDS3Volume::write(
    S3Client &s3,
    uint64_t offset,
    void const *buffer,
    uint32_t length)
{
    uint64_t start_block = offset / m_block_size;
    uint64_t start_offset = offset % m_block_size;
    uint64_t end_block = (offset + length) / m_block_size;
    uint64_t end_offset = (offset + length) % m_block_size;
    const uint8_t *p = static_cast<const uint8_t *>(buffer);

    if (start_offset > 0) {
        // We need a read-modify-write cycle at the start.
        std::unique_ptr<uint8_t[]> tmpbuf(new uint8_t[m_block_size]);
        readBlock(s3, start_block, tmpbuf.get());

        if (start_block == end_block) {
            std::memcpy(tmpbuf.get() + start_offset, p, length);
            p += length;
        } else {
            std::memcpy(tmpbuf.get() + start_offset, p,
                        m_block_size - start_offset);
            p += m_block_size - start_offset;
        }
        
        writeBlock(s3, start_block, tmpbuf.get());
        ++start_block;

        if (start_block == end_block) {
            return;
        }
    }

    for (uint64_t i = start_block; i < end_block; ++i) {
        writeBlock(s3, i, p);
        p += m_block_size;
    }

    if (end_offset > 0) {
        // We need a read-modify-write cycle at the end.
        std::unique_ptr<uint8_t[]> tmpbuf(new uint8_t[m_block_size]);
        readBlock(s3, end_block, tmpbuf.get());
        std::memcpy(tmpbuf.get(), p, end_offset);

        writeBlock(s3, end_block, tmpbuf.get());
    }

    return;
}

void UBDS3Volume::trim(
    S3Client &s3,
    uint64_t offset,
    uint32_t length)
{
    uint64_t start_block = offset / m_block_size;
    uint64_t start_offset = offset % m_block_size;
    uint64_t end_block = (offset + length) / m_block_size;

    if (start_offset > 0) {
        // Don't trim partial blocks;
        ++start_block;
    }

    for (uint64_t i = start_block; i < end_block; ++i) {
        trimBlock(s3, i);
    }

    return;
}

class RegionMap {
public:
    RegionMap();
    Aws::Region forName(Aws::String const &name) const;

private:
    std::map<Aws::String, Aws::Region> m_regions;
};

RegionMap::RegionMap() {
    m_regions["us-east-1"] = Aws::Region::US_EAST_1;
    m_regions["us-west-1"] = Aws::Region::US_WEST_1;
    m_regions["us-west-2"] = Aws::Region::US_WEST_2;
    m_regions["eu-west-1"] = Aws::Region::EU_WEST_1;
    m_regions["eu-central-1"] = Aws::Region::EU_CENTRAL_1;
    m_regions["ap-southeast-1"] = Aws::Region::AP_SOUTHEAST_1;
    m_regions["ap-southeast-1"] = Aws::Region::AP_SOUTHEAST_2;
    m_regions["ap-northeast-1"] = Aws::Region::AP_NORTHEAST_1;
    m_regions["ap-northeast-2"] = Aws::Region::AP_NORTHEAST_2;
    m_regions["sa-east-1"] = Aws::Region::SA_EAST_1;
    return;
}

Aws::Region RegionMap::forName(Aws::String const &name) const {
    auto pos = m_regions.find(name);
    if (pos == m_regions.end()) {
        throw std::domain_error("Unknown region " + std::string(name.c_str()));
    }

    return pos->second;
}

static RegionMap regionMap;

Aws::Client::ClientConfiguration UBDS3Volume::getS3Configuration() {
    Aws::Client::ClientConfiguration result;
    result.region = regionMap.forName(m_region);
    return result;
}

static const char *b64alphabet = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

Aws::String UBDS3Volume::blockToPrefix(
    uint64_t block_index)
{
    char buf[12];

    for (int i = 0; i < 11; ++i) {
        buf[i] = b64alphabet[block_index & 63];
        block_index >>= 6;
    }

    buf[11] = '\0';

    return Aws::String(buf);
}

void UBDS3Volume::readBlock(
    S3Client &s3,
    uint64_t block_id,
    void *buffer)
{
    GetObjectRequest req;
    milliseconds sleep_time(100);
    req.SetBucket(m_bucket_name);
    req.SetKey(blockToPrefix(block_id) + m_suffix);

    while (true) {
        auto outcome = s3.GetObject(req);

        if (outcome.IsSuccess()) {
            auto &result = outcome.GetResult();
            auto &body = result.GetBody();
            
            body.read(static_cast<char *>(buffer), m_block_size);
            if (body.gcount() != m_block_size) {
                throw UBDError(EIO);
            }

            return;
        }
        
        auto &error = outcome.GetError();
        auto ecode = error.GetErrorType();

        if (ecode == Aws::S3::S3Errors::RESOURCE_NOT_FOUND ||
            ecode == Aws::S3::S3Errors::NO_SUCH_KEY)
        {
            // Never-written block. Return all zeroes.
            memset(buffer, 0, m_block_size);
            return;
        }

        if (error.ShouldRetry()) {
            std::this_thread::sleep_for(sleep_time);
            sleep_time = sleep_time * 3 / 2;
            if (sleep_time > seconds(5)) {
                sleep_time = seconds(5);
            }

            continue;
        }

        throw UBDError(EIO);
    }
}

void UBDS3Volume::writeBlock(
    S3Client &s3,
    uint64_t block_id,
    const void *buffer)
{
    PutObjectRequest req;
    milliseconds sleep_time(100);

    std::shared_ptr<std::stringstream> body(new std::stringstream);

    body->rdbuf()->pubsetbuf(
        const_cast<char *>(static_cast<char const *>(buffer)), m_block_size);

    req.SetBucket(m_bucket_name);
    req.SetKey(blockToPrefix(block_id) + m_suffix);
    req.SetACL(m_policy);
    req.SetStorageClass(m_storage_class);
    req.SetBody(body);

    while (true) {
        auto outcome = s3.PutObject(req);
        if (outcome.IsSuccess()) {
            return;
        }
        
        auto &error = outcome.GetError();
        if (error.ShouldRetry()) {
            std::this_thread::sleep_for(sleep_time);
            sleep_time = sleep_time * 3 / 2;
            if (sleep_time > seconds(5)) {
                sleep_time = seconds(5);
            }

            continue;
        }

        throw UBDError(EIO);
    }
}

void UBDS3Volume::trimBlock(
    S3Client &s3,
    uint64_t block_id)
{
    DeleteObjectRequest req;
    milliseconds sleep_time(100);

    req.SetBucket(m_bucket_name);
    req.SetKey(blockToPrefix(block_id) + m_suffix);

    while (true) {
        auto outcome = s3.DeleteObject(req);
        if (outcome.IsSuccess()) {
            return;
        }
        
        auto &error = outcome.GetError();
        auto ecode = error.GetErrorType();

        if (ecode == Aws::S3::S3Errors::RESOURCE_NOT_FOUND ||
            ecode == Aws::S3::S3Errors::NO_SUCH_KEY)
        {
            // Never-written block. Trim is a no-op.
            return;
        }

        if (error.ShouldRetry()) {
            std::this_thread::sleep_for(sleep_time);
            sleep_time = sleep_time * 3 / 2;
            if (sleep_time > seconds(5)) {
                sleep_time = seconds(5);
            }

            continue;
        }

        throw UBDError(EIO);
    }
}

UBDS3Handler::UBDS3Handler(UBDS3Volume *volume) :
    m_volume(volume),
    m_ubd(),
    m_message(),
    m_buffer(new uint8_t[INITIAL_BUFFER_SIZE]),
    m_buffer_size(INITIAL_BUFFER_SIZE),
    m_s3(volume->getS3Configuration())
{
    m_message.ubd_data = m_buffer.get();
    m_ubd.tie(m_volume->getMajor());
}

UBDS3Handler::UBDS3Handler(UBDS3Handler &&other) :
    m_volume(other.m_volume),
    m_ubd(std::move(other.m_ubd)),
    m_message(),
    m_buffer(std::move(other.m_buffer)),
    m_buffer_size(other.m_buffer_size),
    m_s3(std::move(other.m_s3))
{
    m_message.ubd_data = m_buffer.get();
    m_buffer_size = other.m_buffer_size;

    other.m_volume = nullptr;
    other.m_message.ubd_data = nullptr;
}


void UBDS3Handler::operator() () {
    run();
}

void UBDS3Handler::run() {
    struct pollfd fds[1];
    struct ubd_message message;

    fds[0].fd = m_ubd.getDescriptor();
    fds[0].events = POLLIN;

    while (! m_volume->isStopRequested()) {
        int poll_result = poll(fds, 1, 1000);

        if (poll_result < 0) {
            std::cerr << "Thread " << std::this_thread::get_id()
                      << " failed to poll: " << std::strerror(errno) << std::endl;
            break;
        }

        if (poll_result > 0) {
            // Event ready.
            try {
                m_message.ubd_size = m_buffer_size;
                m_ubd.getRequest(m_message);
            }
            catch (UBDError const &e) {
                if (e.getError() == ENOMEM) {
                    // Resize the buffer
                    try {
                        resizeBuffer(m_message.ubd_size);
                    }
                    catch (std::bad_alloc &) {
                        std::cerr << "Thread " << std::this_thread::get_id()
                                  << " failed to allocate " << message.ubd_size
                                  << " bytes; exiting." << std::endl;
                        break;
                    }
                }
            }

            handleUBDRequest();
        }
    }
}

void UBDS3Handler::handleUBDRequest() {
    uint64_t offset = 512u * m_message.ubd_first_sector;
    uint32_t length = 512u * m_message.ubd_nsectors;

    switch (m_message.ubd_msgtype) {
    case UBD_MSGTYPE_READ:
        if (length > m_buffer_size) {
            try {
                resizeBuffer(length);
            }
            catch (std::bad_alloc &) {
                m_message.ubd_status = -EIO;
                m_ubd.putReply(m_message);
                return;
            }
        }

        m_volume->read(m_s3, offset, m_message.ubd_data, length);
        m_message.ubd_status = m_message.ubd_size;
        m_message.ubd_size = length;
        m_ubd.putReply(m_message);
        break;

    case UBD_MSGTYPE_WRITE:
        m_volume->write(m_s3, offset, m_message.ubd_data, length);
        m_message.ubd_status = length;
        m_message.ubd_size = 0;
        m_ubd.putReply(m_message);
        break;

    case UBD_MSGTYPE_DISCARD:
        m_volume->trim(m_s3, offset, m_message.ubd_size);
        m_message.ubd_status = length;
        m_message.ubd_size = 0;
        m_ubd.putReply(m_message);
        break;

    case UBD_MSGTYPE_FLUSH:
        m_message.ubd_status = length;
        m_message.ubd_size = 0;
        m_ubd.putReply(m_message);
        break;

    default:
        m_message.ubd_status = -EINVAL;
        m_ubd.putReply(m_message);
        break;
    }
}

void UBDS3Handler::resizeBuffer(uint32_t new_size) {
    std::unique_ptr<uint8_t[]> new_buffer(new uint8_t[new_size]);

    m_buffer.swap(new_buffer);
    m_buffer_size = new_size;
    m_message.ubd_data = m_buffer.get();
    return;
}

int main(int argc, char *argv[]) {
    // XXX
    return 0;
}
