#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

#include <aws/core/utils/Array.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/ObjectCannedACL.h>
#include <aws/s3/model/ServerSideEncryption.h>
#include <aws/s3/model/StorageClass.h>

class UBDS3Volume {
public:
    UBDS3Volume(
        Aws::String const &bucket_name,
        Aws::String const &devname,
        Aws::String const &region,
        uint32_t thread_count);

    virtual ~UBDS3Volume();
    
    virtual void registerVolume();

    virtual void run();

    virtual void readVolumeInfo();

    virtual void createVolume(
        uint64_t size,
        uint32_t blockSize = 4096,
        Aws::S3::Model::ServerSideEncryption encryption =
        Aws::S3::Model::ServerSideEncryption::NOT_SET,
        Aws::S3::Model::ObjectCannedACL policy =
        Aws::S3::Model::ObjectCannedACL::private_,
        Aws::S3::Model::StorageClass storage_class =
        Aws::S3::Model::StorageClass::STANDARD,
        Aws::String const &suffix = "");

    virtual void read(
        Aws::S3::S3Client &s3,
        uint64_t offset,
        void *buffer /* OUT */,
        uint32_t length);

    virtual void write(
        Aws::S3::S3Client &s3,
        uint64_t offset,
        void const *buffer,
        uint32_t length);

    virtual void trim(
        Aws::S3::S3Client &s3,
        uint64_t offset,
        uint32_t length);

    virtual Aws::Client::ClientConfiguration getS3Configuration();

    uint32_t getMajor() { return m_major; }
    bool isStopRequested() { return m_stop_requested.load(); }
    void requestStop() { m_stop_requested.store(true); }

    static Aws::String blockToPrefix(uint64_t block_index);

protected:
    virtual void readBlock(
        Aws::S3::S3Client &s3,
        uint64_t block_id,
        void *buffer);

    virtual void writeBlock(
        Aws::S3::S3Client &s3,
        uint64_t block_id,
        void const *buffer);

    virtual void trimBlock(
        Aws::S3::S3Client &s3,
        uint64_t block_id);

private:
    UserBlockDevice *m_ubd;
    Aws::String m_bucket_name;
    Aws::String m_devname;
    Aws::String m_region;
    uint32_t m_thread_count;
    uint32_t m_block_size;
    Aws::S3::Model::ServerSideEncryption m_encryption;
    Aws::S3::Model::ObjectCannedACL m_policy;
    Aws::S3::Model::StorageClass m_storage_class;
    Aws::String m_suffix;
    uint64_t m_size;
    uint32_t m_major;
    std::atomic_bool m_stop_requested;

    Aws::Utils::Array<std::thread> m_threads;
};

class UBDS3Handler {
public:
    UBDS3Handler(UBDS3Volume *volume);
    UBDS3Handler(UBDS3Handler &&other);

    void operator() ();
    void run();
    void handleUBDRequest();
    void resizeBuffer(uint32_t new_size);

private:
    UBDS3Handler(UBDS3Handler const &) = delete;
    UBDS3Handler & operator = (UBDS3Handler const &) = delete;

    UBDS3Volume *m_volume;
    UserBlockDevice m_ubd;
    struct ubd_message m_message;
    std::unique_ptr<uint8_t[]> m_buffer;
    uint32_t m_buffer_size;
    Aws::S3::S3Client m_s3;
};
