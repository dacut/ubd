#pragma once
#include <stdint.h>
#include <string>

#include <aws/s3/S3Client.h>
#include <aws/s3/model/ObjectCannedACL.h>
#include <aws/s3/model/ServerSideEncryption.h>
#include <aws/s3/model/StorageClass.h>

class UBDS3Volume {
public:
    UBDS3Volume(
        std::string const &bucket_name,
        std::string const &devname,
        std::string const &region,
        uint32_t thread_count);

    virtual ~UBDS3Volume();
    
    virtual void registerVolume();
    virtual void run();
    virtual void readVolumeInfo();
    virtual void createVolume(
        uint32_t blockSize,
        Aws::S3::Model::ServerSideEncryption encryption =
        Aws::S3::Model::ServerSideEncryption::NOT_SET,
        Aws::S3::Model::ObjectCannedACL policy =
        Aws::S3::Model::ObjectCannedACL::private_,
        Aws::S3::Model::StorageClass storage_class =
        Aws::S3::Model::StorageClass::STANDARD,
        std::string const &suffix = "");
    virtual void read(
        uint64_t offset,
        void *buffer /* OUT */,
        uint32_t length);
    virtual void write(
        uint64_t offset,
        void const *buffer,
        uint32_t length);
    virtual void trim(
        uint64_t offset,
        uint32_t length);

    static std::string blockToPrefix(uint64_t block_index);

protected:
    virtual void readBlock(
        uint64_t block_id,
        void *buffer);

    virtual void writeBlock(
        uint64_t block_id,
        void *buffer);

    virtual void trimBlock(
        uint64_t block_id);

private:
    UserBlockDevice *m_ubd;
    std::string m_bucket_name;
    std::string m_devname;
    std::string m_region;
    uint32_t m_thread_count;
    uint32_t m_block_size;
    Aws::S3::Model::ServerSideEncryption m_encryption;
    Aws::S3::Model::ObjectCannedACL m_policy;
    Aws::S3::Model::StorageClass m_storage_class;
    std::string m_suffix;
    uint64_t m_size;
    uint32_t m_major;
    volatile bool m_stop_requested;
};

class S3Pool;
class S3PoolConnection;

class S3Pool {
public:
    S3Pool(
        std::string region,
        uint32_t size,
        std::string bucket_name);

private:
    Aws::S3::S3Client *getConnection();
    void returnConnection(Aws::S3::S3Client *client);

    Aws::Utils::Array<Aws::S3::S3Client *> m_connections;

    friend class S3PoolConnection;
};

class S3PoolConnection {
public:
    S3PoolConnection(S3Pool *pool) :
        m_pool(pool),
        m_client(pool->getConnection()) { }
        
    ~S3PoolConnection() {
        m_pool->returnConnection(m_client);
    }

    Aws::S3::S3Client *operator ->() { return m_client; }

private:
    S3Pool *m_pool;
    Aws::S3::S3Client *m_client;
};

