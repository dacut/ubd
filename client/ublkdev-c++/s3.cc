#include <ublkdev.hh>
#include <aws/core/Aws.h>
#include "s3.hh"

UBDS3Volume::UBDS3Volume(
    std::string const &bucket_name,
    std::string const &devname,
    std::string const &region,
    uint32_t thread_count) :
    m_ubd(NULL),
    m_bucket_name(bucket_name),
    m_devname(devname),
    m_region(region),
    m_thread_count(thread_count),
    m_block_size(-1),
    m_encryption(Aws::S3::Model::ServerSideEncryption::NOT_SET),
    m_policy(Aws::S3::Model::ObjectCannedACL::private_),
    m_storage_class(Aws::S3::Model::StorageClass::STANDARD),
    m_suffix(),
    m_size(0ull),
    m_major(0),
    m_stop_requested(false)
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

void UBDS3Volume::readVolumeInfo() {
    
}
