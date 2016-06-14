#include <cerrno>
#include <climits>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <getopt.h>
#include <poll.h>
#include <ublkdev.hh>
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include "s3.hh"
#include "regionmap.hh"

#define INITIAL_BUFFER_SIZE (4096)

using std::chrono::milliseconds;
using std::chrono::seconds;
using std::bad_alloc;
using std::cerr;
using std::clog;
using std::cout;
using std::domain_error;
using std::endl;
using std::map;
using std::memcpy;
using std::memmove;
using std::move;
using std::ostream;
using std::ostringstream;
using std::shared_ptr;
using std::strcmp;
using std::strerror;
using std::string;
using std::stringstream;
using std::thread;
using std::to_string;
using std::underlying_type;
using std::unique_ptr;

using Aws::Auth::AWSCredentialsProvider;
using Aws::Auth::EnvironmentAWSCredentialsProvider;
using Aws::Auth::InstanceProfileCredentialsProvider;
using Aws::Auth::ProfileConfigFileAWSCredentialsProvider;
using Aws::Client::ClientConfiguration;
using Aws::Region;
using Aws::S3::S3Client;
using Aws::S3::S3Errors;
using Aws::S3::Model::DeleteObjectRequest;
using Aws::S3::Model::GetObjectRequest;
using Aws::S3::Model::ObjectCannedACL;
using Aws::S3::Model::ObjectCannedACLMapper::GetNameForObjectCannedACL;
using Aws::S3::Model::ObjectCannedACLMapper::GetObjectCannedACLForName;
using Aws::S3::Model::PutObjectRequest;
using Aws::S3::Model::ServerSideEncryption;
using Aws::S3::Model::ServerSideEncryptionMapper::GetNameForServerSideEncryption;
using Aws::S3::Model::ServerSideEncryptionMapper::GetServerSideEncryptionForName;
using Aws::S3::Model::StorageClass;
using Aws::S3::Model::StorageClassMapper::GetNameForStorageClass;
using Aws::S3::Model::StorageClassMapper::GetStorageClassForName;
using Aws::String;
using Aws::Utils::Json::JsonValue;

static String getNameForS3Error(
    S3Errors err);
static uint64_t parseSize(
    string const &value,
    string const &parameter_name,
    uint64_t min=0,
    uint64_t max=uint64_t(-1));
static void usage(
    ostream &os = cerr);

#define OPT_BUCKET          'b'
#define OPT_BLOCK_SIZE      'B'
#define OPT_CREATE          'c'
#define OPT_ENCRYPTION      'e'
#define OPT_HELP            'h'
#define OPT_POLICY          'P'
#define OPT_PROFILE         'p'
#define OPT_PROXY_HOST      1000
#define OPT_PROXY_USER      1001
#define OPT_PROXY_PASSWORD  1002
#define OPT_PROXY_PORT      1003
#define OPT_REGION          'r'
#define OPT_SIZE            's'
#define OPT_STORAGE_CLASS   'C'
#define OPT_SUFFIX          'S'
#define OPT_THREADS         1004

static struct option longopts[] = {
    { "bucket", required_argument, nullptr, OPT_BUCKET },
    { "block-size", required_argument, nullptr, OPT_BLOCK_SIZE },
    { "create", no_argument, nullptr, OPT_CREATE },
    { "encryption", required_argument, nullptr, OPT_ENCRYPTION },
    { "help", no_argument, nullptr, OPT_HELP },
    { "policy", required_argument, nullptr, OPT_POLICY },
    { "profile", required_argument, nullptr, OPT_PROFILE },
    { "proxy-host", required_argument, nullptr, OPT_PROXY_HOST },
    { "proxy-user", required_argument, nullptr, OPT_PROXY_USER },
    { "proxy-password", required_argument, nullptr, OPT_PROXY_PASSWORD },
    { "proxy-port", required_argument, nullptr, OPT_PROXY_PORT },
    { "region", required_argument, nullptr, OPT_REGION },
    { "size", required_argument, nullptr, OPT_SIZE },
    { "storage-class", required_argument, nullptr, OPT_STORAGE_CLASS },
    { "suffix", required_argument, nullptr, OPT_SUFFIX },
    { "threads", required_argument, nullptr, OPT_THREADS },
    { nullptr, 0, nullptr, 0 },
};

int main(int argc, char *argv[]) {
    Aws::SDKOptions sdk_options;
    String bucket_name;
    uint64_t block_size = 0;
    bool create = false;
    ServerSideEncryption sse = ServerSideEncryption::NOT_SET;
    ObjectCannedACL policy = ObjectCannedACL::NOT_SET;
    unique_ptr<String> profile;
    unique_ptr<String> proxy_host;
    unique_ptr<String> proxy_user;
    unique_ptr<String> proxy_password;
    uint16_t proxy_port = 0;
    unique_ptr<Region> region;
    StorageClass storage_class = StorageClass::NOT_SET;
    String suffix;
    uint32_t thread_count = 10;
    uint64_t size = 0;
    
    int c;

    while ((c = getopt_long(argc, argv, "b:B:cC:e:hp:P:r:s:S:t:", longopts,
                            nullptr)) != -1)
    {
        switch (c) {
        case OPT_BUCKET:
            bucket_name = optarg;
            break;

        case OPT_BLOCK_SIZE:
            try {
                block_size = parseSize(optarg, "block size", 512, 1<<30);
            }
            catch (domain_error &e) {
                usage();
                return 1;
            }
            break;

        case OPT_CREATE:
            create = true;
            break;

        case OPT_ENCRYPTION:
            if (strcmp(optarg, "sse-s3") == 0) {
                sse = ServerSideEncryption::AES256;
            }
            else {
                cerr << "Unknown encryption specification: " << optarg << endl;
                usage();
                return 1;
            }
            break;

        case OPT_HELP:
            usage(cout);
            return 0;

        case OPT_POLICY:
            policy = GetObjectCannedACLForName(optarg);
            if (policy == ObjectCannedACL::NOT_SET) {
                cerr << "Invalid storage policy: " << optarg << endl;
                usage();
                return 1;
            }
            break;

        case OPT_PROFILE:
            profile = unique_ptr<String>(new String(optarg));
            break;

        case OPT_PROXY_HOST:
            proxy_host = unique_ptr<String>(new String(optarg));
            break;

        case OPT_PROXY_USER:
            proxy_user = unique_ptr<String>(new String(optarg));
            break;

        case OPT_PROXY_PASSWORD:
            proxy_password = unique_ptr<String>(new String(optarg));
            break;

        case OPT_PROXY_PORT: {
            char *endptr;
            long parsed_port = strtoll(optarg, &endptr, 0);
            
            if (*endptr != '\0' || parsed_port <= 0 || parsed_port > 65535) {
                cerr << "Invalid proxy port: " << optarg << endl;
                usage();
                return 1;
            }

            proxy_port = uint16_t(parsed_port);
            break;
        }

        case OPT_REGION:
            try {
                region = unique_ptr<Region>(
                    new Region(getRegionForName(optarg)));
            }
            catch (domain_error &e) {
                cerr << "Unknown region: " << optarg << endl;
                usage();
                return 1;
            }
            break;

        case OPT_SIZE:
            try {
                size = parseSize(optarg, "size", 0, ULLONG_MAX);
            }
            catch (domain_error &e) {
                cerr << e.what() << endl;
                usage();
                return 1;
            }
            break;
     
        case OPT_STORAGE_CLASS:
            storage_class = GetStorageClassForName(optarg);
            if (storage_class == StorageClass::NOT_SET) {
                cerr << "Invalid storage class: " << optarg << endl;
                usage();
                return 1;
            }
            break;

        case OPT_SUFFIX:
            suffix = optarg;
            break;

        case OPT_THREADS: {
            char *endptr;
            long parsed_threads = strtoll(optarg, &endptr, 0);
            
            if (*endptr != '\0' || parsed_threads <= 0 ||
                parsed_threads > UINT_MAX)
            {
                cerr << "Invalid thread count: " << optarg << endl;
                usage();
                return 1;
            }

            thread_count = uint16_t(parsed_threads);
            break;
        }

        default:
            usage();
            return 1;
        }
    }

    if (bucket_name.length() == 0) {
        cerr << "--bucket-name is required" << endl;
        usage();
        return 1;
    }

    if (! create) {
        if (block_size != 0) {
            cerr << "--block-size is valid only with --create" << endl;
            usage();
            return 1;
        }
        
        if (sse != ServerSideEncryption::NOT_SET) {
            cerr << "--encryption is valid only with --create" << endl;
            usage();
            return 1;
        }

        if (policy != ObjectCannedACL::NOT_SET) {
            cerr << "--policy is valid only with --create" << endl;
            usage();
            return 1;
        }

        if (size != 0) {
            cerr << "--size is valid only with --create" << endl;
            usage();
            return 1;
        }

        if (storage_class != StorageClass::NOT_SET) {
            cerr << "--storage-class is valid only with --create" << endl;
            usage();
            return 1;
        }

        if (suffix.length() != 0) {
            cerr << "--suffix is valid only with --create" << endl;
            usage();
            return 1;
        }
    } else {
        if (block_size == 0) {
            block_size = 4096;
        }

        if (policy == ObjectCannedACL::NOT_SET) {
            policy = ObjectCannedACL::private_;
        }

        if (size == 0) {
            cerr << "--size must be specified with --create" << endl;
            usage();
            return 1;
        }

        if (storage_class == StorageClass::NOT_SET) {
            storage_class = StorageClass::STANDARD;
        }
    }

    if (optind >= argc) {
        cerr << "Missing device name" << endl;
        usage();
        return 1;
    }

    if (optind + 1 != argc) {
        cerr << "Unknown argument " << argv[optind + 1] << endl;
        usage();
        return 1;
    }

    String devname = argv[optind];
    
    if (create && suffix.length() == 0) {
        suffix = "." + devname;
    }

    sdk_options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Debug;
    Aws::InitAPI(sdk_options);
    try {
        ClientConfiguration client_config;
        if (region) {
            client_config.region = *region;
        }
    
        if (proxy_host) {
            client_config.proxyHost = *proxy_host;
        }

        if (proxy_user) {
            client_config.proxyUserName = *proxy_user;
        }

        if (proxy_password) {
            client_config.proxyPassword = *proxy_password;
        }

        if (proxy_port != 0) {
            client_config.proxyPort = proxy_port;
        }

        shared_ptr<AWSCredentialsProvider> creds;

        if (profile) {
            cerr << "Using ProfileConfigFileAWSCredentialsProvider" << endl;
            creds = shared_ptr<AWSCredentialsProvider>(
                new ProfileConfigFileAWSCredentialsProvider(profile->c_str()));
        }
        else if (getenv("AWS_ACCESS_KEY_ID") != nullptr &&
                 getenv("AWS_SECRET_ACCESS_KEY") != nullptr)
        {
            creds = shared_ptr<AWSCredentialsProvider>(
                new EnvironmentAWSCredentialsProvider);
        }
        else {
            creds = shared_ptr<AWSCredentialsProvider>(
                new InstanceProfileCredentialsProvider);
        }

        UBDS3Volume vol(bucket_name, devname, creds, client_config,
                        thread_count);
        if (create) {
            vol.createVolume(size, block_size, sse, policy, storage_class,
                             suffix);
        } else {
            vol.readVolumeInfo();
        }

        vol.registerVolume();
        vol.run();

        Aws::ShutdownAPI(sdk_options);
        return 0;
    }
    catch (...) {
        Aws::ShutdownAPI(sdk_options);
        throw;
    }
}

UBDS3Volume::UBDS3Volume(
    String const &bucket_name,
    String const &devname,
    shared_ptr<AWSCredentialsProvider> &auth,
    ClientConfiguration const &client_config,
    uint32_t thread_count) :
    m_ubd(NULL),
    m_bucket_name(bucket_name),
    m_devname(devname),
    m_auth(auth),
    m_client_config(client_config),
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
        m_threads[i] = thread {UBDS3Handler(this)};
    }

    while (! m_stop_requested.load()) {
        std::this_thread::sleep_for(seconds(30));
    }

    for (uint32_t i = 0; i < m_thread_count; ++i) {
        m_threads[i].join();
    }

    return;
}

void UBDS3Volume::readVolumeInfo() {
    milliseconds sleep_time(100);

    S3Client s3(getS3Credentials(), getS3Configuration());
    GetObjectRequest req;
    req.SetBucket(m_bucket_name);
    req.SetKey(m_devname + ".volinfo");
    
    while (true) {
        auto outcome = s3.GetObject(req);
        
        if (outcome.IsSuccess()) {
            auto &result = outcome.GetResult();
            auto &body = result.GetBody();

            JsonValue config(body);
            if (! config.WasParseSuccessful()) {
                clog << "Invalid JSON in s3://" << m_bucket_name << "/"
                     << m_devname << ".volinfo: "
                     << config.GetErrorMessage() << endl;
                throw UBDError(EINVAL);
            }

            m_size = config.GetInt64("size");
            m_block_size = config.GetInteger("block-size");
            m_policy = GetObjectCannedACLForName(config.GetString("policy"));
            m_storage_class = GetStorageClassForName(
                config.GetString("storage-class"));

            if (config.ValueExists("encryption")) {
                m_encryption = GetServerSideEncryptionForName(
                    config.GetString("encryption"));
            } else {
                m_encryption = ServerSideEncryption::NOT_SET;
            }

            if (config.ValueExists("suffix")) {
                m_suffix = config.GetString("suffix");
            } else {
                m_suffix = "";
            }

            return;
        }

        auto &error = outcome.GetError();
        auto ecode = error.GetErrorType();

        if (error.ShouldRetry()) {
            std::this_thread::sleep_for(sleep_time);
            sleep_time = sleep_time * 3 / 2;
            if (sleep_time > seconds(5)) {
                sleep_time = seconds(5);
            }

            continue;
        }

        string message("Failed to read s3://");
        message += m_bucket_name.c_str();
        message += '/';
        message += m_devname.c_str();
        message += ".volinfo: ";
        message += getNameForS3Error(ecode).c_str();

        throw UBDS3Error(message);
    }
}

void UBDS3Volume::createVolume(
    uint64_t size,
    uint32_t blockSize,
    ServerSideEncryption encryption,
    ObjectCannedACL policy,
    StorageClass storage_class,
    String const &suffix)
{
    milliseconds sleep_time(100);

    m_size = size;
    m_block_size = blockSize;
    m_encryption = encryption;
    m_policy = policy;
    m_storage_class = storage_class;
    m_suffix = suffix;

    JsonValue config = JsonValue()
        .WithInt64("size", size)
        .WithInteger("block-size", blockSize)
        .WithString("policy", GetNameForObjectCannedACL(policy))
        .WithString("storage-class", GetNameForStorageClass(storage_class));

    if (encryption != ServerSideEncryption::NOT_SET) {
        config = config.WithString(
            "encryption", GetNameForServerSideEncryption(encryption));
    }

    if (suffix.length() > 0) {
        config = config.WithString("suffix", suffix);
    }

    shared_ptr<stringstream> body(new stringstream);
    config.WriteReadable(*body);
    body->seekg(0);

    S3Client s3(getS3Configuration());
    PutObjectRequest req;
    req.SetBucket(m_bucket_name);
    req.SetKey(m_devname + ".volinfo");
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

        auto ecode = error.GetErrorType();
        string message("Failed to write s3://");
        message += m_bucket_name.c_str();
        message += '/';
        message += m_devname.c_str();
        message += ".volinfo: ";
        message += getNameForS3Error(ecode).c_str();

        throw UBDS3Error(message);
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
            memmove(p, p + start_offset, m_block_size - start_offset);
            p += m_block_size - start_offset;
        } else {
            p += m_block_size;
        }
    }

    // While reading the last block, we may need to do a read shorter than the
    // buffer size.
    if (end_offset > 0) {
        unique_ptr<uint8_t[]> tmpbuf(new uint8_t[m_block_size]);
        readBlock(s3, end_block, tmpbuf.get());
        memcpy(p, tmpbuf.get(), end_offset);
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
        unique_ptr<uint8_t[]> tmpbuf(new uint8_t[m_block_size]);
        readBlock(s3, start_block, tmpbuf.get());

        if (start_block == end_block) {
            memcpy(tmpbuf.get() + start_offset, p, length);
            p += length;
        } else {
            memcpy(tmpbuf.get() + start_offset, p,
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
        unique_ptr<uint8_t[]> tmpbuf(new uint8_t[m_block_size]);
        readBlock(s3, end_block, tmpbuf.get());
        memcpy(tmpbuf.get(), p, end_offset);

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

shared_ptr<AWSCredentialsProvider> UBDS3Volume::getS3Credentials() {
    return m_auth;
}

ClientConfiguration UBDS3Volume::getS3Configuration() {
    return m_client_config;
}

static const char *b64alphabet = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

String UBDS3Volume::blockToPrefix(
    uint64_t block_index)
{
    char buf[12];

    for (int i = 0; i < 11; ++i) {
        buf[i] = b64alphabet[block_index & 63];
        block_index >>= 6;
    }

    buf[11] = '\0';

    return String(buf);
}

void UBDS3Volume::readBlock(
    S3Client &s3,
    uint64_t block_id,
    void *buffer)
{
    GetObjectRequest req;
    milliseconds sleep_time(100);
    String key = blockToPrefix(block_id) + m_suffix;
    req.SetBucket(m_bucket_name);
    req.SetKey(key);

    while (true) {
        auto outcome = s3.GetObject(req);

        if (outcome.IsSuccess()) {
            auto &result = outcome.GetResult();
            auto &body = result.GetBody();
            
            body.read(static_cast<char *>(buffer), m_block_size);
            if (body.gcount() != m_block_size) {
                string message("While reading s3://");
                message += m_bucket_name.c_str();
                message += '/';
                message += key.c_str();
                message += ": short read (expected ";
                message += m_block_size;
                message += " bytes, read ";
                message += body.gcount();
                message += ")";

                throw UBDError(message, EIO);
            }

            return;
        }
        
        auto &error = outcome.GetError();
        auto ecode = error.GetErrorType();

        if (ecode == S3Errors::RESOURCE_NOT_FOUND ||
            ecode == S3Errors::NO_SUCH_KEY)
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

        throw UBDError(
            ("While reading s3://" + m_bucket_name + "/" + key + ": " +
             getNameForS3Error(ecode)).c_str(), EIO);
    }
}

void UBDS3Volume::writeBlock(
    S3Client &s3,
    uint64_t block_id,
    const void *buffer)
{
    PutObjectRequest req;
    milliseconds sleep_time(100);
    String key = blockToPrefix(block_id) + m_suffix;

    shared_ptr<stringstream> body(new stringstream);

    body->rdbuf()->pubsetbuf(
        const_cast<char *>(static_cast<char const *>(buffer)), m_block_size);

    req.SetBucket(m_bucket_name);
    req.SetKey(key);
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

        auto ecode = error.GetErrorType();

        throw UBDError(
            ("While writing s3://" + m_bucket_name + "/" + key + ": " +
             getNameForS3Error(ecode)).c_str(), EIO);
    }
}

void UBDS3Volume::trimBlock(
    S3Client &s3,
    uint64_t block_id)
{
    DeleteObjectRequest req;
    milliseconds sleep_time(100);
    String key = blockToPrefix(block_id) + m_suffix;

    req.SetBucket(m_bucket_name);
    req.SetKey(key);

    while (true) {
        auto outcome = s3.DeleteObject(req);
        if (outcome.IsSuccess()) {
            return;
        }
        
        auto &error = outcome.GetError();
        auto ecode = error.GetErrorType();

        if (ecode == S3Errors::RESOURCE_NOT_FOUND ||
            ecode == S3Errors::NO_SUCH_KEY)
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

        throw UBDError(
            ("While deleting s3://" + m_bucket_name + "/" + key + ": " +
             getNameForS3Error(ecode)).c_str(), EIO);
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
    m_ubd(move(other.m_ubd)),
    m_message(),
    m_buffer(move(other.m_buffer)),
    m_buffer_size(other.m_buffer_size),
    m_s3(move(other.m_s3))
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

    cerr << "Thread " << std::this_thread::get_id() << " started" << endl;

    fds[0].fd = m_ubd.getDescriptor();
    fds[0].events = POLLIN;

    while (! m_volume->isStopRequested()) {
        int poll_result = poll(fds, 1, 1000);

        if (poll_result < 0) {
            cerr << "Thread " << std::this_thread::get_id()
                 << " failed to poll: " << strerror(errno) << endl;
            break;
        }

        if (poll_result > 0) {
            // Event ready.
            cerr << "Thread " << std::this_thread::get_id() << " processing a message" << endl;

            try {
                m_message.ubd_size = m_buffer_size;
                m_ubd.getRequest(m_message);
            }
            catch (UBDError const &e) {
                if (e.getError() == ENOMEM) {
                    // Resize the buffer
                    try {
                        cerr << "ENOMEM -- allocated " << m_buffer_size
                             << " bytes but need " << m_message.ubd_size
                             << " bytes" << endl;
                        resizeBuffer(m_message.ubd_size);
                        cerr << "Now have " << m_buffer_size << " bytes" << endl;
                    }
                    catch (bad_alloc &) {
                        cerr << "Thread " << std::this_thread::get_id()
                             << " failed to allocate " << message.ubd_size
                             << " bytes; exiting." << endl;
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
        cerr << "Thread " << std::this_thread::get_id()
             << ": read (first_sector=" << m_message.ubd_first_sector
             << ", nsectors=" << m_message.ubd_nsectors << ")" << endl;

        if (length > m_buffer_size) {
            try {
                resizeBuffer(length);
            }
            catch (bad_alloc &) {
                m_message.ubd_status = -EIO;
                m_ubd.putReply(m_message);
                return;
            }
        }

        m_volume->read(m_s3, offset, m_message.ubd_data, length);
        m_message.ubd_status = m_message.ubd_size = length;
        m_ubd.putReply(m_message);
        break;

    case UBD_MSGTYPE_WRITE:
        cerr << "Thread " << std::this_thread::get_id()
             << ": write (first_sector=" << m_message.ubd_first_sector
             << ", nsectors=" << m_message.ubd_nsectors << ")" << endl;

        m_volume->write(m_s3, offset, m_message.ubd_data, length);
        m_message.ubd_status = length;
        m_message.ubd_size = 0;
        m_ubd.putReply(m_message);
        break;

    case UBD_MSGTYPE_DISCARD:
        cerr << "Thread " << std::this_thread::get_id()
             << ": discard (first_sector=" << m_message.ubd_first_sector
             << ", nsectors=" << m_message.ubd_nsectors << ")" << endl;

        m_volume->trim(m_s3, offset, m_message.ubd_size);
        m_message.ubd_status = length;
        m_message.ubd_size = 0;
        m_ubd.putReply(m_message);
        break;

    case UBD_MSGTYPE_FLUSH:
        cerr << "Thread " << std::this_thread::get_id()
             << ": flush (first_sector=" << m_message.ubd_first_sector
             << ", nsectors=" << m_message.ubd_nsectors << ")" << endl;

        m_message.ubd_status = length;
        m_message.ubd_size = 0;
        m_ubd.putReply(m_message);
        break;

    default:
        cerr << "Thread " << std::this_thread::get_id()
             << ": invalid message " << m_message.ubd_msgtype << endl;
        m_message.ubd_status = -EINVAL;
        m_ubd.putReply(m_message);
        break;
    }
}

void UBDS3Handler::resizeBuffer(uint32_t new_size) {
    unique_ptr<uint8_t[]> new_buffer(new uint8_t[new_size]);

    m_buffer.swap(new_buffer);
    m_buffer_size = new_size;
    m_message.ubd_data = m_buffer.get();
    return;
}

static String getNameForS3Error(S3Errors err) {
    switch (err) {

    case S3Errors::INCOMPLETE_SIGNATURE:
        return String("INCOMPLETE_SIGNATURE");

    case S3Errors::INTERNAL_FAILURE:
        return String("INTERNAL_FAILURE");

    case S3Errors::INVALID_ACTION:
        return String("INVALID_ACTION");

    case S3Errors::INVALID_CLIENT_TOKEN_ID:
        return String("INVALID_CLIENT_TOKEN_ID");

    case S3Errors::INVALID_PARAMETER_COMBINATION:
        return String("INVALID_PARAMETER_COMBINATION");

    case S3Errors::INVALID_QUERY_PARAMETER:
        return String("INVALID_QUERY_PARAMETER");

    case S3Errors::INVALID_PARAMETER_VALUE:
        return String("INVALID_PARAMETER_VALUE");

    case S3Errors::MISSING_ACTION:
        return String("MISSING_ACTION");

    case S3Errors::MISSING_AUTHENTICATION_TOKEN:
        return String("MISSING_AUTHENTICATION_TOKEN");

    case S3Errors::MISSING_PARAMETER:
        return String("MISSING_PARAMETER");

    case S3Errors::OPT_IN_REQUIRED:
        return String("OPT_IN_REQUIRED");

    case S3Errors::REQUEST_EXPIRED:
        return String("REQUEST_EXPIRED");

    case S3Errors::SERVICE_UNAVAILABLE:
        return String("SERVICE_UNAVAILABLE");

    case S3Errors::THROTTLING:
        return String("THROTTLING");

    case S3Errors::VALIDATION:
        return String("VALIDATION");

    case S3Errors::ACCESS_DENIED:
        return String("ACCESS_DENIED");

    case S3Errors::RESOURCE_NOT_FOUND:
        return String("RESOURCE_NOT_FOUND");

    case S3Errors::UNRECOGNIZED_CLIENT:
        return String("UNRECOGNIZED_CLIENT");

    case S3Errors::MALFORMED_QUERY_STRING:
        return String("MALFORMED_QUERY_STRING");

    case S3Errors::NETWORK_CONNECTION:
        return String("NETWORK_CONNECTION");

    case S3Errors::UNKNOWN:
        return String("UNKNOWN");

    case S3Errors::BUCKET_ALREADY_EXISTS:
        return String("BUCKET_ALREADY_EXISTS");

    case S3Errors::BUCKET_ALREADY_OWNED_BY_YOU:
        return String("BUCKET_ALREADY_OWNED_BY_YOU");

    case S3Errors::NO_SUCH_BUCKET:
        return String("NO_SUCH_BUCKET");

    case S3Errors::NO_SUCH_KEY:
        return String("NO_SUCH_KEY");

    case S3Errors::NO_SUCH_UPLOAD:
        return String("NO_SUCH_UPLOAD");

    case S3Errors::OBJECT_ALREADY_IN_ACTIVE_TIER:
        return String("OBJECT_ALREADY_IN_ACTIVE_TIER");

    case S3Errors::OBJECT_NOT_IN_ACTIVE_TIER:
        return String("OBJECT_NOT_IN_ACTIVE_TIER");
    }

    ostringstream msg;
    msg << "Unknown error "
        << static_cast<underlying_type<S3Errors>::type>(err);

    return String(msg.str().c_str());
}

static uint64_t parseSize(
    string const &value,
    string const &parameter_name,
    uint64_t min,
    uint64_t max)
{
    // g++ 4.8.3 -- what's in Amazon Linux 2016.03 -- doesn't support
    // regular expression properly, so we have to use this manual parse
    // hack.
    char const *p = value.c_str();
    char *endptr;

    uint64_t result = strtoull(p, &endptr, 0);
    if (*endptr == '\0') {
        if (endptr == p) {
            // Nothing matched.
            throw domain_error("Invalid " + parameter_name + " value: " +
                               value);
        }
        
        // No suffix.
        return result;
    }

    p = endptr;
    while (isspace(*p)) {
        ++p;
    }

    string suffix = p;
    if      (suffix == "k" || suffix == "kiB") { result <<= 10; }
    else if (suffix == "M" || suffix == "MiB") { result <<= 20; }
    else if (suffix == "G" || suffix == "GiB") { result <<= 30; }
    else if (suffix == "T" || suffix == "TiB") { result <<= 40; }
    else if (suffix == "P" || suffix == "PiB") { result <<= 50; }
    else if (suffix == "E" || suffix == "EiB") { result <<= 60; }
    else if (suffix != "") {
        // Illegal suffix.
        throw domain_error(
            "Invalid " + parameter_name + " value: " + value);
    }

    if (result < min) {
        throw domain_error(
            "Invalid " + parameter_name + " value (must be at least " +
            to_string(min) + ": " + value);
    }

    if (result > max) {
        throw domain_error(
            "Invalid " + parameter_name + " value (cannot be greater than " +
            to_string(max) + ": " + value);
    }

    return result;
}

static void usage(ostream &os) {
    os << ("\
Usage: ubds3 [options] <devname>\n\
\n\
Create a block device backed by S3.  <devname> specifies the name of the\n\
block device.\n\
\n\
General options:\n\
    --bucket <name> | -b <name>\n\
        Use the specified S3 bucket.  This is required.\n\
\n\
    --profile <name> | -p <name>\n\
        Use the specified AWS profile for credentials.  This is stored in\n\
        ~/.boto.\n\
\n\
    --region <name> | -r <name>\n\
        Connect to the S3 endpoint in the specified region.  This is required.\n\
\n\
Creating a new block device:\n\
    --create\n\
        Required to create a new block device.  This creates an object\n\
        in the S3 bucket named <devname>.volinfo storing the below\n\
        configuration details.\n\
\n\
    --encryption <policy> | -e <policy>\n\
        Use the specified encryption policy.  Valid policies are:\n\
           ss3-s3       S3-managed server-side encryption.\n\
\n\
    --block-size <value>{k,M,G} | -B <value>{k,M,G}\n\
        Use <value> as the size of block in S3.  This defaults to 4k.  The\n\
        block size must be between 512 and 1G and must be a power of 2.\n\
        The k, M, and G suffixes are base-2 (k == 2**10, M == 2**20,\n\
        G == 2 ** 30).\n\
\n\
    --policy <policy> | -p <policy>\n\
        Use the specified ACL policy.  This defaults to 'private'.  Valid\n\
        values are 'private', 'public-read', 'public-read-write' (DANGEROUS),\n\
        'authenticated-read', 'bucket-owner-read', 'bucket-owner-full-control'.\n\
\n\
    --storage-class <class> | -C <class>\n\
        Store objects with the given storage class.  This defaults to\n\
        'standard'.  Valid values are 'standard', 'reduced-redundancy', and\n\
        'infrequently-accessed'.\n\
\n\
    --size <value>{k,M,G,T,P,E} | -s <value>{k,M,G,T,P,E}\n\
        Specifies the size of the volume.  This is required.  This must be a\n\
        multiple of the block size; the maximum size is 16 EiB (2 ** 64 bytes).\n\
        The suffixes are base-2.\n\
\n\
    --suffix <string> | -S <string>\n\
        Append the given suffix to object names.  This defaults to .<devname>.\n\
        Object names are suffixed rather than prefixed to improve performance\n\
        (due to the way S3 partitions the bucket keyspace).\n\
\n\
    --threads <int>\n\
        Create the specified number of threads to handle requests.\n\
");
    os.flush();
}
