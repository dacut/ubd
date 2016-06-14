#include <string>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ublkdev.hh>

using std::string;

UserBlockDevice::UserBlockDevice(
    char const *control_endpoint) :
    m_control(open(control_endpoint, O_RDWR | O_SYNC | O_NONBLOCK))
{
    if (m_control < 0) {
        string msg("Unable to open ");

        msg += control_endpoint;
        msg += ": ";
        msg += strerror(errno);
        
        throw UBDError(msg, errno);
    }

    return;
}

UserBlockDevice::UserBlockDevice(
    UserBlockDevice &&other) :
    m_control(other.m_control)
{
    other.m_control = -1;
    return;
}

UserBlockDevice::~UserBlockDevice()
{
    if (m_control != -1) {
        close(m_control);
    }

    return;
}

struct ubd_info UserBlockDevice::registerEndpoint(
        const char *name,
        ssize_t n_sectors,
        bool read_only)
{
    struct ubd_info ui;
    strncpy(ui.ubd_name, name, UBD_DISK_NAME_LEN);
    ui.ubd_flags = (read_only ? UBD_FL_READ_ONLY : 0u);
    ui.ubd_major = 0u;
    ui.ubd_nsectors = n_sectors;

    if (ioctl(m_control, UBD_IOCREGISTER, &ui) != 0) {
        throw UBDError(errno);
    }

    return ui;
}

void UserBlockDevice::unregisterEndpoint(
    uint32_t major)
{
    if (ioctl(m_control, UBD_IOCUNREGISTER, major) != 0) {
        throw UBDError(errno);
    }

    return;
}

int UserBlockDevice::getCount() {
    int result = ioctl(m_control, UBD_IOCGETCOUNT);
    if (result < 0) {
        throw UBDError(errno);
    }

    return result;
}

struct ubd_info UserBlockDevice::describe(
    uint32_t index)
{
    struct ubd_describe desc;
    desc.ubd_index = index;
    
    if (ioctl(m_control, UBD_IOCDESCRIBE, &desc) != 0) {
        throw UBDError(errno);
    }

    return desc.ubd_info;
}

void UserBlockDevice::tie(
    uint32_t major)
{
    if (ioctl(m_control, UBD_IOCTIE, major) != 0) {
        throw UBDError(errno);
    }

    return;
}

void UserBlockDevice::getRequest(
    struct ubd_message &result)
{
    if (ioctl(m_control, UBD_IOCGETREQUEST, &result) != 0) {
        throw UBDError(errno);
    }

    return;
}

void UserBlockDevice::putReply(
    struct ubd_message const &reply)
{
    if (ioctl(m_control, UBD_IOCPUTREPLY, &reply) != 0) {
        throw UBDError(errno);
    }

    return;
}

void UserBlockDevice::debug()
{
    if (ioctl(m_control, UBD_IOCDEBUG) != 0) {
        throw UBDError(errno);
    }

    return;
}

