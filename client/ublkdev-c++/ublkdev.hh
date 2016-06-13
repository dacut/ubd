#ifndef UBLKDEV_HH
#define UBLKDEV_HH

#include <cstring>
#include <stdexcept>
#include <string>

#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" {
#include <ublkdev.h>
}

#ifndef UBD_IOC_MAGIC
#error No UBD_IOC_MAGIC defined
#endif

class UBDError : public std::runtime_error {
public:
    inline UBDError(std::string const &what_arg) :
        std::runtime_error(what_arg), m_error(0) { }

    inline UBDError(std::string const &what_arg, int error) :
        std::runtime_error(what_arg), m_error(error) { }

    inline UBDError(int error) :
        std::runtime_error(std::string(std::strerror(error))),
        m_error(error) { }
    
#if __cplusplus >= 201103L /* C++11 */
    inline UBDError(char const *what_arg) :
        std::runtime_error(what_arg), m_error(0) { }
        
    inline UBDError(char const *what_arg, int error) :
        std::runtime_error(what_arg), m_error(error) { }
#endif /* C++11 */
            
    inline int getError() const { return m_error; }
    
private:
    const int m_error;
};

class UserBlockDevice {
public:
    explicit UserBlockDevice(
        char const *control_endpoint="/dev/ubdctl");
    UserBlockDevice(UserBlockDevice &&other);
    
    virtual ~UserBlockDevice();

    virtual struct ubd_info registerEndpoint(
        const char *name,
        ssize_t n_sectors,
        bool read_only);

    virtual void unregisterEndpoint(
        uint32_t major);

    virtual int getCount();

    virtual struct ubd_info describe(
        uint32_t index);

    virtual void tie(
        uint32_t major);

    virtual void getRequest(
        struct ubd_message &result /* IN/OUT */);

    virtual void putReply(
        struct ubd_message const &reply /* IN */);

    virtual void debug();

    int getDescriptor() { return m_control; }


private:
    UserBlockDevice(UserBlockDevice const &) = delete;
    UserBlockDevice operator = (UserBlockDevice const &) = delete;

    int m_control;
};

#endif /* UBLKDEV_HH */
