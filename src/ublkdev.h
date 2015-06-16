/** @file   ublkdev.h
 *  @brief  General (userland) header for userspace block devices.
 */

#ifndef UBLKDEV_H
#define UBLKDEV_H

#include <linux/genhd.h>
#include <linux/types.h>

/** ubd ioctl magic number -- seems unused */
#define UBD_IOC_MAGIC           0xbf

/** ioctl: register block device. */
#define UBD_IOCREGISTER     _IOWR(UBD_IOC_MAGIC, 0xa0, struct ubd_info)

/** ioctl: unregister block device. */
#define UBD_IOCUNREGISTER   _IO(UBD_IOC_MAGIC, 0xa1)

/** ioctl: get registered block device count. */
#define UBD_IOCGETCOUNT    _IOR(UBD_IOC_MAGIC, 0xa2, int)

/** ioctl: describe block device. */
#define UBD_IOCDESCRIBE     _IOWR(UBD_IOC_MAGIC, 0xa3, struct ubd_describe)

/** ubd_flags: device is read only. */
#define UBD_FL_READ_ONLY    0x00000001

/** ubd_flags: device is a removable disk. */
#define UBD_FL_REMOVABLE    0x00000002

/** Information about a userspace block device. */
struct ubd_info {
    /** Device name */
    char ubd_name[DISK_NAME_LEN];

    /** Device flags */
    uint32_t ubd_flags;

    /** Device capacity in 512-byte sectors. */
    uint64_t ubd_nsectors;

    /** Major number */
    uint32_t ubd_major;

    /** Minor number */
    uint32_t ubd_minor;
};

struct ubd_describe {
    /** In: the index to return. */
    size_t ubd_index;

    /** Out: The resulting ubd_info data. */
    struct ubd_info ubd_info;
};

/** ubd_msgtype code for a read request. */
#define UBD_MSGTYPE_READ_REQUEST            0

/** ubd_msgtype code for a write request. */
#define UBD_MSGTYPE_WRITE_REQUEST           1

/** ubd_msgtype code for a discard (trim) request. */
#define UBD_MSGTYPE_DISCARD_REQUEST         2

/** ubd_msgtype code for a read reply. */
#define UBD_MSGTYPE_READ_REPLY              0x80000000

/** ubd_msgtype code for a write reply. */
#define UBD_MSGTYPE_WRITE_REPLY             0x80000001

/** ubd_msgtype code for a discard (trim) request. */
#define UBD_MSGTYPE_DISCARD_REPLY           0x80000002

/** Maximum size of a UBD message */
#define UBD_MAX_MESSAGE_SIZE                ((size_t) (4 << 20))   /* 4 MB */

/** Common header for all UBD control messages.
 *  
 *  Requests are made by the driver and sent to userspace upon a read()
 *  on the control endpoint.  Replies are sent from userspace through a
 *  write() on the control endpoint.
 */
struct ubd_header {
    /** The type of this message. */
    uint32_t ubd_msgtype;
    
    /** Size of the entire message in bytes. */
    uint32_t ubd_size;

    /** Tag to match up requests with replies. */
    uint32_t ubd_tag;
};

struct ubd_request {
    /** Common header */
    struct ubd_header ubd_header;
    
    /** Number of 512-byte sectors to read. */
    uint32_t ubd_nsectors;

    /** First sector of the request. */
    uint64_t ubd_first_sector;

    /** Data for this request. */
    char ubd_data[0];
};

struct ubd_reply {
    /** Common header */
    struct ubd_header ubd_header;

    /** Size in 512-byte sectors of data written, or (if negative) an error
     *  code.
     */
    int32_t ubd_status;

    /** Data for this reply. */
    char ubd_data[0];
};

#endif /* UBLKDEV_H */

/* Local variables: */
/* mode: C */
/* indent-tabs-mode: nil */
/* tab-width: 8 */
/* End: */
/* vi: set expandtab tabstop=8 */
