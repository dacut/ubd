/** @file   ublkdev.h
 *  @brief  Module header for UBD.
 */

#ifndef UBLKDEV_H
#define UBLKDEV_H

#include <linux/fs.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

#define UBLKDEV_KERNEL_VERSION          1
#define UBLKDEV_KERNEL_MINOR_VERSION    0
#define UBLKDEV_MODULE_VERSION          "1.0"

struct ublkdev_request;
struct ublkdev;

struct ublkdev_request {
    int id;

    struct ublkdev *dev;
    struct ublkdev_request *next;

    struct request *req;
    char *serialized_request;
    int serialized_request_size;
    const char *serialized_request_readp;

    char *serialized_response;
    int serialized_response_size;
    char *serialized_response_writep;
};

/** Structure managing a block device. */
struct ublkdev {
    struct ublkdev_transfer *request_head;
    struct ublkdev_transfer *request_tail;
    struct ublkdev_transfer *response_head;
    struct ublkdev_transfer *response_tail;
    atomic_t next_request_id;
    spinlock_t lock;
};

#define ubd_w32(ptr, data)                      \
    do {                                        \
        memcpy((ptr), (data), 4);               \
        (ptr) += 4;                             \
    } while (0)

#define ubd_w64(ptr, data)                      \
    do {                                        \
        memcpy((ptr), (data), 8);               \
        (ptr) += 8;                             \
    } while (0)

#endif /* UBLKDEV_H */

/* Local variables: */
/* mode: C */
/* indent-tabs-mode: nil */
/* tab-width: 8 */
/* End: */
/* vi: set expandtab tabstop=8 */
