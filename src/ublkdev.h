/** @file   ublkdev.h
 *  @brief  General header for UBD.
 */

#ifndef UBLKDEV_H
#define UBLKDEV_H

#include <linux/types.h>

#define UBLKDEV_SECTOR_SIZE         512

#define UBLKDEV_MSGTYPE_READ        0
#define UBLKDEV_MSGTYPE_WRITE       1
#define UBLKDEV_MSGTYPE_REGISTER    2
#define UBLKDEV_MSGTYPE_DEREGISTER  3

struct ublkdev_msghdr {
    uint64_t reply : 1;
    uint64_t msgType : 7;
    uint64_t msgId : 56;
};

struct ublkdev_rblock {
    uint64_t startingSector;
    uint64_t nSectors;
};

struct ublkdev_wblock {
    uint64_t startingSector;
    uint64_t nSectors;
    char *data;
};

struct ublkdev_readmsg {
    struct ublkdev_msghdr header;
    uint64_t nBlocks;
    struct ublkdev_rblock *block;
};

struct ublkdev_writemsg {
    struct ublkdev_msghdr header;
    uint64_t nBlocks;
    struct ublkdev_wblock *block;
};

struct ublkdev_registermsg {
    struct ublkdev_msghdr header;
    
};

#endif /* UBLKDEV_H */

/* Local variables: */
/* mode: C */
/* indent-tabs-mode: nil */
/* tab-width: 8 */
/* End: */
/* vi: set expandtab tabstop=8 */
