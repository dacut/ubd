/** @file   ublkdev_private.h
 *  @brief  Kernel-only header for UBD.
 */

#ifndef UBLKDEV_PRIVATE_H
#define UBLKDEV_PRIVATE_H

#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/genhd.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include "ublkdev.h"

/** Initial capacity for holding an incoming message. */
#define UBD_INITIAL_MESSAGE_CAPACITY        ((size_t) (128u << 10)) /* 128 kB */

/** Maximum number of pending messages.
 *
 *  FIXME: Make this user-configurable.
 */
#define UBD_MAX_TAGS                64

/** Status: Registering; waiting for add_disk() call to start.
 *
 *  Cannot be combined with any other flags.
 */
#define UBD_STATUS_REGISTERING      0x01

/** Status: Add disk call in progress.
 *
 *  Cannot be combined with UBD_STATUS_REGISTERING or UBD_STATUS_UNREGISTERING.
 */
#define UBD_STATUS_ADDING           0x02

/** Status: Running.
 *
 *  Cannot be combined with UBD_STATUS_REGISTERING or UBD_STATUS_UNREGISTERING.
 */
#define UBD_STATUS_RUNNING          0x04

/** Status: Unregistiering -- waiting for commands to finish.
 *
 *  Cannot be combined with UBD_STATUS_REGISTERING or UBD_STATUS_RUNNING.
 */
#define UBD_STATUS_UNREGISTERING    0x08

/** Status: Block device opened.
 *
 *  Cannot be combined with UBD_STATUS_REGISTERING.
 */
#define UBD_STATUS_OPENED           0x10

/** Indicates that the device is in a transitory state. */
#define UBD_STATUS_TRANSIENT \
    (UBD_STATUS_REGISTERING | UBD_STATUS_ADDING | UBD_STATUS_UNREGISTERING)

/** Structure connecting a control (character device) endpoint to a block
 *  endpoint.
 */
struct ublkdev {
    /** List structure for putting this in a linked list. */
    struct list_head list;
    
    /** Disk structure for this block device.
     *
     *  If NULL, a block device has not yet been registered.
     */
    struct gendisk *disk;

    /** Work structure for scheduling add_disk() asynchronously. */
    struct work_struct add_disk_work;

    /** A list of requests waiting to be delivered.
     */
    struct request_queue *pending_delivery;

    /** An array of requests waiting for replies.
     *
     *  The index of the array corresponds to the tag delivered to the handler.
     */
    struct request **pending_reply;

    /** The maximum number of pending replies. */
    uint32_t max_pending_reply;

    /** Number of messages awaiting a reply. */
    uint32_t n_pending_reply;

    /** Status of this device.
     *
     *  @c status_wait.lock must be held to read or write this.
     */
    uint32_t status;

    /** Wait queue for notifying anyone waiting on a status change. */
    wait_queue_head_t status_wait;

    /** Flags passed when registering. */
    uint32_t flags;
};

#endif /* UBLKDEV_PRIVATE_H */
