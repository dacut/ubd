/** @file   ublkdev_private.h
 *  @brief  Kernel-only header for UBD.
 */

#ifndef UBLKDEV_PRIVATE_H
#define UBLKDEV_PRIVATE_H

#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/genhd.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include "ublkdev.h"

/** Initial capacity for holding an incoming message. */
#define UBD_INITIAL_MESSAGE_CAPACITY        ((size_t) (128u << 10)) /* 128 kB */

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

/** Wraps a UBD message in a Linux linked list.
 */
struct ubd_outgoing_message {
    /** For managing this in a linked list. */
    struct list_head list;

    /** How much of the message has been written to userspace. */
    uint64_t n_written;

    /** The request */
    struct ubd_request *request;
};

struct ubd_incoming_message {
    /** How much of the message has been read from userspace. */
    uint32_t n_read;

    /** The capacity of the message structure. */
    uint32_t capacity;

    /** The reply */
    struct ubd_reply *reply;
};

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

    /** Lock for manipulating this data structure. */
    spinlock_t lock;

    /** Work structure for scheduling add_disk() asynchronously. */
    struct work_struct add_disk_work;

    /** List of messages waiting to be sent to the control endpoint. */
    struct list_head ctl_outgoing_head;

    /** Message currently being written. */
    struct ubd_outgoing_message *ctl_current_outgoing;

    /** Wait queue for notifying ubdctl_read when a new message is available.
     */
    wait_queue_head_t ctl_outgoing_wait;

    /** Pending message being read from the control endpoint. */
    struct ubd_incoming_message ctl_incoming;

    /** A list of requests waiting to be handled or replied to. */
    struct request_queue *blk_pending;

    /** Status of this device.  The lock must be held to read or write this. */
    uint32_t status;

    /** Wait queue for notifying anyone waiting on a status change. */
    wait_queue_head_t status_wait;

    /** Flags passed when registering. */
    uint32_t flags;
};

#endif /* UBLKDEV_PRIVATE_H */
