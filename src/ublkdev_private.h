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

/** Status: Not registered */
#define UBD_STATUS_IDLE             0

/** Status: Waiting for add_disk to be called */
#define UBD_STATUS_REGISTERING      1

/** Status: Running, but add_disk() hasn't returned.
 *
 *  The disk can't be unregistered in this state.
 */
#define UBD_STATUS_ADDING_RUNNING   2

/** Status: Running. */
#define UBD_STATUS_RUNNING          3

/** Status: Unregistiering -- waiting for commands to finish */
#define UBD_STATUS_UNREGISTERING    4

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

    /** Wait queue for notifying ubdctl_read when a new message is available. */
    wait_queue_head_t ctl_outgoing_wait;

    /** Pending message being read from the control endpoint. */
    struct ubd_incoming_message ctl_incoming;

    /** A list of requests waiting to be handled or replied to. */
    struct request_queue *blk_pending;

    /** The thread for handling block device requests. */
    struct task_struct *thread;

    /** Indicates completion of the thread. */
    struct completion thread_complete;

    /** Status of this device */
    uint32_t status;

    /** Flags passed when registering. */
    uint32_t flags;
};

#endif /* UBLKDEV_PRIVATE_H */
