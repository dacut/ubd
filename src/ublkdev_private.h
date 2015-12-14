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

/** Initial capacity of pending replies. */
#define UBD_INITIAL_PENDING_REPLY_CAPACITY 64
#define UBD_INITIAL_PENDING_REPLY_SIZE \
    ((size_t) sizeof(void *) * UBD_INITIAL_PENDING_REPLY_CAPACITY)

/** Status: Registering; waiting for add_disk() call to start. */
#define UBD_STATUS_REGISTERING      1

/** Status: Add disk call in progress. */
#define UBD_STATUS_ADDING           2

/** Status: Running. */
#define UBD_STATUS_RUNNING          3

/** Status: Unregistering -- waiting for commands to finish. */
#define UBD_STATUS_UNREGISTERING    4

/** Status: Terminated -- waiting for control endpoints to untie. */
#define UBD_STATUS_TERMINATED       5

/** Structure connecting a control (character device) endpoint to a block
 *  endpoint.
 */
struct ublkdev {
    /** List structure for putting this in a linked list. */
    struct list_head list;
    
    /** Request queue from the block subsystem. */
    struct request_queue *in_flight;

    /** Disk structure for this block device.
     *
     *  If NULL, a block device has not yet been registered.
     */
    struct gendisk *disk;

    /** Work structure for scheduling add_disk() asynchronously. */
    struct work_struct add_disk_work;

    /** List of requests waiting to be delivered to the handler. 
     *
     *  We use @c request->special as a pointer to the next request in
     *  the list rather than use Linux's @c list_head so we don't have
     *  to allocate/deallocate another structure to wrap requests.
     *  @par
     *  @c wait.lock must be held to read or modify this.
     */
    struct request *pending_delivery_head;

    /** Last request in the list of requests waiting to be delivered.
     *
     *  This allows us to append a request in O(1) time.
     *  @par
     *  @c wait.lock must be held to read or modify this.
     */
    struct request *pending_delivery_tail;

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
     *  @c wait.lock must be held to read or write this.
     */
    uint32_t status;

    /** Wait queue for notifying anyone waiting on a change. */
    wait_queue_head_t wait;

    /** Flags passed when registering. */
    uint32_t flags;

    /** Number of control enpoints tied to this device. */
    uint32_t n_control_handles;

    /** Number of block filehandles open. */
    uint32_t n_block_handles;
};

/** Emit a debug message. */
#define ubd_debug(fmt, ...)                                             \
    printk(KERN_DEBUG "[%d] %s %s:%d " fmt "\n", current->pid,          \
           __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)

/** Emit an info message. */
#define ubd_info(fmt, ...)                                              \
    printk(KERN_INFO "[%d] %s %s:%d " fmt "\n", current->pid,           \
           __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)

/** Emit a notice message. */
#define ubd_notice(fmt, ...)                                            \
    printk(KERN_NOTICE "[%d] %s %s:%d " fmt "\n", current->pid,         \
           __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)

/** Emit a warning message. */
#define ubd_warning(fmt, ...)                                           \
    printk(KERN_WARNING "[%d] %s %s:%d " fmt "\n", current->pid,        \
           __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)

/** Emit an error message. */
#define ubd_err(fmt, ...)                                               \
    printk(KERN_ERR "[%d] %s %s:%d " fmt "\n", current->pid,            \
           __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)

#endif /* UBLKDEV_PRIVATE_H */
