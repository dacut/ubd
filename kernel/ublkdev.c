/** @file   ublkdev.c
 *  @brief
 */

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "ublkdev_private.h"

MODULE_AUTHOR("dacut@kanga.org");
MODULE_DESCRIPTION("Userspace block devices");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

/* ***** Driver global functions and variables. ***** */

/** List of block devices allocated. */
LIST_HEAD(ubd_devices);

/** Lock for ubd_devices. */
DEFINE_MUTEX(ubd_devices_lock);

/** Initialize the driver. */
static int __init ubd_init(void);

/** Clean up the driver. */
static void __exit ubd_exit(void);

/** Actual work of tearing down the driver.
 *  This allows the logic to be shared with ubd_init if initialization fails.
 *  Linux doesn't like __init functions calling __exit functions.
 */
static void ubd_teardown(void);

/* The rq_for_each_segment macro changed incompatibly between Linux 3.13 and
   3.14.  This takes care of the differences. */
#if KERNEL_VERSION < 3 || (KERNEL_VERSION == 3 && KERNEL_PATCHLEVEL < 14)
typedef struct bio_vec *ubd_bvec_iter_t;
#define ubd_bvptr(bvec) (bvec)
#define ubd_first_sector(iter) ((iter).bio->bi_sector)
#else
typedef struct bio_vec ubd_bvec_iter_t;
#define ubd_bvptr(bvec) (&(bvec))
#define ubd_first_sector(iter) ((iter).iter.bi_sector)
#endif

/* blk_queue_init_tags added an argument with Linux 4.0. */
#if KERNEL_VERSION >= 4
#define ubd_blk_queue_init_tags(queue, depth, tags)                     \
    blk_queue_init_tags((queue), (depth), (tags), BLK_TAG_ALLOC_FIFO)
#else
#define ubd_blk_queue_init_tags(queue, depth, tags)     \
    blk_queue_init_tags((queue), (depth), (tags))
#endif

/** Retreive a block device given its major number.
 *
 *  @c ubd_devices_lock must be held while invoking this function.
 *
 *  @param  major   The major number of the device to return.
 *  @return The @c ublkdev object corresponding to the major number, or
 *          @c NULL if a corresponding device does not exist.
 */
static struct ublkdev *ubd_find_device_by_major(uint32_t major) {
    struct list_head *el;
    
    BUG_ON(! mutex_is_locked(&ubd_devices_lock));

    list_for_each(el, &ubd_devices) {
        struct ublkdev *dev = list_entry(el, struct ublkdev, list);
        if (dev->disk != NULL && dev->disk->major == major) {
            return dev;
        }
    }

    return NULL;
}

/** Convert a message type to a string.
 *
 *  @param  msgtype     The message type to decode.
 *  @param  buffer      A buffer to write a dynamic message to.  This must be
 *                      at least 32 bytes.
 */
static char const *ubd_msgtype_to_string(uint32_t msgtype, char *buffer) {
    switch (msgtype) {
    case UBD_MSGTYPE_READ: return "UBD_MSGTYPE_READ";
    case UBD_MSGTYPE_WRITE: return "UBD_MSGTYPE_WRITE";
    case UBD_MSGTYPE_DISCARD: return "UBD_MSGTYPE_DISCARD";
    case UBD_MSGTYPE_FLUSH: return "UBD_MSGTYPE_FLUSH";
    default:
        sprintf(buffer, "Unknown message type %d", msgtype);
        return buffer;
    }
}

/** Free a block device.
 *
 *  The device must be terminated.  No locks may be held.
 *
 *  @param  dev     The device to free.
 */
static void ubd_free_ublkdev(struct ublkdev *dev) {
    BUG_ON(dev == NULL);
    BUG_ON(ACCESS_ONCE(dev->status) != UBD_STATUS_TERMINATED);

    blk_cleanup_queue(dev->in_flight);
    del_gendisk(dev->disk);
    kfree(dev->pending_reply);
    kfree(dev);

    return;
}

/** Fail all requests on a block endpoint.
 *
 *  The device lock must be held.
 *
 *  @param  dev         The device to fail requests on.
 *  @param  lock_flags  Flags saved from the device lock.
 */
static void ubd_fail_requests(struct ublkdev *dev, unsigned long lock_flags) {
    struct request *req;
    bool unfinished;
    size_t i;

    /* Increase the control handle count while unregistering so we don't
     * release the structure while we're still in this routine.
     */
    ACCESS_ONCE(dev->n_control_handles) =
        ACCESS_ONCE(dev->n_control_handles) + 1;

    /* Don't deliver any messages pending delivery. */
    while ((req = ACCESS_ONCE(dev->pending_delivery_head)) != NULL) {
        /* Pop the top of the pending_delivery list.  The special field
         * is used to point to the next request.
         */
        struct request *next_request;
        
        next_request = (struct request *) ACCESS_ONCE(req->special);
        ACCESS_ONCE(dev->pending_delivery_head) = next_request;

        if (next_request == NULL) {
            /* Removed the last item; axe the tail. */
            ACCESS_ONCE(dev->pending_delivery_tail) = NULL;
        }

        unfinished = blk_end_request_err(req, -EIO);
        BUG_ON(unfinished);
    }

    /* Fail any messages awaiting a reply. */
    for (i = 0; i < dev->max_pending_reply; ++i) {
        if ((req = ACCESS_ONCE(dev->pending_reply[i])) != NULL) {
            uint32_t n_pending_reply = ACCESS_ONCE(dev->n_pending_reply);
            BUG_ON(n_pending_reply == 0);

            --n_pending_reply;
            ACCESS_ONCE(dev->n_pending_reply) = n_pending_reply;
            ACCESS_ONCE(dev->pending_reply[i]) = NULL;
            
            unfinished = blk_end_request_err(req, -EIO);
            BUG_ON(unfinished);
        }
    }

    /* Decrement the control handle count we held earlier. */
    ACCESS_ONCE(dev->n_control_handles) = 
        ACCESS_ONCE(dev->n_control_handles) - 1;
    return;
}

/* ***** Control endpoint functions ***** */

/** Handler for open() on the control endpoint. */
static int ubdctl_open(struct inode *inode, struct file *filp);

/** Handler for close() on the control endpoint. */
static int ubdctl_release(struct inode *inode, struct file *filp);

/** Handler for read() on the control endpoint. */
static ssize_t ubdctl_read(struct file *filp, char *buffer, size_t size,
                           loff_t *offp);

/** Handler for write() on the control endpoint. */
static ssize_t ubdctl_write(struct file *filp, const char *buffer, size_t size,
                            loff_t *offp);

/** Handler for poll() on the control endpoint. */
static unsigned int ubdctl_poll(struct file *filp, poll_table *wait);

/** Handler for ioctl() on the control endpoint. */
static long ubdctl_ioctl(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Register a new userspace block device. */
static long ubdctl_ioctl_register(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Unregister a userspace block device. */
static long ubdctl_ioctl_unregister(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Get the count of userspace block devices. */
static long ubdctl_ioctl_getcount(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Get a description of a userspace block device. */
static long ubdctl_ioctl_describe(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Tie this control endpoint to the request stream of a particular
 *  userspace block device.
 */
static long ubdctl_ioctl_tie(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Send a request from the block endpoint to the control endpoint. */
static long ubdctl_ioctl_getrequest(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Handle a reply from the control endpoint back to the block endpoint. */
static long ubdctl_ioctl_putreply(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Print debugging information to the console. */
static long ubdctl_ioctl_debug(
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

/** Control endpoint file operations. */
static struct file_operations ubdctl_fops = {
    .owner = THIS_MODULE,
    .llseek = no_llseek,
    .read = ubdctl_read,
    .write = ubdctl_write,
    .poll = ubdctl_poll,
    .unlocked_ioctl = ubdctl_ioctl,
    .open = ubdctl_open,
    .release = ubdctl_release,
};

/** Control endpoint device descriptor. */
static struct miscdevice ubdctl_miscdevice = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "ubdctl",
    .fops = &ubdctl_fops,
};

/* ***** Block endpoint functions ***** */

/** Handler for gendisk device node name query. */
static char *ubdblk_get_devnode(struct gendisk *gd, umode_t *mode);

/** Handler for open() on the block endpoint. */
static int ubdblk_open(struct block_device *blkdev, fmode_t mode);

/** Handler for close() on the block endpoint. */
static void ubdblk_release(struct gendisk *disk, fmode_t mode);

/** Handler for ioctl() on the block endpoint. */
static int ubdblk_ioctl(struct block_device *blkdev, fmode_t mode,
                        unsigned int cmd, unsigned long data);

/** Handler for event queries (e.g. media change) from the kernel on the block
 *  endpoint.
 */
static unsigned int ubdblk_check_events(struct gendisk *gd,
                                        unsigned int clearing);

/** Handler for disk revalidation from the kernel on the block endpoint when
    the media has been changed. */
static int ubdblk_revalidate_disk(struct gendisk *gd);

/** Start the disk associated with a handler.
 *
 *  This is called asynchronously in a workqueue.
 */
static void ubdblk_add_disk(struct work_struct *work);

/** Handle a request from the block endpoint. */
static void ubdblk_handle_request(struct request_queue *rq);

/** Handle a filesystem request from the block endpoint. */
static void ubdblk_handle_fs_request(struct ublkdev *dev, struct request *r);


/** Block endpoint functions. */
static struct block_device_operations ubdblk_fops = {
    .owner = THIS_MODULE,
    .open = ubdblk_open,
    .release = ubdblk_release,
    .ioctl = ubdblk_ioctl,
    .check_events = ubdblk_check_events,
    .revalidate_disk = ubdblk_revalidate_disk,
};

/* ***** Implementation ***** */

static int __init ubd_init(void) {
    int result;

    /* Register the control endpoint */
    if ((result = misc_register(&ubdctl_miscdevice)) < 0) {
        ubd_err("Failed to register misc device: error code %d", result);
        goto error;
    }

    ubd_debug("ubdctl registered as device %d:%d", MISC_MAJOR,
              ubdctl_miscdevice.minor);

    return 0;

error:
    ubd_teardown();

    return result;
}


static void __exit ubd_exit(void) {
    ubd_teardown();
    return;
}

static void ubd_teardown(void) {
    struct list_head *el, *next;

    mutex_lock(&ubd_devices_lock);
    list_for_each_safe(el, next, &ubd_devices) {
        struct ublkdev *dev = list_entry(el, struct ublkdev, list);
        struct gendisk *disk;
        unsigned long lock_flags;
        uint32_t status;

        spin_lock_irqsave(&dev->wait.lock, lock_flags);

        // If we're still registering, wait for add_disk to finish.
        wait_event_lock_irq(
            dev->wait,
            (status = ACCESS_ONCE(dev->status)) != UBD_STATUS_REGISTERING,
            dev->wait.lock);

        // We shouldn't have even seen the device if it's terminating.
        BUG_ON(status != UBD_STATUS_RUNNING);
        disk = ACCESS_ONCE(dev->disk);
        BUG_ON(disk == NULL);

        ubd_debug("Unregistering device \"%s\".", disk->disk_name);
        
        // Unregister this device.
        ACCESS_ONCE(dev->status) = UBD_STATUS_TERMINATED;
            
        // Remove this device from the list of devices.
        list_del(el);

        ubd_debug("Failing requests.");
        
        // Fail all requests on this device.
        ubd_fail_requests(dev, lock_flags);

        ubd_debug("Notifying waiters about status change.");

        // Notify anyone waiting on a status change.
        smp_wmb();
        wake_up_all_locked(&dev->wait);

        ubd_debug("Waiting for handles to vanish (%d control, %d block).",
                  ACCESS_ONCE(dev->n_control_handles),
                  ACCESS_ONCE(dev->n_block_handles));

        /* Wait for all handles to this device to close. */
        wait_event_lock_irq(
            dev->wait,
            ACCESS_ONCE(dev->n_control_handles) == 0 &&
            ACCESS_ONCE(dev->n_block_handles) == 0,
            dev->wait.lock);
            
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        
        ubd_free_ublkdev(dev);
    }
    mutex_unlock(&ubd_devices_lock);

    if (ubdctl_miscdevice.minor != MISC_DYNAMIC_MINOR) {
        ubd_debug("Unregistering ubdctl device %d:%d", MISC_MAJOR,
                  ubdctl_miscdevice.minor);
        misc_deregister(&ubdctl_miscdevice);
    }

    return;
}

module_init(ubd_init);
module_exit(ubd_exit);

static int ubdctl_open(struct inode *inode, struct file *filp) {
    /* Initially unassociated with a device. */
    filp->private_data = NULL;
    return 0;
}

static int ubdctl_release(struct inode *inode, struct file *filp) {
    struct ublkdev *dev = filp->private_data;
    unsigned long lock_flags;
    uint32_t n_control_handles;

    if (dev != NULL) {
        spin_lock_irqsave(&dev->wait.lock, lock_flags);

        // Decrement the control handle count and possibly free up the
        // structure.
        n_control_handles = ACCESS_ONCE(dev->n_control_handles) - 1;
        ACCESS_ONCE(dev->n_control_handles) = n_control_handles;

        if (n_control_handles == 0 &&
            ACCESS_ONCE(dev->status) == UBD_STATUS_TERMINATED &&
            ACCESS_ONCE(dev->n_block_handles) == 0)
        {
            // Nothing else can acquire this device.
            spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
            ubd_free_ublkdev(dev);
        } else {
            spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        }
    }
    
    return 0;
}

static ssize_t ubdctl_read(struct file *filp, char *buffer, size_t size,
                           loff_t *offp)
{
    return -EIO;
}

static ssize_t ubdctl_write(struct file *filp, const char *buffer, size_t size,
                            loff_t *offp)
{
    return -EIO;
}

static unsigned int ubdctl_poll(struct file *filp, poll_table *wait) {
    struct ublkdev *dev = filp->private_data;
    unsigned int result = 0;

    if (dev == NULL) {
        /* Endpoint isn't tied to a device. */
        result |= POLLHUP;
    } else {
        unsigned long lock_flags;
        uint32_t status;
        wait_queue_head_t *wq;
        struct request *pending_delivery;

        spin_lock_irqsave(&dev->wait.lock, lock_flags);
        status = ACCESS_ONCE(dev->status);
        wq = &dev->wait;
        pending_delivery = ACCESS_ONCE(dev->pending_delivery_head);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);

        if (status == UBD_STATUS_RUNNING) {
            poll_wait(filp, wq, wait);
            result |= POLLOUT | POLLWRNORM;
            
            if (pending_delivery != NULL) {
                result |= POLLIN | POLLRDNORM;
            }
        } else if (status == UBD_STATUS_TERMINATED) {
            /* Device is being torn down. */
            result |= POLLHUP;
        }
    }

    return result;
}


static long ubdctl_ioctl(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    switch (cmd) {
    case UBD_IOCREGISTER:
        return ubdctl_ioctl_register(filp, cmd, data);

    case UBD_IOCUNREGISTER:
        return ubdctl_ioctl_unregister(filp, cmd, data);

    case UBD_IOCGETCOUNT:
        return ubdctl_ioctl_getcount(filp, cmd, data);

    case UBD_IOCDESCRIBE:
        return ubdctl_ioctl_describe(filp, cmd, data);

    case UBD_IOCTIE:
        return ubdctl_ioctl_tie(filp, cmd, data);

    case UBD_IOCGETREQUEST:
        return ubdctl_ioctl_getrequest(filp, cmd, data);

    case UBD_IOCPUTREPLY:
        return ubdctl_ioctl_putreply(filp, cmd, data);

    case UBD_IOCDEBUG:
        return ubdctl_ioctl_debug(filp, cmd, data);

    default:
        break;
    }
    
    ubd_info("Unknown ioctl 0x%x", cmd);
    return -EINVAL;
}

static long ubdctl_ioctl_register(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    struct ubd_info info;
    size_t name_length;
    int major;
    struct ublkdev *dev;
    struct gendisk *disk;

    /* Get the disk info from userspace. */
    if (copy_from_user(&info, (void *) data, sizeof(info)) != 0) {
        ubd_notice("Invalid userspace address %p.", (void *) data);
        return -EFAULT;
    }
    
    /* Make sure the name is NUL terminated. */
    name_length = strnlen(info.ubd_name, DISK_NAME_LEN);
    if (name_length == 0) {
        ubd_notice("Name cannot be empty.");
        return -EINVAL;
    } else if (name_length >= DISK_NAME_LEN) {
        ubd_notice("Name is not NUL terminated.");
        return -EINVAL;
    }

    /* Register the new block device. */
    if ((major = register_blkdev(0, info.ubd_name)) < 0) {
        ubd_notice("Failed to register %s: error code %d.\n", info.ubd_name,
                   -major);
        return major;
    }

    /* Allocate the block device structure.  Require this to reside in RAM so
     * we don't end up swapping to another (possibly this?) ublkdev.
     */
    dev = kmalloc(sizeof(*dev), GFP_NOIO);
    if (dev == NULL) {
        ubd_err("Failed to allocate %zu bytes for struct ublkdev.",
                sizeof(*dev));
        unregister_blkdev(major, info.ubd_name);
        return -ENOMEM;
    }

    /* Allocate and initialize the reply array. */
    if ((dev->pending_reply = kmalloc(
             UBD_INITIAL_PENDING_REPLY_SIZE, GFP_NOIO)) == NULL)
    {
        ubd_err("Failed to allocate %zu bytes for reply array.",
                UBD_INITIAL_PENDING_REPLY_SIZE);
        kfree(dev);
        unregister_blkdev(major, info.ubd_name);
        return -ENOMEM;
    }
    dev->max_pending_reply = UBD_INITIAL_PENDING_REPLY_CAPACITY;
    dev->n_pending_reply = 0u;
    memset(dev->pending_reply, 0, UBD_INITIAL_PENDING_REPLY_SIZE);

    // Allocate and initialize the request queue.
    if ((dev->in_flight = blk_init_queue(ubdblk_handle_request, NULL)) == NULL)
    {
        ubd_err("Failed to allocate block request queue.");
        kfree(dev->pending_reply);
        kfree(dev);
        unregister_blkdev(major, info.ubd_name);
        return -ENOMEM;
    }
    
    dev->in_flight->queuedata = dev;
    
    /* Allocate the disk structure.
     * XXX: Allow users to register more than 1 minor.
     */
    if ((dev->disk = disk = alloc_disk(1)) == NULL) {
        ubd_err("Failed to allocate gendisk structure.");
        blk_cleanup_queue(dev->in_flight);
        kfree(dev->pending_reply);
        kfree(dev);
        unregister_blkdev(major, info.ubd_name);
        return -ENOMEM;
    }

    // Initialize the rest of the gendisk structure.
    disk->major = major;
    disk->first_minor = 0;
    memcpy(disk->disk_name, info.ubd_name, DISK_NAME_LEN);
    disk->devnode = ubdblk_get_devnode;
    disk->fops = &ubdblk_fops;
    disk->queue = dev->in_flight;
    disk->flags = (info.ubd_flags & UBD_FL_REMOVABLE) ? GENHD_FL_REMOVABLE : 0;
    set_capacity(disk, info.ubd_nsectors);
    disk->private_data = dev;

    // No requests pending delivery.
    dev->pending_delivery_head = dev->pending_delivery_tail = NULL;

    // Mark this device as registering.
    dev->status = UBD_STATUS_REGISTERING;

    // Initialize the status change wait queue.
    init_waitqueue_head(&dev->wait);

    // Copy flags over.
    dev->flags = info.ubd_flags;

    // Nobody has this open or tied yet.
    dev->n_control_handles = 0;
    dev->n_block_handles = 0;

    ubd_debug("Registering %s with %llu sectors", info.ubd_name,
              (long long unsigned) info.ubd_nsectors);

    // Flush everything before the work function might start.
    smp_wmb();

    /* Asynchronously add the disk.  Otherwise, there can be a race condition
     * where udev attempts to read the disk before this ioctl returns.
     */
    INIT_WORK(&dev->add_disk_work, ubdblk_add_disk);
    schedule_work(&dev->add_disk_work);

    smp_wmb();

    /* Add this device to the global list of devices. */
    mutex_lock(&ubd_devices_lock);
    list_add_tail(& dev->list, &ubd_devices);
    mutex_unlock(&ubd_devices_lock);

    /* Copy the major number back to user space. */
    info.ubd_major = major;
    if (copy_to_user((void *) data, &info, sizeof(info))) {
        ubd_err("Userspace structure became invalid.");
        return -EFAULT;
    }

    return 0;
}

static long ubdctl_ioctl_unregister(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    int major = (int) data;
    struct ublkdev *dev;
    unsigned long lock_flags;
    uint32_t status;

    mutex_lock(&ubd_devices_lock);

    dev = ubd_find_device_by_major(major);
    if (dev == NULL) {
        mutex_unlock(&ubd_devices_lock);
        ubd_info("Unknown major device %d. (originally %lu)", major, data);
        return -EINVAL;
    }

    spin_lock_irqsave(&dev->wait.lock, lock_flags);
    status = ACCESS_ONCE(dev->status);

    if (status == UBD_STATUS_REGISTERING) {
        ubd_info("Cannot unregister device major %d; still registering "
                 "device.", major);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        mutex_unlock(&ubd_devices_lock);
        return -EBUSY;
    } else if (status == UBD_STATUS_TERMINATED) {
        ubd_info("Cannot unregister device major %d; already terminated.",
                 major);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        mutex_unlock(&ubd_devices_lock);
        return -EINVAL;
    }
    
    ubd_debug("Setting status to terminated.");
    // Start the unregister process.
    ACCESS_ONCE(dev->status) = UBD_STATUS_TERMINATED;

    // Remove this device from the list of devices.
    ubd_debug("Removing device from list of devices.");
    list_del(&dev->list);
    mutex_unlock(&ubd_devices_lock);

    // Fail all requests on this device.
    ubd_debug("Failing all requests.");
    ubd_fail_requests(dev, lock_flags);

    // Notify anyone waiting on a status change.
    ubd_debug("Notifying waiters.");
    smp_wmb();
    wake_up_all_locked(&dev->wait);

    if (ACCESS_ONCE(dev->n_control_handles) == 0 &&
        ACCESS_ONCE(dev->n_block_handles) == 0)
    {
        // Nothing else can acquire this device.
        ubd_debug("No more handles open; freeing device.");
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        ubd_free_ublkdev(dev);        
    } else {
        // Allow the unmount to proceed asynchronously.
        ubd_debug("Device handles are still open; will keep device up.");
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
    }
    
    return 0;
}

static long ubdctl_ioctl_getcount(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    struct list_head *iter;
    size_t count = 0;

    mutex_lock(&ubd_devices_lock);
    list_for_each(iter, &ubd_devices) {
        ++count;
    }
    mutex_unlock(&ubd_devices_lock);

    return count;
}

static long ubdctl_ioctl_describe(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    struct ubd_describe desc;
    struct list_head *iter;
    unsigned long lock_flags;
    uint32_t i = 0, index;

    /* Get the describe structure from userspace. */
    if (copy_from_user(&desc, (void *) data, sizeof(desc)) != 0) {
        ubd_info("Invalid userspace address %p.", (void *) data);
        return -EFAULT;
    }

    index = desc.ubd_index;

    mutex_lock(&ubd_devices_lock);
    list_for_each(iter, &ubd_devices) {
        struct ublkdev *dev;

        // Skip over devices until we find the one we're interested in.
        if (i != desc.ubd_index) {
            ++i;
            continue;
        }

        // Found it.
        dev = container_of(iter, struct ublkdev, list);
        spin_lock_irqsave(&dev->wait.lock, lock_flags);
        BUG_ON(dev->disk == NULL);

        // Copy the data out of the device structure.
        memcpy(desc.ubd_info.ubd_name, dev->disk->disk_name, DISK_NAME_LEN);
        desc.ubd_info.ubd_flags = dev->flags;
        desc.ubd_info.ubd_nsectors = get_capacity(dev->disk);
        desc.ubd_info.ubd_major = dev->disk->major;
        // desc.ubd_info.ubd_minor = dev->disk->first_minor;
        
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        mutex_unlock(&ubd_devices_lock);
        
        if (copy_to_user((void *) data, &desc, sizeof(desc)) != 0) {
            ubd_info("Invalid userspace address %p.", (void *) data);
            return -EFAULT;
        }

        return 0;
    }

    // No such index.
    mutex_lock(&ubd_devices_lock);
    ubd_info("Index %u beyond end of device list.", index);
    return -EINVAL;
}


static long ubdctl_ioctl_tie(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    struct ublkdev *olddev, *newdev;
    unsigned long lock_flags;
    uint32_t n_control_handles;

    // Attempt to tie this to a new device.
    if (data > UINT_MAX) {
        ubd_warning("Major device number %lu out of range.", data);
        return -EINVAL;
    }

    mutex_lock(&ubd_devices_lock);

    if (data != 0) {
        newdev = ubd_find_device_by_major((uint32_t) data);
        if (newdev == NULL) {
            mutex_unlock(&ubd_devices_lock);
            ubd_warning("Unknown device major %lu.", data);
            return -ENODEV;
        }
    } else {
        newdev = NULL;
    }

    olddev = filp->private_data;
    if (olddev != NULL && newdev != olddev) {
        // Untie the existing device.
        spin_lock_irqsave(&olddev->wait.lock, lock_flags);
        // Decrement the control handle count and possibly free up the
        // structure.
        n_control_handles = ACCESS_ONCE(olddev->n_control_handles) - 1;
        ACCESS_ONCE(olddev->n_control_handles) = n_control_handles;

        // Notify anyone waiting on the control handle count to change.
        smp_wmb();
        wake_up_all_locked(&olddev->wait);

        if (n_control_handles == 0 &&
            ACCESS_ONCE(olddev->status) == UBD_STATUS_TERMINATED &&
            ACCESS_ONCE(olddev->n_block_handles) == 0)
        {
            // Nothing else can acquire this device.
            spin_unlock_irqrestore(&olddev->wait.lock, lock_flags);
            ubd_free_ublkdev(olddev);
        } else {
            spin_unlock_irqrestore(&olddev->wait.lock, lock_flags);
        }
    }

    if (newdev != NULL && newdev != olddev) {
        // Increment the control handle count on this device.
        spin_lock_irqsave(&newdev->wait.lock, lock_flags);
        n_control_handles = ACCESS_ONCE(newdev->n_control_handles) + 1;
        ACCESS_ONCE(newdev->n_control_handles) = n_control_handles;

        // Notify anyone waiting on the control handle count to change.
        smp_wmb();
        wake_up_all_locked(&newdev->wait);
        
        spin_unlock_irqrestore(&newdev->wait.lock, lock_flags);
    }

    filp->private_data = newdev;
    mutex_unlock(&ubd_devices_lock);

    return 0;
}


/** Send a request from the block endpoint to the control endpoint. */
static long ubdctl_ioctl_getrequest(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    struct ublkdev *dev;
    unsigned long lock_flags;
    struct request *req;
    ubd_bvec_iter_t bvec;
    struct req_iterator iter;
    struct request *next_req;
    struct ubd_message msg;
    uint32_t max_pending_reply;
    uint32_t tag;

    if ((dev = filp->private_data) == NULL) {
        ubd_warning("Control endpoint is not tied to a device.");
        return -ENODEV;
    }
    
    if (! access_ok(VERIFY_WRITE, (void *) data, sizeof(struct ubd_message))) {
        ubd_warning("Invalid userspace address %p.", (void *) data);
        return -EFAULT;
    }

    // Get the ubd_size data and verify the userspace address is at least
    // somewhat valid.
    if (copy_from_user(&msg, (void *) data, sizeof(msg))) {
        ubd_warning("Invalid userspace address %p.", (void *) data);
        return -EFAULT;
    }

    // Wait for a message to become available *and* a tag slot to become
    // available.
    ubd_debug("About to enter spinlock to wait for a message");
    spin_lock_irqsave(&dev->wait.lock, lock_flags);
    if (wait_event_interruptible_locked(
            dev->wait,
            (req = ACCESS_ONCE(dev->pending_delivery_head)) != NULL &&
            ACCESS_ONCE(dev->n_pending_reply) <
            ACCESS_ONCE(dev->max_pending_reply)))
    {
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        return -ERESTARTSYS;
    }
    ubd_debug("Message and tag available");

    msg.ubd_nsectors = blk_rq_sectors(req);
    msg.ubd_first_sector = blk_rq_pos(req);

    // Fill in the remaining details.
    if ((req->cmd_flags & REQ_DISCARD) != 0) {
        ubd_debug("Got a discard request (first_sector=%llu, nsectors=%llu)",
                  (long long unsigned) msg.ubd_first_sector,
                  (long long unsigned) msg.ubd_nsectors);
        msg.ubd_msgtype = UBD_MSGTYPE_DISCARD;
        msg.ubd_size = 0;
    } else if ((req->cmd_flags & REQ_FLUSH) != 0) {
        ubd_debug("Got a flush request (first_sector=%llu, nsectors=%llu)",
                  (long long unsigned) msg.ubd_first_sector,
                  (long long unsigned) msg.ubd_nsectors);
        msg.ubd_msgtype = UBD_MSGTYPE_FLUSH;
        msg.ubd_size = 0;
    } else if (rq_data_dir(req) == READ) {
        ubd_debug("Got a read request (first_sector=%llu, nsectors=%llu)",
                  (long long unsigned) msg.ubd_first_sector,
                  (long long unsigned) msg.ubd_nsectors);

        msg.ubd_msgtype = UBD_MSGTYPE_READ;
        msg.ubd_size = 0;
    } else {
        void __user *dest = msg.ubd_data;
        uint32_t write_size = msg.ubd_nsectors << 9;

        ubd_debug("Got a write request (first_sector=%llu, nsectors=%llu)",
                  (long long unsigned) msg.ubd_first_sector,
                  (long long unsigned) msg.ubd_nsectors);


        BUG_ON(rq_data_dir(req) != WRITE);
        
        if (write_size > msg.ubd_size) {
            ubd_warning("Insufficient buffer space: need %u bytes; userspace "
                        "provided only %u bytes.", write_size, msg.ubd_size);
            msg.ubd_size = write_size;
            copy_to_user((void *) data, &msg, sizeof(msg));
            spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
            return -ENOMEM;
        }

        msg.ubd_msgtype = UBD_MSGTYPE_WRITE;
        msg.ubd_size = write_size;

        // Copy the data from the write request over to the userspace buffer.
        rq_for_each_segment(bvec, req, iter) {
            void *src;
            long n_uncopied;
            unsigned int src_len;
            unsigned long bvec_irq_flags;

            // Attempt to copy the bytes over.
            src = bvec_kmap_irq(ubd_bvptr(bvec), &bvec_irq_flags);
            src_len = ubd_bvptr(bvec)->bv_len;
            n_uncopied = copy_to_user(dest, src, src_len);
            bvec_kunmap_irq(src, &bvec_irq_flags);

            if (n_uncopied > 0) {
                ubd_warning("Failed to copy %ld bytes of %u total bytes to "
                            "userspace.", n_uncopied, src_len);
                spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
                
                return -EFAULT;
            }

            dest += src_len;
        }
    }

    // Allocate a tag for this request.
    max_pending_reply = ACCESS_ONCE(dev->max_pending_reply);
    for (tag = 0u; tag < max_pending_reply; ++tag) {
        if (ACCESS_ONCE(dev->pending_reply[tag]) == NULL) {
            break;
        }
    }

    ubd_debug("Allocated tag %u", tag);

    BUG_ON(tag == max_pending_reply);
    msg.ubd_tag = tag;
    ACCESS_ONCE(dev->pending_reply[tag]) = req;
    ACCESS_ONCE(dev->n_pending_reply) = ACCESS_ONCE(dev->n_pending_reply) + 1;
    
    // Copy the message back to userspace.  If this is a write request, the
    // data has already been copied over.
    if (copy_to_user((void *) data, &msg, sizeof(msg)) != 0) {
        // Userspace became invalid?!
        ubd_err("Userspace address %p became invalid.", (void *) data);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        return -EFAULT;
    }

    // Remove this request from the pending delivery list.
    next_req = (struct request *) req->special;
    ACCESS_ONCE(dev->pending_delivery_head) = next_req;
    if (next_req == NULL) {
        ACCESS_ONCE(dev->pending_delivery_tail) = NULL;
    }

    spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
    ubd_debug("Left spinlock");

    return 0;
}


static long ubdctl_ioctl_putreply(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    struct ublkdev *dev;
    struct ubd_message msg;
    struct request *req = NULL;
    ubd_bvec_iter_t bvec;
    struct req_iterator iter;
    unsigned long lock_flags;
    uint32_t msgtype, expected_msgtype;
    uint32_t tag;
    uint32_t dev_status;
    int32_t status;
    uint32_t size;
    long result = -EIO;
    bool unfinished;
    char msgbuf1[64], msgbuf2[64];

#define UBD_ABORT(_result) do { result = (_result); goto done; } while (0)
#define UBD_FINISH_ERR(_err)                                            \
    do {                                                                \
        result = 0;                                                     \
        unfinished = blk_end_request_err(req, (_err));                  \
        BUG_ON(unfinished);                                             \
        goto done;                                                      \
    } while (0)
#define UBD_FINISH(_nbytes)                                             \
    do {                                                                \
        result = 0;                                                     \
        unfinished = blk_end_request(req, 0, (_nbytes));                \
        BUG_ON(unfinished);                                             \
        goto done;                                                      \
    } while (0)

    dev = filp->private_data;
    if (dev == NULL) {
        ubd_warning("Reply received from an untied control endpoint.");
        UBD_ABORT(-EINVAL);
    }

    if (copy_from_user(&msg, (void *) data, sizeof(msg)) != 0) {
        ubd_warning("Invalid userspace address %p.", (void *) data);
        UBD_ABORT(-EFAULT);
    }

    msgtype = msg.ubd_msgtype;
    tag = msg.ubd_tag;
    status = msg.ubd_status;
    size = msg.ubd_size;

    if (size != 0) {
        if (msgtype != UBD_MSGTYPE_READ) {
            ubd_warning("Userspace provided data on a non-read reply.");
            UBD_ABORT(-EINVAL);
        }
    }

    spin_lock_irqsave(&dev->wait.lock, lock_flags);

    // If the device isn't running, just drop this.
    dev_status = ACCESS_ONCE(dev->status);
    if (dev_status == UBD_STATUS_TERMINATED) {
        ubd_warning("Received a reply for a non-running device.");
        UBD_ABORT(-EBUSY);
    }

    // Get the request corresponding to this tag -- assume this tag is
    // sensical.
    if (tag > ACCESS_ONCE(dev->max_pending_reply) ||
        (req = ACCESS_ONCE(dev->pending_reply[tag])) == NULL)
    {
        ubd_warning("Received a reply for unknown tag %u.", tag);
        UBD_ABORT(-EBUSY);
    }

    // Remove this reply from the list of pending replies.
    ACCESS_ONCE(dev->pending_reply[tag]) = NULL;
    ACCESS_ONCE(dev->n_pending_reply) = 
        ACCESS_ONCE(dev->n_pending_reply) - 1;
    wake_up_all_locked(&dev->wait);
    spin_unlock_irqrestore(&dev->wait.lock, lock_flags);

    // Make sure the reply type matches the request type.
    if ((req->cmd_flags & REQ_DISCARD) != 0) {
        expected_msgtype = UBD_MSGTYPE_DISCARD;
    } else if ((req->cmd_flags & REQ_FLUSH) != 0) {
        expected_msgtype = UBD_MSGTYPE_FLUSH;
    } else if (rq_data_dir(req) == READ) {
        expected_msgtype = UBD_MSGTYPE_READ;
    } else {
        expected_msgtype = UBD_MSGTYPE_WRITE;
    }

    if (msgtype != expected_msgtype) {
        ubd_err("Tag %u: Expected msgtype %s, got %s.", tag,
                ubd_msgtype_to_string(expected_msgtype, msgbuf1),
                ubd_msgtype_to_string(msgtype, msgbuf2));
        UBD_FINISH_ERR(-EIO);
    }

    if (status < 0) {
        // Error -- pass this back to the requester.
        UBD_FINISH_ERR(status);
    }

    if (status != (blk_rq_sectors(req) << 9)) {
        ubd_err("Tag %u: Status %d doesn't match request size %u.", tag,
                status, blk_rq_sectors(req) << 9);
        UBD_FINISH_ERR(-EIO);
    }

    if (msgtype == UBD_MSGTYPE_READ) {
        void __user *src = msg.ubd_data;
        uint32_t read_size = blk_rq_sectors(req) << 9;

        // Make sure the sizes match.
        if (read_size != size) {
            ubd_err("Tag %u: Expected %u bytes in read reply, got %u.", tag,
                    read_size, size);
            UBD_FINISH_ERR(-EIO);
        }

        // Copy the data from userspace over.
        rq_for_each_segment(bvec, req, iter) {
            long n_uncopied;
            unsigned long bvec_irq_flags;
            unsigned int src_len;
            void *dest;

            dest = bvec_kmap_irq(ubd_bvptr(bvec), &bvec_irq_flags);
            src_len = ubd_bvptr(bvec)->bv_len;
            n_uncopied = copy_from_user(dest, src, src_len);
            bvec_kunmap_irq(dest, &lock_flags);

            if (n_uncopied > 0) {
                ubd_warning("Failed to copy %ld bytes of %u total bytes from "
                            "userspace.", n_uncopied, src_len);
                UBD_FINISH_ERR(-EIO);
            }

            src += src_len;
        }

        UBD_FINISH(size);
    } else {
        if (size != 0) {
            ubd_warning("Tag %u: Expected 0 bytes in non-read reply, "
                        "got %u.", tag, size);
            UBD_FINISH_ERR(-EIO);
        }

        UBD_FINISH(status);
    }

done:
    return result;

#undef UBD_ABORT
#undef UBD_FINISH_ERR
#undef UBD_FINISH
}


static long ubdctl_ioctl_debug(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    int devices_lock_acquired;
    struct list_head *el;
    
    devices_lock_acquired = mutex_trylock(&ubd_devices_lock);
    if (! devices_lock_acquired) {
        ubd_warning("Failed to acquire devices lock; proceeding anyway.");
    }

    list_for_each(el, &ubd_devices) {
        struct ublkdev *dev = list_entry(el, struct ublkdev, list);
        int dev_lock_acquired;
        unsigned long lock_flags;
        uint32_t status;
        struct gendisk *disk;
        struct request *head, *req;
        uint32_t n_pending_delivery = 0;

        dev_lock_acquired = spin_trylock_irqsave(&dev->wait.lock, lock_flags);
        if (! dev_lock_acquired) {
            ubd_warning("Failed to acquire lock on device at %p; proceeding "
                        "anyway.", dev);
        }

        status = ACCESS_ONCE(dev->status);
        disk = ACCESS_ONCE(dev->disk);

        ubd_info("Device %p: \"%s\" %s (%u)", dev,
                 (disk != NULL ? disk->disk_name : ""),
                 (status == UBD_STATUS_REGISTERING ? "UBD_STATUS_REGISTERING" :
                  (status == UBD_STATUS_RUNNING ? "UBD_STATUS_RUNNING" :
                   (status == UBD_STATUS_TERMINATED ? "UBD_STATUS_TERMINATED" :
                    "unknown status"))), status);
        req = head = ACCESS_ONCE(dev->pending_delivery_head);
        while (req != NULL) {
            n_pending_delivery++;
            req = (struct request *) req->special;
        }
        ubd_info("    pending_delivery_head=%p pending_delivery_tail=%p "
                 "n_pending_delivery=%u",
                 head, ACCESS_ONCE(dev->pending_delivery_tail),
                 n_pending_delivery);


        ubd_info("    n_pending_reply=%u max_pending_reply=%u",
                 ACCESS_ONCE(dev->n_pending_reply),
                 ACCESS_ONCE(dev->max_pending_reply));
        ubd_info("    n_control_handles=%u n_block_handles=%u",
                 ACCESS_ONCE(dev->n_control_handles),
                 ACCESS_ONCE(dev->n_block_handles));
        
        if (dev_lock_acquired) {
            spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        }
    }

    if (devices_lock_acquired) {
        mutex_unlock(&ubd_devices_lock);
    }

    return 0;
}


static char *ubdblk_get_devnode(struct gendisk *gd, umode_t *mode) {
    return kasprintf(GFP_KERNEL, "ubd/%s", gd->disk_name);
}


static int ubdblk_open(struct block_device *blkdev, fmode_t mode) {
    struct ublkdev *dev;
    unsigned long lock_flags;
    uint32_t flags;
    uint32_t status;

    BUG_ON(blkdev == NULL);
    BUG_ON(blkdev->bd_disk == NULL);

    dev = blkdev->bd_disk->private_data;
    BUG_ON(dev == NULL);

    spin_lock_irqsave(&dev->wait.lock, lock_flags);

    flags = ACCESS_ONCE(dev->flags);
    status = ACCESS_ONCE(dev->status);

    /* If opened for writing, make sure this isn't read-only. */
    if (unlikely((flags & UBD_FL_READ_ONLY) != 0 &&
                 (mode & (FMODE_WRITE | FMODE_PWRITE)) != 0))
    {
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        return -EACCES;
    }

    if (unlikely(status != UBD_STATUS_RUNNING)) {
        ubd_warning("Device is not running.");
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        return -EAGAIN;
    }

    ACCESS_ONCE(dev->n_block_handles) = ACCESS_ONCE(dev->n_block_handles) + 1;
    wake_up_all_locked(&dev->wait);
    spin_unlock_irqrestore(&dev->wait.lock, lock_flags);

    return 0;
}


static void ubdblk_release(struct gendisk *disk, fmode_t mode) {
    struct ublkdev *dev;
    unsigned long lock_flags;
    uint32_t n_block_handles;

    BUG_ON(disk == NULL);
    dev = disk->private_data;
    BUG_ON(dev == NULL);

    spin_lock_irqsave(&dev->wait.lock, lock_flags);
    
    n_block_handles = ACCESS_ONCE(dev->n_block_handles) - 1;
    ACCESS_ONCE(dev->n_block_handles) = n_block_handles;

    if (n_block_handles == 0 &&
        ACCESS_ONCE(dev->status) == UBD_STATUS_TERMINATED &&
        ACCESS_ONCE(dev->n_control_handles) == 0)
    {
        // Nothing else can acquire this device.
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        ubd_free_ublkdev(dev);
    } else {
        wake_up_all_locked(&dev->wait);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
    }

    return;
}


static int ubdblk_ioctl(struct block_device *blkdev, fmode_t mode,
                        unsigned int cmd, unsigned long data)
{
    /* FIXME: Implement ioctls */
    printk(KERN_ERR "[%d] ubdblk_ioctl: unknown ioctl %u\n", current->pid,
           cmd);
    return -EINVAL;
}


static unsigned int ubdblk_check_events(struct gendisk *gd,
                                        unsigned int clearing)
{
    /* FIXME: Implement */
    return 0;
}


static int ubdblk_revalidate_disk(struct gendisk *gd) {
    return 0;
}


static void ubdblk_add_disk(struct work_struct *work) {
    struct ublkdev *dev = container_of(work, struct ublkdev, add_disk_work);
    unsigned long lock_flags;
    uint32_t status;

    BUG_ON(dev == NULL);

    ubd_debug("Adding disk %.*s", DISK_NAME_LEN, dev->disk->disk_name);

    /* Go from registering to running */
    spin_lock_irqsave(&dev->wait.lock, lock_flags);
    status = ACCESS_ONCE(dev->status);
    BUG_ON(status != UBD_STATUS_REGISTERING);
    ACCESS_ONCE(dev->status) = UBD_STATUS_RUNNING;

    wake_up_all_locked(&dev->wait);
    spin_unlock_irqrestore(&dev->wait.lock, lock_flags);

    /* Add the disk to the system. */
    add_disk(dev->disk);

    ubd_debug("Added disk %.*s", DISK_NAME_LEN, dev->disk->disk_name);

    return;
}


static void ubdblk_handle_request(struct request_queue *rq) {
    struct ublkdev *dev = rq->queuedata;
    struct request *req;
    unsigned long lock_flags;
    uint32_t status;
    bool unfinished;

    BUG_ON(dev == NULL);

    while ((req = blk_fetch_request(rq)) != NULL) {
        spin_lock_irqsave(&dev->wait.lock, lock_flags);
        status = dev->status;

        ubd_debug("Handling a request");

        if (unlikely(status == UBD_STATUS_TERMINATED)) {
            // Device is not running; fail the request.
            ubd_warning("Received a request for a non-running device.");
            unfinished = blk_end_request_err(req, -EIO);
            BUG_ON(unfinished);
        } else {
            switch (req->cmd_type) {
            case REQ_TYPE_FS:
                ubdblk_handle_fs_request(dev, req);
                break;

            default:
                ubd_err("Unknown request type 0x%x", req->cmd_type);
                unfinished = blk_end_request_err(req, -EIO);
                BUG_ON(unfinished);
                break;
            }
        }
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
    }

    return;
}


static void ubdblk_handle_fs_request(
    struct ublkdev *dev,
    struct request *req)
{
    struct request *tail;

    BUG_ON(dev == NULL);
    BUG_ON(req == NULL);

    tail = ACCESS_ONCE(dev->pending_delivery_tail);

    ubd_debug("ubdblk_handle_fs_request: queueing %s request for sector %llu to %llu",
              ((req->cmd_flags & REQ_DISCARD) ? "discard" :
               (req->cmd_flags & REQ_FLUSH) ? "flush" :
               (rq_data_dir(req) == READ) ? "read" : "write"),
              (long long unsigned) blk_rq_pos(req),
              (long long unsigned) blk_rq_sectors(req));

    ACCESS_ONCE(dev->pending_delivery_tail) = req;
    if (tail == NULL) {
        ACCESS_ONCE(dev->pending_delivery_head) = req;
    } else {
        tail->special = req;
    }

    req->special = NULL;
    wake_up_all_locked(&dev->wait);
    return;
}

/* Local variables: */
/* mode: C */
/* indent-tabs-mode: nil */
/* tab-width: 8 */
/* End: */
/* vi: set expandtab tabstop=8 */
