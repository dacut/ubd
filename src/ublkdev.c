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
#include "ublkdev_kernel.h"

MODULE_AUTHOR("dacut@kanga.org");
MODULE_DESCRIPTION("Userspace block devices");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

static int ubd_major = 0;
module_param(ubd_major, int, 0444);
MODULE_PARM_DESC(ubd_major, "UBD major node");

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
#if KERNEL_VERSION < 0x030e
typedef struct bio_vec *ubd_bvec_iter_t;
#define ubd_bvptr(bvec) (bvec)
#define ubd_first_sector(iter) ((iter).bio->bi_sector)
#else
typedef struct bio_vec ubd_bvec_iter_t;
#define ubd_bvptr(bvec) (&(bvec))
#define ubd_first_sector(iter) ((iter).iter.bi_sector)
#endif

/* blk_queue_init_tags added an argument with Linux 4.0. */
#if KERNEL_VERSION >= 0x0400
#define ubd_blk_queue_init_tags(queue, depth, tags)                     \
    blk_queue_init_tags((queue), (depth), (tags), BLK_TAG_ALLOC_FIFO)
#else
#define ubd_blk_queue_init_tags(queue, depth, tags)     \
    blk_queue_init_tags((queue), (depth), (tags))
#endif

/** Helper for retrieving the status. */
static inline uint32_t ubd_get_status(struct ublkdev *dev) {
    uint32_t status;
    
    mutex_lock(&dev->status_lock);
    status = READ_ONCE(dev->status);
    mutex_unlock(&dev->status_lock);

    return status;
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
static long ubdctl_ioctl(struct file *filp, unsigned int cmd,
                         unsigned long data);

/** Handle a reply from the control endpoint back to the block endpoint. */
static void ubdctl_handle_reply(struct ublkdev *dev, struct ubd_reply *message);

/** Register a disk with the control endpoint. */
static int ubdctl_register(struct ublkdev *dev, struct ubd_info *info);

/** Unregister a disk from the control endpoint.
 *  dev->status_lock MUST be held while calling this function.
 */
static int ubdctl_unregister(struct ublkdev *dev);

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

    /* Register the block device */
    if ((result = register_blkdev(ubd_major, "ubd")) < 0) {
        ubd_err("Failed to register block device: error code %d", result);
        goto error;
    }

    if (ubd_major == 0) {
        ubd_major = result;
    }

    ubd_debug("ubd block registered as device major %d", ubd_major);

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
    if (ubd_major != 0) {
        ubd_debug("Unregistering block device (major %d)", ubd_major);
        unregister_blkdev(ubd_major, "ubd");
        ubd_major = 0;
    }

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

        spin_lock_irqsave(&dev->wait.lock, lock_flags);
        smp_rmb();
        status = READ_ONCE(dev->status);

        poll_wait(filp, &dev->status_wait, wait);

        if (status == UBD_STATUS_RUNNING) {
            result |= POLLOUT | POLLWRNORM;
            
            if (dev->pending_delivery_head != NULL) {
                result |= POLLIN | POLLRDNORM;
            }
        } else if (status == UBD_STATUS_UNREGISTERING) {
            /* Device is being torn down. */
            result |= POLLHUP;
        }

        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
    }

    return result;
}


static long ubdctl_ioctl(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    printk(KERN_DEBUG "[%d] ubdctl_ioctl: ioctl(%u, 0x%lx)\n",
           current->pid, cmd, data);

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

    default:
        break;
    }
    
    printk(KERN_INFO "[%d] ubdctl_ioctl: unknown ioctl 0x%x\n",
           current->pid, cmd);
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
    struct gendisk *disk;

    ubd_debug("Copying structures from userspace.");

    /* Get the disk info from userspace. */
    if (copy_from_user(&info, (void *) data, sizeof(info)) != 0) {
        ubd_notice("Invalid userspace address.");
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
        return -ENOMEM;
    }

    /* Allocate and initialize the reply array. */
    if ((dev->pending_reply = kmalloc(UBD_INITIAL_PENDING_REPLY_SIZE)) == NULL)
    {
        ubd_err("Failed to allocate %zu bytes for reply array.",
                UBD_INITIAL_PENDING_REPLY_SIZE);
        kfree(dev);
        return -ENOMEM;
    }
    dev->max_pending_reply = UBD_INITIAL_PENDING_REPLY_CAPACITY;
    dev->n_pending_reply = 0u;

    /* Allocate and initialize the request queue. */
    if ((dev->in_flight = blk_init_queue(ubdblk_handle_request, NULL)) == NULL)
    {
        ubd_err("Failed to allocate block request queue.");
        kfree(dev);
        return -ENOMEM;
    }
    
    /* Allocate the disk structure.
     * XXX: Allow users to register more than 1 minor.
     */
    if ((dev->disk = disk = alloc_disk(1)) == NULL) {
        ubd_err("Failed to allocate gendisk structure.");
        blk_cleanup_queue(dev->in_flight);
        kfree(dev);
        return -ENOMEM;
    }

    /* Initialize the rest of the structure. */
    disk->major = major;
    disk->first_minor = 0;
    memcpy(disk->disk_name, ubd_info.ubd_name, DISK_NAME_LEN);
    disk->devnode = ubdblk_get_devnode;
    disk->fops = &ubdblk_fops;
    disk->queue = dev->in_flight;
    disk->flags = (info.ubd_flags & UBD_FL_REMOVABLE) ? GENHD_FL_REMOVABLE : 0;
    set_capacity(disk, info.ubd_nsectors);
    disk->private_data = dev;

    /* Asynchronously add the disk.  Otherwise, there can be a race condition
     * where udev attempts to read the disk before this ioctl returns.
     */
    INIT_WORK(&dev->add_disk_work, ubdblk_add_disk);
    schedule_work(&dev->add_disk_work);

    /* No requests pending delivery. */
    dev->pending_delivery_head = dev->pending_delivery_tail = NULL;
    
    /* Mark this device as registering. */
    dev->status = UBD_STATUS_REGISTERING;

    /* Initialize the status change wait queue. */
    init_waitqueue_head(&dev->wait);

    /* Copy flags over. */
    dev->flags = info.flags;

    /* Nobody has this open or tied yet. */
    dev->n_control_handles = 0;
    dev->n_block_handles = 0;

    /* Add this device to the global list of devices. */
    mutex_lock(&ubd_devices_lock);
    list_add_tail(& dev->list, &ubd_devices);
    smp_wmb();
    mutex_unlock(&ubd_devices_lock);

    /* Copy the major number back to user space. */
    info.ubd_major = major;
    copy_to_user((void *) data, &info, sizeof(info)) {
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
    struct ubdblk *dev;
    unsigned long lock_flags;
    struct request *req;
    bool unfinished;
        
    dev = ubd_find_device_by_major(major);
    if (dev == NULL) {
        ubd_info("Unknown major device %d", major);
        return -EINVAL;
    }

    spin_lock_irqsave(&dev->wait.lock, lock_flags);
    smp_rmb();
    status = READ_ONCE(dev->status);

    if (status == UBD_STATUS_REGISTERING) {
        ubd_info("Cannot unregister device major %d; still registering "
                 "device.", major);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        return -EBUSY;
    } else if (status == UBD_STATUS_ADDING) {
        ubd_info("Cannot unregister device major %d; still adding "
                 "device.", major);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        return -EBUSY;
    } else if (status == UBD_STATUS_UNREGISTERING) {
        ubd_info("Cannot unregister device major %d; already unregistering.",
                 major);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        return -EBUSY;
    } else if (status == UBD_STATUS_TERMINATED) {
        ubd_info("Cannot unregister device major %d; already terminated.",
                 major);
        spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
        return -EBUSY;
    }
        
    /* Start the unregister process. */
    WRITE_ONCE(dev->status, UBD_STATUS_UNREGISTERING);
    smp_wmb();

    /* Don't deliver any messages pending delivery. */
    while (dev->pending_delivery_head != NULL) {
        req = dev->pending_delivery_head;
        dev->pending_delivery_head = (struct request *) req->special;

        if (dev->pending_delivery_head == NULL) {
            /* Removed the last item; axe the tail. */
            dev->pending_delivery_tail = NULL;
        }

        smp_wmb();
        spin_lock_irqrestore(&dev->wait.lock, lock_flags);

        /* Fail this request.  This requires the queue lock to be held. */
        spin_lock_irqsave(&dev->in_flight.queue_lock, lock_flags);
        unfinished = blk_end_request_err(req, -EIO);
        spin_lock_irqrestore(&dev->in_flight.queue_lock, lock_flags);

        BUG_ON(unfinished);

        spin_lock_irqsave(&dev->wait.lock, lock_flags);
    }

    /* Fail any messages awaiting a reply. */
    for (size_t i = 0; i < dev->max_pending_reply; ++i) {
        req = dev->pending_reply[i];

        if (req != NULL) {
            uint32_t n_pending_reply;

            n_pending_reply = READ_ONCE(dev->n_pending_reply);
            BUG_ON(n_pending_reply == 0);

            --n_pending_reply;
            WRITE_ONCE(dev->n_pending_reply, n_pending_reply);
            dev->pending_reply[i] = NULL;
            smp_wmb();
                
            spin_unlock_irqrestore(&dev->wait.lock, lock_flags);

            /* Fail this request.  This requires the queue lock to be held. */
            spin_lock_irqsave(&dev->in_flight.queue_lock, lock_flags);
            unfinished = blk_end_request_err(req, -EIO);
            spin_lock_irqrestore(&dev->in_flight.queue_lock, lock_flags);
                
            BUG_ON(unfinished);

            spin_lock_irqsave(&dev->wait.lock, lock_flags);
        }
    }

    /* Allow the unmount to proceed asynchronously. */
    spin_unlock_irqrestore(&dev->wait.lock, lock_flags);
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

    case UBD_IOCDESCRIBE: {
        struct ubd_describe desc;
        struct list_head *iter;
        size_t index = 0;

        printk(KERN_DEBUG "[%d] ubdctl_ioctl: UBD_IOCDESCRIBE\n",
               current->pid);

        /* Get the describe structure from userspace. */
        if (copy_from_user(&desc, (void *) data, sizeof(desc)) != 0) {
            printk(KERN_DEBUG "[%d] ubdctl_ioctl: invalid userspace address\n",
                current->pid);
            return -EFAULT;
        }

        mutex_lock(&ubd_devices_lock);
        list_for_each(iter, &ubd_devices) {
            struct ublkdev *dev;

            if (index != desc.ubd_index) {
                ++index;
                continue;
            }

            /* Found it; return this. */
            dev = container_of(iter, struct ublkdev, list);
            mutex_unlock(&ubd_devices_lock);

            if (dev->disk == NULL) {
                /* Already deallocated? */
                return -EAGAIN;
            }

            memcpy(desc.ubd_info.ubd_name, dev->disk->disk_name,
                   DISK_NAME_LEN);
            desc.ubd_info.ubd_flags = dev->flags;
            desc.ubd_info.ubd_nsectors = get_capacity(dev->disk);
            desc.ubd_info.ubd_major = dev->disk->major;
            desc.ubd_info.ubd_minor = dev->disk->first_minor;

            if (copy_to_user((void *) data, &desc, sizeof(desc)) != 0) {
                printk(KERN_DEBUG "[%d] ubdctl_ioctl: invalid userspace "
                       "address\n", current->pid);
                return -EFAULT;
            }

            return 0;
        }
        mutex_lock(&ubd_devices_lock);
        return -EINVAL;
    }

    default:
        printk(KERN_INFO "[%d] ubdctl_ioctl: unknown ioctl 0x%x\n",
               current->pid, cmd);
        return -EINVAL;
    }

    return -EINVAL;
}


static void ubdctl_handle_reply(struct ublkdev *dev, struct ubd_reply *reply) {
    ubd_bvec_iter_t bvec;
    struct req_iterator iter;
    struct request *rq;
    int32_t status;
    uint32_t msgtype;
    uint32_t size;
    uint32_t tag;
    int result = -EINVAL;
    unsigned int n_bytes = 0;
    bool unfinished;
    int n_pending;

    BUG_ON(dev == NULL);
    BUG_ON(reply == NULL);

    status = reply->ubd_status;
    msgtype = reply->ubd_header.ubd_msgtype;
    size = reply->ubd_header.ubd_size;
    tag = reply->ubd_header.ubd_tag;

    /* Make sure the message type and size are sensical. */
    if (msgtype == UBD_MSGTYPE_READ_REPLY) {
        if (size < offsetof(struct ubd_reply, ubd_data)) {
            printk(KERN_INFO "[%d] ubdctl_handle_reply: received invalid read "
                   "reply packet with size %u (minimum is %zu)\n",
                   current->pid, size, offsetof(struct ubd_reply, ubd_data));
            return;
        }

        /* Make sure the size of the data is on a sector boundary. */
        if ((size - offsetof(struct ubd_reply, ubd_data)) % 512 != 0) {
            printk(KERN_INFO "[%d] ubdctl_handle_reply: received invalid read "
                   "reply packet with size %u (not a sector-sized reply)\n",
                   current->pid, size);
            return;
        }
    } else if (msgtype == UBD_MSGTYPE_WRITE_REPLY) {
        if (size != sizeof(struct ubd_reply)) {
            printk(KERN_INFO "[%d] ubdctl_handle_reply: received invalid "
                   "write reply packet with size %u (expected %zu)\n",
                   current->pid, size, sizeof(struct ubd_reply));
            return;
        }
    } else if (msgtype == UBD_MSGTYPE_DISCARD_REPLY) {
        if (size != sizeof(struct ubd_reply)) {
            printk(KERN_INFO "[%d] ubdctl_handle_reply: received invalid "
                   "discard reply packet with size %u (expected %zu)\n",
                   current->pid, size, sizeof(struct ubd_reply));
            return;
        }
    } else {
        printk(KERN_INFO "[%d] ubdctl_handle_reply: received invalid reply "
               "type 0x%x\n", current->pid, msgtype);
        return;
    }

    /* Find the request this belongs to. */
    rq = blk_queue_find_tag(dev->blk_pending, tag);
    if (rq == NULL) {
        printk(KERN_INFO "[%d] ubdctl_handle_reply: received reply for "
               "unknown tag %u\n", current->pid, tag);
        return;
    }

    rq_for_each_segment(bvec, rq, iter) {
        struct bio *bio = iter.bio;
        uint32_t n_sectors = bio_sectors(bio);

        BUG_ON(bio_segments(bio) != 1);

        if (reply->ubd_status < 0) {
            /* Error received */
            result = reply->ubd_status;
            n_bytes += n_sectors * 512;
        } else if (reply->ubd_status != n_sectors) {
            /* Sector count mismatch. */
            printk(KERN_INFO "[%d] ubdctl_handle_reply: expected %u sectors; "
                   "received %u sectors.\n", current->pid, n_sectors,
                   reply->ubd_status);

            result = -EIO;
            n_bytes += n_sectors * 512;
        } else if (bio_data_dir(bio) == READ) {
            /* Read request */
            uint32_t recv_data = reply->ubd_header.ubd_size -
                offsetof(struct ubd_reply, ubd_data);

            if (msgtype != UBD_MSGTYPE_READ_REPLY) {
                /* Reply type doesn't match what was requested. */
                printk(KERN_INFO "[%d] ubdctl_handle_reply: expected read "
                       "reply packet for tag %u.\n", current->pid, tag);
                result = -EIO;
            } else if (recv_data != 512 * n_sectors) {
                /* Reply size does not match the requested size. */
                printk(KERN_INFO "[%d] ubdctl_handle_reply: expected %u "
                       "bytes; received %u bytes.\n", current->pid,
                       512 * n_sectors, recv_data);
                result = -EIO;
            } else {
                /* Ok -- copy the data back. */
                char *buffer;
                unsigned long flags;

                buffer = bvec_kmap_irq(ubd_bvptr(bvec), &flags);
                memcpy(buffer, reply->ubd_data, recv_data);
                bvec_kunmap_irq(buffer, &flags);

                result = 0;
                n_bytes += recv_data;
            }
        } else if ((bio->bi_rw & REQ_DISCARD) != 0) {
            if (msgtype != UBD_MSGTYPE_DISCARD_REPLY) {
                printk(KERN_INFO "[%d] ubdctl_handle_reply: expected discard "
                       "reply packet for tag %u.\n", current->pid, tag);
                result = -EIO;
            } else {
                result = 0;
                n_bytes += 512 * n_sectors;
            }
        } else {
            if (msgtype != UBD_MSGTYPE_WRITE_REPLY) {
                printk(KERN_INFO "[%d] ubdctl_handle_reply: expected write "
                       "reply packet for tag %u.\n", current->pid, tag);
                result = -EIO;
            } else {
                result = 0;
            }

            n_bytes += 512 * n_sectors;
        }
    }

    BUG_ON(result == -EINVAL);
    unfinished = blk_end_request(rq, result, n_bytes);
    if (unfinished) {
        printk(KERN_ERR "[%d] ubdctl_handle_reply: blk_end_request didn't "
               "finish; tag=%d, n_bytes=%u\n", current->pid, rq->tag, n_bytes);
    }
    BUG_ON(unfinished);

    /* ubdblk_handle_fs_request might be waiting for a tag.  Notify it
       that we just made one available. */
    n_pending = atomic_dec_return(&dev->n_pending);
    printk(KERN_DEBUG "[%d] ubdctl_handle_reply: n_pending now %d\n",
           current->pid, n_pending);

    return;
}


static int ubdctl_register(
    struct file *filp,
    unsigned int cmd,
    unsigned long data)
{
    struct gendisk *disk;
    int major;
    int result = -EINVAL;
    uint32_t status;

    if (mutex_lock_interruptible(&dev->status_lock)) {
        return -ERESTARTSYS;
    }
    
    /* Make sure we haven't already registered a disk on this control
       endpoint */
    smp_rmb();
    status = READ_ONCE(dev->status);

    if (status != 0) {
        printk(KERN_INFO "[%d] ubdctl_register: attempted to register "
               "duplicate device\n", current->pid);
        mutex_unlock(&dev->status_lock);
        return -EBUSY;
    }

    BUG_ON(dev->disk != NULL);

    /* Make sure the name is NUL terminated. */
    memcpy(name, info->ubd_name, DISK_NAME_LEN);
    name[DISK_NAME_LEN] = '\0';

    /* Register the block device. */
    if ((major = register_blkdev(0, name)) < 0) {
        /* Error -- maybe in the name? */
        printk(KERN_INFO "[%d] ubdctl_register: failed to register block "
               "device with name \"%s\": %d\n", current->pid, name, major);
        mutex_unlock(&dev->status_lock);
        return major;
    }

    info->ubd_major = (uint32_t) major;

    /* Register the request handler */
    dev->blk_pending = blk_init_queue(ubdblk_handle_request, NULL);
    dev->blk_pending->queuedata = dev;

    /* XXX: We only support one segment at a time for now. */
    blk_queue_max_segments(dev->blk_pending, 1);
    if ((result = ubd_blk_queue_init_tags(
             dev->blk_pending, UBD_MAX_TAGS, NULL)) != 0)
    {
        printk(KERN_ERR "[%d] ubdctl_register: failed to initialize tags: "
               "err=%d\n", current->pid, -result);
        mutex_unlock(&dev->status_lock);
        return result;
    }

    /* Allocate a disk structure. */
    /* FIXME: Allow users to register more than 1 minor. */
    if ((dev->disk = disk = alloc_disk(1)) == NULL) {
        printk(KERN_ERR "[%d] ubdctl_register: failed to allocate gendisk "
               "structure\n", current->pid);
        mutex_unlock(&dev->status_lock);
        return -ENOMEM;
    }

    /* Fill in the disk structure. */
    disk->major = major;
    disk->first_minor = 0;
    // disk->minors = 1;
    memcpy(disk->disk_name, name, DISK_NAME_LEN);
    disk->devnode = ubdblk_get_devnode;
    disk->fops = &ubdblk_fops;
    disk->queue = dev->blk_pending;
    disk->flags =
        (info->ubd_flags & UBD_FL_REMOVABLE) ? GENHD_FL_REMOVABLE : 0;
    set_capacity(disk, info->ubd_nsectors);
    disk->private_data = dev;

    /* Add the disk after this method returns. */
    INIT_WORK(&dev->add_disk_work, ubdblk_add_disk);
    schedule_work(&dev->add_disk_work);

    /* Mark this device as registering */
    WRITE_ONCE(dev->status, UBD_STATUS_REGISTERING);
    dev->flags = info->ubd_flags;
    mutex_unlock(&dev->status_lock);

    /* Add this to the list of registered disks. */
    mutex_lock(&ubd_devices_lock);
    list_add_tail(&dev->list, &ubd_devices);
    mutex_unlock(&ubd_devices_lock);

    return 0;
}



static char *ubdblk_get_devnode(struct gendisk *gd, umode_t *mode) {
    return kasprintf(GFP_KERNEL, "ubd/%s", gd->disk_name);
}


static int ubdblk_open(struct block_device *blkdev, fmode_t mode) {
    struct ublkdev *dev;

    BUG_ON(blkdev == NULL);
    BUG_ON(blkdev->bd_disk == NULL);

    dev = blkdev->bd_disk->private_data;
    BUG_ON(dev == NULL);

    /* If opened for writing, make sure this isn't read-only. */
    if ((dev->flags & UBD_FL_READ_ONLY) != 0 &&
        (mode & (FMODE_WRITE | FMODE_PWRITE)) != 0)
    {
        return -EACCES;
    }

    if (mutex_lock_interruptible(&dev->status_lock)) {
        return -ERESTARTSYS;
    }
    
    if ((dev->status & UBD_STATUS_RUNNING) == 0) {
        printk(KERN_ERR "[%d] ubdblk_open: device is not running\n",
               current->pid);
        mutex_unlock(&dev->status_lock);
        return -EAGAIN;
    }

    if ((dev->status & UBD_STATUS_OPENED) != 0) {
        printk(KERN_ERR "[%d] ubdblk_open: device is already open\n",
               current->pid);
        mutex_unlock(&dev->status_lock);
        return -EBUSY;
    }
    
    dev->status |= UBD_STATUS_OPENED;
    mutex_unlock(&dev->status_lock);
    wake_up_interruptible(&dev->status_wait);

    printk(KERN_ERR "[%d] ubdblk_open: success\n", current->pid);

    return 0;
}


static void ubdblk_release(struct gendisk *disk, fmode_t mode) {
    struct ublkdev *dev;
    uint32_t status;

    BUG_ON(disk == NULL);

    dev = disk->private_data;
    BUG_ON(dev == NULL);

    mutex_lock(&dev->status_lock);
    status = READ_ONCE(dev->status);

    BUG_ON((status & UBD_STATUS_OPENED) == 0);
    status &= ~UBD_STATUS_OPENED;
    
    WRITE_ONCE(dev->status, status);

    mutex_unlock(&dev->status_lock);
    wake_up_interruptible(&dev->status_wait);    

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

    printk(KERN_DEBUG "[%d] ubdblk_add_disk: dev=%p\n", current->pid, dev);
    BUG_ON(dev == NULL);

    /* Go from registering to running+adding */
    mutex_lock(&dev->status_lock);    
    BUG_ON(dev->status != UBD_STATUS_REGISTERING);
    dev->status = (UBD_STATUS_ADDING | UBD_STATUS_RUNNING);
    mutex_unlock(&dev->status_lock);
    wake_up_interruptible(&dev->status_wait);

    /* Add the disk to the system. */
    printk(KERN_DEBUG "[%d] ubdblk_add_disk: calling add_disk\n",
           current->pid);
    add_disk(dev->disk);

    printk(KERN_DEBUG "[%d] ubdblk_add_disk: add_disk returned\n",
           current->pid);

    /* Go from running+adding to just running */
    mutex_lock(&dev->status_lock);
    dev->status &= ~UBD_STATUS_ADDING;
    mutex_unlock(&dev->status_lock);
    wake_up_interruptible(&dev->status_wait);

    printk(KERN_DEBUG "[%d] ubdblk_add_disk: done\n", current->pid);

    return;
}


static void ubdblk_handle_request(struct request_queue *rq) {
    struct ublkdev *dev = rq->queuedata;
    int is_running;
    struct request *req;

    BUG_ON(dev == NULL);

    /* We can't use blk_fetch_request here -- the tag API also starts the
       request, which will result in a bugcheck. */
    while ((req = blk_peek_request(rq)) != NULL) {
        bool unfinished;

        // spin_unlock_irq(rq->queue_lock);
        is_running = ((ubd_get_status(dev) & UBD_STATUS_RUNNING) != 0);

        if (unlikely(! is_running)) {
            /* Device is not running; fail the request. */
            blk_start_request(req);
            unfinished = blk_end_request_err(req, -EIO);
            BUG_ON(unfinished);
            printk(KERN_INFO "[%d] ublkdev_handle_request: request failed.\n",
                   current->pid);
        } else {
            switch (req->cmd_type) {
            case REQ_TYPE_FS:
                ubdblk_handle_fs_request(dev, req);
                break;

            default:
                printk(KERN_DEBUG "[%d] ubdblk: unknown request type 0x%x\n",
                       current->pid, req->cmd_type);
                blk_start_request(req);
                unfinished = blk_end_request_err(req, -EIO);
                BUG_ON(unfinished);
                break;
            }
        }
        
        // spin_lock_irq(rq->queue_lock);
    }

    return;
}


static void ubdblk_handle_fs_request(struct ublkdev *dev, struct request *rq) {
    ubd_bvec_iter_t bvec;
    struct req_iterator iter;
    struct ubd_outgoing_message *msg;
    struct ubd_request *ureq;
    int n_pending;

    BUG_ON(dev == NULL);
    BUG_ON(rq == NULL);

    /* Allocate a tag for this request. */
    BUG_ON(dev->blk_pending == NULL);

    rq_for_each_segment(bvec, rq, iter) {
        struct bio *bio = iter.bio;
        size_t req_size = sizeof(*ureq);
        void *data = NULL;
        bool unfinished;

        BUG_ON(bio == NULL);
        BUG_ON(bio_segments(bio) != 1);

        if (blk_queue_start_tag(dev->blk_pending, rq)) {
            // Couldn't allocate the tag.  Don't pull it off the queue.
            printk(KERN_INFO "[%d] ubdblk_handle_fs_request: failed to "
                   "allocate a tag.\n", current->pid);
            return;
        }

        printk(KERN_DEBUG "[%d] ubdblk_handle_fs_request: request tag=%d, "
               "size=%d\n", current->pid, rq->tag, bio_sectors(rq->bio) * 512);

        /* Allocate the message structure */
        if ((msg = kmalloc(sizeof(*msg), GFP_NOIO)) == NULL) {
            printk(KERN_ERR "[%d] ubdblk_handle_fs_request: failed to "
                   "allocate %zu bytes for request.\n", current->pid,
                   sizeof(*msg));
            blk_start_request(rq);
            unfinished = blk_end_request_err(rq, -ENOMEM);
            BUG_ON(unfinished);
            return;
        }

        if (bio_data_dir(bio) == WRITE && (bio->bi_rw & REQ_DISCARD) == 0) {
            /* Write request -- requires extra data. */
            size_t cur_bytes = bio_cur_bytes(bio);
            req_size += cur_bytes;
            data = bio_data(bio);
        }

        /* Allocate the request structure */
        if ((ureq = kmalloc(req_size, GFP_NOIO)) == NULL) {
            printk(KERN_ERR "[%d] ubdblk_handle_fs_request: failed to "
                   "allocate %zu bytes for request.\n", current->pid,
                   req_size);
            kfree(msg);
            blk_start_request(rq);
            unfinished = blk_end_request_err(rq, -ENOMEM);
            BUG_ON(unfinished);
            return;
        }

        /* Initialize the request */
        msg->n_written = 0;
        msg->request = ureq;
        ureq->ubd_header.ubd_msgtype = (
            bio_data_dir(bio) != WRITE ? UBD_MSGTYPE_READ_REQUEST : (
                bio->bi_rw & REQ_DISCARD ? UBD_MSGTYPE_DISCARD_REQUEST :
                UBD_MSGTYPE_WRITE_REQUEST));
        ureq->ubd_header.ubd_size = req_size;
        ureq->ubd_header.ubd_tag = rq->tag;
        ureq->ubd_first_sector = ubd_first_sector(iter);
        ureq->ubd_nsectors = bio_sectors(bio);

        if (data != NULL) {
            memcpy(ureq->ubd_data, data, bio_cur_bytes(bio));
        }

        /* Queue the request for the control endpoint. */
        mutex_lock(&dev->outgoing_lock);
        list_add_tail(&msg->list, &dev->ctl_outgoing_head);
        n_pending = atomic_inc_return(&dev->n_pending);
        printk(KERN_DEBUG "[%d] ubdblk_handle_fs_request: n_pending now %d\n",
               current->pid, n_pending);
        mutex_unlock(&dev->outgoing_lock);
        wake_up_interruptible(&dev->ctl_outgoing_wait);
    }

    return;
}

/* Local variables: */
/* mode: C */
/* indent-tabs-mode: nil */
/* tab-width: 8 */
/* End: */
/* vi: set expandtab tabstop=8 */
