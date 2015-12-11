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

    printk(KERN_INFO "ubd_reply: header at 0x%zx (0x%zx bytes)\n",
           offsetof(struct ubd_reply, ubd_header), sizeof(struct ubd_header));
    printk(KERN_INFO "ubd_reply: status at 0x%zx\n",
           offsetof(struct ubd_reply, ubd_status));
    printk(KERN_INFO "ubd_reply: data at 0x%zx\n",
           offsetof(struct ubd_reply, ubd_data));

    /* Register the control endpoint */
    if ((result = misc_register(&ubdctl_miscdevice)) < 0) {
        printk(KERN_ERR "[%d] ubdctl failed to register misc device: "
               "error code %d\n", current->pid, result);
        goto error;
    }

    printk(KERN_DEBUG "[%d] ubdctl registered as device %d:%d\n",
           current->pid, MISC_MAJOR, ubdctl_miscdevice.minor);

    /* Register the block device */
    if ((result = register_blkdev(ubd_major, "ubd")) < 0) {
        printk(KERN_ERR "[%d] ubd failed to register block device: "
               "error code %d\n", current->pid, result);
        goto error;
    }

    if (ubd_major == 0) {
        ubd_major = result;
    }

    printk(KERN_DEBUG "[%d] ubd registered as block device %d\n",
           current->pid, ubd_major);

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
        printk(KERN_DEBUG "ubd unregistering block device %d\n", ubd_major);
        unregister_blkdev(ubd_major, "ubd");
        ubd_major = 0;
    }

    if (ubdctl_miscdevice.minor != MISC_DYNAMIC_MINOR) {
        misc_deregister(&ubdctl_miscdevice);
    }

    return;
}

module_init(ubd_init);
module_exit(ubd_exit);

static int ubdctl_open(struct inode *inode, struct file *filp) {
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
    unsigned long lock_flags;

    if (dev != NULL) {
        /* Indicate when data is available. */
        spin_lock_irqsave(&dev->status_wait.lock, lock_flags);

        poll_wait(filp, &dev->ctl_outgoing_wait, wait);

    mutex_lock(&dev->outgoing_lock);
    if (dev->ctl_current_outgoing != NULL ||
        ! list_empty(&dev->ctl_outgoing_head))
    {
        result |= (POLLIN | POLLRDNORM);
    }
    mutex_unlock(&dev->outgoing_lock);

    /* XXX: Reevaluate should we create a queue for outgoing replies. */
    result |= POLLOUT | POLLWRNORM;

    return result;
}


static long ubdctl_ioctl(struct file *filp, unsigned int cmd,
                         unsigned long data)
{
    struct ublkdev *dev = filp->private_data;

    printk(KERN_DEBUG "[%d] ubdctl_ioctl: ioctl(%u, 0x%lx)\n",
           current->pid, cmd, data);

    BUG_ON(dev == NULL);

    switch (cmd) {
    case UBD_IOCREGISTER: {
        struct ubd_info info;
        long result;

        printk(KERN_DEBUG "[%d] ubdctl_ioctl: UBD_IOCREGISTER -- copying "
               "structures from userspace\n", current->pid);
        
        /* Get the disk info from userspace. */
        if (copy_from_user(&info, (void *) data, sizeof(info)) != 0) {
            printk(KERN_DEBUG "[%d] ubdctl_ioctl: invalid userspace address\n",
                   current->pid);
            return -EFAULT;
        }

        printk(KERN_DEBUG "[%d] ubdctl_ioctl: ubd_info: ubd_name=\"%.8s\", "
               "ubd_flags=0x%x, ubd_nsectors=%llu, ubd_major=%ud, "
               "ubd_minor=%ud\n", current->pid, info.ubd_name, info.ubd_flags,
               (unsigned long long) info.ubd_nsectors, info.ubd_major,
               info.ubd_minor);
        printk(KERN_DEBUG "[%d] ubdctl_ioctl: registering device\n",
               current->pid);

        result = ubdctl_register(dev, &info);
        if (result == 0) {
            printk(KERN_DEBUG "[%d] ubdctl_ioctl: register call succeeded; "
                   "copying results back to userspace\n", current->pid);
            /* Copy the disk info back to userspace. */
            if (copy_to_user((void *) data, &info, sizeof(info)) != 0) {
                printk(KERN_ERR "[%d] ubdctl_ioctl: userspace address became "
                       "invalid\n", current->pid);
                return -EFAULT;
            }
        } else {
            printk(KERN_DEBUG "[%d] ubdctl_ioctl: register call failed; "
                   "errno=%d.\n", current->pid, (int) -result);
        }

        printk(KERN_DEBUG "[%d] ubdctl_ioctl: returning %ld\n", current->pid,
               result);
        return result;
    }

    case UBD_IOCUNREGISTER: {
        long result;
        
        printk(KERN_DEBUG "[%d] ubdctl_ioctl: UBD_IOCUNREGISTER\n",
               current->pid);

        mutex_lock(&dev->status_lock);
        result = ubdctl_unregister(dev);
        mutex_unlock(&dev->status_lock);

        if (result == 0) {
            printk(KERN_DEBUG "[%d] ubdctl_ioctl: unregister succeeded.\n",
                   current->pid);
        } else {
            printk(KERN_DEBUG "[%d] ubdctl_ioctl: unregister call failed; "
                   "errno=%d\n", current->pid, (int) -result);
        }

        return result;
    }

    case UBD_IOCGETCOUNT: {
        struct list_head *iter;
        size_t count = 0;

        printk(KERN_DEBUG "[%d] ubdctl_ioctl: UBD_IOCGETCOUNT\n",
               current->pid);

        mutex_lock(&ubd_devices_lock);
        list_for_each(iter, &ubd_devices) {
            ++count;
        }
        mutex_unlock(&ubd_devices_lock);

        printk(KERN_DEBUG "[%d] ubdctl_ioctl: UBD_IOCGETCOUNT -- found %zu "
               "devices\n", current->pid, count);
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


static int ubdctl_register(struct ublkdev *dev, struct ubd_info *info) {
    char name[DISK_NAME_LEN + 1];
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


static int ubdctl_unregister(struct ublkdev *dev) {
    uint32_t status;

    BUG_ON(dev == NULL);

    // dev->status_lock *MUST* be held.
    smp_rmb();
    status = READ_ONCE(dev->status);

    if ((status & (UBD_STATUS_REGISTERING | UBD_STATUS_ADDING)) != 0) {
        /* Can't unregister a device coming up. */
        printk(KERN_INFO "[%d] ubdctl_unregister: attempted to "
               "unregister a device in a transient state.\n", current->pid);
        return -EBUSY;
    }

    if ((status & (UBD_STATUS_RUNNING | UBD_STATUS_UNREGISTERING)) == 0) {
        /* Device isn't running. */
        printk(KERN_INFO "[%d] ubdctl_unregister: attempted to "
               "unregister a non-running device.\n", current->pid);
        return -EINVAL;
    }

    status = (status | UBD_STATUS_UNREGISTERING) & ~UBD_STATUS_RUNNING;
    WRITE_ONCE(dev->status, status);
    smp_wmb();
    
    wake_up_interruptible(&dev->status_wait);

    /* Are we serving traffic? */
    if ((status & UBD_STATUS_OPENED) != 0) {
        struct request *req;
        
        printk(KERN_DEBUG "[%d] ubdctl_unregister: unregistering an "
               "open device\n", current->pid);
        
        /* Move the tagged commands back so we can read them again. */
        blk_queue_invalidate_tags(dev->blk_pending);

        /* Wait for the device to be unmounted. */
        while (1) {
            uint32_t status;
            uint32_t n_failed = 0;
            bool unfinished;

            smp_rmb();
            status = READ_ONCE(dev->status);

            if ((dev->status & UBD_STATUS_OPENED) == 0) {
                break;
            }

            printk(KERN_DEBUG "[%d] ubdctl_unregister: device is opened; "
                   "will fail existing requests.\n", current->pid);

            mutex_unlock(&dev->status_lock);
            spin_lock_irq(dev->blk_pending->queue_lock);
            /* Reply to all pending messages. */
            while ((req = blk_fetch_request(dev->blk_pending)) != NULL) {
                spin_unlock_irq(dev->blk_pending->queue_lock);
                if (req->cmd_type == REQ_TYPE_FS) {
                    char const *cmd_type;

                    if (bio_data_dir(req->bio) == WRITE) {
                        cmd_type = req->bio->bi_rw & REQ_DISCARD ?
                            "discard" : "write";
                    } else {
                        cmd_type = "read";
                    }

                    printk(KERN_DEBUG "[%d] ubdctl_unregister: flushing "
                           "%s request", current->pid, cmd_type);
                } else {
                    printk(KERN_DEBUG "[%d] ubdctl_unregister: flushing "
                           "request of type 0x%x", current->pid,
                           req->cmd_type);
                }
                unfinished = blk_end_request_err(req, -EIO);
                BUG_ON(unfinished);
                spin_lock_irq(dev->blk_pending->queue_lock);
                ++n_failed;
            }
            spin_unlock_irq(dev->blk_pending->queue_lock);

            printk(KERN_DEBUG "[%d] ubdctl_unregister: failed %u messages.\n",
                   current->pid, n_failed);

            if (wait_event_interruptible(
                    dev->status_wait,
                    (ubd_get_status(dev) & UBD_STATUS_OPENED) == 0))
            {
                /* Interrupted; we can pick up again, so leave the device in
                   the unregistering state. */
                printk(KERN_INFO "[%d] ubdctl_unregister: unregister "
                       "interrupted.\n", current->pid);
                mutex_lock(&dev->status_lock);
                return -ERESTARTSYS;
            }
        }
    }

    printk(KERN_DEBUG "[%d] ubdctl_unregister: device closed, stopping "
           "disk.\n", current->pid);
    BUG_ON((READ_ONCE(dev->status) & UBD_STATUS_OPENED) != 0);

    /* Stop the disk. */
    del_gendisk(dev->disk);
    dev->disk = NULL;

    printk(KERN_DEBUG "[%d] ubdctl_unregister: disk stopped; cleaning "
           "queue\n", current->pid);
    blk_cleanup_queue(dev->blk_pending);

    /* Clean up the disk structure */
    dev->flags = 0;
    WRITE_ONCE(dev->status, 0);
    dev->blk_pending = NULL;
    dev->disk = NULL;

    printk(KERN_DEBUG "[%d] ubdctl_unregister: queue cleaned; "
           "removing device from list of devices\n", current->pid);

    /* Remove this disk structure from the list of devices. */
    mutex_lock(&ubd_devices_lock);
    list_del(&dev->list);
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
