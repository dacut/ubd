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

static int ubd_major = 0;
module_param(ubd_major, int, 0444);
MODULE_PARM_DESC(ubd_major, "UBD major node");

/* ***** Driver global functions and variables. ***** */

/** List of block devices allocated. */
LIST_HEAD(ubd_devices);

/** Lock for ubd_devices. */
DEFINE_SPINLOCK(ubd_devices_lock);

/** Initialize the driver. */
static int __init ubd_init(void);

/** Clean up the driver. */
static void __exit ubd_exit(void);


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

/** Unregister a disk from the control endpoint. */
static int ubdctl_unregister(struct ublkdev *dev);

/** Unregister a disk from the control endpoint.
 *
 *  This variant assumes the spinlock for the device is already held.
 */
static int ubdctl_unregister_nolock(struct ublkdev *dev);

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
        printk(KERN_ERR "ubdctl failed to register misc device: "
               "error code %d\n", result);
        goto error;
    }

    printk(KERN_DEBUG "ubdctl registered as device %d:%d\n", MISC_MAJOR,
           ubdctl_miscdevice.minor);

    /* Register the block device */
    if ((result = register_blkdev(ubd_major, "ubd")) < 0) {
        printk(KERN_ERR "ubd failed to register block device: "
               "error code %d\n", result);
        goto error;
    }

    if (ubd_major == 0) {
        ubd_major = result;
    }

    printk(KERN_DEBUG "ubd registered as block device %d\n", ubd_major);

    return 0;

error:
    ubd_exit();

    return result;
}


static void __exit ubd_exit(void) {
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
    /* Allocate the ublkdev structure associated with this control point.
       Do not allow I/O to happen; we could loop if the system has a swapfile
       mounted on a ublkdev device. */
    struct ublkdev *dev;

    dev = kmalloc(sizeof(struct ublkdev), GFP_NOIO);
    if (dev == NULL) {
        return -ENOMEM;
    }

    if ((dev->ctl_incoming.reply = kmalloc(
             UBD_INITIAL_MESSAGE_CAPACITY, GFP_NOIO)) == NULL)
    {
        printk(KERN_ERR "ubd: failed to allocate %zu bytes for incoming "
               "replies.\n", UBD_INITIAL_MESSAGE_CAPACITY);
        kfree(dev);
        return -ENOMEM;
    }

    filp->private_data = dev;

    /* Initialize the structure. */
    dev->disk = NULL;
    spin_lock_init(&dev->lock);
    INIT_LIST_HEAD(&dev->ctl_outgoing_head);
    dev->ctl_current_outgoing = NULL;
    init_waitqueue_head(&dev->ctl_outgoing_wait);
    dev->ctl_incoming.n_read = 0;
    dev->ctl_incoming.capacity = UBD_INITIAL_MESSAGE_CAPACITY;
    dev->blk_pending = NULL;
    dev->status = 0;
    init_waitqueue_head(&dev->status_wait);
    dev->flags = 0;

    return 0;
}

static int ubdctl_release(struct inode *inode, struct file *filp) {
    int result;

    if (filp->private_data != NULL) {
        struct ublkdev *dev = filp->private_data;

        spin_lock(&dev->lock);
        /* This can't be closed while in a transitory state. */
        while ((dev->status & UBD_STATUS_TRANSIENT) != 0) {
            spin_unlock(&dev->lock);
            if (wait_event_interruptible(
                    dev->status_wait,
                    (dev->status & UBD_STATUS_TRANSIENT) == 0))
            {
                /* Interrupted while waiting. */
                return -ERESTARTSYS;
            }
            spin_lock(&dev->lock);
        }

        /* Are we running? */
        if ((dev->status & UBD_STATUS_RUNNING) != 0) {
            /* Yes; unregister the device */
            if ((result = ubdctl_unregister_nolock(dev)) != 0) {
                spin_unlock(&dev->lock);
                return result;
            }

            /* Wait for the device to become idle again. */
            while (dev->status != 0) {
                spin_unlock(&dev->lock);
                if (wait_event_interruptible(dev->status_wait,
                                             dev->status == 0))
                {
                    /* Interrupted while waiting. */
                    spin_unlock(&dev->lock);
                    return -ERESTARTSYS;
                }
            }
        }

        /* We should now be ok to release the structure. */
        BUG_ON(dev->status != 0);
        kfree(dev);
        filp->private_data = NULL;
    }

    return 0;
}

static ssize_t ubdctl_read(struct file *filp, char *buffer, size_t size,
                           loff_t *offp)
{
    struct ublkdev *dev = filp->private_data;
    struct ubd_outgoing_message *out;
    size_t n_to_write;
    size_t n_pending;

    BUG_ON(dev == NULL);

    spin_lock(&dev->lock);

    while (dev->ctl_current_outgoing == NULL) {
        struct list_head *first_message;

        /* Need to pull a new message off the queue. */
        while (list_empty(& dev->ctl_outgoing_head)) {
            /* No messages; sleep until we have a new one. */
            spin_unlock(&dev->lock);

            if (wait_event_interruptible(
                    dev->ctl_outgoing_wait,
                    ! list_empty(& dev->ctl_outgoing_head)))
            {
                /* Interrupted; give up here. */
                return -ERESTARTSYS;
            }

            spin_lock(&dev->lock);
        }

        /* Get the outgoing message structure first on the list. */
        first_message = dev->ctl_outgoing_head.next;
        dev->ctl_current_outgoing = list_entry(
            first_message, struct ubd_outgoing_message, list);

        /* And remove it from the queue. */
        list_del(first_message);
    }

    out = dev->ctl_current_outgoing;

    /* Write as much as we can to userspace. */
    n_pending = out->request->ubd_header.ubd_size - out->n_written;
    n_to_write = size;
    if (n_to_write > n_pending) {
        n_to_write = n_pending;
    }

    if (copy_to_user(buffer, ((char *) out->request) + out->n_written,
                     n_to_write) != 0)
    {
        /* Failed -- userspace address isn't valid. */
        spin_unlock(&dev->lock);
        return -EFAULT;
    }

    /* Update the pointer on the message to indicate how much we wrote. */
    out->n_written += n_to_write;

    /* Are we done with this message? */
    if (out->n_written == out->request->ubd_header.ubd_size) {
        /* Yes -- discard it. */
        kfree(out->request);
        kfree(out);
        dev->ctl_current_outgoing = NULL;
    }

    spin_unlock(&dev->lock);

    /* Update the file pointer (just to keep tell() happy). */
    *offp += n_to_write;

    return n_to_write;
}

static ssize_t ubdctl_write(struct file *filp, const char *buffer, size_t size,
                            loff_t *offp)
{
    struct ublkdev *dev = filp->private_data;
    struct ubd_incoming_message *in;
    ssize_t n_read = 0;
    ssize_t n_to_read = 0;

    BUG_ON(dev == NULL);

    spin_lock(&dev->lock);

    in = &dev->ctl_incoming;

    /* Have we read the header yet? */
    if (in->n_read < sizeof(struct ubd_header)) {
        /* Read just enough to handle the header. */
        n_to_read = sizeof(struct ubd_header) - in->n_read;

        if (n_to_read > size) {
            n_to_read = size;
        }

        /* Do the move from userspace into kernelspace. */
        if (copy_from_user(((char *) in->reply) + in->n_read, buffer,
                           n_to_read) != 0)
        {
            /* Failed -- userspace address isn't valid. */
            spin_unlock(&dev->lock);
            return -EFAULT;
        }

        /* Adjust pointers to accomodate the part of the header we just read. */
        in->n_read += n_to_read;
        n_read += n_to_read;
        *offp += n_to_read;
        buffer += n_to_read;
        size -= n_to_read;

        /* Is the header complete now? */
        if (in->n_read < sizeof(struct ubd_header)) {
            /* Nope; stop here. */
            spin_unlock(&dev->lock);
            return n_read;
        }

        /* Yes; is the size sensical?  If so, do we have enough capacity? */
        if (in->reply->ubd_header.ubd_size <= UBD_MAX_MESSAGE_SIZE) {
            if (in->capacity < in->reply->ubd_header.ubd_size) {
                /* Need more capacity. */
                struct ubd_reply *newbuf = kmalloc(
                    in->reply->ubd_header.ubd_size, GFP_NOIO);

                if (newbuf == NULL) {
                    /* Allocation failed -- we need to "unread" what we just
                       read. */
                    spin_unlock(&dev->lock);
                    in->n_read -= n_to_read;
                    *offp -= n_to_read;
                    return -ENOMEM;
                }

                /* Shuffle the buffers around. */
                memcpy(newbuf, in->reply, in->n_read);
                kfree(in->reply);
                in->reply = newbuf;
            }
        }
    }

    n_to_read = in->reply->ubd_header.ubd_size - in->n_read;
    if (n_to_read >= size) {
        n_to_read = size;
    }

    /* Do the copy from userspace. */
    if (copy_from_user(((char *) in->reply) + in->n_read, buffer,
                       n_to_read) != 0)
    {
        /* Failed -- userspace range isn't fully valid. */
        spin_unlock(&dev->lock);

        if (n_read > 0) {
            /* Can't return EFAULT here -- we're already read part of the
               buffer to get at the header. */
            return n_read;
        } else {
            return -EFAULT;
        }
    }

    /* Have we read the entire message? */
    if (in->n_read == in->reply->ubd_header.ubd_size) {
        /* Yep; parse it. */
        ubdctl_handle_reply(dev, in->reply);
    }

    spin_unlock(&dev->lock);
    return n_read;
}


static unsigned int ubdctl_poll(struct file *filp, poll_table *wait) {
    struct ublkdev *dev = filp->private_data;
    unsigned long req_events = poll_requested_events(wait);
    unsigned int result = 0;

    BUG_ON(dev == NULL);

    if ((req_events & (POLLIN | POLLRDNORM)) != 0) {
        /* Indicate when data is available. */
        poll_wait(filp, &dev->ctl_outgoing_wait, wait);

        spin_lock(&dev->lock);
        if (dev->ctl_current_outgoing != NULL ||
            ! list_empty(&dev->ctl_outgoing_head))
        {
            result |= (POLLIN | POLLRDNORM);
        }
        spin_unlock(&dev->lock);
    }

    /* XXX: Reevaluate should we create a queue for outgoing replies. */
    result |= POLLOUT | POLLWRNORM;

    return result;
}


static long ubdctl_ioctl(struct file *filp, unsigned int cmd,
                         unsigned long data)
{
    struct ublkdev *dev = filp->private_data;

    printk(KERN_DEBUG "ubd: ioctl(%u, 0x%lx)\n", cmd, data);

    BUG_ON(dev == NULL);

    switch (cmd) {
    case UBD_IOCREGISTER: {
        struct ubd_info info;
        long result;

        printk(KERN_DEBUG "ubd: UBD_IOCREGISTER -- copying structures from "
               "userspace\n");
        
        /* Get the disk info from userspace. */
        if (copy_from_user(&info, (void *) data, sizeof(info)) != 0) {
            printk(KERN_DEBUG "ubd: invalid userspace address\n");
            return -EFAULT;
        }

        printk(KERN_DEBUG "ubd: info: ubd_name=\"%.8s\", ubd_flags=0x%x, ubd_nsectors=%lu, ubd_major=%ud, ubd_minor=%ud\n", info.ubd_name, info.ubd_flags, info.ubd_nsectors, info.ubd_major, info.ubd_minor);
        printk(KERN_DEBUG "ubd: registering device\n");

        result = ubdctl_register(dev, &info);
        if (result == 0) {
            printk(KERN_DEBUG "ubd: register call succeeded; copying results back to userspace\n");
            /* Copy the disk info back to userspace. */
            if (copy_to_user((void *) data, &info, sizeof(info)) != 0) {
                printk(KERN_ERR "ubd: userspace address became invalid\n");
                return -EFAULT;
            }
        } else {
            printk(KERN_DEBUG "ubd: register call failed.\n");
        }

        printk(KERN_DEBUG "ubd: returning %ld\n", result);
        return result;
    }

    case UBD_IOCUNREGISTER: {
        return ubdctl_unregister(dev);
    }

    case UBD_IOCGETCOUNT: {
        struct list_head *iter;
        size_t count = 0;

        printk(KERN_DEBUG "ubd: UBD_IOCGETCOUNT -- locking ubd_devices\n");

        spin_lock(&ubd_devices_lock);
        list_for_each(iter, &ubd_devices) {
            ++count;
        }
        spin_unlock(&ubd_devices_lock);

        printk(KERN_DEBUG "ubd: UBD_IOCGETCOUNT -- found %zu devices\n",
               count);
        return count;
    }

    case UBD_IOCDESCRIBE: {
        struct ubd_describe desc;
        struct list_head *iter;
        size_t index = 0;

        /* Get the describe structure from userspace. */
        if (copy_from_user(&desc, (void *) data, sizeof(desc)) != 0) {
            printk(KERN_DEBUG "ubd: invalid userspace address\n");
            return -EFAULT;
        }

        spin_lock(&ubd_devices_lock);
        list_for_each(iter, &ubd_devices) {
            struct ublkdev *dev;

            if (index != desc.ubd_index) {
                ++index;
                continue;
            }

            /* Found it; return this. */
            dev = container_of(iter, struct ublkdev, list);
            spin_unlock(&ubd_devices_lock);
            spin_lock(&dev->lock);

            if (dev->disk == NULL) {
                /* Already deallocated? */
                spin_unlock(&dev->lock);
                return -EAGAIN;
            }

            memcpy(desc.ubd_info.ubd_name, dev->disk->disk_name,
                   DISK_NAME_LEN);
            desc.ubd_info.ubd_flags = dev->flags;
            desc.ubd_info.ubd_nsectors = get_capacity(dev->disk);
            desc.ubd_info.ubd_major = dev->disk->major;
            desc.ubd_info.ubd_minor = dev->disk->first_minor;

            spin_unlock(&dev->lock);

            if (copy_to_user((void *) data, &desc, sizeof(desc)) != 0) {
                printk(KERN_DEBUG "ubd: invalid userspace address\n");
                return -EFAULT;
            }

            return 0;
        }
        spin_unlock(&ubd_devices_lock);
        return -EINVAL;
    }

    default:
        return -EINVAL;
    }

    return -EINVAL;
}


static void ubdctl_handle_reply(struct ublkdev *dev, struct ubd_reply *reply) {
    struct bio_vec bvec;
    struct req_iterator iter;
    struct request *rq;
    uint32_t msgtype = reply->ubd_header.ubd_msgtype;
    uint32_t size = size;

    /* Make sure the message type and size are sensical. */
    if (msgtype == UBD_MSGTYPE_READ_REPLY) {
        if (size < offsetof(struct ubd_reply, ubd_data)) {
            printk(KERN_INFO "ubd: received invalid read reply packet with "
                   "size %u (minimum is %zu)\n", size,
                   offsetof(struct ubd_reply, ubd_data));
            return;
        }

        /* Make sure the size of the data is on a sector boundary. */
        if ((size - offsetof(struct ubd_reply, ubd_data)) % 512 != 0) {
            printk(KERN_INFO "ubd: received invalid read reply packet with "
                   "size %u (not a sector-sized reply)\n", size);
            return;
        }
    } else if (msgtype == UBD_MSGTYPE_WRITE_REPLY) {
        if (size != sizeof(struct ubd_reply)) {
            printk(KERN_INFO "ubd: received invalid write reply packet with "
                   "size %u (expected %zu)\n", size, sizeof(struct ubd_reply));
            return;
        }
    } else if (msgtype == UBD_MSGTYPE_DISCARD_REPLY) {
        if (size != sizeof(struct ubd_reply)) {
            printk(KERN_INFO "ubd: received invalid discard reply packet "
                   "with size %u (expected %zu)\n", size,
                   sizeof(struct ubd_reply));
            return;
        }
    } else {
        printk(KERN_INFO "ubd: received invalid reply type 0x%x\n", msgtype);
        return;
    }

    spin_lock(&dev->lock);

    /* Find the request this belongs to. */
    rq = blk_queue_find_tag(dev->blk_pending, reply->ubd_header.ubd_tag);
    if (rq == NULL) {
        spin_unlock(&dev->lock);
        printk(KERN_INFO "ubd: received reply for unknown tag %u\n",
               reply->ubd_header.ubd_tag);
        return;
    }

    rq_for_each_segment(bvec, rq, iter) {
        struct bio *bio = iter.bio;
        uint32_t n_sectors = bio_sectors(bio);

        BUG_ON(bio_segments(bio) != 1);

        if (reply->ubd_status < 0) {
            /* Error received */
            blk_end_request_err(rq, reply->ubd_status);
        } else if (reply->ubd_status != n_sectors) {
            /* Sector count mismatch. */
            printk(KERN_INFO "ubd: expected %u sectors; received %u "
                   "sectors.\n", n_sectors, reply->ubd_status);
            blk_end_request_err(rq, -EIO);
        } else if (bio_data_dir(bio) == READ) {
            /* Read request */
            uint32_t recv_data = reply->ubd_header.ubd_size -
                offsetof(struct ubd_reply, ubd_data);

            if (msgtype != UBD_MSGTYPE_READ_REPLY) {
                /* Reply type doesn't match what was requested. */
                printk(KERN_INFO "ubd: expected read reply packet.\n");
                blk_end_request_err(rq, -EIO);
            } else if (recv_data != 512 * n_sectors) {
                /* Reply size does not match the requested size. */
                printk(KERN_INFO "ubd: expected %u bytes; received %u bytes.\n",
                       512 * n_sectors, recv_data);
                blk_end_request_err(rq, -EIO);
            } else {
                /* Ok -- copy the data back. */
                memcpy(bio_data(bio), reply->ubd_data, recv_data);
                blk_end_request(rq, 0, recv_data);
            }
        } else if ((bio->bi_rw & REQ_DISCARD) != 0) {
            if (msgtype != UBD_MSGTYPE_DISCARD_REPLY) {
                printk(KERN_INFO "ubd: expected discard reply packet.\n");
                blk_end_request_err(rq, -EIO);
            } else {
                blk_end_request(rq, 0, 0);
            }
        } else {
            if (msgtype != UBD_MSGTYPE_WRITE_REPLY) {
                printk(KERN_INFO "ubd: expected write reply packet.\n");
                blk_end_request_err(rq, -EIO);
            } else {
                blk_end_request(rq, 0, 0);
            }
        }
    }

    blk_queue_end_tag(rq->q, rq);
    spin_unlock(&dev->lock);
    return;
}


static int ubdctl_register(struct ublkdev *dev, struct ubd_info *info) {
    char name[DISK_NAME_LEN + 1];
    struct gendisk *disk;
    int major;
    int result = -EINVAL;

    printk(KERN_DEBUG "ubdctl_register: locking spinlock\n");
    spin_lock(&dev->lock);

    /* Make sure we haven't already registered a disk on this control
       endpoint */
    if (dev->status != 0) {
        printk(KERN_DEBUG "ubd: attempted to register duplicate device\n");
        result = -EBUSY;
        goto done;
    }

    printk(KERN_DEBUG "faulting if dev->disk is non-NULL\n");
    BUG_ON(dev->disk != NULL);
    printk(KERN_DEBUG "dev->disk is null\n");

    /* Make sure the name is NUL terminated. */
    memcpy(name, info->ubd_name, DISK_NAME_LEN);
    name[DISK_NAME_LEN] = '\0';

    printk(KERN_DEBUG "disk_name is %s\n", name);

    /* Register the block device. */
    if ((major = register_blkdev(0, name)) < 0) {
        /* Error -- maybe in the name? */
        printk(KERN_INFO "ubd: failed to register block device with name "
               "\"%s\": %d\n", name, major);
        result = major;
        goto done;
    }

    info->ubd_major = (uint32_t) major;
    printk(KERN_DEBUG "major is %ud\n", (unsigned int) major);

    /* Allocate a disk structure. */
    /* FIXME: Allow users to register more than 1 minor. */
    if ((dev->disk = disk = alloc_disk(1)) == NULL) {
        printk(KERN_ERR "ubd: failed to allocate gendisk structure\n");
        result = -ENOMEM;
        goto done;
    }

    printk(KERN_DEBUG "disk structure allocated\n");

    /* Fill in the disk structure. */
    disk->major = major;
    disk->first_minor = 0;
    disk->minors = 1;
    memcpy(disk->disk_name, name, DISK_NAME_LEN);
    disk->fops = &ubdblk_fops;
    disk->queue = dev->blk_pending;
    disk->flags =
        (info->ubd_flags & UBD_FL_REMOVABLE) ? GENHD_FL_REMOVABLE : 0;
    set_capacity(disk, info->ubd_nsectors);
    disk->private_data = dev;

    printk(KERN_DEBUG "inializing request queue\n");

    /* Register the request handler */
    dev->blk_pending = blk_init_queue(ubdblk_handle_request, NULL);
    dev->blk_pending->queuedata = dev;

    /* XXX: We only support one segment at a time for now. */
    blk_queue_max_segments(dev->blk_pending, 1);

    printk(KERN_DEBUG "scheduling worker to add_disk()\n");

    /* Add the disk after this method returns. */
    INIT_WORK(&dev->add_disk_work, ubdblk_add_disk);
    schedule_work(&dev->add_disk_work);

    /* Mark this device as registering */
    dev->status = UBD_STATUS_REGISTERING;
    wake_up_interruptible(&dev->status_wait);
    dev->flags = info->ubd_flags;
    result = 0;

    printk(KERN_DEBUG "adding this struct to the list of devices\n");

    /* Add this to the list of registered disks. */
    spin_lock(&ubd_devices_lock);
    list_add_tail(&dev->list, &ubd_devices);
    spin_unlock(&ubd_devices_lock);

    printk(KERN_DEBUG "done, releasing device spinlock\n");

done:
    spin_unlock(&dev->lock);
    return result;
}


static int ubdctl_unregister(struct ublkdev *dev) {
    int result;

    spin_lock(&dev->lock);
    result = ubdctl_unregister_nolock(dev);
    spin_lock(&dev->lock);

    return result;
}


static int ubdctl_unregister_nolock(struct ublkdev *dev) {
    if ((dev->status & (UBD_STATUS_REGISTERING | UBD_STATUS_ADDING)) != 0) {
        /* Can't unregister a device coming up. */
        printk(KERN_INFO "ubd: attempted to unregister a device in a "
               "transient state.\n");
        return -EBUSY;
    }

    if ((dev->status & (UBD_STATUS_RUNNING | UBD_STATUS_UNREGISTERING)) == 0) {
        /* Device isn't running. */
        printk(KERN_INFO "ubd: attempted to unregister a non-running "
               "device.\n");
        return -EINVAL;
    }

    dev->status &= ~UBD_STATUS_RUNNING;
    dev->status |= UBD_STATUS_UNREGISTERING;
    wake_up_interruptible(&dev->status_wait);

    /* Are we serving traffic? */
    if ((dev->status & UBD_STATUS_OPENED) != 0) {
        /* Reply to all pending messages. */
        blk_queue_invalidate_tags(dev->blk_pending);

        /* Wait for the device to be unmounted. */
        while ((dev->status & UBD_STATUS_OPENED) != 0) {
            int wait_result;

            spin_unlock(&dev->lock);
            wait_result = wait_event_interruptible(
                dev->status_wait,
                (dev->status & UBD_STATUS_OPENED) == 0);
            spin_lock(&dev->lock);

            if (wait_result != 0) {
                /* Interrupted; we can pick up again, so leave the device in
                   the unregistering state. */
                return -ERESTARTSYS;
            }
        }
    }

    BUG_ON((dev->status & UBD_STATUS_OPENED) != 0);

    /* Stop the disk. */
    del_gendisk(dev->disk);

    /* Clean up the disk structure */
    dev->flags = 0;
    dev->status = 0;
    blk_cleanup_queue(dev->blk_pending);
    dev->blk_pending = NULL;
    dev->disk = NULL;

    /* Remove this disk structure from the list of devices. */
    spin_lock(&ubd_devices_lock);
    list_del(&dev->list);
    spin_unlock(&ubd_devices_lock);

    return 0;
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

    return 0;
}


static void ubdblk_release(struct gendisk *disk, fmode_t mode) {
    return;
}


static int ubdblk_ioctl(struct block_device *blkdev, fmode_t mode,
                        unsigned int cmd, unsigned long data)
{
    /* FIXME: Implement ioctls */
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

    BUG_ON(dev == NULL);

    /* Go from registering to running+adding */
    spin_lock(&dev->lock);
    BUG_ON(dev->status != UBD_STATUS_REGISTERING);
    dev->status = (UBD_STATUS_ADDING | UBD_STATUS_RUNNING);
    wake_up_interruptible(&dev->status_wait);

    /* Add the disk to the system. */
    spin_unlock(&dev->lock);
    add_disk(dev->disk);
    spin_lock(&dev->lock);

    /* Go from running+adding to just running */
    dev->status &= ~UBD_STATUS_ADDING;
    wake_up_interruptible(&dev->status_wait);
    spin_unlock(&dev->lock);

    return;
}


static void ubdblk_handle_request(struct request_queue *rq) {
    struct ublkdev *dev = rq->queuedata;
    int is_running;
    struct request *req;

    spin_lock(&dev->lock);
    is_running = ((dev->status & UBD_STATUS_RUNNING) != 0);
    spin_unlock(&dev->lock);

    while ((req = blk_fetch_request(rq)) != NULL) {
        if (unlikely(! is_running)) {
            /* Device is not running; fail the request. */
            blk_end_request_err(req, -EIO);
            continue;
        }

        spin_unlock_irq(rq->queue_lock);

        switch (req->cmd_type) {
            case REQ_TYPE_FS:
            ubdblk_handle_fs_request(dev, req);
            break;

            default:
            printk(KERN_DEBUG "ubd ignoring request type %d", req->cmd_type);
            break;
        }

        spin_lock_irq(rq->queue_lock);
    }
}


static void ubdblk_handle_fs_request(struct ublkdev *dev, struct request *rq) {
    struct bio_vec bvec;
    struct req_iterator iter;
    struct ubd_outgoing_message *msg;
    struct ubd_request *ureq;

    rq_for_each_segment(bvec, rq, iter) {
        struct bio *bio = iter.bio;
        size_t req_size = sizeof(*ureq);
        void *data = NULL;

        BUG_ON(bio_segments(bio) != 1);

        /* Allocate the message structure */
        if ((msg = kmalloc(sizeof(*msg), GFP_NOIO)) == NULL) {
            printk(KERN_ERR "ubd: failed to allocate %zu bytes for request.\n",
                   sizeof(*msg));
            blk_end_request_err(rq, -ENOMEM);
            return;
        }

        if (bio_data_dir(bio) == WRITE && (bio->bi_rw & REQ_DISCARD) == 0) {
            /* Write request -- requires extra data. */
            req_size += bio_cur_bytes(bio);
            data = bio_data(bio);
        }

        /* Allocate the request structure */
        if ((ureq = kmalloc(req_size, GFP_NOIO)) == NULL) {
            printk(KERN_ERR "ubd: failed to allocate %zu bytes for request.\n",
                   req_size);
            kfree(msg);
            blk_end_request_err(rq, -ENOMEM);
            return;
        }

        /* Allocate a tag for this request */
        if (blk_queue_start_tag(rq->q, rq) != 0) {
            /* Out of tags; give up. */
            printk(KERN_ERR "ubd: could not get a tag for a request\n");
            kfree(msg->request);
            kfree(msg);
            blk_end_request_err(rq, -ENOMEM);
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
        ureq->ubd_first_sector = iter.iter.bi_sector;
        ureq->ubd_nsectors = bio_sectors(bio);

        if (data != NULL) {
            memcpy(ureq->ubd_data, data, bio_cur_bytes(bio));
        }

        /* Queue the request for the control endpoint. */
        spin_lock(&dev->lock);
        list_add_tail(&msg->list, &dev->ctl_outgoing_head);
        spin_unlock(&dev->lock);
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
