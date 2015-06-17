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

#define spin_lock(x)                                                    \
    do {                                                                \
        printk(KERN_DEBUG "[%d] %s %d: BEGIN spin_lock(%s)\n",          \
               current->pid, __func__, __LINE__, #x);                   \
        spin_lock(x);                                                   \
        printk(KERN_DEBUG "[%d] %s %d: END   spin_lock(%s)\n",          \
               current->pid, __func__, __LINE__, #x);                   \
    } while (0)

#define spin_unlock(x)                                                  \
    do {                                                                \
        printk(KERN_DEBUG "[%d] %s %d: BEGIN spin_unlock(%s)\n",        \
               current->pid, __func__, __LINE__, #x);                   \
        spin_unlock(x);                                                 \
        printk(KERN_DEBUG "[%d] %s %d: END   spin_unlock(%s)\n",        \
               current->pid, __func__, __LINE__, #x);                   \
    } while (0)

#define spin_lock_irq(x)                                                \
    do {                                                                \
        printk(KERN_DEBUG "[%d] %s %d: BEGIN spin_lock_irq(%s)\n",      \
               current->pid, __func__, __LINE__, #x);                   \
        spin_lock_irq(x);                                               \
        printk(KERN_DEBUG "[%d] %s %d: END   spin_lock_irq(%s)\n",      \
               current->pid, __func__, __LINE__, #x);                   \
    } while (0)

#define spin_unlock_irq(x)                                              \
    do {                                                                \
        printk(KERN_DEBUG "[%d] %s %d: BEGIN spin_unlock_irq(%s)\n",    \
               current->pid, __func__, __LINE__, #x);                   \
        spin_unlock_irq(x);                                             \
        printk(KERN_DEBUG "[%d] %s %d: END  spin_unlock_irq(%s)\n",     \
               current->pid, __func__, __LINE__, #x);                   \
    } while (0)

#define dmutex_lock(x)                                                  \
    do {                                                                \
        printk(KERN_DEBUG "[%d] %s %d: BEGIN mutex_lock(%s)\n",         \
               current->pid, __func__, __LINE__, #x);                   \
        mutex_lock(x);                                                  \
        printk(KERN_DEBUG "[%d] %s %d: END   mutex_lock(%s)\n",         \
               current->pid, __func__, __LINE__, #x);                   \
    } while (0)

#define dmutex_lock_interruptible(x)                                    \
    ({                                                                  \
        int result;                                                     \
                                                                        \
        printk(KERN_DEBUG "[%d] %s %d: BEGIN mutex_lock_interruptible(%s)\n", \
               current->pid, __func__, __LINE__, #x);                   \
        result = mutex_lock_interruptible(x);                           \
        if (result) {                                                   \
            printk(KERN_DEBUG "[%d] %s %d: FAIL  mutex_lock_interruptible(%s)\n", \
                   current->pid, __func__, __LINE__, #x);               \
        } else {                                                        \
            printk(KERN_DEBUG "[%d] %s %d: END   mutex_lock_interruptible(%s)\n", \
                   current->pid, __func__, __LINE__, #x);               \
        }                                                               \
        result;                                                         \
    })

#define dmutex_unlock(x)                                                \
    do {                                                                \
        printk(KERN_DEBUG "[%d] %s %d: BEGIN mutex_unlock(%s)\n",       \
               current->pid, __func__, __LINE__, #x);                   \
        mutex_unlock(x);                                                \
        printk(KERN_DEBUG "[%d] %s %d: END   mutex_unlock(%s)\n",       \
               current->pid, __func__, __LINE__, #x);                   \
    } while (0)


/* ***** Driver global functions and variables. ***** */

/** List of block devices allocated. */
LIST_HEAD(ubd_devices);

/** Lock for ubd_devices. */
DEFINE_MUTEX(ubd_devices_lock);

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
    INIT_LIST_HEAD(&dev->ctl_outgoing_head);
    dev->ctl_current_outgoing = NULL;
    init_waitqueue_head(&dev->ctl_outgoing_wait);
    mutex_init(&dev->outgoing_lock);
    dev->ctl_incoming.n_read = 0;
    dev->ctl_incoming.capacity = UBD_INITIAL_MESSAGE_CAPACITY;
    mutex_init(&dev->incoming_lock);
    dev->blk_pending = NULL;
    dev->status = 0;
    init_waitqueue_head(&dev->status_wait);
    mutex_init(&dev->status_lock);
    dev->flags = 0;

    return 0;
}

static int ubdctl_release(struct inode *inode, struct file *filp) {
    int result;

    if (filp->private_data != NULL) {
        struct ublkdev *dev = filp->private_data;

        printk(KERN_DEBUG "ubdctl_release: releasing dev=%p\n", dev);

        /* This can't be closed while in a transitory state. */
        if (dmutex_lock_interruptible(&dev->status_lock)) {
            printk(KERN_DEBUG "[%d] ubdctl_release: interrupted\n",
                   current->pid);
            return -ERESTARTSYS;
        }
        
        while ((dev->status & UBD_STATUS_TRANSIENT) != 0) {
            printk(KERN_DEBUG "[%d] ubdctl_release: device in transient "
                   "state: 0x%x\n", current->pid, dev->status);

            dmutex_unlock(&dev->status_lock);
            if (wait_event_interruptible(dev->status_wait, dev->status == 0)) {
                printk(KERN_DEBUG "[%d] ubdctl_release: interrupted\n",
                       current->pid);
                /* Interrupted while waiting. */
                return -ERESTARTSYS;
            }
            if (dmutex_lock_interruptible(&dev->status_lock)) {
                printk(KERN_DEBUG "[%d] ubdctl_release: interrupted\n",
                       current->pid);
                return -ERESTARTSYS;
            }
        }

        /* Are we running? */
        while ((dev->status & UBD_STATUS_RUNNING) != 0) {
            /* Yes; unregister the device */
            if ((result = ubdctl_unregister(dev)) != 0) {
                if (result == -EBUSY) {
                    printk(KERN_INFO "[%d] ubdctl_release: failed to "
                           "unregister device: still busy; will retry.\n",
                           current->pid);
                    dmutex_unlock(&dev->status_lock);
                    schedule();
                    if (dmutex_lock_interruptible(&dev->status_lock)) {
                        printk(KERN_DEBUG "[%d] ubdctl_relase: interrupted\n",
                               current->pid);
                        return -ERESTARTSYS;
                    }
                    continue;
                } else {
                    printk(KERN_ERR "[%d] ubdctl_release: failed to "
                           "unregister device: error=%d\n", current->pid,
                           -result);
                    dmutex_unlock(&dev->status_lock);
                    return result;
                }
            }
        }
        
        /* We should now be ok to release the structure. */
        BUG_ON(dev->status != 0);
        dmutex_unlock(&dev->status_lock);
        mutex_destroy(&dev->outgoing_lock);
        mutex_destroy(&dev->incoming_lock);
        mutex_destroy(&dev->status_lock);
        kfree(dev);
        filp->private_data = NULL;
    }

    printk(KERN_DEBUG "ubdctl_release: success\n");

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

    if (dmutex_lock_interruptible(&dev->outgoing_lock)) {
        return -ERESTARTSYS;
    }
    
    while (dev->ctl_current_outgoing == NULL) {
        struct list_head *first_message;

        printk(KERN_DEBUG "[%d] ubdctl_read: no current outgoing message; "
               "looking for a new one.\n", current->pid);

        /* Need to pull a new message off the queue. */
        while (list_empty(& dev->ctl_outgoing_head)) {
            /* No messages; sleep until we have a new one. */
            printk(KERN_DEBUG "[%d] ubdctl_read: queue empty; sleeping.\n",
                   current->pid);

            dmutex_unlock(&dev->outgoing_lock);
            if (wait_event_interruptible(
                    dev->ctl_outgoing_wait,
                    ! list_empty(& dev->ctl_outgoing_head)) ||
                dmutex_lock_interruptible(&dev->outgoing_lock))
            {
                /* Interrupted; give up here. */
                return -ERESTARTSYS;
            }
        }

        /* Get the outgoing message structure first on the list. */
        first_message = dev->ctl_outgoing_head.next;
        dev->ctl_current_outgoing = list_entry(
            first_message, struct ubd_outgoing_message, list);

        /* And remove it from the queue. */
        list_del(first_message);
    }

    out = dev->ctl_current_outgoing;
    printk(KERN_DEBUG "[%d] ubdctl_read: current_outgoing is at %p\n",
           current->pid, out);

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
        printk(KERN_ERR "[%d] ubdctl_read: invalid userspace buffer.\n",
               current->pid);
        dmutex_unlock(&dev->outgoing_lock);
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
        printk(KERN_DEBUG "[%d] ubdctl_read: message completed; "
               "current_outgoing now NULL.\n", current->pid);
    }

    /* Update the file pointer (just to keep tell() happy). */
    *offp += n_to_write;
    dmutex_unlock(&dev->outgoing_lock);    

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

    if (dmutex_lock_interruptible(&dev->incoming_lock)) {
        return -ERESTARTSYS;
    }
    
    in = &dev->ctl_incoming;

    /* Have we read the header yet? */
    if (in->n_read < sizeof(struct ubd_header)) {
        void *rptr;
        
        /* Read just enough to handle the header. */
        n_to_read = sizeof(struct ubd_header) - in->n_read;

        if (n_to_read > size) {
            n_to_read = size;
        }

        rptr = ((char *) in->reply) + in->n_read;
        
        /* Do the move from userspace into kernelspace. */
        if (copy_from_user(rptr, buffer, n_to_read) != 0) {
            /* Failed -- userspace address isn't valid. */
            dmutex_unlock(&dev->incoming_lock);
            printk(KERN_INFO "[%d] ubdctl_write: invalid userspace address.\n",
                   current->pid);
            return -EFAULT;
        }

        /* Adjust pointers to accomodate the part of the header we just
           read. */
        in->n_read += n_to_read;
        n_read += n_to_read;
        *offp += n_to_read;
        buffer += n_to_read;
        size -= n_to_read;

        /* Is the header complete now? */
        if (in->n_read < sizeof(struct ubd_header)) {
            /* Nope; stop here. */
            dmutex_unlock(&dev->incoming_lock);
            printk(KERN_DEBUG "[%d] ubdctl_write: Header not done.\n",
                   current->pid);
            return n_read;
        }

        /* Yes; is the size sensical?  If so, do we have enough capacity? */
        if (in->reply->ubd_header.ubd_size <= UBD_MAX_MESSAGE_SIZE) {
            if (in->capacity < in->reply->ubd_header.ubd_size) {
                /* Need more capacity. */
                struct ubd_reply *newbuf;

                printk(KERN_DEBUG "[%d] ubdctl_write: current buffer is too "
                       "small; resizing from %u to %u bytes.\n",
                       current->pid, in->capacity,
                       in->reply->ubd_header.ubd_size);
                newbuf = kmalloc(in->reply->ubd_header.ubd_size, GFP_NOIO);

                if (newbuf == NULL) {
                    /* Allocation failed -- we need to "unread" what we just
                       read. */
                    printk(KERN_ERR "[%d] ubdctl_write: failed to allocate "
                           "%u bytes.\n", current->pid,
                           in->reply->ubd_header.ubd_size);
                    in->n_read -= n_to_read;
                    *offp -= n_to_read;
                    dmutex_unlock(&dev->incoming_lock);
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
    
    if (n_to_read > size) {
        printk(KERN_DEBUG "[%d] ubdctl_write: only %zu bytes available; "
               "limiting read.\n", current->pid, size);
        n_to_read = size;
    }

    /* Do the copy from userspace. */
    if (copy_from_user(((char *) in->reply) + in->n_read, buffer,
                       n_to_read) != 0)
    {
        printk(KERN_ERR "[%d] ubdctl_write: userspace invalid during "
               "packet body read.\n", current->pid);
        
        /* Failed -- userspace range isn't fully valid. */
        if (n_read > 0) {
            /* Can't return EFAULT here -- we're already read part of the
               buffer to get at the header. */
            printk(KERN_INFO "[%d] ubdctl_write: partial write of "
                   "%zd bytes completed.\n", current->pid, n_read);
            dmutex_unlock(&dev->incoming_lock);
            return n_read;
        } else {
            printk(KERN_INFO "[%d] ubdctl_write: no bytes read; returning "
                   "EFAULT.\n", current->pid);
            dmutex_unlock(&dev->incoming_lock);
            return -EFAULT;
        }
    }

    in->n_read += n_to_read;

    /* Have we read the entire message? */
    if (in->n_read == in->reply->ubd_header.ubd_size) {
        char buffer[320];
        char *p;
        unsigned int i;
        
        /* Yep; parse it. */
        printk(KERN_DEBUG "[%d] ubdctl_write: packet complete; processing.\n",
               current->pid);

        #if 0
        /* Show the received packet. */
        p = buffer;
        for (i = 0; i < in->reply->ubd_header.ubd_size; i += 16) {
            int j, max_j;

            p += sprintf(p, KERN_DEBUG "[%d] %08x:", current->pid, i);
            max_j = i + 16;
            if (max_j > in->reply->ubd_header.ubd_size) {
                max_j = in->reply->ubd_header.ubd_size;
            }
            
            for (j = i; j < max_j; ++j) {
                p += sprintf(p, " %02x", ((char *) in->reply)[j]);
            }

            p += sprintf(p, "\n");
            printk(buffer);
        }
        printk(KERN_DEBUG "[%d] %08x.\n", current->pid,
               in->reply->ubd_header.ubd_size);
        #endif
        ubdctl_handle_reply(dev, in->reply);
        in->n_read = 0;
    } else {
        printk(KERN_DEBUG "[%d] ubdctl_write: packet incomplete: need %u "
               "bytes; have %u bytes.\n", current->pid,
               in->reply->ubd_header.ubd_size, in->n_read);
    }

    dmutex_unlock(&dev->incoming_lock);
    printk(KERN_DEBUG "[%d] ubdctl_write: done\n", current->pid);
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

        dmutex_lock(&dev->outgoing_lock);
        if (dev->ctl_current_outgoing != NULL ||
            ! list_empty(&dev->ctl_outgoing_head))
        {
            result |= (POLLIN | POLLRDNORM);
        }
        dmutex_unlock(&dev->outgoing_lock);
    }

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
        result = ubdctl_unregister(dev);
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

        dmutex_lock(&ubd_devices_lock);
        list_for_each(iter, &ubd_devices) {
            ++count;
        }
        dmutex_unlock(&ubd_devices_lock);

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

        dmutex_lock(&ubd_devices_lock);
        list_for_each(iter, &ubd_devices) {
            struct ublkdev *dev;

            if (index != desc.ubd_index) {
                ++index;
                continue;
            }

            /* Found it; return this. */
            dev = container_of(iter, struct ublkdev, list);
            dmutex_unlock(&ubd_devices_lock);

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
        dmutex_lock(&ubd_devices_lock);
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
    int32_t status;
    uint32_t msgtype;
    uint32_t size;
    uint32_t tag;
    int result = -EINVAL;
    unsigned int n_bytes = 0;
    bool is_unfinished;

    BUG_ON(dev == NULL);
    BUG_ON(reply == NULL);

    status = reply->ubd_status;
    msgtype = reply->ubd_header.ubd_msgtype;
    size = reply->ubd_header.ubd_size;
    tag = reply->ubd_header.ubd_tag;

    printk(KERN_DEBUG "[%d] ubdctl_handle_reply: msgtype=0x%x, size=%u, "
           "tag=%u, status=%d\n", current->pid, msgtype, size, tag, status);

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
            printk(KERN_DEBUG "[%d] ubdctl_handle_reply: sending error back to "
                   "block device.\n", current->pid);
            result = reply->ubd_status;
        } else if (reply->ubd_status != n_sectors) {
            /* Sector count mismatch. */
            printk(KERN_INFO "[%d] ubdctl_handle_reply: expected %u sectors; "
                   "received %u sectors.\n", current->pid, n_sectors,
                   reply->ubd_status);

            result = -EIO;
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
                buffer = page_address(bvec.bv_page) + bvec.bv_offset;
                printk(KERN_DEBUG "[%d] ubdctl_handle_reply: sending data back "
                       "to bio at %p, bv_len=%u, recv_data=%u\n", current->pid, buffer, bvec.bv_len, recv_data);
                memcpy(buffer, reply->ubd_data, recv_data);

                printk(KERN_DEBUG "[%d] ubdctl_handle_reply: ending request\n",
                       current->pid);
                result = 0;
                n_bytes = recv_data;
            }
        } else if ((bio->bi_rw & REQ_DISCARD) != 0) {
            if (msgtype != UBD_MSGTYPE_DISCARD_REPLY) {
                printk(KERN_INFO "[%d] ubdctl_handle_reply: expected discard "
                       "reply packet for tag %u.\n", current->pid, tag);
                result = -EIO;
            } else {
                result = 0;
                n_bytes = 512 * n_sectors;
            }
        } else {
            if (msgtype != UBD_MSGTYPE_WRITE_REPLY) {
                printk(KERN_INFO "[%d] ubdctl_handle_reply: expected write "
                       "reply packet for tag %u.\n", current->pid, tag);
                result = -EIO;
            } else {
                result = 0;
                n_bytes = 512 * n_sectors;
            }
        }
    }

    BUG_ON(result == -EINVAL);

    printk(KERN_INFO "[%d] ubdctl_handle_reply: finishing request\n",
           current->pid);
    is_unfinished = blk_end_request(rq, result, n_bytes);
    BUG_ON(is_unfinished);
    return;
}


static int ubdctl_register(struct ublkdev *dev, struct ubd_info *info) {
    char name[DISK_NAME_LEN + 1];
    struct gendisk *disk;
    int major;
    int result = -EINVAL;

    if (dmutex_lock_interruptible(&dev->status_lock)) {
        return -ERESTARTSYS;
    }
    
    /* Make sure we haven't already registered a disk on this control
       endpoint */
    if (dev->status != 0) {
        printk(KERN_DEBUG "[%d] ubdctl_register: attempted to register "
               "duplicate device\n", current->pid);
        dmutex_unlock(&dev->status_lock);
        return -EBUSY;
    }

    BUG_ON(dev->disk != NULL);

    /* Make sure the name is NUL terminated. */
    memcpy(name, info->ubd_name, DISK_NAME_LEN);
    name[DISK_NAME_LEN] = '\0';

    printk(KERN_DEBUG "[%d] ubdctl_register: disk_name is %s\n",
           current->pid, name);

    /* Register the block device. */
    if ((major = register_blkdev(0, name)) < 0) {
        /* Error -- maybe in the name? */
        printk(KERN_INFO "[%d] ubdctl_register: failed to register block "
               "device with name \"%s\": %d\n", current->pid, name, major);
        dmutex_unlock(&dev->status_lock);
        return major;
    }

    info->ubd_major = (uint32_t) major;
    printk(KERN_DEBUG "[%d] ubdctl_register: major is %ud\n", current->pid,
           (unsigned int) major);

    printk(KERN_DEBUG "[%d] ubdctl_register: initalizing request queue\n",
           current->pid);

    /* Register the request handler */
    dev->blk_pending = blk_init_queue(ubdblk_handle_request, NULL);
    dev->blk_pending->queuedata = dev;

    /* XXX: We only support one segment at a time for now. */
    blk_queue_max_segments(dev->blk_pending, 1);
    if ((result = blk_queue_init_tags(dev->blk_pending, 64, NULL)) != 0) {
        printk(KERN_ERR "[%d] ubdctl_register: failed to initialize tags: "
               "err=%d\n", current->pid, -result);
        dmutex_unlock(&dev->status_lock);
        return result;
    }

    /* Allocate a disk structure. */
    /* FIXME: Allow users to register more than 1 minor. */
    if ((dev->disk = disk = alloc_disk(1)) == NULL) {
        printk(KERN_ERR "[%d] ubdctl_register: failed to allocate gendisk "
               "structure\n", current->pid);
        dmutex_unlock(&dev->status_lock);
        return -ENOMEM;
    }

    printk(KERN_DEBUG "[%d] ubdctl_register: disk structure allocated\n",
           current->pid);

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

    printk(KERN_DEBUG "[%d] ubdctl_register: scheduling worker to invoke "
           "add_disk()\n", current->pid);

    /* Add the disk after this method returns. */
    INIT_WORK(&dev->add_disk_work, ubdblk_add_disk);
    schedule_work(&dev->add_disk_work);

    /* Mark this device as registering */
    dev->status = UBD_STATUS_REGISTERING;
    dev->flags = info->ubd_flags;
    dmutex_unlock(&dev->status_lock);

    printk(KERN_DEBUG "[%d] ubdctl_register: adding this struct to the list "
           "of devices\n", current->pid);

    /* Add this to the list of registered disks. */
    dmutex_lock(&ubd_devices_lock);
    list_add_tail(&dev->list, &ubd_devices);
    dmutex_unlock(&ubd_devices_lock);

    printk(KERN_DEBUG "[%d] ubdctl_register: done", current->pid);

    return 0;
}


static int ubdctl_unregister(struct ublkdev *dev) {
    BUG_ON(dev == NULL);

    if ((dev->status & (UBD_STATUS_REGISTERING | UBD_STATUS_ADDING)) != 0) {
        /* Can't unregister a device coming up. */
        printk(KERN_INFO "[%d] ubdctl_unregister: attempted to "
               "unregister a device in a transient state.\n", current->pid);
        return -EBUSY;
    }

    if ((dev->status & (UBD_STATUS_RUNNING | UBD_STATUS_UNREGISTERING)) == 0) {
        /* Device isn't running. */
        printk(KERN_INFO "[%d] ubdctl_unregister: attempted to "
               "unregister a non-running device.\n", current->pid);
        return -EINVAL;
    }

    dev->status =
        (dev->status | UBD_STATUS_UNREGISTERING) & ~UBD_STATUS_RUNNING;
    wake_up_interruptible(&dev->status_wait);

    /* Are we serving traffic? */
    if ((dev->status & UBD_STATUS_OPENED) != 0) {
        struct request *req;
        
        printk(KERN_DEBUG "[%d] ubdctl_unregister: unregistering an "
               "open device\n", current->pid);
        
        /* Move the tagged commands back so we can read them again. */
        blk_queue_invalidate_tags(dev->blk_pending);

        /* Wait for the device to be unmounted. */
        while ((dev->status & UBD_STATUS_OPENED) != 0) {
            uint32_t n_failed = 0;

            printk(KERN_DEBUG "[%d] ubdctl_unregister: device is opened; "
                   "will fail existing requests.\n", current->pid);
            
            spin_lock(dev->blk_pending->queue_lock);
            /* Reply to all pending messages. */
            while ((req = blk_fetch_request(dev->blk_pending)) != NULL) {
                blk_finish_request(req, -EIO);
                ++n_failed;
            }
            spin_unlock(dev->blk_pending->queue_lock);

            printk(KERN_DEBUG "[%d] ubdctl_unregister: failed %u messages.\n",
                   current->pid, n_failed);

            if (wait_event_interruptible(
                    dev->status_wait,
                    (dev->status & UBD_STATUS_OPENED) == 0))
            {
                /* Interrupted; we can pick up again, so leave the device in
                   the unregistering state. */
                printk(KERN_INFO "[%d] ubdctl_unregister: unregister "
                       "interrupted.\n", current->pid);
                return -ERESTARTSYS;
            }
        }
    }

    printk(KERN_DEBUG "[%d] ubdctl_unregister: device closed, stopping "
           "disk.\n", current->pid);
    BUG_ON((dev->status & UBD_STATUS_OPENED) != 0);

    /* Stop the disk. */
    del_gendisk(dev->disk);
    dev->disk = NULL;

    printk(KERN_DEBUG "[%d] ubdctl_unregister: disk stopped; cleaning "
           "queue\n", current->pid);
    blk_cleanup_queue(dev->blk_pending);

    /* Clean up the disk structure */
    dev->flags = 0;
    dev->status = 0;
    dev->blk_pending = NULL;
    dev->disk = NULL;

    printk(KERN_DEBUG "[%d] ubdctl_unregister: queue cleaned; "
           "removing device from list of devices\n", current->pid);

    /* Remove this disk structure from the list of devices. */
    dmutex_lock(&ubd_devices_lock);
    list_del(&dev->list);
    dmutex_unlock(&ubd_devices_lock);

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

    printk(KERN_DEBUG "[%d] ubdblk_open: dev=%p\n", current->pid, dev);
    
    /* If opened for writing, make sure this isn't read-only. */
    if ((dev->flags & UBD_FL_READ_ONLY) != 0 &&
        (mode & (FMODE_WRITE | FMODE_PWRITE)) != 0)
    {
        return -EACCES;
    }

    if (dmutex_lock_interruptible(&dev->status_lock)) {
        return -ERESTARTSYS;
    }
    
    if ((dev->status & UBD_STATUS_RUNNING) == 0) {
        printk(KERN_ERR "[%d] ubdblk_open: device is not running\n",
               current->pid);
        dmutex_unlock(&dev->status_lock);
        return -EAGAIN;
    }

    if ((dev->status & UBD_STATUS_OPENED) != 0) {
        printk(KERN_ERR "[%d] ubdblk_open: device is already open\n",
               current->pid);
        dmutex_unlock(&dev->status_lock);
        return -EBUSY;
    }
    
    dev->status |= UBD_STATUS_OPENED;
    dmutex_unlock(&dev->status_lock);
    wake_up_interruptible(&dev->status_wait);

    printk(KERN_ERR "[%d] ubdblk_open: success\n", current->pid);

    return 0;
}


static void ubdblk_release(struct gendisk *disk, fmode_t mode) {
    struct ublkdev *dev;

    BUG_ON(disk == NULL);

    dev = disk->private_data;
    BUG_ON(dev == NULL);

    printk(KERN_DEBUG "[%d] ubdblk_release: dev=%p\n", current->pid, dev);

    dmutex_lock(&dev->status_lock);
    BUG_ON((dev->status & UBD_STATUS_OPENED) == 0);
    dev->status &= ~UBD_STATUS_OPENED;
    dmutex_unlock(&dev->status_lock);
    wake_up_interruptible(&dev->status_wait);    

    printk(KERN_DEBUG "[%d] ubdblk_release: success\n", current->pid);
    
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
    printk(KERN_DEBUG "[%d] ubdblk_add_disk: asserting current state\n",
           current->pid);
    dmutex_lock(&dev->status_lock);    
    BUG_ON(dev->status != UBD_STATUS_REGISTERING);
    dev->status = (UBD_STATUS_ADDING | UBD_STATUS_RUNNING);
    dmutex_unlock(&dev->status_lock);
    wake_up_interruptible(&dev->status_wait);

    /* Add the disk to the system. */
    printk(KERN_DEBUG "[%d] ubdblk_add_disk: calling add_disk\n",
           current->pid);
    add_disk(dev->disk);

    /* Go from running+adding to just running */
    dmutex_lock(&dev->status_lock);
    dev->status &= ~UBD_STATUS_ADDING;
    dmutex_unlock(&dev->status_lock);
    wake_up_interruptible(&dev->status_wait);

    printk(KERN_DEBUG "[%d] ubdblk_add_disk: done\n", current->pid);

    return;
}


static void ubdblk_handle_request(struct request_queue *rq) {
    struct ublkdev *dev = rq->queuedata;
    int is_running;
    struct request *req;

    BUG_ON(dev == NULL);
    printk(KERN_DEBUG "[%d] ubdblk_handle_request: dev=%p\n",
           current->pid, dev);

    dmutex_lock(&dev->status_lock);
    is_running = ((dev->status & UBD_STATUS_RUNNING) != 0);
    dmutex_unlock(&dev->status_lock);

    printk(KERN_DEBUG "[%d] ubdblk_handle_request: is_running=%d\n",
           current->pid, is_running);

    /* We can't use blk_fetch_request here -- the tag API also starts the
       request, which will result in a bugcheck. */
    while ((req = blk_peek_request(rq)) != NULL) {
        spin_unlock_irq(rq->queue_lock);

        if (unlikely(! is_running)) {
            /* Device is not running; fail the request. */
            printk(KERN_INFO "[%d] ubdblk_handle_request: device is not "
                   "running; failing request\n", current->pid);
            blk_start_request(req);
            blk_end_request_err(req, -EIO);
        } else {
            printk(KERN_DEBUG "[%d] ubdblk_handle_request: cmd_type is 0x%x\n",
                   current->pid, req->cmd_type);

            switch (req->cmd_type) {
            case REQ_TYPE_FS:
                printk(KERN_DEBUG "[%d] ubdblk_handle_request: handling "
                       "filesystem request\n", current->pid);
                ubdblk_handle_fs_request(dev, req);
                break;

            default:
                printk(KERN_DEBUG "[%d] ubdblk: unknown request type 0x%x\n",
                       current->pid, req->cmd_type);
                blk_start_request(req);
                blk_end_request_err(req, -EIO);
                break;
            }
        }
        
        spin_lock_irq(rq->queue_lock);
    }

    printk(KERN_DEBUG "[%d] ubdblk_handle_request: done\n", current->pid);
}


static void ubdblk_handle_fs_request(struct ublkdev *dev, struct request *rq) {
    struct bio_vec bvec;
    struct req_iterator iter;
    struct ubd_outgoing_message *msg;
    struct ubd_request *ureq;

    printk(KERN_DEBUG "[%d] ubdblk_handle_fs_request: dev=%p rq=%p\n",
           current->pid, dev, rq);
    
    BUG_ON(dev == NULL);
    BUG_ON(rq == NULL);

    rq_for_each_segment(bvec, rq, iter) {
        struct bio *bio = iter.bio;
        size_t req_size = sizeof(*ureq);
        void *data = NULL;
        int tag_result;

        BUG_ON(bio == NULL);
        BUG_ON(bio_segments(bio) != 1);

        printk(KERN_DEBUG "[%d] ubdblk_handle_fs_request: bio=%p "
               "bio_segments=%d\n", current->pid, bio, bio_segments(bio));

        /* Allocate the message structure */
        if ((msg = kmalloc(sizeof(*msg), GFP_NOIO)) == NULL) {
            printk(KERN_ERR "[%d] ubdblk_handle_fs_request: failed to allocate "
                   "%zu bytes for request.\n", current->pid, sizeof(*msg));
            blk_start_request(rq);
            blk_end_request_err(rq, -ENOMEM);
            return;
        }

        if (bio_data_dir(bio) == WRITE && (bio->bi_rw & REQ_DISCARD) == 0) {
            /* Write request -- requires extra data. */
            size_t cur_bytes = bio_cur_bytes(bio);
            req_size += cur_bytes;
            data = bio_data(bio);
            
            printk(KERN_DEBUG "[%d] ubdblk_handle_fs_request: write request; "
                   "cur_bytes=%zu data=%p\n", current->pid, cur_bytes, data);
        }

        /* Allocate the request structure */
        if ((ureq = kmalloc(req_size, GFP_NOIO)) == NULL) {
            printk(KERN_ERR "[%d] ubdblk_handle_fs_request: failed to allocate "
                   "%zu bytes for request.\n", current->pid, req_size);
            kfree(msg);
            blk_start_request(rq);
            blk_end_request_err(rq, -ENOMEM);
            return;
        }

        /* Allocate a tag for this request */
        printk(KERN_ERR "[%d] ubdblk_handle_fs_request: rq->q=%p\n",
               current->pid, rq->q);
        BUG_ON(dev->blk_pending == NULL);
        spin_lock(dev->blk_pending->queue_lock);
        tag_result = blk_queue_start_tag(dev->blk_pending, rq);
        spin_unlock(dev->blk_pending->queue_lock);
        
        if (tag_result != 0) {
            /* Out of tags; give up. */
            printk(KERN_ERR "[%d] ubdblk_handle_fs_request: could not get a "
                   "tag for a request\n", current->pid);
            kfree(msg->request);
            kfree(msg);
            blk_start_request(rq);
            blk_end_request_err(rq, -ENOMEM);
            return;
        }

        printk(KERN_DEBUG "ubdblk_handle_fs_request: tag=%d\n", rq->tag);

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
        printk(KERN_DEBUG "[%d] ubdblk_handle_fs_request: adding message to "
               "queue\n", current->pid);
        dmutex_lock(&dev->outgoing_lock);
        list_add_tail(&msg->list, &dev->ctl_outgoing_head);
        printk(KERN_DEBUG "[%d] ubdblk_handle_fs_request: request added\n",
            current->pid);
        dmutex_unlock(&dev->outgoing_lock);
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
