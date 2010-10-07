/** @file   ublkdev.c
 *  @brief  
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/types.h>

#include "ublkdev.h"

MODULE_AUTHOR("dacut@kanga.org");
MODULE_DESCRIPTION("Userspace block devices");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(UBLKDEV_MODULE_VERSION);

static int ubd_major = 0;
module_param(ubd_major, int, 0);
static int ubd_maxdevices = 4;
module_param(ubd_maxdevices, int, 4);

static struct ublkdev *ubd_devices = NULL;

static ssize_t ubdctl_read(
    struct file *filp,
    char *buffer,
    size_t size,
    loff_t *offp);

static ssize_t ubdctl_write(
    struct file *filp,
    const char *buffer,
    size_t size,
    loff_t *offp);

static unsigned int ubdctl_poll(
    struct file *filp,
    poll_table *wait);

static int ubdctl_ioctl(
    struct inode *inode,
    struct file *filp,
    unsigned int cmd,
    unsigned long data);

static void __exit ubd_exit(void);


/** Called when the control endpoint is opened by a process. */
static int ubdctl_open(
    struct inode *inode,
    struct file *filp)
{
    /* Allocate the ublkdev structure associated with this control point.
       Do not allow I/O to happen; we could loop if the system has a swapfile
       mounted on a ublkdev device. */
    filp->private_data = kmalloc(sizeof(struct ublkdev), GFP_NOIO);

    if (filp->private_data == NULL)
        return -ENOMEM;

    return 0;
}

static int ubdctl_release(
    struct inode *inode,
    struct file *filp)
{
    if (filp->private_data != NULL) {
        kfree(filp->private_data);
        filp->private_data = NULL;
    }

    return 0;
}

static struct file_operations ubdctl_fops = {
    .owner = THIS_MODULE,
    .llseek = no_llseek,
    .read = ubdctl_read,
    .write = ubdctl_write,
    .poll = ubdctl_poll,
    .ioctl = ubdctl_ioctl,
    .open = ubdctl_open,
    .release = ubdctl_release,
};

static struct miscdevice ubdctl_miscdevice = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "ubdctl",
    .fops = &ubdctl_fops,
};

static void ubd_request(request_queue_t *rq)
{
    struct ublkdev *dev = rq->queuedata;
    struct request *req;
    
    while ((req = elv_next_request(rq)) != NULL) {
        switch (req->cmd_type) {
            case REQ_TYPE_FS:
            ubd_handle_fs_request(dev, req);
            break;

            default:
            printk(KERN_DEBUG "ubd ignoring request type %d", req->cmd_type);
            break;
        }
    }
}

/** Serialize a read/write request.
 *
 *  Request format:
 *  Offset  Size    Content
 *   0      4       Request id
 *   4      4       "READ" or "WRIT"
 *   8      8       Total request size.
 *  16      8       Number of BIOs
 *  24      ...     First BIO.
 *
 *  BIO format:
 *  Offset  Size    Content
 *   0      8       Sector
 *   8      8       Flags
 *  16      8       R/W flags
 *  24      8       Size of data
 *  32      ...     Data [write requests only]
 */
static void ubd_handle_fs_request(struct ublkdev *dev, struct request *req)
{
    __u64 serialized_size = 24;  /* Overhead before first BIO. */
    __u64 n_bios = 0; /* Number of BIOs. */
    struct ublkdev_request *ureq = NULL;
    char *sreq = NULL;
    char *sreqp;
    struct bio *bio;
    int req_id;
    int is_write = (rq_data_dir(req) == WRITE);

    /* Calculate the size contribution of each bio request */
    rq_for_each_bio(bio, req) {
        ++n_bios;

        /* Each BIO requires 32 bytes of overhead. */
        serialized_size += 32;
        
        if (is_write) {
            struct bio_vec *bvec;
            int i;

            /* Add the size of each segment to the total size. */
            bio_for_each_segment(bvec, bio, i) {
                serialized_size += bvec->bv_len;
            }
        }
    }

    /* Done calculating.  Allocate the actual request buffer. */
    sreqp = sreq = kmalloc(serialized_size, GFP_KERNEL);
    if (sreq == NULL) {
        printk(KERN_ERR "ubd failed to allocate %u bytes", serialized_size);
        goto error;
    }

    /* Allocate a request id. */
    req_id = atomic_inc_return(&dev->next_request_id);

    ubd_w32(sreqp, &req_id);
    ubd_w32(sreqp, (is_write ? "WRIT" : "READ"));
    ubd_w64(sreqp, &serialized_size);
    ubd_w64(sreqp, &n_bios);
    
    /* Serialize each BIO. */
    rq_for_each_bio(bio, req) {
        __u64 sector = (__u64) bio->bi_sector;
        __u64 flags = (__u64) bio->bi_flags;
        __u64 rwflags = (__u64) bio->bi_rw;
        __u64 size = 0;
        char *sizep;
        struct bio_vec *bvec;
        int i;

        /* Write out the BIO header */
        ubd_w64(sreqp, &sector);
        ubd_w64(sreqp, &flags);
        ubd_w64(sreqp, &rwflags);

        /* Fill in size later; remember where it is for now. */
        sizep = sreqp;
        ubd_w64(sreqp, &size);

        bio_for_each_segment(bvec, bio, i) {
            char *segdata;

            /* Add the segment's size to the BIO packet size. */
            size += bvec->bv_len;

            if (is_write) {
                /* Copy the data over. */
                segdata = __bio_kmap_atomic(bio, i, KM_USER0);
                memcpy(sreqp, segdata, bvec->bv_len);
                sreqp += bvec->bv_len;
                __bio_kunmap_atomic(bio, KM_USER0);
            }
        }

        /* Go back and fill in the size. */
        memcpy(sizep, &size, 8);
    }

    BUG_ON((sreqp - sreq) != serialized_size);

    /* Create the ubd request structure. */
    ureq = kmalloc(sizeof(struct ublkdev_request), GFP_KERNEL);
    if (ureq == NULL) {
        printk(KERN_ERR "ubd failed to allocate %u bytes",
               sizeof(struct ublkdev_request));
        
        goto error;
    }

    ureq->id = request_id;
    ureq->dev = dev;
    ureq->next = NULL;
    ureq->req = req;
    ureq->serialized_request = sreq;
    ureq->serialized_request_size = serialized_size;
    ureq->serialized_request_readp = sreq;
    ureq->serialized_response = NULL;
    ureq->serialized_response_size = 0;
    ureq->serialized_response_writep = NULL;

    /* Remove the request from the pending requests. */
    blkdev_dequeue_request(req);

    /* Add the request to the pending requests for this device. */
    spin_lock(dev->lock);
    if (dev->xfer_head == NULL) {
        BUG_ON(dev->xfer_tail != NULL);
        dev->xfer_head = dev->xfer_tail = ureq;
    } else {
        dev->xfer_tail->next = ureq;
        dev->xfer_tail = ureq;
    }
    spin_unlock(dev->lock);
    
    return;

error:
    if (sreq != NULL)
        kfree(sreq);

    if (ureq != NULL)
        kfree(ureq);

    return;
}

static int __init ubd_init(void)
{
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

    if (ubd_major == 0)
        ubd_major = result;
    printk(KERN_DEBUG "ubd registered as block device %d\n", ubd_major);

    /* Allocate device structures. */
    ubd_devices = kmalloc(ubd_maxdevices * sizeof(struct ublkdev), GFP_KERNEL);
    if (ubd_devices == NULL) {
        printk(KERN_ERR "ubd failed to allocate device structures");
        goto error;
    }
    
    return 0;
    
error:
    ubd_exit();

    return result;
}

static void __exit ubd_exit(void)
{
    if (ubd_major != 0) {
        printk(KERN_DEBUG "ubd unregistering block device %d\n", ubd_major);
        unregister_blkdev(ubd_major, "ubd");
        ubd_major = 0;
    }

    if (ubdctl_miscdevice.minor != MISC_DYNAMIC_MINOR) {
        misc_deregister(&ubdctl_miscdevice);        
    }

    if (ubd_devices != NULL) {
        kfree(ubd_devices);
        ubd_devices = NULL;
    }

    return;
}

/* Local variables: */
/* mode: C */
/* indent-tabs-mode: nil */
/* tab-width: 8 */
/* End: */
/* vi: set expandtab tabstop=8 */
