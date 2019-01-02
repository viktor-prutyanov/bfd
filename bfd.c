/*
 * File backed block device driver.
 *
 * Based on Linux Kernel source.
 *
 */

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>

#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Viktor Prutyanov");
MODULE_VERSION("0.1");

#define DEVICE_NAME "bfd"
#define BACKEND_FILE_NAME "/root/bfd_backend0"

#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)

struct bfd_device {
    struct gendisk *disk;
    struct request_queue *queue;
    int major;
    struct file *f;
};

static struct bfd_device bfd;

static ssize_t bfd_backend_write(const void *buf, size_t count, loff_t offset)
{
    return kernel_write(bfd.f, buf, count, &offset);
}

static ssize_t bfd_backend_read(void *buf, size_t count, loff_t offset)
{
    //pr_info("bfd: read count=%lu offset=%lld buf=%p\n", count, offset, buf);
    return kernel_read(bfd.f, buf, count, &offset);
}

/*
 * Process a single bvec of a bio.
 */
static int bfd_do_bvec(struct bfd_device *bfd, struct page *page,
        unsigned int len, unsigned int off,
        unsigned int op, sector_t sector)
{
    void *mem;
    unsigned int offset = sector << SECTOR_SHIFT;

    //pr_info("bfd: len=%u off=%u sector=%lu page=%p\n", len, off, sector, page);

    mem = kmap_atomic(page);
    if (!op_is_write(op)) {
        bfd_backend_read(mem + off, len, offset);
        flush_dcache_page(page);
    } else {
        bfd_backend_write(mem + off, len, offset);
        flush_dcache_page(page);
    }
    kunmap_atomic(mem);

    return 0;
}

static blk_qc_t bfd_make_request(struct request_queue *q, struct bio *bio)
{
    struct bio_vec bvec;
    sector_t sector;
    struct bvec_iter iter;

    //pr_info("bfd: make_request\n");

    sector = bio->bi_iter.bi_sector;
    if (bio_end_sector(bio) > get_capacity(bio->bi_disk)) {
        goto io_error;
    }

    bio_for_each_segment(bvec, bio, iter) {
        unsigned int len = bvec.bv_len;

        if (bfd_do_bvec(&bfd, bvec.bv_page, len, bvec.bv_offset,
                    bio_op(bio), sector)) {
            goto io_error;
        }
        sector += len >> SECTOR_SHIFT;
    }

    bio_endio(bio);

    return BLK_QC_T_NONE;

io_error:
    bio_io_error(bio);

    return BLK_QC_T_NONE;
}

static int bfd_rw_page(struct block_device *bdev, sector_t sector,
        struct page *page, unsigned int op)
{
    int err;

    //pr_info("bfd: rw_page\n");

    if (PageTransHuge(page)) {
        return -ENOTSUPP;
    }

    err = bfd_do_bvec(&bfd, page, PAGE_SIZE, 0, op, sector);
    page_endio(page, op_is_write(op), err);

    return err;
}

static const struct block_device_operations bfd_fops = {
    .owner = THIS_MODULE,
    .rw_page = bfd_rw_page,
};

static int bfd_alloc(void)
{
    int err = 0;

    bfd.queue = blk_alloc_queue(GFP_KERNEL);
    if (!bfd.queue) {
        pr_alert("bfd: failed to allocate blk queue\n");

        return -1;
    }

    blk_queue_make_request(bfd.queue, bfd_make_request);
    blk_queue_max_hw_sectors(bfd.queue, 1024);

    blk_queue_physical_block_size(bfd.queue, PAGE_SIZE);
    bfd.disk = alloc_disk(1);
    if (!bfd.disk) {
        pr_alert(KERN_ALERT "bfd: failed to allocate disk\n");
        err = -1;

        goto out_queue;
    }
    bfd.disk->major = bfd.major;
    bfd.disk->first_minor = 0;
    bfd.disk->fops = &bfd_fops;
    bfd.disk->private_data = &bfd;
    bfd.disk->flags = GENHD_FL_EXT_DEVT;
    sprintf(bfd.disk->disk_name, "file0");
    set_capacity(bfd.disk, (4 << 20) >> SECTOR_SHIFT);
    bfd.queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

    blk_queue_flag_set(QUEUE_FLAG_NONROT, bfd.queue);
    blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, bfd.queue);

    bfd.f = filp_open(BACKEND_FILE_NAME, O_RDWR, 0);
    if (!bfd.f) {
        pr_info("bfd: failed to open "BACKEND_FILE_NAME"\n");
        goto out_disk;
    }

    return 0;

out_disk:
    put_disk(bfd.disk);
out_queue:
    blk_cleanup_queue(bfd.queue);

    return err;
}

static void bfd_free(void)
{
    filp_close(bfd.f, NULL);
    put_disk(bfd.disk);
    blk_cleanup_queue(bfd.queue);
}

static int __init bfd_init(void)
{
    int err = 0;

    if (bfd.major != 0) {
        return -EBUSY;
    }

    bfd.major = register_blkdev(0, DEVICE_NAME);
    if (bfd.major <= 0) {
        pr_alert("bfd: failed to register major number\n");
        err = -EIO;

        goto out_major;
    }

    if (bfd_alloc()) {
        err = -1;

        goto out_blkdev;
    }

    bfd.disk->queue = bfd.queue;
    add_disk(bfd.disk);

    pr_info("bfd: module loaded\n");

    return 0;

out_blkdev:
    unregister_blkdev(bfd.major, DEVICE_NAME);
out_major:
    bfd.major = 0;

    return err;
}

static void __exit bfd_exit(void)
{
    del_gendisk(bfd.disk);
    bfd_free();
    unregister_blkdev(bfd.major, DEVICE_NAME);
    bfd.major = 0;

    pr_info("bfd: module unloaded\n");
}

module_init(bfd_init);
module_exit(bfd_exit);
