/*
 * File backed block device driver.
 *
 * Copyright (C) 2018 Viktor Prutyanov
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
MODULE_DESCRIPTION("Block device backed by file");
MODULE_VERSION("0.1");

#define DEVICE_NAME "bfd"

#define bfd_alert(...) printk(KERN_ALERT DEVICE_NAME ": " __VA_ARGS__)
#define bfd_info(...)  printk(KERN_INFO DEVICE_NAME ": " __VA_ARGS__)

#define SECTOR_SHIFT 9

struct bfd_device {
    struct gendisk *disk;
    struct request_queue *queue;
    int major;
};

static struct bfd_device bfd;

/*
 * Process a single bvec of a bio.
 */
static int bfd_do_bvec(struct bfd_device *bfd, struct page *page,
			unsigned int len, unsigned int off, unsigned int op,
			sector_t sector)
{
	void *mem;

    bfd_info("len=%u off=%u sector=%lu page=%p\n", len, off, sector, page);

	if (op_is_write(op)) {
        return 0;
	}

	mem = kmap_atomic(page);
	if (!op_is_write(op)) {
        memset(mem + off, 0, len);
		flush_dcache_page(page);
	} else {
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

    bfd_info("make_request\n");

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bio->bi_disk))
		goto io_error;

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
        struct page *page, bool op)
{
	int err;

    bfd_info("rw_page\n");

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
        bfd_alert("failed to allocate blk queue\n");

        return -1;
    }

    blk_queue_make_request(bfd.queue, bfd_make_request);
    blk_queue_max_hw_sectors(bfd.queue, 1024);

    blk_queue_physical_block_size(bfd.queue, PAGE_SIZE);
    bfd.disk = alloc_disk(1);
    if (!bfd.disk) {
        bfd_alert("failed to allocate disk\n");
        err = -1;

        goto out_queue;
    }
    bfd.disk->major = bfd.major;
    bfd.disk->first_minor = 0;
    bfd.disk->fops = &bfd_fops;
    bfd.disk->private_data = &bfd;
    bfd.disk->flags = GENHD_FL_EXT_DEVT;
    sprintf(bfd.disk->disk_name, "file0");
    set_capacity(bfd.disk, 4 << 20); // 4MB
    bfd.queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

    queue_flag_set(QUEUE_FLAG_NONROT, bfd.queue);
    queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, bfd.queue);

    return 0;

out_queue:
    blk_cleanup_queue(bfd.queue);

    return err;
}

static void bfd_free(void)
{
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
        bfd_alert("failed to register major number\n");
        err = -EIO;

        goto out_major;
    }

    if (bfd_alloc()) {
        err = -1;

        goto out_blkdev;
    }

    bfd.disk->queue = bfd.queue;
    add_disk(bfd.disk);

    bfd_info("module loaded\n");

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
}

module_init(bfd_init);
module_exit(bfd_exit);
