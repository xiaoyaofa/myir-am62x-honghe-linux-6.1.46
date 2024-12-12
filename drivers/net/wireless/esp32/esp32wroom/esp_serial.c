// SPDX-License-Identifier: GPL-2.0-only
/*
 * Espressif Systems Wireless LAN device driver
 *
 * Copyright (C) 2015-2021 Espressif Systems (Shanghai) PTE LTD
 *
 * This software file (the "File") is distributed by Espressif Systems (Shanghai)
 * PTE LTD under the terms of the GNU General Public License Version 2, June 1991
 * (the "License").  You may use, redistribute and/or modify this File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
 * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 */
#include "esp_utils.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/slab.h>

#include "esp.h"
#include "esp_rb.h"
#include "esp_api.h"
#include "esp_kernel_port.h"

#define ESP_SERIAL_MAJOR      221
#define ESP_SERIAL_MINOR_MAX  1
#define ESP_RX_RB_SIZE        4096
#define ESP_SERIAL_MAX_TX     4096

static struct esp_serial_devs {
	struct device* dev;
	struct cdev cdev;
	int dev_index;
	esp_rb_t rb;
	void *priv;
	struct mutex lock;
} devs[ESP_SERIAL_MINOR_MAX];

static uint8_t serial_init_done;
static atomic_t ref_count_open;

static ssize_t esp_serial_read(struct file *file, char __user *user_buffer, size_t size, loff_t *offset)
{
	struct esp_serial_devs *dev = NULL;
	int ret_size = 0;
	dev = (struct esp_serial_devs *) file->private_data;
	ret_size = esp_rb_read_by_user(&dev->rb, user_buffer, size, !(file->f_flags & O_NONBLOCK));
	if (ret_size == 0) {
		esp_verbose("%u err: EAGAIN\n", __LINE__);
		return -EAGAIN;
	}
	return ret_size;
}

static ssize_t esp_serial_write(struct file *file, const char __user *user_buffer, size_t size, loff_t * offset)
{
	struct esp_payload_header *hdr = NULL;
	u8 *tx_buf = NULL;
	struct esp_serial_devs *dev = NULL;
	struct sk_buff * tx_skb = NULL;
	int ret = 0;
	size_t total_len = 0;
	size_t frag_len = 0;
	u32 left_len = size;
	static u16 seq_num = 0;
	u8 flag = 0;
	u8 *pos;

	if (size > ESP_SERIAL_MAX_TX) {
		esp_err("Exceed max tx buffer size [%zu]\n", size);
		return 0;
	}

	seq_num++;
	dev = (struct esp_serial_devs *) file->private_data;
	pos = (u8 *) user_buffer;

	do {
		/* Fragmentation support
		 *  - Fragment large packets into multiple 1500 byte packets
		 *  - MORE_FRAGMENT bit in flag tells if there are more fragments expected
		 **/
		if (left_len > ETH_DATA_LEN) {
			frag_len = ETH_DATA_LEN;
			flag = MORE_FRAGMENT;
		} else {
			frag_len = left_len;
			flag = 0;
		}

		total_len = frag_len + sizeof(struct esp_payload_header);

		tx_skb = esp_alloc_skb(total_len);
		if (!tx_skb) {
			esp_err("SKB alloc failed\n");
			return (size - left_len);
		}

		tx_buf = skb_put(tx_skb, total_len);

		hdr = (struct esp_payload_header *) tx_buf;

		memset (hdr, 0, sizeof(struct esp_payload_header));

		hdr->if_type = ESP_SERIAL_IF;
		hdr->if_num = dev->dev_index;
		hdr->len = cpu_to_le16(frag_len);
		hdr->seq_num = cpu_to_le16(seq_num);
		hdr->offset = cpu_to_le16(sizeof(struct esp_payload_header));
		hdr->flags |= flag;

		ret = copy_from_user(tx_buf + hdr->offset, pos, frag_len);
		if (ret) {
			dev_kfree_skb(tx_skb);
			esp_err("Error copying buffer to send serial data\n");
			return (size - left_len);
		}
		hdr->checksum = cpu_to_le16(compute_checksum(tx_skb->data, (frag_len + sizeof(struct esp_payload_header))));

		esp_hex_dump_dbg("esp_serial_tx: ", pos, frag_len);

		ret = esp_send_packet(dev->priv, tx_skb);
		if (ret) {
			esp_err("Failed to transmit data, error %d\n", ret);
			return (size - left_len);
		}

		left_len -= frag_len;
		pos += frag_len;
	} while(left_len);

	return size;
}

static long esp_serial_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
	esp_info("IOCTL unsupported %d\n", cmd);
	return 0;
}

static int esp_serial_open(struct inode *inode, struct file *file)
{
	struct esp_serial_devs *devs = NULL;

	if (atomic_read(&ref_count_open) >= 1) {
		esp_warn("already opened: denying new open request\n");
		/* returning -EPERM may mislead user into checking the permission bits
		 * of the device file. -EBUSY tells the user that the serial channel is
		 * busy servicing another user of the device file */
		return -EBUSY;
	}

	devs = container_of(inode->i_cdev, struct esp_serial_devs, cdev);
	file->private_data = devs;

	atomic_inc(&ref_count_open);

	return 0;
}

static int esp_serial_release(struct inode *inode, struct file *file)
{
	if (atomic_read(&ref_count_open)) {
		atomic_dec(&ref_count_open);
	} else {
		esp_warn("ref_count_open count already zero\n");
	}

	return 0;
}

static unsigned int esp_serial_poll(struct file *file, poll_table *wait)
{
    struct esp_serial_devs *dev = (struct esp_serial_devs *)file->private_data;
    unsigned int mask = 0;

    mutex_lock(&dev->lock);
    poll_wait(file, &dev->rb.wq,  wait);

    if (dev->rb.rp != dev->rb.wp) {
        mask |= (POLLIN | POLLRDNORM) ;   /* readable */
    }
    if (get_free_space(&dev->rb)) {
        mask |= (POLLOUT | POLLWRNORM) ;  /* writable */
    }

    mutex_unlock(&dev->lock);
    return mask;
}

const struct file_operations esp_serial_fops = {
	.owner = THIS_MODULE,
	.open = esp_serial_open,
	.read = esp_serial_read,
	.write = esp_serial_write,
	.unlocked_ioctl = esp_serial_ioctl,
	.poll = esp_serial_poll,
	.release = esp_serial_release,
};

int esp_serial_data_received(int dev_index, const char *data, size_t len)
{
	int ret = 0, ret_len = 0;
	if (dev_index >= ESP_SERIAL_MINOR_MAX) {
		esp_err("%u ERR: serial_dev_idx[%d] >= minor_max[%d]\n",
				__LINE__, dev_index, ESP_SERIAL_MINOR_MAX);
		return -EINVAL;
	}

	if (!atomic_read(&ref_count_open)) {
		esp_verbose("no user app listening: dropping packet\n");
		return len;
	}

	while (ret_len != len) {
		ret = esp_rb_write_by_kernel(&devs[dev_index].rb,
				data+ret_len, (len-ret_len));
		if (ret <= 0) {
			break;
		}
		ret_len += ret;
	}
	if (ret <= 0) {
		return ret;
	}
	if (ret_len != len) {
		esp_err("RB full, no space to receive. Dropping packet\n");
	}

	return ret_len;
}

static dev_t dev_first;
static struct class *cl;

int esp_serial_init(void *priv)
{
	int err = -EINVAL, i = 0;

	if (!priv) {
		esp_err("failed. NULL adapter\n");
		goto err;
	}

	/* already in correct state, ignore */
	if (serial_init_done)
		return 0;

	err = alloc_chrdev_region(&dev_first, 0, ESP_SERIAL_MINOR_MAX, "esp_serial_driver");
	if (err) {
		esp_err("Error alloc chrdev region %d\n", err);
		goto err;
	}

	cl = CLASS_CREATE("esp_serial_chardrv");
	if (IS_ERR(cl)) {
		esp_err("Class create err[%d]\n", err);
		err = PTR_ERR(cl);
		goto err_class_create;
	}

	for (i = 0; i < ESP_SERIAL_MINOR_MAX; i++) {
		dev_t dev_num = dev_first + i;
		devs[i].dev_index = i;
		devs[i].dev = device_create(cl, NULL, dev_num, NULL, "esps%d", i);
		cdev_init(&devs[i].cdev, &esp_serial_fops);
		cdev_add(&devs[i].cdev, dev_num, 1);
		esp_rb_init(&devs[i].rb, ESP_RX_RB_SIZE);
		devs[i].priv = priv;
		mutex_init(&devs[i].lock);
	}

	serial_init_done = 1;

	atomic_set(&ref_count_open, 0);

	esp_verbose("\n");
	return 0;

err_class_create:
	unregister_chrdev_region(dev_first, ESP_SERIAL_MINOR_MAX);
err:
	return err;
}

void esp_serial_cleanup(void)
{
	int i = 0;

	for (i = 0; serial_init_done && i < ESP_SERIAL_MINOR_MAX; i++) {
		dev_t dev_num = dev_first + i;
		device_destroy(cl, dev_num);
		if (!devs[i].cdev.ops)
			cdev_del(&devs[i].cdev);

		esp_rb_cleanup(&devs[i].rb);
		mutex_destroy(&devs[i].lock);
	}

	class_destroy(cl);
	unregister_chrdev_region(dev_first, ESP_SERIAL_MINOR_MAX);

	serial_init_done = 0;
	esp_info("\n");
	return;
}

int esp_serial_reinit(void *priv)
{
	if (serial_init_done) {
		return 0;
	}

	return esp_serial_init(priv);
}
