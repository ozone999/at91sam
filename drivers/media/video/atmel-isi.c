/*
 * Copyright (c) 2011 Atmel Corporation
 * Josh Wu, <josh.wu@atmel.com>
 *
 * Based on previous work by Lars Haring, <lars.haring@atmel.com>
 * and Sedji Gaouaou
 * Based on the bttv driver for Bt848 with respective copyright holders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include <media/atmel-isi.h>
#include <media/soc_camera.h>
#include <media/soc_mediabus.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-memops.h>

#define MAX_BUFFER_NUM			32
#define MAX_SUPPORT_WIDTH		2048
#define MAX_SUPPORT_HEIGHT		2048
#define VID_LIMIT_BYTES			(4 * 1024 * 1024)
#define MIN_FRAME_RATE			15
#define FRAME_INTERVAL_MILLI_SEC	(1000 / MIN_FRAME_RATE)

/* Add by embest
  * Allocate dma buf for video buf
  * We allocate it before android bootup because after android bootup, allocate will failed as OUT OF MEMORY*/
#define ANDROID

/* Use preview path OR codec path */
bool use_preview_path;

/* ISI states */
enum {
	ISI_STATE_IDLE = 0,
	ISI_STATE_READY,
	ISI_STATE_WAIT_SOF,
};

#ifdef ANDROID

static unsigned long offset = 0;
struct vb2_vmarea_handler	mmap_handler;

#define call_memop(q, plane, op, args...)				\
	(((q)->mem_ops->op) ?						\
		((q)->mem_ops->op(args)) : 0)

struct vb2_dc_conf {
	struct device		*dev;
};


struct vb2_dc_buf {
	struct vb2_dc_conf		*conf;
	void				*vaddr;
	dma_addr_t			paddr;
	unsigned long			size;
	struct vm_area_struct		*vma;
	atomic_t			refcount;
	struct vb2_vmarea_handler	handler;
};

static void vb2_dma_contig_put(void *buf_priv)
{
	struct vb2_dc_buf *buf = buf_priv;

	if (atomic_dec_and_test(&buf->refcount)) {
		kfree(buf);
	}
	offset = 0;
}

static void __vb2_buf_mem_free(struct vb2_buffer *vb)
{
	struct vb2_queue *q = vb->vb2_queue;
	unsigned int plane;

	for (plane = 0; plane < vb->num_planes; ++plane) {
		struct vb2_dc_buf *buf = vb->planes[plane].mem_priv;
		atomic_dec_return(&buf->refcount);
	}
}

#endif


/* Frame buffer descriptor */
struct fbd {
	/* Physical address of the frame buffer */
	u32 fb_address;
	/* DMA Control Register(only in HISI2) */
	u32 dma_ctrl;
	/* Physical address of the next fbd */
	u32 next_fbd_address;
};

static void set_dma_ctrl(struct fbd *fb_desc, u32 ctrl)
{
	fb_desc->dma_ctrl = ctrl;
}

struct isi_dma_desc {
	struct list_head list;
	struct fbd *p_fbd;
	u32 fbd_phys;
};

/* Frame buffer data */
struct frame_buffer {
	struct vb2_buffer vb;
	struct isi_dma_desc *p_dma_desc;
	struct list_head list;
};

struct atmel_isi {
	/* Protects the access of variables shared with the ISR */
	spinlock_t			lock;
	void __iomem			*regs;

	int				sequence;
	/* State of the ISI module in capturing mode */
	int				state;

	/* Wait queue for waiting for SOF */
	wait_queue_head_t		vsync_wq;

	struct vb2_alloc_ctx		*alloc_ctx;

	/* Allocate descriptors for dma buffer use */
	struct fbd			*p_fb_descriptors;
	u32				fb_descriptors_phys;
	struct				list_head dma_desc_head;
	struct isi_dma_desc		dma_desc[MAX_BUFFER_NUM];

#ifdef ANDROID
	void				*video_buf;
	u32				video_buf_phys;
#endif	

	struct completion		complete;
	struct clk			*pclk;
	struct clk			*pck1;
	unsigned int			irq;

	struct isi_platform_data	*pdata;

	struct list_head		video_buffer_list;
	struct frame_buffer		*active;

	struct soc_camera_device	*icd;
	struct soc_camera_host		soc_host;
};

static void isi_writel(struct atmel_isi *isi, u32 reg, u32 val)
{
	writel(val, isi->regs + reg);
}
static u32 isi_readl(struct atmel_isi *isi, u32 reg)
{
	return readl(isi->regs + reg);
}

static int configure_geometry(struct atmel_isi *isi, u32 width,
			u32 height, enum v4l2_mbus_pixelcode code)
{
	u32 cfg2, cr, psize;

	switch (code) {
	/* YUV, including grey */
	case V4L2_MBUS_FMT_Y8_1X8:
		cr = ISI_CFG2_GRAYSCALE;
		break;
	/* Default format output by isi module is: Cb Y1 Cr Y2/ U Y1 V Y2 */
	/* Output data format from ov2640 is: U Y1 V Y2 */
	case V4L2_MBUS_FMT_UYVY8_2X8:
	 	/* ISI output will be U Y1 V Y2 */
		cr = ISI_CFG2_YCC_SWAP_DEFAULT;
		break;
	case V4L2_MBUS_FMT_VYUY8_2X8:
	 	/* ISI output will be U Y1 V Y2 */
		cr = ISI_CFG2_YCC_SWAP_MODE_1;
		break;
	case V4L2_MBUS_FMT_YUYV8_2X8:
		/* ISI output will be U Y1 V Y2 */
		cr = ISI_CFG2_YCC_SWAP_MODE_2;
		break;
	case V4L2_MBUS_FMT_YVYU8_2X8:
		/* ISI output will be U Y1 V Y2 */
		cr = ISI_CFG2_YCC_SWAP_MODE_3;
		break;
	case V4L2_MBUS_FMT_RGB565_2X8_LE:
		cr = ISI_CFG2_COL_SPACE | ISI_CFG2_RGB_MODE;
		break;
	default:
		return -EINVAL;
	}

	isi_writel(isi, ISI_CTRL, ISI_CTRL_DIS);

	cfg2 = isi_readl(isi, ISI_CFG2);
	cfg2 &= ~(ISI_CFG2_YCC_SWAP_MASK);
	cfg2 &= ~(ISI_CFG2_COL_SPACE);
	cfg2 &= ~(ISI_CFG2_RGB_MODE);
	cfg2 |= cr;
	/* Set width */
	cfg2 &= ~(ISI_CFG2_IM_HSIZE_MASK);
	cfg2 |= ((width - 1) << ISI_CFG2_IM_HSIZE_OFFSET) &
			ISI_CFG2_IM_HSIZE_MASK;
	/* Set height */
	cfg2 &= ~(ISI_CFG2_IM_VSIZE_MASK);
	cfg2 |= ((height - 1) << ISI_CFG2_IM_VSIZE_OFFSET)
			& ISI_CFG2_IM_VSIZE_MASK;
	isi_writel(isi, ISI_CFG2, cfg2);
	if(use_preview_path){
		psize = 0;
		psize |= ((width - 1) << ISI_PSIZE_IM_HSIZE_OFFSET) &
			ISI_PSIZE_IM_HSIZE_MASK;
		psize |= ((height - 1) << ISI_PSIZE_IM_VSIZE_OFFSET) &
			ISI_PSIZE_IM_VSIZE_MASK;
		isi_writel(isi, ISI_PSIZE, psize);
	}

	return 0;
}

static irqreturn_t atmel_isi_handle_streaming(struct atmel_isi *isi, bool isCapture)
{
	if (isi->active) {
		struct vb2_buffer *vb = &isi->active->vb;
		struct frame_buffer *buf = isi->active;

		list_del_init(&buf->list);
		do_gettimeofday(&vb->v4l2_buf.timestamp);
		vb->v4l2_buf.sequence = isi->sequence++;
		vb2_buffer_done(vb, VB2_BUF_STATE_DONE);
	}

	if (list_empty(&isi->video_buffer_list)) {
		isi->active = NULL;
	} else {
		/* start next dma frame. */
		isi->active = list_entry(isi->video_buffer_list.next,
					struct frame_buffer, list);
		if(isCapture){
			isi_writel(isi, ISI_DMA_C_DSCR,
				isi->active->p_dma_desc->fbd_phys);
			isi_writel(isi, ISI_DMA_C_CTRL,
				ISI_DMA_CTRL_FETCH | ISI_DMA_CTRL_DONE);
			isi_writel(isi, ISI_DMA_CHER, ISI_DMA_CHSR_C_CH);
		}else{
			isi_writel(isi, ISI_DMA_P_DSCR,
				isi->active->p_dma_desc->fbd_phys);
			isi_writel(isi, ISI_DMA_P_CTRL,
				ISI_DMA_CTRL_FETCH | ISI_DMA_CTRL_DONE);
			isi_writel(isi, ISI_DMA_CHER, ISI_DMA_CHSR_P_CH);
		}
	}
	return IRQ_HANDLED;
}

/* ISI interrupt service routine */
static irqreturn_t isi_interrupt(int irq, void *dev_id)
{
	struct atmel_isi *isi = dev_id;
	u32 status, mask, pending;
	irqreturn_t ret = IRQ_NONE;

	spin_lock(&isi->lock);

	status = isi_readl(isi, ISI_STATUS);
	mask = isi_readl(isi, ISI_INTMASK);
	pending = status & mask;

	if (pending & ISI_CTRL_SRST) {
		complete(&isi->complete);
		isi_writel(isi, ISI_INTDIS, ISI_CTRL_SRST);
		ret = IRQ_HANDLED;
	} else if (pending & ISI_CTRL_DIS) {
		complete(&isi->complete);
		isi_writel(isi, ISI_INTDIS, ISI_CTRL_DIS);
		ret = IRQ_HANDLED;
	} else {
		if ((pending & ISI_SR_VSYNC) &&
				(isi->state == ISI_STATE_IDLE)) {
			isi->state = ISI_STATE_READY;
			wake_up_interruptible(&isi->vsync_wq);
			ret = IRQ_HANDLED;
		}
		if (likely(pending & ISI_SR_CXFR_DONE))
			ret = atmel_isi_handle_streaming(isi, true);
		if (likely(pending & ISI_SR_PXFR_DONE)){
			ret = atmel_isi_handle_streaming(isi, false);
		}
	}

	spin_unlock(&isi->lock);
	return ret;
}

#define	WAIT_ISI_RESET		1
#define	WAIT_ISI_DISABLE	0
static int atmel_isi_wait_status(struct atmel_isi *isi, int wait_reset)
{
	unsigned long timeout;
	/*
	 * The reset or disable will only succeed if we have a
	 * pixel clock from the camera.
	 */
	init_completion(&isi->complete);

	if (wait_reset) {
		isi_writel(isi, ISI_INTEN, ISI_CTRL_SRST);
		isi_writel(isi, ISI_CTRL, ISI_CTRL_SRST);
	} else {
		isi_writel(isi, ISI_INTEN, ISI_CTRL_DIS);
		isi_writel(isi, ISI_CTRL, ISI_CTRL_DIS);
	}

	timeout = wait_for_completion_timeout(&isi->complete,
			msecs_to_jiffies(100));
	if (timeout == 0)
		return -ETIMEDOUT;

	return 0;
}

/* ------------------------------------------------------------------
	Videobuf operations
   ------------------------------------------------------------------*/
static int queue_setup(struct vb2_queue *vq, unsigned int *nbuffers,
				unsigned int *nplanes, unsigned long sizes[],
				void *alloc_ctxs[])
{
	struct soc_camera_device *icd = soc_camera_from_vb2q(vq);
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	unsigned long size;
	int ret, bytes_per_line;

	/* Reset ISI */
	ret = atmel_isi_wait_status(isi, WAIT_ISI_RESET);
	if (ret < 0) {
		dev_err(icd->dev.parent, "Reset ISI timed out\n");
		return ret;
	}
	/* Disable all interrupts */
	isi_writel(isi, ISI_INTDIS, ~0UL);

	bytes_per_line = soc_mbus_bytes_per_line(icd->user_width,
						icd->current_fmt->host_fmt);

	if (bytes_per_line < 0)
		return bytes_per_line;

	size = bytes_per_line * icd->user_height;

	if (!*nbuffers || *nbuffers > MAX_BUFFER_NUM)
		*nbuffers = MAX_BUFFER_NUM;

	if (size * *nbuffers > VID_LIMIT_BYTES)
		*nbuffers = VID_LIMIT_BYTES / size;

	*nplanes = 1;
	sizes[0] = size;
	alloc_ctxs[0] = isi->alloc_ctx;

	isi->sequence = 0;
	isi->active = NULL;

	dev_dbg(icd->dev.parent, "%s, count=%d, size=%ld\n", __func__,
		*nbuffers, size);

	return 0;
}

static int buffer_init(struct vb2_buffer *vb)
{
	struct frame_buffer *buf = container_of(vb, struct frame_buffer, vb);

	buf->p_dma_desc = NULL;
	INIT_LIST_HEAD(&buf->list);

	return 0;
}

static int buffer_prepare(struct vb2_buffer *vb)
{
	struct soc_camera_device *icd = soc_camera_from_vb2q(vb->vb2_queue);
	struct frame_buffer *buf = container_of(vb, struct frame_buffer, vb);
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	unsigned long size;
	struct isi_dma_desc *desc;
	int bytes_per_line = soc_mbus_bytes_per_line(icd->user_width,
						icd->current_fmt->host_fmt);

	if (bytes_per_line < 0)
		return bytes_per_line;

	size = bytes_per_line * icd->user_height;

	if (vb2_plane_size(vb, 0) < size) {
		dev_err(icd->dev.parent, "%s data will not fit into plane (%lu < %lu)\n",
				__func__, vb2_plane_size(vb, 0), size);
		return -EINVAL;
	}

	vb2_set_plane_payload(&buf->vb, 0, size);

	if (!buf->p_dma_desc) {
		if (list_empty(&isi->dma_desc_head)) {
			dev_err(icd->dev.parent, "Not enough dma descriptors.\n");
			return -EINVAL;
		} else {
			/* Get an available descriptor */
			desc = list_entry(isi->dma_desc_head.next,
						struct isi_dma_desc, list);
			/* Delete the descriptor since now it is used */
			list_del_init(&desc->list);

			/* Initialize the dma descriptor */
			desc->p_fbd->fb_address =
					vb2_dma_contig_plane_paddr(vb, 0);
			desc->p_fbd->next_fbd_address = 0;
			set_dma_ctrl(desc->p_fbd, ISI_DMA_CTRL_WB);

			buf->p_dma_desc = desc;
		}
	}
	return 0;
}

static void buffer_cleanup(struct vb2_buffer *vb)
{
	struct soc_camera_device *icd = soc_camera_from_vb2q(vb->vb2_queue);
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	struct frame_buffer *buf = container_of(vb, struct frame_buffer, vb);

	/* This descriptor is available now and we add to head list */
	if (buf->p_dma_desc)
		list_add(&buf->p_dma_desc->list, &isi->dma_desc_head);
}

static void start_dma(struct atmel_isi *isi, struct frame_buffer *buffer)
{
	u32 ctrl, cfg1;

	cfg1 = isi_readl(isi, ISI_CFG1);
	/* Enable irq: cxfr for the codec path, pxfr for the preview path */
	isi_writel(isi, ISI_INTEN,
			ISI_SR_CXFR_DONE | ISI_SR_PXFR_DONE);

	if(use_preview_path) {
		isi_writel(isi, ISI_DMA_P_DSCR, buffer->p_dma_desc->fbd_phys);
		isi_writel(isi, ISI_DMA_P_CTRL, ISI_DMA_CTRL_FETCH | ISI_DMA_CTRL_DONE);
		isi_writel(isi, ISI_DMA_CHER, ISI_DMA_CHSR_P_CH);
	} else {
		/* Check if already in a frame */
		if (isi_readl(isi, ISI_STATUS) & ISI_CTRL_CDC) {
			dev_err(isi->icd->dev.parent, "Already in frame handling.\n");
			return;
		}
		isi_writel(isi, ISI_DMA_C_DSCR, buffer->p_dma_desc->fbd_phys);
		isi_writel(isi, ISI_DMA_C_CTRL, ISI_DMA_CTRL_FETCH | ISI_DMA_CTRL_DONE);
		isi_writel(isi, ISI_DMA_CHER, ISI_DMA_CHSR_C_CH);
		/* Enable linked list */
		cfg1 |= isi->pdata->frate | ISI_CFG1_DISCR;
		/* Enable codec path */
		ctrl = ISI_CTRL_CDC;
	}
	/* Enable ISI */
	ctrl |= ISI_CTRL_EN;
	isi_writel(isi, ISI_CTRL, ctrl);
	isi_writel(isi, ISI_CFG1, cfg1);
}

static void buffer_queue(struct vb2_buffer *vb)
{
	struct soc_camera_device *icd = soc_camera_from_vb2q(vb->vb2_queue);
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	struct frame_buffer *buf = container_of(vb, struct frame_buffer, vb);
	unsigned long flags = 0;

	spin_lock_irqsave(&isi->lock, flags);
	list_add_tail(&buf->list, &isi->video_buffer_list);

	if (isi->active == NULL) {
		isi->active = buf;
		start_dma(isi, buf);
	}
	spin_unlock_irqrestore(&isi->lock, flags);
}

static int start_streaming(struct vb2_queue *vq)
{
	struct soc_camera_device *icd = soc_camera_from_vb2q(vq);
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;

	u32 sr = 0;
	int ret;

	spin_lock_irq(&isi->lock);
	isi->state = ISI_STATE_IDLE;
	/* Clear any pending SOF interrupt */
	sr = isi_readl(isi, ISI_STATUS);
	/* Enable VSYNC interrupt for SOF */
	isi_writel(isi, ISI_INTEN, ISI_SR_VSYNC);
	isi_writel(isi, ISI_CTRL, ISI_CTRL_EN);
	spin_unlock_irq(&isi->lock);

	dev_dbg(icd->dev.parent, "Waiting for SOF\n");
	ret = wait_event_interruptible(isi->vsync_wq,
				       isi->state != ISI_STATE_IDLE);
	if (ret)
		return ret;

	if (isi->state != ISI_STATE_READY)
		return -EIO;

	spin_lock_irq(&isi->lock);
	isi->state = ISI_STATE_WAIT_SOF;
	isi_writel(isi, ISI_INTDIS, ISI_SR_VSYNC);
	spin_unlock_irq(&isi->lock);

	return 0;
}

/* abort streaming and wait for last buffer */
static int stop_streaming(struct vb2_queue *vq)
{
	struct soc_camera_device *icd = soc_camera_from_vb2q(vq);
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	struct frame_buffer *buf, *node;
	int ret = 0;
	unsigned long timeout;

	spin_lock_irq(&isi->lock);
	isi->active = NULL;
	/* Release all active buffers */
	list_for_each_entry_safe(buf, node, &isi->video_buffer_list, list) {
		list_del_init(&buf->list);
		vb2_buffer_done(&buf->vb, VB2_BUF_STATE_ERROR);
#ifdef ANDROID		
		__vb2_buf_mem_free(&buf->vb);
#endif
	}
	spin_unlock_irq(&isi->lock);

	if(use_preview_path)
		goto STOP;

	timeout = jiffies + FRAME_INTERVAL_MILLI_SEC * HZ;
	/* Wait until the end of the current frame. */
	while ((isi_readl(isi, ISI_STATUS) & ISI_CTRL_CDC) &&
			time_before(jiffies, timeout))
		msleep(1);

	if (time_after(jiffies, timeout)) {
		dev_err(icd->dev.parent,
			"Timeout waiting for finishing codec request\n");
		return -ETIMEDOUT;
	}
STOP:
	/* Disable interrupts */
	isi_writel(isi, ISI_INTDIS,
			ISI_SR_CXFR_DONE | ISI_SR_PXFR_DONE);

	/* Disable ISI and wait for it is done */
	ret = atmel_isi_wait_status(isi, WAIT_ISI_DISABLE);
	if (ret < 0)
		dev_err(icd->dev.parent, "Disable ISI timed out\n");

	return ret;
}

static struct vb2_ops isi_video_qops = {
	.queue_setup		= queue_setup,
	.buf_init		= buffer_init,
	.buf_prepare		= buffer_prepare,
	.buf_cleanup		= buffer_cleanup,
	.buf_queue		= buffer_queue,
	.start_streaming	= start_streaming,
	.stop_streaming		= stop_streaming,
	.wait_prepare		= soc_camera_unlock,
	.wait_finish		= soc_camera_lock,
};

#ifdef ANDROID
static void *vb2_dma_contig_alloc(void *alloc_ctx, unsigned long size)
{
	struct vb2_dc_conf *conf = alloc_ctx;
	struct vb2_dc_buf *buf;
	struct soc_camera_host *soc_host = to_soc_camera_host(conf->dev);
	struct atmel_isi *isi = container_of(soc_host,
					struct atmel_isi, soc_host);

	buf = kzalloc(sizeof *buf, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	offset = PAGE_ALIGN(offset);

	buf->vaddr = isi->video_buf + offset;
	buf->paddr = isi->video_buf_phys + offset;
	
	if (!buf->vaddr || (offset > VID_LIMIT_BYTES)) {
		dev_err(conf->dev, "dma_alloc_coherent of size %ld failed\n",
			size);
		kfree(buf);
		return ERR_PTR(-ENOMEM);
	}

	offset += size;

	buf->conf = conf;
	buf->size = size;

	buf->handler.refcount = &buf->refcount;
	buf->handler.put = vb2_dma_contig_put;
	buf->handler.arg = buf;

	atomic_inc(&buf->refcount);

	return buf;
}

static void atmel_isi_vm_open(struct vm_area_struct *vma)
{
	printk(KERN_DEBUG "atmel_isi: vm_open\n");
}

static void atmel_isi_vm_close(struct vm_area_struct *vma)
{
	printk(KERN_DEBUG "atmel_isi: vm_close\n");
}


static struct vm_operations_struct atmel_isi_vm_ops = {
	.open = atmel_isi_vm_open,
	.close = atmel_isi_vm_close,
};

int mmap_pfn_range(struct vm_area_struct *vma, unsigned long paddr,
				unsigned long size,
				const struct vm_operations_struct *vm_ops,
				void *priv)
{
	int ret;
	
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	ret = remap_pfn_range(vma, vma->vm_start, paddr >> PAGE_SHIFT,
				size, vma->vm_page_prot);
	if (ret) {
		printk(KERN_ERR "Remapping memory failed, error: %d\n", ret);
		return ret;
	}
	if(!priv)
		printk(KERN_DEBUG "mmap_pfn_range get a NULL point\n");

	vma->vm_flags		|= VM_DONTEXPAND | VM_RESERVED;
	vma->vm_private_data	= priv;
	vma->vm_ops		= vm_ops;

	vma->vm_ops->open(vma);

	printk(KERN_DEBUG "%s: mapped paddr 0x%08lx at 0x%08lx, size %ld\n",
			__func__, paddr, vma->vm_start, size);

	return 0;
}


static int vb2_dma_contig_mmap(void *buf_priv, struct vm_area_struct *vma)
{
	struct vb2_dc_buf *buf = buf_priv;
	struct soc_camera_host *soc_host = to_soc_camera_host(buf->conf->dev);
	struct atmel_isi *isi = container_of(soc_host,
					struct atmel_isi, soc_host);

	unsigned long size = vma->vm_end - vma->vm_start;

	if (!buf) {
		printk(KERN_ERR "No buffer to map\n");
		return -EINVAL;
	}

	printk(KERN_DEBUG "size: %d, buf->size: %d\n",size, buf->size);

	if(size <= PAGE_ALIGN(buf->size))
		return vb2_mmap_pfn_range(vma, buf->paddr, buf->size,
				  &vb2_common_vm_ops, &buf->handler);
	else
		printk(KERN_DEBUG "Warning, we will mmap all the buffer to the application by one operate! May be this is called by android\n");
	return mmap_pfn_range(vma, isi->video_buf_phys, size,
				  &atmel_isi_vm_ops, NULL);
}

#endif


/* ------------------------------------------------------------------
	SOC camera operations for the device
   ------------------------------------------------------------------*/
static int isi_camera_init_videobuf(struct vb2_queue *q,
				     struct soc_camera_device *icd)
{
	q->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	q->io_modes = VB2_MMAP;
	q->drv_priv = icd;
	q->buf_struct_size = sizeof(struct frame_buffer);
	q->ops = &isi_video_qops;
	q->mem_ops = &vb2_dma_contig_memops;
#ifdef ANDROID
	q->mem_ops->alloc = vb2_dma_contig_alloc;
	q->mem_ops->put = vb2_dma_contig_put;
	q->mem_ops->mmap = vb2_dma_contig_mmap;
#endif

	return vb2_queue_init(q);
}

static int isi_camera_set_fmt(struct soc_camera_device *icd,
			      struct v4l2_format *f)
{
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	struct v4l2_subdev *sd = soc_camera_to_subdev(icd);
	const struct soc_camera_format_xlate *xlate;
	struct v4l2_pix_format *pix = &f->fmt.pix;
	struct v4l2_mbus_framefmt mf;
	int ret;

	switch (pix->pixelformat){
	case V4L2_PIX_FMT_RGB565:
		use_preview_path = true;
		break;
	case V4L2_PIX_FMT_YUYV:
	case V4L2_PIX_FMT_UYVY:
		use_preview_path = false;
		break;
	default:
		use_preview_path = false;
	}

	xlate = soc_camera_xlate_by_fourcc(icd, pix->pixelformat);
	if (!xlate) {
		dev_warn(icd->dev.parent, "Format %x not found\n",
			 pix->pixelformat);
		return -EINVAL;
	}

	dev_dbg(icd->dev.parent, "Plan to set format %dx%d\n",
			pix->width, pix->height);

	mf.width	= pix->width;
	mf.height	= pix->height;
	mf.field	= pix->field;
	mf.colorspace	= pix->colorspace;
	mf.code		= xlate->code;

	ret = v4l2_subdev_call(sd, video, s_mbus_fmt, &mf);
	if (ret < 0)
		return ret;

	if (mf.code != xlate->code)
		return -EINVAL;

	ret = configure_geometry(isi, pix->width, pix->height, xlate->code);
	if (ret < 0)
		return ret;

	pix->width		= mf.width;
	pix->height		= mf.height;
	pix->field		= mf.field;
	pix->colorspace		= mf.colorspace;
	icd->current_fmt	= xlate;

	dev_dbg(icd->dev.parent, "Finally set format %dx%d\n",
		pix->width, pix->height);

	return ret;
}

static int isi_camera_try_fmt(struct soc_camera_device *icd,
			      struct v4l2_format *f)
{
	struct v4l2_subdev *sd = soc_camera_to_subdev(icd);
	const struct soc_camera_format_xlate *xlate;
	struct v4l2_pix_format *pix = &f->fmt.pix;
	struct v4l2_mbus_framefmt mf;
	u32 pixfmt = pix->pixelformat;
	int ret;

	xlate = soc_camera_xlate_by_fourcc(icd, pixfmt);
	if (pixfmt && !xlate) {
		dev_warn(icd->dev.parent, "Format %x not found\n", pixfmt);
		return -EINVAL;
	}

	/* limit to Atmel ISI hardware capabilities */
	if (pix->height > MAX_SUPPORT_HEIGHT)
		pix->height = MAX_SUPPORT_HEIGHT;
	if (pix->width > MAX_SUPPORT_WIDTH)
		pix->width = MAX_SUPPORT_WIDTH;

	/* limit to sensor capabilities */
	mf.width	= pix->width;
	mf.height	= pix->height;
	mf.field	= pix->field;
	mf.colorspace	= pix->colorspace;
	mf.code		= xlate->code;

	ret = v4l2_subdev_call(sd, video, try_mbus_fmt, &mf);
	if (ret < 0)
		return ret;

	pix->width	= mf.width;
	pix->height	= mf.height;
	pix->colorspace	= mf.colorspace;

	switch (mf.field) {
	case V4L2_FIELD_ANY:
		pix->field = V4L2_FIELD_NONE;
		break;
	case V4L2_FIELD_NONE:
		break;
	default:
		dev_err(icd->dev.parent, "Field type %d unsupported.\n",
			mf.field);
		ret = -EINVAL;
	}

	return ret;
}

static const struct soc_mbus_pixelfmt isi_camera_formats[] = {
	{
		.fourcc			= V4L2_PIX_FMT_UYVY,
		.name			= "Packed YUV422 16 bit",
		.bits_per_sample	= 8,
		.packing		= SOC_MBUS_PACKING_2X8_PADHI,
		.order			= SOC_MBUS_ORDER_LE,
	},
	{
		.fourcc			= V4L2_PIX_FMT_RGB565,
		.name			= "RGB565 16 bit",
		.bits_per_sample		= 8,
		.packing			= SOC_MBUS_PACKING_2X8_PADHI,
		.order			= SOC_MBUS_ORDER_LE,
	},
};

/* This will be corrected as we get more formats */
static bool isi_camera_packing_supported(const struct soc_mbus_pixelfmt *fmt)
{
	return	fmt->packing == SOC_MBUS_PACKING_NONE ||
		(fmt->bits_per_sample == 8 &&
		 fmt->packing == SOC_MBUS_PACKING_2X8_PADHI) ||
		(fmt->bits_per_sample > 8 &&
		 fmt->packing == SOC_MBUS_PACKING_EXTEND16);
}

static unsigned long make_bus_param(struct atmel_isi *isi)
{
	unsigned long flags;
	/*
	 * Platform specified synchronization and pixel clock polarities are
	 * only a recommendation and are only used during probing. Atmel ISI
	 * camera interface only works in master mode, i.e., uses HSYNC and
	 * VSYNC signals from the sensor
	 */
	flags = SOCAM_MASTER |
		SOCAM_HSYNC_ACTIVE_HIGH |
		SOCAM_HSYNC_ACTIVE_LOW |
		SOCAM_VSYNC_ACTIVE_HIGH |
		SOCAM_VSYNC_ACTIVE_LOW |
		SOCAM_PCLK_SAMPLE_RISING |
		SOCAM_PCLK_SAMPLE_FALLING |
		SOCAM_DATA_ACTIVE_HIGH;

	if (isi->pdata->data_width_flags & ISI_DATAWIDTH_10)
		flags |= SOCAM_DATAWIDTH_10;

	if (isi->pdata->data_width_flags & ISI_DATAWIDTH_8)
		flags |= SOCAM_DATAWIDTH_8;

	if (flags & SOCAM_DATAWIDTH_MASK)
		return flags;

	return 0;
}

static int isi_camera_try_bus_param(struct soc_camera_device *icd,
				    unsigned char buswidth)
{
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	unsigned long camera_flags;
	int ret;

	camera_flags = icd->ops->query_bus_param(icd);
	ret = soc_camera_bus_param_compatible(camera_flags,
					make_bus_param(isi));
	if (!ret)
		return -EINVAL;
	return 0;
}


static int isi_camera_get_formats(struct soc_camera_device *icd,
				  unsigned int idx,
				  struct soc_camera_format_xlate *xlate)
{
	struct v4l2_subdev *sd = soc_camera_to_subdev(icd);
	int formats = 0, ret;
	/* sensor format */
	enum v4l2_mbus_pixelcode code;
	/* soc camera host format */
	const struct soc_mbus_pixelfmt *fmt;

	ret = v4l2_subdev_call(sd, video, enum_mbus_fmt, idx, &code);
	if (ret < 0)
		/* No more formats */
		return 0;

	fmt = soc_mbus_get_fmtdesc(code);
	if (!fmt) {
		dev_err(icd->dev.parent,
			"Invalid format code #%u: %d\n", idx, code);
		return 0;
	}

	/* This also checks support for the requested bits-per-sample */
	ret = isi_camera_try_bus_param(icd, fmt->bits_per_sample);
	if (ret < 0) {
		dev_err(icd->dev.parent,
			"Fail to try the bus parameters.\n");
		return 0;
	}

	switch (code) {
	case V4L2_MBUS_FMT_UYVY8_2X8:
	case V4L2_MBUS_FMT_VYUY8_2X8:
	case V4L2_MBUS_FMT_YUYV8_2X8:
	case V4L2_MBUS_FMT_YVYU8_2X8:
		formats++;
		if (xlate) {
			xlate->host_fmt	= &isi_camera_formats[0];
			xlate->code	= code;
			xlate++;
			dev_dbg(icd->dev.parent, "Providing format %s using code %d\n",
				isi_camera_formats[0].name, code);
		}
		if (xlate) {
			formats++;
			xlate->host_fmt	= &isi_camera_formats[1];
			xlate->code	= code;
			xlate++;
			dev_dbg(icd->dev.parent, "Providing format %s using code %d\n",
				isi_camera_formats[1].name, code);
		}
		break;
	default:
		if (!isi_camera_packing_supported(fmt))
			return 0;
		if (xlate)
			dev_dbg(icd->dev.parent,
				"Providing format %s in pass-through mode\n",
				fmt->name);
	}

	/* Generic pass-through */
	formats++;
	if (xlate) {
		xlate->host_fmt	= fmt;
		xlate->code	= code;
		xlate++;
	}

	return formats;
}

/* Called with .video_lock held */
static int isi_camera_add_device(struct soc_camera_device *icd)
{
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	int ret;

	if (isi->icd)
		return -EBUSY;

	ret = clk_enable(isi->pck1);
	if(ret)
		return ret;

	ret = clk_enable(isi->pclk);
	if (ret)
		return ret;

	isi->icd = icd;
	dev_dbg(icd->dev.parent, "Atmel ISI Camera driver attached to camera %d\n",
		 icd->devnum);
	return 0;
}
/* Called with .video_lock held */
static void isi_camera_remove_device(struct soc_camera_device *icd)
{
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;

	BUG_ON(icd != isi->icd);

	clk_disable(isi->pclk);
	clk_disable(isi->pck1);
	isi->icd = NULL;

	dev_dbg(icd->dev.parent, "Atmel ISI Camera driver detached from camera %d\n",
		 icd->devnum);
}

static unsigned int isi_camera_poll(struct file *file, poll_table *pt)
{
	struct soc_camera_device *icd = file->private_data;

	return vb2_poll(&icd->vb2_vidq, file, pt);
}

static int isi_camera_querycap(struct soc_camera_host *ici,
			       struct v4l2_capability *cap)
{
	strcpy(cap->driver, "atmel-isi");
	strcpy(cap->card, "Atmel Image Sensor Interface");
	cap->capabilities = (V4L2_CAP_VIDEO_CAPTURE |
				V4L2_CAP_STREAMING);
	return 0;
}

static int isi_camera_set_bus_param(struct soc_camera_device *icd, u32 pixfmt)
{
	struct soc_camera_host *ici = to_soc_camera_host(icd->dev.parent);
	struct atmel_isi *isi = ici->priv;
	unsigned long bus_flags, camera_flags, common_flags;
	int ret;
	u32 cfg1 = 0;

	camera_flags = icd->ops->query_bus_param(icd);

	bus_flags = make_bus_param(isi);
	common_flags = soc_camera_bus_param_compatible(camera_flags, bus_flags);
	dev_dbg(icd->dev.parent, "Flags cam: 0x%lx host: 0x%lx common: 0x%lx\n",
		camera_flags, bus_flags, common_flags);
	if (!common_flags)
		return -EINVAL;

	/* Make choises, based on platform preferences */
	if ((common_flags & SOCAM_HSYNC_ACTIVE_HIGH) &&
	    (common_flags & SOCAM_HSYNC_ACTIVE_LOW)) {
		if (isi->pdata->hsync_act_low)
			common_flags &= ~SOCAM_HSYNC_ACTIVE_HIGH;
		else
			common_flags &= ~SOCAM_HSYNC_ACTIVE_LOW;
	}

	if ((common_flags & SOCAM_VSYNC_ACTIVE_HIGH) &&
	    (common_flags & SOCAM_VSYNC_ACTIVE_LOW)) {
		if (isi->pdata->vsync_act_low)
			common_flags &= ~SOCAM_VSYNC_ACTIVE_HIGH;
		else
			common_flags &= ~SOCAM_VSYNC_ACTIVE_LOW;
	}

	if ((common_flags & SOCAM_PCLK_SAMPLE_RISING) &&
	    (common_flags & SOCAM_PCLK_SAMPLE_FALLING)) {
		if (isi->pdata->pclk_act_falling)
			common_flags &= ~SOCAM_PCLK_SAMPLE_RISING;
		else
			common_flags &= ~SOCAM_PCLK_SAMPLE_FALLING;
	}

	ret = icd->ops->set_bus_param(icd, common_flags);
	if (ret < 0) {
		dev_dbg(icd->dev.parent, "Camera set_bus_param(%lx) returned %d\n",
			common_flags, ret);
		return ret;
	}

	/* set bus param for ISI */
	if (common_flags & SOCAM_HSYNC_ACTIVE_LOW)
		cfg1 |= ISI_CFG1_HSYNC_POL_ACTIVE_LOW;
	if (common_flags & SOCAM_VSYNC_ACTIVE_LOW)
		cfg1 |= ISI_CFG1_VSYNC_POL_ACTIVE_LOW;
	if (common_flags & SOCAM_PCLK_SAMPLE_FALLING)
		cfg1 |= ISI_CFG1_PIXCLK_POL_ACTIVE_FALLING;

	if (isi->pdata->has_emb_sync)
		cfg1 |= ISI_CFG1_EMB_SYNC;
	if (isi->pdata->isi_full_mode)
		cfg1 |= ISI_CFG1_FULL_MODE;

	isi_writel(isi, ISI_CTRL, ISI_CTRL_DIS);
	isi_writel(isi, ISI_CFG1, cfg1);

	return 0;
}


static int isi_camera_set_parm(struct soc_camera_device *icd, struct v4l2_streamparm *parm)
{
	return 0;
}

static struct soc_camera_host_ops isi_soc_camera_host_ops = {
	.owner		= THIS_MODULE,
	.add		= isi_camera_add_device,
	.remove		= isi_camera_remove_device,
	.set_fmt	= isi_camera_set_fmt,
	.try_fmt	= isi_camera_try_fmt,
	.get_formats	= isi_camera_get_formats,
	.init_videobuf2	= isi_camera_init_videobuf,
	.poll		= isi_camera_poll,
	.querycap	= isi_camera_querycap,
	.set_bus_param	= isi_camera_set_bus_param,
	.set_parm	= isi_camera_set_parm,
};

static void __init isi_set_clk(void)
{
	struct clk *pck1;
	struct clk *plla;

	pck1 = clk_get(NULL, "pck1");
	plla = clk_get(NULL, "plla");

	clk_set_parent(pck1, plla);
	/* for the sensor ov9655: 10< Fclk < 48, Fclk typ = 24MHz */
	clk_set_rate(pck1, 25000000);
}

/* -----------------------------------------------------------------------*/
static int __devexit atmel_isi_remove(struct platform_device *pdev)
{
	struct soc_camera_host *soc_host = to_soc_camera_host(&pdev->dev);
	struct atmel_isi *isi = container_of(soc_host,
					struct atmel_isi, soc_host);

	free_irq(isi->irq, isi);
	soc_camera_host_unregister(soc_host);
	vb2_dma_contig_cleanup_ctx(isi->alloc_ctx);
#ifdef ANDROID	
	dma_free_coherent(&pdev->dev,
			VID_LIMIT_BYTES,
			isi->video_buf,
			isi->video_buf_phys);
#endif
	dma_free_coherent(&pdev->dev,
			sizeof(struct fbd) * MAX_BUFFER_NUM,
			isi->p_fb_descriptors,
			isi->fb_descriptors_phys);

	iounmap(isi->regs);
	clk_put(isi->pclk);
	clk_put(isi->pck1);
	kfree(isi);

	return 0;
}

static int __devinit atmel_isi_probe(struct platform_device *pdev)
{
	unsigned int irq;
	struct atmel_isi *isi;
	struct clk *pclk, *pck1;
	struct resource *regs;
	int ret, i;
	struct device *dev = &pdev->dev;
	struct soc_camera_host *soc_host;
	struct isi_platform_data *pdata;

	pdata = dev->platform_data;
	if (!pdata || !pdata->data_width_flags) {
		dev_err(&pdev->dev,
			"No config available for Atmel ISI\n");
		return -EINVAL;
	}

	regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!regs)
		return -ENXIO;

	isi_set_clk();

	pclk = clk_get(&pdev->dev, "isi_clk");
	if (IS_ERR(pclk))
		return PTR_ERR(pclk);

	pck1 = clk_get(NULL, "pck1");
	if (IS_ERR(pck1)){
		ret = -EINVAL;
		dev_err(&pdev->dev, "Can't get pck1\n");
		goto err_get_pck1;
	}

	isi = kzalloc(sizeof(struct atmel_isi), GFP_KERNEL);
	if (!isi) {
		ret = -ENOMEM;
		dev_err(&pdev->dev, "Can't allocate interface!\n");
		goto err_alloc_isi;
	}

	isi->pclk = pclk;
	isi->pck1 = pck1;
	isi->pdata = pdata;
	isi->active = NULL;
	spin_lock_init(&isi->lock);
	init_waitqueue_head(&isi->vsync_wq);
	INIT_LIST_HEAD(&isi->video_buffer_list);
	INIT_LIST_HEAD(&isi->dma_desc_head);

	isi->p_fb_descriptors = dma_alloc_coherent(&pdev->dev,
				sizeof(struct fbd) * MAX_BUFFER_NUM,
				&isi->fb_descriptors_phys,
				GFP_KERNEL);
	if (!isi->p_fb_descriptors) {
		ret = -ENOMEM;
		dev_err(&pdev->dev, "Can't allocate descriptors!\n");
		goto err_alloc_descriptors;
	}

	for (i = 0; i < MAX_BUFFER_NUM; i++) {
		isi->dma_desc[i].p_fbd = isi->p_fb_descriptors + i;
		isi->dma_desc[i].fbd_phys = isi->fb_descriptors_phys +
					i * sizeof(struct fbd);
		list_add(&isi->dma_desc[i].list, &isi->dma_desc_head);
	}

#ifdef ANDROID
	isi->video_buf = dma_alloc_coherent(&pdev->dev,
				VID_LIMIT_BYTES,
				&isi->video_buf_phys,
				GFP_KERNEL);
	if (!isi->video_buf){
		ret = -ENOMEM;
		dev_err(&pdev->dev, "Can't allocate video buffer.Size: 0x%x!\n",VID_LIMIT_BYTES);
		goto err_alloc_videobuf;		
	}
#endif

	isi->alloc_ctx = vb2_dma_contig_init_ctx(&pdev->dev);
	if (IS_ERR(isi->alloc_ctx)) {
		ret = PTR_ERR(isi->alloc_ctx);
		goto err_alloc_ctx;
	}
	
	isi->regs = ioremap(regs->start, resource_size(regs));
	if (!isi->regs) {
		ret = -ENOMEM;
		goto err_ioremap;
	}

	isi_writel(isi, ISI_CTRL, ISI_CTRL_DIS);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		ret = irq;
		goto err_req_irq;
	}

	ret = request_irq(irq, isi_interrupt, 0, "isi", isi);
	if (ret) {
		dev_err(&pdev->dev, "Unable to request irq %d\n", irq);
		goto err_req_irq;
	}
	isi->irq = irq;

	soc_host		= &isi->soc_host;
	soc_host->drv_name	= "isi-camera";
	soc_host->ops		= &isi_soc_camera_host_ops;
	soc_host->priv		= isi;
	soc_host->v4l2_dev.dev	= &pdev->dev;
	soc_host->nr		= pdev->id;

	ret = soc_camera_host_register(soc_host);
	if (ret) {
		dev_err(&pdev->dev, "Unable to register soc camera host\n");
		goto err_register_soc_camera_host;
	}
	return 0;

err_register_soc_camera_host:
	free_irq(isi->irq, isi);
err_req_irq:
	iounmap(isi->regs);
err_ioremap:
	vb2_dma_contig_cleanup_ctx(isi->alloc_ctx);
err_alloc_ctx:
#ifdef ANDROID
	dma_free_coherent(&pdev->dev,
			VID_LIMIT_BYTES,
			isi->video_buf,
			isi->video_buf_phys);

#endif
err_alloc_videobuf:
		dma_free_coherent(&pdev->dev,
			sizeof(struct fbd) * MAX_BUFFER_NUM,
			isi->p_fb_descriptors,
			isi->fb_descriptors_phys);
err_alloc_descriptors:
	kfree(isi);
err_alloc_isi:
	clk_put(pck1);
err_get_pck1:
	clk_put(pclk);

	return ret;
}

#ifdef CONFIG_PM

static int atmel_isi_suspend(struct platform_device *pdev, pm_message_t mesg)
{
	struct soc_camera_host *soc_host = to_soc_camera_host(&pdev->dev);
	struct atmel_isi *isi = container_of(soc_host,
					struct atmel_isi, soc_host);
	/* Nothing need to do here, clock has been disabled by isi_camera_remove_device */
	return 0;
}

static int atmel_isi_resume(struct platform_device *pdev)
{
	int ret = 0;
	struct soc_camera_host *soc_host = to_soc_camera_host(&pdev->dev);
	struct atmel_isi *isi = container_of(soc_host,
					struct atmel_isi, soc_host);
	/* Nothing need to do here, clock has been enabled by isi_camera_add_device */
	return ret;
}

#else
#define atmel_isi_suspend	NULL
#define atmel_isi_resume	NULL
#endif


static struct platform_driver atmel_isi_driver = {
	.probe		= atmel_isi_probe,
	.remove		= __devexit_p(atmel_isi_remove),
	.suspend	= atmel_isi_suspend,
	.resume 	= atmel_isi_resume,
	.driver		= {
		.name = "atmel_isi",
		.owner = THIS_MODULE,
	},
};

static int __init atmel_isi_init_module(void)
{
	return  platform_driver_probe(&atmel_isi_driver, &atmel_isi_probe);
}

static void __exit atmel_isi_exit(void)
{
	platform_driver_unregister(&atmel_isi_driver);
}
module_init(atmel_isi_init_module);
module_exit(atmel_isi_exit);

MODULE_AUTHOR("Josh Wu <josh.wu@atmel.com>");
MODULE_DESCRIPTION("The V4L2 driver for Atmel Linux");
MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("video");
