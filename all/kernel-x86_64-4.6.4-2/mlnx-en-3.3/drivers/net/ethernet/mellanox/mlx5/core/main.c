/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <asm-generic/kmap_types.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/cq.h>
#include <linux/mlx5/qp.h>
#include <linux/mlx5/srq.h>
#include <linux/debugfs.h>
#include <linux/kmod.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/pm.h>
#ifdef CONFIG_RFS_ACCEL
#include <linux/cpu_rmap.h>
#endif
#include <linux/bitmap.h>
#include "mlx5_core.h"
#include "fs_core.h"
#include "eswitch.h"
#include <linux/ctype.h>

MODULE_AUTHOR("Eli Cohen <eli@mellanox.com>");
MODULE_DESCRIPTION("Mellanox Connect-IB, ConnectX-4 core driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);

int mlx5_core_debug_mask;
module_param_named(debug_mask, mlx5_core_debug_mask, int, 0644);
MODULE_PARM_DESC(debug_mask, "debug mask: 1 = dump cmd data, 2 = dump cmd exec time, 3 = both. Default=0");

#define MLX5_DEFAULT_PROF	2
static int prof_sel = MLX5_DEFAULT_PROF;
module_param_named(prof_sel, prof_sel, int, 0444);
MODULE_PARM_DESC(prof_sel, "profile selector. Valid range 0 - 2");

static LIST_HEAD(intf_list);
static LIST_HEAD(dev_list);
static DEFINE_MUTEX(intf_mutex);

static struct pci_dev *mlx5_pci_phys_fn(struct pci_dev *pdev)
{
#ifdef CONFIG_PCI_IOV
	if (pdev->is_virtfn)
		pdev = pdev->physfn;
#endif
	return pdev;
}

struct mlx5_device_context {
	struct list_head	list;
	struct mlx5_interface  *intf;
	void		       *context;
};

enum {
	MLX5_ATOMIC_REQ_MODE_BE = 0x0,
	MLX5_ATOMIC_REQ_MODE_HOST_ENDIANNESS = 0x1,
};

static struct mlx5_profile profile[] = {
	[0] = {
		.mask           = 0,
	},
	[1] = {
		.mask		= MLX5_PROF_MASK_QP_SIZE |
				  MLX5_PROF_MASK_DCT,
		.log_max_qp	= 12,
		.dct_enable	= 1,
	},
	[2] = {
		.mask		= MLX5_PROF_MASK_QP_SIZE  |
				  MLX5_PROF_MASK_MR_CACHE |
				  MLX5_PROF_MASK_DCT,
		.log_max_qp	= 18,
		.dct_enable	= 1,
		.mr_cache[0]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[1]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[2]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[3]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[4]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[5]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[6]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[7]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[8]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[9]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[10]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[11]	= {
			.size	= 500,
			.limit	= 250
		},
		.mr_cache[12]	= {
			.size	= 64,
			.limit	= 32
		},
		.mr_cache[13]	= {
			.size	= 32,
			.limit	= 16
		},
		.mr_cache[14]	= {
			.size	= 16,
			.limit	= 8
		},
	},
};

#define FW_INIT_TIMEOUT_MILI	2000
#define FW_INIT_WAIT_MS		2

static int wait_fw_init(struct mlx5_core_dev *dev, u32 max_wait_mili)
{
	unsigned long end = jiffies + msecs_to_jiffies(max_wait_mili);
	int err = 0;

	while (fw_initializing(dev)) {
		if (time_after(jiffies, end)) {
			err = -EBUSY;
			break;
		}
		msleep(FW_INIT_WAIT_MS);
	}

	return err;
}

static int set_dma_caps(struct pci_dev *pdev)
{
	int err;

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		dev_warn(&pdev->dev, "Warning: couldn't set 64-bit PCI DMA mask\n");
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "Can't set PCI DMA mask, aborting\n");
			return err;
		}
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		dev_warn(&pdev->dev,
			 "Warning: couldn't set 64-bit consistent PCI DMA mask\n");
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev,
				"Can't set consistent PCI DMA mask, aborting\n");
			return err;
		}
	}

	dma_set_max_seg_size(&pdev->dev, 2u * 1024 * 1024 * 1024);
	return err;
}

static int mlx5_pci_enable_device(struct mlx5_core_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;
	int err = 0;

	mutex_lock(&dev->pci_status_mutex);
	if (dev->pci_status == MLX5_PCI_STATUS_DISABLED) {
		err = pci_enable_device(pdev);
		if (!err)
			dev->pci_status = MLX5_PCI_STATUS_ENABLED;
	}
	mutex_unlock(&dev->pci_status_mutex);

	return err;
}

static void mlx5_pci_disable_device(struct mlx5_core_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;

	mutex_lock(&dev->pci_status_mutex);
	if (dev->pci_status == MLX5_PCI_STATUS_ENABLED) {
		pci_disable_device(pdev);
		dev->pci_status = MLX5_PCI_STATUS_DISABLED;
	}
	mutex_unlock(&dev->pci_status_mutex);
}

static int request_bar(struct pci_dev *pdev)
{
	int err = 0;

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Missing registers BAR, aborting\n");
		return -ENODEV;
	}

	err = pci_request_regions(pdev, DRIVER_NAME);
	if (err)
		dev_err(&pdev->dev, "Couldn't get PCI resources, aborting\n");

	return err;
}

static void release_bar(struct pci_dev *pdev)
{
	pci_release_regions(pdev);
}

enum {
	PPC_MAX_VECTORS = 32,
};

static int mlx5_enable_msix(struct mlx5_core_dev *dev)
{
	struct mlx5_eq_table *table = &dev->priv.eq_table;
	int num_eqs = 1 << MLX5_CAP_GEN(dev, log_max_eq);
	struct mlx5_priv *priv = &dev->priv;
	int nvec;
#ifndef HAVE_PCI_ENABLE_MSIX_RANGE
	int err;
#endif 
	int i;

	nvec = MLX5_CAP_GEN(dev, num_ports) * num_online_cpus() +
	       MLX5_EQ_VEC_COMP_BASE;
	nvec = min_t(int, nvec, num_eqs);
#ifdef CONFIG_PPC
	nvec = min_t(int, nvec, PPC_MAX_VECTORS);
#endif
	if (nvec <= MLX5_EQ_VEC_COMP_BASE)
		return -ENOMEM;

	priv->msix_arr = kzalloc(nvec * sizeof(*priv->msix_arr), GFP_KERNEL);
	priv->irq_info = kzalloc(nvec * sizeof(*priv->irq_info), GFP_KERNEL);
	if (!priv->msix_arr || !priv->irq_info)
		goto err_free_msix;

	for (i = 0; i < nvec; i++)
		priv->msix_arr[i].entry = i;

#ifdef HAVE_PCI_ENABLE_MSIX_RANGE
	nvec = pci_enable_msix_range(dev->pdev, priv->msix_arr,
				     MLX5_EQ_VEC_COMP_BASE + 1, nvec);
	if (nvec < 0)
		return nvec;

	table->num_comp_vectors = nvec - MLX5_EQ_VEC_COMP_BASE;
#else
retry:
	table->num_comp_vectors = nvec - MLX5_EQ_VEC_COMP_BASE;
	err = pci_enable_msix(dev->pdev, priv->msix_arr, nvec);
	if (err <= 0) {
		return err;
	} else if (err > 2) {
		nvec = err;
		goto retry;
	}
	mlx5_core_dbg(dev, "received %d MSI vectors out of %d requested\n", err, nvec);
#endif
 
	return 0;

err_free_msix:
	kfree(priv->irq_info);
	kfree(priv->msix_arr);
	return -ENOMEM;
}

static void mlx5_disable_msix(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;

	pci_disable_msix(dev->pdev);
	kfree(priv->irq_info);
	kfree(priv->msix_arr);
}

struct mlx5_reg_host_endianess {
	u8	he;
	u8      rsvd[15];
};


#define CAP_MASK(pos, size) ((u64)((1 << (size)) - 1) << (pos))

enum {
	MLX5_CAP_BITS_RW_MASK = CAP_MASK(MLX5_CAP_OFF_CMDIF_CSUM, 2) |
				MLX5_DEV_CAP_FLAG_DCT |
				MLX5_DEV_CAP_FLAG_DRAIN_SIGERR,
};

static u16 to_fw_pkey_sz(u32 size)
{
	switch (size) {
	case 128:
		return 0;
	case 256:
		return 1;
	case 512:
		return 2;
	case 1024:
		return 3;
	case 2048:
		return 4;
	case 4096:
		return 5;
	default:
		pr_warn("invalid pkey table size %d\n", size);
		return 0;
	}
}

int mlx5_core_query_special_contexts(struct mlx5_core_dev *dev)
{
	u32 in[MLX5_ST_SZ_DW(query_special_contexts_in)];
	u32 out[MLX5_ST_SZ_DW(query_special_contexts_out)];
	int err;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(query_special_contexts_in, in, opcode,
		 MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS);
	err = mlx5_cmd_exec_check_status(dev, in, sizeof(in), out,
					 sizeof(out));
	if (err)
		return err;

	dev->special_contexts.resd_lkey = MLX5_GET(query_special_contexts_out,
						   out, resd_lkey);

	return err;
}

int mlx5_core_get_caps(struct mlx5_core_dev *dev, enum mlx5_cap_type cap_type,
		       enum mlx5_cap_mode cap_mode)
{
	u8 in[MLX5_ST_SZ_BYTES(query_hca_cap_in)];
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	void *out, *hca_caps;
	u16 opmod = (cap_type << 1) | (cap_mode & 0x01);
	int err;

	memset(in, 0, sizeof(in));
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	MLX5_SET(query_hca_cap_in, in, op_mod, opmod);
	err = mlx5_cmd_exec(dev, in, sizeof(in), out, out_sz);
	if (err)
		goto query_ex;

	err = mlx5_cmd_status_to_err_v2(out);
	if (err) {
		mlx5_core_warn(dev,
			       "QUERY_HCA_CAP : type(%x) opmode(%x) Failed(%d)\n",
			       cap_type, cap_mode, err);
		goto query_ex;
	}

	hca_caps =  MLX5_ADDR_OF(query_hca_cap_out, out, capability);

	switch (cap_mode) {
	case HCA_CAP_OPMOD_GET_MAX:
		memcpy(dev->hca_caps_max[cap_type], hca_caps,
		       MLX5_UN_SZ_BYTES(hca_cap_union));
		break;
	case HCA_CAP_OPMOD_GET_CUR:
		memcpy(dev->hca_caps_cur[cap_type], hca_caps,
		       MLX5_UN_SZ_BYTES(hca_cap_union));
		break;
	default:
		mlx5_core_warn(dev,
			       "Tried to query dev cap type(%x) with wrong opmode(%x)\n",
			       cap_type, cap_mode);
		err = -EINVAL;
		break;
	}
query_ex:
	kfree(out);
	return err;
}

static int set_caps(struct mlx5_core_dev *dev, void *in, int in_sz, int opmod)
{
	u32 out[MLX5_ST_SZ_DW(set_hca_cap_out)];
	int err;

	memset(out, 0, sizeof(out));

	MLX5_SET(set_hca_cap_in, in, opcode, MLX5_CMD_OP_SET_HCA_CAP);
	MLX5_SET(set_hca_cap_in, in, op_mod, opmod << 1);
	err = mlx5_cmd_exec(dev, in, in_sz, out, sizeof(out));
	if (err)
		return err;

	err = mlx5_cmd_status_to_err_v2(out);

	return err;
}

static int handle_hca_cap_atomic(struct mlx5_core_dev *dev)
{
	void *set_ctx;
	void *set_hca_cap;
	int set_sz = MLX5_ST_SZ_BYTES(set_hca_cap_in);
	int req_endianness;
	int err;

	if (MLX5_CAP_GEN(dev, atomic)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_ATOMIC,
					 HCA_CAP_OPMOD_GET_CUR);
		if (err)
			return err;
	} else {
		return 0;
	}

	req_endianness =
		MLX5_CAP_ATOMIC(dev,
				supported_atomic_req_8B_endianess_mode_1);

	if (req_endianness != MLX5_ATOMIC_REQ_MODE_HOST_ENDIANNESS)
		return 0;

	set_ctx = kzalloc(set_sz, GFP_KERNEL);
	if (!set_ctx)
		return -ENOMEM;

	set_hca_cap = MLX5_ADDR_OF(set_hca_cap_in, set_ctx, capability);

	/* Set requestor to host endianness */
	MLX5_SET(atomic_caps, set_hca_cap, atomic_req_8B_endianess_mode,
		 MLX5_ATOMIC_REQ_MODE_HOST_ENDIANNESS);

	err = set_caps(dev, set_ctx, set_sz, MLX5_SET_HCA_CAP_OP_MOD_ATOMIC);

	kfree(set_ctx);
	return err;
}

static int handle_hca_cap(struct mlx5_core_dev *dev)
{
	void *set_ctx = NULL;
	struct mlx5_profile *prof = dev->profile;
	int err = -ENOMEM;
	int set_sz = MLX5_ST_SZ_BYTES(set_hca_cap_in);
	void *set_hca_cap;

	set_ctx = kzalloc(set_sz, GFP_KERNEL);
	if (!set_ctx)
		goto query_ex;

	err = mlx5_core_get_caps(dev, MLX5_CAP_GENERAL, HCA_CAP_OPMOD_GET_MAX);
	if (err)
		goto query_ex;

	err = mlx5_core_get_caps(dev, MLX5_CAP_GENERAL, HCA_CAP_OPMOD_GET_CUR);
	if (err)
		goto query_ex;

	set_hca_cap = MLX5_ADDR_OF(set_hca_cap_in, set_ctx,
				   capability);
	memcpy(set_hca_cap, dev->hca_caps_cur[MLX5_CAP_GENERAL],
	       MLX5_ST_SZ_BYTES(cmd_hca_cap));

	mlx5_core_dbg(dev, "Current Pkey table size %d Setting new size %d\n",
		      mlx5_to_sw_pkey_sz(MLX5_CAP_GEN(dev, pkey_table_size)),
		      128);
	/* we limit the size of the pkey table to 128 entries for now */
	MLX5_SET(cmd_hca_cap, set_hca_cap, pkey_table_size,
		 to_fw_pkey_sz(128));

	if (prof->mask & MLX5_PROF_MASK_QP_SIZE)
		MLX5_SET(cmd_hca_cap, set_hca_cap, log_max_qp,
			 prof->log_max_qp);

	/* disable cmdif checksum */
	MLX5_SET(cmd_hca_cap, set_hca_cap, cmdif_checksum, 0);

	/* enable drain sigerr */
	MLX5_SET(cmd_hca_cap, set_hca_cap, drain_sigerr, 1);

	/* disable link up by INIT_HCA */
	if (MLX5_CAP_GEN_MAX(dev, disable_linkup))
		MLX5_SET(cmd_hca_cap, set_hca_cap, disable_linkup, 1);

	MLX5_SET(cmd_hca_cap, set_hca_cap, log_uar_page_sz, PAGE_SHIFT - 12);

	if (prof->mask & MLX5_PROF_MASK_DCT) {
		if (prof->dct_enable) {
			if (MLX5_CAP_GEN_MAX(dev, dct)) {
				MLX5_SET(cmd_hca_cap, set_hca_cap, dct, 1);
				dev->aysnc_events_mask |= (1ull << MLX5_EVENT_TYPE_DCT_DRAINED) |
					(1ull << MLX5_EVENT_TYPE_DCT_KEY_VIOLATION);
			}
		} else {
			MLX5_SET(cmd_hca_cap, set_hca_cap, dct, 0);
		}
	}

	if (MLX5_GET(cmd_hca_cap, dev->hca_caps_max, cache_line_128byte))
		MLX5_SET(cmd_hca_cap,
			 set_hca_cap,
			 cache_line_128byte,
			 cache_line_size() == 128 ? 1 : 0);

	err = set_caps(dev, set_ctx, set_sz,
		       MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE);

query_ex:
	kfree(set_ctx);
	return err;
}

static int set_hca_ctrl(struct mlx5_core_dev *dev)
{
	struct mlx5_reg_host_endianess he_in;
	struct mlx5_reg_host_endianess he_out;
	int err;

	if (!mlx5_core_is_pf(dev))
		return 0;

	memset(&he_in, 0, sizeof(he_in));
	he_in.he = MLX5_SET_HOST_ENDIANNESS;
	err = mlx5_core_access_reg(dev, &he_in,  sizeof(he_in),
					&he_out, sizeof(he_out),
					MLX5_REG_HOST_ENDIANNESS, 0, 1);
	return err;
}

int mlx5_core_enable_hca(struct mlx5_core_dev *dev, u16 func_id)
{
	u32 in[MLX5_ST_SZ_DW(enable_hca_in)];
	u32 out[MLX5_ST_SZ_DW(enable_hca_out)];

	memset(in, 0, sizeof(in));
	MLX5_SET(enable_hca_in, in, opcode, MLX5_CMD_OP_ENABLE_HCA);
	MLX5_SET(enable_hca_in, in, function_id, func_id);
	memset(out, 0, sizeof(out));

	return mlx5_cmd_exec_check_status(dev, in, sizeof(in),
					  out, sizeof(out));
}

int mlx5_core_disable_hca(struct mlx5_core_dev *dev, u16 func_id)
{
	u32 in[MLX5_ST_SZ_DW(disable_hca_in)];
	u32 out[MLX5_ST_SZ_DW(disable_hca_out)];

	memset(in, 0, sizeof(in));
	MLX5_SET(disable_hca_in, in, opcode, MLX5_CMD_OP_DISABLE_HCA);
	MLX5_SET(disable_hca_in, in, function_id, func_id);
	memset(out, 0, sizeof(out));

	return mlx5_cmd_exec_check_status(dev, in, sizeof(in), out, sizeof(out));
}

static u32 internal_timer_h(struct mlx5_core_dev *dev)
{
	return ioread32be(&dev->iseg->internal_timer_h);
}

static u32 internal_timer_l(struct mlx5_core_dev *dev)
{
	return ioread32be(&dev->iseg->internal_timer_l);
}

cycle_t mlx5_core_read_clock(struct mlx5_core_dev *dev)
{
	u32 timer_h, timer_h1, timer_l;

	/*  Reading the internal timer using 2 PCI reads in a non-atomic manner
	 * may hit the wraparound of the 32 LSBs. Reading the 32 MSBs twice can
	 * verify a wraparound did not happen.
	 */
	timer_h = internal_timer_h(dev);
	timer_l = internal_timer_l(dev);
	timer_h1 = internal_timer_h(dev);
	if (timer_h == timer_h1)
		goto ret;

	/* In case of overflow or wraparound, re-read the LSB */
	timer_l = internal_timer_l(dev);

ret:
	return (u64)timer_l | (u64)timer_h1 << 32;
}
EXPORT_SYMBOL(mlx5_core_read_clock);

static int mlx5_core_set_issi(struct mlx5_core_dev *dev)
{
	u32 query_in[MLX5_ST_SZ_DW(query_issi_in)];
	u32 query_out[MLX5_ST_SZ_DW(query_issi_out)];
	u32 set_in[MLX5_ST_SZ_DW(set_issi_in)];
	u32 set_out[MLX5_ST_SZ_DW(set_issi_out)];
	int err;

	memset(query_in, 0, sizeof(query_in));
	memset(query_out, 0, sizeof(query_out));

	MLX5_SET(query_issi_in, query_in, opcode, MLX5_CMD_OP_QUERY_ISSI);

	err = mlx5_cmd_exec_check_status(dev, query_in, sizeof(query_in),
					 query_out, sizeof(query_out));
	if (err) {
		dev->issi = 0;
		return 0;
	}

	dev->supported_issi_mask = MLX5_GET(query_issi_out, query_out, supported_issi_dw0);

	if (dev->supported_issi_mask & (1 << 1)) {
		memset(set_in, 0, sizeof(set_in));
		memset(set_out, 0, sizeof(set_out));

		MLX5_SET(set_issi_in, set_in, opcode, MLX5_CMD_OP_SET_ISSI);
		MLX5_SET(set_issi_in, set_in, current_issi, 1);

		err = mlx5_cmd_exec_check_status(dev, set_in, sizeof(set_in),
						 set_out, sizeof(set_out));
		if (err) {
			mlx5_core_warn(dev, "failed to set ISSI=1\n");
			return err;
		}
		dev->issi = 1;
		return 0;
	} else if ((dev->supported_issi_mask & (1 << 0)) ||
		   (!dev->supported_issi_mask)) {
		dev->issi = 0;
		return 0;
	}

	return -ENOTSUPP;
}

static inline int get_num_of_numas(u64 *numa_bitmap)
{
	int i = 0;
	int cpu_id;

	for_each_cpu(cpu_id, cpu_online_mask) {
		if (!test_bit(cpu_to_node(cpu_id), (unsigned long *)numa_bitmap)) {
			bitmap_set((unsigned long *)numa_bitmap, cpu_to_node(cpu_id), 1);
			i++;
		}
	}

	return i + 1;
}

static inline void get_numa_phys_mask(struct cpumask *phys_cpus, int node)
{
	struct cpumask log_cpus;
	int log_cpu;
	int cpu;

	memset(&log_cpus, 0, sizeof(log_cpus));
	for_each_cpu_and(cpu, cpumask_of_node(node), cpu_online_mask) {
		int lc = 0;

		/* Make sure we are not getting the same physical cpu again */
		if (cpumask_test_cpu(cpu, &log_cpus))
			continue;

		for_each_cpu_and(log_cpu, topology_thread_cpumask(cpu), cpu_online_mask) {
			if (lc == 0)
				cpumask_set_cpu(log_cpu, phys_cpus);

			cpumask_set_cpu(log_cpu, &log_cpus);
			lc++;
		}
	}
}

static unsigned int get_next_numa_cpu(unsigned int i, int node)
{
	struct cpumask *free_threads = NULL;
	struct cpumask *cpu_threads = NULL;
	struct cpumask *phys_cores = NULL;
	unsigned int log_cpu;
	int cpu;

	free_threads = kzalloc(sizeof(*free_threads), GFP_KERNEL);
	cpu_threads = kzalloc(sizeof(*cpu_threads), GFP_KERNEL);
	phys_cores = kzalloc(sizeof(*phys_cores), GFP_KERNEL);
	if (!phys_cores || !cpu_threads || !free_threads)
		goto err;

	cpumask_and(free_threads, cpu_online_mask, cpumask_of_node(node));
	get_numa_phys_mask(phys_cores, node);

	 while (!cpumask_empty(free_threads)) {
		for_each_cpu(cpu, phys_cores) {

			cpumask_and(cpu_threads, topology_thread_cpumask(cpu),
				    free_threads);

			if (cpumask_empty(cpu_threads))
				continue;

			log_cpu = cpumask_first(cpu_threads);
			cpumask_clear_cpu(log_cpu, free_threads);
			if (i-- == 0)
				goto out;
		}
	}
err:
	log_cpu = cpumask_first(cpumask_of_node(node));
out:
	kfree(phys_cores);
	kfree(cpu_threads);
	kfree(free_threads);

	return log_cpu;
}

static unsigned int get_ncores_in_numa(int node)
{
	struct cpumask node_online_mask;

	cpumask_and(&node_online_mask, cpu_online_mask, cpumask_of_node(node));
	return cpumask_weight(&node_online_mask);
}

static unsigned int get_next_cpu(unsigned int i, int node)
{
	int node_num_of_cores;
	u64 numa_bitmap = 0;
	int num_of_numas;
	unsigned int cpu;
	int node_id;

	/* Wrap: we always want a cpu. */
	i %= num_online_cpus();

	if (node == -1) {
		for_each_cpu(cpu, cpu_online_mask)
			if (i-- == 0)
				break;
		return cpu;
	}

	node_num_of_cores = get_ncores_in_numa(node);
	if (i < node_num_of_cores)
		return get_next_numa_cpu(i, node);

	i -= node_num_of_cores;

	/* All other numas */
	num_of_numas = get_num_of_numas(&numa_bitmap);
	for_each_set_bit(node_id, (unsigned long *)(&numa_bitmap), 64) {
		if (node == node_id)
			continue;

		node_num_of_cores = get_ncores_in_numa(node_id);
		if (i < node_num_of_cores)
			return get_next_numa_cpu(i, node_id);

		i -= node_num_of_cores;
	}

	return cpumask_first(cpumask_of_node(node));
}

static void mlx5_irq_set_affinity_hint(struct mlx5_core_dev *mdev, int i)
{
	struct mlx5_priv *priv  = &mdev->priv;
	struct msix_entry *msix = priv->msix_arr;
	int irq                 = msix[i + MLX5_EQ_VEC_COMP_BASE].vector;
	int numa_node           = priv->numa_node;

	if (numa_node == -1)
		numa_node = first_online_node;

	if (!zalloc_cpumask_var(&priv->irq_info[i].mask, GFP_KERNEL)) {
		mlx5_core_warn(mdev, "zalloc_cpumask_var failed");
		return;
	}

	cpumask_set_cpu(get_next_cpu(i, numa_node),
			priv->irq_info[i].mask);

	if (irq_set_affinity_hint(irq, priv->irq_info[i].mask)) {
		mlx5_core_warn(mdev, "irq_set_affinity_hint failed,irq 0x%.4x",
			       irq);
		goto err_clear_mask;
	}

	return;

err_clear_mask:
#ifdef CONFIG_CPUMASK_OFFSTACK
	priv->irq_info[i].mask = NULL;
#else
	/* just to keep gcc happy - (we can't have a label at the end of a
	 * function) */
	return;
#endif
}

static void mlx5_irq_clear_affinity_hint(struct mlx5_core_dev *mdev, int i)
{
	struct mlx5_priv *priv  = &mdev->priv;
	struct msix_entry *msix = priv->msix_arr;
	int irq                 = msix[i + MLX5_EQ_VEC_COMP_BASE].vector;
	cpumask_var_t mask;

	if (!priv->irq_info[i].mask)
		return;
#ifdef CONFIG_CPUMASK_OFFSTACK
	mask                    = priv->irq_info[i].mask;
#else
	mask[0]                 = *(priv->irq_info[i].mask);
#endif

	irq_set_affinity_hint(irq, NULL);
	free_cpumask_var(mask);
}

static void mlx5_irq_set_affinity_hints(struct mlx5_core_dev *mdev)
{
	int i;

	for (i = 0; i < mdev->priv.eq_table.num_comp_vectors; i++)
		mlx5_irq_set_affinity_hint(mdev, i);
}

static void mlx5_irq_clear_affinity_hints(struct mlx5_core_dev *mdev)
{
	int i;

	for (i = 0; i < mdev->priv.eq_table.num_comp_vectors; i++) {
		mlx5_irq_clear_affinity_hint(mdev, i);
	}
}

int mlx5_vector2eqn(struct mlx5_core_dev *dev, int vector, int *eqn,
		    unsigned int *irqn)
{
	struct mlx5_eq_table *table = &dev->priv.eq_table;
	struct mlx5_eq *eq, *n;
	int err = -ENOENT;

	spin_lock(&table->lock);
	list_for_each_entry_safe(eq, n, &table->comp_eqs_list, list) {
		if (eq->index == vector) {
			*eqn = eq->eqn;
			*irqn = eq->irqn;
			err = 0;
			break;
		}
	}
	spin_unlock(&table->lock);

	return err;
}
EXPORT_SYMBOL(mlx5_vector2eqn);

struct mlx5_eq *mlx5_eqn2eq(struct mlx5_core_dev *dev, int eqn)
{
	struct mlx5_eq_table *table = &dev->priv.eq_table;
	struct mlx5_eq *eq;

	spin_lock(&table->lock);
	list_for_each_entry(eq, &table->comp_eqs_list, list)
		if (eq->eqn == eqn) {
			spin_unlock(&table->lock);
			return eq;
		}

	spin_unlock(&table->lock);

	return ERR_PTR(-ENOENT);
}

void mlx5_rename_comp_eq(struct mlx5_core_dev *dev, unsigned int eq_ix,
			 char *name)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_eq_table *table = &priv->eq_table;
	char *dst_name;
	int irq_ix;
	int err = 0;

	spin_lock(&table->lock);
	if (eq_ix >= table->num_comp_vectors) {
		err = -ENOENT;
		dev_err(&dev->pdev->dev, "%s: mlx5_rename_comp_eq failed: %d\n",
			__func__, err);
		goto unlock;
	}
	irq_ix = eq_ix + MLX5_EQ_VEC_COMP_BASE;
	dst_name = priv->irq_info[irq_ix].name;
	if (!name) {
		snprintf(dst_name, MLX5_MAX_IRQ_NAME,
			 MLX5_DEFAULT_COMP_IRQ_NAME, eq_ix);
		mlx5_add_pci_to_irq_name(dev, dst_name, dst_name);
	} else {
		snprintf(dst_name, MLX5_MAX_IRQ_NAME, "%s-%d", name, eq_ix);
	}
unlock:
	spin_unlock(&table->lock);
}

static void free_comp_eqs(struct mlx5_core_dev *dev)
{
	struct mlx5_eq_table *table = &dev->priv.eq_table;
	struct mlx5_eq *eq, *n;

#ifdef CONFIG_RFS_ACCEL
	if (dev->rmap) {
		free_irq_cpu_rmap(dev->rmap);
		dev->rmap = NULL;
	}
#endif
	spin_lock(&table->lock);
	list_for_each_entry_safe(eq, n, &table->comp_eqs_list, list) {
		list_del(&eq->list);
		spin_unlock(&table->lock);
		if (mlx5_destroy_unmap_eq(dev, eq))
			mlx5_core_warn(dev, "failed to destroy EQ 0x%x\n",
				       eq->eqn);
		kfree(eq);
		spin_lock(&table->lock);
	}
	spin_unlock(&table->lock);
}

static int alloc_comp_eqs(struct mlx5_core_dev *dev)
{
	struct mlx5_eq_table *table = &dev->priv.eq_table;
	char name[MLX5_MAX_IRQ_NAME];
	struct mlx5_eq *eq;
	int ncomp_vec;
	int nent;
	int err;
	int i;

	INIT_LIST_HEAD(&table->comp_eqs_list);
	ncomp_vec = table->num_comp_vectors;
	nent = MLX5_COMP_EQ_SIZE;
#ifdef CONFIG_RFS_ACCEL
	dev->rmap = alloc_irq_cpu_rmap(ncomp_vec);
	if (!dev->rmap)
		return -ENOMEM;
#endif
	for (i = 0; i < ncomp_vec; i++) {
		eq = kzalloc(sizeof(*eq), GFP_KERNEL);
		if (!eq) {
			err = -ENOMEM;
			goto clean;
		}

		snprintf(name, MLX5_MAX_IRQ_NAME,
			 MLX5_DEFAULT_COMP_IRQ_NAME, i);
#ifdef CONFIG_RFS_ACCEL
		irq_cpu_rmap_add(dev->rmap,
				 dev->priv.msix_arr[i + MLX5_EQ_VEC_COMP_BASE].vector);
#endif
		err = mlx5_create_map_eq(dev, eq,
					 i + MLX5_EQ_VEC_COMP_BASE, nent, 0,
					 name, &dev->priv.uuari.uars[0]);
		if (err) {
			kfree(eq);
			goto clean;
		}
		mlx5_core_dbg(dev, "allocated completion EQN %d\n", eq->eqn);
		eq->index = i;
		spin_lock(&table->lock);
		list_add_tail(&eq->list, &table->comp_eqs_list);
		spin_unlock(&table->lock);
	}

	return 0;

clean:
	free_comp_eqs(dev);
	return err;
}

static void mlx5_add_device(struct mlx5_interface *intf, struct mlx5_priv *priv)
{
	struct mlx5_device_context *dev_ctx;
	struct mlx5_core_dev *dev = container_of(priv, struct mlx5_core_dev, priv);

	dev_ctx = kmalloc(sizeof(*dev_ctx), GFP_KERNEL);
	if (!dev_ctx) {
		pr_warn("mlx5_add_device: alloc context failed\n");
		return;
	}

	dev_ctx->intf    = intf;
	dev_ctx->context = intf->add(dev);

	if (dev_ctx->context) {
		spin_lock_irq(&priv->ctx_lock);
		list_add_tail(&dev_ctx->list, &priv->ctx_list);
		spin_unlock_irq(&priv->ctx_lock);
	} else {
		kfree(dev_ctx);
	}
}

static void mlx5_remove_device(struct mlx5_interface *intf, struct mlx5_priv *priv)
{
	struct mlx5_device_context *dev_ctx;
	struct mlx5_core_dev *dev = container_of(priv, struct mlx5_core_dev, priv);

	list_for_each_entry(dev_ctx, &priv->ctx_list, list)
		if (dev_ctx->intf == intf) {
			spin_lock_irq(&priv->ctx_lock);
			list_del(&dev_ctx->list);
			spin_unlock_irq(&priv->ctx_lock);

			intf->remove(dev, dev_ctx->context);
			kfree(dev_ctx);
			return;
		}
}
static int mlx5_register_device(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_interface *intf;

	mutex_lock(&intf_mutex);
	list_add_tail(&priv->dev_list, &dev_list);
	list_for_each_entry(intf, &intf_list, list)
		mlx5_add_device(intf, priv);
	mutex_unlock(&intf_mutex);

	return 0;
}
static void mlx5_unregister_device(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_interface *intf;

	mutex_lock(&intf_mutex);
	list_for_each_entry(intf, &intf_list, list)
		mlx5_remove_device(intf, priv);
	list_del(&priv->dev_list);
	mutex_unlock(&intf_mutex);
}

int mlx5_register_interface(struct mlx5_interface *intf)
{
	struct mlx5_priv *priv;

	if (!intf->add || !intf->remove)
		return -EINVAL;

	mutex_lock(&intf_mutex);
	list_add_tail(&intf->list, &intf_list);
	list_for_each_entry(priv, &dev_list, dev_list)
		mlx5_add_device(intf, priv);
	mutex_unlock(&intf_mutex);

	return 0;
}
EXPORT_SYMBOL(mlx5_register_interface);

void mlx5_unregister_interface(struct mlx5_interface *intf)
{
	struct mlx5_priv *priv;

	mutex_lock(&intf_mutex);
	list_for_each_entry(priv, &dev_list, dev_list)
	       mlx5_remove_device(intf, priv);
	list_del(&intf->list);
	mutex_unlock(&intf_mutex);
}
EXPORT_SYMBOL(mlx5_unregister_interface);

void *mlx5_get_protocol_dev(struct mlx5_core_dev *mdev, int protocol)
{
	struct mlx5_priv *priv = &mdev->priv;
	struct mlx5_device_context *dev_ctx;
	unsigned long flags;
	void *result = NULL;

	spin_lock_irqsave(&priv->ctx_lock, flags);

	list_for_each_entry(dev_ctx, &mdev->priv.ctx_list, list)
		if ((dev_ctx->intf->protocol == protocol) &&
		    dev_ctx->intf->get_dev) {
			result = dev_ctx->intf->get_dev(dev_ctx->context);
			break;
		}

	spin_unlock_irqrestore(&priv->ctx_lock, flags);

	return result;
}
EXPORT_SYMBOL(mlx5_get_protocol_dev);

static int mlx5_pci_init(struct mlx5_core_dev *dev, struct mlx5_priv *priv)
{
	struct pci_dev *pdev = dev->pdev;
	int err = 0;

	pci_set_drvdata(dev->pdev, dev);
	strncpy(priv->name, dev_name(&pdev->dev), MLX5_MAX_NAME_LEN);
	priv->name[MLX5_MAX_NAME_LEN - 1] = 0;

	mutex_init(&priv->pgdir_mutex);
	INIT_LIST_HEAD(&priv->pgdir_list);
	spin_lock_init(&priv->mkey_lock);

	mutex_init(&priv->alloc_mutex);

	priv->numa_node = dev_to_node(&dev->pdev->dev);

	priv->dbg_root = debugfs_create_dir(dev_name(&pdev->dev), mlx5_debugfs_root);
	if (!priv->dbg_root)
		return -ENOMEM;

	err = mlx5_pci_enable_device(dev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
		goto err_dbg;
	}

	err = request_bar(pdev);
	if (err) {
		dev_err(&pdev->dev, "error requesting BARs, aborting\n");
		goto err_disable;
	}

	pci_set_master(pdev);

	err = set_dma_caps(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed setting DMA capabilities mask, aborting\n");
		goto err_clr_master;
	}

	dev->iseg_base = pci_resource_start(dev->pdev, 0);
	dev->iseg = ioremap(dev->iseg_base, sizeof(*dev->iseg));
	if (!dev->iseg) {
		err = -ENOMEM;
		dev_err(&pdev->dev, "Failed mapping initialization segment, aborting\n");
		goto err_clr_master;
	}

	return 0;

err_clr_master:
	pci_clear_master(dev->pdev);
	release_bar(dev->pdev);
err_disable:
	mlx5_pci_disable_device(dev);

err_dbg:
	debugfs_remove(priv->dbg_root);
	return err;
}

static void mlx5_pci_close(struct mlx5_core_dev *dev, struct mlx5_priv *priv)
{
	iounmap(dev->iseg);
	pci_clear_master(dev->pdev);
	release_bar(dev->pdev);
	mlx5_pci_disable_device(dev);
	debugfs_remove(priv->dbg_root);
}

/* The driver version format does not follow PRM but it is consistent
 * with mlx4 code
 */
static void mlx5_set_driver_version(struct mlx5_core_dev *dev)
{
	u8 set_in[MLX5_ST_SZ_BYTES(set_driver_version_in)];
	u8 set_out[MLX5_ST_SZ_BYTES(set_driver_version_out)];
	char *origin;
	int remaining_size = DRIVER_VERSION_SZ;

	if (!MLX5_CAP_GEN(dev, driver_version))
		return;

	memset(set_in, 0, sizeof(set_in));
	memset(set_out, 0, sizeof(set_out));

	origin = MLX5_ADDR_OF(set_driver_version_in,
			      set_in,
			      driver_version);

	strncpy(origin, OS_NAME_FOR_FW, remaining_size);

	remaining_size = max_t(int, 0, DRIVER_VERSION_SZ - strlen(origin));
	strncat(origin, ",", remaining_size);

	remaining_size = max_t(int, 0, DRIVER_VERSION_SZ - strlen(origin));
	strncat(origin, DRIVER_NAME, remaining_size);

	remaining_size = max_t(int, 0, DRIVER_VERSION_SZ - strlen(origin));
	strncat(origin, ",", remaining_size);

	remaining_size = max_t(int, 0, DRIVER_VERSION_SZ - strlen(origin));
	strncat(origin, DRIVER_VERSION, remaining_size);

	/*Send the command*/
	MLX5_SET(set_driver_version_in,
		 set_in,
		 opcode,
		 MLX5_CMD_OP_SET_DRIVER_VERSION);

	if (mlx5_cmd_exec(dev,
			  set_in,
			  sizeof(set_in),
			  set_out,
			  sizeof(set_out)))
		mlx5_core_warn(dev, "failed to set driver version.\n");
}

/* TODO: Calling to io_mapping_create_wc spoils the IB user BF mapping as WC
 *       Fix this before enabling this function.
static int map_bf_area(struct mlx5_core_dev *dev)
{
	resource_size_t bf_start = pci_resource_start(dev->pdev, 0);
	resource_size_t bf_len = pci_resource_len(dev->pdev, 0);

	dev->priv.bf_mapping = io_mapping_create_wc(bf_start, bf_len);

	return dev->priv.bf_mapping ? 0 : -ENOMEM;
}
*/

static void unmap_bf_area(struct mlx5_core_dev *dev)
{
	if (dev->priv.bf_mapping)
		io_mapping_free(dev->priv.bf_mapping);
}

static void enable_vfs(struct pci_dev *pdev)
{
	struct mlx5_core_dev *dev  = pci_get_drvdata(pdev);
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	int err;
	int vf;
	int num_vf;

	if (!sriov->vfs_ctx)
		mlx5_core_warn(dev, "need to enable VFs but have no context. enabled_vfs %d\n",
			       sriov->enabled_vfs);

	num_vf = sriov->enabled_vfs;
	for (vf = 1; vf <= num_vf; vf++) {
		if (!sriov->vfs_ctx[vf - 1].enabled) {
			err = mlx5_core_enable_hca(dev, vf);
			if (err) {
				mlx5_core_warn(dev, "failed to enable VF %d\n", vf - 1);
			} else {
				pr_info("enable vf %d success\n", vf - 1);
				sriov->vfs_ctx[vf - 1].enabled = 1;
			}
		}
	}
}

static int update_pf_policy(struct mlx5_core_dev *dev)
{
	struct mlx5_hca_vport_context *in;
	int port;
	int err;

	if (!mlx5_core_is_pf(dev))
		return 0;

	if (MLX5_CAP_GEN(dev, port_type) != MLX5_CAP_PORT_TYPE_IB)
		return 0;

	if (!MLX5_CAP_GEN(dev, ib_virt))
		return 0;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select = MLX5_HCA_VPORT_SEL_STATE_POLICY;
	in->policy = MLX5_POLICY_FOLLOW;
	for (port = 1; port <= MLX5_CAP_GEN(dev, num_ports); port++) {
		err = mlx5_core_modify_hca_vport_context(dev, 0, port, 0, in);
		if (err) {
			mlx5_core_warn(dev, "failed to update port %d policy\n", port);
			break;
		}
	}
	kfree(in);

	return err;
}

#define MLX5_IB_MOD "mlx5_ib"
static int mlx5_load_one(struct mlx5_core_dev *dev, struct mlx5_priv *priv)
{
	struct pci_dev *pdev = dev->pdev;
	int err;

	mutex_lock(&dev->intf_state_mutex);
	if (test_bit(MLX5_INTERFACE_STATE_UP, &dev->intf_state)) {
		dev_warn(&dev->pdev->dev, "%s: interface is up, NOP\n",
			 __func__);
		goto out;
	}

	dev_info(&pdev->dev, "firmware version: %d.%d.%d\n", fw_rev_maj(dev),
		 fw_rev_min(dev), fw_rev_sub(dev));

	/* on load removing any previous indication of internal error, device is
	 * up
	 */
	dev->state = MLX5_DEVICE_STATE_UP;

	err = mlx5_cmd_init(dev);
	if (err) {
		dev_err(&pdev->dev, "Failed initializing command interface, aborting\n");
		goto out_err;
	}

	if (!mlx5_core_is_pf(dev)) {
		struct pci_dev *phys_pdev = mlx5_pci_phys_fn(pdev);

		if (phys_pdev != pdev)
			enable_vfs(phys_pdev);
	}

	err = wait_fw_init(dev, FW_INIT_TIMEOUT_MILI);
	if (err) {
		dev_err(&dev->pdev->dev, "Firmware over %d MS in initializing state, aborting\n",
			FW_INIT_TIMEOUT_MILI);
		goto cmd_cleanup;
	}

	mlx5_pagealloc_init(dev);

	err = mlx5_core_enable_hca(dev, 0);
	if (err) {
		dev_err(&pdev->dev, "enable hca failed\n");
		goto err_pagealloc_cleanup;
	}

	mlx5_start_health_poll(dev);
	err = mlx5_core_set_issi(dev);
	if (err) {
		dev_err(&pdev->dev, "failed to set issi\n");
		goto err_disable_hca;
	}

	err = mlx5_satisfy_startup_pages(dev, 1);
	if (err) {
		dev_err(&pdev->dev, "failed to allocate boot pages\n");
		goto err_disable_hca;
	}

	err = mlx5_update_guids(dev);
	if (err)
		dev_err(&pdev->dev, "failed to update guids. continue with default...\n");

	err = set_hca_ctrl(dev);
	if (err) {
		dev_err(&pdev->dev, "set_hca_ctrl failed\n");
		goto reclaim_boot_pages;
	}

	err = handle_hca_cap(dev);
	if (err) {
		dev_err(&pdev->dev, "handle_hca_cap failed\n");
		goto reclaim_boot_pages;
	}

	err = handle_hca_cap_atomic(dev);
	if (err) {
		dev_err(&pdev->dev, "handle_hca_cap_atomic failed\n");
		goto reclaim_boot_pages;
	}

	err = mlx5_satisfy_startup_pages(dev, 0);
	if (err) {
		dev_err(&pdev->dev, "failed to allocate init pages\n");
		goto reclaim_boot_pages;
	}

	err = mlx5_pagealloc_start(dev);
	if (err) {
		dev_err(&pdev->dev, "mlx5_pagealloc_start failed\n");
		goto reclaim_boot_pages;
	}

	err = mlx5_cmd_init_hca(dev);
	if (err) {
		dev_err(&pdev->dev, "init hca failed\n");
		goto err_pagealloc_stop;
	}

	mlx5_set_driver_version(dev);

	err = mlx5_query_hca_caps(dev);
	if (err) {
		dev_err(&pdev->dev, "query hca failed\n");
		goto err_teardown;
	}

	err = update_pf_policy(dev);
	if (err) {
		dev_err(&pdev->dev, "failed to update PF policy to Follow\n");
		goto err_teardown;
	}

	err = mlx5_query_board_id(dev);
	if (err) {
		dev_err(&pdev->dev, "query board id failed\n");
		goto err_teardown;
	}

	err = mlx5_enable_msix(dev);
	if (err) {
		dev_err(&pdev->dev, "enable msix failed\n");
		goto err_teardown;
	}

	err = mlx5_eq_init(dev);
	if (err) {
		dev_err(&pdev->dev, "failed to initialize eq\n");
		goto disable_msix;
	}

	err = mlx5_alloc_uuars(dev, &priv->uuari);
	if (err) {
		dev_err(&pdev->dev, "Failed allocating uar, aborting\n");
		goto err_eq_cleanup;
	}

	err = mlx5_start_eqs(dev);
	if (err) {
		dev_err(&pdev->dev, "Failed to start pages and async EQs\n");
		goto err_free_uar;
	}

	err = alloc_comp_eqs(dev);
	if (err) {
		dev_err(&pdev->dev, "Failed to alloc completion EQs\n");
		goto err_stop_eqs;
	}

	/*
	 * if (map_bf_area(dev))
	 *	dev_err(&pdev->dev, "Failed to map blue flame area\n");
	 * TODO: Open this mapping when map_bf_area is fixed
	 */

	mlx5_irq_set_affinity_hints(dev);
	MLX5_INIT_DOORBELL_LOCK(&priv->cq_uar_lock);

	mlx5_init_cq_table(dev);
	mlx5_init_qp_table(dev);
	mlx5_init_srq_table(dev);
	mlx5_init_mr_table(dev);
	mlx5_init_dct_table(dev);

	err = mlx5_init_fs(dev);
	if (err) {
		mlx5_core_err(dev, "flow steering init %d\n", err);
		goto err_reg_dev;
	}

	err = mlx5_init_rl_table(dev);
	if (err) {
		dev_err(&pdev->dev, "Failed to init rate limiting\n");
		goto err_fs;
	}

	err = mlx5_eswitch_init(dev);
	if (err) {
		dev_err(&pdev->dev, "eswitch init failed %d\n", err);
		goto err_rl;
	}

	err = mlx5_sriov_init(dev);
	if (err) {
		dev_err(&pdev->dev, "sriov init failed %d\n", err);
		goto err_eswitch;
	}

	err = mlx5_register_device(dev);
	if (err) {
		dev_err(&pdev->dev, "mlx5_register_device failed %d\n", err);
		goto err_sriov;
	}

	err = request_module_nowait(MLX5_IB_MOD);
	if (err)
		pr_info("failed request module on %s\n", MLX5_IB_MOD);

	clear_bit(MLX5_INTERFACE_STATE_DOWN, &dev->intf_state);
	set_bit(MLX5_INTERFACE_STATE_UP, &dev->intf_state);
out:
	mutex_unlock(&dev->intf_state_mutex);

	return 0;

err_sriov:
	if (mlx5_sriov_cleanup(dev))
		dev_err(&dev->pdev->dev, "sriov cleanup failed\n");
err_eswitch:
	mlx5_eswitch_cleanup(dev->priv.eswitch);
err_rl:
	mlx5_cleanup_rl_table(dev);
err_fs:
	mlx5_cleanup_fs(dev);
err_reg_dev:
	mlx5_cleanup_dct_table(dev);
	mlx5_cleanup_mr_table(dev);
	mlx5_cleanup_srq_table(dev);
	mlx5_cleanup_qp_table(dev);
	mlx5_cleanup_cq_table(dev);
	mlx5_irq_clear_affinity_hints(dev);
	free_comp_eqs(dev);

err_stop_eqs:
	mlx5_stop_eqs(dev);

err_free_uar:
	mlx5_free_uuars(dev, &priv->uuari);

err_eq_cleanup:
	mlx5_eq_cleanup(dev);

disable_msix:
	mlx5_disable_msix(dev);

err_teardown:
	if (mlx5_cmd_teardown_hca(dev)) {
		dev_err(&dev->pdev->dev, "tear_down_hca failed, skip cleanup\n");
		return err;
	}

err_pagealloc_stop:
	mlx5_pagealloc_stop(dev);

reclaim_boot_pages:
	mlx5_reclaim_startup_pages(dev);

err_disable_hca:
	mlx5_stop_health_poll(dev);
	mlx5_core_disable_hca(dev, 0);

err_pagealloc_cleanup:
	mlx5_pagealloc_cleanup(dev);
cmd_cleanup:
	mlx5_cmd_cleanup(dev);

out_err:
	dev->state = MLX5_DEVICE_STATE_INTERNAL_ERROR;
	mutex_unlock(&dev->intf_state_mutex);

	return err;
}

static int mlx5_unload_one(struct mlx5_core_dev *dev, struct mlx5_priv *priv)
{
	int err = 0;

	err = mlx5_sriov_cleanup(dev);
	if (err) {
		dev_warn(&dev->pdev->dev, "%s: sriov cleanup failed - abort\n",
			 __func__);
		return err;
	}
	mutex_lock(&dev->intf_state_mutex);
	if (test_bit(MLX5_INTERFACE_STATE_DOWN, &dev->intf_state)) {
		dev_warn(&dev->pdev->dev, "%s: interface is down, NOP\n",
			 __func__);
		goto out;
	}

	mlx5_unregister_device(dev);

	mlx5_eswitch_cleanup(dev->priv.eswitch);
	mlx5_cleanup_rl_table(dev);
	mlx5_cleanup_fs(dev);
	mlx5_cleanup_dct_table(dev);
	mlx5_cleanup_mr_table(dev);
	mlx5_cleanup_srq_table(dev);
	mlx5_cleanup_qp_table(dev);
	mlx5_cleanup_cq_table(dev);
	mlx5_irq_clear_affinity_hints(dev);
	unmap_bf_area(dev);
	free_comp_eqs(dev);
	mlx5_stop_eqs(dev);
	mlx5_free_uuars(dev, &priv->uuari);
	mlx5_eq_cleanup(dev);
	mlx5_disable_msix(dev);
	err = mlx5_cmd_teardown_hca(dev);
	if (err) {
		dev_err(&dev->pdev->dev, "tear_down_hca failed, skip cleanup\n");
		goto out;
	}
	mlx5_pagealloc_stop(dev);
	mlx5_reclaim_startup_pages(dev);
	mlx5_core_disable_hca(dev, 0);
	mlx5_stop_health_poll(dev);
	mlx5_pagealloc_cleanup(dev);
	mlx5_cmd_cleanup(dev);

out:
	clear_bit(MLX5_INTERFACE_STATE_UP, &dev->intf_state);
	set_bit(MLX5_INTERFACE_STATE_DOWN, &dev->intf_state);
	mutex_unlock(&dev->intf_state_mutex);
	return err;
}

void mlx5_core_event(struct mlx5_core_dev *dev, enum mlx5_dev_event event,
			    unsigned long param)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_device_context *dev_ctx;
	unsigned long flags;

	spin_lock_irqsave(&priv->ctx_lock, flags);

	list_for_each_entry(dev_ctx, &priv->ctx_list, list)
		if (dev_ctx->intf->event)
			dev_ctx->intf->event(dev, dev_ctx->context, event, param);

	spin_unlock_irqrestore(&priv->ctx_lock, flags);
}

struct mlx5_core_event_handler {
	void (*event)(struct mlx5_core_dev *dev,
		      enum mlx5_dev_event event,
		      void *data);
};

static int init_one(struct pci_dev *pdev,
		    const struct pci_device_id *id)
{
	struct mlx5_core_dev *dev;
	struct mlx5_priv *priv;
	int err;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		dev_err(&pdev->dev, "kzalloc failed\n");
		return -ENOMEM;
	}
	priv = &dev->priv;
	priv->pci_dev_data = id->driver_data;

	pci_set_drvdata(pdev, dev);

	if (prof_sel < 0 || prof_sel >= ARRAY_SIZE(profile)) {
		pr_warn("selected profile out of range, selecting default (%d)\n",
			MLX5_DEFAULT_PROF);
		prof_sel = MLX5_DEFAULT_PROF;
	}
	dev->profile = &profile[prof_sel];
	dev->pdev = pdev;
	dev->event = mlx5_core_event;

	INIT_LIST_HEAD(&priv->ctx_list);
	spin_lock_init(&priv->ctx_lock);
	mutex_init(&dev->pci_status_mutex);
	mutex_init(&dev->intf_state_mutex);
	err = mlx5_pci_init(dev, priv);
	if (err) {
		dev_err(&pdev->dev, "mlx5_pci_init failed with error code %d\n", err);
		goto clean_dev;
	}

	err = mlx5_health_init(dev);
	if (err) {
		dev_err(&pdev->dev, "mlx5_health_init failed with error code %d\n", err);
		goto close_pci;
	}
	err = mlx5_load_one(dev, priv);
	if (err) {
		dev_err(&pdev->dev, "mlx5_load_one failed with error code %d\n", err);
		goto clean_health;
	}

	pci_save_state(pdev);

	return 0;

clean_health:
	mlx5_health_cleanup(dev);
close_pci:
	mlx5_pci_close(dev, priv);
clean_dev:
	pci_set_drvdata(pdev, NULL);
	kfree(dev);

	return err;
}

static void remove_one(struct pci_dev *pdev)
{
	struct mlx5_core_dev *dev  = pci_get_drvdata(pdev);
	struct mlx5_priv *priv = &dev->priv;

	if (mlx5_unload_one(dev, priv)) {
		dev_err(&dev->pdev->dev, "mlx5_unload_one failed\n");
		mlx5_health_cleanup(dev);
		return;
	}
	mlx5_health_cleanup(dev);
	mlx5_pci_close(dev, priv);
	pci_set_drvdata(pdev, NULL);
	kfree(dev);
}

#ifdef CONFIG_PM
static int suspend(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct mlx5_core_dev *dev = pci_get_drvdata(pdev);
	struct mlx5_priv *priv = &dev->priv;
	int err;

	dev_info(&pdev->dev, "suspend was called\n");

	err = mlx5_unload_one(dev, priv);
	if (err) {
		dev_err(&pdev->dev, "mlx5_unload_one failed with error code: %d\n", err);
		return err;
	}

	err = pci_save_state(pdev);
	if (err) {
		dev_err(&pdev->dev, "pci_save_state failed with error code: %d\n", err);
		return err;
	}

	err = pci_enable_wake(pdev, PCI_D3hot, 0);
	if (err) {
		dev_err(&pdev->dev, "pci_enable_wake failed with error code: %d\n", err);
		return err;
	}

	mlx5_pci_disable_device(dev);
	err = pci_set_power_state(pdev, PCI_D3hot);
	if (err) {
		dev_warn(&pdev->dev, "pci_set_power_state failed with error code: %d\n", err);
		return err;
	}

	return 0;
}

static int resume(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct mlx5_core_dev *dev = pci_get_drvdata(pdev);
	struct mlx5_priv *priv = &dev->priv;
	int err;

	dev_info(&pdev->dev, "resume was called\n");

	err = pci_set_power_state(pdev, PCI_D0);
	if (err) {
		dev_warn(&pdev->dev, "pci_set_power_state failed with error code: %d\n", err);
		return err;
	}

	pci_restore_state(pdev);
	err = pci_save_state(pdev);
	if (err) {
		dev_err(&pdev->dev, "pci_save_state failed with error code: %d\n", err);
		return err;
	}
	err = mlx5_pci_enable_device(dev);
	if (err) {
		dev_err(&pdev->dev, "mlx5_pci_enabel_device failed with error code: %d\n", err);
		return err;
	}
	pci_set_master(pdev);

	err = mlx5_load_one(dev, priv);
	if (err) {
		dev_err(&pdev->dev, "mlx5_load_one failed with error code: %d\n", err);
		return err;
	}

	return 0;
}

static const struct dev_pm_ops mlnx_pm = {
	.suspend = suspend,
	.resume = resume,
};
#endif	/* CONFIG_PM */

static pci_ers_result_t mlx5_pci_err_detected(struct pci_dev *pdev,
					      pci_channel_state_t state)
{
	struct mlx5_core_dev *dev = pci_get_drvdata(pdev);
	struct mlx5_priv *priv = &dev->priv;

	dev_info(&pdev->dev, "%s was called\n", __func__);
	mlx5_enter_error_state(dev);
	mlx5_unload_one(dev, priv);
	mlx5_pci_disable_device(dev);
	return state == pci_channel_io_perm_failure ?
		PCI_ERS_RESULT_DISCONNECT : PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t mlx5_pci_slot_reset(struct pci_dev *pdev)
{
	struct mlx5_core_dev *dev = pci_get_drvdata(pdev);
	int err = 0;

	dev_info(&pdev->dev, "%s was called\n", __func__);

	err = mlx5_pci_enable_device(dev);
	if (err) {
		dev_err(&pdev->dev, "%s: mlx5_pci_enable_device failed with error code: %d\n"
			, __func__, err);
		return PCI_ERS_RESULT_DISCONNECT;
	}
	pci_set_master(pdev);
	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);

	return err ? PCI_ERS_RESULT_DISCONNECT : PCI_ERS_RESULT_RECOVERED;
}

void mlx5_disable_device(struct mlx5_core_dev *dev)
{
	mlx5_pci_err_detected(dev->pdev, 0);
}

/* wait for the device to show vital signs. For now we check
 * that we can read the device ID and that the health buffer
 * shows a non zero value which is different than 0xffffffff
 */
static void wait_vital(struct pci_dev *pdev)
{
	struct mlx5_core_dev *dev = pci_get_drvdata(pdev);
	struct mlx5_core_health *health = &dev->priv.health;
	const int niter = 300;
	u32 last_count = 0;
	u32 count;
	int i;

	for (i = 0; i < niter; i++) {
		count = ioread32be(health->health_counter);
		if (count && count != 0xffffffff) {
			if (last_count && last_count != count) {
				dev_info(&pdev->dev, "Counter value 0x%x after %d iterations\n", count, i);
				break;
			}
			last_count = count;
		}
		msleep(50);
	}

	if (i == niter)
		dev_warn(&pdev->dev, "%s-%d: health counter isn't counting.\n", __func__, __LINE__);
}

static void mlx5_pci_resume(struct pci_dev *pdev)
{
	struct mlx5_core_dev *dev = pci_get_drvdata(pdev);
	struct mlx5_priv *priv = &dev->priv;
	int err;

	dev_info(&pdev->dev, "%s was called\n", __func__);

	pci_save_state(pdev);

	wait_vital(pdev);

	err = mlx5_load_one(dev, priv);
	if (err)
		dev_err(&pdev->dev, "%s: mlx5_load_one failed with error code: %d\n"
			, __func__, err);
	else
		dev_info(&pdev->dev, "%s: device recovered\n", __func__);
}

#ifdef CONFIG_COMPAT_IS_CONST_PCI_ERROR_HANDLERS
static const struct pci_error_handlers mlx5_err_handler = {
#else
static struct pci_error_handlers mlx5_err_handler = {
#endif
	.error_detected = mlx5_pci_err_detected,
	.slot_reset	= mlx5_pci_slot_reset,
	.resume		= mlx5_pci_resume
};

static void shutdown(struct pci_dev *pdev)
{
	struct mlx5_core_dev  *dev  = pci_get_drvdata(pdev);
	struct mlx5_priv *priv = &dev->priv;

	dev_info(&pdev->dev, "shutdown was called\n");
	/* Notify mlx5 clients that the kernel is being shut down */
	set_bit(MLX5_INTERFACE_STATE_SHUTDOWN, &dev->intf_state);
	mlx5_unload_one(dev, priv);
	mlx5_pci_disable_device(dev);
}

static const struct pci_device_id mlx5_core_pci_table[] = {
	{ PCI_VDEVICE(MELLANOX, 0x1011) }, /* Connect-IB */
	{ PCI_VDEVICE(MELLANOX, 0x1012), MLX5_PCI_DEV_IS_VF}, /* Connect-IB VF */
	{ PCI_VDEVICE(MELLANOX, 0x1013) }, /* ConnectX-4 */
	{ PCI_VDEVICE(MELLANOX, 0x1014), MLX5_PCI_DEV_IS_VF}, /* ConnectX-4 VF */
	{ PCI_VDEVICE(MELLANOX, 0x1015) }, /* ConnectX-4LX */
	{ PCI_VDEVICE(MELLANOX, 0x1016), MLX5_PCI_DEV_IS_VF}, /* ConnectX-4LX VF */
	{ PCI_VDEVICE(MELLANOX, 0x1017) },
	{ PCI_VDEVICE(MELLANOX, 0x1018), MLX5_PCI_DEV_IS_VF}, /* ConnectX-5 VF */
	{ PCI_VDEVICE(MELLANOX, 0x1019) },
	{ PCI_VDEVICE(MELLANOX, 0x101a) },
	{ PCI_VDEVICE(MELLANOX, 0x101c) },
	{ PCI_VDEVICE(MELLANOX, 0x101b) },
	{ PCI_VDEVICE(MELLANOX, 0x101d) },
	{ PCI_VDEVICE(MELLANOX, 0x101e) },
	{ PCI_VDEVICE(MELLANOX, 0x101f) },
	{ PCI_VDEVICE(MELLANOX, 0x1020) },
	{ PCI_VDEVICE(MELLANOX, 0x1021) },
	{ PCI_VDEVICE(MELLANOX, 0x1022) },
	{ PCI_VDEVICE(MELLANOX, 0x1023) },
	{ PCI_VDEVICE(MELLANOX, 0x1024) },
	{ PCI_VDEVICE(MELLANOX, 0x1025) },
	{ PCI_VDEVICE(MELLANOX, 0x1026) },
	{ PCI_VDEVICE(MELLANOX, 0x1027) },
	{ PCI_VDEVICE(MELLANOX, 0x1028) },
	{ PCI_VDEVICE(MELLANOX, 0x1029) },
	{ PCI_VDEVICE(MELLANOX, 0x102a) },
	{ PCI_VDEVICE(MELLANOX, 0x102b) },
	{ PCI_VDEVICE(MELLANOX, 0x102c) },
	{ PCI_VDEVICE(MELLANOX, 0x102d) },
	{ PCI_VDEVICE(MELLANOX, 0x102e) },
	{ PCI_VDEVICE(MELLANOX, 0x102f) },
	{ PCI_VDEVICE(MELLANOX, 0x1030) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, mlx5_core_pci_table);

static struct pci_driver mlx5_core_driver = {
	.name           = DRIVER_NAME,
	.id_table       = mlx5_core_pci_table,
#ifdef CONFIG_PM
	.driver = {
		.pm	= &mlnx_pm,
	},
#endif /* CONFIG_PM */
	.probe			= init_one,
	.remove			= remove_one,
	.shutdown		= shutdown,
	.err_handler		= &mlx5_err_handler,
#ifdef HAVE_PCI_DRIVER_SRIOV_CONFIGURE
	.sriov_configure	= mlx5_core_sriov_configure,
#endif
};

static int __init init(void)
{
	int err;

	mlx5_register_debugfs();
	err = pci_register_driver(&mlx5_core_driver);
	if (err)
		goto err_debug;

	mlx5e_init();

	return 0;

err_debug:
	mlx5_unregister_debugfs();
	return err;
}

static void __exit cleanup(void)
{
	mlx5e_cleanup();
	pci_unregister_driver(&mlx5_core_driver);
	mlx5_unregister_debugfs();
}

module_init(init);
module_exit(cleanup);
