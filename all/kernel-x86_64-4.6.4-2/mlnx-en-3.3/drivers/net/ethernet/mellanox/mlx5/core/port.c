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

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/cmd.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/mlx5_ifc.h>
#include "mlx5_core.h"

static int is_valid_vf(struct mlx5_core_dev *dev, int vf)
{
	struct pci_dev *pdev = dev->pdev;

	if (vf == 1)
		return 1;

	if (mlx5_core_is_pf(dev))
		return (vf <= pci_num_vf(pdev)) && (vf >= 1);

	return 0;
}

int mlx5_core_access_reg(struct mlx5_core_dev *dev, void *data_in,
			 int size_in, void *data_out, int size_out,
			 u16 reg_num, int arg, int write)
{
	struct mlx5_access_reg_mbox_in *in = NULL;
	struct mlx5_access_reg_mbox_out *out = NULL;
	int err = -ENOMEM;

	in = mlx5_vzalloc(sizeof(*in) + size_in);
	if (!in)
		goto ex;

	out = mlx5_vzalloc(sizeof(*out) + size_out);
	if (!out)
		goto ex;

	memcpy(in->data, data_in, size_in);
	in->hdr.opcode = cpu_to_be16(MLX5_CMD_OP_ACCESS_REG);
	in->hdr.opmod = cpu_to_be16(!write);
	in->arg = cpu_to_be32(arg);
	in->register_id = cpu_to_be16(reg_num);
	err = mlx5_cmd_exec(dev, in, sizeof(*in) + size_in, out,
			    sizeof(*out) + size_out);
	if (err)
		goto ex;

	err = mlx5_cmd_status_to_err(&out->hdr);
	if (!err)
		memcpy(data_out, out->data, size_out);

ex:
	kvfree(out);
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_reg);


struct mlx5_reg_pcap {
	u8			rsvd0;
	u8			port_num;
	u8			rsvd1[2];
	__be32			caps_127_96;
	__be32			caps_95_64;
	__be32			caps_63_32;
	__be32			caps_31_0;
};

static int set_port_caps_pf(struct mlx5_core_dev *dev, u8 port_num,
			    u32 set, u32 clear, u32 cur)
{
	struct mlx5_reg_pcap in;
	struct mlx5_reg_pcap out;
	u32 tmp;
	int err;

	tmp = (cur | set) & ~clear;

	memset(&in, 0, sizeof(in));
	in.caps_127_96 = cpu_to_be32(tmp);
	in.port_num = port_num;

	err = mlx5_core_access_reg(dev, &in, sizeof(in), &out,
				   sizeof(out), MLX5_REG_PCAP, 0, 1);

	return err;
}

static int set_port_caps_vf(struct mlx5_core_dev *dev, u8 port_num,
			    u32 set, u32 clear)
{
	struct mlx5_hca_vport_context *req;
	int err;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->cap_mask1 = set | ~clear;
	req->cap_mask1_perm = set | clear;
	err = mlx5_core_modify_hca_vport_context(dev, 0, port_num,
						 0, req);

	kfree(req);
	return err;
}

int mlx5_set_port_caps(struct mlx5_core_dev *dev, u8 port_num,
		       u32 set, u32 clear, u32 cur)
{
	if (unlikely(!MLX5_CAP_GEN(dev, ib_virt)))
		if (mlx5_core_is_pf(dev))
			return set_port_caps_pf(dev, port_num, set, clear, cur);
	return set_port_caps_vf(dev, port_num, set, clear);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_caps);

int mlx5_query_port_ptys(struct mlx5_core_dev *dev, u32 *ptys,
			 int ptys_size, int proto_mask)
{
	u32 in[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	memset(in, 0, sizeof(in));
	MLX5_SET(ptys_reg, in, local_port, 1);
	MLX5_SET(ptys_reg, in, proto_mask, proto_mask);

	err = mlx5_core_access_reg(dev, in, sizeof(in), ptys,
				   ptys_size, MLX5_REG_PTYS, 0, 0);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_ptys);

int mlx5_set_port_beacon(struct mlx5_core_dev *dev, u32 *mlcr,
			 int mlcr_size, u16 beacon_duration)
{
	u32 in[MLX5_ST_SZ_DW(mlcr_reg)];
	int err;

	memset(in, 0, sizeof(in));
	MLX5_SET(mlcr_reg, in, local_port, 1);
	MLX5_SET(mlcr_reg, in, beacon_duration, beacon_duration);

	err = mlx5_core_access_reg(dev, in, sizeof(in), mlcr,
				   mlcr_size, MLX5_REG_MLCR, 0, 1);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_set_port_beacon);

int mlx5_query_port_proto_cap(struct mlx5_core_dev *dev,
			      u32 *proto_cap, int proto_mask)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), proto_mask);
	if (err)
		return err;

	if (proto_mask == MLX5_PTYS_EN)
		*proto_cap = MLX5_GET(ptys_reg, out, eth_proto_capability);
	else
		*proto_cap = MLX5_GET(ptys_reg, out, ib_proto_capability);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_proto_cap);

int mlx5_core_access_ptys(struct mlx5_core_dev *dev, struct mlx5_ptys_reg *ptys, int write)
{
	int sz = MLX5_ST_SZ_BYTES(ptys_reg);
	void *out = NULL;
	void *in = NULL;
	int err;

	in = kzalloc(sz, GFP_KERNEL);
	out = kzalloc(sz, GFP_KERNEL);
	if (!in || !out)
		return -ENOMEM;

	MLX5_SET(ptys_reg, in, local_port, ptys->local_port);
	MLX5_SET(ptys_reg, in, proto_mask, ptys->proto_mask);
	if (write) {
		MLX5_SET(ptys_reg, in, eth_proto_capability, ptys->eth_proto_cap);
		MLX5_SET(ptys_reg, in, ib_link_width_capability, ptys->ib_link_width_cap);
		MLX5_SET(ptys_reg, in, ib_proto_capability, ptys->ib_proto_cap);
		MLX5_SET(ptys_reg, in, eth_proto_admin, ptys->eth_proto_admin);
		MLX5_SET(ptys_reg, in, ib_link_width_admin, ptys->ib_link_width_admin);
		MLX5_SET(ptys_reg, in, ib_proto_admin, ptys->ib_proto_admin);
		MLX5_SET(ptys_reg, in, eth_proto_oper, ptys->eth_proto_oper);
		MLX5_SET(ptys_reg, in, ib_link_width_oper, ptys->ib_link_width_oper);
		MLX5_SET(ptys_reg, in, ib_proto_oper, ptys->ib_proto_oper);
		MLX5_SET(ptys_reg, in, eth_proto_lp_advertise, ptys->eth_proto_lp_advertise);
	}

	err = mlx5_core_access_reg(dev, in, sz, out, sz, MLX5_REG_PTYS, 0, !!write);
	if (err)
		goto out;

	if (!write) {
		ptys->local_port = MLX5_GET(ptys_reg, out, local_port);
		ptys->proto_mask = MLX5_GET(ptys_reg, out, proto_mask);
		ptys->eth_proto_cap = MLX5_GET(ptys_reg, out, eth_proto_capability);
		ptys->ib_link_width_cap = MLX5_GET(ptys_reg, out, ib_link_width_capability);
		ptys->ib_proto_cap = MLX5_GET(ptys_reg, out, ib_proto_capability);
		ptys->eth_proto_admin = MLX5_GET(ptys_reg, out, eth_proto_admin);
		ptys->ib_link_width_admin = MLX5_GET(ptys_reg, out, ib_link_width_admin);
		ptys->ib_proto_admin = MLX5_GET(ptys_reg, out, ib_proto_admin);
		ptys->eth_proto_oper = MLX5_GET(ptys_reg, out, eth_proto_oper);
		ptys->ib_link_width_oper = MLX5_GET(ptys_reg, out, ib_link_width_oper);
		ptys->ib_proto_oper = MLX5_GET(ptys_reg, out, ib_proto_oper);
		ptys->eth_proto_lp_advertise = MLX5_GET(ptys_reg, out, eth_proto_lp_advertise);
	}

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_ptys);

int mlx5_core_access_pvlc(struct mlx5_core_dev *dev, struct mlx5_pvlc_reg *pvlc, int write)
{
	int sz = MLX5_ST_SZ_BYTES(pvlc_reg);
	u8 in[MLX5_ST_SZ_BYTES(pvlc_reg)];
	u8 out[MLX5_ST_SZ_BYTES(pvlc_reg)];
	int err;

	memset(out, 0, sizeof(out));
	memset(in, 0, sizeof(in));

	MLX5_SET(pvlc_reg, in, local_port, pvlc->local_port);
	if (write)
		MLX5_SET(pvlc_reg, in, vl_admin, pvlc->vl_admin);

	err = mlx5_core_access_reg(dev, in, sz, out, sz, MLX5_REG_PVLC, 0, !!write);
	if (err)
		return err;

	if (!write) {
		pvlc->local_port = MLX5_GET(pvlc_reg, out, local_port);
		pvlc->vl_hw_cap = MLX5_GET(pvlc_reg, out, vl_hw_cap);
		pvlc->vl_admin = MLX5_GET(pvlc_reg, out, vl_admin);
		pvlc->vl_operational = MLX5_GET(pvlc_reg, out, vl_operational);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_pvlc);

static int mtu_to_ib_mtu(int mtu)
{
	switch (mtu) {
	case 256: return 1;
	case 512: return 2;
	case 1024: return 3;
	case 2048: return 4;
	case 4096: return 5;
	default:
		pr_warn("invalid mtu\n");
		return -1;
	}
}

int mlx5_core_access_pmtu(struct mlx5_core_dev *dev, struct mlx5_pmtu_reg *pmtu, int write)
{
	int sz = MLX5_ST_SZ_BYTES(pmtu_reg);
	void *out = NULL;
	void *in = NULL;
	int err;

	in = kzalloc(sz, GFP_KERNEL);
	out = kzalloc(sz, GFP_KERNEL);
	if (!in || !out)
		return -ENOMEM;

	MLX5_SET(pmtu_reg, in, local_port, pmtu->local_port);
	if (write)
		MLX5_SET(pmtu_reg, in, admin_mtu, pmtu->admin_mtu);

	err = mlx5_core_access_reg(dev, in, sz, out, sz, MLX5_REG_PMTU, 0, !!write);
	if (err)
		goto out;

	if (!write) {
		pmtu->local_port = MLX5_GET(pmtu_reg, out, local_port);
		pmtu->max_mtu = mtu_to_ib_mtu(MLX5_GET(pmtu_reg, out, max_mtu));
		pmtu->admin_mtu = mtu_to_ib_mtu(MLX5_GET(pmtu_reg, out, admin_mtu));
		pmtu->oper_mtu = mtu_to_ib_mtu(MLX5_GET(pmtu_reg, out, oper_mtu));
	}

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_pmtu);

int mlx5_query_port_proto_admin(struct mlx5_core_dev *dev,
				u32 *proto_admin, int proto_mask)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), proto_mask);
	if (err)
		return err;

	if (proto_mask == MLX5_PTYS_EN)
		*proto_admin = MLX5_GET(ptys_reg, out, eth_proto_admin);
	else
		*proto_admin = MLX5_GET(ptys_reg, out, ib_proto_admin);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_proto_admin);

int mlx5_set_port_proto(struct mlx5_core_dev *dev, u32 proto_admin,
			int proto_mask)
{
	u32 in[MLX5_ST_SZ_DW(ptys_reg)];
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	memset(in, 0, sizeof(in));

	MLX5_SET(ptys_reg, in, local_port, 1);
	MLX5_SET(ptys_reg, in, proto_mask, proto_mask);
	if (proto_mask == MLX5_PTYS_EN)
		MLX5_SET(ptys_reg, in, eth_proto_admin, proto_admin);
	else
		MLX5_SET(ptys_reg, in, ib_proto_admin, proto_admin);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PTYS, 0, 1);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_set_port_proto);

int mlx5_set_port_status(struct mlx5_core_dev *dev,
			 enum mlx5_port_status status,
			 u8 port)
{
	u32 in[MLX5_ST_SZ_DW(paos_reg)];
	u32 out[MLX5_ST_SZ_DW(paos_reg)];
	int err;

	memset(in, 0, sizeof(in));
	MLX5_SET(paos_reg, in, local_port, port);
	MLX5_SET(paos_reg, in, admin_status, status);
	MLX5_SET(paos_reg, in, ase, 1);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PAOS, 0, 1);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_set_port_status);

int mlx5_query_port_status(struct mlx5_core_dev *dev, u8 *status)
{
	u32 in[MLX5_ST_SZ_DW(paos_reg)];
	u32 out[MLX5_ST_SZ_DW(paos_reg)];
	int err;

	memset(in, 0, sizeof(in));

	MLX5_SET(paos_reg, in, local_port, 1);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PAOS, 0, 0);
	if (err)
		return err;

	*status = MLX5_GET(paos_reg, out, admin_status);
	return err;
}

static void mlx5_query_port_mtu(struct mlx5_core_dev *dev,
				u16 *admin_mtu, u16 *max_mtu, u16 *oper_mtu)
{
	u32 in[MLX5_ST_SZ_DW(pmtu_reg)];
	u32 out[MLX5_ST_SZ_DW(pmtu_reg)];

	memset(in, 0, sizeof(in));

	MLX5_SET(pmtu_reg, in, local_port, 1);

	mlx5_core_access_reg(dev, in, sizeof(in), out,
			     sizeof(out), MLX5_REG_PMTU, 0, 0);

	if (max_mtu)
		*max_mtu  = MLX5_GET(pmtu_reg, out, max_mtu);
	if (oper_mtu)
		*oper_mtu = MLX5_GET(pmtu_reg, out, oper_mtu);
	if (admin_mtu)
		*admin_mtu = MLX5_GET(pmtu_reg, out, admin_mtu);
}

int mlx5_set_port_mtu(struct mlx5_core_dev *dev, u16 mtu)
{
	u32 in[MLX5_ST_SZ_DW(pmtu_reg)];
	u32 out[MLX5_ST_SZ_DW(pmtu_reg)];

	memset(in, 0, sizeof(in));

	MLX5_SET(pmtu_reg, in, admin_mtu, mtu);
	MLX5_SET(pmtu_reg, in, local_port, 1);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PMTU, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_mtu);

void mlx5_query_port_max_mtu(struct mlx5_core_dev *dev, u16 *max_mtu)
{
	mlx5_query_port_mtu(dev, NULL, max_mtu, NULL);
}
EXPORT_SYMBOL_GPL(mlx5_query_port_max_mtu);

void mlx5_query_port_oper_mtu(struct mlx5_core_dev *dev, u16 *oper_mtu)
{
	mlx5_query_port_mtu(dev, NULL, NULL, oper_mtu);
}
EXPORT_SYMBOL_GPL(mlx5_query_port_oper_mtu);

static int mlx5_query_module_num(struct mlx5_core_dev *dev, int *module_num)
{
	u32 out[MLX5_ST_SZ_DW(pmlp_reg)];
	u32 in[MLX5_ST_SZ_DW(pmlp_reg)];
	int module_mapping;
	int err;

	memset(in, 0, sizeof(in));

	MLX5_SET(pmlp_reg, in, local_port, 1);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_PMLP, 0, 0);
	if (err)
		return err;

	module_mapping = MLX5_GET(pmlp_reg, out, lane0_module_mapping);
	*module_num = module_mapping & MLX5_EEPROM_IDENTIFIER_BYTE_MASK;

	return 0;
}

int mlx5_query_module_eeprom(struct mlx5_core_dev *dev,
			     u16 offset, u16 size, u8 *data)
{
	u32 out[MLX5_ST_SZ_DW(mcia_reg)];
	u32 in[MLX5_ST_SZ_DW(mcia_reg)];
	int module_num;
	u16 i2c_addr;
	int status;
	int err;
	void *ptr = MLX5_ADDR_OF(mcia_reg, out, dword_0);

	err = mlx5_query_module_num(dev, &module_num);
	if (err)
		return err;

	memset(in, 0, sizeof(in));
	size = min_t(int, size, MLX5_EEPROM_MAX_BYTES);

	if (offset < MLX5_EEPROM_PAGE_LENGTH &&
	    offset + size > MLX5_EEPROM_PAGE_LENGTH)
		/* Cross pages read, read until offset 256 in low page */
		size -= offset + size - MLX5_EEPROM_PAGE_LENGTH;

	i2c_addr = MLX5_I2C_ADDR_LOW;
	if (offset >= MLX5_EEPROM_PAGE_LENGTH) {
		i2c_addr = MLX5_I2C_ADDR_HIGH;
		offset -= MLX5_EEPROM_PAGE_LENGTH;
	}

	MLX5_SET(mcia_reg, in, l, 0);
	MLX5_SET(mcia_reg, in, module, module_num);
	MLX5_SET(mcia_reg, in, i2c_device_address, i2c_addr);
	MLX5_SET(mcia_reg, in, page_number, 0);
	MLX5_SET(mcia_reg, in, device_address, offset);
	MLX5_SET(mcia_reg, in, size, size);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_MCIA, 0, 0);
	if (err)
		return err;

	status = MLX5_GET(mcia_reg, out, status);
	if (status) {
		mlx5_core_err(dev, "query_mcia_reg failed: status: 0x%x\n",
			      status);
		return -EIO;
	}

	memcpy(data, ptr, size);

	return size;
}
EXPORT_SYMBOL_GPL(mlx5_query_module_eeprom);

int mlx5_core_query_gids(struct mlx5_core_dev *dev, u8 other_vport,
			 u8 port_num, u16  vf_num, u16 gid_index,
			 union ib_gid *gid)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_hca_vport_gid_in);
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_gid_out);
	int is_group_manager;
	void *out = NULL;
	void *in = NULL;
	union ib_gid *tmp;
	int tbsz;
	int nout;
	int err;

	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	tbsz = mlx5_get_gid_table_len(MLX5_CAP_GEN(dev, gid_table_size));
	mlx5_core_dbg(dev, "vf_num %d, index %d, gid_table_size %d\n",
		      vf_num, gid_index, tbsz);

	if (gid_index > tbsz && gid_index != 0xffff)
		return -EINVAL;

	if (gid_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * sizeof(*gid);

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(query_hca_vport_gid_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_GID);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_gid_in, in, vport_number, vf_num);
			MLX5_SET(query_hca_vport_gid_in, in, other_vport, 1);
		} else {
			err = -EPERM;
			goto out;
		}
	}
	MLX5_SET(query_hca_vport_gid_in, in, gid_index, gid_index);

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_gid_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	err = mlx5_cmd_status_to_err_v2(out);
	if (err)
		goto out;

	tmp = out + MLX5_ST_SZ_BYTES(query_hca_vport_gid_out);
	gid->global.subnet_prefix = tmp->global.subnet_prefix;
	gid->global.interface_id = tmp->global.interface_id;

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_gids);

int mlx5_core_query_pkeys(struct mlx5_core_dev *dev, u8 other_vport,
			  u8 port_num, u16 vf_num, u16 pkey_index,
			  u16 *pkey)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_hca_vport_pkey_in);
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_pkey_out);
	int is_group_manager;
	void *out = NULL;
	void *in = NULL;
	void *pkarr;
	int nout;
	int tbsz;
	int err;
	int i;

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);

	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	tbsz = mlx5_to_sw_pkey_sz(MLX5_CAP_GEN(dev, pkey_table_size));
	if (pkey_index > tbsz && pkey_index != 0xffff)
		return -EINVAL;

	if (pkey_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * MLX5_ST_SZ_BYTES(pkey);

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(query_hca_vport_pkey_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_PKEY);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_pkey_in, in, vport_number, vf_num);
			MLX5_SET(query_hca_vport_pkey_in, in, other_vport, 1);
		} else {
			err = -EPERM;
			goto out;
		}
	}
	MLX5_SET(query_hca_vport_pkey_in, in, pkey_index, pkey_index);

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_pkey_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	err = mlx5_cmd_status_to_err_v2(out);
	if (err)
		goto out;

	pkarr = out + MLX5_ST_SZ_BYTES(query_hca_vport_pkey_out);
	for (i = 0; i < nout; i++, pkey++, pkarr += MLX5_ST_SZ_BYTES(pkey))
		*pkey = MLX5_GET_PR(pkey, pkarr, pkey);

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_pkeys);

int mlx5_core_modify_hca_vport_context(struct mlx5_core_dev *dev,
				       u8 other_vport, u8 port_num,
				       u16 vf_num,
				       struct mlx5_hca_vport_context *req)
{
	int in_sz = MLX5_ST_SZ_BYTES(modify_hca_vport_context_in);
	u8 out[MLX5_ST_SZ_BYTES(modify_hca_vport_context_out)];
	int is_group_manager;
	void *in;
	int err;
	void *ctx;

	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);
	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	memset(out, 0, sizeof(out));
	MLX5_SET(modify_hca_vport_context_in, in, opcode, MLX5_CMD_OP_MODIFY_HCA_VPORT_CONTEXT);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(modify_hca_vport_context_in, in, other_vport, 1);
			MLX5_SET(modify_hca_vport_context_in, in, vport_number, vf_num);
		} else {
			err = -EPERM;
			goto ex;
		}
	}

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(modify_hca_vport_context_in, in, port_num, port_num);

	ctx = MLX5_ADDR_OF(modify_hca_vport_context_in, in, hca_vport_context);
	MLX5_SET(hca_vport_context, ctx, field_select, req->field_select);
	MLX5_SET(hca_vport_context, ctx, sm_virt_aware, req->sm_virt_aware);
	MLX5_SET(hca_vport_context, ctx, has_smi, req->has_smi);
	MLX5_SET(hca_vport_context, ctx, has_raw, req->has_raw);
	MLX5_SET(hca_vport_context, ctx, vport_state_policy, req->policy);
	MLX5_SET(hca_vport_context, ctx, port_physical_state, req->phys_state);
	MLX5_SET(hca_vport_context, ctx, vport_state, req->vport_state);
	MLX5_SET64(hca_vport_context, ctx, port_guid, req->port_guid);
	MLX5_SET64(hca_vport_context, ctx, node_guid, req->node_guid);
	MLX5_SET(hca_vport_context, ctx, cap_mask1, req->cap_mask1);
	MLX5_SET(hca_vport_context, ctx, cap_mask1_field_select, req->cap_mask1_perm);
	MLX5_SET(hca_vport_context, ctx, cap_mask2, req->cap_mask2);
	MLX5_SET(hca_vport_context, ctx, cap_mask2_field_select, req->cap_mask2_perm);
	MLX5_SET(hca_vport_context, ctx, lid, req->lid);
	MLX5_SET(hca_vport_context, ctx, init_type_reply, req->init_type_reply);
	MLX5_SET(hca_vport_context, ctx, lmc, req->lmc);
	MLX5_SET(hca_vport_context, ctx, subnet_timeout, req->subnet_timeout);
	MLX5_SET(hca_vport_context, ctx, sm_lid, req->sm_lid);
	MLX5_SET(hca_vport_context, ctx, sm_sl, req->sm_sl);
	MLX5_SET(hca_vport_context, ctx, qkey_violation_counter, req->qkey_violation_counter);
	MLX5_SET(hca_vport_context, ctx, pkey_violation_counter, req->pkey_violation_counter);
	err = mlx5_cmd_exec(dev, in, in_sz, out, sizeof(out));
	if (err)
		goto ex;

	err = mlx5_cmd_status_to_err_v2(out);

ex:
	kfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_modify_hca_vport_context);

int mlx5_core_query_hca_vport_context(struct mlx5_core_dev *dev,
				      u8 other_vport, u8 port_num,
				      u16 vf_num,
				      struct mlx5_hca_vport_context *rep)
{
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_context_out);
	u32 in[MLX5_ST_SZ_DW(query_hca_vport_context_in)];
	int is_group_manager;
	void *out;
	void *ctx;
	int err;

	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);
	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	memset(in, 0, sizeof(in));
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_hca_vport_context_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT);

	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_context_in, in, other_vport, 1);
			MLX5_SET(query_hca_vport_context_in, in, vport_number, vf_num);
		} else {
			err = -EPERM;
			goto ex;
		}
	}

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_context_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out,  out_sz);
	if (err)
		goto ex;
	err = mlx5_cmd_status_to_err_v2(out);
	if (err)
		goto ex;

	ctx = MLX5_ADDR_OF(query_hca_vport_context_out, out, hca_vport_context);
	rep->field_select = MLX5_GET_PR(hca_vport_context, ctx, field_select);
	rep->sm_virt_aware = MLX5_GET_PR(hca_vport_context, ctx, sm_virt_aware);
	rep->has_smi = MLX5_GET_PR(hca_vport_context, ctx, has_smi);
	rep->has_raw = MLX5_GET_PR(hca_vport_context, ctx, has_raw);
	rep->policy = MLX5_GET_PR(hca_vport_context, ctx, vport_state_policy);
	rep->phys_state = MLX5_GET_PR(hca_vport_context, ctx,
				      port_physical_state);
	rep->vport_state = MLX5_GET_PR(hca_vport_context, ctx, vport_state);
	rep->port_physical_state = MLX5_GET_PR(hca_vport_context, ctx,
					       port_physical_state);
	rep->port_guid = MLX5_GET64_PR(hca_vport_context, ctx, port_guid);
	rep->node_guid = MLX5_GET64_PR(hca_vport_context, ctx, node_guid);
	rep->cap_mask1 = MLX5_GET_PR(hca_vport_context, ctx, cap_mask1);
	rep->cap_mask1_perm = MLX5_GET_PR(hca_vport_context, ctx,
					  cap_mask1_field_select);
	rep->cap_mask2 = MLX5_GET_PR(hca_vport_context, ctx, cap_mask2);
	rep->cap_mask2_perm = MLX5_GET_PR(hca_vport_context, ctx,
					  cap_mask2_field_select);
	rep->lid = MLX5_GET_PR(hca_vport_context, ctx, lid);
	rep->init_type_reply = MLX5_GET_PR(hca_vport_context, ctx,
					   init_type_reply);
	rep->lmc = MLX5_GET_PR(hca_vport_context, ctx, lmc);
	rep->subnet_timeout = MLX5_GET_PR(hca_vport_context, ctx,
					  subnet_timeout);
	rep->sm_lid = MLX5_GET_PR(hca_vport_context, ctx, sm_lid);
	rep->sm_sl = MLX5_GET_PR(hca_vport_context, ctx, sm_sl);
	rep->qkey_violation_counter = MLX5_GET_PR(hca_vport_context, ctx,
						  qkey_violation_counter);
	rep->pkey_violation_counter = MLX5_GET_PR(hca_vport_context, ctx,
						  pkey_violation_counter);
	rep->grh_required = MLX5_GET_PR(hca_vport_context, ctx, grh_required);
	rep->sys_image_guid = MLX5_GET64_PR(hca_vport_context, ctx,
					    system_image_guid);

ex:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_hca_vport_context);

int mlx5_core_query_vport_counter(struct mlx5_core_dev *dev, u8 other_vport,
				  u8 port_num, u16 vf_num,
				  struct mlx5_vport_counters *vc)
{
	int	out_sz = MLX5_ST_SZ_BYTES(query_vport_counter_out);
	int	in_sz = MLX5_ST_SZ_BYTES(query_vport_counter_in);
	int	is_group_manager;
	void   *out;
	void   *in;
	int	err;

	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);
	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto ex;
	}

	MLX5_SET(query_vport_counter_in, in, opcode, MLX5_CMD_OP_QUERY_VPORT_COUNTER);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_vport_counter_in, in, other_vport, 1);
			MLX5_SET(query_vport_counter_in, in, vport_number, vf_num);
		} else {
			err = -EPERM;
			goto ex;
		}
	}
	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_vport_counter_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out,  out_sz);
	if (err)
		goto ex;
	err = mlx5_cmd_status_to_err_v2(out);
	if (err)
		goto ex;

	vc->received_errors.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_errors.packets);
	vc->received_errors.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_errors.octets);
	vc->transmit_errors.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmit_errors.packets);
	vc->transmit_errors.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmit_errors.octets);
	vc->received_ib_unicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_unicast.packets);
	vc->received_ib_unicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_unicast.octets);
	vc->transmitted_ib_unicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_unicast.packets);
	vc->transmitted_ib_unicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_unicast.octets);
	vc->received_ib_multicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_multicast.packets);
	vc->received_ib_multicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_multicast.octets);
	vc->transmitted_ib_multicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_multicast.packets);
	vc->transmitted_ib_multicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_multicast.octets);
	vc->received_eth_broadcast.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_eth_broadcast.packets);
	vc->received_eth_broadcast.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_eth_broadcast.octets);
	vc->transmitted_eth_broadcast.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_eth_broadcast.packets);
	vc->transmitted_eth_broadcast.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_eth_broadcast.octets);
	vc->received_eth_unicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_eth_unicast.octets);
	vc->received_eth_unicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_eth_unicast.packets);
	vc->transmitted_eth_unicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_eth_unicast.octets);
	vc->transmitted_eth_unicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_eth_unicast.packets);
	vc->received_eth_multicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_eth_multicast.octets);
	vc->received_eth_multicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_eth_multicast.packets);
	vc->transmitted_eth_multicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_eth_multicast.octets);
	vc->transmitted_eth_multicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_eth_multicast.packets);

ex:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_vport_counter);

int mlx5_core_query_ib_ppcnt(struct mlx5_core_dev *dev,
			     u8 port_num, void *out, size_t sz)
{
	u32 *in;
	int err;

	in  = mlx5_vzalloc(sz);
	if (!in) {
		err = -ENOMEM;
		return err;
	}

	MLX5_SET(ppcnt_reg, in, local_port, port_num);

	MLX5_SET(ppcnt_reg, in, grp, MLX5_INFINIBAND_PORT_COUNTERS_GROUP);
	err = mlx5_core_access_reg(dev, in, sz, out,
				   sz, MLX5_REG_PPCNT, 0, 0);

	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_ib_ppcnt);

int mlx5_set_port_pause(struct mlx5_core_dev *dev, u32 rx_pause, u32 tx_pause)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)];
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];
	int err;

	memset(in, 0, sizeof(in));
	MLX5_SET(pfcc_reg, in, local_port, 1);
	MLX5_SET(pfcc_reg, in, pptx, tx_pause);
	MLX5_SET(pfcc_reg, in, pprx, rx_pause);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PFCC, 0, 1);
	return err;
}

int mlx5_query_port_pause(struct mlx5_core_dev *dev,
			  u32 *rx_pause, u32 *tx_pause)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)];
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];
	int err;

	memset(in, 0, sizeof(in));
	MLX5_SET(pfcc_reg, in, local_port, 1);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PFCC, 0, 0);
	if (err)
		return err;

	*rx_pause = MLX5_GET(pfcc_reg, out, pprx);
	*tx_pause = MLX5_GET(pfcc_reg, out, pptx);

	return 0;
}

int mlx5_set_port_wol(struct mlx5_core_dev *mdev, u8 wol_mode)
{
	u32 in[MLX5_ST_SZ_DW(set_wol_rol_in)];
	u32 out[MLX5_ST_SZ_DW(set_wol_rol_out)];

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(set_wol_rol_in, in, opcode, MLX5_CMD_OP_SET_WOL_ROL);
	MLX5_SET(set_wol_rol_in, in, wol_mode_valid, 1);
	MLX5_SET(set_wol_rol_in, in, wol_mode, wol_mode);

	return mlx5_cmd_exec_check_status(mdev, in, sizeof(in),
					  out, sizeof(out));
}

int mlx5_query_port_wol(struct mlx5_core_dev *mdev, u8 *wol_mode)
{
	u32 in[MLX5_ST_SZ_DW(query_wol_rol_in)];
	u32 out[MLX5_ST_SZ_DW(query_wol_rol_out)];
	int err;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(query_wol_rol_in, in, opcode, MLX5_CMD_OP_QUERY_WOL_ROL);

	err = mlx5_cmd_exec_check_status(mdev, in, sizeof(in),
					 out, sizeof(out));

	if (!err)
		*wol_mode = MLX5_GET(query_wol_rol_out, out, wol_mode);

	return err;
}

int mlx5_query_port_cong_status(struct mlx5_core_dev *mdev, int protocol,
				int priority, int *is_enable)
{
	u32 in[MLX5_ST_SZ_DW(query_cong_status_in)];
	u32 out[MLX5_ST_SZ_DW(query_cong_status_out)];
	int err;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(query_cong_status_in, in, opcode,
		 MLX5_CMD_OP_QUERY_CONG_STATUS);
	MLX5_SET(query_cong_status_in, in, cong_protocol, protocol);
	MLX5_SET(query_cong_status_in, in, priority, priority);

	err = mlx5_cmd_exec_check_status(mdev, in, sizeof(in),
					 out, sizeof(out));
	if (!err)
		*is_enable = MLX5_GET(query_cong_status_out, out, enable);
	return err;
}

int mlx5_modify_port_cong_status(struct mlx5_core_dev *mdev, int protocol,
				 int priority, int enable)
{
	u32 in[MLX5_ST_SZ_DW(modify_cong_status_in)];
	u32 out[MLX5_ST_SZ_DW(modify_cong_status_out)];
	int err;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(modify_cong_status_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_STATUS);
	MLX5_SET(modify_cong_status_in, in, cong_protocol, protocol);
	MLX5_SET(modify_cong_status_in, in, priority, priority);
	MLX5_SET(modify_cong_status_in, in, enable, enable);

	err = mlx5_cmd_exec_check_status(mdev, in, sizeof(in),
					 out, sizeof(out));
	return err;
}

int mlx5_query_port_cong_params(struct mlx5_core_dev *mdev, int protocol,
				void *out, int out_size)
{
	u32 in[MLX5_ST_SZ_DW(query_cong_params_in)];
	int err;

	memset(in, 0, sizeof(in));

	MLX5_SET(query_cong_params_in, in, opcode,
		 MLX5_CMD_OP_QUERY_CONG_PARAMS);
	MLX5_SET(query_cong_params_in, in, cong_protocol, protocol);

	err = mlx5_cmd_exec_check_status(mdev, in, sizeof(in),
					 out, out_size);
	return err;
}

int mlx5_modify_port_cong_params(struct mlx5_core_dev *mdev,
				 void *in, int in_size)
{
	u32 out[MLX5_ST_SZ_DW(modify_cong_params_out)];
	int err;

	memset(out, 0, sizeof(out));

	err = mlx5_cmd_exec_check_status(mdev, in, in_size, out, sizeof(out));
	return err;
}

int mlx5_max_tc(struct mlx5_core_dev *mdev)
{
	u8 num_tc = MLX5_CAP_GEN(mdev, max_tc) ? : 8;

	return num_tc - 1;
}

int mlx5_query_port_dcbx_param(struct mlx5_core_dev *mdev, u32 *out)
{
	u32 in[MLX5_ST_SZ_DW(dcbx_param)];

	memset(in, 0, sizeof(in));

	MLX5_SET(dcbx_param, in, port_number, 1);

	return  mlx5_core_access_reg(mdev, in, sizeof(in), out,
				    sizeof(in), MLX5_REG_DCBX_PARAM, 0, 0);
}

int mlx5_set_port_dcbx_param(struct mlx5_core_dev *mdev, u32 *in)
{
	u32 out[MLX5_ST_SZ_DW(dcbx_param)];

	MLX5_SET(dcbx_param, in, port_number, 1);

	return mlx5_core_access_reg(mdev, in, sizeof(out), out,
				    sizeof(out), MLX5_REG_DCBX_PARAM, 0, 1);
}

int mlx5_modify_port_ets_tc_bw_alloc(struct mlx5_core_dev *mdev,
				     u8 tc_tx_bw[MLX5_MAX_NUM_TC],
				     u8 tc_group[MLX5_MAX_NUM_TC])
{
	u32 in[MLX5_ST_SZ_DW(qetc_reg)];
	u32 out[MLX5_ST_SZ_DW(qetc_reg)];
	void *ets_tcn_conf;
	int i;

	/* Check ETS capability bit. If disabled, return. */
	if (!MLX5_CAP_GEN(mdev, ets))
		return -ENOTSUPP;

	memset(in, 0, sizeof(in));

	MLX5_SET(qetc_reg, in, port_number, 1);

	for (i = 0; i < MLX5_MAX_NUM_TC; i++) {
		ets_tcn_conf = MLX5_ADDR_OF(qetc_reg, in, tc_conf[i]);

		MLX5_SET(ets_tcn_conf, ets_tcn_conf, g, 1);
		MLX5_SET(ets_tcn_conf, ets_tcn_conf, b, 1);
		MLX5_SET(ets_tcn_conf, ets_tcn_conf, group, tc_group[i]);
		MLX5_SET(ets_tcn_conf, ets_tcn_conf, bw_allocation,
			 tc_tx_bw[i]);
	}

	return mlx5_core_access_reg(mdev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_QETCR, 0, 1);
}

int mlx5_query_port_ets_tc_bw_alloc(struct mlx5_core_dev *mdev,
				    u8 tc_tx_bw[MLX5_MAX_NUM_TC])
{
	u32 in[MLX5_ST_SZ_DW(qetc_reg)];
	u32 out[MLX5_ST_SZ_DW(qetc_reg)];
	void *ets_tcn_conf;
	int err;
	int i;

	memset(in, 0, sizeof(in));

	MLX5_SET(qetc_reg, in, port_number, 1);

	err = mlx5_core_access_reg(mdev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_QETCR, 0, 0);

	if (err)
		return err;

	for (i = 0; i < MLX5_MAX_NUM_TC; i++) {
		ets_tcn_conf = MLX5_ADDR_OF(qetc_reg, out, tc_conf[i]);

		tc_tx_bw[i] = MLX5_GET(ets_tcn_conf, ets_tcn_conf,
				      bw_allocation);
	}

	return 0;
}

int mlx5_modify_port_priority2tc(struct mlx5_core_dev *mdev,
				 u8 prio2tc[MLX5_MAX_NUM_TC])
{
	u32 in[MLX5_ST_SZ_DW(qtct_reg)];
	u32 out[MLX5_ST_SZ_DW(qtct_reg)];
	int err = 0;
	int i;

	/* Check ETS capability bit. If disabled, return. */
	if (!MLX5_CAP_GEN(mdev, ets))
		return -ENOTSUPP;

	for (i = 0; i < MLX5_MAX_NUM_TC; i++) {
		memset(in, 0, sizeof(in));
		memset(out, 0, sizeof(out));

		MLX5_SET(qtct_reg, in, port_number, 1);
		MLX5_SET(qtct_reg, in, prio, i);
		MLX5_SET(qtct_reg, in, t_class, prio2tc[i]);

		err |= mlx5_core_access_reg(mdev, in, sizeof(in), out,
					    sizeof(out), MLX5_REG_QTCT, 0, 1);
	}

	return err;
}

int mlx5_query_port_priority2tc(struct mlx5_core_dev *mdev,
				u8 prio2tc[MLX5_MAX_NUM_TC])
{
	u32 in[MLX5_ST_SZ_DW(qtct_reg)];
	u32 out[MLX5_ST_SZ_DW(qtct_reg)];
	int err = 0;
	int i;

	for (i = 0; i < MLX5_MAX_NUM_TC; i++) {
		memset(in, 0, sizeof(in));
		memset(out, 0, sizeof(out));

		MLX5_SET(qtct_reg, in, port_number, 1);
		MLX5_SET(qtct_reg, in, prio, i);

		err = mlx5_core_access_reg(mdev, in, sizeof(in), out,
					   sizeof(out), MLX5_REG_QTCT, 0, 0);
		if (!err)
			prio2tc[i] = MLX5_GET(qtct_reg, out, t_class);
		else
			return err;
	}

	return 0;
}

int mlx5_modify_port_ets_rate_limit(struct mlx5_core_dev *mdev,
				    u8 max_bw_value[MLX5_MAX_NUM_TC],
				    u8 max_bw_unit[MLX5_MAX_NUM_TC])

{
	u32 in[MLX5_ST_SZ_DW(qetc_reg)];
	u32 out[MLX5_ST_SZ_DW(qetc_reg)];
	void *ets_tcn_conf;
	int i;

	/* Check ETS capability bit. If disabled, return. */
	if (!MLX5_CAP_GEN(mdev, ets))
		return -ENOTSUPP;

	memset(in, 0, sizeof(in));

	MLX5_SET(qetc_reg, in, port_number, 1);

	for (i = 0; i < MLX5_MAX_NUM_TC; i++) {
		ets_tcn_conf = MLX5_ADDR_OF(qetc_reg, in, tc_conf[i]);

		MLX5_SET(ets_tcn_conf, ets_tcn_conf, r, 1);
		MLX5_SET(ets_tcn_conf, ets_tcn_conf, max_bw_unit,
			 max_bw_unit[i]);
		MLX5_SET(ets_tcn_conf, ets_tcn_conf, max_bw_value,
			 max_bw_value[i]);
	}

	return mlx5_core_access_reg(mdev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_QETCR, 0, 1);
}

int mlx5_query_port_ets_rate_limit(struct mlx5_core_dev *mdev,
				   u8 max_bw_value[MLX5_MAX_NUM_TC],
				   u8 max_bw_unit[MLX5_MAX_NUM_TC])
{
	u32 in[MLX5_ST_SZ_DW(qetc_reg)];
	u32 out[MLX5_ST_SZ_DW(qetc_reg)];
	void *ets_tcn_conf;
	int err;
	int i;

	memset(in, 0, sizeof(in));

	MLX5_SET(qetc_reg, in, port_number, 1);

	err = mlx5_core_access_reg(mdev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_QETCR, 0, 0);

	if (err)
		return err;

	for (i = 0; i < MLX5_MAX_NUM_TC; i++) {
		ets_tcn_conf = MLX5_ADDR_OF(qetc_reg, out, tc_conf[i]);

		max_bw_value[i] = MLX5_GET(ets_tcn_conf, ets_tcn_conf,
					   max_bw_value);
		max_bw_unit[i] = MLX5_GET(ets_tcn_conf, ets_tcn_conf,
					  max_bw_unit);
	}

	return 0;
}

static const char *mlx5_port_module_event_error_type_to_string(u8 error_type)
{
	switch (error_type) {
	case MLX5_MODULE_EVENT_ERROR_POWER_BUDGET_EXCEEDED:
		return "Power Budget Exceeded";

	case MLX5_MODULE_EVENT_ERROR_LONG_RANGE_FOR_NON_MLNX_CABLE_MODULE:
		return "Long Range for non MLNX cable/module";

	case MLX5_MODULE_EVENT_ERROR_BUS_STUCK:
		return "Bus stuck(I2C or data shorted)";

	case MLX5_MODULE_EVENT_ERROR_NO_EEPROM_RETRY_TIMEOUT:
		return "No EEPROM/retry timeout";

	case MLX5_MODULE_EVENT_ERROR_ENFORCE_PART_NUMBER_LIST:
		return "Enforce part number list";

	case MLX5_MODULE_EVENT_ERROR_UNKNOWN_IDENTIFIER:
		return "Unknown identifier";

	case MLX5_MODULE_EVENT_ERROR_HIGH_TEMPERATURE:
		return "High Temperature";

	case MLX5_MODULE_EVENT_ERROR_BAD_CABLE:
		return "Bad cable (module/cable is shorted)";

	default:
		return "Unknown error type";
	}
}

void mlx5_port_module_event(
	struct mlx5_core_dev *dev,
	struct mlx5_eqe *eqe)
{
	unsigned int module_num;
	unsigned int module_status;
	unsigned int error_type;

	struct mlx5_eqe_port_module_event *module_event_eqe;
	struct pci_dev *pdev;

	module_event_eqe = &eqe->data.port_module_event;
	pdev = dev->pdev;

	module_num  = (unsigned int)module_event_eqe->module;
	module_status = (unsigned int)module_event_eqe->module_status &
				PORT_MODULE_EVENT_MODULE_STATUS_MASK;
	error_type = (unsigned int)module_event_eqe->error_type &
				PORT_MODULE_EVENT_ERROR_TYPE_MASK;

	switch (module_status) {
	case MLX5_MODULE_STATUS_PLUGGED:
		dev_info(
			&pdev->dev, "Module %u, status: plugged",
			module_num);
		break;

	case MLX5_MODULE_STATUS_UNPLUGGED:
		dev_info(
			&pdev->dev, "Module %u, status: unplugged",
			module_num);
		break;

	case MLX5_MODULE_STATUS_ERROR:
		dev_info(
			&pdev->dev, "Module %u, status: error, %s",
			module_num,
			mlx5_port_module_event_error_type_to_string(error_type));
		break;

	default:
		dev_info(
			&pdev->dev, "Module %u, unknown status",
			module_num);
	}
}

int mlx5_set_port_pfc(struct mlx5_core_dev *dev, u8 pfc_en_tx, u8 pfc_en_rx)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)];
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];

	memset(in, 0, sizeof(in));
	MLX5_SET(pfcc_reg, in, local_port, 1);
	MLX5_SET(pfcc_reg, in, pfctx, pfc_en_tx);
	MLX5_SET(pfcc_reg, in, pfcrx, pfc_en_rx);
	MLX5_SET_TO_ONES(pfcc_reg, in, prio_mask_tx);
	MLX5_SET_TO_ONES(pfcc_reg, in, prio_mask_rx);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_PFCC, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_pfc);

int mlx5_query_port_pfc(struct mlx5_core_dev *dev, u8 *pfc_en_tx, u8 *pfc_en_rx)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)];
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];
	int err;

	memset(in, 0, sizeof(in));
	MLX5_SET(pfcc_reg, in, local_port, 1);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PFCC, 0, 0);
	if (err)
		return err;

	if (pfc_en_tx)
		*pfc_en_tx = MLX5_GET(pfcc_reg, out, pfctx);

	if (pfc_en_rx)
		*pfc_en_rx = MLX5_GET(pfcc_reg, out, pfcrx);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_pfc);

int mlx5_query_port_autoneg(struct mlx5_core_dev *dev, int proto_mask,
			    u8 *an_disable_cap, u8 *an_disable_status)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), proto_mask);
	if (err)
		return err;

	*an_disable_status = MLX5_GET(ptys_reg, out, an_disable_admin);
	*an_disable_cap = MLX5_GET(ptys_reg, out, an_disable_cap);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_autoneg);

int mlx5_set_port_autoneg(struct mlx5_core_dev *dev, bool disable,
			  u32 eth_proto_admin, int proto_mask)
{
	u32 in[MLX5_ST_SZ_DW(ptys_reg)];
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	u8 an_disable_cap;
	u8 an_disable_status;
	int err;

	err = mlx5_query_port_autoneg(dev, proto_mask, &an_disable_cap,
				      &an_disable_status);
	if (!an_disable_cap)
		return -EPERM;

	memset(in, 0, sizeof(in));

	MLX5_SET(ptys_reg, in, local_port, 1);
	MLX5_SET(ptys_reg, in, an_disable_admin, disable);
	MLX5_SET(ptys_reg, in, proto_mask, proto_mask);
	if (proto_mask == MLX5_PTYS_EN)
		MLX5_SET(ptys_reg, in, eth_proto_admin, eth_proto_admin);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PTYS, 0, 1);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_set_port_autoneg);
