/*
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include "mlx5_core.h"
#include "vxlan.h"

void mlx5e_vxlan_init(struct mlx5e_priv *priv)
{
	struct mlx5e_vxlan_db *vxlan_db = &priv->vxlan;

	spin_lock_init(&vxlan_db->lock);
	INIT_RADIX_TREE(&vxlan_db->tree, GFP_ATOMIC);
	mlx5_vxlan_debugfs_init(priv->mdev);
}

static int mlx5e_vxlan_core_add_port_cmd(struct mlx5_core_dev *mdev, u16 port)
{
	struct mlx5_outbox_hdr *hdr;
	int err;

	u32 in[MLX5_ST_SZ_DW(add_vxlan_udp_dport_in)];
	u32 out[MLX5_ST_SZ_DW(add_vxlan_udp_dport_out)];

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(add_vxlan_udp_dport_in, in, opcode,
		 MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT);
	MLX5_SET(add_vxlan_udp_dport_in, in, vxlan_udp_port, port);

	err = mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
	if (err)
		return err;

	hdr = (struct mlx5_outbox_hdr *)out;
	return hdr->status ? -ENOMEM : 0;
}

static int mlx5e_vxlan_core_del_port_cmd(struct mlx5_core_dev *mdev, u16 port)
{
	u32 in[MLX5_ST_SZ_DW(delete_vxlan_udp_dport_in)];
	u32 out[MLX5_ST_SZ_DW(delete_vxlan_udp_dport_out)];

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	MLX5_SET(delete_vxlan_udp_dport_in, in, opcode,
		 MLX5_CMD_OP_DELETE_VXLAN_UDP_DPORT);
	MLX5_SET(delete_vxlan_udp_dport_in, in, vxlan_udp_port, port);

	return mlx5_cmd_exec_check_status(mdev, in, sizeof(in), out,
					  sizeof(out));
}

struct mlx5e_vxlan *mlx5e_vxlan_lookup_port(struct mlx5e_priv *priv, u16 port)
{
	struct mlx5e_vxlan_db *vxlan_db = &priv->vxlan;
	struct mlx5e_vxlan *vxlan;

	spin_lock(&vxlan_db->lock);
	vxlan = radix_tree_lookup(&vxlan_db->tree, port);
	spin_unlock(&vxlan_db->lock);

	return vxlan;
}

static void mlx5e_vxlan_add_port(struct mlx5e_priv *priv, sa_family_t sa_family, u16 port)
{
	int err;
	u16 ethertype;
	struct mlx5e_vxlan_db *vxlan_db = &priv->vxlan;
	struct mlx5e_vxlan *vxlan;

	if (sa_family == AF_INET)
		ethertype = ETH_P_IP;
	else if (sa_family == AF_INET6)
		ethertype = ETH_P_IPV6;
	else
		return;

	if (mlx5e_vxlan_core_add_port_cmd(priv->mdev, port))
		return;

	vxlan = kzalloc(sizeof(*vxlan), GFP_KERNEL);
	if (!vxlan)
		goto err_delete_port;

	vxlan->udp_port = port;

	err = mlx5e_add_tunneling_rule(priv, MLX5E_TUNNEL_RULE_TYPE_VXLAN, port,
				       ethertype, &vxlan->flow_rule);
	if (err) {
		mlx5_core_warn(priv->mdev, "failed to add tunneling rule\n");
		goto err_free;
	}

	spin_lock_irq(&vxlan_db->lock);
	err = radix_tree_insert(&vxlan_db->tree, vxlan->udp_port, vxlan);
	spin_unlock_irq(&vxlan_db->lock);
	if (err)
		goto err_free;

	if (mlx5_vxlan_debugfs_add(priv->mdev, vxlan))
		pr_warn("Failed to add VXLAN port %d to debugfs\n", vxlan->udp_port);

	return;

err_free:
	kfree(vxlan);
err_delete_port:
	mlx5e_vxlan_core_del_port_cmd(priv->mdev, port);
}

void mlx5e_vxlan_add_task(struct work_struct *work)
{
	struct mlx5e_vxlan_work *vxlan_work;
	struct mlx5e_priv *priv;

	vxlan_work = container_of(work, struct mlx5e_vxlan_work, work);
	priv = vxlan_work->priv;

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state) &&
	    !priv->internal_error)
		mlx5e_vxlan_add_port(priv, vxlan_work->sa_family, vxlan_work->port);
	mutex_unlock(&priv->state_lock);
	kfree(vxlan_work);
}

static void __mlx5e_vxlan_del_port(struct mlx5e_priv *priv, u16 port)
{
	struct mlx5e_vxlan_db *vxlan_db = &priv->vxlan;
	struct mlx5e_vxlan *vxlan;

	spin_lock_irq(&vxlan_db->lock);
	vxlan = radix_tree_delete(&vxlan_db->tree, port);
	spin_unlock_irq(&vxlan_db->lock);

	if (!vxlan)
		return;

	mlx5_vxlan_debugfs_remove(priv->mdev, vxlan);
	mlx5e_del_tunneling_rule(priv, &vxlan->flow_rule);
	mlx5e_vxlan_core_del_port_cmd(priv->mdev, vxlan->udp_port);

	kfree(vxlan);
}

static void mlx5e_vxlan_del_port(struct mlx5e_priv *priv, u16 port)
{
	if (!mlx5e_vxlan_lookup_port(priv, port))
		return;

	__mlx5e_vxlan_del_port(priv, port);
}

static void mlx5e_vxlan_del_task(struct work_struct *work)
{
	struct mlx5e_vxlan_work *vxlan_work;
	struct mlx5e_priv *priv;

	vxlan_work = container_of(work, struct mlx5e_vxlan_work, work);
	priv = vxlan_work->priv;

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state) &&
	    !priv->internal_error)
		mlx5e_vxlan_del_port(priv, vxlan_work->port);
	mutex_unlock(&priv->state_lock);
	kfree(vxlan_work);
}

void mlx5e_vxlan_queue_work(struct mlx5e_priv *priv, sa_family_t sa_family,
			    u16 port, int add)
{
	struct mlx5e_vxlan_work *vxlan_work;

	vxlan_work = kmalloc(sizeof(*vxlan_work), GFP_ATOMIC);
	if (!vxlan_work)
		return;

	if (add)
		INIT_WORK(&vxlan_work->work, mlx5e_vxlan_add_task);
	else
		INIT_WORK(&vxlan_work->work, mlx5e_vxlan_del_task);

	vxlan_work->priv = priv;
	vxlan_work->port = port;
	vxlan_work->sa_family = sa_family;
	queue_work(priv->wq, &vxlan_work->work);
}


void mlx5e_vxlan_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_vxlan_db *vxlan_db = &priv->vxlan;
	struct mlx5e_vxlan *vxlan;
	unsigned int idx = 0;

	mlx5_vxlan_debugfs_cleanup(priv->mdev);
	spin_lock_irq(&vxlan_db->lock);
	while (radix_tree_gang_lookup(&vxlan_db->tree, (void **)&vxlan, idx, 1)) {
		spin_unlock_irq(&vxlan_db->lock);
		idx = vxlan->udp_port;
		__mlx5e_vxlan_del_port(priv, vxlan->udp_port);
		spin_lock_irq(&vxlan_db->lock);
	}
	spin_unlock_irq(&vxlan_db->lock);
}
