/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <linux/etherdevice.h>
#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <net/ip.h>
#ifdef CONFIG_NET_RX_BUSY_POLL
#include <net/busy_poll.h>
#endif
#ifdef HAVE_VXLAN_ENABLED
#ifdef HAVE_VXLAN_DYNAMIC_PORT
#include <net/vxlan.h>
#endif
#endif

#include <linux/mlx4/driver.h>
#include <linux/mlx4/device.h>
#include <linux/mlx4/cmd.h>
#include <linux/mlx4/cq.h>
#include <uapi/linux/if_bonding.h>

#include "mlx4_en.h"
#include "en_port.h"

#ifdef CONFIG_INFINIBAND_WQE_FORMAT
	#define INIT_OWNER_BIT	cpu_to_be32(1 << 30)
#else
	#define INIT_OWNER_BIT  0xffffffff
#endif

static int mlx4_en_uc_steer_add(struct mlx4_en_priv *priv,
				unsigned char *mac, int *qpn,
				u64 *reg_id, u16 vlan);
static void mlx4_en_uc_steer_release(struct mlx4_en_priv *priv,
				     unsigned char *mac, int qpn, u64 reg_id);

#ifdef HAVE_NEW_TX_RING_SCHEME
int mlx4_en_setup_tc(struct net_device *dev, u8 up)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	int i;
	unsigned int offset = 0;

	if (priv->vgtp)
		return -ENOTSUPP;

	if (up && up != MLX4_EN_NUM_UP)
		return -EINVAL;

	netdev_set_num_tc(dev, up);

	/* Partition Tx queues evenly amongst UP's */
	for (i = 0; i < up; i++) {
		netdev_set_tc_queue(dev, i, priv->num_tx_rings_p_up, offset);
		offset += priv->num_tx_rings_p_up;
	}

#ifdef CONFIG_MLX4_EN_DCB
	if (!mlx4_is_slave(priv->mdev->dev)) {
		if (up) {
			priv->flags |= MLX4_EN_FLAG_DCB_ENABLED;
		} else {
			priv->flags &= ~MLX4_EN_FLAG_DCB_ENABLED;
			priv->cee_params.dcb_cfg.pfc_state = false;
		}
	}
#endif /* CONFIG_MLX4_EN_DCB */

	return 0;
}

#ifdef HAVE_NDO_SETUP_TC_4_PARAMS
static int __mlx4_en_setup_tc(struct net_device *dev, u32 handle, __be16 proto,
			      struct tc_to_netdev *tc)
{
	if (tc->type != TC_SETUP_MQPRIO)
		return -EINVAL;

	return mlx4_en_setup_tc(dev, tc->tc);
}
#endif /* HAVE_NDO_SETUP_TC_4_PARAMS */
#endif /* HAVE_NEW_TX_RING_SCHEME */

#ifdef CONFIG_NET_RX_BUSY_POLL
/* must be called with local_bh_disable()d */
static int mlx4_en_low_latency_recv(struct napi_struct *napi)
{
	struct mlx4_en_cq *cq = container_of(napi, struct mlx4_en_cq, napi);
	struct net_device *dev = cq->dev;
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_rx_ring *rx_ring = priv->rx_ring[cq->ring];
	int done;

	if (!priv->port_up)
		return LL_FLUSH_FAILED;

	if (!mlx4_en_cq_lock_poll(cq))
		return LL_FLUSH_BUSY;

	done = mlx4_en_process_rx_cq(dev, cq, 4);
	if (likely(done))
		rx_ring->cleaned += done;
	else
		rx_ring->misses++;

	mlx4_en_cq_unlock_poll(cq);

	return done;
}
#endif	/* CONFIG_NET_RX_BUSY_POLL */

#ifdef CONFIG_RFS_ACCEL

#ifdef HAVE_NDO_RX_FLOW_STEER
struct mlx4_en_filter {
	struct list_head next;
	struct work_struct work;

	u8     ip_proto;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;

	int rxq_index;
	struct mlx4_en_priv *priv;
	u32 flow_id;			/* RFS infrastructure id */
	int id;				/* mlx4_en driver id */
	u64 reg_id;			/* Flow steering API id */
	u8 activated;			/* Used to prevent expiry before filter
					 * is attached
					 */
	struct hlist_node filter_chain;
};

static void mlx4_en_filter_rfs_expire(struct mlx4_en_priv *priv);

static enum mlx4_net_trans_rule_id mlx4_ip_proto_to_trans_rule_id(u8 ip_proto)
{
	switch (ip_proto) {
	case IPPROTO_UDP:
		return MLX4_NET_TRANS_RULE_ID_UDP;
	case IPPROTO_TCP:
		return MLX4_NET_TRANS_RULE_ID_TCP;
	default:
		return MLX4_NET_TRANS_RULE_NUM;
	}
};

static void mlx4_en_filter_work(struct work_struct *work)
{
	struct mlx4_en_filter *filter = container_of(work,
						     struct mlx4_en_filter,
						     work);
	struct mlx4_en_priv *priv = filter->priv;
	struct mlx4_spec_list spec_tcp_udp = {
		.id = mlx4_ip_proto_to_trans_rule_id(filter->ip_proto),
		{
			.tcp_udp = {
				.dst_port = filter->dst_port,
				.dst_port_msk = (__force __be16)-1,
				.src_port = filter->src_port,
				.src_port_msk = (__force __be16)-1,
			},
		},
	};
	struct mlx4_spec_list spec_ip = {
		.id = MLX4_NET_TRANS_RULE_ID_IPV4,
		{
			.ipv4 = {
				.dst_ip = filter->dst_ip,
				.dst_ip_msk = (__force __be32)-1,
				.src_ip = filter->src_ip,
				.src_ip_msk = (__force __be32)-1,
			},
		},
	};
	struct mlx4_spec_list spec_eth = {
		.id = MLX4_NET_TRANS_RULE_ID_ETH,
	};
	struct mlx4_net_trans_rule rule = {
		.list = LIST_HEAD_INIT(rule.list),
		.queue_mode = MLX4_NET_TRANS_Q_LIFO,
		.exclusive = 1,
		.allow_loopback = 1,
		.promisc_mode = MLX4_FS_REGULAR,
		.port = priv->port,
		.priority = MLX4_DOMAIN_RFS,
	};
	int rc;
	__be64 mac_mask = cpu_to_be64(MLX4_MAC_MASK << 16);

	if (spec_tcp_udp.id >= MLX4_NET_TRANS_RULE_NUM) {
		en_warn(priv, "RFS: ignoring unsupported ip protocol (%d)\n",
			filter->ip_proto);
		goto ignore;
	}
	list_add_tail(&spec_eth.list, &rule.list);
	list_add_tail(&spec_ip.list, &rule.list);
	list_add_tail(&spec_tcp_udp.list, &rule.list);

	rule.qpn = priv->rss_map.qps[filter->rxq_index].qpn;
	memcpy(spec_eth.eth.dst_mac, priv->dev->dev_addr, ETH_ALEN);
	memcpy(spec_eth.eth.dst_mac_msk, &mac_mask, ETH_ALEN);

	filter->activated = 0;

	if (filter->reg_id) {
		rc = mlx4_flow_detach(priv->mdev->dev, filter->reg_id);
		if (rc && rc != -ENOENT)
			en_err(priv, "Error detaching flow. rc = %d\n", rc);
	}

	rc = mlx4_flow_attach(priv->mdev->dev, &rule, &filter->reg_id);
	if (rc)
		en_err(priv, "Error attaching flow. err = %d\n", rc);

ignore:
	mlx4_en_filter_rfs_expire(priv);

	filter->activated = 1;
}

static inline struct hlist_head *
filter_hash_bucket(struct mlx4_en_priv *priv, __be32 src_ip, __be32 dst_ip,
		   __be16 src_port, __be16 dst_port)
{
	unsigned long l;
	int bucket_idx;

	l = (__force unsigned long)src_port |
	    ((__force unsigned long)dst_port << 2);
	l ^= (__force unsigned long)(src_ip ^ dst_ip);

	bucket_idx = hash_long(l, MLX4_EN_FILTER_HASH_SHIFT);

	return &priv->filter_hash[bucket_idx];
}

static struct mlx4_en_filter *
mlx4_en_filter_alloc(struct mlx4_en_priv *priv, int rxq_index, __be32 src_ip,
		     __be32 dst_ip, u8 ip_proto, __be16 src_port,
		     __be16 dst_port, u32 flow_id)
{
	struct mlx4_en_filter *filter = NULL;

	filter = kzalloc(sizeof(struct mlx4_en_filter), GFP_ATOMIC);
	if (!filter)
		return NULL;

	filter->priv = priv;
	filter->rxq_index = rxq_index;
	INIT_WORK(&filter->work, mlx4_en_filter_work);

	filter->src_ip = src_ip;
	filter->dst_ip = dst_ip;
	filter->ip_proto = ip_proto;
	filter->src_port = src_port;
	filter->dst_port = dst_port;

	filter->flow_id = flow_id;

	filter->id = priv->last_filter_id++ % RPS_NO_FILTER;

	list_add_tail(&filter->next, &priv->filters);
	hlist_add_head(&filter->filter_chain,
		       filter_hash_bucket(priv, src_ip, dst_ip, src_port,
					  dst_port));

	return filter;
}

static void mlx4_en_filter_free(struct mlx4_en_filter *filter)
{
	struct mlx4_en_priv *priv = filter->priv;
	int rc;

	list_del(&filter->next);

	rc = mlx4_flow_detach(priv->mdev->dev, filter->reg_id);
	if (rc && rc != -ENOENT)
		en_err(priv, "Error detaching flow. rc = %d\n", rc);

	kfree(filter);
}

static inline struct mlx4_en_filter *
mlx4_en_filter_find(struct mlx4_en_priv *priv, __be32 src_ip, __be32 dst_ip,
		    u8 ip_proto, __be16 src_port, __be16 dst_port)
{
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
	struct hlist_node *hlnode;
#endif
	struct mlx4_en_filter *filter;
	struct mlx4_en_filter *ret = NULL;

	compat_hlist_for_each_entry(filter,
			     filter_hash_bucket(priv, src_ip, dst_ip,
						src_port, dst_port),
			     filter_chain) {
		if (filter->src_ip == src_ip &&
		    filter->dst_ip == dst_ip &&
		    filter->ip_proto == ip_proto &&
		    filter->src_port == src_port &&
		    filter->dst_port == dst_port) {
			ret = filter;
			break;
		}
	}

	return ret;
}

static int
mlx4_en_filter_rfs(struct net_device *net_dev, const struct sk_buff *skb,
		   u16 rxq_index, u32 flow_id)
{
	struct mlx4_en_priv *priv = netdev_priv(net_dev);
	struct mlx4_en_filter *filter;
	const struct iphdr *ip;
	const __be16 *ports;
	u8 ip_proto;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	int nhoff = skb_network_offset(skb);
	int ret = 0;

	if (skb->protocol != htons(ETH_P_IP))
		return -EPROTONOSUPPORT;

	ip = (const struct iphdr *)(skb->data + nhoff);
	if (ip_is_fragment(ip))
		return -EPROTONOSUPPORT;

	if ((ip->protocol != IPPROTO_TCP) && (ip->protocol != IPPROTO_UDP))
		return -EPROTONOSUPPORT;
	ports = (const __be16 *)(skb->data + nhoff + 4 * ip->ihl);

	ip_proto = ip->protocol;
	src_ip = ip->saddr;
	dst_ip = ip->daddr;
	src_port = ports[0];
	dst_port = ports[1];

	spin_lock_bh(&priv->filters_lock);
	filter = mlx4_en_filter_find(priv, src_ip, dst_ip, ip_proto,
				     src_port, dst_port);
	if (filter) {
		if (filter->rxq_index == rxq_index)
			goto out;

		filter->rxq_index = rxq_index;
	} else {
		filter = mlx4_en_filter_alloc(priv, rxq_index,
					      src_ip, dst_ip, ip_proto,
					      src_port, dst_port, flow_id);
		if (!filter) {
			ret = -ENOMEM;
			goto err;
		}
	}

	queue_work(priv->mdev->workqueue, &filter->work);

out:
	ret = filter->id;
err:
	spin_unlock_bh(&priv->filters_lock);

	return ret;
}

void mlx4_en_cleanup_filters(struct mlx4_en_priv *priv)
{
	struct mlx4_en_filter *filter, *tmp;
	LIST_HEAD(del_list);

	spin_lock_bh(&priv->filters_lock);
	list_for_each_entry_safe(filter, tmp, &priv->filters, next) {
		list_move(&filter->next, &del_list);
		hlist_del(&filter->filter_chain);
	}
	spin_unlock_bh(&priv->filters_lock);

	list_for_each_entry_safe(filter, tmp, &del_list, next) {
		cancel_work_sync(&filter->work);
		mlx4_en_filter_free(filter);
	}
}

static void mlx4_en_filter_rfs_expire(struct mlx4_en_priv *priv)
{
	struct mlx4_en_filter *filter = NULL, *tmp, *last_filter = NULL;
	LIST_HEAD(del_list);
	int i = 0;

	spin_lock_bh(&priv->filters_lock);
	list_for_each_entry_safe(filter, tmp, &priv->filters, next) {
		if (i > MLX4_EN_FILTER_EXPIRY_QUOTA)
			break;

		if (filter->activated &&
		    !work_pending(&filter->work) &&
		    rps_may_expire_flow(priv->dev,
					filter->rxq_index, filter->flow_id,
					filter->id)) {
			list_move(&filter->next, &del_list);
			hlist_del(&filter->filter_chain);
		} else
			last_filter = filter;

		i++;
	}

	if (last_filter && (&last_filter->next != priv->filters.next))
		list_move(&priv->filters, &last_filter->next);

	spin_unlock_bh(&priv->filters_lock);

	list_for_each_entry_safe(filter, tmp, &del_list, next)
		mlx4_en_filter_free(filter);
}
#endif
#endif

#ifdef HAVE_VLAN_GRO_RECEIVE
static void mlx4_en_vlan_rx_register(struct net_device *dev, struct vlan_group *grp)
{
        struct mlx4_en_priv *priv = netdev_priv(dev);

        en_dbg(HW, priv, "Registering VLAN group:%p\n", grp);
        priv->vlgrp = grp;
}
#endif

static void mlx4_en_remove_tx_rings_per_vlan(struct mlx4_en_priv *priv, int vid)
{
	struct mlx4_en_vgtp *vgtp = priv->vgtp;
	int i;
	int tx_ring = vgtp->tx_map[vid];

	if (tx_ring == -1)
		return;

	for (i = tx_ring; i <  tx_ring + priv->num_tx_rings_p_up; i++) {
		mlx4_en_deactivate_tx_ring(priv, vgtp->rings[i].tx_ring);
		mlx4_en_deactivate_cq(priv, vgtp->rings[i].cq);
		mlx4_en_destroy_tx_ring(priv, &vgtp->rings[i].tx_ring);
		mlx4_en_destroy_cq(priv, &vgtp->rings[i].cq);
	}

	vgtp->tx_map[vid] = -1;
}

int mlx4_en_vgtp_find_free_ix(struct mlx4_en_priv *priv)
{
	struct mlx4_en_vgtp *vgtp = priv->vgtp;
	int i;

	for (i = 0; i < MLX4_MAX_VLAN_SET_SIZE * MLX4_EN_MAX_TX_RING_P_UP;
	     i += priv->num_tx_rings_p_up) {
		if (!vgtp->rings[i].tx_ring)
			return i;
	}

	return -ENOMEM; /* FULL */
}

static int mlx4_en_add_tx_rings_per_vlan(struct mlx4_en_priv *priv,
					 u16 vid, int idx)
{
	struct net_device *dev = priv->dev;
	struct mlx4_en_port_profile *prof = priv->prof;
	struct mlx4_en_cq *cq;
	struct mlx4_en_tx_ring *tx_ring;
	struct mlx4_en_vgtp *vgtp = priv->vgtp;
	int err = 0;
	int i, j;
	int free_ix = mlx4_en_vgtp_find_free_ix(priv);

	if (free_ix < 0)
		return free_ix;

	en_dbg(HW, priv, "VGT+: Tx RINGs(%d) offset for VID(%d) = [%d]\n",
	       priv->num_tx_rings_p_up, vid, free_ix);

	for (i = 0; i < priv->num_tx_rings_p_up; i++) {
		int node = cpu_to_node(i % num_online_cpus());
		int ring_ix = free_ix + i;

		if (mlx4_en_create_cq(priv, &vgtp->rings[ring_ix].cq,
				      prof->tx_ring_size, ring_ix, TX, node)) {
			en_err(priv, "Failed to create Tx CQ\n");
			goto err;
		}

		if (mlx4_en_create_tx_ring(priv, &priv->vgtp->rings[ring_ix].tx_ring,
					   prof->tx_ring_size, TXBB_SIZE,
					   node, i)) {
			en_err(priv, "Failed to create Tx Ring\n");
			goto ring_err;
		}

		/* Configure cq */
		cq = vgtp->rings[ring_ix].cq;
		err = mlx4_en_activate_cq(priv, cq, i, true);
		if (err) {
			en_err(priv, "Failed to activate Tx CQ\n");
			goto tx_err;
		}
		err = mlx4_en_set_cq_moder(priv, cq);
		if (err) {
			en_err(priv, "Failed setting cq moderation parameters");
			goto cq_err;
		}
		en_dbg(DRV, priv,
		       "Resetting index of collapsed CQ:%d to -1\n", i);
		cq->buf->wqe_index = cpu_to_be16(0xffff);

		/* Configure ring */
		tx_ring = vgtp->rings[ring_ix].tx_ring;

#ifdef HAVE_NEW_TX_RING_SCHEME
		err = mlx4_en_activate_tx_ring(priv, tx_ring,
					       cq->mcq.cqn, 0, idx);
#else
		err = mlx4_en_activate_tx_ring(priv, tx_ring,
					       cq->mcq.cqn, idx);
#endif
		if (err) {
			en_err(priv, "Failed allocating Tx ring\n");
			goto cq_err;
		}
		tx_ring->tx_queue = netdev_get_tx_queue(dev, i);

		/* Arm CQ for TX completions */
		mlx4_en_arm_cq(priv, cq);

		/* Set initial ownership of all Tx TXBBs to SW (1) */
		for (j = 0; j < tx_ring->buf_size; j += STAMP_STRIDE)
			*((u32 *)(tx_ring->buf + j)) = 0xffffffff;
	}

	vgtp->tx_map[vid] = free_ix;
	return 0;

cq_err:
	mlx4_en_deactivate_cq(priv, priv->vgtp->rings[free_ix + i].cq);

tx_err:
	mlx4_en_destroy_tx_ring(priv, &priv->vgtp->rings[free_ix + i].tx_ring);

ring_err:
	mlx4_en_destroy_cq(priv, &priv->vgtp->rings[free_ix + i].cq);

err:
	en_err(priv, "Failed to allocate NIC resources per VLAN\n");
	for (j = 0; j < i; j++) {
		int ring_ix = free_ix + j;

		mlx4_en_deactivate_tx_ring(priv, priv->vgtp->rings[ring_ix].tx_ring);
		mlx4_en_deactivate_cq(priv, priv->vgtp->rings[ring_ix].cq);
		if (priv->vgtp->rings[ring_ix].tx_ring)
			mlx4_en_destroy_tx_ring(priv, &priv->vgtp->rings[ring_ix].tx_ring);
		if (priv->vgtp->rings[ring_ix].cq)
			mlx4_en_destroy_cq(priv, &priv->vgtp->rings[ring_ix].cq);
	}
	return -ENOMEM;
}

static int mlx4_en_vgtp_add_vid(struct net_device *dev, unsigned short vid)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int *qpn = &priv->base_qpn;
	u64 reg_id;
	int err;
	int vlan_idx;

	en_dbg(HW, priv, "VGT+: adding VLAN:%d\n", vid);
	if (!vid || !mdev->device_up || !priv->port_up)
		return 0;

	err = mlx4_register_vlan(mdev->dev, priv->port, vid, &vlan_idx);
	if (err) {
		en_err(priv,
		       "Failed to add VLAN %d due to VLAN policy\n",
		       vid);
		clear_bit(vid, priv->vgtp->bitmap);
		return err;
	}

	err = mlx4_en_uc_steer_add(priv, priv->dev->dev_addr,
				   qpn, &reg_id, vid);
	if (err) {
		en_err(priv, "Failed to open VLAN %hu\n", vid);
		goto uc_steer_add_err;
	}
	err = mlx4_en_add_tx_rings_per_vlan(priv, vid, vlan_idx);
	if (err) {
		en_err(priv, "Failed to create rings per VLAN\n");
		goto add_tx_rings_per_vlan_err;
	}
	priv->vgtp->rings[priv->vgtp->tx_map[vid]].reg_id = reg_id;

	return 0;

add_tx_rings_per_vlan_err:
	mlx4_en_uc_steer_release(priv, priv->dev->dev_addr, *qpn, reg_id);

uc_steer_add_err:
	mlx4_unregister_vlan(mdev->dev, priv->port, vid);
	clear_bit(vid, priv->vgtp->bitmap);

	return err;
}

#if defined(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS)
static int mlx4_en_vlan_rx_add_vid(struct net_device *dev,
				   __be16 proto, u16 vid)
#elif defined(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT)
static int mlx4_en_vlan_rx_add_vid(struct net_device *dev, unsigned short vid)
#else
static void mlx4_en_vlan_rx_add_vid(struct net_device *dev, unsigned short vid)
#endif
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int err = 0;
	int vlan_idx;

	en_dbg(HW, priv, "adding VLAN:%d\n", vid);

	set_bit(vid, priv->active_vlans);

	/* Add VID to port VLAN filter */
	mutex_lock(&mdev->state_lock);
	if (mdev->device_up && priv->port_up) {
		err = mlx4_SET_VLAN_FLTR(mdev->dev, priv);
		if (err)
			en_err(priv, "Failed configuring VLAN filter\n");
	}

	/* VGT+ */
	if (priv->vgtp && !test_and_set_bit(vid, priv->vgtp->bitmap)) {
		err = mlx4_en_vgtp_add_vid(priv->dev, vid);
		goto out;
	}

	err = mlx4_register_vlan(mdev->dev, priv->port, vid, &vlan_idx);
	if (err) {
		en_dbg(HW, priv, "failed adding vlan %d\n", vid);
		goto out;
	}

out:
	mutex_unlock(&mdev->state_lock);

#if (defined(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS) || \
     defined(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT))
	return err;
#endif
}


static int mlx4_en_vgtp_kill_vid(struct net_device *dev, unsigned short vid)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;

	en_dbg(HW, priv, "VGT+: Killing VID:%d\n", vid);

	if (!vid)
		return 0;

	mlx4_unregister_vlan(mdev->dev, priv->port, vid);
	mlx4_en_remove_tx_rings_per_vlan(priv, vid);

	return 0;
}

#if defined(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS)
static int mlx4_en_vlan_rx_kill_vid(struct net_device *dev,
				    __be16 proto, u16 vid)
#elif defined(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT)
static int mlx4_en_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
#else
static void mlx4_en_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
#endif
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_vgtp *vgtp = priv->vgtp;
	int err;

	en_dbg(HW, priv, "Killing VID:%d\n", vid);

	clear_bit(vid, priv->active_vlans);

	/* Remove VID from port VLAN filter */
	mutex_lock(&mdev->state_lock);
	mlx4_unregister_vlan(mdev->dev, priv->port, vid);

	if (mdev->device_up && priv->port_up) {
		err = mlx4_SET_VLAN_FLTR(mdev->dev, priv);
		if (err) {
			en_err(priv, "Failed configuring VLAN filter\n");
			goto out;
		}
	}

	/* VGT+ */
	if (priv->vgtp && mdev->device_up && priv->port_up) {
		int qpn = priv->base_qpn;
		u64 reg_id = priv->vgtp->rings[priv->vgtp->tx_map[vid]].reg_id;

		if (!test_and_clear_bit(vid, vgtp->bitmap)) {
			en_dbg(HW, priv,
			       "VGT+ trying to kill vid %d that doesn't exist\n", vid);
			goto out;
		}
		mlx4_en_remove_tx_rings_per_vlan(priv, vid);
		mlx4_en_uc_steer_release(priv, priv->dev->dev_addr,
					 qpn, reg_id);
	}

out:
	mutex_unlock(&mdev->state_lock);
#if (defined(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS) || \
     defined(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT))
	return 0;
#endif
}

int mlx4_en_vgtp_alloc_res(struct mlx4_en_priv *priv)
{
	struct mlx4_en_vgtp *vgtp = priv->vgtp;
	int i;

	for (i = 0; i < VLAN_N_VID; i++) {
		if (!test_bit(i, vgtp->bitmap))
			continue;

		mlx4_en_vgtp_add_vid(priv->dev, i);
	}

	return 0;
}

int mlx4_en_vgtp_destroy_res(struct mlx4_en_priv *priv)
{
	struct mlx4_en_vgtp *vgtp = priv->vgtp;
	int i;

	for (i = 0; i < VLAN_N_VID; i++) {
		if (!test_bit(i, vgtp->bitmap))
			continue;

		mlx4_en_vgtp_kill_vid(priv->dev, i);
	}

	return 0;
}

static void mlx4_en_u64_to_mac(unsigned char dst_mac[ETH_ALEN + 2], u64 src_mac)
{
	int i;
	for (i = ETH_ALEN - 1; i >= 0; --i) {
		dst_mac[i] = src_mac & 0xff;
		src_mac >>= 8;
	}
	memset(&dst_mac[ETH_ALEN], 0, 2);
}

static int mlx4_en_tunnel_steer_add(struct mlx4_en_priv *priv, unsigned char *addr,
				    int qpn, u64 *reg_id)
{
	int err;

	if (priv->mdev->dev->caps.tunnel_offload_mode != MLX4_TUNNEL_OFFLOAD_MODE_VXLAN ||
	    priv->mdev->dev->caps.dmfs_high_steer_mode == MLX4_STEERING_DMFS_A0_STATIC)
		return 0; /* do nothing */

	err = mlx4_tunnel_steer_add(priv->mdev->dev, addr, priv->port, qpn,
				    MLX4_DOMAIN_NIC, reg_id);
	if (err) {
		en_err(priv, "failed to add vxlan steering rule, err %d\n", err);
		return err;
	}
	en_dbg(DRV, priv, "added vxlan steering rule, mac %pM reg_id %llx\n", addr, *reg_id);
	return 0;
}

static int mlx4_en_uc_steer_add(struct mlx4_en_priv *priv,
				unsigned char *mac, int *qpn,
				u64 *reg_id, u16 vlan)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_dev *dev = mdev->dev;
	int err;

	switch (dev->caps.steering_mode) {
	case MLX4_STEERING_MODE_B0: {
		struct mlx4_qp qp;
		u8 gid[16] = {0};

		if (vlan != MLX4_EN_NO_VLAN) {
			en_err(priv, "Invalid parameter for current steering mode\n");
			err = -EINVAL;
			break;
		}
		qp.qpn = *qpn;
		memcpy(&gid[10], mac, ETH_ALEN);
		gid[5] = priv->port;

		err = mlx4_unicast_attach(dev, &qp, gid, 0, MLX4_PROT_ETH);
		break;
	}
	case MLX4_STEERING_MODE_DEVICE_MANAGED: {
		struct mlx4_spec_list spec_eth = { {NULL} };
		__be64 mac_mask = cpu_to_be64(MLX4_MAC_MASK << 16);

		struct mlx4_net_trans_rule rule = {
			.queue_mode = MLX4_NET_TRANS_Q_FIFO,
			.exclusive = 0,
			.allow_loopback = 1,
			.promisc_mode = MLX4_FS_REGULAR,
			.priority = MLX4_DOMAIN_NIC,
		};

		rule.port = priv->port;
		rule.qpn = *qpn;
		INIT_LIST_HEAD(&rule.list);

		spec_eth.id = MLX4_NET_TRANS_RULE_ID_ETH;
		memcpy(spec_eth.eth.dst_mac, mac, ETH_ALEN);
		memcpy(spec_eth.eth.dst_mac_msk, &mac_mask, ETH_ALEN);
		if (vlan != MLX4_EN_NO_VLAN) {
			spec_eth.eth.vlan_id = cpu_to_be16(vlan);
			spec_eth.eth.vlan_id_msk = cpu_to_be16(0xfff);
		}
		list_add_tail(&spec_eth.list, &rule.list);

		err = mlx4_flow_attach(dev, &rule, reg_id);
		break;
	}
	default:
		return -EINVAL;
	}
	if (err)
		en_warn(priv, "Failed Attaching Unicast\n");

	return err;
}

static void mlx4_en_uc_steer_release(struct mlx4_en_priv *priv,
				     unsigned char *mac, int qpn, u64 reg_id)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_dev *dev = mdev->dev;

	switch (dev->caps.steering_mode) {
	case MLX4_STEERING_MODE_B0: {
		struct mlx4_qp qp;
		u8 gid[16] = {0};

		qp.qpn = qpn;
		memcpy(&gid[10], mac, ETH_ALEN);
		gid[5] = priv->port;

		mlx4_unicast_detach(dev, &qp, gid, MLX4_PROT_ETH);
		break;
	}
	case MLX4_STEERING_MODE_DEVICE_MANAGED: {
		mlx4_flow_detach(dev, reg_id);
		break;
	}
	default:
		en_err(priv, "Invalid steering mode.\n");
	}
}

static int mlx4_en_get_qp(struct mlx4_en_priv *priv)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_dev *dev = mdev->dev;
	int index = 0;
	int err = 0;
	int *qpn = &priv->base_qpn;
	u64 mac = mlx4_mac_to_u64(priv->dev->dev_addr);

	en_dbg(DRV, priv, "Registering MAC: %pM for adding\n",
	       priv->dev->dev_addr);
	index = mlx4_register_mac(dev, priv->port, mac);
	if (index < 0) {
		err = index;
		en_err(priv, "Failed adding MAC: %pM\n",
		       priv->dev->dev_addr);
		return err;
	}

	if (dev->caps.steering_mode == MLX4_STEERING_MODE_A0) {
		int base_qpn = mlx4_get_base_qpn(dev, priv->port);
		*qpn = base_qpn + index;
		return 0;
	}

	err = mlx4_qp_reserve_range(dev, 1, 1, qpn, MLX4_RESERVE_A0_QP);
	en_dbg(DRV, priv, "Reserved qp %d\n", *qpn);
	if (err) {
		en_err(priv, "Failed to reserve qp for mac registration\n");
		mlx4_unregister_mac(dev, priv->port, mac);
		return err;
	}

	return 0;
}

static void mlx4_en_put_qp(struct mlx4_en_priv *priv)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_dev *dev = mdev->dev;
	int qpn = priv->base_qpn;

	if (dev->caps.steering_mode == MLX4_STEERING_MODE_A0) {
		u64 mac = mlx4_mac_to_u64(priv->dev->dev_addr);
		en_dbg(DRV, priv, "Registering MAC: %pM for deleting\n",
		       priv->dev->dev_addr);
		mlx4_unregister_mac(dev, priv->port, mac);
	} else {
		en_dbg(DRV, priv, "Releasing qp: port %d, qpn %d\n",
		       priv->port, qpn);
		mlx4_qp_release_range(dev, qpn, 1);
		priv->flags &= ~MLX4_EN_FLAG_FORCE_PROMISC;
	}
}

static int mlx4_en_replace_mac(struct mlx4_en_priv *priv, int qpn,
			       unsigned char *new_mac, unsigned char *prev_mac)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_dev *dev = mdev->dev;
	int err = 0;
	u64 new_mac_u64 = mlx4_mac_to_u64(new_mac);

	if (dev->caps.steering_mode != MLX4_STEERING_MODE_A0) {
		struct hlist_head *bucket;
		unsigned int mac_hash;
		struct mlx4_mac_entry *entry;
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
		struct hlist_node *hlnode;
#endif
		struct hlist_node *tmp;
		u64 prev_mac_u64 = mlx4_mac_to_u64(prev_mac);

		bucket = &priv->mac_hash[prev_mac[MLX4_EN_MAC_HASH_IDX]];
		compat_hlist_for_each_entry_safe(entry, tmp, bucket, hlist) {
			if (ether_addr_equal_64bits(entry->mac, prev_mac)) {
				mlx4_en_uc_steer_release(priv, entry->mac,
							 qpn, entry->reg_id);
				mlx4_unregister_mac(dev, priv->port,
						    prev_mac_u64);
				hlist_del_rcu(&entry->hlist);
				synchronize_rcu();
				memcpy(entry->mac, new_mac, ETH_ALEN);
				entry->reg_id = 0;
				mac_hash = new_mac[MLX4_EN_MAC_HASH_IDX];
				hlist_add_head_rcu(&entry->hlist,
						   &priv->mac_hash[mac_hash]);
				err = mlx4_register_mac(dev, priv->port,
							new_mac_u64);
				if (err < 0)
					return err;
				err = mlx4_en_uc_steer_add(priv, new_mac,
							   &qpn,
							   &entry->reg_id,
							   MLX4_EN_NO_VLAN);
				if (err)
					return err;
				if (priv->tunnel_reg_id) {
					mlx4_flow_detach(priv->mdev->dev, priv->tunnel_reg_id);
					priv->tunnel_reg_id = 0;
				}
				err = mlx4_en_tunnel_steer_add(priv, new_mac, qpn,
							       &priv->tunnel_reg_id);
				return err;
			}
		}
		return -EINVAL;
	}

	return __mlx4_replace_mac(dev, priv->port, qpn, new_mac_u64);
}

static int mlx4_en_do_set_mac(struct mlx4_en_priv *priv,
			      unsigned char new_mac[ETH_ALEN + 2])
{
	int err = 0;

	if (priv->port_up) {
		/* Remove old MAC and insert the new one */
		err = mlx4_en_replace_mac(priv, priv->base_qpn,
					  new_mac, priv->current_mac);
		if (err)
			en_err(priv, "Failed changing HW MAC address\n");
	} else
		en_dbg(HW, priv, "Port is down while registering mac, exiting...\n");

	if (!err)
		memcpy(priv->current_mac, new_mac, sizeof(priv->current_mac));

	return err;
}

static int mlx4_en_set_mac(struct net_device *dev, void *addr)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct sockaddr *saddr = addr;
	unsigned char new_mac[ETH_ALEN + 2];
	int err;

	if (!is_valid_ether_addr(saddr->sa_data))
		return -EADDRNOTAVAIL;

	mutex_lock(&mdev->state_lock);
	memcpy(new_mac, saddr->sa_data, ETH_ALEN);
	err = mlx4_en_do_set_mac(priv, new_mac);
	if (!err)
		memcpy(dev->dev_addr, saddr->sa_data, ETH_ALEN);
	mutex_unlock(&mdev->state_lock);

	return err;
}

static void mlx4_en_clear_list(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_mc_list *tmp, *mc_to_del;

	list_for_each_entry_safe(mc_to_del, tmp, &priv->mc_list, list) {
		list_del(&mc_to_del->list);
		kfree(mc_to_del);
	}
}

static void mlx4_en_cache_mclist(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
#ifdef HAVE_NETDEV_FOR_EACH_MC_ADDR
	struct netdev_hw_addr *ha;
#else
	struct dev_mc_list *mclist;
#endif
	struct mlx4_en_mc_list *tmp;

	mlx4_en_clear_list(dev);
#ifdef HAVE_NETDEV_FOR_EACH_MC_ADDR
	netdev_for_each_mc_addr(ha, dev) {
#else
	for (mclist = dev->mc_list; mclist; mclist = mclist->next) {
#endif
		tmp = kzalloc(sizeof(struct mlx4_en_mc_list), GFP_ATOMIC);
		if (!tmp) {
			mlx4_en_clear_list(dev);
			return;
		}
#ifdef HAVE_NETDEV_FOR_EACH_MC_ADDR
		memcpy(tmp->addr, ha->addr, ETH_ALEN);
#else
		memcpy(tmp->addr, mclist->dmi_addr, ETH_ALEN);
#endif
		list_add_tail(&tmp->list, &priv->mc_list);
	}
}

static void update_mclist_flags(struct mlx4_en_priv *priv,
				struct list_head *dst,
				struct list_head *src)
{
	struct mlx4_en_mc_list *dst_tmp, *src_tmp, *new_mc;
	bool found;

	/* Find all the entries that should be removed from dst,
	 * These are the entries that are not found in src
	 */
	list_for_each_entry(dst_tmp, dst, list) {
		found = false;
		list_for_each_entry(src_tmp, src, list) {
			if (ether_addr_equal(dst_tmp->addr, src_tmp->addr)) {
				found = true;
				break;
			}
		}
		if (!found)
			dst_tmp->action = MCLIST_REM;
	}

	/* Add entries that exist in src but not in dst
	 * mark them as need to add
	 */
	list_for_each_entry(src_tmp, src, list) {
		found = false;
		list_for_each_entry(dst_tmp, dst, list) {
			if (ether_addr_equal(dst_tmp->addr, src_tmp->addr)) {
				dst_tmp->action = MCLIST_NONE;
				found = true;
				break;
			}
		}
		if (!found) {
			new_mc = kmemdup(src_tmp,
					 sizeof(struct mlx4_en_mc_list),
					 GFP_KERNEL);
			if (!new_mc)
				return;

			new_mc->action = MCLIST_ADD;
			list_add_tail(&new_mc->list, dst);
		}
	}
}

int mlx4_en_check_is_available_mac(struct mlx4_en_dev *mdev, int port)
{
	int max_macs = mlx4_get_port_max_macs(mdev->dev, port);
	int total = mlx4_get_port_total_macs(mdev->dev, port);
	int free_macs = mlx4_get_port_free_macs(mdev->dev, port);

	mlx4_info(mdev, "%s Checking available mac.port: %d. (max: %d, total:%d, free: %d)\n",
		  __func__, port, max_macs, total, free_macs);
	if (free_macs <= 1) {
		mlx4_warn(mdev, "No Available mac. already %d macs (max: %d) free_macs: %d\n",
			  total, max_macs, free_macs);
		return 0;
	}
	return 1;
}

static void mlx4_en_set_rx_mode(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);

	if (!priv->port_up)
		return;

	queue_work(priv->mdev->workqueue, &priv->rx_mode_task);
}

static void mlx4_en_set_mc_promisc_mode(struct mlx4_en_priv *priv,
					struct mlx4_en_dev *mdev)
{
	int err;

	if (priv->flags & MLX4_EN_FLAG_MC_PROMISC)
		return;

	err = mlx4_SET_MCAST_FLTR(mdev->dev, priv->port, 0,
				  0, MLX4_MCAST_DISABLE);
	if (err)
		en_err(priv, "Failed disabling multicast filter\n");

	/* Add the default qp number as multicast promisc */
	switch (mdev->dev->caps.steering_mode) {
	case MLX4_STEERING_MODE_DEVICE_MANAGED:
		err = mlx4_flow_steer_promisc_add(mdev->dev,
						  priv->port,
						  priv->base_qpn,
						  MLX4_FS_MC_DEFAULT);
		break;

	case MLX4_STEERING_MODE_B0:
		err = mlx4_multicast_promisc_add(mdev->dev,
						 priv->base_qpn,
						 priv->port);
		break;

	case MLX4_STEERING_MODE_A0:
		break;
	}

	if (err) {
		en_err(priv, "Failed entering multicast promisc mode\n");
	} else {
		priv->flags |= MLX4_EN_FLAG_MC_PROMISC;
	}
}

static void mlx4_en_set_promisc_mode(struct mlx4_en_priv *priv,
				     struct mlx4_en_dev *mdev)
{
	int err = 0;

	/* promisc already set in the HW */
	if (priv->flags & MLX4_EN_FLAG_PROMISC)
		return;

	if (netif_msg_rx_status(priv))
		en_warn(priv, "Entering promiscuous mode\n");

	/* Enable promiscouos mode */
	switch (mdev->dev->caps.steering_mode) {
	case MLX4_STEERING_MODE_DEVICE_MANAGED:
		err = mlx4_flow_steer_promisc_add(mdev->dev,
						  priv->port,
						  priv->base_qpn,
						  MLX4_FS_ALL_DEFAULT);
		if (err) {
			en_err(priv, "Failed enabling promiscuous mode\n");
		} else {
			priv->flags |= MLX4_EN_FLAG_PROMISC;
		}
		break;

	case MLX4_STEERING_MODE_B0:
		err = mlx4_unicast_promisc_add(mdev->dev,
					       priv->base_qpn,
					       priv->port);
		if (err) {
			en_err(priv, "Failed enabling unicast promiscuous mode\n");
		} else {
			priv->flags |= MLX4_EN_FLAG_PROMISC;
		}

		/* Add the default qp number as multicast
		 * promisc
		 */
		if (!(priv->flags & MLX4_EN_FLAG_MC_PROMISC)) {
			err = mlx4_multicast_promisc_add(mdev->dev,
							 priv->base_qpn,
							 priv->port);
			if (err) {
				en_err(priv, "Failed enabling multicast promiscuous mode\n");
			} else {
				priv->flags |= MLX4_EN_FLAG_MC_PROMISC;
			}
		}
		break;

	case MLX4_STEERING_MODE_A0:
		err = mlx4_SET_PORT_qpn_calc(mdev->dev,
					     priv->port,
					     priv->base_qpn,
					     1);
		if (err) {
			en_err(priv, "Failed enabling promiscuous mode\n");
		} else {
			priv->flags |= MLX4_EN_FLAG_PROMISC;
		}
		break;
	}

	/* Disable port multicast filter (unconditionally) */
	err = mlx4_SET_MCAST_FLTR(mdev->dev, priv->port, 0,
				  0, MLX4_MCAST_DISABLE);
	if (err) {
		en_err(priv, "Failed disabling multicast filter\n");
		return;
	}
}

static void mlx4_en_clear_mc_promisc_mode(struct mlx4_en_priv *priv,
					  struct mlx4_en_dev *mdev)
{
	/* err can be uninitialized if non of the cases are match,
	 * and this is a bug
	 */
	int err = 1;

	/* HW not set for mc promisc */
	if (!(priv->flags & MLX4_EN_FLAG_MC_PROMISC))
		return;

	switch (mdev->dev->caps.steering_mode) {
	case MLX4_STEERING_MODE_DEVICE_MANAGED:
		err = mlx4_flow_steer_promisc_remove(mdev->dev,
						     priv->port,
						     MLX4_FS_MC_DEFAULT);
		break;

	case MLX4_STEERING_MODE_B0:
		err = mlx4_multicast_promisc_remove(mdev->dev,
						    priv->base_qpn,
						    priv->port);
		break;

	case MLX4_STEERING_MODE_A0:
		break;
	}

	if (err) {
		en_err(priv, "Failed disabling multicast promiscuous mode\n");
	} else {
		priv->flags &= ~MLX4_EN_FLAG_MC_PROMISC;
	}

}

static void mlx4_en_clear_promisc_mode(struct mlx4_en_priv *priv,
				       struct mlx4_en_dev *mdev)
{
	int err = 0;

	/* Promisc not set in the HW, there is nothing to clean */

	if (netif_msg_rx_status(priv))
		en_warn(priv, "Leaving promiscuous mode\n");

	/* Disable promiscouos mode */
	switch (mdev->dev->caps.steering_mode) {
	case MLX4_STEERING_MODE_DEVICE_MANAGED:
		if (!(priv->flags & MLX4_EN_FLAG_PROMISC))
			break;
		err = mlx4_flow_steer_promisc_remove(mdev->dev,
						     priv->port,
						     MLX4_FS_ALL_DEFAULT);
		if (err) {
			en_err(priv, "Failed disabling promiscuous mode\n");
		} else {
			priv->flags &= ~MLX4_EN_FLAG_PROMISC;
		}
		break;

	case MLX4_STEERING_MODE_B0:
		if ((priv->flags & MLX4_EN_FLAG_PROMISC)) {
			err = mlx4_unicast_promisc_remove(mdev->dev, priv->base_qpn,
							  priv->port);
			if (err) {
				en_err(priv, "Failed disabling unicast promiscuous mode\n");
			} else {
				priv->flags &= ~MLX4_EN_FLAG_PROMISC;
			}
		}
		/* Disable Multicast promisc */
		if (priv->flags & MLX4_EN_FLAG_MC_PROMISC) {
			err = mlx4_multicast_promisc_remove(mdev->dev, priv->base_qpn,
							    priv->port);
			if (err) {
				en_err(priv, "Failed disabling multicast promiscuous mode\n");
			} else {
				priv->flags &= ~MLX4_EN_FLAG_MC_PROMISC;
			}
		}
		break;

	case MLX4_STEERING_MODE_A0:
		if ((priv->flags & MLX4_EN_FLAG_PROMISC)) {
			err = mlx4_SET_PORT_qpn_calc(mdev->dev, priv->port,
						     priv->base_qpn, 0);
			if (err) {
				en_err(priv, "Failed disabling promiscuous mode\n");
			} else {
				priv->flags &= ~MLX4_EN_FLAG_PROMISC;
			}
		}
		break;
	}
}

static void mlx4_en_do_multicast(struct mlx4_en_priv *priv,
				 struct net_device *dev,
				 struct mlx4_en_dev *mdev)
{
	struct mlx4_en_mc_list *mclist, *tmp;
	u64 mcast_addr = 0;
	u8 mc_list[16] = {0};
	int err = 0;


	err = mlx4_SET_MCAST_FLTR(mdev->dev, priv->port, 0,
				  0, MLX4_MCAST_DISABLE);
	if (err)
		en_err(priv, "Failed disabling multicast filter\n");

	/* Flush mcast filter and init it with broadcast address */
	mlx4_SET_MCAST_FLTR(mdev->dev, priv->port, ETH_BCAST,
			    1, MLX4_MCAST_CONFIG);
	/* Update multicast list - we cache all addresses so they won't
	 * change while HW is updated holding the command semaphor
	 */
	netif_addr_lock_bh(dev);
	mlx4_en_cache_mclist(dev);
	netif_addr_unlock_bh(dev);
	list_for_each_entry(mclist, &priv->mc_list, list) {
		mcast_addr = mlx4_mac_to_u64(mclist->addr);
		mlx4_SET_MCAST_FLTR(mdev->dev, priv->port,
				    mcast_addr, 0, MLX4_MCAST_CONFIG);
	}
	err = mlx4_SET_MCAST_FLTR(mdev->dev, priv->port, 0,
				  0, MLX4_MCAST_ENABLE);
	if (err)
		en_err(priv, "Failed enabling multicast filter\n");

	update_mclist_flags(priv, &priv->curr_list, &priv->mc_list);
	list_for_each_entry_safe(mclist, tmp, &priv->curr_list, list) {
		if (mclist->action == MCLIST_REM) {
			/* detach this address and delete from list */
			memcpy(&mc_list[10], mclist->addr, ETH_ALEN);
			mc_list[5] = priv->port;
			err = mlx4_multicast_detach(mdev->dev,
						    &priv->rss_map.indir_qp,
						    mc_list,
						    MLX4_PROT_ETH,
						    mclist->reg_id);
			if (err)
				en_err(priv, "Fail to detach multicast address\n");

			if (mclist->tunnel_reg_id) {
				err = mlx4_flow_detach(priv->mdev->dev, mclist->tunnel_reg_id);
				if (err)
					en_err(priv, "Failed to detach multicast address\n");
			}

			/* remove from list */
			list_del(&mclist->list);
			kfree(mclist);
		} else if (mclist->action == MCLIST_ADD) {
			/* attach the address */
			memcpy(&mc_list[10], mclist->addr, ETH_ALEN);
			/* needed for B0 steering support */
			mc_list[5] = priv->port;
			err = mlx4_multicast_attach(mdev->dev,
						    &priv->rss_map.indir_qp,
						    mc_list,
						    priv->port, 0,
						    MLX4_PROT_ETH,
						    &mclist->reg_id);
			if (err)
				en_err(priv, "Fail to attach multicast address\n");

			err = mlx4_en_tunnel_steer_add(priv, &mc_list[10], priv->base_qpn,
						       &mclist->tunnel_reg_id);
			if (err)
				en_err(priv, "Failed to attach multicast address\n");
		}
	}
}

static void mlx4_en_do_uc_filter(struct mlx4_en_priv *priv,
				 struct net_device *dev,
				 struct mlx4_en_dev *mdev)
{
	struct netdev_hw_addr *ha;
	struct mlx4_mac_entry *entry;
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
	struct hlist_node *hlnode;
#endif
	struct hlist_node *tmp;
	bool found;
	u64 mac;
	int err = 0;
	struct hlist_head *bucket;
	unsigned int i;
	int removed = 0;
	u32 prev_flags;

	/* Note that we do not need to protect our mac_hash traversal with rcu,
	 * since all modification code is protected by mdev->state_lock
	 */

	/* find what to remove */
	for (i = 0; i < MLX4_EN_MAC_HASH_SIZE; ++i) {
		bucket = &priv->mac_hash[i];
		compat_hlist_for_each_entry_safe(entry, tmp, bucket, hlist) {
			found = false;
			netdev_for_each_uc_addr(ha, dev) {
				if (ether_addr_equal_64bits(entry->mac,
							    ha->addr)) {
					found = true;
					break;
				}
			}

			/* MAC address of the port is not in uc list */
			if (ether_addr_equal_64bits(entry->mac,
						    priv->current_mac))
				found = true;

			if (!found) {
				mac = mlx4_mac_to_u64(entry->mac);
				mlx4_en_uc_steer_release(priv, entry->mac,
							 priv->base_qpn,
							 entry->reg_id);
				mlx4_unregister_mac(mdev->dev, priv->port, mac);

				hlist_del_rcu(&entry->hlist);
				kfree_rcu(entry, rcu);
				en_dbg(DRV, priv, "Removed MAC %pM on port:%d\n",
				       entry->mac, priv->port);
				++removed;
			}
		}
	}

	/* if we didn't remove anything, there is no use in trying to add
	 * again once we are in a forced promisc mode state
	 */
	if ((priv->flags & MLX4_EN_FLAG_FORCE_PROMISC) && 0 == removed)
		return;

	prev_flags = priv->flags;
	priv->flags &= ~MLX4_EN_FLAG_FORCE_PROMISC;

	/* find what to add */
	netdev_for_each_uc_addr(ha, dev) {
		found = false;
		bucket = &priv->mac_hash[ha->addr[MLX4_EN_MAC_HASH_IDX]];
		compat_hlist_for_each_entry(entry, bucket, hlist) {
			if (ether_addr_equal_64bits(entry->mac, ha->addr)) {
				found = true;
				break;
			}
		}

		if (!found) {
			entry = kmalloc(sizeof(*entry), GFP_KERNEL);
			if (!entry) {
				en_err(priv, "Failed adding MAC %pM on port:%d (out of memory)\n",
				       ha->addr, priv->port);
				priv->flags |= MLX4_EN_FLAG_FORCE_PROMISC;
				break;
			}
			mac = mlx4_mac_to_u64(ha->addr);
			memcpy(entry->mac, ha->addr, ETH_ALEN);

			if (!mlx4_en_check_is_available_mac(priv->mdev, priv->port)) {
				mlx4_warn(priv->mdev, "Cannot add mac:%pM, no free macs.\n", &mac);
				break;
			}

			err = mlx4_register_mac(mdev->dev, priv->port, mac);
			if (err < 0) {
				en_err(priv, "Failed registering MAC %pM on port %d: %d\n",
				       ha->addr, priv->port, err);
				kfree(entry);
				priv->flags |= MLX4_EN_FLAG_FORCE_PROMISC;
				break;
			}
			err = mlx4_en_uc_steer_add(priv, ha->addr,
						   &priv->base_qpn,
						   &entry->reg_id,
						   MLX4_EN_NO_VLAN);
			if (err) {
				en_err(priv, "Failed adding MAC %pM on port %d: %d\n",
				       ha->addr, priv->port, err);
				mlx4_unregister_mac(mdev->dev, priv->port, mac);
				kfree(entry);
				priv->flags |= MLX4_EN_FLAG_FORCE_PROMISC;
				break;
			} else {
				unsigned int mac_hash;
				en_dbg(DRV, priv, "Added MAC %pM on port:%d\n",
				       ha->addr, priv->port);
				mac_hash = ha->addr[MLX4_EN_MAC_HASH_IDX];
				bucket = &priv->mac_hash[mac_hash];
				hlist_add_head_rcu(&entry->hlist, bucket);
			}
		}
	}

	if (priv->flags & MLX4_EN_FLAG_FORCE_PROMISC) {
		en_warn(priv, "Forcing promiscuous mode on port:%d\n",
			priv->port);
	} else if (prev_flags & MLX4_EN_FLAG_FORCE_PROMISC) {
		en_warn(priv, "Stop forcing promiscuous mode on port:%d\n",
			priv->port);
	}
}

static void mlx4_en_do_set_rx_mode(struct work_struct *work)
{
	struct mlx4_en_priv *priv = container_of(work, struct mlx4_en_priv,
						 rx_mode_task);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct net_device *dev = priv->dev;
	int promisc = 0;

	mutex_lock(&mdev->state_lock);
	if (!mdev->device_up) {
		en_dbg(HW, priv, "Card is not up, ignoring rx mode change.\n");
		goto out;
	}
	if (!priv->port_up) {
		en_dbg(HW, priv, "Port is down, ignoring rx mode change.\n");
		goto out;
	}

	if (!netif_carrier_ok(dev)) {
		if (!mlx4_en_QUERY_PORT(mdev, priv->port)) {
			if (priv->port_state.link_state) {
				priv->last_link_state = MLX4_DEV_EVENT_PORT_UP;
				netif_carrier_on(dev);
				en_dbg(LINK, priv, "Link Up\n");
			}
		}
	}

#ifdef HAVE_NETDEV_IFF_UNICAST_FLT
	if (dev->priv_flags & IFF_UNICAST_FLT)
#else
	if (mdev->dev->caps.steering_mode != MLX4_STEERING_MODE_A0)
#endif
		mlx4_en_do_uc_filter(priv, dev, mdev);

	promisc = (dev->flags & IFF_PROMISC) ||
		  (priv->flags & MLX4_EN_FLAG_FORCE_PROMISC);

	if (promisc)
		mlx4_en_set_promisc_mode(priv, mdev);
	else
		mlx4_en_clear_promisc_mode(priv, mdev);

	if (!promisc) {
		if (dev->flags & IFF_ALLMULTI)
			mlx4_en_set_mc_promisc_mode(priv, mdev);
		else
			mlx4_en_clear_mc_promisc_mode(priv, mdev);
	}

	mlx4_en_do_multicast(priv, dev, mdev);

out:
	mutex_unlock(&mdev->state_lock);
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void mlx4_en_netpoll(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_cq *cq;
	int i;

	for (i = 0; i < priv->rx_ring_num; i++) {
		cq = priv->rx_cq[i];
		napi_schedule(&cq->napi);
	}
}
#endif

static int mlx4_en_set_rss_steer_rules(struct mlx4_en_priv *priv)
{
	u64 reg_id;
	int err = 0;
	int *qpn = &priv->base_qpn;
	struct mlx4_mac_entry *entry;

	err = mlx4_en_uc_steer_add(priv, priv->dev->dev_addr,
				   qpn, &reg_id, MLX4_EN_NO_VLAN);
	if (err)
		return err;

	err = mlx4_en_tunnel_steer_add(priv, priv->dev->dev_addr, *qpn,
				       &priv->tunnel_reg_id);
	if (err)
		goto tunnel_err;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		err = -ENOMEM;
		goto alloc_err;
	}

	memcpy(entry->mac, priv->dev->dev_addr, sizeof(entry->mac));
	memcpy(priv->current_mac, entry->mac, sizeof(priv->current_mac));
	entry->reg_id = reg_id;
	hlist_add_head_rcu(&entry->hlist,
			   &priv->mac_hash[entry->mac[MLX4_EN_MAC_HASH_IDX]]);

	return 0;

alloc_err:
	if (priv->tunnel_reg_id)
		mlx4_flow_detach(priv->mdev->dev, priv->tunnel_reg_id);

tunnel_err:
	mlx4_en_uc_steer_release(priv, priv->dev->dev_addr, *qpn, reg_id);
	return err;
}

static void mlx4_en_delete_rss_steer_rules(struct mlx4_en_priv *priv)
{
	u64 mac;
	unsigned int i;
	int qpn = priv->base_qpn;
	struct hlist_head *bucket;
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
	struct hlist_node *hlnode;
#endif
	struct hlist_node *tmp;
	struct mlx4_mac_entry *entry;

	for (i = 0; i < MLX4_EN_MAC_HASH_SIZE; ++i) {
		bucket = &priv->mac_hash[i];
		compat_hlist_for_each_entry_safe(entry, tmp, bucket, hlist) {
			mac = mlx4_mac_to_u64(entry->mac);
			en_dbg(DRV, priv, "Registering MAC:%pM for deleting\n",
			       entry->mac);
			mlx4_en_uc_steer_release(priv, entry->mac,
						 qpn, entry->reg_id);

			mlx4_unregister_mac(priv->mdev->dev, priv->port, mac);
			hlist_del_rcu(&entry->hlist);
			kfree_rcu(entry, rcu);
		}
	}

	if (priv->tunnel_reg_id) {
		mlx4_flow_detach(priv->mdev->dev, priv->tunnel_reg_id);
		priv->tunnel_reg_id = 0;
	}
}

static void mlx4_en_tx_timeout(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int i;

	if (netif_msg_timer(priv))
		en_warn(priv, "Tx timeout called on port:%d\n", priv->port);

	for (i = 0; i < priv->tx_ring_num; i++) {
		if (!netif_tx_queue_stopped(netdev_get_tx_queue(dev, i)))
			continue;
		en_warn(priv, "TX timeout on queue: %d, QP: 0x%x, CQ: 0x%x, Cons: 0x%x, Prod: 0x%x\n",
			i, priv->tx_ring[i]->qpn, priv->tx_ring[i]->cqn,
			priv->tx_ring[i]->cons, priv->tx_ring[i]->prod);
	}

	priv->port_stats.tx_timeout++;
	en_dbg(DRV, priv, "Scheduling watchdog\n");
	queue_work(mdev->workqueue, &priv->watchdog_task);
}


static struct net_device_stats *mlx4_en_get_stats(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);

	spin_lock_bh(&priv->stats_lock);
	memcpy(&priv->ret_stats, &priv->stats, sizeof(priv->stats));
	spin_unlock_bh(&priv->stats_lock);

	return &priv->ret_stats;
}

static void mlx4_en_set_default_moderation(struct mlx4_en_priv *priv)
{
	struct mlx4_en_cq *cq;
	int i;

	/* If we haven't received a specific coalescing setting
	 * (module param), we set the moderation parameters as follows:
	 * - moder_cnt is set to the number of mtu sized packets to
	 *   satisfy our coalescing target.
	 * - moder_time is set to a fixed value.
	 */
	priv->rx_frames = MLX4_EN_RX_COAL_TARGET;
	priv->rx_usecs = MLX4_EN_RX_COAL_TIME;
	priv->tx_frames = MLX4_EN_TX_COAL_PKTS;
	priv->tx_usecs = MLX4_EN_TX_COAL_TIME;
	en_dbg(INTR, priv, "Default coalesing params for mtu:%d - rx_frames:%d rx_usecs:%d\n",
	       priv->dev->mtu, priv->rx_frames, priv->rx_usecs);

	/* Setup cq moderation params */
	for (i = 0; i < priv->rx_ring_num; i++) {
		cq = priv->rx_cq[i];
		cq->moder_cnt = priv->rx_frames;
		cq->moder_time = priv->rx_usecs;
		priv->last_moder_time[i] = MLX4_EN_AUTO_CONF;
		priv->last_moder_packets[i] = 0;
		priv->last_moder_bytes[i] = 0;
	}

	for (i = 0; i < priv->tx_ring_num; i++) {
		cq = priv->tx_cq[i];
		cq->moder_cnt = priv->tx_frames;
		cq->moder_time = priv->tx_usecs;
	}

	/* Reset auto-moderation params */
	priv->pkt_rate_low = MLX4_EN_RX_RATE_LOW;
	priv->rx_usecs_low = MLX4_EN_RX_COAL_TIME_LOW;
	priv->pkt_rate_high = MLX4_EN_RX_RATE_HIGH;
	priv->rx_usecs_high = MLX4_EN_RX_COAL_TIME_HIGH;
	priv->sample_interval = MLX4_EN_SAMPLE_INTERVAL;
	priv->adaptive_rx_coal = 1;
	priv->last_moder_jiffies = 0;
	priv->last_moder_tx_packets = 0;
}

static void mlx4_en_auto_moderation(struct mlx4_en_priv *priv)
{
	unsigned long period = (unsigned long) (jiffies - priv->last_moder_jiffies);
	struct mlx4_en_cq *cq;
	unsigned long packets;
	unsigned long rate;
	unsigned long avg_pkt_size;
	unsigned long rx_packets;
	unsigned long rx_bytes;
	unsigned long rx_pkt_diff;
	int moder_time;
	int ring, err;

	if (!priv->adaptive_rx_coal || period < priv->sample_interval * HZ)
		return;

	for (ring = 0; ring < priv->rx_ring_num; ring++) {
		spin_lock_bh(&priv->stats_lock);
		rx_packets = priv->rx_ring[ring]->packets;
		rx_bytes = priv->rx_ring[ring]->bytes;
		spin_unlock_bh(&priv->stats_lock);

		rx_pkt_diff = ((unsigned long) (rx_packets -
				priv->last_moder_packets[ring]));
		packets = rx_pkt_diff;
		rate = packets * HZ / period;
		avg_pkt_size = packets ? ((unsigned long) (rx_bytes -
				priv->last_moder_bytes[ring])) / packets : 0;

		/* Apply auto-moderation only when packet rate
		 * exceeds a rate that it matters */
		if (rate > (MLX4_EN_RX_RATE_THRESH / priv->rx_ring_num) &&
		    avg_pkt_size > MLX4_EN_AVG_PKT_SMALL) {
			if (rate < priv->pkt_rate_low)
				moder_time = priv->rx_usecs_low;
			else if (rate > priv->pkt_rate_high)
				moder_time = priv->rx_usecs_high;
			else
				moder_time = (rate - priv->pkt_rate_low) *
					(priv->rx_usecs_high - priv->rx_usecs_low) /
					(priv->pkt_rate_high - priv->pkt_rate_low) +
					priv->rx_usecs_low;
		} else {
			moder_time = priv->rx_usecs_low;
		}

		if (moder_time != priv->last_moder_time[ring]) {
			priv->last_moder_time[ring] = moder_time;
			cq = priv->rx_cq[ring];
			cq->moder_time = moder_time;
			cq->moder_cnt = priv->rx_frames;
			err = mlx4_en_set_cq_moder(priv, cq);
			if (err)
				en_err(priv, "Failed modifying moderation for cq:%d\n",
				       ring);
		}
		priv->last_moder_packets[ring] = rx_packets;
		priv->last_moder_bytes[ring] = rx_bytes;
	}

	priv->last_moder_jiffies = jiffies;
}

static void mlx4_en_do_get_stats(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct mlx4_en_priv *priv = container_of(delay, struct mlx4_en_priv,
						 stats_task);
	struct mlx4_en_dev *mdev = priv->mdev;
	int err;

	mutex_lock(&mdev->state_lock);
	if (mdev->device_up) {
		if (priv->port_up) {
			if (mlx4_is_slave(mdev->dev))
				err = mlx4_en_get_vport_stats(mdev, priv->port);
			else
				err = mlx4_en_DUMP_ETH_STATS(mdev, priv->port, 0);
			if (err)
				en_dbg(HW, priv, "Could not update stats\n");

			mlx4_en_auto_moderation(priv);
		}

		queue_delayed_work(mdev->workqueue, &priv->stats_task, STATS_DELAY);
	}
	if (mdev->mac_removed[MLX4_MAX_PORTS + 1 - priv->port]) {
		mlx4_en_do_set_mac(priv, priv->current_mac);
		mdev->mac_removed[MLX4_MAX_PORTS + 1 - priv->port] = 0;
	}
	mutex_unlock(&mdev->state_lock);
}

/* mlx4_en_service_task - Run service task for tasks that needed to be done
 * periodically
 */
static void mlx4_en_service_task(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct mlx4_en_priv *priv = container_of(delay, struct mlx4_en_priv,
						 service_task);
	struct mlx4_en_dev *mdev = priv->mdev;

	mutex_lock(&mdev->state_lock);
	if (mdev->device_up) {
		if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_TS)
			mlx4_en_ptp_overflow_check(mdev);

		mlx4_en_recover_from_oom(priv);
		queue_delayed_work(mdev->workqueue, &priv->service_task,
				   SERVICE_TASK_DELAY);
	}
	mutex_unlock(&mdev->state_lock);
}

static void mlx4_en_linkstate(struct work_struct *work)
{
	struct mlx4_en_priv *priv = container_of(work, struct mlx4_en_priv,
						 linkstate_task);
	struct mlx4_en_dev *mdev = priv->mdev;
	int linkstate = priv->link_state;

	mutex_lock(&mdev->state_lock);
	/* If observable port state changed set carrier state and
	 * report to system log */
	if (priv->last_link_state != linkstate) {
		if (linkstate == MLX4_DEV_EVENT_PORT_DOWN) {
			en_info(priv, "Link Down\n");
			netif_carrier_off(priv->dev);
		} else {
			en_info(priv, "Link Up\n");
			netif_carrier_on(priv->dev);
		}
	}
	priv->last_link_state = linkstate;
	mutex_unlock(&mdev->state_lock);
}

static int mlx4_en_init_affinity_hint(struct mlx4_en_priv *priv, int ring_idx)
{
	struct mlx4_en_rx_ring *ring = priv->rx_ring[ring_idx];
	int numa_node = priv->mdev->dev->numa_node;

	if (!zalloc_cpumask_var(&ring->affinity_mask, GFP_KERNEL))
		return -ENOMEM;

	cpumask_set_cpu(cpumask_local_spread(ring_idx, numa_node),
			ring->affinity_mask);
	return 0;
}

static void mlx4_en_free_affinity_hint(struct mlx4_en_priv *priv, int ring_idx)
{
	free_cpumask_var(priv->rx_ring[ring_idx]->affinity_mask);
}

int mlx4_en_start_port(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_cq *cq;
	struct mlx4_en_tx_ring *tx_ring;
	int rx_index = 0;
	int tx_index = 0;
	int err = 0;
	int i;
	int j;
	u8 mc_list[16] = {0};

	if (priv->port_up) {
		en_dbg(DRV, priv, "start port called while port already up\n");
		return 0;
	}

	INIT_LIST_HEAD(&priv->mc_list);
	INIT_LIST_HEAD(&priv->curr_list);
	INIT_LIST_HEAD(&priv->ethtool_list);
	memset(&priv->ethtool_rules[0], 0,
	       sizeof(struct ethtool_flow_id) * MAX_NUM_OF_FS_RULES);

	/* Calculate Rx buf size */
	dev->mtu = min(dev->mtu, priv->max_mtu);
	mlx4_en_calc_rx_buf(dev);
	en_dbg(DRV, priv, "Rx buf size:%d\n", priv->rx_skb_size);

	/* Configure rx cq's and rings */
	err = mlx4_en_activate_rx_rings(priv);
	if (err) {
		en_err(priv, "Failed to activate RX rings\n");
		return err;
	}
	for (i = 0; i < priv->rx_ring_num; i++) {
		cq = priv->rx_cq[i];

		mlx4_en_cq_init_lock(cq);

		err = mlx4_en_init_affinity_hint(priv, i);
		if (err) {
			en_err(priv, "Failed preparing IRQ affinity hint\n");
			goto cq_err;
		}

		err = mlx4_en_activate_cq(priv, cq, i, false);
		if (err) {
			en_err(priv, "Failed activating Rx CQ\n");
			mlx4_en_free_affinity_hint(priv, i);
			goto cq_err;
		}

		for (j = 0; j < cq->size; j++) {
			struct mlx4_cqe *cqe = NULL;

			cqe = mlx4_en_get_cqe(cq->buf, j, priv->cqe_size) +
			      priv->cqe_factor;
			cqe->owner_sr_opcode = MLX4_CQE_OWNER_MASK;
		}

		err = mlx4_en_set_cq_moder(priv, cq);
		if (err) {
			en_err(priv, "Failed setting cq moderation parameters\n");
			mlx4_en_deactivate_cq(priv, cq);
			mlx4_en_free_affinity_hint(priv, i);
			goto cq_err;
		}
		mlx4_en_arm_cq(priv, cq);
		priv->rx_ring[i]->cqn = cq->mcq.cqn;
		++rx_index;
	}

	/* Set qp number */
	en_dbg(DRV, priv, "Getting qp number for port %d\n", priv->port);
	err = mlx4_en_get_qp(priv);
	if (err) {
		en_err(priv, "Failed getting eth qp\n");
		goto cq_err;
	}
	mdev->mac_removed[priv->port] = 0;

	/* gets default allocated counter index from func cap */
	/* or sink counter index if no resources */
	priv->counter_index = mdev->dev->caps.def_counter_index[priv->port - 1];

	en_dbg(DRV, priv, "%s: default counter index %d for port %d\n",
	       __func__, priv->counter_index, priv->port);

	err = mlx4_en_config_rss_steer(priv);
	if (err) {
		en_err(priv, "Failed configuring rss steering\n");
		goto mac_err;
	}

	err = mlx4_en_create_drop_qp(priv);
	if (err)
		goto rss_err;

	/* Configure tx cq's and rings */
	for (i = 0; i < priv->tx_ring_num; i++) {
		/* Configure cq */
		cq = priv->tx_cq[i];
		err = mlx4_en_activate_cq(priv, cq, i, false);
		if (err) {
			en_err(priv, "Failed allocating Tx CQ\n");
			goto tx_err;
		}
		err = mlx4_en_set_cq_moder(priv, cq);
		if (err) {
			en_err(priv, "Failed setting cq moderation parameters\n");
			mlx4_en_deactivate_cq(priv, cq);
			goto tx_err;
		}
		en_dbg(DRV, priv, "Resetting index of collapsed CQ:%d to -1\n", i);
		cq->buf->wqe_index = cpu_to_be16(0xffff);

		/* Configure ring */
		tx_ring = priv->tx_ring[i];
#ifdef HAVE_NEW_TX_RING_SCHEME
		err = mlx4_en_activate_tx_ring(priv, tx_ring, cq->mcq.cqn,
			i / priv->num_tx_rings_p_up, MLX4_EN_NO_VLAN);
#else
		err = mlx4_en_activate_tx_ring(priv, tx_ring, cq->mcq.cqn, MLX4_EN_NO_VLAN);
#endif
		if (err) {
			en_err(priv, "Failed allocating Tx ring\n");
			mlx4_en_deactivate_cq(priv, cq);
			goto tx_err;
		}
		tx_ring->tx_queue = netdev_get_tx_queue(dev, i);

		/* Arm CQ for TX completions */
		mlx4_en_arm_cq(priv, cq);

		/* Set initial ownership of all Tx TXBBs to SW (1) */
		for (j = 0; j < tx_ring->buf_size; j += STAMP_STRIDE)
			*((u32 *) (tx_ring->buf + j)) = INIT_OWNER_BIT;
		++tx_index;
	}

	/* Configure port */
	err = mlx4_SET_PORT_general(mdev->dev, priv->port,
				    priv->rx_skb_size + ETH_FCS_LEN,
				    priv->prof->tx_pause,
				    priv->prof->tx_ppp,
				    priv->prof->rx_pause,
				    priv->prof->rx_ppp);
	if (err) {
		en_err(priv, "Failed setting port general configurations for port %d, with error %d\n",
		       priv->port, err);
		goto tx_err;
	}
	/* Set default qp number */
	err = mlx4_SET_PORT_qpn_calc(mdev->dev, priv->port, priv->base_qpn, 0);
	if (err) {
		en_err(priv, "Failed setting default qp numbers\n");
		goto tx_err;
	}

	if (mdev->dev->caps.tunnel_offload_mode == MLX4_TUNNEL_OFFLOAD_MODE_VXLAN) {
		err = mlx4_SET_PORT_VXLAN(mdev->dev, priv->port, VXLAN_STEER_BY_OUTER_MAC, 1);
		if (err) {
			en_err(priv, "Failed setting port L2 tunnel configuration, err %d\n",
			       err);
			goto tx_err;
		}
	}

	/* Init port */
	en_dbg(HW, priv, "Initializing port\n");
	err = mlx4_INIT_PORT(mdev->dev, priv->port);
	if (err) {
		en_err(priv, "Failed Initializing port\n");
		goto tx_err;
	}

	/* Set Unicast and VXLAN steering rules */
	if (mdev->dev->caps.steering_mode != MLX4_STEERING_MODE_A0 &&
	    mlx4_en_set_rss_steer_rules(priv))
		mlx4_warn(mdev, "Failed setting steering rules\n");

	/* Attach rx QP to bradcast address */
	memset(&mc_list[10], 0xff, ETH_ALEN);
	mc_list[5] = priv->port; /* needed for B0 steering support */
	if (mlx4_multicast_attach(mdev->dev, &priv->rss_map.indir_qp, mc_list,
				  priv->port, 0, MLX4_PROT_ETH,
				  &priv->broadcast_id))
		mlx4_warn(mdev, "Failed Attaching Broadcast\n");

	/* Must redo promiscuous mode setup. */
	priv->flags &= ~(MLX4_EN_FLAG_PROMISC | MLX4_EN_FLAG_MC_PROMISC);

	/* Schedule multicast task to populate multicast list */
	queue_work(mdev->workqueue, &priv->rx_mode_task);

#ifdef HAVE_VXLAN_DYNAMIC_PORT
	if (priv->mdev->dev->caps.tunnel_offload_mode == MLX4_TUNNEL_OFFLOAD_MODE_VXLAN)
		vxlan_get_rx_port(dev);
#endif
	priv->port_up = true;

	/* Process all completions if exist to prevent
	 * the queues freezing if they are full
	 */
	for (i = 0; i < priv->rx_ring_num; i++)
		napi_schedule(&priv->rx_cq[i]->napi);

	netif_tx_start_all_queues(dev);
	netif_device_attach(dev);

	/* VGT+ */
	if (priv->vgtp)
		mlx4_en_vgtp_alloc_res(priv);

	return 0;

tx_err:
	while (tx_index--) {
		mlx4_en_deactivate_tx_ring(priv, priv->tx_ring[tx_index]);
		mlx4_en_deactivate_cq(priv, priv->tx_cq[tx_index]);
	}
	mlx4_en_destroy_drop_qp(priv);
rss_err:
	mlx4_en_release_rss_steer(priv);
mac_err:
	mlx4_en_put_qp(priv);
cq_err:
	while (rx_index--) {
		mlx4_en_deactivate_cq(priv, priv->rx_cq[rx_index]);
		mlx4_en_free_affinity_hint(priv, rx_index);
	}
	for (i = 0; i < priv->rx_ring_num; i++)
		mlx4_en_deactivate_rx_ring(priv, priv->rx_ring[i]);

	return err; /* need to close devices */
}


void mlx4_en_stop_port(struct net_device *dev, int detach)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_mc_list *mclist, *tmp;
	struct ethtool_flow_id *flow, *tmp_flow;
	int i;
	u8 mc_list[16] = {0};

	if (!priv->port_up) {
		en_dbg(DRV, priv, "stop port called while port already down\n");
		return;
	}

	/* close port*/
	mlx4_CLOSE_PORT(mdev->dev, priv->port);

	/* Synchronize with tx routine */
	netif_tx_lock_bh(dev);
	if (detach)
		netif_device_detach(dev);
	netif_tx_stop_all_queues(dev);
	netif_tx_unlock_bh(dev);

	netif_tx_disable(dev);

	/* Set port as not active */
	priv->port_up = false;

	mlx4_en_clear_mc_promisc_mode(priv, mdev);
	mlx4_en_clear_promisc_mode(priv, mdev);

	/* Detach All multicasts */
	memset(&mc_list[10], 0xff, ETH_ALEN);
	mc_list[5] = priv->port; /* needed for B0 steering support */
	mlx4_multicast_detach(mdev->dev, &priv->rss_map.indir_qp, mc_list,
			      MLX4_PROT_ETH, priv->broadcast_id);
	list_for_each_entry(mclist, &priv->curr_list, list) {
		memcpy(&mc_list[10], mclist->addr, ETH_ALEN);
		mc_list[5] = priv->port;
		mlx4_multicast_detach(mdev->dev, &priv->rss_map.indir_qp,
				      mc_list, MLX4_PROT_ETH, mclist->reg_id);
		if (mclist->tunnel_reg_id)
			mlx4_flow_detach(mdev->dev, mclist->tunnel_reg_id);
	}
	mlx4_en_clear_list(dev);
	list_for_each_entry_safe(mclist, tmp, &priv->curr_list, list) {
		list_del(&mclist->list);
		kfree(mclist);
	}

	/* Flush multicast filter */
	mlx4_SET_MCAST_FLTR(mdev->dev, priv->port, 0, 1, MLX4_MCAST_CONFIG);

	/* Remove flow steering rules for the port*/
	if (mdev->dev->caps.steering_mode ==
	    MLX4_STEERING_MODE_DEVICE_MANAGED) {
		ASSERT_RTNL();
		list_for_each_entry_safe(flow, tmp_flow,
					 &priv->ethtool_list, list) {
			mlx4_flow_detach(mdev->dev, flow->id);
			list_del(&flow->list);
		}
	}

	mlx4_en_destroy_drop_qp(priv);

	/* Free TX Rings */
	for (i = 0; i < priv->tx_ring_num; i++) {
		mlx4_en_deactivate_tx_ring(priv, priv->tx_ring[i]);
		mlx4_en_deactivate_cq(priv, priv->tx_cq[i]);
	}
	msleep(10);

	for (i = 0; i < priv->tx_ring_num; i++)
		mlx4_en_free_tx_buf(dev, priv->tx_ring[i]);

	if (mdev->dev->caps.steering_mode != MLX4_STEERING_MODE_A0)
		mlx4_en_delete_rss_steer_rules(priv);

	/* Free RSS qps */
	mlx4_en_release_rss_steer(priv);

	/* Unregister Mac address for the port */
	mlx4_en_put_qp(priv);
	if (!(mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_REASSIGN_MAC_EN))
		mdev->mac_removed[priv->port] = 1;

	/* Free RX Rings */
	for (i = 0; i < priv->rx_ring_num; i++) {
		struct mlx4_en_cq *cq = priv->rx_cq[i];

		local_bh_disable();
		while (!mlx4_en_cq_lock_napi(cq)) {
			pr_info("CQ %d locked\n", i);
			mdelay(1);
		}
		local_bh_enable();

		napi_synchronize(&cq->napi);
		mlx4_en_deactivate_rx_ring(priv, priv->rx_ring[i]);
		mlx4_en_deactivate_cq(priv, cq);

		mlx4_en_free_affinity_hint(priv, i);
	}

	/* VGT+ */
	if (priv->vgtp)
		mlx4_en_vgtp_destroy_res(priv);
}

static void mlx4_en_restart(struct work_struct *work)
{
	struct mlx4_en_priv *priv = container_of(work, struct mlx4_en_priv,
						 watchdog_task);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct net_device *dev = priv->dev;

	en_dbg(DRV, priv, "Watchdog task called for port %d\n", priv->port);

	rtnl_lock();
	mutex_lock(&mdev->state_lock);
	if (priv->port_up) {
		mlx4_en_stop_port(dev, 1);
		if (mlx4_en_start_port(dev))
			en_err(priv, "Failed restarting port %d\n", priv->port);
	}
	mutex_unlock(&mdev->state_lock);
	rtnl_unlock();
}

static void mlx4_en_clear_stats(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int i;

	if (!mlx4_is_slave(mdev->dev))
		if (mlx4_en_DUMP_ETH_STATS(mdev, priv->port, 1))
			en_dbg(HW, priv, "Failed dumping statistics\n");

	memset(&priv->stats, 0, sizeof(priv->stats));
	memset(&priv->pstats, 0, sizeof(priv->pstats));
	memset(&priv->pkstats, 0, sizeof(priv->pkstats));
	memset(&priv->port_stats, 0, sizeof(priv->port_stats));
	memset(&priv->vport_stats, 0, sizeof(priv->vport_stats));
	memset(&priv->rx_flowstats, 0, sizeof(priv->rx_flowstats));
	memset(&priv->tx_flowstats, 0, sizeof(priv->tx_flowstats));
	memset(&priv->rx_priority_flowstats, 0,
	       sizeof(priv->rx_priority_flowstats));
	memset(&priv->tx_priority_flowstats, 0,
	       sizeof(priv->tx_priority_flowstats));

	for (i = 0; i < priv->tx_ring_num; i++) {
		priv->tx_ring[i]->bytes = 0;
		priv->tx_ring[i]->packets = 0;
		priv->tx_ring[i]->tx_csum = 0;
	}
	for (i = 0; i < priv->rx_ring_num; i++) {
		priv->rx_ring[i]->bytes = 0;
		priv->rx_ring[i]->packets = 0;
		priv->rx_ring[i]->csum_ok = 0;
		priv->rx_ring[i]->csum_none = 0;
		priv->rx_ring[i]->csum_complete = 0;
	}
}

static int mlx4_en_open(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int err = 0;

	mutex_lock(&mdev->state_lock);

	if (!mdev->device_up) {
		en_err(priv, "Cannot open - device down/disabled\n");
		err = -EBUSY;
		goto out;
	}

	/* Reset HW statistics and SW counters */
	mlx4_en_clear_stats(dev);

	err = mlx4_en_start_port(dev);
	if (err)
		en_err(priv, "Failed starting port:%d\n", priv->port);

out:
	mutex_unlock(&mdev->state_lock);
	return err;
}


static int mlx4_en_close(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;

	en_dbg(IFDOWN, priv, "Close port called\n");

	mutex_lock(&mdev->state_lock);

	mlx4_en_stop_port(dev, 0);
	netif_carrier_off(dev);

	mutex_unlock(&mdev->state_lock);
	return 0;
}

void mlx4_en_free_resources(struct mlx4_en_priv *priv)
{
	int i;

#ifdef HAVE_NETDEV_RX_CPU_RMAP
#ifdef CONFIG_RFS_ACCEL
	priv->dev->rx_cpu_rmap = NULL;
#endif
#endif

	for (i = 0; i < priv->tx_ring_num; i++) {
		if (priv->tx_ring && priv->tx_ring[i])
			mlx4_en_destroy_tx_ring(priv, &priv->tx_ring[i]);
		if (priv->tx_cq && priv->tx_cq[i])
			mlx4_en_destroy_cq(priv, &priv->tx_cq[i]);
	}

	for (i = 0; i < priv->rx_ring_num; i++) {
		if (priv->rx_ring[i])
			mlx4_en_destroy_rx_ring(priv, &priv->rx_ring[i],
				priv->prof->rx_ring_size, priv->stride);
		if (priv->rx_cq[i])
			mlx4_en_destroy_cq(priv, &priv->rx_cq[i]);
	}
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
/* returns the details of the mac table. used only in multi_function mode */
static ssize_t mlx4_en_show_fdb_details(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct net_device *netdev = to_net_dev(dev);
	struct mlx4_en_priv *priv = netdev_priv(netdev);
	int max_macs = mlx4_get_port_max_macs(priv->mdev->dev, priv->port);
	int total = mlx4_get_port_total_macs(priv->mdev->dev, priv->port);
	int free_macs = mlx4_get_port_free_macs(priv->mdev->dev, priv->port);
	ssize_t len = 0;

	/* in VF the macs that allocated before it been opened are count */
	total = min(max_macs, total);
		len += sprintf(&buf[len],
			       "FDB details: device %s: max: %d, used: %d, free macs: %d\n",
			       netdev->name, max_macs, total, free_macs);

	return len;
}
static DEVICE_ATTR(fdb_det, S_IRUGO, mlx4_en_show_fdb_details, NULL);
#endif

int mlx4_en_alloc_resources(struct mlx4_en_priv *priv)
{
	struct mlx4_en_port_profile *prof = priv->prof;
	int i;
	int node;

	/* Create tx Rings */
	for (i = 0; i < priv->tx_ring_num; i++) {
		node = cpu_to_node(i % num_online_cpus());
		if (mlx4_en_create_cq(priv, &priv->tx_cq[i],
				      prof->tx_ring_size, i, TX, node))
			goto err;

		if (mlx4_en_create_tx_ring(priv, &priv->tx_ring[i],
					   prof->tx_ring_size, TXBB_SIZE,
					   node, i))
			goto err;
	}

	/* Create rx Rings */
	for (i = 0; i < priv->rx_ring_num; i++) {
		node = cpu_to_node(i % num_online_cpus());
		if (mlx4_en_create_cq(priv, &priv->rx_cq[i],
				      prof->rx_ring_size, i, RX, node))
			goto err;

		if (mlx4_en_create_rx_ring(priv, &priv->rx_ring[i],
					   prof->rx_ring_size, priv->stride,
					   node))
			goto err;
	}

#ifdef HAVE_NETDEV_RX_CPU_RMAP
#ifdef CONFIG_RFS_ACCEL
	priv->dev->rx_cpu_rmap = mlx4_get_cpu_rmap(priv->mdev->dev, priv->port);
#endif
#endif

	return 0;

err:
	en_err(priv, "Failed to allocate NIC resources\n");
	for (i = 0; i < priv->rx_ring_num; i++) {
		if (priv->rx_ring[i])
			mlx4_en_destroy_rx_ring(priv, &priv->rx_ring[i],
						prof->rx_ring_size,
						priv->stride);
		if (priv->rx_cq[i])
			mlx4_en_destroy_cq(priv, &priv->rx_cq[i]);
	}
	for (i = 0; i < priv->tx_ring_num; i++) {
		if (priv->tx_ring[i])
			mlx4_en_destroy_tx_ring(priv, &priv->tx_ring[i]);
		if (priv->tx_cq[i])
			mlx4_en_destroy_cq(priv, &priv->tx_cq[i]);
	}
	return -ENOMEM;
}

static const char fmt_u64[] = "%llu\n";

struct en_stats_attribute {
	struct attribute attr;
	ssize_t (*show)(struct en_port *, struct en_stats_attribute *,
			char *buf);
	ssize_t (*store)(struct en_port *, struct en_stats_attribute *,
			 char *buf, size_t count);
};

struct en_port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct en_port *, struct en_port_attribute *,
			char *buf);
	ssize_t (*store)(struct en_port *, struct en_port_attribute *,
			 const char *buf, size_t count);
};

#define EN_PORT_ATTR(_name, _mode, _show, _store) \
struct en_stats_attribute en_stats_attr_##_name = \
	__ATTR(_name, _mode, _show, _store)

/* Show a given an attribute in the statistics group */
static ssize_t mlx4_en_show_vf_statistics(struct en_port *en_p,
					  struct en_stats_attribute *attr,
					  char *buf, unsigned long offset)
{
	ssize_t ret = -EINVAL;
	struct net_device_stats link_stats;

	memset(&link_stats, 0xff, sizeof(struct net_device_stats));

	mlx4_get_vf_statistics(en_p->dev, en_p->port_num, en_p->vport_num, &link_stats);

	ret = sprintf(buf, fmt_u64, *(u64 *)(((u8 *)&link_stats) + offset));

	return ret;
}

/* generate a read-only statistics attribute */
#define VFSTAT_ENTRY(name)						\
static ssize_t name##_show(struct en_port *en_p,			\
			   struct en_stats_attribute *attr, char *buf)	\
{									\
	return mlx4_en_show_vf_statistics(en_p, attr, buf,		\
			    offsetof(struct net_device_stats, name));	\
}									\
static EN_PORT_ATTR(name, S_IRUGO, name##_show, NULL)

VFSTAT_ENTRY(rx_packets);
VFSTAT_ENTRY(tx_packets);
VFSTAT_ENTRY(rx_bytes);
VFSTAT_ENTRY(tx_bytes);
VFSTAT_ENTRY(rx_errors);
VFSTAT_ENTRY(tx_errors);
VFSTAT_ENTRY(rx_dropped);
VFSTAT_ENTRY(tx_dropped);
VFSTAT_ENTRY(multicast);
VFSTAT_ENTRY(collisions);
VFSTAT_ENTRY(rx_length_errors);
VFSTAT_ENTRY(rx_over_errors);
VFSTAT_ENTRY(rx_crc_errors);
VFSTAT_ENTRY(rx_frame_errors);
VFSTAT_ENTRY(rx_fifo_errors);
VFSTAT_ENTRY(rx_missed_errors);
VFSTAT_ENTRY(tx_aborted_errors);
VFSTAT_ENTRY(tx_carrier_errors);
VFSTAT_ENTRY(tx_fifo_errors);
VFSTAT_ENTRY(tx_heartbeat_errors);
VFSTAT_ENTRY(tx_window_errors);
VFSTAT_ENTRY(rx_compressed);
VFSTAT_ENTRY(tx_compressed);

static struct attribute *vfstat_attrs[] = {
	&en_stats_attr_rx_packets.attr,
	&en_stats_attr_tx_packets.attr,
	&en_stats_attr_rx_bytes.attr,
	&en_stats_attr_tx_bytes.attr,
	&en_stats_attr_rx_errors.attr,
	&en_stats_attr_tx_errors.attr,
	&en_stats_attr_rx_dropped.attr,
	&en_stats_attr_tx_dropped.attr,
	&en_stats_attr_multicast.attr,
	&en_stats_attr_collisions.attr,
	&en_stats_attr_rx_length_errors.attr,
	&en_stats_attr_rx_over_errors.attr,
	&en_stats_attr_rx_crc_errors.attr,
	&en_stats_attr_rx_frame_errors.attr,
	&en_stats_attr_rx_fifo_errors.attr,
	&en_stats_attr_rx_missed_errors.attr,
	&en_stats_attr_tx_aborted_errors.attr,
	&en_stats_attr_tx_carrier_errors.attr,
	&en_stats_attr_tx_fifo_errors.attr,
	&en_stats_attr_tx_heartbeat_errors.attr,
	&en_stats_attr_tx_window_errors.attr,
	&en_stats_attr_rx_compressed.attr,
	&en_stats_attr_tx_compressed.attr,
	NULL
};

static ssize_t en_stats_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct en_stats_attribute *en_stats_attr =
		container_of(attr, struct en_stats_attribute, attr);
	struct en_port *p = container_of(kobj, struct en_port, kobj_stats);

	if (!en_stats_attr->show)
		return -EIO;

	return en_stats_attr->show(p, en_stats_attr, buf);
}

#ifdef CONFIG_COMPAT_SYSFS_OPS_CONST
static const struct sysfs_ops en_port_stats_sysfs_ops = {
#else
static struct sysfs_ops en_port_stats_sysfs_ops = {
#endif
	.show = en_stats_show
};

static struct kobj_type en_port_stats = {
	.sysfs_ops  = &en_port_stats_sysfs_ops,
	.default_attrs = vfstat_attrs,
};

static ssize_t mlx4_en_show_vf_link_state(struct en_port *en_p,
					  struct en_port_attribute *attr,
					  char *buf)
{
	static const char * const str[] = { "auto", "enable", "disable" };
	int link_state;
	ssize_t len = 0;

	link_state = mlx4_get_vf_link_state(en_p->dev, en_p->port_num,
					    en_p->vport_num);
	if (link_state >= 0)
		len += sprintf(&buf[len], "%s\n", str[link_state]);

	return len;
}

static ssize_t mlx4_en_store_vf_link_state(struct en_port *en_p,
					   struct en_port_attribute *attr,
					   const char *buf, size_t count)
{
	int err, link_state;

	if (count > 128)
		return -EINVAL;

	if (strstr(buf, "auto"))
		link_state = IFLA_VF_LINK_STATE_AUTO;
	else if (strstr(buf, "enable"))
		link_state = IFLA_VF_LINK_STATE_ENABLE;
	else if (strstr(buf, "disable"))
		link_state = IFLA_VF_LINK_STATE_DISABLE;
	else
		return -EINVAL;

	err = mlx4_set_vf_link_state(en_p->dev, en_p->port_num,
				     en_p->vport_num, link_state);
	return err ? err : count;
}

struct en_port_attribute en_port_attr_link_state = __ATTR(link_state,
						S_IRUGO | S_IWUSR,
						mlx4_en_show_vf_link_state,
						mlx4_en_store_vf_link_state);

static ssize_t mlx4_en_show_tx_rate(struct en_port *en_p,
				    struct en_port_attribute *attr,
				    char *buf)
{
	return mlx4_get_vf_rate(en_p->dev, en_p->port_num,
				en_p->vport_num, buf);
}

struct en_port_attribute en_port_attr_tx_rate = __ATTR(tx_rate,
						       S_IRUGO,
						       mlx4_en_show_tx_rate,
						       NULL);

static ssize_t en_port_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct en_port_attribute *en_port_attr =
		container_of(attr, struct en_port_attribute, attr);
	struct en_port *p = container_of(kobj, struct en_port, kobj_vf);

	if (!en_port_attr->show)
		return -EIO;

	return en_port_attr->show(p, en_port_attr, buf);
}

static ssize_t en_port_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buf, size_t count)
{
	struct en_port_attribute *en_port_attr =
		container_of(attr, struct en_port_attribute, attr);
	struct en_port *p = container_of(kobj, struct en_port, kobj_vf);

	if (!en_port_attr->store)
		return -EIO;

	return en_port_attr->store(p, en_port_attr, buf, count);
}

#ifdef CONFIG_COMPAT_SYSFS_OPS_CONST
static const struct sysfs_ops en_port_vf_ops = {
#else
static struct sysfs_ops en_port_vf_ops = {
#endif
	.show = en_port_show,
	.store = en_port_store,
};

static ssize_t mlx4_en_show_vlan_set(struct en_port *en_p,
				     struct en_port_attribute *attr,
				     char *buf)
{
	return mlx4_get_vf_vlan_set(en_p->dev, en_p->port_num,
				    en_p->vport_num, buf);
}

static ssize_t mlx4_en_store_vlan_set(struct en_port *en_p,
				      struct en_port_attribute *attr,
				      const char *buf, size_t count)
{
	int err;
	u16 vlan;
	struct mlx4_dev *dev = en_p->dev;
	int port = en_p->port_num;
	int vf = en_p->vport_num;
	char save;

	/* Max symbols per VLAN 4 * MAX_VLANS + (MAX_VLANS - 1) for spaces */
	if (count > MLX4_MAX_VLAN_SET_SIZE * 4 + (MLX4_MAX_VLAN_SET_SIZE - 1))
		return -EINVAL;

	err = mlx4_reset_vlan_policy(dev, port, vf);
	if (err)
		return err;

	do {
		int len;

		len = strcspn(buf, " ");

		/* nul-terminate and parse */
		save = buf[len];
		((char *)buf)[len] = '\0';

		if (sscanf(buf, "%hu", &vlan) != 1 ||
		    vlan > VLAN_MAX_VALUE) {
			if (!strcmp(buf, "\n"))
				err = 1;
			else
				err = -EINVAL;
			return err;
		}
		err = mlx4_set_vf_vlan_next(dev, port, vf, vlan);
		if (err) {
			mlx4_reset_vlan_policy(dev, port, vf);
			return err;
		}

		buf += len+1;
	} while (save == ' ');

	return count;
}

struct en_port_attribute en_port_attr_vlan_set = __ATTR(vlan_set,
						S_IRUGO | S_IWUSR,
						mlx4_en_show_vlan_set,
						mlx4_en_store_vlan_set);

static struct attribute *vf_attrs[] = {
	&en_port_attr_link_state.attr,
	&en_port_attr_tx_rate.attr,
	&en_port_attr_vlan_set.attr,
	NULL
};

static struct kobj_type en_port_type = {
	.sysfs_ops  = &en_port_vf_ops,
	.default_attrs = vf_attrs,
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
static ssize_t mlx4_en_show_fdb(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct net_device *netdev = to_net_dev(dev);
	ssize_t len = 0;
	struct netdev_hw_addr *ha;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
	struct netdev_hw_addr *mc;
#else
	struct dev_addr_list *mc;
#endif

	netif_addr_lock_bh(netdev);

	netdev_for_each_uc_addr(ha, netdev) {
		len += sprintf(&buf[len], "%02x:%02x:%02x:%02x:%02x:%02x\n",
			       ha->addr[0], ha->addr[1], ha->addr[2],
			       ha->addr[3], ha->addr[4], ha->addr[5]);
	}
	netdev_for_each_mc_addr(mc, netdev) {
		len += sprintf(&buf[len], "%02x:%02x:%02x:%02x:%02x:%02x\n",
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
			mc->addr[0], mc->addr[1], mc->addr[2],
			mc->addr[3], mc->addr[4], mc->addr[5]);
#else
			mc->da_addr[0], mc->da_addr[1], mc->da_addr[2],
			mc->da_addr[3], mc->da_addr[4], mc->da_addr[5]);
#endif
	}

	netif_addr_unlock_bh(netdev);

	return len;
}

static ssize_t mlx4_en_set_fdb(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct net_device *netdev = to_net_dev(dev);
	struct mlx4_en_priv *priv = netdev_priv(netdev);
	unsigned char mac[ETH_ALEN];
	unsigned int tmp[ETH_ALEN];
	int add = 0;
	int err, i;

	if (count < sizeof("-01:02:03:04:05:06"))
		return -EINVAL;

	if (!priv->mdev)
		return -EOPNOTSUPP;

	switch (buf[0]) {
	case '-':
		break;
	case '+':
		add = 1;
		break;
	default:
		return -EINVAL;
	}
	err = sscanf(&buf[1], "%02x:%02x:%02x:%02x:%02x:%02x",
		     &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);

	if (err != ETH_ALEN)
		return -EINVAL;
	for (i = 0; i < ETH_ALEN; ++i)
		mac[i] = tmp[i] & 0xff;

	/* make sure all the other fdb actions are done,
	 * otherwise no way to know the current state.
	 */
	flush_work(&priv->rx_mode_task);
	if (add) {
		if (!mlx4_en_check_is_available_mac(priv->mdev, priv->port)) {
			mlx4_warn(priv->mdev, "Cannot add mac:%pM, no free macs.\n",mac);
			return -EINVAL;
		}
	}

	rtnl_lock();
	if (is_unicast_ether_addr(mac)) {
		if (add)
			err = dev_uc_add_excl(netdev, mac);
		else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
			err = dev_uc_del(netdev, mac);
#else
			err = dev_unicast_delete(netdev, mac);
 #endif
	} else if (is_multicast_ether_addr(mac)) {
		if (add)
			err = dev_mc_add_excl(netdev, mac);
		else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
			err = dev_mc_del(netdev, mac);
#else
			err = dev_mc_delete(netdev, mac, ETH_ALEN, true);
#endif
	} else {
		rtnl_unlock();
		return -EINVAL;
	}
	rtnl_unlock();

	en_dbg(DRV, priv, "Port:%d: %s %pM\n", priv->port,
	       (add ? "adding" : "removing"), mac);

	return err ? err : count;
}

static DEVICE_ATTR(fdb, S_IRUGO | 002, mlx4_en_show_fdb, mlx4_en_set_fdb);
#endif

static void mlx4_en_shutdown(struct net_device *dev)
{
	rtnl_lock();
	netif_device_detach(dev);
	mlx4_en_close(dev);
	rtnl_unlock();
}

void mlx4_en_destroy_netdev(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	bool shutdown = mdev->dev->persist->interface_state &
					    MLX4_INTERFACE_STATE_SHUTDOWN;
	int i;

	en_dbg(DRV, priv, "Destroying netdev on port:%d\n", priv->port);

#ifdef CONFIG_COMPAT_EN_SYSFS
	if (priv->sysfs_group_initialized)
		mlx4_en_sysfs_remove(dev);
#endif

	/* Unregister device - this will close the port if it was up */
	if (priv->registered) {
		if (shutdown)
			mlx4_en_shutdown(dev);
		else
			unregister_netdev(dev);
	}

	if (priv->allocated)
		mlx4_free_hwq_res(mdev->dev, &priv->res, MLX4_EN_PAGE_SIZE);

	cancel_delayed_work(&priv->stats_task);
	cancel_delayed_work(&priv->service_task);
	/* flush any pending task for this netdev */
	flush_workqueue(mdev->workqueue);

	if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_TS)
		mlx4_en_remove_timestamp(mdev);

	/* Detach the netdev so tasks would not attempt to access it */
	mutex_lock(&mdev->state_lock);
	mdev->pndev[priv->port] = NULL;
	mdev->upper[priv->port] = NULL;
	mutex_unlock(&mdev->state_lock);

	if (mlx4_is_master(priv->mdev->dev)) {
		for (i = 0; i < priv->mdev->dev->persist->num_vfs; i++) {
			if (priv->vf_ports[i]) {
				kobject_put(&priv->vf_ports[i]->kobj_stats);
				kobject_put(&priv->vf_ports[i]->kobj_vf);
				kfree(priv->vf_ports[i]);
				priv->vf_ports[i] = NULL;
			}
		}
	}

	mlx4_en_free_resources(priv);

	if (priv->vgtp) {
		kfree(priv->vgtp->bitmap);
		kfree(priv->vgtp);
	}

	kfree(priv->tx_ring);
	kfree(priv->tx_cq);

	if (!shutdown)
		free_netdev(dev);
}

static int mlx4_en_change_mtu(struct net_device *dev, int new_mtu)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int err = 0;

	en_dbg(DRV, priv, "Change MTU called - current:%d new:%d\n",
		 dev->mtu, new_mtu);

	if ((new_mtu < MLX4_EN_MIN_MTU) || (new_mtu > priv->max_mtu)) {
		en_err(priv, "Bad MTU size:%d.\n", new_mtu);
		return -EPERM;
	}

	if (priv->prof->inline_scatter_thold >= MIN_INLINE_SCATTER) {
		en_err(priv, "Please disable RX Copybreak by setting to 0\n");
		return -EPERM;
	}

	dev->mtu = new_mtu;

	if (netif_running(dev)) {
		mutex_lock(&mdev->state_lock);
		if (!mdev->device_up) {
			/* NIC is probably restarting - let watchdog task reset
			 * the port */
			en_dbg(DRV, priv, "Change MTU called with card down!?\n");
		} else {
			mlx4_en_stop_port(dev, 1);
			err = mlx4_en_start_port(dev);
			if (err) {
				en_err(priv, "Failed restarting port:%d\n",
					 priv->port);
				queue_work(mdev->workqueue, &priv->watchdog_task);
			}
		}
		mutex_unlock(&mdev->state_lock);
	}
	return 0;
}

#ifdef HAVE_SIOCGHWTSTAMP
static int mlx4_en_hwtstamp_set(struct net_device *dev, struct ifreq *ifr)
#else
static int mlx4_en_hwtstamp_ioctl(struct net_device *dev, struct ifreq *ifr)
#endif
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct hwtstamp_config config;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	/* reserved for future extensions */
	if (config.flags)
		return -EINVAL;

	/* device doesn't support time stamping */
	if (!(mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_TS))
		return -EINVAL;

	/* TX HW timestamp */
	switch (config.tx_type) {
	case HWTSTAMP_TX_OFF:
	case HWTSTAMP_TX_ON:
		break;
	default:
		return -ERANGE;
	}

	/* RX HW timestamp */
	switch (config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		break;
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_SOME:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		config.rx_filter = HWTSTAMP_FILTER_ALL;
		break;
	default:
		return -ERANGE;
	}

	if (mlx4_en_reset_config(dev, config, dev->features)) {
		config.tx_type = HWTSTAMP_TX_OFF;
		config.rx_filter = HWTSTAMP_FILTER_NONE;
	}

	return copy_to_user(ifr->ifr_data, &config,
			    sizeof(config)) ? -EFAULT : 0;
}

#ifdef HAVE_SIOCGHWTSTAMP
static int mlx4_en_hwtstamp_get(struct net_device *dev, struct ifreq *ifr)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);

	return copy_to_user(ifr->ifr_data, &priv->hwtstamp_config,
			    sizeof(priv->hwtstamp_config)) ? -EFAULT : 0;
}
#endif

static int mlx4_en_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case SIOCSHWTSTAMP:
#ifdef HAVE_SIOCGHWTSTAMP
		return mlx4_en_hwtstamp_set(dev, ifr);
	case SIOCGHWTSTAMP:
		return mlx4_en_hwtstamp_get(dev, ifr);
#else
		return mlx4_en_hwtstamp_ioctl(dev, ifr);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef HAVE_NETIF_F_HW_VLAN_STAG_RX
static netdev_features_t mlx4_en_fix_features(struct net_device *netdev,
					      netdev_features_t features)
{
	struct mlx4_en_priv *en_priv = netdev_priv(netdev);
	struct mlx4_en_dev *mdev = en_priv->mdev;

	/* Since there is no support for separate RX C-TAG/S-TAG vlan accel
	 * enable/disable make sure S-TAG flag is always in same state as
	 * C-TAG.
	 */
	if (features & NETIF_F_HW_VLAN_CTAG_RX &&
	    !(mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_SKIP_OUTER_VLAN))
		features |= NETIF_F_HW_VLAN_STAG_RX;
	else
		features &= ~NETIF_F_HW_VLAN_STAG_RX;

	return features;
}
#endif

#ifndef CONFIG_SYSFS_LOOPBACK
static
#endif
int mlx4_en_set_features(struct net_device *netdev,
#ifdef HAVE_NET_DEVICE_OPS_EXT
			u32 features)
#else
		netdev_features_t features)
#endif
{
	struct mlx4_en_priv *priv = netdev_priv(netdev);
	bool reset = false;
	int ret = 0;

#ifdef HAVE_NETIF_F_RXFCS
	if (DEV_FEATURE_CHANGED(netdev, features, NETIF_F_RXFCS)) {
		en_info(priv, "Turn %s RX-FCS\n",
			(features & NETIF_F_RXFCS) ? "ON" : "OFF");
		reset = true;
	}
#endif

#ifdef HAVE_NETIF_F_RXALL
	if (DEV_FEATURE_CHANGED(netdev, features, NETIF_F_RXALL)) {
		u8 ignore_fcs_value = (features & NETIF_F_RXALL) ? 1 : 0;

		en_info(priv, "Turn %s RX-ALL\n",
			ignore_fcs_value ? "ON" : "OFF");
		ret = mlx4_SET_PORT_fcs_check(priv->mdev->dev,
					      priv->port, ignore_fcs_value);
		if (ret)
			return ret;
	}
#endif

	if (DEV_FEATURE_CHANGED(netdev, features, NETIF_F_HW_VLAN_CTAG_RX)) {
		en_info(priv, "Turn %s RX vlan strip offload\n",
			(features & NETIF_F_HW_VLAN_CTAG_RX) ? "ON" : "OFF");
		reset = true;
	}

	if (DEV_FEATURE_CHANGED(netdev, features, NETIF_F_HW_VLAN_CTAG_TX))
		en_info(priv, "Turn %s TX vlan strip offload\n",
			(features & NETIF_F_HW_VLAN_CTAG_TX) ? "ON" : "OFF");

#ifdef HAVE_NETIF_F_HW_VLAN_STAG_RX
	if (DEV_FEATURE_CHANGED(netdev, features, NETIF_F_HW_VLAN_STAG_TX))
		en_info(priv, "Turn %s TX S-VLAN strip offload\n",
			(features & NETIF_F_HW_VLAN_STAG_TX) ? "ON" : "OFF");
#endif

	if (DEV_FEATURE_CHANGED(netdev, features, NETIF_F_LOOPBACK)) {
		en_info(priv, "Turn %s loopback\n",
			(features & NETIF_F_LOOPBACK) ? "ON" : "OFF");
		mlx4_en_update_loopback_state(netdev, features);
	}

	if (reset) {
		ret = mlx4_en_reset_config(netdev, priv->hwtstamp_config,
					   features);
		if (ret)
			return ret;
	}
	return 0;
}

#ifdef HAVE_NDO_SET_VF_MAC
static int mlx4_en_set_vf_mac(struct net_device *dev, int queue, u8 *mac)
{
	struct mlx4_en_priv *en_priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = en_priv->mdev;
	u64 mac_u64 = mlx4_mac_to_u64(mac);

	if (is_multicast_ether_addr(mac))
		return -EINVAL;

	return mlx4_set_vf_mac(mdev->dev, en_priv->port, queue, mac_u64);
}

static int mlx4_en_set_vf_vlan(struct net_device *dev, int vf, u16 vlan, u8 qos)
{
	struct mlx4_en_priv *en_priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = en_priv->mdev;

	return mlx4_set_vf_vlan(mdev->dev, en_priv->port, vf, vlan, qos);
}
#endif

#ifdef HAVE_TX_RATE_LIMIT
static int mlx4_en_set_vf_rate(struct net_device *dev, int vf, int min_tx_rate,
			       int max_tx_rate)
{
	struct mlx4_en_priv *en_priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = en_priv->mdev;

	return mlx4_set_vf_rate(mdev->dev, en_priv->port, vf, min_tx_rate,
				max_tx_rate);
}
#elif defined(HAVE_VF_TX_RATE)
static int mlx4_en_set_vf_tx_rate(struct net_device *dev, int vf, int rate)
{
	struct mlx4_en_priv *en_priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = en_priv->mdev;

	return mlx4_set_vf_rate(mdev->dev, en_priv->port, vf, 0, rate);
}
#endif

#if defined(HAVE_VF_INFO_SPOOFCHK) || defined(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_SPOOFCHK)
static int mlx4_en_set_vf_spoofchk(struct net_device *dev, int vf, bool setting)
{
	struct mlx4_en_priv *en_priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = en_priv->mdev;

	return mlx4_set_vf_spoofchk(mdev->dev, en_priv->port, vf, setting);
}
#endif

#ifdef HAVE_NDO_SET_VF_MAC
static int mlx4_en_get_vf_config(struct net_device *dev, int vf, struct ifla_vf_info *ivf)
{
	struct mlx4_en_priv *en_priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = en_priv->mdev;

	return mlx4_get_vf_config(mdev->dev, en_priv->port, vf, ivf);
}
#endif

#if defined(HAVE_NETDEV_OPS_NDO_SET_VF_LINK_STATE) || defined(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_LINK_STATE)
static int mlx4_en_set_vf_link_state(struct net_device *dev, int vf, int link_state)
{
	struct mlx4_en_priv *en_priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = en_priv->mdev;

	return mlx4_set_vf_link_state(mdev->dev, en_priv->port, vf, link_state);
}
#endif

#if defined(HAVE_NETDEV_NDO_GET_PHYS_PORT_ID) || defined(HAVE_NETDEV_EXT_NDO_GET_PHYS_PORT_ID)
#define PORT_ID_BYTE_LEN 8
static int mlx4_en_get_phys_port_id(struct net_device *dev,
#ifdef HAVE_NETDEV_PHYS_ITEM_ID
				    struct netdev_phys_item_id *ppid)
#else
				    struct netdev_phys_port_id *ppid)
#endif
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_dev *mdev = priv->mdev->dev;
	int i;
	u64 phys_port_id = mdev->caps.phys_port_id[priv->port];

	if (!phys_port_id)
		return -EOPNOTSUPP;

	ppid->id_len = sizeof(phys_port_id);
	for (i = PORT_ID_BYTE_LEN - 1; i >= 0; --i) {
		ppid->id[i] =  phys_port_id & 0xff;
		phys_port_id >>= 8;
	}
	return 0;
}
#endif

#ifdef HAVE_VXLAN_ENABLED
static void mlx4_en_add_vxlan_offloads(struct work_struct *work)
{
	int ret;
	struct mlx4_en_priv *priv = container_of(work, struct mlx4_en_priv,
						 vxlan_add_task);

	ret = mlx4_config_vxlan_port(priv->mdev->dev, priv->vxlan_port);
	if (ret)
		goto out;

	ret = mlx4_SET_PORT_VXLAN(priv->mdev->dev, priv->port,
				  VXLAN_STEER_BY_OUTER_MAC, 1);
out:
	if (ret) {
		en_err(priv, "failed setting L2 tunnel configuration ret %d\n", ret);
		return;
	}

	/* set offloads */
#ifdef HAVE_NETDEV_HW_ENC_FEATURES
	priv->dev->hw_enc_features |= NETIF_F_IP_CSUM | NETIF_F_RXCSUM |
				      NETIF_F_TSO | NETIF_F_GSO_UDP_TUNNEL;
#endif
#ifdef HAVE_NETDEV_HW_FEATURES
	priv->dev->hw_features |= NETIF_F_GSO_UDP_TUNNEL;
#elif defined(HAVE_NETDEV_EXTENDED_HW_FEATURES)
	netdev_extended(priv->dev)->hw_features |= NETIF_F_GSO_UDP_TUNNEL;
#endif
#ifdef HAVE_NETDEV_WANTED_FEATURES
	priv->dev->wanted_features |= NETIF_F_GSO_UDP_TUNNEL;
#elif defined(HAVE_NETDEV_EXTENDED_WANTED_FEATURES)
	netdev_extended(priv->dev)->wanted_features |= NETIF_F_GSO_UDP_TUNNEL;
#endif
#ifdef HAVE_NETDEV_UPDATE_FEATURES
	rtnl_lock();
	netdev_update_features(priv->dev);
	rtnl_unlock();
#else
	priv->dev->features |= NETIF_F_GSO_UDP_TUNNEL;
#endif
}

static void mlx4_en_del_vxlan_offloads(struct work_struct *work)
{
	int ret;
	struct mlx4_en_priv *priv = container_of(work, struct mlx4_en_priv,
						 vxlan_del_task);
	/* unset offloads */
#ifdef HAVE_NETDEV_HW_ENC_FEATURES
	priv->dev->hw_enc_features &= ~(NETIF_F_IP_CSUM | NETIF_F_RXCSUM |
				      NETIF_F_TSO | NETIF_F_GSO_UDP_TUNNEL);
#endif
#ifdef HAVE_NETDEV_HW_FEATURES
	priv->dev->hw_features &= ~NETIF_F_GSO_UDP_TUNNEL;
#elif defined(HAVE_NETDEV_EXTENDED_HW_FEATURES)
	netdev_extended(priv->dev)->hw_features &= ~NETIF_F_GSO_UDP_TUNNEL;
#endif
#ifdef HAVE_NETDEV_WANTED_FEATURES
	priv->dev->wanted_features &= ~NETIF_F_GSO_UDP_TUNNEL;
#elif defined(HAVE_NETDEV_EXTENDED_WANTED_FEATURES)
	netdev_extended(priv->dev)->wanted_features &= ~NETIF_F_GSO_UDP_TUNNEL;
#endif
#ifdef HAVE_NETDEV_UPDATE_FEATURES
	rtnl_lock();
	netdev_update_features(priv->dev);
	rtnl_unlock();
#else
	priv->dev->wanted_features &= ~NETIF_F_GSO_UDP_TUNNEL;
#endif
	ret = mlx4_SET_PORT_VXLAN(priv->mdev->dev, priv->port,
				  VXLAN_STEER_BY_OUTER_MAC, 0);
	if (ret)
		en_err(priv, "failed setting L2 tunnel configuration ret %d\n", ret);

	priv->vxlan_port = 0;
}

#ifdef HAVE_VXLAN_DYNAMIC_PORT
static void mlx4_en_add_vxlan_port(struct  net_device *dev,
				   sa_family_t sa_family, __be16 port)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	__be16 current_port;

	if (priv->mdev->dev->caps.tunnel_offload_mode != MLX4_TUNNEL_OFFLOAD_MODE_VXLAN)
		return;

	if (sa_family == AF_INET6)
		return;

	current_port = priv->vxlan_port;
	if (current_port && current_port != port) {
		en_warn(priv, "vxlan port %d configured, can't add port %d\n",
			ntohs(current_port), ntohs(port));
		return;
	}

	priv->vxlan_port = port;
	queue_work(priv->mdev->workqueue, &priv->vxlan_add_task);
}

static void mlx4_en_del_vxlan_port(struct  net_device *dev,
				   sa_family_t sa_family, __be16 port)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	__be16 current_port;

	if (priv->mdev->dev->caps.tunnel_offload_mode != MLX4_TUNNEL_OFFLOAD_MODE_VXLAN)
		return;

	if (sa_family == AF_INET6)
		return;

	current_port = priv->vxlan_port;
	if (current_port != port) {
		en_dbg(DRV, priv, "vxlan port %d isn't configured, ignoring\n", ntohs(port));
		return;
	}

	queue_work(priv->mdev->workqueue, &priv->vxlan_del_task);
}

#ifdef HAVE_NETDEV_FEATURES_T
static netdev_features_t mlx4_en_features_check(struct sk_buff *skb,
						struct net_device *dev,
						netdev_features_t features)
{
	return vxlan_features_check(skb, features);
}

#else
#ifdef HAVE_VXLAN_GSO_CHECK
static bool mlx4_en_gso_check(struct sk_buff *skb, struct net_device *dev)
{
	return vxlan_gso_check(skb);
}
#endif
#endif
#endif
#endif

static const struct net_device_ops mlx4_netdev_base_ops = {
	.ndo_open		= mlx4_en_open,
	.ndo_stop		= mlx4_en_close,
	.ndo_start_xmit		= mlx4_en_xmit,
	.ndo_select_queue	= mlx4_en_select_queue,
	.ndo_get_stats		= mlx4_en_get_stats,
	.ndo_set_rx_mode	= mlx4_en_set_rx_mode,
	.ndo_set_mac_address	= mlx4_en_set_mac,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_change_mtu		= mlx4_en_change_mtu,
	.ndo_do_ioctl		= mlx4_en_ioctl,
	.ndo_tx_timeout		= mlx4_en_tx_timeout,
#ifdef HAVE_VLAN_GRO_RECEIVE
	.ndo_vlan_rx_register   = mlx4_en_vlan_rx_register,
#endif
	.ndo_vlan_rx_add_vid	= mlx4_en_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= mlx4_en_vlan_rx_kill_vid,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= mlx4_en_netpoll,
#endif
#if (defined(HAVE_NDO_SET_FEATURES) && !defined(HAVE_NET_DEVICE_OPS_EXT))
	.ndo_set_features	= mlx4_en_set_features,
#endif
#ifdef HAVE_NETIF_F_HW_VLAN_STAG_RX
	.ndo_fix_features	= mlx4_en_fix_features,
#endif
#ifdef HAVE_NDO_SETUP_TC
#ifdef HAVE_NDO_SETUP_TC_4_PARAMS
	.ndo_setup_tc		= __mlx4_en_setup_tc,
#else /* HAVE_NDO_SETUP_TC_4_PARAMS */
	.ndo_setup_tc		= mlx4_en_setup_tc,
#endif /* HAVE_NDO_SETUP_TC_4_PARAMS */
#endif /* HAVE_NDO_SETUP_TC */
#ifdef HAVE_NDO_RX_FLOW_STEER
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer	= mlx4_en_filter_rfs,
#endif
#endif
#ifdef CONFIG_NET_RX_BUSY_POLL
#ifndef HAVE_NETDEV_EXTENDED_NDO_BUSY_POLL
	.ndo_busy_poll		= mlx4_en_low_latency_recv,
#endif
#endif
#ifdef HAVE_NETDEV_NDO_GET_PHYS_PORT_ID
	.ndo_get_phys_port_id	= mlx4_en_get_phys_port_id,
#endif
#ifdef HAVE_VXLAN_ENABLED
#ifdef HAVE_VXLAN_DYNAMIC_PORT
	.ndo_add_vxlan_port	= mlx4_en_add_vxlan_port,
	.ndo_del_vxlan_port	= mlx4_en_del_vxlan_port,
#ifdef HAVE_NETDEV_FEATURES_T
	.ndo_features_check	= mlx4_en_features_check,
#else
#ifdef HAVE_VXLAN_GSO_CHECK
	.ndo_gso_check		= mlx4_en_gso_check,
#endif
#endif
#endif
#endif
};

#ifdef HAVE_NET_DEVICE_OPS_EXT
static const struct net_device_ops_ext mlx4_netdev_ops_ext = {
	.size		  = sizeof(struct net_device_ops_ext),
	.ndo_set_features = mlx4_en_set_features,
#ifdef HAVE_NETDEV_EXT_NDO_GET_PHYS_PORT_ID
	.ndo_get_phys_port_id	= mlx4_en_get_phys_port_id,
#endif
};

static const struct net_device_ops_ext mlx4_netdev_ops_master_ext = {
	.size                   = sizeof(struct net_device_ops_ext),
#ifdef HAVE_NETDEV_OPS_EXT_NDO_SET_VF_SPOOFCHK
	.ndo_set_vf_spoofchk	= mlx4_en_set_vf_spoofchk,
#endif
#if defined(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_LINK_STATE)
	.ndo_set_vf_link_state	= mlx4_en_set_vf_link_state,
#endif
#ifdef HAVE_NETDEV_EXT_NDO_GET_PHYS_PORT_ID
	.ndo_get_phys_port_id	= mlx4_en_get_phys_port_id,
#endif
	.ndo_set_features	= mlx4_en_set_features,
};
#endif

struct mlx4_en_bond {
	struct work_struct work;
	struct mlx4_en_priv *priv;
	int is_bonded;
	struct mlx4_port_map port_map;
};

#ifdef HAVE_NETDEV_BONDING_INFO
static void mlx4_en_bond_work(struct work_struct *work)
{
	struct mlx4_en_bond *bond = container_of(work,
						     struct mlx4_en_bond,
						     work);
	int err = 0;
	struct mlx4_dev *dev = bond->priv->mdev->dev;

	if (bond->is_bonded) {
		if (!mlx4_is_bonded(dev)) {
			err = mlx4_bond(dev);
			if (err)
				en_err(bond->priv, "Fail to bond device\n");
		}
		if (!err) {
			err = mlx4_port_map_set(dev, &bond->port_map);
			if (err)
				en_err(bond->priv, "Fail to set port map [%d][%d]: %d\n",
				       bond->port_map.port1,
				       bond->port_map.port2,
				       err);
		}
	} else if (mlx4_is_bonded(dev)) {
		err = mlx4_unbond(dev);
		if (err)
			en_err(bond->priv, "Fail to unbond device\n");
	}
	dev_put(bond->priv->dev);
	kfree(bond);
}

static int mlx4_en_queue_bond_work(struct mlx4_en_priv *priv, int is_bonded,
				   u8 v2p_p1, u8 v2p_p2)
{
	struct mlx4_en_bond *bond = NULL;

	bond = kzalloc(sizeof(*bond), GFP_ATOMIC);
	if (!bond)
		return -ENOMEM;

	INIT_WORK(&bond->work, mlx4_en_bond_work);
	bond->priv = priv;
	bond->is_bonded = is_bonded;
	bond->port_map.port1 = v2p_p1;
	bond->port_map.port2 = v2p_p2;
	dev_hold(priv->dev);
	queue_work(priv->mdev->workqueue, &bond->work);
	return 0;
}

int mlx4_en_netdev_event(struct notifier_block *this,
			 unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	u8 port = 0;
	struct mlx4_en_dev *mdev;
	struct mlx4_dev *dev;
	int i, num_eth_ports = 0;
	bool do_bond = true;
	struct mlx4_en_priv *priv;
	u8 v2p_port1 = 0;
	u8 v2p_port2 = 0;

	if (!net_eq(dev_net(ndev), &init_net))
		return NOTIFY_DONE;

	mdev = container_of(this, struct mlx4_en_dev, nb);
	dev = mdev->dev;

	/* Go into this mode only when two network devices set on two ports
	 * of the same mlx4 device are slaves of the same bonding master
	 */
	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH) {
		++num_eth_ports;
		if (!port && (mdev->pndev[i] == ndev))
			port = i;
		mdev->upper[i] = mdev->pndev[i] ?
			netdev_master_upper_dev_get(mdev->pndev[i]) : NULL;
		/* condition not met: network device is a slave */
		if (!mdev->upper[i])
			do_bond = false;
		if (num_eth_ports < 2)
			continue;
		/* condition not met: same master */
		if (mdev->upper[i] != mdev->upper[i-1])
			do_bond = false;
	}
	/* condition not met: 2 salves */
	do_bond = (num_eth_ports ==  2) ? do_bond : false;

	/* handle only events that come with enough info */
	if ((do_bond && (event != NETDEV_BONDING_INFO)) || !port)
		return NOTIFY_DONE;

	priv = netdev_priv(ndev);
	if (do_bond) {
		struct netdev_notifier_bonding_info *notifier_info = ptr;
		struct netdev_bonding_info *bonding_info =
			&notifier_info->bonding_info;

		/* required mode 1, 2 or 4 */
		if ((bonding_info->master.bond_mode != BOND_MODE_ACTIVEBACKUP) &&
		    (bonding_info->master.bond_mode != BOND_MODE_XOR) &&
		    (bonding_info->master.bond_mode != BOND_MODE_8023AD))
			do_bond = false;

		/* require exactly 2 slaves */
		if (bonding_info->master.num_slaves != 2)
			do_bond = false;

		/* calc v2p */
		if (do_bond) {
			if (bonding_info->master.bond_mode ==
			    BOND_MODE_ACTIVEBACKUP) {
				/* in active-backup mode virtual ports are
				 * mapped to the physical port of the active
				 * slave */
				if (bonding_info->slave.state ==
				    BOND_STATE_BACKUP) {
					if (port == 1) {
						v2p_port1 = 2;
						v2p_port2 = 2;
					} else {
						v2p_port1 = 1;
						v2p_port2 = 1;
					}
				} else { /* BOND_STATE_ACTIVE */
					if (port == 1) {
						v2p_port1 = 1;
						v2p_port2 = 1;
					} else {
						v2p_port1 = 2;
						v2p_port2 = 2;
					}
				}
			} else { /* Active-Active */
				/* in active-active mode a virtual port is
				 * mapped to the native physical port if and only
				 * if the physical port is up */
				__s8 link = bonding_info->slave.link;

				if (port == 1)
					v2p_port2 = 2;
				else
					v2p_port1 = 1;
				if ((link == BOND_LINK_UP) ||
				    (link == BOND_LINK_FAIL)) {
					if (port == 1)
						v2p_port1 = 1;
					else
						v2p_port2 = 2;
				} else { /* BOND_LINK_DOWN || BOND_LINK_BACK */
					if (port == 1)
						v2p_port1 = 2;
					else
						v2p_port2 = 1;
				}
			}
		}
	}

	mlx4_en_queue_bond_work(priv, do_bond,
				v2p_port1, v2p_port2);

	return NOTIFY_DONE;
}
#endif

void mlx4_en_update_pfc_stats_bitmap(struct mlx4_dev *dev,
				     struct mlx4_en_stats_bitmap *stats_bitmap,
				     u8 rx_ppp, u8 rx_pause,
				     u8 tx_ppp, u8 tx_pause)
{
	int last_i = NUM_MAIN_STATS + NUM_PORT_STATS;

	if (!mlx4_is_slave(dev) &&
	    (dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_FLOWSTATS_EN)) {
		mutex_lock(&stats_bitmap->mutex);
		bitmap_clear(stats_bitmap->bitmap, last_i, NUM_FLOW_STATS);

		if (rx_ppp)
			bitmap_set(stats_bitmap->bitmap, last_i,
				   NUM_FLOW_PRIORITY_STATS_RX);
		last_i += NUM_FLOW_PRIORITY_STATS_RX;

		if (rx_pause && !(rx_ppp))
			bitmap_set(stats_bitmap->bitmap, last_i,
				   NUM_FLOW_STATS_RX);
		last_i += NUM_FLOW_STATS_RX;

		if (tx_ppp)
			bitmap_set(stats_bitmap->bitmap, last_i,
				   NUM_FLOW_PRIORITY_STATS_TX);
		last_i += NUM_FLOW_PRIORITY_STATS_TX;

		if (tx_pause && !(tx_ppp))
			bitmap_set(stats_bitmap->bitmap, last_i,
				   NUM_FLOW_STATS_TX);
		last_i += NUM_FLOW_STATS_TX;

		mutex_unlock(&stats_bitmap->mutex);
	}
}

void mlx4_en_set_stats_bitmap(struct mlx4_dev *dev,
			      struct mlx4_en_stats_bitmap *stats_bitmap,
			      u8 rx_ppp, u8 rx_pause,
			      u8 tx_ppp, u8 tx_pause)
{
	int last_i = 0;

	mutex_init(&stats_bitmap->mutex);
	bitmap_zero(stats_bitmap->bitmap, NUM_ALL_STATS);

	if (mlx4_is_slave(dev)) {
		bitmap_set(stats_bitmap->bitmap, last_i +
					 MLX4_FIND_NETDEV_STAT(rx_packets), 1);
		bitmap_set(stats_bitmap->bitmap, last_i +
					 MLX4_FIND_NETDEV_STAT(tx_packets), 1);
		bitmap_set(stats_bitmap->bitmap, last_i +
					 MLX4_FIND_NETDEV_STAT(rx_bytes), 1);
		bitmap_set(stats_bitmap->bitmap, last_i +
					 MLX4_FIND_NETDEV_STAT(tx_bytes), 1);
		bitmap_set(stats_bitmap->bitmap, last_i +
					 MLX4_FIND_NETDEV_STAT(rx_dropped), 1);
		bitmap_set(stats_bitmap->bitmap, last_i +
					 MLX4_FIND_NETDEV_STAT(tx_dropped), 1);
	} else {
		bitmap_set(stats_bitmap->bitmap, last_i, NUM_MAIN_STATS);
	}
	last_i += NUM_MAIN_STATS;

	bitmap_set(stats_bitmap->bitmap, last_i, NUM_PORT_STATS);
	last_i += NUM_PORT_STATS;

	mlx4_en_update_pfc_stats_bitmap(dev, stats_bitmap,
					rx_ppp, rx_pause,
					tx_ppp, tx_pause);
	last_i += NUM_FLOW_STATS;

	if (mlx4_is_slave(dev))
		bitmap_set(stats_bitmap->bitmap, last_i, NUM_VF_STATS);
	last_i += NUM_VF_STATS;

	if (!mlx4_is_slave(dev))
		bitmap_set(stats_bitmap->bitmap, last_i, NUM_VPORT_STATS);
	last_i += NUM_VPORT_STATS;

	if (!mlx4_is_slave(dev))
		bitmap_set(stats_bitmap->bitmap, last_i, NUM_PKT_STATS);
}

static void mlx4_en_set_netdev_ops(struct mlx4_en_priv *priv)
{
	if (priv->vgtp)
		priv->dev_ops.ndo_start_xmit = mlx4_en_vgtp_xmit;

	if (mlx4_is_master(priv->mdev->dev)) {
#ifdef HAVE_NDO_SET_VF_MAC
		priv->dev_ops.ndo_set_vf_mac = mlx4_en_set_vf_mac;
		priv->dev_ops.ndo_set_vf_vlan = mlx4_en_set_vf_vlan;
#endif
#ifdef HAVE_TX_RATE_LIMIT
		priv->dev_ops.ndo_set_vf_rate = mlx4_en_set_vf_rate;
#elif defined(HAVE_VF_TX_RATE)
		priv->dev_ops.ndo_set_vf_tx_rate =  mlx4_en_set_vf_tx_rate;
#endif
#if (defined(HAVE_NETDEV_OPS_NDO_SET_VF_SPOOFCHK) && !defined(HAVE_NET_DEVICE_OPS_EXT))
		priv->dev_ops.ndo_set_vf_spoofchk = mlx4_en_set_vf_spoofchk;
#endif
#if (defined(HAVE_NETDEV_OPS_NDO_SET_VF_LINK_STATE) && !defined(HAVE_NET_DEVICE_OPS_EXT))
		priv->dev_ops.ndo_set_vf_link_state = mlx4_en_set_vf_link_state;
#endif
#ifdef HAVE_NDO_SET_VF_MAC
		priv->dev_ops.ndo_get_vf_config = mlx4_en_get_vf_config;
#endif
	}

	priv->dev->netdev_ops = &priv->dev_ops;

#ifdef HAVE_NET_DEVICE_OPS_EXT
	if (mlx4_is_master(priv->mdev->dev)) {
		set_netdev_ops_ext(priv->dev, &mlx4_netdev_ops_master_ext);
	}
	else {
		set_netdev_ops_ext(priv->dev, &mlx4_netdev_ops_ext);
	}
#endif
}

int mlx4_en_init_netdev(struct mlx4_en_dev *mdev, int port,
			struct mlx4_en_port_profile *prof)
{
	struct net_device *dev;
	struct mlx4_en_priv *priv;
	int i;
	int err;
	u64 mac_u64;
#if (!defined(CONFIG_COMPAT_DISABLE_DCB) && defined(CONFIG_MLX4_EN_DCB))
	u8 config = 0;
	struct tc_configuration *tc;
#endif
#ifdef HAVE_NEW_TX_RING_SCHEME
	dev = alloc_etherdev_mqs(sizeof(struct mlx4_en_priv),
				 MAX_TX_RINGS, MAX_RX_RINGS);
#else
	dev = alloc_etherdev_mq(sizeof(struct mlx4_en_priv), MAX_TX_RINGS);
#endif
	if (dev == NULL)
		return -ENOMEM;

#ifdef HAVE_NEW_TX_RING_SCHEME
	netif_set_real_num_tx_queues(dev, prof->tx_ring_num);
#else
	dev->real_num_tx_queues = prof->tx_ring_num;
#endif
	netif_set_real_num_rx_queues(dev, prof->rx_ring_num);

	SET_NETDEV_DEV(dev, &mdev->dev->persist->pdev->dev);
#ifdef HAVE_NET_DEVICE_DEV_PORT
	dev->dev_port = port - 1;
#else
	dev->dev_id = port - 1;
#endif

	/*
	 * Initialize driver private data
	 */

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct mlx4_en_priv));
	priv->dev_ops = mlx4_netdev_base_ops;
	priv->counter_index = 0xff;
	spin_lock_init(&priv->stats_lock);
	INIT_WORK(&priv->rx_mode_task, mlx4_en_do_set_rx_mode);
	INIT_WORK(&priv->watchdog_task, mlx4_en_restart);
	INIT_WORK(&priv->linkstate_task, mlx4_en_linkstate);
	INIT_DELAYED_WORK(&priv->stats_task, mlx4_en_do_get_stats);
	INIT_DELAYED_WORK(&priv->service_task, mlx4_en_service_task);
#ifdef HAVE_VXLAN_ENABLED
	INIT_WORK(&priv->vxlan_add_task, mlx4_en_add_vxlan_offloads);
	INIT_WORK(&priv->vxlan_del_task, mlx4_en_del_vxlan_offloads);
#endif
#ifdef CONFIG_RFS_ACCEL
	INIT_LIST_HEAD(&priv->filters);
	spin_lock_init(&priv->filters_lock);
#endif

	priv->dev = dev;
	priv->mdev = mdev;
	priv->ddev = &mdev->pdev->dev;
	priv->prof = prof;
	priv->port = port;
	priv->port_up = false;
	priv->flags = prof->flags;
	priv->pflags = MLX4_EN_PRIV_FLAGS_BLUEFLAME;
	priv->ctrl_flags = cpu_to_be32(MLX4_WQE_CTRL_CQ_UPDATE |
			MLX4_WQE_CTRL_SOLICITED);
	priv->num_tx_rings_p_up =
		mdev->profile.prof[priv->port].num_tx_rings_p_up;
	priv->tx_ring_num = prof->tx_ring_num;
	priv->num_up = prof->num_up;
	priv->tx_work_limit = MLX4_EN_DEFAULT_TX_WORK;
#ifdef HAVE_NETDEV_RSS_KEY_FILL
	netdev_rss_key_fill(priv->rss_key, sizeof(priv->rss_key));
#endif

	priv->tx_ring = kzalloc(sizeof(struct mlx4_en_tx_ring *) * MAX_TX_RINGS,
				GFP_KERNEL);
	if (!priv->tx_ring) {
		err = -ENOMEM;
		goto out;
	}
	priv->tx_cq = kzalloc(sizeof(struct mlx4_en_cq *) * MAX_TX_RINGS,
			      GFP_KERNEL);
	if (!priv->tx_cq) {
		err = -ENOMEM;
		goto out;
	}
	priv->rx_ring_num = prof->rx_ring_num;
	priv->cqe_factor = (mdev->dev->caps.cqe_size == 64) ? 1 : 0;
	priv->cqe_size = mdev->dev->caps.cqe_size;
	priv->mac_index = -1;
	priv->msg_enable = MLX4_EN_MSG_LEVEL;
#ifndef CONFIG_COMPAT_DISABLE_DCB
#ifdef CONFIG_MLX4_EN_DCB
	if (!mlx4_is_slave(priv->mdev->dev)) {
		u8 prio;

		for (prio = 0; prio < IEEE_8021QAZ_MAX_TCS; ++prio) {
			priv->ets.prio_tc[prio] = prio;
			priv->ets.tc_tsa[prio] = IEEE_8021QAZ_TSA_VENDOR;
		}

		priv->cee_params.dcbx_cap = DCB_CAP_DCBX_VER_CEE |
					    DCB_CAP_DCBX_HOST |
					    DCB_CAP_DCBX_VER_IEEE;
		priv->flags |= MLX4_EN_DCB_ENABLED;
		priv->cee_params.dcb_cfg.pfc_state = false;

		for (i = 0; i < MLX4_EN_NUM_UP; i++) {
			tc = &priv->cee_params.dcb_cfg.tc_config[i];
			tc->dcb_pfc = pfc_disabled;
		}

		if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_ETS_CFG) {
			dev->dcbnl_ops = &mlx4_en_dcbnl_ops;
		} else {
			en_info(priv, "enabling only PFC DCB ops\n");
			dev->dcbnl_ops = &mlx4_en_dcbnl_pfc_ops;
		}
		/* Query for defalut disable_32_14_4_e value for qcn */
		err = mlx4_disable_32_14_4_e_read(priv->mdev->dev, &config, priv->port);
		if (!err) {
			if (config)
				priv->pflags |= MLX4_EN_PRIV_FLAGS_DISABLE_32_14_4_E;
			else
				priv->pflags &= ~MLX4_EN_PRIV_FLAGS_DISABLE_32_14_4_E;
		} else {
			en_err(priv, "Failed to query disable_32_14_4_e field for QCN\n");
		}
	}
#endif
#endif

	for (i = 0; i < MLX4_EN_MAC_HASH_SIZE; ++i)
		INIT_HLIST_HEAD(&priv->mac_hash[i]);

	/* Query for default mac and max mtu */
	priv->max_mtu = mdev->dev->caps.eth_mtu_cap[priv->port];

	if (mdev->dev->caps.rx_checksum_flags_port[priv->port] &
	    MLX4_RX_CSUM_MODE_VAL_NON_TCP_UDP)
		priv->flags |= MLX4_EN_FLAG_RX_CSUM_NON_TCP_UDP;

	/* Set default MAC */
	dev->addr_len = ETH_ALEN;
	mlx4_en_u64_to_mac(dev->dev_addr, mdev->dev->caps.def_mac[priv->port]);
	if (!is_valid_ether_addr(dev->dev_addr)) {
		if (mlx4_is_slave(priv->mdev->dev)) {
			eth_hw_addr_random(dev);
			en_warn(priv, "Assigned random MAC address %pM\n", dev->dev_addr);
			mac_u64 = mlx4_mac_to_u64(dev->dev_addr);
			mdev->dev->caps.def_mac[priv->port] = mac_u64;
		} else {
			en_err(priv, "Port: %d, invalid mac burned: %pM, quiting\n",
			       priv->port, dev->dev_addr);
			err = -EINVAL;
			goto out;
		}
	} else if (mlx4_is_slave(priv->mdev->dev) &&
		   (priv->mdev->dev->port_random_macs & 1 << priv->port)) {
		/* Random MAC was assigned in mlx4_slave_cap
		 * in mlx4_core module
		 */
#ifdef HAVE_NETDEV_ADDR_ASSIGN_TYPE
		dev->addr_assign_type |= NET_ADDR_RANDOM;
#endif
		en_warn(priv, "Assigned random MAC address %pM\n", dev->dev_addr);
	}

	memcpy(priv->current_mac, dev->dev_addr, sizeof(priv->current_mac));

	priv->stride = prof->inline_scatter_thold >= MIN_INLINE_SCATTER ?
			prof->inline_scatter_thold :
			roundup_pow_of_two(sizeof(struct mlx4_en_rx_desc) +
				DS_SIZE * MLX4_EN_MAX_RX_FRAGS);

	err = mlx4_en_alloc_resources(priv);
	if (err)
		goto out;

	/* Initialize time stamping config */
	priv->hwtstamp_config.flags = 0;
	priv->hwtstamp_config.tx_type = HWTSTAMP_TX_OFF;
	priv->hwtstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;

	/* Allocate page for receive rings */
	err = mlx4_alloc_hwq_res(mdev->dev, &priv->res,
				MLX4_EN_PAGE_SIZE, MLX4_EN_PAGE_SIZE);
	if (err) {
		en_err(priv, "Failed to allocate page for rx qps\n");
		goto out;
	}
	priv->allocated = 1;

	priv->vgtp = 0;
	if (mdev->dev->caps.force_vlan[priv->port - 1]) {
		priv->vgtp = kmalloc(sizeof(*priv->vgtp), GFP_KERNEL);
		if (!priv->vgtp)
			en_err(priv, "Failed to allocate VGT+ resources for port (%d)\n",
			       priv->port);
		priv->vgtp->bitmap = kcalloc(BITS_TO_LONGS(VLAN_N_VID),
					     sizeof(uintptr_t), GFP_KERNEL);
		if (!priv->vgtp->bitmap) {
			en_err(priv, "Failed to allocate VGT+ resources for port (%d)\n",
			       priv->port);
			kfree(priv->vgtp);
			priv->vgtp = NULL;
		}
		memset(priv->vgtp->rings, 0, sizeof(priv->vgtp->rings));
		for (i = 0; i < VLAN_N_VID; i++)
			priv->vgtp->tx_map[i] = -1;
	}

	/*
	 * Initialize netdev entry points
	 */
	mlx4_en_set_netdev_ops(priv);

	dev->watchdog_timeo = MLX4_EN_WATCHDOG_TIMEOUT;
#ifdef HAVE_NEW_TX_RING_SCHEME
	netif_set_real_num_tx_queues(dev, priv->tx_ring_num);
#else
	dev->real_num_tx_queues = priv->tx_ring_num;
#endif
	netif_set_real_num_rx_queues(dev, priv->rx_ring_num);

#ifdef HAVE_ETHTOOL_OPS_EXT
	SET_ETHTOOL_OPS(dev, &mlx4_en_ethtool_ops);
	set_ethtool_ops_ext(dev, &mlx4_en_ethtool_ops_ext);
#else

	dev->ethtool_ops = &mlx4_en_ethtool_ops;
#endif
#ifdef CONFIG_NET_RX_BUSY_POLL
#ifdef HAVE_NETDEV_EXTENDED_NDO_BUSY_POLL
	netdev_extended(dev)->ndo_busy_poll = mlx4_en_low_latency_recv;
#endif
#endif

	/*
	 * Set driver features
	 */
#ifdef HAVE_NETDEV_HW_FEATURES
	dev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
	if (mdev->LSO_support)
		dev->hw_features |= NETIF_F_TSO | NETIF_F_TSO6;

	dev->vlan_features = dev->hw_features;

#ifdef HAVE_NETIF_F_RXHASH
	dev->hw_features |= NETIF_F_RXCSUM | NETIF_F_RXHASH;
#else
	dev->hw_features |= NETIF_F_RXCSUM;
#endif
	dev->features = dev->hw_features | NETIF_F_HIGHDMA |
			NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX |
			NETIF_F_HW_VLAN_CTAG_FILTER;
	dev->hw_features |= NETIF_F_LOOPBACK |
			NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX;

#ifdef HAVE_NETIF_F_HW_VLAN_STAG_RX
	if (!(mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_SKIP_OUTER_VLAN)) {
		dev->features |= NETIF_F_HW_VLAN_STAG_RX |
			NETIF_F_HW_VLAN_STAG_FILTER;
		dev->hw_features |= NETIF_F_HW_VLAN_STAG_RX;
	}

	if (mlx4_is_slave(mdev->dev)) {
		int phv;

		err = get_phv_bit(mdev->dev, port, &phv);
		if (!err && phv) {
			dev->hw_features |= NETIF_F_HW_VLAN_STAG_TX;
			priv->pflags |= MLX4_EN_PRIV_FLAGS_PHV;
		}
	} else {
		if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_PHV_EN &&
		    !(mdev->dev->caps.flags2 &
		      MLX4_DEV_CAP_FLAG2_SKIP_OUTER_VLAN))
			dev->hw_features |= NETIF_F_HW_VLAN_STAG_TX;
	}
#endif	
#ifdef HAVE_NETIF_F_RXFCS
	if (mdev->dev->caps.flags & MLX4_DEV_CAP_FLAG_FCS_KEEP)
		dev->hw_features |= NETIF_F_RXFCS;
#endif

#ifdef HAVE_NETIF_F_RXALL
	if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_IGNORE_FCS)
		dev->hw_features |= NETIF_F_RXALL;
#endif

	if (mdev->dev->caps.steering_mode ==
	    MLX4_STEERING_MODE_DEVICE_MANAGED &&
	    mdev->dev->caps.dmfs_high_steer_mode != MLX4_STEERING_DMFS_A0_STATIC)
		dev->hw_features |= NETIF_F_NTUPLE;

#ifndef NETIF_F_SOFT_FEATURES
	dev->hw_features |= NETIF_F_GSO | NETIF_F_GRO;
	dev->features |= NETIF_F_GSO | NETIF_F_GRO;
#endif
#ifdef CONFIG_COMPAT_LRO_ENABLED
	dev->hw_features |= NETIF_F_LRO;
	dev->features |= NETIF_F_LRO;
#endif
#else
	dev->features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;

	if (mdev->LSO_support)
		dev->features |= NETIF_F_TSO | NETIF_F_TSO6;

	dev->vlan_features = dev->features;

#ifdef HAVE_NETIF_F_RXHASH
	dev->features |= NETIF_F_RXCSUM | NETIF_F_RXHASH;
#else
	dev->features |= NETIF_F_RXCSUM;
#endif

#ifdef CONFIG_COMPAT_LRO_ENABLED
	dev->features |= NETIF_F_LRO;
#endif
#ifdef HAVE_SET_NETDEV_HW_FEATURES
	set_netdev_hw_features(dev, dev->features);
#endif
	dev->features = dev->features | NETIF_F_HIGHDMA |
			NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX |
			NETIF_F_HW_VLAN_CTAG_FILTER;
#ifdef HAVE_NETDEV_EXTENDED_HW_FEATURES
	netdev_extended(dev)->hw_features |= NETIF_F_LOOPBACK;
	netdev_extended(dev)->hw_features |= NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX;
#endif

	if (mdev->dev->caps.steering_mode ==
		MLX4_STEERING_MODE_DEVICE_MANAGED)
#ifdef HAVE_NETDEV_EXTENDED_HW_FEATURES
		netdev_extended(dev)->hw_features |= NETIF_F_NTUPLE;
#else
		dev->features |= NETIF_F_NTUPLE;
#endif

#ifndef NETIF_F_SOFT_FEATURES
	dev->features |= NETIF_F_GSO | NETIF_F_GRO;
#endif
#endif

#ifdef HAVE_NETDEV_IFF_UNICAST_FLT
	if (mdev->dev->caps.steering_mode != MLX4_STEERING_MODE_A0)
		dev->priv_flags |= IFF_UNICAST_FLT;
#endif

	/* Setting a default hash function value */
	if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_RSS_TOP) {
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
		priv->rss_hash_fn = ETH_RSS_HASH_TOP;
#else
		priv->pflags &= ~MLX4_EN_PRIV_FLAGS_RSS_HASH_XOR;
#ifdef HAVE_NETIF_F_RXHASH
		dev->features |= NETIF_F_RXHASH;
#endif
#endif
	} else if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_RSS_XOR) {
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
		priv->rss_hash_fn = ETH_RSS_HASH_XOR;
#else
		priv->pflags |= MLX4_EN_PRIV_FLAGS_RSS_HASH_XOR;
#ifdef HAVE_NETIF_F_RXHASH
		dev->features &= ~NETIF_F_RXHASH;
#endif
#endif
	} else {
		en_warn(priv,
			"No RSS hash capabilities exposed, using Toeplitz\n");
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
		priv->rss_hash_fn = ETH_RSS_HASH_TOP;
#else
		priv->pflags &= ~MLX4_EN_PRIV_FLAGS_RSS_HASH_XOR;
#ifdef HAVE_NETIF_F_RXHASH
		dev->features |= NETIF_F_RXHASH;
#endif
#endif
	}

	mdev->pndev[port] = dev;
	mdev->upper[port] = NULL;

	netif_carrier_off(dev);
	mlx4_en_set_default_moderation(priv);

	en_warn(priv, "Using %d TX rings\n", prof->tx_ring_num);
	en_warn(priv, "Using %d RX rings\n", prof->rx_ring_num);

	mlx4_en_update_loopback_state(priv->dev, priv->dev->features);

	/* Configure port */
	mlx4_en_calc_rx_buf(dev);
	err = mlx4_SET_PORT_general(mdev->dev, priv->port,
				    priv->rx_skb_size + ETH_FCS_LEN,
				    prof->tx_pause, prof->tx_ppp,
				    prof->rx_pause, prof->rx_ppp);
	if (err) {
		en_err(priv, "Failed setting port general configurations for port %d, with error %d\n",
		       priv->port, err);
		goto out;
	}

	if (mdev->dev->caps.tunnel_offload_mode == MLX4_TUNNEL_OFFLOAD_MODE_VXLAN) {
		err = mlx4_SET_PORT_VXLAN(mdev->dev, priv->port, VXLAN_STEER_BY_OUTER_MAC, 1);
		if (err) {
			en_err(priv, "Failed setting port L2 tunnel configuration, err %d\n",
			       err);
			goto out;
		}
	}

	/* Init port */
	en_warn(priv, "Initializing port\n");
	err = mlx4_INIT_PORT(mdev->dev, priv->port);
	if (err) {
		en_err(priv, "Failed Initializing port\n");
		goto out;
	}
	queue_delayed_work(mdev->workqueue, &priv->stats_task, STATS_DELAY);

	if (mdev->dev->caps.steering_mode ==
	    MLX4_STEERING_MODE_DEVICE_MANAGED) {
		priv->pflags |= MLX4_EN_PRIV_FLAGS_FS_EN_L2;
		if (mdev->dev->caps.dmfs_high_steer_mode != MLX4_STEERING_DMFS_A0_STATIC)
			priv->pflags |= MLX4_EN_PRIV_FLAGS_FS_EN_IPV4	|
					MLX4_EN_PRIV_FLAGS_FS_EN_TCP	|
					MLX4_EN_PRIV_FLAGS_FS_EN_UDP;
	}
	/* Initialize time stamp mechanism */
	if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_TS)
		mlx4_en_init_timestamp(mdev);

	queue_delayed_work(mdev->workqueue, &priv->service_task,
			   SERVICE_TASK_DELAY);

	mlx4_en_set_stats_bitmap(mdev->dev, &priv->stats_bitmap,
				 mdev->profile.prof[priv->port].rx_ppp,
				 mdev->profile.prof[priv->port].rx_pause,
				 mdev->profile.prof[priv->port].tx_ppp,
				 mdev->profile.prof[priv->port].tx_pause);

	err = register_netdev(dev);
	if (err) {
		en_err(priv, "Netdev registration failed for port %d\n", port);
		goto out;
	}

	if (!is_valid_ether_addr(dev->perm_addr))
		memcpy(dev->perm_addr, dev->dev_addr, dev->addr_len);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
        if (mlx4_is_mfunc(priv->mdev->dev)) {
                err = device_create_file(&dev->dev, &dev_attr_fdb);
                if (err) {
                        en_err(priv, "Sysfs registration failed for port %d\n", port);
                        goto out;
                }
        }
#endif

	priv->registered = 1;

	if (mlx4_is_master(priv->mdev->dev)) {
		for (i = 0; i < priv->mdev->dev->persist->num_vfs; i++) {
			priv->vf_ports[i] = kzalloc(sizeof(*priv->vf_ports[i]), GFP_KERNEL);
			if (!priv->vf_ports[i]) {
				err = -ENOMEM;
				goto out;
			}
			priv->vf_ports[i]->dev = priv->mdev->dev;
			priv->vf_ports[i]->port_num = port & 0xff;
			priv->vf_ports[i]->vport_num = i & 0xff;
			err = kobject_init_and_add(&priv->vf_ports[i]->kobj_vf,
						   &en_port_type,
						   &dev->dev.kobj,
						   "vf%d", i);
			if (err) {
				kfree(priv->vf_ports[i]);
				priv->vf_ports[i] = NULL;
				goto out;
			}
			err = kobject_init_and_add(&priv->vf_ports[i]->kobj_stats,
						   &en_port_stats,
						   &priv->vf_ports[i]->kobj_vf,
						   "statistics");
			if (err) {
				kobject_put(&priv->vf_ports[i]->kobj_vf);
				kfree(priv->vf_ports[i]);
				priv->vf_ports[i] = NULL;
				goto out;
			}
		}
	}

#ifdef CONFIG_COMPAT_EN_SYSFS
	err = mlx4_en_sysfs_create(dev);
	if (err)
		goto out;
	priv->sysfs_group_initialized = 1;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	if (mlx4_is_mfunc(priv->mdev->dev)) {
		err = device_create_file(&dev->dev, &dev_attr_fdb_det);
		if (err) {
			en_err(priv,
			       "Sysfs (fdb_det) registration failed port %d\n",
			       port);
			goto out;
		}
	}
#endif

	return 0;

out:
	mlx4_en_destroy_netdev(dev);
	return err;
}

int mlx4_en_reset_config(struct net_device *dev,
			 struct hwtstamp_config ts_config,
			 netdev_features_t features)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int port_up = 0;
	int err = 0;

	if (priv->hwtstamp_config.tx_type == ts_config.tx_type &&
	    priv->hwtstamp_config.rx_filter == ts_config.rx_filter &&
	    !DEV_FEATURE_CHANGED(dev, features, NETIF_F_HW_VLAN_CTAG_RX)
#ifdef HAVE_NETIF_F_RXFCS
	    && !DEV_FEATURE_CHANGED(dev, features, NETIF_F_RXFCS)
#endif
	   )
		return 0; /* Nothing to change */

	if (DEV_FEATURE_CHANGED(dev, features, NETIF_F_HW_VLAN_CTAG_RX) &&
	    (features & NETIF_F_HW_VLAN_CTAG_RX) &&
	    (priv->hwtstamp_config.rx_filter != HWTSTAMP_FILTER_NONE)) {
		en_warn(priv, "Can't turn ON rx vlan offload while time-stamping rx filter is ON\n");
		return -EINVAL;
	}

	mutex_lock(&mdev->state_lock);
	if (priv->port_up) {
		port_up = 1;
		mlx4_en_stop_port(dev, 1);
	}

	mlx4_en_free_resources(priv);

	en_warn(priv, "Changing device configuration rx filter(%x) rx vlan(%x)\n",
		ts_config.rx_filter, !!(features & NETIF_F_HW_VLAN_CTAG_RX));

	priv->hwtstamp_config.tx_type = ts_config.tx_type;
	priv->hwtstamp_config.rx_filter = ts_config.rx_filter;

	if (DEV_FEATURE_CHANGED(dev, features, NETIF_F_HW_VLAN_CTAG_RX)) {
		if (features & NETIF_F_HW_VLAN_CTAG_RX)
			dev->features |= NETIF_F_HW_VLAN_CTAG_RX;
		else
			dev->features &= ~NETIF_F_HW_VLAN_CTAG_RX;
#ifdef HAVE_WANTED_FEATURES
	} else if (ts_config.rx_filter == HWTSTAMP_FILTER_NONE) {
		/* RX time-stamping is OFF, update the RX vlan offload
		 * to the latest wanted state
		 */
		if (dev->wanted_features & NETIF_F_HW_VLAN_CTAG_RX)
			dev->features |= NETIF_F_HW_VLAN_CTAG_RX;
		else
			dev->features &= ~NETIF_F_HW_VLAN_CTAG_RX;
#endif
	}

#ifdef HAVE_NETIF_F_RXFCS
	if (DEV_FEATURE_CHANGED(dev, features, NETIF_F_RXFCS)) {
		if (features & NETIF_F_RXFCS)
			dev->features |= NETIF_F_RXFCS;
		else
			dev->features &= ~NETIF_F_RXFCS;
	}
#endif

	/* RX vlan offload and RX time-stamping can't co-exist !
	 * Regardless of the caller's choice,
	 * Turn Off RX vlan offload in case of time-stamping is ON
	 */
	if (ts_config.rx_filter != HWTSTAMP_FILTER_NONE) {
		if (dev->features & NETIF_F_HW_VLAN_CTAG_RX)
			en_warn(priv, "Turning off RX vlan offload since RX time-stamping is ON\n");
		dev->features &= ~NETIF_F_HW_VLAN_CTAG_RX;
	}

	err = mlx4_en_alloc_resources(priv);
	if (err) {
		en_err(priv, "Failed reallocating port resources\n");
		goto out;
	}
	if (port_up) {
		err = mlx4_en_start_port(dev);
		if (err)
			en_err(priv, "Failed starting port\n");
	}

out:
	mutex_unlock(&mdev->state_lock);
	netdev_features_change(dev);
	return err;
}

