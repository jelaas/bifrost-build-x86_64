/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

#include <linux/cpumask.h>
#if defined(HAVE_VXLAN_ENABLED) && defined(HAVE_VXLAN_DYNAMIC_PORT)
#include <net/vxlan.h>
#include "vxlan.h"
#endif
#include "en.h"
#include "eswitch.h"

struct mlx5e_rq_param {
	u32                        rqc[MLX5_ST_SZ_DW(rqc)];
	struct mlx5_wq_param       wq;
};

struct mlx5e_sq_param {
	u32                        sqc[MLX5_ST_SZ_DW(sqc)];
	struct mlx5_wq_param       wq;
};

struct mlx5e_cq_param {
	u32                        cqc[MLX5_ST_SZ_DW(cqc)];
	struct mlx5_wq_param       wq;
	u16                        eq_ix;
};

struct mlx5e_channel_param {
	struct mlx5e_rq_param      rq;
	struct mlx5e_sq_param      sq;
	struct mlx5e_cq_param      rx_cq;
	struct mlx5e_cq_param      tx_cq;
};

static void mlx5e_update_carrier(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u8 port_state;

	port_state = mlx5_query_vport_state(mdev,
		MLX5_QUERY_VPORT_STATE_IN_OP_MOD_VNIC_VPORT, 0);

	if (port_state == VPORT_STATE_UP)
		netif_carrier_on(priv->netdev);
	else
		netif_carrier_off(priv->netdev);
}

static void mlx5e_update_carrier_work(struct work_struct *work)
{
	struct mlx5e_priv *priv = container_of(work, struct mlx5e_priv,
					       update_carrier_work);

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_update_carrier(priv);
	mutex_unlock(&priv->state_lock);
}

static void mlx5e_tx_timeout_work(struct work_struct *work)
{
	struct mlx5e_priv *priv = container_of(work, struct mlx5e_priv,
					       tx_timeout_work);
	int err;

	rtnl_lock();
	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		mlx5e_close_locked(priv->netdev);
		err = mlx5e_open_locked(priv->netdev);
		if (err)
			netdev_err(priv->netdev, "mlx5e_open_locked failed recovering from a tx_timeout, err(%d).\n",
				   err);
	}
	mutex_unlock(&priv->state_lock);
	rtnl_unlock();
}

static void mlx5e_update_sw_counters(struct mlx5e_priv *priv)
{
	struct mlx5e_sw_stats *ss = &priv->stats.sw;
	struct mlx5e_rq_stats *rq_stats;
	struct mlx5e_sq_stats *sq_stats;
	int i, j;

	memset(ss, 0, sizeof(*ss));
	for (i = 0; i < priv->params.num_channels; i++) {
		rq_stats = &priv->channel[i]->rq.stats;

		ss->rx_packets		+= rq_stats->packets;
		ss->rx_bytes		+= rq_stats->bytes;
		ss->lro_packets		+= rq_stats->lro_packets;
		ss->lro_bytes		+= rq_stats->lro_bytes;
		ss->rx_csum_none	+= rq_stats->csum_none;
		ss->rx_csum_sw		+= rq_stats->csum_sw;
		ss->rx_csum_inner	+= rq_stats->csum_inner;
		ss->rx_wqe_err		+= rq_stats->wqe_err;

		for (j = 0; j < priv->params.num_tc; j++) {
			sq_stats = &priv->channel[i]->sq[j].stats;

			ss->tx_packets		+= sq_stats->packets;
			ss->tx_bytes		+= sq_stats->bytes;
			ss->tso_packets		+= sq_stats->tso_packets;
			ss->tso_bytes		+= sq_stats->tso_bytes;
			ss->tso_inner_packets	+= sq_stats->tso_inner_packets;
			ss->tso_inner_bytes	+= sq_stats->tso_inner_bytes;
			ss->tx_queue_stopped	+= sq_stats->stopped;
			ss->tx_queue_wake	+= sq_stats->wake;
			ss->tx_queue_dropped	+= sq_stats->dropped;
			ss->tx_csum_none	+= sq_stats->csum_offload_none;
			ss->tx_csum_offload	+= sq_stats->csum_offload_part;
			ss->tx_csum_inner	+= sq_stats->csum_offload_inner;
		}
	}

	/* Update calculated offload counters */
	ss->rx_csum_good	= ss->rx_packets - ss->rx_csum_none -
				  ss->rx_csum_sw - ss->rx_csum_inner;

	ss->link_down_events = MLX5_GET(ppcnt_reg,
				priv->stats.pport.phy_counters,
				counter_set.phys_layer_cntrs.link_down_events);
}

static void mlx5e_update_vport_counters(struct mlx5e_priv *priv)
{
	int outlen = MLX5_ST_SZ_BYTES(query_vport_counter_out);
	u32 in[MLX5_ST_SZ_DW(query_vport_counter_in)];
	u32 *out = (u32 *)priv->stats.vport.query_vport_out;
	struct mlx5_core_dev *mdev = priv->mdev;

	memset(in, 0, sizeof(in));

	MLX5_SET(query_vport_counter_in, in, opcode,
		 MLX5_CMD_OP_QUERY_VPORT_COUNTER);
	MLX5_SET(query_vport_counter_in, in, op_mod, 0);
	MLX5_SET(query_vport_counter_in, in, other_vport, 0);

	memset(out, 0, outlen);

	mlx5_cmd_exec(mdev, in, sizeof(in), out, outlen);
}

static void mlx5e_update_pport_counters(struct mlx5e_priv *priv)
{
	struct mlx5e_pport_stats *pstats = &priv->stats.pport;
	struct mlx5_core_dev *mdev = priv->mdev;
	int sz = MLX5_ST_SZ_BYTES(ppcnt_reg);
	int prio;
	void *out;
	u32 *in;

	in = mlx5_vzalloc(sz);
	if (!in)
		goto free_out;

	MLX5_SET(ppcnt_reg, in, local_port, 1);

	out = pstats->IEEE_802_3_counters;
	MLX5_SET(ppcnt_reg, in, grp, MLX5_IEEE_802_3_COUNTERS_GROUP);
	mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_PPCNT, 0, 0);

	out = pstats->RFC_2863_counters;
	MLX5_SET(ppcnt_reg, in, grp, MLX5_RFC_2863_COUNTERS_GROUP);
	mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_PPCNT, 0, 0);

	out = pstats->RFC_2819_counters;
	MLX5_SET(ppcnt_reg, in, grp, MLX5_RFC_2819_COUNTERS_GROUP);
	mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_PPCNT, 0, 0);

	out = pstats->phy_counters;
	MLX5_SET(ppcnt_reg, in, grp, MLX5_PHYSICAL_LAYER_COUNTERS_GROUP);
	mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_PPCNT, 0, 0);

	MLX5_SET(ppcnt_reg, in, grp, MLX5_PER_PRIORITY_COUNTERS_GROUP);
	for (prio = 0; prio < NUM_PPORT_PRIO; prio++) {
		out = pstats->per_prio_counters[prio];
		MLX5_SET(ppcnt_reg, in, prio_tc, prio);
		mlx5_core_access_reg(mdev, in, sz, out, sz,
				     MLX5_REG_PPCNT, 0, 0);
	}

free_out:
	kvfree(in);
}

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
static void mlx5e_update_sw_lro_stats(struct mlx5e_priv *priv)
{
	int i;
	struct mlx5e_sw_stats *s = &priv->stats.sw;

	s->sw_lro_aggregated = 0;
	s->sw_lro_flushed = 0;
	s->sw_lro_no_desc = 0;

	for (i = 0; i < priv->params.num_channels; i++) {
		struct mlx5e_rq *rq = &priv->channel[i]->rq;

		s->sw_lro_aggregated += rq->sw_lro.lro_mgr.stats.aggregated;
		s->sw_lro_flushed += rq->sw_lro.lro_mgr.stats.flushed;
		s->sw_lro_no_desc += rq->sw_lro.lro_mgr.stats.no_desc;
	}
}
#endif

void mlx5e_update_stats(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;

	mlx5_vport_query_out_of_buffer(mdev, priv->counter_set_id,
			       &priv->stats.qcnt.rx_out_of_buffer);
	mlx5e_update_vport_counters(priv);
	mlx5e_update_pport_counters(priv);
	mlx5e_update_sw_counters(priv);
#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
	mlx5e_update_sw_lro_stats(priv);
#endif
}

static void mlx5e_update_stats_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct mlx5e_priv *priv = container_of(dwork, struct mlx5e_priv,
					       update_stats_work);
	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state) && !priv->internal_error) {
		mlx5e_update_stats(priv);
		queue_delayed_work(priv->wq, dwork,
				   msecs_to_jiffies(MLX5E_UPDATE_STATS_INTERVAL));
	}
	mutex_unlock(&priv->state_lock);
}

static void __mlx5e_async_event(struct mlx5e_priv *priv,
				enum mlx5_dev_event event)
{
	switch (event) {
	case MLX5_DEV_EVENT_PORT_UP:
		if (!priv->internal_error)
			queue_work(priv->wq, &priv->update_carrier_work);
		mlx5e_dbg(LINK, priv, "Link up.\n");
		break;
	case MLX5_DEV_EVENT_PORT_DOWN:
		if (!priv->internal_error)
			queue_work(priv->wq, &priv->update_carrier_work);
		mlx5e_dbg(LINK, priv, "Link down.\n");
		break;
	case MLX5_DEV_EVENT_SYS_ERROR:
		priv->internal_error = 1;
		/* this is used to serialize the marking of internal error
		 * state and the restart of update stats work
		 */
		mutex_lock(&priv->state_lock);
		mutex_unlock(&priv->state_lock);
		cancel_delayed_work_sync(&priv->update_stats_work);
		cancel_delayed_work_sync(&priv->service_task);
		flush_workqueue(priv->wq);
		break;

	default:
		break;
	}
}

static void mlx5e_async_event(struct mlx5_core_dev *mdev, void *vpriv,
			      enum mlx5_dev_event event, unsigned long param)
{
	struct mlx5e_priv *priv = vpriv;

	spin_lock(&priv->async_events_spinlock);
	if (test_bit(MLX5E_STATE_ASYNC_EVENTS_ENABLE, &priv->state))
		__mlx5e_async_event(priv, event);
	spin_unlock(&priv->async_events_spinlock);
}

static void mlx5e_enable_async_events(struct mlx5e_priv *priv)
{
	set_bit(MLX5E_STATE_ASYNC_EVENTS_ENABLE, &priv->state);
}

static void mlx5e_disable_async_events(struct mlx5e_priv *priv)
{
	spin_lock_irq(&priv->async_events_spinlock);
	clear_bit(MLX5E_STATE_ASYNC_EVENTS_ENABLE, &priv->state);
	spin_unlock_irq(&priv->async_events_spinlock);
}

void free_rq_res(struct mlx5e_rq *rq)
{
	kfree(rq->skb);
}

void free_striding_rq_res(struct mlx5e_rq *rq)
{
	int i;
	int num_of_wqe = mlx5_wq_ll_get_size(&rq->wq);

	for (i = 0; i < num_of_wqe; i++)
		if (rq->wqe_info[i].page)
			put_page(rq->wqe_info[i].page);

	kfree(rq->wqe_info);
}

#define MLX5E_HW2SW_MTU(hwmtu) (hwmtu - (ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN))
#define MLX5E_SW2HW_MTU(swmtu) (swmtu + (ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN))

static int mlx5e_create_rq(struct mlx5e_channel *c,
			   struct mlx5e_rq_param *param,
			   struct mlx5e_rq *rq)
{
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	void *rqc = param->rqc;
	void *rqc_wq = MLX5_ADDR_OF(rqc, rqc, wq);
	int wq_sz;
	u32 byte_count;
	int err;
	int i;

	param->wq.db_numa_node = cpu_to_node(c->cpu);

	rq->rq_type =  MLX5_CAP_GEN(mdev, striding_rq);

	err = mlx5_wq_ll_create(mdev, &param->wq, rqc_wq, &rq->wq,
				&rq->wq_ctrl);
	if (err)
		return err;

	rq->wq.db = &rq->wq.db[MLX5_RCV_DBR];

	wq_sz = mlx5_wq_ll_get_size(&rq->wq);

	if (rq->rq_type == RQ_TYPE_STRIDE) {
		/* TODO: take them from ethtool ..*/
		rq->num_of_strides_in_wqe = MLX5E_PARAMS_HW_NUM_STRIDES_BASIC_VAL << MLX5E_PARAMS_DEFAULT_LOG_WQE_NUM_STRIDES;
		rq->stride_size = (MLX5E_PARAMS_HW_STRIDE_SIZE_BASIC_VAL << MLX5E_PARAMS_DEFAULT_LOG_WQE_STRIDE_SIZE);

		rq->wqe_info = kzalloc_node(wq_sz * sizeof(*rq->wqe_info), GFP_KERNEL, cpu_to_node(c->cpu));
		if (!rq->wqe_info) {
			err = -ENOMEM;
			goto err_rq_wq_destroy;
		}

		/* functions to handle striding rq */
		rq->clean_rq = free_striding_rq_res;
		rq->alloc_wqe = mlx5e_alloc_striding_rx_wqe;
		rq->is_poll = is_poll_striding_wqe;
		rq->mlx5e_poll_specific_rx_cq = mlx5e_poll_striding_rx_cq;
		rq->wqe_sz = rq->num_of_strides_in_wqe * rq->stride_size;
		rq->page_order = rq->wqe_sz > PAGE_SIZE ? ilog2(rq->wqe_sz / PAGE_SIZE) : 0;
		byte_count = rq->wqe_sz;
	} else {
		rq->skb = kzalloc_node(wq_sz * sizeof(*rq->skb), GFP_KERNEL,
				       cpu_to_node(c->cpu));
		if (!rq->skb) {
			err = -ENOMEM;
			goto err_rq_wq_destroy;
		}
		rq->is_poll = NULL;
		rq->clean_rq = free_rq_res;
		rq->alloc_wqe = mlx5e_alloc_rx_wqe;
		rq->mlx5e_poll_specific_rx_cq = mlx5e_poll_default_rx_cq;
#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
		rq->wqe_sz = IS_HW_LRO(priv) ? priv->params.lro_wqe_sz :
			MLX5E_SW2HW_MTU(priv->netdev->mtu);
#else
		rq->wqe_sz = (priv->params.lro_en) ? priv->params.lro_wqe_sz :
						     MLX5E_SW2HW_MTU(priv->netdev->mtu);
#endif
		byte_count = rq->wqe_sz | MLX5_HW_START_PADDING;
		rq->wqe_sz = SKB_DATA_ALIGN(rq->wqe_sz + MLX5E_NET_IP_ALIGN);
	}

	for (i = 0; i < wq_sz; i++) {
		struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(&rq->wq, i);

		wqe->data.lkey       = c->mkey_be;
		wqe->data.byte_count = cpu_to_be32(byte_count);
	}

	rq->pdev    = c->pdev;
	rq->netdev  = c->netdev;
	rq->channel = c;
	rq->ix      = c->ix;

	return 0;

err_rq_wq_destroy:
	mlx5_wq_destroy(&rq->wq_ctrl);

	return err;
}

static void mlx5e_destroy_rq(struct mlx5e_rq *rq)
{
	rq->clean_rq(rq);
	mlx5_wq_destroy(&rq->wq_ctrl);
}

static int mlx5e_enable_rq(struct mlx5e_rq *rq, struct mlx5e_rq_param *param,
			   int vsd)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in;
	void *rqc;
	void *wq;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_rq_in) +
		sizeof(u64) * rq->wq_ctrl.buf.npages;
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	rqc = MLX5_ADDR_OF(create_rq_in, in, ctx);
	wq  = MLX5_ADDR_OF(rqc, rqc, wq);

	memcpy(rqc, param->rqc, sizeof(param->rqc));

	MLX5_SET(rqc,  rqc, cqn,		c->rq.cq.mcq.cqn);
	MLX5_SET(rqc,  rqc, state,		MLX5_RQC_STATE_RST);
	MLX5_SET(rqc,  rqc, flush_in_error_en,	1);
	MLX5_SET(rqc,  rqc, vsd, vsd);
	MLX5_SET(wq,   wq,  log_wq_pg_sz,	rq->wq_ctrl.buf.page_shift -
						MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(wq, wq,  dbr_addr,		rq->wq_ctrl.db.dma);

	mlx5_fill_page_array(&rq->wq_ctrl.buf,
			     (__be64 *)MLX5_ADDR_OF(wq, wq, pas));

	err = mlx5_core_create_rq(mdev, in, inlen, &rq->rqn);

	kvfree(in);

	return err;
}

static int mlx5e_modify_rq_state(struct mlx5e_rq *rq, int curr_state,
				 int next_state)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in;
	void *rqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(modify_rq_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	rqc = MLX5_ADDR_OF(modify_rq_in, in, ctx);

	MLX5_SET(modify_rq_in, in, rqn, rq->rqn);
	MLX5_SET(modify_rq_in, in, rq_state, curr_state);
	MLX5_SET(rqc, rqc, state, next_state);

	err = mlx5_core_modify_rq(mdev, in, inlen);

	kvfree(in);

	return err;
}

static int mlx5e_modify_rq_vsd(struct mlx5e_rq *rq, int curr_state, int vsd)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in, *rqc;
	int inlen, err;

	inlen = MLX5_ST_SZ_BYTES(modify_rq_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	rqc = MLX5_ADDR_OF(modify_rq_in, in, ctx);

	MLX5_SET(modify_rq_in, in, rq_state, curr_state);
	MLX5_SET(modify_rq_in, in, rqn, rq->rqn);
	MLX5_SET(modify_rq_in, in, bitmask.vsd, 1);
	MLX5_SET(rqc, rqc, state, MLX5_RQC_STATE_RDY);
	MLX5_SET(rqc, rqc, vsd, vsd);

	err = mlx5_core_modify_rq(mdev, in, inlen);

	kvfree(in);
	return err;
}

static void mlx5e_disable_rq(struct mlx5e_rq *rq)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	mlx5_core_destroy_rq(mdev, rq->rqn);
}

enum {
	MLX5_EN_MAX_WAIT_MS	= 10000,
	MLX5_EN_MSLEEP_QUANT	= 20,
	MLX5_EN_MAX_ITER	= MLX5_EN_MAX_WAIT_MS / MLX5_EN_MSLEEP_QUANT,
};

static int mlx5e_wait_for_min_rx_wqes(struct mlx5e_rq *rq)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_wq_ll *wq = &rq->wq;
	int i;

	for (i = 0; i < MLX5_EN_MAX_ITER; i++) {
		if (wq->cur_sz >= priv->params.min_rx_wqes)
			return 0;

		msleep(MLX5_EN_MSLEEP_QUANT);
	}

	return -ETIMEDOUT;
}

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
static int get_skb_hdr(struct sk_buff *skb, void **iphdr,
			void **tcph, u64 *hdr_flags, void *priv)
{
	unsigned int ip_len;
	struct iphdr *iph;

	if (unlikely(skb->protocol != htons(ETH_P_IP)))
		return -1;

	/*
	* In the future we may add an else clause that verifies the
	* checksum and allows devices which do not calculate checksum
	* to use LRO.
	*/
	if (unlikely(skb->ip_summed != CHECKSUM_UNNECESSARY))
		return -1;

	/* Check for non-TCP packet */
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return -1;

	ip_len = ip_hdrlen(skb);
	skb_set_transport_header(skb, ip_len);
	*tcph = tcp_hdr(skb);

	/* check if IP header and TCP header are complete */
	if (ntohs(iph->tot_len) < ip_len + tcp_hdrlen(skb))
		return -1;

	*hdr_flags = LRO_IPV4 | LRO_TCP;
	*iphdr = iph;

	return 0;
}

static void mlx5e_rq_sw_lro_init(struct mlx5e_rq *rq)
{
	rq->sw_lro.lro_mgr.max_aggr 		= 64;
	rq->sw_lro.lro_mgr.max_desc		= MLX5E_LRO_MAX_DESC;
	rq->sw_lro.lro_mgr.lro_arr		= rq->sw_lro.lro_desc;
	rq->sw_lro.lro_mgr.get_skb_header	= get_skb_hdr;
	rq->sw_lro.lro_mgr.features		= LRO_F_NAPI;
	rq->sw_lro.lro_mgr.frag_align_pad	= NET_IP_ALIGN;
	rq->sw_lro.lro_mgr.dev			= rq->netdev;
	rq->sw_lro.lro_mgr.ip_summed		= CHECKSUM_UNNECESSARY;
	rq->sw_lro.lro_mgr.ip_summed_aggr	= CHECKSUM_UNNECESSARY;
}
#endif

static int mlx5e_open_rq(struct mlx5e_channel *c,
			 struct mlx5e_rq_param *param,
			 struct mlx5e_rq *rq)
{
	int err;
	int vsd = !(c->priv->netdev->features & NETIF_F_HW_VLAN_CTAG_RX);

	err = mlx5e_create_rq(c, param, rq);
	if (err)
		return err;

	err = mlx5e_enable_rq(rq, param, vsd);
	if (err)
		goto err_destroy_rq;

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
	mlx5e_rq_sw_lro_init(rq);
#endif

	err = mlx5e_modify_rq_state(rq, MLX5_RQC_STATE_RST, MLX5_RQC_STATE_RDY);
	if (err)
		goto err_disable_rq;

	set_bit(MLX5E_RQ_STATE_POST_WQES_ENABLE, &rq->state);
	mlx5e_send_nop(&c->sq[0], true); /* trigger mlx5e_post_rx_wqes() */

	return 0;

err_disable_rq:
	mlx5e_disable_rq(rq);
err_destroy_rq:
	mlx5e_destroy_rq(rq);

	return err;
}

static void mlx5e_close_rq(struct mlx5e_rq *rq)
{
	struct mlx5e_channel *c = container_of(rq, struct mlx5e_channel, rq);
	struct mlx5e_priv *priv = c->priv;
	int i;

	clear_bit(MLX5E_RQ_STATE_POST_WQES_ENABLE, &rq->state);
	napi_synchronize(&rq->channel->napi); /* prevent mlx5e_post_rx_wqes */

	mlx5e_modify_rq_state(rq, MLX5_RQC_STATE_RDY, MLX5_RQC_STATE_ERR);
	if (!priv->internal_error) {
		for (i = 0; i < MLX5_EN_MAX_ITER && !mlx5_wq_ll_is_empty(&rq->wq); i++)
			msleep(MLX5_EN_MSLEEP_QUANT);

		if (i == MLX5_EN_MAX_ITER)
			pr_warn("%s: aborted\n", __func__);
	}

	/* avoid destroying rq before mlx5e_poll_rx_cq() is done with it */
	napi_synchronize(&rq->channel->napi);

	mlx5e_disable_rq(rq);
	mlx5e_destroy_rq(rq);
}

static void mlx5e_free_sq_db(struct mlx5e_sq *sq)
{
	kfree(sq->wqe_info);
	kfree(sq->dma_fifo);
	kfree(sq->skb);
}

static int mlx5e_alloc_sq_db(struct mlx5e_sq *sq, int numa)
{
	int wq_sz = mlx5_wq_cyc_get_size(&sq->wq);
	int df_sz = wq_sz * MLX5_SEND_WQEBB_NUM_DS;

	sq->skb = kzalloc_node(wq_sz * sizeof(*sq->skb), GFP_KERNEL, numa);
	sq->dma_fifo = kzalloc_node(df_sz * sizeof(*sq->dma_fifo), GFP_KERNEL,
				    numa);
	sq->wqe_info = kzalloc_node(wq_sz * sizeof(*sq->wqe_info), GFP_KERNEL,
				    numa);

	if (!sq->skb || !sq->dma_fifo || !sq->wqe_info) {
		mlx5e_free_sq_db(sq);
		return -ENOMEM;
	}

	sq->dma_fifo_mask = df_sz - 1;

	return 0;
}

static int mlx5e_create_sq(struct mlx5e_channel *c,
			   int index,
			   struct mlx5e_sq_param *param,
			   struct mlx5e_sq *sq)
{
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *sqc = param->sqc;
	void *sqc_wq = MLX5_ADDR_OF(sqc, sqc, wq);
	int tc = index >= c->num_tc ? 0 : index;
	int txq_ix;
	int err;

	err = mlx5_alloc_map_uar(mdev, &sq->uar);
	if (err)
		return err;

	param->wq.db_numa_node = cpu_to_node(c->cpu);

	err = mlx5_wq_cyc_create(mdev, &param->wq, sqc_wq, &sq->wq,
				 &sq->wq_ctrl);
	if (err)
		goto err_unmap_free_uar;

	sq->wq.db       = &sq->wq.db[MLX5_SND_DBR];
	sq->uar_map     = sq->uar.map;
	sq->uar_bf_map  = sq->uar.bf_map;
	sq->bf_buf_size = (1 << MLX5_CAP_GEN(mdev, log_bf_reg_size)) / 2;
	sq->max_inline  = sq->bf_buf_size -
			  sizeof(struct mlx5e_tx_wqe) +
			  2 /*sizeof(mlx5e_tx_wqe.inline_hdr_start)*/;

	err = mlx5e_alloc_sq_db(sq, cpu_to_node(c->cpu));
	if (err)
		goto err_sq_wq_destroy;

	txq_ix = c->ix + index * priv->params.num_channels;
	sq->txq = netdev_get_tx_queue(priv->netdev, txq_ix);
	priv->txq_to_sq_map[txq_ix] = sq;

	sq->pdev      = c->pdev;
	sq->mkey_be   = c->mkey_be;
	sq->channel   = c;
	sq->tc        = tc;
	sq->tx_ind    = index;
	sq->bf_budget = MLX5E_SQ_BF_BUDGET;
	sq->edge      = (sq->wq.sz_m1 + 1) - MLX5_SEND_WQE_MAX_WQEBBS;

	return 0;

err_sq_wq_destroy:
	mlx5_wq_destroy(&sq->wq_ctrl);

err_unmap_free_uar:
	mlx5_unmap_free_uar(mdev, &sq->uar);

	return err;
}

static void mlx5e_destroy_sq(struct mlx5e_sq *sq)
{
	struct mlx5e_channel *c = sq->channel;
	struct mlx5e_priv *priv = c->priv;

	mlx5e_free_sq_db(sq);
	mlx5_wq_destroy(&sq->wq_ctrl);
	mlx5_unmap_free_uar(priv->mdev, &sq->uar);
}

static int mlx5e_enable_sq(struct mlx5e_sq *sq, struct mlx5e_sq_param *param)
{
	struct mlx5e_channel *c = sq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in;
	void *sqc;
	void *wq;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_sq_in) +
		sizeof(u64) * sq->wq_ctrl.buf.npages;
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	sqc = MLX5_ADDR_OF(create_sq_in, in, ctx);
	wq = MLX5_ADDR_OF(sqc, sqc, wq);

	memcpy(sqc, param->sqc, sizeof(param->sqc));

	MLX5_SET(sqc,  sqc, tis_num_0,		priv->tisn[sq->tc]);
	MLX5_SET(sqc,  sqc, cqn,		sq->cq.mcq.cqn);
	MLX5_SET(sqc,  sqc, state,		MLX5_SQC_STATE_RST);
	MLX5_SET(sqc,  sqc, tis_lst_sz,		1);
	MLX5_SET(sqc,  sqc, flush_in_error_en,	1);

	MLX5_SET(wq,   wq, wq_type,       MLX5_WQ_TYPE_CYCLIC);
	MLX5_SET(wq,   wq, uar_page,      sq->uar.index);
	MLX5_SET(wq,   wq, log_wq_pg_sz,  sq->wq_ctrl.buf.page_shift -
					  MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(wq, wq, dbr_addr,      sq->wq_ctrl.db.dma);

	mlx5_fill_page_array(&sq->wq_ctrl.buf,
			     (__be64 *)MLX5_ADDR_OF(wq, wq, pas));

	err = mlx5_core_create_sq(mdev, in, inlen, &sq->sqn);

	kvfree(in);

	return err;
}

static int mlx5e_modify_sq(struct mlx5e_sq *sq, int curr_state, int next_state,
			   bool update_rl, int rl_index)
{
	struct mlx5e_channel *c = sq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in;
	void *sqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(modify_sq_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	sqc = MLX5_ADDR_OF(modify_sq_in, in, ctx);

	MLX5_SET(modify_sq_in, in, sqn, sq->sqn);
	MLX5_SET(modify_sq_in, in, sq_state, curr_state);
	MLX5_SET(sqc, sqc, state, next_state);
	if (update_rl && next_state == MLX5_SQC_STATE_RDY) {
		MLX5_SET64(modify_sq_in, in, modify_bitmask, 1);
		MLX5_SET(sqc,  sqc, packet_pacing_rate_limit_index, rl_index);
	}

	err = mlx5_core_modify_sq(mdev, in, inlen);

	kvfree(in);

	return err;
}

static void mlx5e_disable_sq(struct mlx5e_sq *sq)
{
	struct mlx5e_channel *c = sq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	mlx5_core_destroy_sq(mdev, sq->sqn);
	if (sq->rate_limit)
		mlx5_rl_remove_rate(mdev, sq->rate_limit);
}

static int mlx5e_open_sq(struct mlx5e_channel *c,
			 int index,
			 struct mlx5e_sq_param *param,
			 struct mlx5e_sq *sq)
{
	int err;

	err = mlx5e_create_sq(c, index, param, sq);
	if (err)
		return err;

	err = mlx5e_enable_sq(sq, param);
	if (err)
		goto err_destroy_sq;

	err = mlx5e_modify_sq(sq, MLX5_SQC_STATE_RST,
			      MLX5_SQC_STATE_RDY, false, 0);
	if (err)
		goto err_disable_sq;

	set_bit(MLX5E_SQ_STATE_WAKE_TXQ_ENABLE, &sq->state);
	netdev_tx_reset_queue(sq->txq);
	netif_tx_start_queue(sq->txq);

	return 0;

err_disable_sq:
	mlx5e_disable_sq(sq);
err_destroy_sq:
	mlx5e_destroy_sq(sq);

	return err;
}

/* TODO: make this function general, i.e move to netdevice.h */
static inline void netif_tx_disable_queue(struct netdev_queue *txq)
{
	__netif_tx_lock_bh(txq);
	netif_tx_stop_queue(txq);
	__netif_tx_unlock_bh(txq);
}

static void mlx5e_close_sq(struct mlx5e_priv *priv, struct mlx5e_sq *sq)
{
	int err;
	int i;

	clear_bit(MLX5E_SQ_STATE_WAKE_TXQ_ENABLE, &sq->state);
	napi_synchronize(&sq->channel->napi); /* prevent netif_tx_wake_queue */
	netif_tx_disable_queue(sq->txq);

	/* ensure hw is notified of all pending wqes */
	if (mlx5e_sq_has_room_for(sq, 1))
		mlx5e_send_nop(sq, true);

	err = mlx5e_modify_sq(sq, MLX5_SQC_STATE_RDY, MLX5_SQC_STATE_ERR, false, 0);
	if (!priv->internal_error && !err) {
		for (i = 0; i < MLX5_EN_MAX_ITER; i++) {
			if (sq->cc == sq->pc ||
			    test_bit(MLX5E_SQ_TX_TIMEOUT, &sq->state))
				break;
			msleep(MLX5_EN_MSLEEP_QUANT);
		}

		if (i == MLX5_EN_MAX_ITER)
			pr_warn("%s: aborted\n", __func__);
	}

	/* Make sure mlx5e_poll_tx_cq won't race with mlx5e_free_tx_descs */
	if (sq->cc != sq->pc)
		set_bit(MLX5E_SQ_TX_TIMEOUT, &sq->state);
	napi_synchronize(&sq->channel->napi);

	mlx5e_free_tx_descs(sq);
	mlx5e_disable_sq(sq);
	mlx5e_destroy_sq(sq);
}

static int mlx5e_create_cq(struct mlx5e_channel *c,
			   struct mlx5e_cq_param *param,
			   struct mlx5e_cq *cq)
{
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_core_cq *mcq = &cq->mcq;
	int eqn_not_used;
	unsigned int irqn;
	int err;
	u32 i;

	param->wq.buf_numa_node = cpu_to_node(c->cpu);
	param->wq.db_numa_node  = cpu_to_node(c->cpu);
	param->eq_ix   = c->ix;

	err = mlx5_cqwq_create(mdev, &param->wq, param->cqc, &cq->wq,
			       &cq->wq_ctrl);
	if (err)
		return err;

	mlx5_vector2eqn(mdev, param->eq_ix, &eqn_not_used, &irqn);

	cq->napi        = &c->napi;

	mcq->cqe_sz     = 1 << (6 + MLX5_GET(cqc, param->cqc, cqe_sz));
	mcq->set_ci_db  = cq->wq_ctrl.db.db;
	mcq->arm_db     = cq->wq_ctrl.db.db + 1;
	*mcq->set_ci_db = 0;
	*mcq->arm_db    = 0;
	mcq->vector     = param->eq_ix;
	mcq->comp       = mlx5e_completion_event;
	mcq->event      = mlx5e_cq_error_event;
	mcq->irqn       = irqn;
	mcq->uar        = &priv->cq_uar;

	for (i = 0; i < mlx5_cqwq_get_size(&cq->wq); i++) {
		struct mlx5_cqe64 *cqe = mlx5_cqwq_get_wqe(&cq->wq, i);
		cqe->op_own = 0xf1;
	}

	cq->channel = c;

	return 0;
}

static void mlx5e_destroy_cq(struct mlx5e_cq *cq)
{
	mlx5_wq_destroy(&cq->wq_ctrl);
}

static int mlx5e_enable_cq(struct mlx5e_cq *cq, struct mlx5e_cq_param *param,
			   u8 moderation_mode)
{
	struct mlx5e_channel *c = cq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_core_cq *mcq = &cq->mcq;

	void *in;
	void *cqc;
	int inlen;
	unsigned int irqn_not_used;
	int eqn;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_cq_in) +
		sizeof(u64) * cq->wq_ctrl.buf.npages;
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	cqc = MLX5_ADDR_OF(create_cq_in, in, cq_context);

	memcpy(cqc, param->cqc, sizeof(param->cqc));

	mlx5_fill_page_array(&cq->wq_ctrl.buf,
			     (__be64 *)MLX5_ADDR_OF(create_cq_in, in, pas));

	mlx5_vector2eqn(mdev, param->eq_ix, &eqn, &irqn_not_used);

	MLX5_SET(cqc,   cqc, cq_period_mode,
		 MLX5_CAP_GEN(mdev, cq_period_start_from_cqe) &&
		 moderation_mode == MLX5_CQ_PERIOD_MODE_START_FROM_CQE ?
		 MLX5_CQ_PERIOD_MODE_START_FROM_CQE :
		 MLX5_CQ_PERIOD_MODE_START_FROM_EQE);
	MLX5_SET(cqc,   cqc, c_eqn,         eqn);
	MLX5_SET(cqc,   cqc, uar_page,      mcq->uar->index);
	MLX5_SET(cqc,   cqc, log_page_size, cq->wq_ctrl.buf.page_shift -
					    MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(cqc, cqc, dbr_addr,      cq->wq_ctrl.db.dma);

	err = mlx5_core_create_cq(mdev, mcq, in, inlen);

	kvfree(in);

	if (err)
		return err;

	mlx5e_cq_arm(cq);

	return 0;
}

static void mlx5e_disable_cq(struct mlx5e_cq *cq)
{
	struct mlx5e_channel *c = cq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	mlx5_core_destroy_cq(mdev, &cq->mcq);
}

static int mlx5e_open_cq(struct mlx5e_channel *c,
			 struct mlx5e_cq_param *param,
			 struct mlx5e_cq *cq,
			 u16 moderation_usecs,
			 u16 moderation_frames,
			 u8 moderation_mode)
{
	int err;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	err = mlx5e_create_cq(c, param, cq);
	if (err)
		return err;

	err = mlx5e_enable_cq(cq, param, moderation_mode);
	if (err)
		goto err_destroy_cq;

	mlx5_core_modify_cq_moderation(mdev, &cq->mcq,
				       moderation_usecs,
				       moderation_frames);

	return 0;

err_destroy_cq:
	mlx5e_destroy_cq(cq);

	return err;
}

static void mlx5e_close_cq(struct mlx5e_cq *cq)
{
	mlx5e_disable_cq(cq);
	mlx5e_destroy_cq(cq);
}

/* mlx5e_service_task - Run service task for tasks that needed to be done
 * periodically
 */
static void mlx5e_service_task(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct mlx5e_priv *priv = container_of(dwork, struct mlx5e_priv,
					       service_task);

	mutex_lock(&priv->state_lock);
#if defined (HAVE_PTP_CLOCK_INFO) && (defined (CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE))
	if (test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		if (priv->tstamp.ptp) {
			mlx5e_ptp_overflow_check(priv);
			/* Only mlx5e_ptp_overflow_check is called from this
			 * service task. schedule a new task only if ptp_clock
			 * is initialized. if changed, move the scheduler.
			 */
			queue_delayed_work(priv->wq, dwork, MLX5E_SERVICE_TASK_DELAY);
		}
	}
#endif
	mutex_unlock(&priv->state_lock);
}

static int mlx5e_get_cpu(struct mlx5e_priv *priv, int ix)
{
	cpumask_var_t affinity_mask;

	if (!priv->mdev->priv.irq_info[ix].mask)
		return 0;

#ifdef CONFIG_CPUMASK_OFFSTACK
	affinity_mask = priv->mdev->priv.irq_info[ix].mask;
#else
	affinity_mask[0] = *(priv->mdev->priv.irq_info[ix].mask);
#endif
	return cpumask_first(affinity_mask);
}

static void mlx5e_build_tc_to_txq_map(struct mlx5e_priv *priv, int ix)
{
	int i;

	for (i = 0; i < MLX5E_MAX_NUM_TC; i++)
		priv->tc_to_txq_map[ix][i] = ix + i * priv->params.num_channels;
}

static int mlx5e_open_tx_cqs(struct mlx5e_channel *c,
			     struct mlx5e_channel_param *cparam)
{
	struct mlx5e_priv *priv = c->priv;
	int err;
	int i;

	for (i = 0; i < c->num_tx; i++) {
		err = mlx5e_open_cq(c, &cparam->tx_cq, &c->sq[i].cq,
				    priv->params.tx_cq_moderation_usec,
				    priv->params.tx_cq_moderation_pkts,
				    MLX5_CQ_PERIOD_MODE_START_FROM_EQE);
		if (err)
			goto err_close_tx_cqs;
	}

	return 0;

err_close_tx_cqs:
	for (i--; i >= 0; i--)
		mlx5e_close_cq(&c->sq[i].cq);

	return err;
}

static void mlx5e_close_tx_cqs(struct mlx5e_channel *c)
{
	int i;

	for (i = 0; i < c->num_tx; i++)
		mlx5e_close_cq(&c->sq[i].cq);
}

static int mlx5e_open_sqs(struct mlx5e_channel *c,
			  struct mlx5e_channel_param *cparam)
{
	int err;
	int i;

	for (i = 0; i < c->num_tx; i++) {
		err = mlx5e_open_sq(c, i, &cparam->sq, &c->sq[i]);
		if (err)
			goto err_close_sqs;
	}

	return 0;

err_close_sqs:
	for (i--; i >= 0; i--)
		mlx5e_close_sq(c->priv, &c->sq[i]);

	return err;
}

static void mlx5e_close_sqs(struct mlx5e_channel *c)
{
	int i;

	for (i = 0; i < c->num_tx; i++)
		mlx5e_close_sq(c->priv, &c->sq[i]);
}

static int mlx5e_set_sq_maxrate(struct net_device *dev,
				  struct mlx5e_sq *sq, u32 rate)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u16 rl_index = 0;
	int err;

	if (rate == sq->rate_limit)
		/* nothing to do */
		return 0;

	if (sq->rate_limit)
		/* remove current rl index to free space to next ones */
		mlx5_rl_remove_rate(mdev, sq->rate_limit);

	sq->rate_limit = 0;

	if (rate) {
		err = mlx5_rl_add_rate(mdev, rate, &rl_index);
		if (err) {
			netdev_err(dev, "Failed configuring rate %u: %d\n",
				   rate, err);
			return err;
		}
	}

	err = mlx5e_modify_sq(sq, MLX5_SQC_STATE_RDY,
			      MLX5_SQC_STATE_RDY, true, rl_index);
	if (err) {
		netdev_err(dev, "Failed configuring rate %u: %d\n",
			   rate, err);
		/* remove the rate from the table */
		if (rate)
			mlx5_rl_remove_rate(mdev, rate);
		return err;
	}

	sq->rate_limit = rate;
	return 0;
}

int mlx5e_set_tx_maxrate(struct net_device *dev, int index, u32 rate)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_sq *sq = priv->txq_to_sq_map[index];
	int err = 0;

	if (!mlx5_rl_is_supported(mdev)) {
		netdev_err(dev, "Rate limiting is not supported on this device\n");
		return -EINVAL;
	}

	/* rate is given in Mb/sec, HW config is in Kb/sec */
	rate = rate << 10;

	/* Check whether rate in valid range, 0 is always valid */
	if (rate && !mlx5_rl_is_in_range(mdev, rate)) {
		netdev_err(dev, "TX rate %u, is not in range\n", rate);
		return -ERANGE;
	}

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		err = mlx5e_set_sq_maxrate(dev, sq, rate);
	if (!err)
		priv->tx_rates[index] = rate;
	mutex_unlock(&priv->state_lock);

	return err;
}

static int mlx5e_open_channel(struct mlx5e_priv *priv, int ix,
			      struct mlx5e_channel_param *cparam,
			      struct mlx5e_channel **cp,
			      int num_tx)
{
	struct net_device *netdev = priv->netdev;
	int cpu = mlx5e_get_cpu(priv, ix);
	struct mlx5e_channel *c;
	struct mlx5e_sq *sq;
	int err;
	int i;

	c = kzalloc_node(sizeof(*c), GFP_KERNEL, cpu_to_node(cpu));
	if (!c)
		return -ENOMEM;

	c->priv     = priv;
	c->ix       = ix;
	c->cpu      = cpu;
	c->pdev     = &priv->mdev->pdev->dev;
	c->netdev   = priv->netdev;
	c->mkey_be  = cpu_to_be32(priv->mr.key);
	c->num_tc   = priv->params.num_tc;
	c->num_tx   = num_tx;

	c->sq = kzalloc_node(sizeof(*c->sq) * c->num_tx, GFP_KERNEL,
			     cpu_to_node(cpu));
	if (!c->sq) {
		err = -ENOMEM;
		goto err_ch_free;
	}

	mlx5e_build_tc_to_txq_map(priv, ix);

	netif_napi_add(netdev, &c->napi, mlx5e_napi_poll, 64);

	err = mlx5e_open_tx_cqs(c, cparam);
	if (err)
		goto err_napi_del;

	err = mlx5e_open_cq(c, &cparam->rx_cq, &c->rq.cq,
			    priv->params.rx_cq_moderation_usec,
			    priv->params.rx_cq_moderation_pkts,
			    MLX5_CQ_PERIOD_MODE_START_FROM_CQE);
	if (err)
		goto err_close_tx_cqs;

	napi_enable(&c->napi);

	err = mlx5e_open_sqs(c, cparam);
	if (err)
		goto err_disable_napi;

	for (i = 0; i < c->num_tx; i++) {
		u32 txq_ix = ix + i * priv->params.num_channels;
		sq = priv->txq_to_sq_map[txq_ix];

		if (priv->tx_rates[txq_ix]) {
			mlx5e_set_sq_maxrate(priv->netdev, sq,
					       priv->tx_rates[txq_ix]);
		}
	}

	err = mlx5e_open_rq(c, &cparam->rq, &c->rq);
	if (err)
		goto err_close_sqs;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)) || \
     defined(CONFIG_COMPAT_IS_NETIF_SET_XPS_QUEUE_NOT_CONST_CPUMASK)
	netif_set_xps_queue(netdev, (struct cpumask *)get_cpu_mask(c->cpu), ix);
#else
	netif_set_xps_queue(netdev, get_cpu_mask(c->cpu), ix);
#endif
#if defined(HAVE_IRQ_DESC_GET_IRQ_DATA) && defined(HAVE_IRQ_TO_DESC_EXPORTED)
	c->irq_desc = irq_to_desc(c->rq.cq.mcq.irqn);
#endif

	*cp = c;
	mlx5_rename_comp_eq(priv->mdev, ix, priv->netdev->name);

	return 0;

err_close_sqs:
	mlx5e_close_sqs(c);

err_disable_napi:
	napi_disable(&c->napi);
	mlx5e_close_cq(&c->rq.cq);

err_close_tx_cqs:
	mlx5e_close_tx_cqs(c);

err_napi_del:
	netif_napi_del(&c->napi);
	kfree(c->sq);

err_ch_free:
	kfree(c);

	return err;
}

static void mlx5e_close_channel(struct mlx5e_channel *c)
{
	mlx5_rename_comp_eq(c->priv->mdev, c->ix, NULL);
	mlx5e_close_rq(&c->rq);
	mlx5e_close_sqs(c);
	napi_disable(&c->napi);
	mlx5e_close_cq(&c->rq.cq);
	mlx5e_close_tx_cqs(c);
	netif_napi_del(&c->napi);
	kfree(c->sq);
	kfree(c);
}

static void mlx5e_build_rq_param(struct mlx5e_priv *priv,
				 struct mlx5e_rq_param *param)
{
	void *rqc = param->rqc;
	void *wq = MLX5_ADDR_OF(rqc, rqc, wq);

	MLX5_SET(wq, wq, wq_type,          MLX5_WQ_TYPE_LINKED_LIST);
	MLX5_SET(wq, wq, end_padding_mode, MLX5_WQ_END_PAD_MODE_ALIGN);
	MLX5_SET(wq, wq, log_wq_stride,    ilog2(sizeof(struct mlx5e_rx_wqe)));
	MLX5_SET(wq, wq, log_wq_sz,        priv->params.log_rq_size);
	MLX5_SET(wq, wq, pd,               priv->pdn);
	MLX5_SET(rqc,  rqc, counter_set_id, priv->counter_set_id);

	if (MLX5_CAP_GEN(priv->mdev, striding_rq) == RQ_TYPE_STRIDE) {
		MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_STRQ);
		MLX5_SET(wq, wq, log_wqe_num_of_strides,
			 MLX5E_PARAMS_DEFAULT_LOG_WQE_NUM_STRIDES);
		MLX5_SET(wq, wq, log_wqe_stride_size,
			 MLX5E_PARAMS_DEFAULT_LOG_WQE_STRIDE_SIZE);
	}

	param->wq.buf_numa_node = dev_to_node(&priv->mdev->pdev->dev);
	param->wq.linear = 1;
}

static void mlx5e_build_sq_param(struct mlx5e_priv *priv,
				 struct mlx5e_sq_param *param)
{
	void *sqc = param->sqc;
	void *wq = MLX5_ADDR_OF(sqc, sqc, wq);

	MLX5_SET(wq, wq, log_wq_sz,     priv->params.log_sq_size);
	MLX5_SET(wq, wq, log_wq_stride, ilog2(MLX5_SEND_WQE_BB));
	MLX5_SET(wq, wq, pd,            priv->pdn);

	param->wq.buf_numa_node = dev_to_node(&priv->mdev->pdev->dev);
}

static void mlx5e_build_common_cq_param(struct mlx5e_priv *priv,
					struct mlx5e_cq_param *param)
{
	void *cqc = param->cqc;

	MLX5_SET(cqc, cqc, uar_page, priv->cq_uar.index);
	if (cache_line_size() == 128)
		MLX5_SET(cqc, cqc, cqe_sz, 1);
}

static void mlx5e_build_rx_cq_param(struct mlx5e_priv *priv,
				    struct mlx5e_cq_param *param)
{
	void *cqc = param->cqc;

	mlx5e_build_common_cq_param(priv, param);

	/* TODO: mini_cqe_res_format currently set to checksum
	 * need to implement the API for switching between formats
	 */
	if (MLX5_CAP_GEN(priv->mdev, cqe_compression) &&
	    !MLX5_GET(cqc, cqc, cqe_sz)) {
		MLX5_SET(cqc, cqc, mini_cqe_res_format, MLX5_CQE_FORMAT_CSUM);
		MLX5_SET(cqc, cqc, cqe_comp_en, 1);
	}

	if (MLX5_CAP_GEN(priv->mdev, striding_rq) == RQ_TYPE_STRIDE) {
		MLX5_SET(cqc, cqc, log_cq_size, priv->params.log_rq_size +
			 ilog2(MLX5E_PARAMS_HW_NUM_STRIDES_BASIC_VAL) +  MLX5E_PARAMS_DEFAULT_LOG_WQE_NUM_STRIDES);
		/* Currently disable compressed with striding */
		MLX5_SET(cqc, cqc, cqe_comp_en, 0);
	} else {
		MLX5_SET(cqc, cqc, log_cq_size, priv->params.log_rq_size);
	}
}

static void mlx5e_build_tx_cq_param(struct mlx5e_priv *priv,
				    struct mlx5e_cq_param *param)
{
	void *cqc = param->cqc;

	MLX5_SET(cqc, cqc, log_cq_size,  priv->params.log_sq_size);

	mlx5e_build_common_cq_param(priv, param);
}

static void mlx5e_build_channel_param(struct mlx5e_priv *priv,
				      struct mlx5e_channel_param *cparam)
{
	memset(cparam, 0, sizeof(*cparam));

	mlx5e_build_rq_param(priv, &cparam->rq);
	mlx5e_build_sq_param(priv, &cparam->sq);
	mlx5e_build_rx_cq_param(priv, &cparam->rx_cq);
	mlx5e_build_tx_cq_param(priv, &cparam->tx_cq);
}

static int mlx5e_open_channels(struct mlx5e_priv *priv)
{
	struct mlx5e_channel_param cparam;
	int nch = priv->params.num_channels;
	int rl_txqs = priv->params.num_rl_txqs;
	int err = -ENOMEM;
	int i;
	int j;

	priv->channel = kcalloc(nch, sizeof(struct mlx5e_channel *),
				GFP_KERNEL);

	priv->txq_to_sq_map = kcalloc(nch * priv->params.num_tc + rl_txqs,
				      sizeof(struct mlx5e_sq *), GFP_KERNEL);

	if (!priv->channel || !priv->txq_to_sq_map)
		goto err_free_txq_to_sq_map;

	mlx5e_build_channel_param(priv, &cparam);

	for (i = 0; i < nch; i++) {
		int num_tx = priv->params.num_tc + rl_txqs / nch +
			     !!(i < rl_txqs % nch);
		err = mlx5e_open_channel(priv, i, &cparam,
					 &priv->channel[i], num_tx);
		if (err)
			goto err_close_channels;
	}

	if (!priv->internal_error) {
		for (j = 0; j < nch; j++) {
			err = mlx5e_wait_for_min_rx_wqes(&priv->channel[j]->rq);
			if (err)
				goto err_close_channels;
		}
	}

	mlx5e_ptp_init(priv);

	return 0;

err_close_channels:
	for (i--; i >= 0; i--)
		mlx5e_close_channel(priv->channel[i]);

err_free_txq_to_sq_map:
	kfree(priv->txq_to_sq_map);
	kfree(priv->channel);

	return err;
}

static void mlx5e_close_channels(struct mlx5e_priv *priv)
{
	int i;

	mlx5e_ptp_cleanup(priv);
	for (i = 0; i < priv->params.num_channels; i++)
		mlx5e_close_channel(priv->channel[i]);

	kfree(priv->txq_to_sq_map);
	kfree(priv->channel);
}

static int mlx5e_open_tis(struct mlx5e_priv *priv, int tc)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 in[MLX5_ST_SZ_DW(create_tis_in)];
	void *tisc = MLX5_ADDR_OF(create_tis_in, in, ctx);

	memset(in, 0, sizeof(in));

	MLX5_SET(tisc, tisc, prio,  tc);
	MLX5_SET(tisc, tisc, transport_domain, priv->tdn);

	return mlx5_core_create_tis(mdev, in, sizeof(in), &priv->tisn[tc]);
}

static void mlx5e_close_tis(struct mlx5e_priv *priv, int tc)
{
	mlx5_core_destroy_tis(priv->mdev, priv->tisn[tc]);
}

static int mlx5e_open_tises(struct mlx5e_priv *priv)
{
	int err;
	int tc;

	for (tc = 0; tc < priv->params.num_tc; tc++) {
		err = mlx5e_open_tis(priv, tc);
		if (err)
			goto err_close_tises;
	}

	return 0;

err_close_tises:
	for (tc--; tc >= 0; tc--)
		mlx5e_close_tis(priv, tc);

	return err;
}

static void mlx5e_close_tises(struct mlx5e_priv *priv)
{
	int tc;

	for (tc = 0; tc < priv->params.num_tc; tc++)
		mlx5e_close_tis(priv, tc);
}

static void mlx5e_close_rqt(struct mlx5e_priv *priv, u32 rqtn)
{
	mlx5_core_destroy_rqt(priv->mdev, rqtn);
}

static void mlx5e_close_rqts(struct mlx5e_priv *priv)
{
	int nch = priv->params.num_channels;
	int i;

	for (i = 0; i < nch; i++)
		mlx5e_close_rqt(priv, priv->outer_direct_tir[i].rqtn);

	mlx5e_close_rqt(priv, priv->indir_rqtn);
}

static int mlx5e_rx_hash_fn(int hfunc)
{
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
	return (hfunc == ETH_RSS_HASH_TOP) ?
	       MLX5_TIRC_RX_HASH_FN_HASH_TOEPLITZ :
	       MLX5_TIRC_RX_HASH_FN_HASH_INVERTED_XOR8;
#else
	return MLX5_TIRC_RX_HASH_FN_HASH_INVERTED_XOR8;
#endif
}

static int mlx5e_bits_invert(unsigned long a, int size)
{
	int i;
	int inv = 0;

	for (i = 0; i < size; i++)
		inv |= (test_bit(size - i - 1, &a) ? 1 : 0) << i;

	return inv;
}

static void mlx5e_fill_direct_rqt_rqn(struct mlx5e_priv *priv, void *rqtc,
				      int ix)
{
	u32 rqn = priv->channel[ix]->rq.rqn;

	MLX5_SET(rqtc, rqtc, rq_num[0], rqn);
}

static void mlx5e_fill_indir_rqt_rqns(struct mlx5e_priv *priv, void *rqtc)
{
	int i;

	for (i = 0; i < MLX5E_INDIR_RQT_SIZE; i++) {
		int ix = i;
		u32 rqn;

#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
		if (priv->params.rss_hfunc == ETH_RSS_HASH_XOR)
			ix = mlx5e_bits_invert(i, MLX5E_LOG_INDIR_RQT_SIZE);
#else
		ix = mlx5e_bits_invert(i, MLX5E_LOG_INDIR_RQT_SIZE);
#endif

		ix = priv->params.indirection_rqt[ix];
		rqn = priv->channel[ix]->rq.rqn;
		MLX5_SET(rqtc, rqtc, rq_num[i], rqn);
	}
}

static int mlx5e_open_rqt(struct mlx5e_priv *priv, int sz, int ix, u32 *rqtn)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 *in;
	void *rqtc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_rqt_in) + sizeof(u32) * sz;
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	rqtc = MLX5_ADDR_OF(create_rqt_in, in, rqt_context);

	MLX5_SET(rqtc, rqtc, rqt_actual_size, sz);
	MLX5_SET(rqtc, rqtc, rqt_max_size, sz);

	if (sz > 1) /* RSS */
		mlx5e_fill_indir_rqt_rqns(priv, rqtc);
	else
		mlx5e_fill_direct_rqt_rqn(priv, rqtc, ix);

	err = mlx5_core_create_rqt(mdev, in, inlen, rqtn);
	kvfree(in);

	return err;
}

static int mlx5e_open_rqts(struct mlx5e_priv *priv)
{
	int nch = priv->params.num_channels;
	u32 *rqtn;
	int err;
	int ix;

	/* Indirect RQT */
	rqtn = &priv->indir_rqtn;
	err = mlx5e_open_rqt(priv, MLX5E_INDIR_RQT_SIZE, 0, rqtn);
	if (err)
		return err;

	/* Direct RQTs */
	for (ix = 0; ix < nch; ix++) {
		rqtn = &priv->outer_direct_tir[ix].rqtn;
		err = mlx5e_open_rqt(priv, 1 /*size */, ix, rqtn);
		if (err)
			goto err_destroy_rqts;
	}

	return 0;

err_destroy_rqts:
	for (ix--; ix >= 0; ix--)
		mlx5e_close_rqt(priv, priv->outer_direct_tir[ix].rqtn);

	mlx5e_close_rqt(priv, priv->indir_rqtn);

	return err;
}

static void mlx5e_build_tir_ctx_common(struct mlx5e_priv *priv, void *tirc)
{
#define ROUGH_MAX_L2_L3_HDR_SZ 256

	MLX5_SET(tirc, tirc, transport_domain, priv->tdn);

	if (MLX5_CAP_ETH(priv->mdev, self_lb_uc))
		MLX5_SET(tirc, tirc, self_lb_block, 1);

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
	if (IS_HW_LRO(priv)) {
#else
	if (priv->params.lro_en) {
#endif
		MLX5_SET(tirc, tirc, lro_enable_mask,
			 MLX5_TIRC_LRO_ENABLE_MASK_IPV4_LRO |
			 MLX5_TIRC_LRO_ENABLE_MASK_IPV6_LRO);
		MLX5_SET(tirc, tirc, lro_max_ip_payload_size,
			 (priv->params.lro_wqe_sz -
			  ROUGH_MAX_L2_L3_HDR_SZ) >> 8);
		/* TODO: add option to choose timer value dynamically */
		MLX5_SET(tirc, tirc, lro_timeout_period_usecs,
			 priv->params.lro_timeout);
	}

	if (mlx5e_tunnel_stateless_supported(priv->mdev))
		MLX5_SET(tirc, tirc, tunneled_offload_en, 0x1);
}

static void mlx5e_build_direct_tir_ctx(struct mlx5e_priv *priv, u32 *tirc,
				       u32 rqtn)
{
	mlx5e_build_tir_ctx_common(priv, tirc);

	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_INDIRECT);
	MLX5_SET(tirc, tirc, indirect_table, rqtn);
	MLX5_SET(tirc, tirc, rx_hash_fn,
		 mlx5e_rx_hash_fn(priv->params.rss_hfunc));
}

static void mlx5e_build_tir_ctx(struct mlx5e_priv *priv, u32 *tirc, int tt,
				bool is_inner)
{
	void *hfso;

#define MLX5_HASH_IP            (MLX5_HASH_FIELD_SEL_SRC_IP   |\
				 MLX5_HASH_FIELD_SEL_DST_IP)

#define MLX5_HASH_IP_L4PORTS    (MLX5_HASH_FIELD_SEL_SRC_IP   |\
				 MLX5_HASH_FIELD_SEL_DST_IP   |\
				 MLX5_HASH_FIELD_SEL_L4_SPORT |\
				 MLX5_HASH_FIELD_SEL_L4_DPORT)

#define MLX5_HASH_IP_IPSEC_SPI  (MLX5_HASH_FIELD_SEL_SRC_IP   |\
				 MLX5_HASH_FIELD_SEL_DST_IP   |\
				 MLX5_HASH_FIELD_SEL_IPSEC_SPI)

	if (is_inner)
		hfso = MLX5_ADDR_OF(tirc, tirc, rx_hash_field_selector_inner);
	else
		hfso = MLX5_ADDR_OF(tirc, tirc, rx_hash_field_selector_outer);

	mlx5e_build_tir_ctx_common(priv, tirc);

	switch (tt) {
	case MLX5E_TT_ANY:
		MLX5_SET(tirc, tirc, disp_type,
			 MLX5_TIRC_DISP_TYPE_DIRECT);
		MLX5_SET(tirc, tirc, inline_rqn,
			 priv->channel[0]->rq.rqn);
		break;
	default:
		MLX5_SET(tirc, tirc, disp_type,
			 MLX5_TIRC_DISP_TYPE_INDIRECT);
		MLX5_SET(tirc, tirc, indirect_table,
			 priv->indir_rqtn);
		MLX5_SET(tirc, tirc, rx_hash_fn,
			 mlx5e_rx_hash_fn(priv->params.rss_hfunc));
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
		if (priv->params.rss_hfunc == ETH_RSS_HASH_TOP) {
			void *rss_key = MLX5_ADDR_OF(tirc, tirc,
						     rx_hash_toeplitz_key);

			MLX5_SET(tirc, tirc, rx_hash_symmetric, 1);

			memcpy(rss_key, priv->params.toeplitz_hash_key,
			       MLX5E_RSS_TOEPLITZ_KEY_SIZE);
		}
#endif
		break;
	}

	switch (tt) {
	case MLX5E_TT_IPV4_TCP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV4);
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
			 MLX5_L4_PROT_TYPE_TCP);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP_L4PORTS);
		break;

	case MLX5E_TT_IPV6_TCP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV6);
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
			 MLX5_L4_PROT_TYPE_TCP);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP_L4PORTS);
		break;

	case MLX5E_TT_IPV4_UDP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV4);
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
			 MLX5_L4_PROT_TYPE_UDP);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP_L4PORTS);
		break;

	case MLX5E_TT_IPV6_UDP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV6);
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
			 MLX5_L4_PROT_TYPE_UDP);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP_L4PORTS);
		break;

	case MLX5E_TT_IPV4_IPSEC_AH:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV4);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP_IPSEC_SPI);
		break;

	case MLX5E_TT_IPV6_IPSEC_AH:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV6);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP_IPSEC_SPI);
		break;

	case MLX5E_TT_IPV4_IPSEC_ESP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV4);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP_IPSEC_SPI);
		break;

	case MLX5E_TT_IPV6_IPSEC_ESP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV6);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP_IPSEC_SPI);
		break;

	case MLX5E_TT_IPV4:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV4);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP);
		break;

	case MLX5E_TT_IPV6:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV6);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
			 MLX5_HASH_IP);
		break;
	}
}

static int mlx5e_open_direct_tir(struct mlx5e_priv *priv, int ix)
{
	int *tir_num = &priv->outer_direct_tir[ix].tirn;
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 *in;
	void *tirc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

	mlx5e_build_direct_tir_ctx(priv, tirc, priv->outer_direct_tir[ix].rqtn);

	err = mlx5_core_create_tir(mdev, in, inlen, tir_num);

	kvfree(in);

	return err;
}

static int mlx5e_open_tir(struct mlx5e_priv *priv, int tt, bool is_inner)
{
	u32 *tir_num = is_inner ? &priv->inner_tirn[tt] : &priv->outer_tirn[tt];
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 *in;
	void *tirc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

	mlx5e_build_tir_ctx(priv, tirc, tt, is_inner);

	err = mlx5_core_create_tir(mdev, in, inlen, tir_num);

	kvfree(in);

	return err;
}

static void mlx5e_close_direct_tir(struct mlx5e_priv *priv, int ix)
{
	int tir_num = priv->outer_direct_tir[ix].tirn;;

	mlx5_core_destroy_tir(priv->mdev, tir_num);
}

static void mlx5e_close_tir(struct mlx5e_priv *priv, int tt, bool is_inner)
{
	u32 tir_num = is_inner ? priv->inner_tirn[tt] : priv->outer_tirn[tt];

	mlx5_core_destroy_tir(priv->mdev, tir_num);
}

static int mlx5e_open_tirs(struct mlx5e_priv *priv)
{
	int nch = priv->params.num_channels;
	int err;
	int i, j, ix;

	for (i = 0; i < MLX5E_NUM_TT; i++) {
		err = mlx5e_open_tir(priv, i, false);
		if (err)
			goto err_close_tirs;
		if (mlx5e_tunnel_stateless_supported(priv->mdev)) {
			err = mlx5e_open_tir(priv, i, true);
			if (err) {
				mlx5e_close_tir(priv, i, false);
				goto err_close_tirs;
			}
		}
	}

	for (ix = 0; ix < nch; ix++) {
		err = mlx5e_open_direct_tir(priv, ix);
		if (err)
			goto err_close_direct_tirs;
	}

	for (j = 0; j < MLX5E_SNIFFER_NUM_TYPE; j++) {
		err = mlx5e_sniffer_open_tir(priv, j);
		if (err)
			goto err_close_sniffer_tirs;
	}

	return 0;

err_close_sniffer_tirs:
	for (j--; j >= 0; j--)
		mlx5_core_destroy_tir(priv->mdev, priv->sniffer_tirn[j]);

err_close_direct_tirs:
	for (ix--; ix >= 0; ix--)
		mlx5e_close_direct_tir(priv, ix);

err_close_tirs:
	for (i--; i >= 0; i--) {
		if (mlx5e_tunnel_stateless_supported(priv->mdev))
			mlx5e_close_tir(priv, i, true);
		mlx5e_close_tir(priv, i, false);
	}

	return err;
}

static void mlx5e_close_tirs(struct mlx5e_priv *priv)
{
	int nch = priv->params.num_channels;
	int i;

	for (i = 0; i < MLX5E_NUM_TT; i++) {
		if (mlx5e_tunnel_stateless_supported(priv->mdev))
			mlx5e_close_tir(priv, i, true);
		mlx5e_close_tir(priv, i, false);
	}

	for (i = 0; i < nch; i++)
		mlx5e_close_direct_tir(priv, i);

	for (i = 0; i < MLX5E_SNIFFER_NUM_TYPE; i++)
		mlx5_core_destroy_tir(priv->mdev, priv->sniffer_tirn[i]);
}

static void mlx5e_netdev_set_tcs(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
#ifdef HAVE_NETDEV_SET_TC_QUEUE
	int nch = priv->params.num_channels;
#endif
	int ntc = priv->params.num_tc;
#ifdef HAVE_NETDEV_SET_PRIO_TC_MAP
	int prio;
#endif
#ifdef HAVE_NETDEV_SET_TC_QUEUE
	int tc;
#endif

#ifdef HAVE_NETDEV_RESET_TC
	netdev_reset_tc(netdev);
#endif
	if (ntc == 1)
		return;
#ifdef HAVE_NETDEV_SET_NUM_TC
	netdev_set_num_tc(netdev, ntc);
#endif
#ifdef HAVE_NETDEV_SET_TC_QUEUE
	for (tc = 0; tc < ntc; tc++)
		netdev_set_tc_queue(netdev, tc, nch, tc * nch);
#endif
#ifdef HAVE_NETDEV_SET_PRIO_TC_MAP
	for (prio = 0; prio < MLX5E_MAX_NUM_PRIO; prio++)
		netdev_set_prio_tc_map(netdev, prio, prio % ntc);
#endif
}

static int mlx5e_set_mtu(struct mlx5e_priv *priv, u16 mtu)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u16 hw_mtu = MLX5E_SW2HW_MTU(mtu);
	int err;

	err = mlx5_set_port_mtu(mdev, hw_mtu);
	if (err)
		return err;

	/* Update vport context MTU */
	mlx5_modify_nic_vport_mtu(mdev, hw_mtu);
	return 0;
}

static void mlx5e_query_mtu(struct mlx5e_priv *priv, u16 *mtu)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u16 hw_mtu = 0;
	int err;

	err = mlx5_query_nic_vport_mtu(mdev, &hw_mtu);
	if (err || !hw_mtu) /* fallback to port oper mtu */
		mlx5_query_port_oper_mtu(mdev, &hw_mtu);

	*mtu = MLX5E_HW2SW_MTU(hw_mtu);
}

static int mlx5e_set_dev_port_mtu(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	u16 mtu;
	int err;

	err = mlx5e_set_mtu(priv, netdev->mtu);
	if (err)
		return err;

	mlx5e_query_mtu(priv, &mtu);
	if (mtu != netdev->mtu)
		netdev_warn(netdev, "%s: VPort MTU %d is different than netdev mtu %d\n",
			    __func__, mtu, netdev->mtu);

	netdev->mtu = mtu;
	return 0;
}

int mlx5e_open_locked(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int num_txqs;
	int err;

	mlx5e_netdev_set_tcs(netdev);

	num_txqs = priv->params.num_channels * priv->params.num_tc +
		   priv->params.num_rl_txqs;
	netif_set_real_num_tx_queues(netdev, num_txqs);
	netif_set_real_num_rx_queues(netdev, priv->params.num_channels);

	err = mlx5e_set_dev_port_mtu(netdev);
	if (err)
		return err;

	err = mlx5e_open_tises(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_tises failed, %d\n",
			   __func__, err);
		return err;
	}

	err = mlx5e_open_channels(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_channels failed, %d\n",
			   __func__, err);
		goto err_close_tises;
	}

	err = mlx5e_open_rqts(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_rqts failed, %d\n",
			   __func__, err);
		goto err_close_channels;
	}

	err = mlx5e_open_tirs(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_tir failed, %d\n",
			   __func__, err);
		goto err_close_rqts;
	}

	err = mlx5e_create_flow_steering(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_create_flow_steering failed, %d\n",
			   __func__, err);
		goto err_close_tirs;
	}

#ifdef HAVE_NDO_SET_TX_MAXRATE
	err = mlx5e_rl_init_sysfs(netdev);
	if (err) {
		netdev_err(netdev, "%s: Failed to create rate limit sysfs entries, %d\n",
			   __func__, err);
		goto err_destroy_flow_steering;
	}
	hash_init(priv->flow_map_hash);
#endif

	mlx5e_init_eth_addr(priv);

#if defined(HAVE_VXLAN_ENABLED) && defined(HAVE_VXLAN_DYNAMIC_PORT)
	mlx5e_vxlan_init(priv);
#endif

	set_bit(MLX5E_STATE_OPENED, &priv->state);

	mlx5e_create_debugfs(priv);
	mlx5e_update_carrier(priv);
#ifdef HAVE_NETDEV_RX_CPU_RMAP
#ifdef CONFIG_RFS_ACCEL
	priv->netdev->rx_cpu_rmap = priv->mdev->rmap;
#endif
#endif
	mlx5e_set_rx_mode_core(priv);

	queue_delayed_work(priv->wq, &priv->update_stats_work, 0);
	queue_delayed_work(priv->wq, &priv->service_task, 0);

	return 0;

#ifdef HAVE_NDO_SET_TX_MAXRATE
err_destroy_flow_steering:
	mlx5e_destroy_flow_steering(priv);
#endif

err_close_tirs:
	mlx5e_close_tirs(priv);

err_close_rqts:
	mlx5e_close_rqts(priv);

err_close_channels:
	mlx5e_close_channels(priv);

err_close_tises:
	mlx5e_close_tises(priv);

	return err;
}

static int mlx5e_open(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err;

	mutex_lock(&priv->state_lock);
	if (mlx5_set_port_status(priv->mdev, MLX5_PORT_UP, 1))
		netdev_err(priv->netdev,
			   "%s: Setting port status to up failed\n",
			   __func__);
	err = mlx5e_open_locked(netdev);
	mutex_unlock(&priv->state_lock);

#if defined(HAVE_VXLAN_ENABLED) && defined(HAVE_VXLAN_DYNAMIC_PORT)
	if (!err && mlx5e_vxlan_allowed(priv->mdev))
		vxlan_get_rx_port(netdev);
#endif

	return err;
}

int mlx5e_close_locked(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	/* May already be CLOSED in case a previous configuration operation
	 * (e.g RX/TX queue size change) that involves close&open failed at the
	 * open stage and then another configuration operation (e.g ifconfig
	 * down) is executed.
	 */
	if (!test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		netdev_err(netdev, "Device is already closed\n");
		return 0;
	}
	clear_bit(MLX5E_STATE_OPENED, &priv->state);

	mlx5e_set_rx_mode_core(priv);
#if defined(HAVE_VXLAN_ENABLED) && defined(HAVE_VXLAN_DYNAMIC_PORT)
	mlx5e_vxlan_cleanup(priv);
#endif
#ifdef HAVE_GET_SET_PRIV_FLAGS
	if (priv->pflags & MLX5E_PRIV_FLAGS_SNIFFER_EN) {
		mlx5e_sniffer_turn_off(netdev);
		priv->pflags ^= MLX5E_PRIV_FLAGS_SNIFFER_EN;
	}
#endif
	netif_carrier_off(priv->netdev);
	mlx5e_destroy_debugfs(priv);
#ifdef HAVE_NDO_SET_TX_MAXRATE
	mlx5e_rl_remove_sysfs(netdev);
#endif
	mlx5e_destroy_flow_steering(priv);
	mlx5e_close_tirs(priv);
	mlx5e_close_rqts(priv);
	mlx5e_close_channels(priv);
	mlx5e_close_tises(priv);

	return 0;
}

static int mlx5e_close(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err;

	mutex_lock(&priv->state_lock);
	err = mlx5e_close_locked(netdev);
	if (mlx5_set_port_status(priv->mdev, MLX5_PORT_DOWN, 1))
		netdev_err(priv->netdev,
			   "%s: Setting port status to down failed\n",
			   __func__);
	mutex_unlock(&priv->state_lock);

	return err;
}

int mlx5e_do_update_priv_params(struct mlx5e_priv *priv,
				struct mlx5e_params *new_params,
				int up)
{
	int err = 0;
	int was_opened = test_bit(MLX5E_STATE_OPENED, &priv->state);

	if (was_opened)
		mlx5e_close_locked(priv->netdev);

	priv->params = *new_params;

	if (was_opened || up)
		err = mlx5e_open_locked(priv->netdev);

	return err;
}

int mlx5e_update_priv_params(struct mlx5e_priv *priv,
			     struct mlx5e_params *new_params)
{
	struct mlx5e_params old_params = priv->params;
	int was_opened;
	int err = 0;
	int rb_err = 0;

	WARN_ON(!mutex_is_locked(&priv->state_lock));

	was_opened = test_bit(MLX5E_STATE_OPENED, &priv->state);

	err = mlx5e_do_update_priv_params(priv, new_params, 0);
	if (err) {
		/* do rollback in case of error */
		netdev_err(priv->netdev,
			   "%s: Failed to change device parameters\n",
			   __func__);
		rb_err = mlx5e_do_update_priv_params(priv, &old_params,
						     was_opened);
		if (rb_err)
			netdev_err(priv->netdev,
				   "%s: Rollback failed. Reboot is needed\n",
				   __func__);
	}
	return err;
}

int mlx5e_modify_rqs_vsd(struct mlx5e_priv *priv, int vsd)
{
	int i, err = 0;

	WARN_ON(!mutex_is_locked(&priv->state_lock));

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		mlx5e_dbg(HW, priv, "Device closed, nothing to change\n");
		return 0;
	}

	for (i = 0; i < priv->params.num_channels; i++) {
		err = mlx5e_modify_rq_vsd(&priv->channel[i]->rq,
					  MLX5_RQC_STATE_RDY, vsd);
		if (err)
			return err;
	}

	return 0;
}

int mlx5e_setup_tc(struct net_device *netdev, u8 tc)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_params new_params;
	int err;

	if (tc > MLX5E_MAX_NUM_TC)
		return -EINVAL;

	mutex_lock(&priv->state_lock);
	new_params = priv->params;
	new_params.num_tc = tc ? tc : 1;
	err = mlx5e_update_priv_params(priv, &new_params);
	mutex_unlock(&priv->state_lock);

	return err;
}

#ifdef HAVE_NDO_SETUP_TC_4_PARAMS
static int mlx5e_ndo_setup_tc(struct net_device *dev, u32 handle,
			      __be16 proto, struct tc_to_netdev *tc)
{
	if (tc->type != TC_SETUP_MQPRIO)
		return -EINVAL;

	return mlx5e_setup_tc(dev, tc->tc);
}
#endif /* HAVE_NDO_SETUP_TC_4_PARAMS */

#ifdef HAVE_NDO_GET_STATS64
static struct rtnl_link_stats64 *
mlx5e_get_stats(struct net_device *dev, struct rtnl_link_stats64 *stats)
#else
static struct net_device_stats *mlx5e_get_stats(struct net_device *dev)
#endif
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_sw_stats *sstats = &priv->stats.sw;
	struct mlx5e_vport_stats *vstats = &priv->stats.vport;
	struct mlx5e_pport_stats *pstats = &priv->stats.pport;

#ifndef HAVE_NDO_GET_STATS64
	struct net_device_stats *stats = &priv->netdev_stats;
#endif

	stats->rx_packets = sstats->rx_packets;
	stats->rx_bytes   = sstats->rx_bytes;
	stats->tx_packets = sstats->tx_packets;
	stats->tx_bytes   = sstats->tx_bytes;

	stats->rx_dropped = priv->stats.qcnt.rx_out_of_buffer;
	stats->tx_dropped = sstats->tx_queue_dropped;

	stats->rx_length_errors =
		PPORT_802_3_GET(pstats, a_in_range_length_errors) +
		PPORT_802_3_GET(pstats, a_out_of_range_length_field) +
		PPORT_802_3_GET(pstats, a_frame_too_long_errors);
	stats->rx_crc_errors =
		PPORT_802_3_GET(pstats, a_frame_check_sequence_errors);
	stats->rx_frame_errors = PPORT_802_3_GET(pstats, a_alignment_errors);
	stats->tx_aborted_errors = PPORT_2863_GET(pstats, if_out_discards);
	stats->tx_carrier_errors =
		PPORT_802_3_GET(pstats, a_symbol_error_during_carrier);
	stats->rx_errors = stats->rx_length_errors + stats->rx_crc_errors +
		stats->rx_frame_errors;
	stats->tx_errors = stats->tx_aborted_errors + stats->tx_carrier_errors;

	/* vport multicast also counts packets that are dropped due to steering
	* or rx out of buffer
	*/
	stats->multicast =
		VPORT_COUNTER_GET(vstats, received_eth_multicast.packets);

	return stats;


	return stats;
}

static void mlx5e_set_rx_mode(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	if (!priv->internal_error)
		queue_work(priv->wq, &priv->set_rx_mode_work);
}

static int mlx5e_set_mac(struct net_device *netdev, void *addr)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct sockaddr *saddr = addr;

	if (!is_valid_ether_addr(saddr->sa_data))
		return -EADDRNOTAVAIL;

	netif_addr_lock_bh(netdev);
	ether_addr_copy(netdev->dev_addr, saddr->sa_data);
	netif_addr_unlock_bh(netdev);

	if (!priv->internal_error)
		queue_work(priv->wq, &priv->set_rx_mode_work);

	return 0;
}

#if (defined(HAVE_NDO_SET_FEATURES) || defined(HAVE_NET_DEVICE_OPS_EXT))
#ifdef CONFIG_RFS_ACCEL
static int set_feature_arfs(struct net_device *netdev, bool enable)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err;

	if (enable)
		err = mlx5e_arfs_enable(priv);
	else
		err = mlx5e_arfs_disable(priv);

	return err;
}
#endif
#endif

#if (defined(HAVE_NDO_SET_FEATURES) || defined(HAVE_NET_DEVICE_OPS_EXT))
static int mlx5e_set_features(struct net_device *netdev,
#ifdef HAVE_NET_DEVICE_OPS_EXT
			      u32 features)
#else
			      netdev_features_t features)
#endif
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	netdev_features_t changes = features ^ netdev->features;
	struct mlx5e_params new_params;
	bool update_params = false;
	int err = 0;

	mutex_lock(&priv->state_lock);
	new_params = priv->params;

	if (changes & NETIF_F_LRO) {
		new_params.lro_en = !!(features & NETIF_F_LRO);
		update_params = true;
	}

	if (update_params)
		err = mlx5e_update_priv_params(priv, &new_params);

	if (err)
		goto out;

	if (changes & NETIF_F_HW_VLAN_CTAG_FILTER) {
		if (features & NETIF_F_HW_VLAN_CTAG_FILTER)
			mlx5e_enable_vlan_filter(priv);
		else
			mlx5e_disable_vlan_filter(priv);
	}

	if (changes & NETIF_F_HW_VLAN_CTAG_RX)
		mlx5e_modify_rqs_vsd(priv, features & NETIF_F_HW_VLAN_CTAG_RX ?
				     0 : 1);
#ifdef CONFIG_RFS_ACCEL
	if (changes & NETIF_F_NTUPLE)
		err = set_feature_arfs(netdev, features & NETIF_F_NTUPLE);
#endif
out:
	mutex_unlock(&priv->state_lock);

	return err;
}
#endif

static int mlx5e_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u16 max_mtu;
	u16 max_hw_mtu;
	u16 min_mtu;
	int err;

	mlx5_query_port_max_mtu(mdev, &max_hw_mtu);

	max_mtu = min_t(int, MLX5E_MAX_MTU, MLX5E_HW2SW_MTU(max_hw_mtu));
	min_mtu = MLX5E_HW2SW_MTU(MXL5E_MIN_MTU);

	if ((new_mtu > max_mtu) || (new_mtu < min_mtu)) {
		netdev_err(netdev,
			   "%s: Bad MTU (%d), valid range is: [%d..%d]\n",
			   __func__, new_mtu, min_mtu, max_mtu);
		return -EINVAL;
	}

	mutex_lock(&priv->state_lock);
	netdev->mtu = new_mtu;
	err = mlx5e_update_priv_params(priv, &priv->params);
	mutex_unlock(&priv->state_lock);

	return err;
}

#ifdef HAVE_SIOCGHWTSTAMP
static int mlx5e_hwstamp_set(struct net_device *dev, struct ifreq *ifr)
#else
static int mlx5e_hwstamp_ioctl(struct net_device *dev, struct ifreq *ifr)
#endif
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct hwtstamp_config config;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

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

	priv->tstamp.hwtstamp_config.tx_type = config.tx_type;
	priv->tstamp.hwtstamp_config.rx_filter = config.rx_filter;

	return copy_to_user(ifr->ifr_data, &config,
			    sizeof(config)) ? -EFAULT : 0;
}

#ifdef HAVE_SIOCGHWTSTAMP
static int mlx5e_hwstamp_get(struct net_device *dev, struct ifreq *ifr)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	return copy_to_user(ifr->ifr_data, &priv->tstamp.hwtstamp_config,
			    sizeof(priv->tstamp.hwtstamp_config)) ? -EFAULT : 0;
}
#endif

static int mlx5e_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case SIOCSHWTSTAMP:
#ifdef HAVE_SIOCGHWTSTAMP
		return mlx5e_hwstamp_set(dev, ifr);
	case SIOCGHWTSTAMP:
		return mlx5e_hwstamp_get(dev, ifr);
#else
	return mlx5e_hwstamp_ioctl(dev, ifr);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
void mlx5e_vlan_register(struct net_device *netdev, struct vlan_group *grp)
{
        struct mlx5e_priv *priv = netdev_priv(netdev);
        priv->vlan_grp = grp;
}
#endif

#ifdef HAVE_NDO_SET_VF_MAC
static int mlx5e_set_vf_mac(struct net_device *dev, int vf, u8 *mac)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	return mlx5_eswitch_set_vport_mac(mdev->priv.eswitch, vf + 1, mac);
}

static int mlx5e_set_vf_vlan(struct net_device *dev, int vf, u16 vlan, u8 qos)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	return mlx5_eswitch_set_vport_vlan(mdev->priv.eswitch, vf + 1, vlan, qos);
}
#endif

#ifdef HAVE_LINKSTATE
static int mlx5_vport_link2ifla(u8 esw_link)
{
	switch (esw_link) {
	case MLX5_ESW_VPORT_ADMIN_STATE_DOWN:
		return IFLA_VF_LINK_STATE_DISABLE;
	case MLX5_ESW_VPORT_ADMIN_STATE_UP:
		return IFLA_VF_LINK_STATE_ENABLE;
	};
	return IFLA_VF_LINK_STATE_AUTO;
}

static int mlx5_ifla_link2vport(u8 ifla_link)
{
	switch (ifla_link) {
	case IFLA_VF_LINK_STATE_DISABLE:
		return MLX5_ESW_VPORT_ADMIN_STATE_DOWN;
	case IFLA_VF_LINK_STATE_ENABLE:
		return MLX5_ESW_VPORT_ADMIN_STATE_UP;
	};
	return MLX5_ESW_VPORT_ADMIN_STATE_AUTO;
}
#endif

#if defined(HAVE_NETDEV_OPS_NDO_SET_VF_LINK_STATE) || defined(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_LINK_STATE)
static int mlx5e_set_vf_link_state(struct net_device *dev, int vf,
				   int link_state)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	return mlx5_eswitch_set_vport_state(mdev->priv.eswitch, vf + 1,
					    mlx5_ifla_link2vport(link_state));
}
#endif

#if defined(HAVE_VF_INFO_SPOOFCHK) || defined(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_SPOOFCHK)
static int mlx5e_set_vf_spoofchk(struct net_device *dev, int vf, bool setting)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	return mlx5_eswitch_set_vport_spoofchk(mdev->priv.eswitch, vf + 1, setting);
}
#endif

#if defined(HAVE_NETDEV_OPS_NDO_SET_VF_TRUST) || defined(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_TRUST)
static int mlx5e_set_vf_trust(struct net_device *dev, int vf, bool setting)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	return mlx5_eswitch_set_vport_trust(mdev->priv.eswitch, vf + 1, setting);
}
#endif

#ifdef HAVE_NDO_SET_VF_MAC
static int mlx5e_get_vf_config(struct net_device *dev,
			       int vf, struct ifla_vf_info *ivi)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_esw_vport_info evi;
	int err = 0;

	memset(&evi, 0, sizeof(evi));
	err = mlx5_eswitch_get_vport_config(mdev->priv.eswitch, vf + 1, &evi);
	if (err)
		return err;

	memset(ivi, 0, sizeof(*ivi));
	ivi->vf = evi.vf;
	ivi->vlan = evi.vlan;
	ivi->qos = evi.qos;
	memcpy(ivi->mac, evi.mac, sizeof(ivi->mac));
#ifdef HAVE_LINKSTATE
	ivi->linkstate = mlx5_vport_link2ifla(evi.linkstate);
#endif
#ifdef HAVE_VF_INFO_SPOOFCHK
	ivi->spoofchk = evi.spoofchk;
#endif
#ifdef HAVE_VF_INFO_TRUST
	ivi->trust = evi.trust;
#endif
	return err;
}
#endif

#ifdef HAVE_NDO_GET_VF_STATS
static int mlx5e_get_vf_stats(struct net_device *dev,
			      int vf, struct ifla_vf_stats *vf_stats)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	return mlx5_eswitch_get_vport_stats(mdev->priv.eswitch, vf + 1, vf_stats);
}
#endif

#if defined(HAVE_VXLAN_ENABLED) && defined(HAVE_VXLAN_DYNAMIC_PORT)
static void mlx5e_add_vxlan_port(struct net_device *netdev,
				 sa_family_t sa_family, __be16 port)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	if (!mlx5e_vxlan_allowed(priv->mdev))
		return;

	mlx5e_vxlan_queue_work(priv, sa_family, be16_to_cpu(port), 1);
}

static void mlx5e_del_vxlan_port(struct net_device *netdev,
				 sa_family_t sa_family, __be16 port)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	if (!mlx5e_vxlan_allowed(priv->mdev))
		return;

	mlx5e_vxlan_queue_work(priv, sa_family, be16_to_cpu(port), 0);
}

#if defined(HAVE_NETDEV_FEATURES_T)
static netdev_features_t mlx5e_vxlan_features_check(struct mlx5e_priv *priv,
						    struct sk_buff *skb,
						    netdev_features_t features)
{
	struct udphdr *udph;
	u16 proto;
	u16 port = 0;

	switch (vlan_get_protocol(skb)) {
	case htons(ETH_P_IP):
		proto = ip_hdr(skb)->protocol;
		break;
	case htons(ETH_P_IPV6):
		proto = ipv6_hdr(skb)->nexthdr;
		break;
	default:
		goto out;
	}

	if (proto == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		port = be16_to_cpu(udph->dest);
	}

	/* Verify if UDP port is being offloaded by HW */
	if (port && mlx5e_vxlan_lookup_port(priv, port))
		return features;

out:
	/* Disable CSUM and GSO if the udp dport is not offloaded by HW */
	return features & ~(NETIF_F_ALL_CSUM | NETIF_F_GSO_MASK);
}

static netdev_features_t mlx5e_features_check(struct sk_buff *skb,
					      struct net_device *netdev,
					      netdev_features_t features)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

#ifdef HAVE_VLAN_FEATURES_CHECK
	features = vlan_features_check(skb, features);
#endif
	features = vxlan_features_check(skb, features);

	/* Validate if the tunneled packet is being offloaded by HW */
	if (skb->encapsulation &&
	    (features & NETIF_F_ALL_CSUM || features & NETIF_F_GSO_MASK))
		return mlx5e_vxlan_features_check(priv, skb, features);

	return features;
}
#elif defined(HAVE_VXLAN_GSO_CHECK)
static bool mlx5e_gso_check(struct sk_buff *skb, struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct udphdr *udph;
	u16 port;

	if (!vxlan_gso_check(skb))
		return false;

	if (!skb->encapsulation)
		return true;

	udph = udp_hdr(skb);
	port = be16_to_cpu(udph->dest);

	if (!mlx5e_vxlan_lookup_port(priv, port)) {
		skb->ip_summed = CHECKSUM_NONE;
		return false;
	}

	return true;
}
#endif
#endif

static void mlx5e_tx_timeout(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	bool sched_work = false;
	int num_sqs;
	int i;

	netdev_err(dev, "TX timeout detected\n");

	num_sqs = priv->params.num_channels * priv->params.num_tc +
		  priv->params.num_rl_txqs;

#if defined(HAVE_NETIF_TX_QUEUE_STOPPED) && defined (HAVE_NETDEV_GET_TX_QUEUE)
	for (i = 0; i < num_sqs; i++) {
		struct mlx5e_sq *sq = priv->txq_to_sq_map[i];

		if (!netif_tx_queue_stopped(netdev_get_tx_queue(dev, i)))
			continue;
		sched_work = true;
		set_bit(MLX5E_SQ_TX_TIMEOUT, &sq->state);
		netdev_err(dev, "TX timeout on queue: %d, SQ: 0x%x, CQ: 0x%x, SQ Cons: 0x%x SQ Prod: 0x%x\n",
			   i, sq->sqn, sq->cq.mcq.cqn, sq->cc, sq->pc);
	}
#else
	sched_work = true;
#endif

	if (sched_work && test_bit(MLX5E_STATE_OPENED, &priv->state))
		queue_work(priv->wq, &priv->tx_timeout_work);
}

static struct net_device_ops mlx5e_netdev_ops = {
	.ndo_open                = mlx5e_open,
 	.ndo_stop                = mlx5e_close,
 	.ndo_start_xmit          = mlx5e_xmit,
#ifdef HAVE_NDO_SETUP_TC
#ifdef HAVE_NDO_SETUP_TC_4_PARAMS
	.ndo_setup_tc            = mlx5e_ndo_setup_tc,
#else /* HAVE_NDO_SETUP_TC_4_PARAMS */
 	.ndo_setup_tc            = mlx5e_setup_tc,
#endif /* HAVE_NDO_SETUP_TC_4_PARAMS */
#endif /* HAVE_NDO_SETUP_TC */
 	.ndo_select_queue        = mlx5e_select_queue,
#ifdef HAVE_NDO_GET_STATS64
 	.ndo_get_stats64         = mlx5e_get_stats,
#else
	.ndo_get_stats           = mlx5e_get_stats,
#endif
 	.ndo_set_rx_mode         = mlx5e_set_rx_mode,
 	.ndo_set_mac_address     = mlx5e_set_mac,
 	.ndo_vlan_rx_add_vid	 = mlx5e_vlan_rx_add_vid,
 	.ndo_vlan_rx_kill_vid	 = mlx5e_vlan_rx_kill_vid,
#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
	.ndo_vlan_rx_register    = mlx5e_vlan_register,
#endif
#if (defined(HAVE_NDO_SET_FEATURES) && !defined(HAVE_NET_DEVICE_OPS_EXT))
	.ndo_set_features        = mlx5e_set_features,
#endif
 	.ndo_change_mtu		 = mlx5e_change_mtu,
#ifdef HAVE_NDO_SET_VF_MAC
	.ndo_set_vf_mac          = mlx5e_set_vf_mac,
	.ndo_set_vf_vlan         = mlx5e_set_vf_vlan,
	.ndo_get_vf_config       = mlx5e_get_vf_config,
#endif
#ifdef HAVE_NDO_GET_VF_STATS
	.ndo_get_vf_stats        = mlx5e_get_vf_stats,
#endif
#if (defined(HAVE_NETDEV_OPS_NDO_SET_VF_LINK_STATE) && !defined(HAVE_NET_DEVICE_OPS_EXT))
	.ndo_set_vf_link_state   = mlx5e_set_vf_link_state,
#endif
#if (defined(HAVE_NETDEV_OPS_NDO_SET_VF_SPOOFCHK) && !defined(HAVE_NET_DEVICE_OPS_EXT))
	.ndo_set_vf_spoofchk     = mlx5e_set_vf_spoofchk,
#endif
#if (defined(HAVE_NETDEV_OPS_NDO_SET_VF_TRUST) && !defined(HAVE_NET_DEVICE_OPS_EXT))
	.ndo_set_vf_trust        = mlx5e_set_vf_trust,
	.ndo_add_vxlan_port	 = mlx5e_add_vxlan_port,
	.ndo_del_vxlan_port	 = mlx5e_del_vxlan_port,
	.ndo_features_check	 = mlx5e_features_check,
#endif
#if defined(HAVE_VXLAN_ENABLED) && defined(HAVE_VXLAN_DYNAMIC_PORT)
	.ndo_add_vxlan_port      = mlx5e_add_vxlan_port,
	.ndo_del_vxlan_port      = mlx5e_del_vxlan_port,
#if defined(HAVE_NETDEV_FEATURES_T)
	.ndo_features_check      = mlx5e_features_check,
#elif defined(HAVE_VXLAN_GSO_CHECK)
	.ndo_gso_check           = mlx5e_gso_check,
#endif
#endif
	.ndo_do_ioctl            = mlx5e_ioctl,
#ifdef HAVE_NDO_RX_FLOW_STEER
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer	 = mlx5e_rx_flow_steer,
#endif
#endif
#ifdef HAVE_NDO_SET_TX_MAXRATE
	.ndo_set_tx_maxrate      = mlx5e_set_tx_maxrate,
#endif
	.ndo_tx_timeout          = mlx5e_tx_timeout,
};

#ifdef HAVE_NET_DEVICE_OPS_EXT
static const struct net_device_ops_ext mlx5_netdev_ops_ext = {
	.size             = sizeof(struct net_device_ops_ext),
	.ndo_set_features = mlx5e_set_features,
#ifdef HAVE_NETDEV_OPS_EXT_NDO_SET_VF_SPOOFCHK
	.ndo_set_vf_spoofchk    = mlx5e_set_vf_spoofchk,
#endif
#ifdef HAVE_NETDEV_OPS_EXT_NDO_SET_VF_TRUST
	.ndo_set_vf_spoofchk    = mlx5e_set_vf_trust,
#endif
#if defined(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_LINK_STATE)
	.ndo_set_vf_link_state  = mlx5e_set_vf_link_state,
#endif
};
#endif

static int mlx5e_check_required_hca_cap(struct mlx5_core_dev *mdev)
{
	if (MLX5_CAP_GEN(mdev, port_type) != MLX5_CAP_PORT_TYPE_ETH)
		return -ENOTSUPP;
	/* TODO: cehck if more caps are needed */
	if (!MLX5_CAP_GEN(mdev, eth_net_offloads) ||
	    !MLX5_CAP_GEN(mdev, nic_flow_table) ||
	    /* TODO: move following caps to control path (NETDEV Flags/OPs) */
	    !MLX5_CAP_ETH(mdev, csum_cap) ||
	    !MLX5_CAP_ETH(mdev, max_lso_cap) ||
	    !MLX5_CAP_ETH(mdev, vlan_cap) ||
	    !MLX5_CAP_ETH(mdev, rss_ind_tbl_cap) ||
	    MLX5_CAP_FLOWTABLE(mdev,
			       flow_table_properties_nic_receive.max_ft_level)
			       < 3) {
		mlx5_core_warn(mdev,
			       "Not creating net device, some required device capabilities are missing\n");
		return -ENOTSUPP;
	}
	if (!MLX5_CAP_GEN(mdev, cq_moderation))
		mlx5_core_warn(mdev, "cq moderation is not supported by the device\n");
	return 0;
}

static int get_num_pcpus_per_numa(int node_id)
{
	int i = 0;
	int cpu;

	if (node_id == -1)
		return num_online_cpus();

	for_each_cpu_and(cpu, cpumask_of_node(node_id), cpu_online_mask)
		i++;

	return i ? i : num_online_cpus();
}

void mlx5e_build_default_indir_rqt(struct mlx5_core_dev *mdev,
				   u32 *indirection_rqt, int len,
				   int num_channels)
{
	int nphys_cores = get_num_pcpus_per_numa(mdev->priv.numa_node);
	int i;

	num_channels = min_t(int, num_channels, nphys_cores);

	for (i = 0; i < len; i++)
		indirection_rqt[i] = i % num_channels;
}

u32 mlx5e_choose_lro_timeout(struct mlx5_core_dev *mdev,
			     u32 wanted_timeout)
{
	int i;

	/* The supported timers are organized in ascending order */
	for (i = 0; i < MLX5E_LRO_TIMEOUT_ARR_SIZE; i++)
		if (MLX5_CAP_ETH(mdev, lro_timer_supported_periods[i]) >=
		    wanted_timeout)
			return MLX5_CAP_ETH(mdev,
					    lro_timer_supported_periods[i]);

	return MLX5_CAP_ETH(mdev, lro_timer_supported_periods[i - 1]);
}

static void mlx5e_build_netdev_priv(struct mlx5_core_dev *mdev,
				    struct net_device *netdev,
				    int num_channels)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	/* TODO: consider link speed for setting the following:
	 *       log_sq_size
	 *       log_rq_size
	 *       cq moderation?
	 *       lro_timeout_period_usecs@mlx5e_build_tir_ctx()
	 */
	priv->params.log_sq_size           =
		MLX5E_PARAMS_DEFAULT_LOG_SQ_SIZE;
	priv->params.log_rq_size           =
		MLX5E_PARAMS_DEFAULT_LOG_RQ_SIZE;
	priv->params.rx_cq_moderation_usec =
		MLX5_CAP_GEN(mdev, cq_period_start_from_cqe) ?
		MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC_FROM_CQE :
		MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC;
	priv->params.rx_cq_moderation_pkts =
		MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_PKTS;
	priv->params.tx_cq_moderation_usec =
		MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC;
	priv->params.tx_cq_moderation_pkts =
		MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_PKTS;
	priv->params.num_tc                = 1;
	priv->params.default_vlan_prio     = 0;
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
	priv->params.rss_hfunc             = ETH_RSS_HASH_XOR;
#endif

	mlx5e_build_default_indir_rqt(mdev, priv->params.indirection_rqt,
				      MLX5E_INDIR_RQT_SIZE, num_channels);

	netdev_rss_key_fill(priv->params.toeplitz_hash_key,
			    sizeof(priv->params.toeplitz_hash_key));

	if (MLX5_CAP_GEN(mdev, striding_rq)) {
		/* TODO ethtoo for these params */
		priv->params.log_rq_size = MLX5E_PARAMS_DEFAULT_LOG_STRIDING_RQ_SIZE;
	}
	priv->params.min_rx_wqes =
		mlx5_min_rx_wqes(MLX5_CAP_GEN(mdev, striding_rq),
				 BIT(priv->params.log_rq_size));
	/* TODO: add user ability to configure lro wqe size */
	/* Enable LRO by default in case of strided RQ is supported */
	if (MLX5_CAP_GEN(mdev, striding_rq) && MLX5_CAP_ETH(mdev, lro_cap)) {
		priv->params.lro_en = true;
#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
		priv->pflags |= MLX5E_PRIV_FLAG_HWLRO;
#endif
	} else {
		priv->params.lro_en = false;
	}

	priv->params.lro_wqe_sz            =
		MLX5E_PARAMS_DEFAULT_LRO_WQE_SZ;

	priv->mdev                         = mdev;
	priv->netdev                       = netdev;
	priv->params.num_channels          = num_channels;
	priv->params.num_rl_txqs           = 0;
	priv->default_vlan_prio            = priv->params.default_vlan_prio;
	priv->msg_level                    = MLX5E_MSG_LEVEL;
	priv->params.lro_timeout	   = mlx5e_choose_lro_timeout(mdev,
						     MLX5E_DEFAULT_LRO_TIMEOUT);

	spin_lock_init(&priv->async_events_spinlock);
	mutex_init(&priv->state_lock);

	INIT_WORK(&priv->update_carrier_work, mlx5e_update_carrier_work);
	INIT_WORK(&priv->set_rx_mode_work, mlx5e_set_rx_mode_work);
	INIT_WORK(&priv->tx_timeout_work, mlx5e_tx_timeout_work);
	INIT_DELAYED_WORK(&priv->update_stats_work, mlx5e_update_stats_work);
	INIT_DELAYED_WORK(&priv->service_task, mlx5e_service_task);
}

static void mlx5e_set_netdev_dev_addr(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	mlx5_query_nic_vport_mac_address(priv->mdev, 0, netdev->dev_addr);

	if (!MLX5_CAP_GEN(priv->mdev, vport_group_manager) &&
	    is_zero_ether_addr(netdev->dev_addr)) {
#ifdef HAVE_NETDEV_ADDR_ASSIGN_TYPE
		netdev->addr_assign_type |= NET_ADDR_RANDOM;
#endif
#ifdef HAVE_ETH_RANDOM_ADDR
		eth_random_addr(netdev->dev_addr);
#else
		eth_hw_addr_random(netdev);
#endif
		mlx5_core_info(priv->mdev, "Assigned random MAC address %pM\n", netdev->dev_addr);
	}
}

static void mlx5e_build_netdev(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;

	SET_NETDEV_DEV(netdev, &mdev->pdev->dev);

	netdev->netdev_ops        = &mlx5e_netdev_ops;
	netdev->watchdog_timeo    = 15 * HZ;

#ifdef HAVE_ETHTOOL_OPS_EXT
	SET_ETHTOOL_OPS(netdev, &mlx5e_ethtool_ops);
	set_ethtool_ops_ext(netdev, &mlx5e_ethtool_ops_ext);
#else
	netdev->ethtool_ops       = &mlx5e_ethtool_ops;
#endif

#ifdef HAVE_IEEE_DCBNL_ETS
	netdev->dcbnl_ops	  = &mlx5e_dcbnl_ops;
#endif

	netdev->vlan_features    |= NETIF_F_SG;
	netdev->vlan_features    |= NETIF_F_IP_CSUM;
	netdev->vlan_features    |= NETIF_F_IPV6_CSUM;
	netdev->vlan_features    |= NETIF_F_GRO;
	netdev->vlan_features    |= NETIF_F_TSO;
	netdev->vlan_features    |= NETIF_F_TSO6;
	netdev->vlan_features    |= NETIF_F_RXCSUM;
#ifdef HAVE_NETIF_F_RXHASH
	netdev->vlan_features    |= NETIF_F_RXHASH;
#endif

	if (!!MLX5_CAP_ETH(mdev, lro_cap))
		netdev->vlan_features    |= NETIF_F_LRO;

#ifdef HAVE_NETDEV_HW_FEATURES
	netdev->hw_features       = netdev->vlan_features;
	netdev->hw_features      |= NETIF_F_HW_VLAN_CTAG_TX;
	netdev->hw_features      |= NETIF_F_HW_VLAN_CTAG_RX;
	netdev->hw_features      |= NETIF_F_HW_VLAN_CTAG_FILTER;

#ifdef CONFIG_RFS_ACCEL
#define FT_CAP(f) MLX5_CAP_FLOWTABLE(mdev, flow_table_properties_nic_receive.f)
	if (FT_CAP(flow_modify_en) &&
	    FT_CAP(modify_root) &&
	    FT_CAP(identified_miss_table_mode) &&
	    FT_CAP(flow_table_modify))
		netdev->hw_features	 |= NETIF_F_NTUPLE;
#endif
#if defined(HAVE_VXLAN_ENABLED) && defined(HAVE_VXLAN_DYNAMIC_PORT)
	if (mlx5e_vxlan_allowed(mdev)) {
#ifdef HAVE_NETIF_F_GSO_UDP_TUNNEL
		netdev->hw_features	|= NETIF_F_GSO_UDP_TUNNEL;
#endif
#ifdef HAVE_NETDEV_HW_ENC_FEATURES
		netdev->hw_enc_features |= NETIF_F_IP_CSUM;
		netdev->hw_enc_features |= NETIF_F_RXCSUM;
		netdev->hw_enc_features |= NETIF_F_TSO;
		netdev->hw_enc_features |= NETIF_F_TSO6;
#ifdef HAVE_NETIF_F_RXHASH
		netdev->hw_enc_features |= NETIF_F_RXHASH;
#endif
#ifdef HAVE_NETIF_F_GSO_UDP_TUNNEL
		netdev->hw_enc_features |= NETIF_F_GSO_UDP_TUNNEL;
#endif
#endif /* HAVE_NETDEV_HW_ENC_FEATURES */
	}
#endif /* HAVE_VXLAN_ENABLED && HAVE_VXLAN_DYNAMIC_PORT */

	netdev->features          = netdev->hw_features;
#else /* HAVE_NETDEV_HW_FEATURES */
	netdev->features       = netdev->vlan_features;
	netdev->features      |= NETIF_F_HW_VLAN_CTAG_TX;
	netdev->features      |= NETIF_F_HW_VLAN_CTAG_RX;
	netdev->features      |= NETIF_F_HW_VLAN_CTAG_FILTER;
#ifdef HAVE_SET_NETDEV_HW_FEATURES
	set_netdev_hw_features(netdev, netdev->features);
#endif
#endif /* HAVE_NETDEV_HW_FEATURES */


#ifdef CONFIG_RFS_ACCEL
	netdev->features	 &= ~NETIF_F_NTUPLE;
#endif

	if (!priv->params.lro_en)
		netdev->features  &= ~NETIF_F_LRO;

	netdev->features         |= NETIF_F_HIGHDMA;

#ifdef HAVE_NETDEV_IFF_UNICAST_FLT
	netdev->priv_flags       |= IFF_UNICAST_FLT;
#endif

#ifdef HAVE_NET_DEVICE_OPS_EXT
	set_netdev_ops_ext(netdev, &mlx5_netdev_ops_ext);
#endif

	mlx5e_set_netdev_dev_addr(netdev);
}

static int mlx5e_create_mkey(struct mlx5e_priv *priv, u32 pdn,
			     struct mlx5_core_mr *mr)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_create_mkey_mbox_in *in;
	int err;

	in = mlx5_vzalloc(sizeof(*in));
	if (!in)
		return -ENOMEM;

	in->seg.flags = MLX5_PERM_LOCAL_WRITE |
			MLX5_PERM_LOCAL_READ  |
			MLX5_ACCESS_MODE_PA;
	in->seg.flags_pd = cpu_to_be32(pdn | MLX5_MKEY_LEN64);
	in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);

	err = mlx5_core_create_mkey(mdev, mr, in, sizeof(*in), NULL, NULL,
				    NULL);

	kvfree(in);

	return err;
}

static void *mlx5e_create_netdev(struct mlx5_core_dev *mdev)
{
	struct net_device *netdev;
	struct mlx5e_priv *priv;
	int nch = mlx5e_max_num_channels(mdev->priv.eq_table.num_comp_vectors);
	int err;

	if (mlx5e_check_required_hca_cap(mdev))
		return NULL;

#ifdef HAVE_NEW_TX_RING_SCHEME
	netdev = alloc_etherdev_mqs(sizeof(struct mlx5e_priv),
				    nch * MLX5E_MAX_NUM_TC + MLX5E_MAX_RL_QUEUES,
				    nch);
#else
	netdev = alloc_etherdev_mq(sizeof(struct mlx5e_priv), nch);
#endif
	if (!netdev) {
		mlx5_core_err(mdev, "alloc_etherdev_mqs() failed\n");
		return NULL;
	}

	mlx5e_build_netdev_priv(mdev, netdev, nch);
	mlx5e_build_netdev(netdev);

	netif_carrier_off(netdev);

	priv = netdev_priv(netdev);

	priv->wq = create_singlethread_workqueue("mlx5e");
	if (!priv->wq)
		goto err_free_netdev;

	err = mlx5_alloc_map_uar(mdev, &priv->cq_uar);
	if (err) {
		netdev_err(netdev, "%s: mlx5_alloc_map_uar failed, %d\n",
			   __func__, err);
		goto err_destroy_wq;
	}

	err = mlx5_core_alloc_pd(mdev, &priv->pdn);
	if (err) {
		netdev_err(netdev, "%s: mlx5_core_alloc_pd failed, %d\n",
			   __func__, err);
		goto err_unmap_free_uar;
	}

	err = mlx5_alloc_transport_domain(mdev, &priv->tdn);
	if (err) {
		netdev_err(netdev, "%s: mlx5_alloc_transport_domain failed, %d\n",
			   __func__, err);
		goto err_dealloc_pd;
	}

	err = mlx5e_create_mkey(priv, priv->pdn, &priv->mr);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_create_mkey failed, %d\n",
			   __func__, err);
		goto err_dealloc_transport_domain;
	}

	err = mlx5_vport_alloc_q_counter(priv->mdev,
					 MLX5_INTERFACE_PROTOCOL_ETH,
					 &priv->counter_set_id);
	if (err) {
		mlx5_core_warn(mdev, "alloc Q counters failed, %d\n", err);
		goto err_destroy_q_counter;
	}

#ifdef HAVE_IEEE_DCBNL_ETS
	if (MLX5_CAP_GEN(mdev, vport_group_manager))
		mlx5e_dcbnl_initialize(netdev);
#endif

	err = register_netdev(netdev);
	if (err) {
		netdev_err(netdev, "%s: register_netdev failed, %d\n",
			   __func__, err);
		goto err_destroy_mkey;
	}

	if (!is_valid_ether_addr(netdev->perm_addr))
		memcpy(netdev->perm_addr, netdev->dev_addr, netdev->addr_len);

	mlx5e_enable_async_events(priv);

	err = mlx5e_sysfs_create(netdev);
	if (err)
		goto err_unregister_netdev;

	return priv;

err_unregister_netdev:
	unregister_netdev(netdev);

err_destroy_q_counter:
	mlx5_vport_dealloc_q_counter(priv->mdev, MLX5_INTERFACE_PROTOCOL_ETH,
				     priv->counter_set_id);
err_destroy_mkey:
	mlx5_core_destroy_mkey(mdev, &priv->mr);

err_dealloc_transport_domain:
	mlx5_dealloc_transport_domain(mdev, priv->tdn);

err_dealloc_pd:
	mlx5_core_dealloc_pd(mdev, priv->pdn);

err_unmap_free_uar:
	mlx5_unmap_free_uar(mdev, &priv->cq_uar);

err_destroy_wq:
	destroy_workqueue(priv->wq);

err_free_netdev:
	free_netdev(netdev);

	return NULL;
}

static void mlx5e_destroy_netdev(struct mlx5_core_dev *mdev, void *vpriv)
{
	struct mlx5e_priv *priv = vpriv;
	struct net_device *netdev = priv->netdev;

	mlx5e_sysfs_remove(netdev);

	if (test_bit(MLX5_INTERFACE_STATE_SHUTDOWN, &mdev->intf_state))
	{
		netif_device_detach(netdev);
		mutex_lock(&priv->state_lock);
		if (test_bit(MLX5E_STATE_OPENED, &priv->state))
			mlx5e_close_locked(netdev);
		mutex_unlock(&priv->state_lock);
	} else
		unregister_netdev(netdev);

	mlx5_vport_dealloc_q_counter(priv->mdev, MLX5_INTERFACE_PROTOCOL_ETH,
				     priv->counter_set_id);
	mlx5_core_destroy_mkey(priv->mdev, &priv->mr);
	mlx5_dealloc_transport_domain(priv->mdev, priv->tdn);
	mlx5_core_dealloc_pd(priv->mdev, priv->pdn);
	mlx5_unmap_free_uar(priv->mdev, &priv->cq_uar);
	mlx5e_disable_async_events(priv);
	/* this is used to serialize the marking of internal error
	 * state and the restart of update stats work
	 */
	mutex_lock(&priv->state_lock);
	mutex_unlock(&priv->state_lock);
	cancel_delayed_work_sync(&priv->update_stats_work);
	cancel_delayed_work_sync(&priv->service_task);
	destroy_workqueue(priv->wq);

	if (!test_bit(MLX5_INTERFACE_STATE_SHUTDOWN, &mdev->intf_state))
		free_netdev(netdev);
}

static void *mlx5e_get_netdev(void *vpriv)
{
	struct mlx5e_priv *priv = vpriv;

	return priv->netdev;
}

static struct mlx5_interface mlx5e_interface = {
	.add       = mlx5e_create_netdev,
	.remove    = mlx5e_destroy_netdev,
	.event     = mlx5e_async_event,
	.protocol  = MLX5_INTERFACE_PROTOCOL_ETH,
	.get_dev   = mlx5e_get_netdev,
};

void mlx5e_init(void)
{
	mlx5e_sniffer_initialize_private_data();
	mlx5_register_interface(&mlx5e_interface);
}

void mlx5e_cleanup(void)
{
	mlx5_unregister_interface(&mlx5e_interface);
}
