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

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/prefetch.h>
#include "en.h"

#define MLX5E_RX_HW_STAMP(priv)				\
	(priv->tstamp.hwtstamp_config.rx_filter ==	\
		     HWTSTAMP_FILTER_ALL)

static inline void mlx5e_read_cqe_slot(struct mlx5e_cq *cq, u32 cc, void *data)
{
	memcpy(data, mlx5_cqwq_get_wqe(&cq->wq, (cc & cq->wq.sz_m1)),
	       sizeof(struct mlx5_cqe64));
}

static inline void mlx5e_write_cqe_slot(struct mlx5e_cq *cq, u32 cc, void *data)
{
	memcpy(mlx5_cqwq_get_wqe(&cq->wq, cc & cq->wq.sz_m1),
	       data, sizeof(struct mlx5_cqe64));
}

static inline void mlx5e_decompress_cqe(struct mlx5e_cq *cq,
					struct mlx5_cqe64 *title,
					struct mlx5_mini_cqe8 *mini,
					u16 wqe_counter, int i)
{
	title->byte_cnt = mini->byte_cnt;
	title->wqe_counter = cpu_to_be16((wqe_counter + i) & cq->wq.sz_m1);
	title->check_sum = mini->checksum;
	title->op_own = (title->op_own & 0xf0) |
		(((cq->wq.cc + i) >> cq->wq.log_sz) & 1);
}

#define MLX5E_MINI_ARRAY_SZ 8
static void mlx5e_decompress_cqes(struct mlx5e_cq *cq)
{
	struct mlx5_mini_cqe8 mini_array[8];
	struct mlx5_cqe64 title;
	u16 title_wqe_counter;
	int cqe_count;
	int i = 0;

	mlx5e_read_cqe_slot(cq, cq->wq.cc, &title);
	title_wqe_counter = be16_to_cpu(title.wqe_counter);
	cqe_count = be32_to_cpu(title.byte_cnt);
	mlx5e_read_cqe_slot(cq, cq->wq.cc + 1, mini_array);
	while (true) {
		mlx5e_decompress_cqe(cq, &title,
				     &mini_array[i % MLX5E_MINI_ARRAY_SZ],
				     title_wqe_counter, i);
		mlx5e_write_cqe_slot(cq, cq->wq.cc + i, &title);
		i++;
		if (i == cqe_count)
			break;
		if (i % MLX5E_MINI_ARRAY_SZ == 0)
			mlx5e_read_cqe_slot(cq, cq->wq.cc + i, mini_array);
	}
}

inline int mlx5e_alloc_rx_wqe(struct mlx5e_rq *rq,
				     struct mlx5e_rx_wqe *wqe, u16 ix)
{
	struct sk_buff *skb;
	dma_addr_t dma_addr;

	skb = netdev_alloc_skb(rq->netdev, rq->wqe_sz);
	if (unlikely(!skb))
		return -ENOMEM;

	dma_addr = dma_map_single(rq->pdev,
				  /* hw start padding */
				  skb->data,
				  /* hw end padding */
				  rq->wqe_sz,
				  DMA_FROM_DEVICE);

	if (unlikely(dma_mapping_error(rq->pdev, dma_addr)))
		goto err_free_skb;

	skb_reserve(skb, MLX5E_NET_IP_ALIGN);

	*((dma_addr_t *)skb->cb) = dma_addr;
	wqe->data.addr = cpu_to_be64(dma_addr + MLX5E_NET_IP_ALIGN);

	rq->skb[ix] = skb;

	return 0;

err_free_skb:
	dev_kfree_skb(skb);

	return -ENOMEM;
}

inline int mlx5e_alloc_striding_rx_wqe(struct mlx5e_rq *rq,
				       struct mlx5e_rx_wqe *wqe, u16 ix)
{
	struct page *page;
	dma_addr_t dma;
	int ret = 0;

	if (rq->wqe_info[ix].used_strides != rq->num_of_strides_in_wqe && rq->wqe_info[ix].page)
		return 0;

	if (rq->wqe_info[ix].page) {
		dma_unmap_page(rq->pdev, rq->wqe_info[ix].dma_addr,
			       PAGE_SIZE << rq->page_order, PCI_DMA_FROMDEVICE);
		put_page(rq->wqe_info[ix].page);
		rq->wqe_info[ix].page = NULL;
	}

	page = alloc_pages(GFP_ATOMIC | __GFP_COMP /*| __GFP_NOWARN;*/,
			   rq->page_order);
	if (unlikely(!page))
		return -ENOMEM;

	dma = dma_map_page(rq->pdev, page, 0, PAGE_SIZE << rq->page_order,
			   PCI_DMA_FROMDEVICE);
	if (dma_mapping_error(rq->pdev, dma)) {
		ret = -ENOMEM;
		goto err_put_page;
	}

	rq->wqe_info[ix].page = page;
	rq->wqe_info[ix].dma_addr = dma;
	rq->wqe_info[ix].used_strides = 0;

	wqe->data.addr = cpu_to_be64(rq->wqe_info[ix].dma_addr);

	return 0;

err_put_page:
	put_page(page);
	return ret;
}

bool mlx5e_post_rx_wqes(struct mlx5e_rq *rq)
{
	struct mlx5_wq_ll *wq = &rq->wq;

	if (unlikely(!test_bit(MLX5E_RQ_STATE_POST_WQES_ENABLE, &rq->state)))
		return false;

	while (!mlx5_wq_ll_is_full(wq)) {
		struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(wq, wq->head);
		if (unlikely(rq->alloc_wqe(rq, wqe, wq->head)))
			break;
		mlx5_wq_ll_push(wq, be16_to_cpu(wqe->next.next_wqe_index));
	}

	/* ensure wqes are visible to device before updating doorbell record */
	wmb();
	mlx5_wq_ll_update_db_record(wq);

	return !mlx5_wq_ll_is_full(wq);
}

bool is_poll_striding_wqe(struct mlx5e_rq *rq)
{
	if (rq->wqe_info[rq->current_wqe].used_strides == rq->num_of_strides_in_wqe)
		return true;
	return false;
}

static void mlx5e_lro_update_hdr(struct sk_buff *skb, struct mlx5_cqe64 *cqe)
{
	/* TODO: consider vlans, ip options, ... */
	struct ethhdr	*eth	= (struct ethhdr *)(skb->data);
	struct iphdr	*ipv4	= (struct iphdr *)(skb->data + ETH_HLEN);
	struct ipv6hdr	*ipv6	= (struct ipv6hdr *)(skb->data + ETH_HLEN);
	struct tcphdr	*tcp;

	u8 l4_hdr_type = get_cqe_l4_hdr_type(cqe);
	int tcp_ack = ((CQE_L4_HDR_TYPE_TCP_ACK_NO_DATA  == l4_hdr_type) ||
		       (CQE_L4_HDR_TYPE_TCP_ACK_AND_DATA == l4_hdr_type));

	/* TODO: consider vlan */
	u16 tot_len = be32_to_cpu(cqe->byte_cnt) - ETH_HLEN;

	if (eth->h_proto == htons(ETH_P_IP)) {
		tcp = (struct tcphdr *)(skb->data + ETH_HLEN +
					sizeof(struct iphdr));
		ipv6 = NULL;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
	} else {
		tcp = (struct tcphdr *)(skb->data + ETH_HLEN +
					sizeof(struct ipv6hdr));
		ipv4 = NULL;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
	}

	/* TODO: handle timestamp */

	if (get_cqe_lro_tcppsh(cqe))
		tcp->psh                = 1;

	if (tcp_ack) {
		tcp->ack                = 1;
		tcp->ack_seq            = cqe->lro_ack_seq_num;
		tcp->window             = cqe->lro_tcp_win;
	}

	if (ipv4) {
		ipv4->ttl               = cqe->lro_min_ttl;
		ipv4->tot_len           = cpu_to_be16(tot_len);
		ipv4->check             = 0;
		ipv4->check             = ip_fast_csum((unsigned char *)ipv4,
						       ipv4->ihl);
	} else {
		ipv6->hop_limit         = cqe->lro_min_ttl;
		ipv6->payload_len       = cpu_to_be16(tot_len -
						      sizeof(struct ipv6hdr));
	}
	/* TODO: handle tcp checksum */
}

#ifdef HAVE_NETIF_F_RXHASH
static inline void mlx5e_skb_set_hash(struct mlx5_cqe64 *cqe,
				      struct sk_buff *skb)
{
#ifdef HAVE_SKB_SET_HASH
	u8 cht = cqe->rss_hash_type;
	int ht = (cht & CQE_RSS_HTYPE_L4) ? PKT_HASH_TYPE_L4 :
		 (cht & CQE_RSS_HTYPE_IP) ? PKT_HASH_TYPE_L3 :
					    PKT_HASH_TYPE_NONE;
	skb_set_hash(skb, be32_to_cpu(cqe->rss_hash_result), ht);
#else
	skb->rxhash = be32_to_cpu(cqe->rss_hash_result);
#endif
}
#endif

static void mlx5e_validate_loopback(struct mlx5e_priv *priv,
				    struct sk_buff *skb)
{
	int i;
	int offset = 0;

	for (i = 0; i < MLX5E_LOOPBACK_TEST_PAYLOAD; i++, offset++) {
		if (*(skb->data + offset) != (unsigned char) (i & 0xff))
			goto out_loopback;
	}

	/* Loopback found */
	priv->loopback_ok = true;

out_loopback:
	dev_kfree_skb_any(skb);
}

static inline bool is_first_ethertype_ip(struct sk_buff *skb)
{
	__be16 ethertype = ((struct ethhdr *)skb->data)->h_proto;

	return (ethertype == htons(ETH_P_IP) || ethertype == htons(ETH_P_IPV6));
}

static inline void mlx5e_handle_csum(struct net_device *netdev,
				     struct mlx5_cqe64 *cqe,
				     struct mlx5e_rq *rq,
				     struct sk_buff *skb)
{
	if (unlikely(!(netdev->features & NETIF_F_RXCSUM)))
		goto csum_none;

	if (likely(cqe->hds_ip_ext & CQE_L3_OK) &&
	    likely(cqe->hds_ip_ext & CQE_L4_OK)) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		if (cqe->outer_l3_tunneled & CQE_TUNNELED) {
#if defined(HAVE_SK_BUFF_CSUM_LEVEL)
			skb->csum_level = 1;
#elif defined(HAVE_SK_BUFF_ENCAPSULATION)
			skb->encapsulation = 1;
#endif
			rq->stats.csum_inner++;
		} else
			rq->stats.csum_good++;
	} else if (is_first_ethertype_ip(skb)) {
		skb->ip_summed = CHECKSUM_COMPLETE;
		skb->csum = csum_unfold(cqe->check_sum);
		rq->stats.csum_sw++;
	} else {
		goto csum_none;
	}

	return;

csum_none:
	skb->ip_summed = CHECKSUM_NONE;
	rq->stats.csum_none++;
}

static inline void mlx5e_build_rx_skb(struct mlx5_cqe64 *cqe,
				      u32 cqe_bcnt,
				      struct mlx5e_rq *rq,
				      struct sk_buff *skb)
{
	struct net_device *netdev = rq->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int lro_num_seg;
	u32 temp;

	/* only for small packet which are linear */
	if (!skb_is_nonlinear(skb))
		skb_put(skb, cqe_bcnt);

	lro_num_seg = be32_to_cpu(cqe->srqn) >> 24;
	if (lro_num_seg > 1) {
		mlx5e_lro_update_hdr(skb, cqe);
		/* calculate the average MSS size of this LRO session */
		skb_shinfo(skb)->gso_size = DIV_ROUND_UP(cqe_bcnt, lro_num_seg);
		rq->stats.lro_packets++;
		rq->stats.lro_bytes += cqe_bcnt;
	}

	if (unlikely(MLX5E_RX_HW_STAMP(priv)))
		mlx5e_fill_hwstamp(&priv->tstamp, skb_hwtstamps(skb),
				   get_cqe_ts(cqe));

	mlx5e_handle_csum(netdev, cqe, rq, skb);

	skb->protocol = eth_type_trans(skb, netdev);

	/*Match two flow tags (24bits)
		MLX5_FS_SNIFFER_FLOW_TAG: bypass and roce
		MLX5_FS_DEFAULT_FLOW_TAG: leftovers*/
	temp = cqe->sop_drop_qpn & cpu_to_be32(MLX5_FS_FLOW_TAG_MASK);
	if (unlikely((temp != cpu_to_be32(MLX5_FS_ETH_FLOW_TAG))))
		skb->protocol = 0xFFFF;

	skb_record_rx_queue(skb, rq->ix);

#ifdef HAVE_NETIF_F_RXHASH
	if (likely(netdev->features & NETIF_F_RXHASH))
		mlx5e_skb_set_hash(cqe, skb);
#endif

	if (cqe_has_vlan(cqe))
#ifndef HAVE_3_PARAMS_FOR_VLAN_HWACCEL_PUT_TAG
		__vlan_hwaccel_put_tag(skb, be16_to_cpu(cqe->vlan_info));
#else
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       be16_to_cpu(cqe->vlan_info));
#endif
}

#define SMALL_PACKET_SIZE      (256 - NET_IP_ALIGN)
#define HEADER_COPY_SIZE       (128 - NET_IP_ALIGN)

static struct sk_buff *mlx5e_get_rx_skb(struct mlx5e_rq *rq, u16 bytes_recv,
					u16 wqe_id, u32 data_offset)
{
	struct sk_buff *skb;
	void *va;

	skb = netdev_alloc_skb(rq->netdev, SMALL_PACKET_SIZE + NET_IP_ALIGN);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, NET_IP_ALIGN);

	/* Get pointer to first fragment so we could copy the headers into the
	 * (linear part of the) skb
	 */
	va = page_address(rq->wqe_info[wqe_id].page) + data_offset;

	dma_sync_single_for_cpu(rq->pdev, rq->wqe_info[wqe_id].dma_addr,
				data_offset + bytes_recv, DMA_FROM_DEVICE);

	if (bytes_recv <= SMALL_PACKET_SIZE) {
		skb_copy_to_linear_data(skb, va, bytes_recv);
		skb->data_len = 0;
	} else {
		/* copy headers */
		skb_copy_to_linear_data(skb, va, HEADER_COPY_SIZE);
		skb_set_tail_pointer(skb, HEADER_COPY_SIZE);

		skb_frag_set_page(skb, 0, rq->wqe_info[wqe_id].page);
		skb_frag_size_set(&skb_shinfo(skb)->frags[0],
				  bytes_recv - HEADER_COPY_SIZE);

		skb_shinfo(skb)->frags[0].page_offset =
			data_offset + HEADER_COPY_SIZE;
		skb_shinfo(skb)->nr_frags = 1;
		skb->len = bytes_recv;

		skb->data_len = bytes_recv - HEADER_COPY_SIZE;
		skb->truesize = SKB_TRUESIZE(bytes_recv);
		/* take ref on the page over each skb */
		get_page(rq->wqe_info[wqe_id].page);
	}

	/* Do we realy need that? */
	dma_sync_single_for_device(rq->pdev, rq->wqe_info[wqe_id].dma_addr,
				   data_offset + bytes_recv, DMA_FROM_DEVICE);

	return skb;
}

static inline void mlx5e_receive_skb(struct mlx5e_cq *cq, struct mlx5e_rq *rq,
#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
			    struct sk_buff *skb, struct mlx5_cqe64 *prev_cqe)
#else
			    struct sk_buff *skb)
#endif
{
#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX || defined CONFIG_COMPAT_LRO_ENABLED_IPOIB
	struct net_device *netdev = rq->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
#endif

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
		if (IS_SW_LRO(priv))
#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
			if (priv->vlan_grp && cqe_has_vlan(prev_cqe))
				lro_vlan_hwaccel_receive_skb(&rq->sw_lro.lro_mgr,
							     skb,priv->vlan_grp,
							     be16_to_cpu(prev_cqe->vlan_info),
							     NULL);
			else
#endif
			lro_receive_skb(&rq->sw_lro.lro_mgr, skb, NULL);
		else
#endif

#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
		if (priv->vlan_grp && cqe_has_vlan(prev_cqe))
#ifdef HAVE_VLAN_GRO_RECEIVE
			vlan_gro_receive(cq->napi, priv->vlan_grp,
					 be16_to_cpu(prev_cqe->vlan_info),
					 skb);
#else
			vlan_hwaccel_receive_skb(skb, priv->vlan_grp,
					be16_to_cpu(prev_cqe->vlan_info));
#endif
		else
#endif
			napi_gro_receive(cq->napi, skb);
}

struct sk_buff *mlx5e_poll_striding_rx_cq(struct mlx5_cqe64 *cqe,
					  struct mlx5e_rq *rq,
					  u16 *ret_bytes_recv,
					  struct mlx5e_rx_wqe **ret_wqe,
					  __be16 *ret_wqe_id_be)
{
	struct sk_buff *skb;
	u16 wqe_id;
	__be16 wqe_id_be;
	u16 bytes_recv;
	u16 consumed_strides;
	u32 data_offset;

	wqe_id_be  = cqe->wqe_id;
	bytes_recv = cqe_get_stride_bytes_recv(cqe);
	*ret_bytes_recv = bytes_recv;
	wqe_id     = be16_to_cpu(wqe_id_be);
	consumed_strides = cqe_get_consumed_strides(cqe);
	*ret_wqe        = mlx5_wq_ll_get_wqe(&rq->wq, wqe_id);
	*ret_wqe_id_be = wqe_id_be;

	rq->current_wqe = wqe_id;

	if (MLX5E_IS_FILLER_CQE(cqe)) {
		rq->wqe_info[wqe_id].used_strides += consumed_strides;
		return NULL;
	}

	rq->wqe_info[wqe_id].used_strides += consumed_strides;

	if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
		*ret_bytes_recv = MLX5E_INDICATE_WQE_ERR;
		return NULL;
	}

	data_offset = (be16_to_cpu(cqe->wqe_counter) * rq->stride_size);
	skb = mlx5e_get_rx_skb(rq, bytes_recv, wqe_id, data_offset);
	if (unlikely(!skb))
		return NULL;

	return skb;
}

bool mlx5e_poll_rx_cq(struct mlx5e_cq *cq, int budget)
{
	struct mlx5e_rq *rq = container_of(cq, struct mlx5e_rq, cq);
	struct net_device *netdev = rq->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_cqe64 *cqe;
#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
	struct mlx5_cqe64 *prev_cqe;
#endif
	int i;

	cqe = mlx5e_get_cqe(cq);

	for (i = 0; i < budget; i++) {
		struct sk_buff *skb;
		u16 bytes_recv = 0;
		__be16 wqe_id_be;
		struct mlx5e_rx_wqe *wqe;

		if (!cqe)
			break;

		if (mlx5_get_cqe_format(cqe) == MLX5_COMPRESSED)
			mlx5e_decompress_cqes(&rq->cq);

		mlx5_cqwq_pop(&cq->wq);
		mlx5e_prefetch_cqe(cq);

		skb = rq->mlx5e_poll_specific_rx_cq(cqe, rq, &bytes_recv, &wqe, &wqe_id_be);
		if (!skb) {
			if (MLX5E_INDICATE_WQE_ERR == bytes_recv)
				rq->stats.wqe_err++;
			cqe = mlx5e_get_cqe(cq);
			goto wq_ll_pop;
		}

		mlx5e_build_rx_skb(cqe, bytes_recv, rq, skb);

		if (unlikely(priv->validate_loopback)) {
			mlx5e_validate_loopback(priv, skb);
			cqe = mlx5e_get_cqe(cq);
			goto wq_ll_pop;
		}

		rq->stats.packets++;
		rq->stats.bytes += bytes_recv;

#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
                prev_cqe = cqe;
#endif

		cqe = mlx5e_get_cqe(cq);

#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
                mlx5e_receive_skb(cq, rq, skb, prev_cqe);
#else
                mlx5e_receive_skb(cq, rq, skb);
#endif

wq_ll_pop:
		if (!rq->is_poll || (rq->is_poll && rq->is_poll(rq)))
			mlx5_wq_ll_pop(&rq->wq, wqe_id_be,
				       &wqe->next.next_wqe_index);
	}

	mlx5_cqwq_update_db_record(&cq->wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
	if (IS_SW_LRO(priv))
		lro_flush_all(&rq->sw_lro.lro_mgr);
#endif

	return (i == budget);
}

struct sk_buff *mlx5e_poll_default_rx_cq(struct mlx5_cqe64 *cqe,
					 struct mlx5e_rq *rq,
					 u16 *ret_bytes_recv,
					 struct mlx5e_rx_wqe **ret_wqe,
					 __be16 *ret_wqe_id_be)
{
	struct sk_buff *skb;
	__be16 wqe_counter_be;
	u16 wqe_counter;

	wqe_counter_be = cqe->wqe_counter;
	*ret_wqe_id_be = wqe_counter_be;
	wqe_counter    = be16_to_cpu(wqe_counter_be);
	*ret_wqe            = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
	*ret_bytes_recv = be32_to_cpu(cqe->byte_cnt);
	skb            = rq->skb[wqe_counter];
	prefetch(skb->data);
	rq->skb[wqe_counter] = NULL;

	dma_unmap_single(rq->pdev,
			 *((dma_addr_t *)skb->cb),
			 rq->wqe_sz,
			 DMA_FROM_DEVICE);

	if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
		*ret_bytes_recv = MLX5E_INDICATE_WQE_ERR;
		dev_kfree_skb(skb);
		return NULL;
	}

	return skb;
}
