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

#include <linux/list.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/mlx5/fs.h>
#include "en.h"

static int mlx5e_add_l2_flow_rule(struct mlx5e_priv *priv,
				  struct mlx5e_l2_rule *ai, int type);

static void mlx5e_del_l2_flow_rule(struct mlx5e_priv *priv,
				   struct mlx5e_l2_rule *ai);

enum {
	MLX5E_FULLMATCH = 0,
	MLX5E_ALLMULTI  = 1,
	MLX5E_PROMISC   = 2,
};

enum {
	MLX5E_UC        = 0,
	MLX5E_MC_IPV4   = 1,
	MLX5E_MC_IPV6   = 2,
	MLX5E_MC_OTHER  = 3,
};

enum {
	MLX5E_ACTION_NONE = 0,
	MLX5E_ACTION_ADD  = 1,
	MLX5E_ACTION_DEL  = 2,
};

struct mlx5e_l2_hash_node {
	struct hlist_node          hlist;
	u8                         action;
	struct mlx5e_l2_rule       ai;
};

static inline int mlx5e_hash_l2(u8 *addr)
{
	return addr[5];
}

static void mlx5e_add_l2_to_hash(struct hlist_head *hash, u8 *addr)
{
	struct mlx5e_l2_hash_node *hn;
	int ix = mlx5e_hash_l2(addr);
	int found = 0;
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
	struct hlist_node *hlnode;
#endif

	compat_hlist_for_each_entry(hn, &hash[ix], hlist)
		if (ether_addr_equal_64bits(hn->ai.addr, addr)) {
			found = 1;
			break;
		}

	if (found) {
		hn->action = MLX5E_ACTION_NONE;
		return;
	}

	hn = kzalloc(sizeof(*hn), GFP_ATOMIC);
	if (!hn)
		return;

	ether_addr_copy(hn->ai.addr, addr);
	hn->action = MLX5E_ACTION_ADD;

	hlist_add_head(&hn->hlist, &hash[ix]);
}

static void mlx5e_del_l2_from_hash(struct mlx5e_l2_hash_node *hn)
{
	hlist_del(&hn->hlist);
	kfree(hn);
}

static int mlx5e_vport_context_update_vlans(struct mlx5e_priv *priv)
{
	struct net_device *ndev = priv->netdev;
	int max_list_size;
	int list_size;
	u16 *vlans;
	int vlan;
	int err;
	int i;

	list_size = 0;
	for_each_set_bit(vlan, priv->fs.vlan.active_vlans, VLAN_N_VID)
		list_size++;

	max_list_size = 1 << MLX5_CAP_GEN(priv->mdev, log_max_vlan_list);

	if (list_size > max_list_size) {
		netdev_warn(ndev,
			    "netdev vlans list size (%d) > (%d) max vport list size, some vlans will be dropped\n",
			    list_size, max_list_size);
		list_size = max_list_size;
	}

	vlans = kcalloc(list_size, sizeof(*vlans), GFP_KERNEL);
	if (!vlans)
		return -ENOMEM;

	i = 0;
	for_each_set_bit(vlan, priv->fs.vlan.active_vlans, VLAN_N_VID) {
		if (i >= list_size)
			break;
		vlans[i++] = vlan;
	}

	err = mlx5_modify_nic_vport_vlans(priv->mdev, vlans, list_size);
	if (err)
		netdev_err(ndev, "Failed to modify vport vlans list err(%d)\n",
			   err);

	kfree(vlans);
	return err;
}

enum mlx5e_vlan_rule_type {
	MLX5E_VLAN_RULE_TYPE_UNTAGGED,
	MLX5E_VLAN_RULE_TYPE_ANY_CTAG_VID,
	MLX5E_VLAN_RULE_TYPE_ANY_STAG_VID,
	MLX5E_VLAN_RULE_TYPE_MATCH_VID,
};

static int __mlx5e_add_vlan_rule(struct mlx5e_priv *priv,
				 enum mlx5e_vlan_rule_type rule_type,
				 u16 vid, u32 *mc, u32 *mv)
{
	struct mlx5_flow_table *ft = priv->fs.vlan.ft.t;
	struct mlx5_flow_destination dest;
	u8 mc_enable = 0;
	struct mlx5_flow_rule **rule_p;
	int err = 0;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = priv->fs.l2.ft.t;

	mc_enable = MLX5_MATCH_OUTER_HEADERS;

	switch (rule_type) {
	case MLX5E_VLAN_RULE_TYPE_UNTAGGED:
		rule_p = &priv->fs.vlan.untagged_rule;
		MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.cvlan_tag);
		break;
	case MLX5E_VLAN_RULE_TYPE_ANY_CTAG_VID:
		rule_p = &priv->fs.vlan.any_cvlan_rule;
		MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.cvlan_tag);
		MLX5_SET(fte_match_param, mv, outer_headers.cvlan_tag, 1);
		break;
	case MLX5E_VLAN_RULE_TYPE_ANY_STAG_VID:
		rule_p = &priv->fs.vlan.any_svlan_rule;
		MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.svlan_tag);
		MLX5_SET(fte_match_param, mv, outer_headers.svlan_tag, 1);
		break;
	default: /* MLX5E_VLAN_RULE_TYPE_MATCH_VID */
		rule_p = &priv->fs.vlan.active_vlans_rule[vid];
		MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.cvlan_tag);
		MLX5_SET(fte_match_param, mv, outer_headers.cvlan_tag, 1);
		MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.first_vid);
		MLX5_SET(fte_match_param, mv, outer_headers.first_vid, vid);
		mlx5e_vport_context_update_vlans(priv);
		break;
	}

	*rule_p = mlx5_add_flow_rule(ft, mc_enable, mc, mv,
				     MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				     MLX5_FS_ETH_FLOW_TAG,
				     &dest);

	if (IS_ERR(*rule_p)) {
		err = PTR_ERR(*rule_p);
		*rule_p = NULL;
		netdev_err(priv->netdev, "%s: add rule failed\n", __func__);
	}

	return err;
}

static int mlx5e_add_vlan_rule(struct mlx5e_priv *priv,
			       enum mlx5e_vlan_rule_type rule_type, u16 vid)
{
	u32 *match_criteria;
	u32 *match_value;
	int err = 0;

	match_value	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto add_vlan_rule_out;
	}

	err = __mlx5e_add_vlan_rule(priv, rule_type, vid, match_criteria,
				    match_value);

add_vlan_rule_out:
	kvfree(match_criteria);
	kvfree(match_value);

	return err;
}

static void mlx5e_del_vlan_rule(struct mlx5e_priv *priv,
				enum mlx5e_vlan_rule_type rule_type, u16 vid)
{
	switch (rule_type) {
	case MLX5E_VLAN_RULE_TYPE_UNTAGGED:
		if (priv->fs.vlan.untagged_rule) {
			mlx5_del_flow_rule(priv->fs.vlan.untagged_rule);
			priv->fs.vlan.untagged_rule = NULL;
		}
		break;
	case MLX5E_VLAN_RULE_TYPE_ANY_CTAG_VID:
		if (priv->fs.vlan.any_cvlan_rule) {
			mlx5_del_flow_rule(priv->fs.vlan.any_cvlan_rule);
			priv->fs.vlan.any_cvlan_rule = NULL;
		}
		break;
	case MLX5E_VLAN_RULE_TYPE_ANY_STAG_VID:
		if (priv->fs.vlan.any_svlan_rule) {
			mlx5_del_flow_rule(priv->fs.vlan.any_svlan_rule);
			priv->fs.vlan.any_svlan_rule = NULL;
		}
		break;
	case MLX5E_VLAN_RULE_TYPE_MATCH_VID:
		if (priv->fs.vlan.active_vlans_rule[vid]) {
			mlx5_del_flow_rule(priv->fs.vlan.active_vlans_rule[vid]);
			priv->fs.vlan.active_vlans_rule[vid] = NULL;
		}
		mlx5e_vport_context_update_vlans(priv);
		break;
	}
}

void mlx5e_del_any_vid_rules(struct mlx5e_priv *priv)
{
	mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_ANY_CTAG_VID, 0);
	mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_ANY_STAG_VID, 0);
}

int mlx5e_add_any_vid_rules(struct mlx5e_priv *priv)
{
	int err;

	err = mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_ANY_CTAG_VID, 0);
	if (err)
		return err;

	return mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_ANY_STAG_VID, 0);
}

void mlx5e_enable_vlan_filter(struct mlx5e_priv *priv)
{
	WARN_ON(!mutex_is_locked(&priv->state_lock));

	if (priv->fs.vlan.filter_disabled) {
		priv->fs.vlan.filter_disabled = false;
		if (priv->netdev->flags & IFF_PROMISC)
			return;
		if (test_bit(MLX5E_STATE_OPENED, &priv->state))
			mlx5e_del_any_vid_rules(priv);
	}
}

void mlx5e_disable_vlan_filter(struct mlx5e_priv *priv)
{
	WARN_ON(!mutex_is_locked(&priv->state_lock));

	if (!priv->fs.vlan.filter_disabled) {
		priv->fs.vlan.filter_disabled = true;
		if (priv->netdev->flags & IFF_PROMISC)
			return;
		if (test_bit(MLX5E_STATE_OPENED, &priv->state))
			mlx5e_add_any_vid_rules(priv);
	}
}

#if defined(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS)
int mlx5e_vlan_rx_add_vid(struct net_device *dev, __always_unused __be16 proto,
			  u16 vid)
#elif defined(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT)
int mlx5e_vlan_rx_add_vid(struct net_device *dev, u16 vid)
#else
void mlx5e_vlan_rx_add_vid(struct net_device *dev, u16 vid)
#endif
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int err = 0;

	mutex_lock(&priv->state_lock);

	if (!test_and_set_bit(vid, priv->fs.vlan.active_vlans) &&
	    test_bit(MLX5E_STATE_OPENED, &priv->state))
		err = mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_MATCH_VID,
					  vid);
	mutex_unlock(&priv->state_lock);

#if (defined(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS) || \
     defined(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT))
	return err;
#endif
}

#if defined(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS)
int mlx5e_vlan_rx_kill_vid(struct net_device *dev, __always_unused __be16 proto,
			   u16 vid)
#elif defined(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT)
int mlx5e_vlan_rx_kill_vid(struct net_device *dev, u16 vid)
#else
void mlx5e_vlan_rx_kill_vid(struct net_device *dev, u16 vid)
#endif
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	mutex_lock(&priv->state_lock);
	clear_bit(vid, priv->fs.vlan.active_vlans);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_MATCH_VID, vid);

	mutex_unlock(&priv->state_lock);

#if (defined(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS) || \
     defined(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT))
	return 0;
#endif
}

int mlx5e_add_all_vlan_rules(struct mlx5e_priv *priv)
{
	int err;
	int i;

	for_each_set_bit(i, priv->fs.vlan.active_vlans, VLAN_N_VID) {
		err = mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_MATCH_VID,
					  i);
		if (err)
			return err;
	}

	err = mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_UNTAGGED, 0);
	if (err)
		return err;

	if (priv->fs.vlan.filter_disabled) {
		err = mlx5e_add_any_vid_rules(priv);
		if (err)
			return err;
	}

	return 0;
}

void mlx5e_del_all_vlan_rules(struct mlx5e_priv *priv)
{
	int i;

	if (priv->fs.vlan.filter_disabled)
		mlx5e_del_any_vid_rules(priv);

	mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_UNTAGGED, 0);

	for_each_set_bit(i, priv->fs.vlan.active_vlans, VLAN_N_VID)
		mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_MATCH_VID, i);
}

static struct {
	u16 etype;
	u8 proto;
} ttc_rules[] = {
	[MLX5E_TT_IPV4_TCP] = {
		.etype = ETH_P_IP,
		.proto = IPPROTO_TCP,
	},
	[MLX5E_TT_IPV6_TCP] = {
		.etype = ETH_P_IPV6,
		.proto = IPPROTO_TCP,
	},
	[MLX5E_TT_IPV4_UDP] = {
		.etype = ETH_P_IP,
		.proto = IPPROTO_UDP,
	},
	[MLX5E_TT_IPV6_UDP] = {
		.etype = ETH_P_IPV6,
		.proto = IPPROTO_UDP,
	},
	[MLX5E_TT_IPV4_IPSEC_AH] = {
		.etype = ETH_P_IP,
		.proto = IPPROTO_AH,
	},
	[MLX5E_TT_IPV6_IPSEC_AH] = {
		.etype = ETH_P_IPV6,
		.proto = IPPROTO_AH,
	},
	[MLX5E_TT_IPV4_IPSEC_ESP] = {
		.etype = ETH_P_IP,
		.proto = IPPROTO_ESP,
	},
	[MLX5E_TT_IPV6_IPSEC_ESP] = {
		.etype = ETH_P_IPV6,
		.proto = IPPROTO_ESP,
	},
	[MLX5E_TT_IPV4] = {
		.etype = ETH_P_IP,
		.proto = 0,
	},
	[MLX5E_TT_IPV6] = {
		.etype = ETH_P_IPV6,
		.proto = 0,
	},
	[MLX5E_TT_ANY] = {
		.etype = 0,
		.proto = 0,
	},
};

static int __mlx5e_add_ttc_rule(struct mlx5e_priv *priv, int tt, u32 *mc,
				u32 *mv, bool is_inner)
{
	struct mlx5e_ttc_table *ttc = is_inner ? &priv->fs.inner_ttc :
		&priv->fs.outer_ttc;
	u32 *tirn = is_inner ? priv->inner_tirn : priv->outer_tirn;
	struct mlx5_flow_table *ft = ttc->ft.t;
	u16 ethertype = ttc_rules[tt].etype;
	u16 ip_proto = ttc_rules[tt].proto;
	struct mlx5_flow_destination dest;
	struct mlx5_flow_rule **rule_p;
	u8 mc_enable = 0;
	char *headers_c;
	char *headers_v;
	int err = 0;

	headers_c = is_inner ? MLX5_ADDR_OF(fte_match_param, mc, inner_headers)
		: MLX5_ADDR_OF(fte_match_param, mc, outer_headers);
	headers_v = is_inner ? MLX5_ADDR_OF(fte_match_param, mv, inner_headers)
		: MLX5_ADDR_OF(fte_match_param, mv, outer_headers);

	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	dest.tir_num = tirn[tt];
	rule_p = &ttc->flow_rules[tt];
	if (ethertype) {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, ethertype);
		mc_enable = is_inner ? MLX5_MATCH_INNER_HEADERS :
			MLX5_MATCH_OUTER_HEADERS;
	}

	if (ip_proto) {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, ip_proto);
		mc_enable = is_inner ? MLX5_MATCH_INNER_HEADERS :
			MLX5_MATCH_OUTER_HEADERS;
	}

	*rule_p = mlx5_add_flow_rule(ft, mc_enable, mc, mv,
				     MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				     MLX5_FS_ETH_FLOW_TAG, &dest);
	if (IS_ERR_OR_NULL(*rule_p)) {
		err = PTR_ERR(*rule_p);
		*rule_p = NULL;
	}

	return err;
}

static int mlx5e_add_ttc_rule(struct mlx5e_priv *priv, int tt, bool is_inner)
{
	u32 *match_criteria;
	u32 *match_value;
	int err;

	match_value	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto add_ttc_rule_out;
	}

	err = __mlx5e_add_ttc_rule(priv, tt, match_criteria, match_value,
				   is_inner);

add_ttc_rule_out:
	kvfree(match_criteria);
	kvfree(match_value);

	return err;
}

static void mlx5e_del_ttc_rule(struct mlx5e_ttc_table *ttc_table, int tt)
{
	struct mlx5_flow_rule **rule_p;

	rule_p = &ttc_table->flow_rules[tt];

	if (*rule_p) {
		mlx5_del_flow_rule(*rule_p);
		*rule_p = NULL;
	}
}

void mlx5e_del_all_ttc_rules(struct mlx5e_priv *priv, bool is_inner)
{
	struct mlx5e_ttc_table *ttc_table =
		is_inner ? &priv->fs.inner_ttc : &priv->fs.outer_ttc;
	int i;

	if (is_inner && !mlx5e_tunnel_stateless_supported(priv->mdev))
		return;

	for (i = 0; i < MLX5E_NUM_TT; i++)
		mlx5e_del_ttc_rule(ttc_table, i);
}

int mlx5e_add_all_ttc_rules(struct mlx5e_priv *priv, bool is_inner)
{
	int err;
	int i;

	if (is_inner && !mlx5e_tunnel_stateless_supported(priv->mdev))
		return 0;

	/* Configure flow rules for all inner/outer tt's */
	for (i = 0; i < MLX5E_NUM_TT; i++) {
		err = mlx5e_add_ttc_rule(priv, i, is_inner);
		if (err) {
			mlx5e_del_all_ttc_rules(priv, is_inner);
			return err;
		}
	}

	return 0;
}

static int __mlx5e_add_tunneling_rule(struct mlx5e_priv *priv,
				      enum mlx5e_tunnel_rule_type rule_type,
				      u16 port_proto, u16 ethertype,
				      struct mlx5_flow_rule **rule_p,
				      u32 *mc, u32 *mv)
{
	struct mlx5_flow_table *ft = priv->fs.outer_ttc.ft.t;
	struct mlx5_flow_destination dest;
	u8 mc_enable = 0;
	int err = 0;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = priv->fs.inner_ttc.ft.t;

	mc_enable = MLX5_MATCH_OUTER_HEADERS;
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.ethertype);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.ip_protocol);

	switch (rule_type) {
	case MLX5E_TUNNEL_RULE_TYPE_VXLAN:
		MLX5_SET(fte_match_param, mv, outer_headers.ethertype,
			 ethertype);
		MLX5_SET(fte_match_param, mv, outer_headers.ip_protocol,
			 IPPROTO_UDP);
		MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.udp_dport);
		MLX5_SET(fte_match_param, mv, outer_headers.udp_dport,
			 port_proto);
		break;
	default:
		netdev_err(priv->netdev, "%s: invalid tunneling rule type: %d\n",
			   __func__, rule_type);
		return -EINVAL;
	}

	*rule_p = mlx5_add_flow_rule(ft, mc_enable, mc, mv,
				     MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				     MLX5_FS_ETH_FLOW_TAG,
				     &dest);

	if (IS_ERR(*rule_p)) {
		err = PTR_ERR(*rule_p);
		*rule_p = NULL;
		netdev_err(priv->netdev, "%s: add rule failed\n", __func__);
	}

	return err;
}

int mlx5e_add_tunneling_rule(struct mlx5e_priv *priv,
			     enum mlx5e_tunnel_rule_type rule_type,
			     u16 port_proto, u16 ethertype,
			     struct mlx5_flow_rule **rule_p)
{
	u32 *match_criteria;
	u32 *match_value;
	int err = 0;

	match_value	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto add_tunneling_rule_out;
	}

	err = __mlx5e_add_tunneling_rule(priv, rule_type, port_proto,
					 ethertype, rule_p, match_criteria,
					 match_value);

add_tunneling_rule_out:
	kvfree(match_criteria);
	kvfree(match_value);

	return err;
}

void mlx5e_del_tunneling_rule(struct mlx5e_priv *priv,
			      struct mlx5_flow_rule **rule_p)
{
	if (*rule_p) {
		mlx5_del_flow_rule(*rule_p);
		*rule_p = NULL;
	}
}

#define mlx5e_for_each_hash_node(hn, tmp, hash, i) \
	for (i = 0; i < MLX5E_L2_ADDR_HASH_SIZE; i++) \
		compat_hlist_for_each_entry_safe(hn, tmp, &hash[i], hlist)

static void mlx5e_execute_l2_action(struct mlx5e_priv *priv,
				    struct mlx5e_l2_hash_node *hn)
{
	switch (hn->action) {
	case MLX5E_ACTION_ADD:
		mlx5e_add_l2_flow_rule(priv, &hn->ai, MLX5E_FULLMATCH);
		hn->action = MLX5E_ACTION_NONE;
		break;

	case MLX5E_ACTION_DEL:
		mlx5e_del_l2_flow_rule(priv, &hn->ai);
		mlx5e_del_l2_from_hash(hn);
		break;
	}
}

static void mlx5e_sync_netdev_addr(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;
	struct netdev_hw_addr *ha;
#ifndef HAVE_NETDEV_FOR_EACH_MC_ADDR
	struct dev_mc_list *mclist;
#endif

	netif_addr_lock_bh(netdev);

	mlx5e_add_l2_to_hash(priv->fs.l2.netdev_uc,
				   priv->netdev->dev_addr);

	netdev_for_each_uc_addr(ha, netdev)
		mlx5e_add_l2_to_hash(priv->fs.l2.netdev_uc, ha->addr);

#ifdef HAVE_NETDEV_FOR_EACH_MC_ADDR
	netdev_for_each_mc_addr(ha, netdev)
		mlx5e_add_l2_to_hash(priv->fs.l2.netdev_mc, ha->addr);
#else
	for (mclist = netdev->mc_list; mclist; mclist = mclist->next)
		mlx5e_add_l2_to_hash(priv->fs.l2.netdev_mc,
				     mclist->dmi_addr);
#endif

	netif_addr_unlock_bh(netdev);
}

static void mlx5e_fill_addr_array(struct mlx5e_priv *priv, int list_type,
				  u8 addr_array[][ETH_ALEN], int size)
{
	bool is_uc = (list_type == MLX5_NVPRT_LIST_TYPE_UC);
	struct net_device *ndev = priv->netdev;
	struct mlx5e_l2_hash_node *hn;
	struct hlist_head *addr_list;
	struct hlist_node *tmp;
	int i = 0;
	int hi;
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
	struct hlist_node *hlnode;
#endif

	addr_list = is_uc ? priv->fs.l2.netdev_uc : priv->fs.l2.netdev_mc;

	if (is_uc) /* Make sure our own address is pushed first */
		ether_addr_copy(addr_array[i++], ndev->dev_addr);
	else if (priv->fs.l2.broadcast_enabled)
		ether_addr_copy(addr_array[i++], ndev->broadcast);

	mlx5e_for_each_hash_node(hn, tmp, addr_list, hi) {
		if (ether_addr_equal(ndev->dev_addr, hn->ai.addr))
			continue;
		if (i >= size)
			break;
		ether_addr_copy(addr_array[i++], hn->ai.addr);
	}
}

static void mlx5e_vport_context_update_addr_list(struct mlx5e_priv *priv,
						 int list_type)
{
	bool is_uc = (list_type == MLX5_NVPRT_LIST_TYPE_UC);
	struct mlx5e_l2_hash_node *hn;
	u8 (*addr_array)[ETH_ALEN] = NULL;
	struct hlist_head *addr_list;
	struct hlist_node *tmp;
	int max_size;
	int size;
	int err;
	int hi;
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
	struct hlist_node *hlnode;
#endif

	size = is_uc ? 0 : (priv->fs.l2.broadcast_enabled ? 1 : 0);
	max_size = is_uc ?
		1 << MLX5_CAP_GEN(priv->mdev, log_max_current_uc_list) :
		1 << MLX5_CAP_GEN(priv->mdev, log_max_current_mc_list);

	addr_list = is_uc ? priv->fs.l2.netdev_uc : priv->fs.l2.netdev_mc;
	mlx5e_for_each_hash_node(hn, tmp, addr_list, hi)
		size++;

	if (size > max_size) {
		netdev_warn(priv->netdev,
			    "netdev %s list size (%d) > (%d) max vport list size, some addresses will be dropped\n",
			    is_uc ? "UC" : "MC", size, max_size);
		size = max_size;
	}

	if (size) {
		addr_array = kcalloc(size, ETH_ALEN, GFP_KERNEL);
		if (!addr_array) {
			err = -ENOMEM;
			goto out;
		}
		mlx5e_fill_addr_array(priv, list_type, addr_array, size);
	}

	err = mlx5_modify_nic_vport_mac_list(priv->mdev, list_type, addr_array, size);
out:
	if (err)
		netdev_err(priv->netdev,
			   "Failed to modify vport %s list err(%d)\n",
			   is_uc ? "UC" : "MC", err);
	kfree(addr_array);
}

static void mlx5e_vport_context_update(struct mlx5e_priv *priv)
{
	struct mlx5e_l2_table *l2_table = &priv->fs.l2;

	mlx5e_vport_context_update_addr_list(priv, MLX5_NVPRT_LIST_TYPE_UC);
	mlx5e_vport_context_update_addr_list(priv, MLX5_NVPRT_LIST_TYPE_MC);
	mlx5_modify_nic_vport_promisc(priv->mdev, 0,
				      l2_table->allmulti_enabled,
				      l2_table->promisc_enabled);
}

static void mlx5e_apply_netdev_addr(struct mlx5e_priv *priv)
{
	struct mlx5e_l2_hash_node *hn;
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
	struct hlist_node *hlnode;
#endif
	struct hlist_node *tmp;
	int i;

	mlx5e_for_each_hash_node(hn, tmp, priv->fs.l2.netdev_uc, i)
		mlx5e_execute_l2_action(priv, hn);

	mlx5e_for_each_hash_node(hn, tmp, priv->fs.l2.netdev_mc, i)
		mlx5e_execute_l2_action(priv, hn);
}

static void mlx5e_handle_netdev_addr(struct mlx5e_priv *priv)
{
	struct mlx5e_l2_hash_node *hn;
#ifndef HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS
	struct hlist_node *hlnode;
#endif
	struct hlist_node *tmp;
	int i;

	mlx5e_for_each_hash_node(hn, tmp, priv->fs.l2.netdev_uc, i)
		hn->action = MLX5E_ACTION_DEL;
	mlx5e_for_each_hash_node(hn, tmp, priv->fs.l2.netdev_mc, i)
		hn->action = MLX5E_ACTION_DEL;

	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_sync_netdev_addr(priv);

	mlx5e_apply_netdev_addr(priv);
}

void mlx5e_set_rx_mode_core(struct mlx5e_priv *priv)
{
	struct mlx5e_l2_table *l2_table = &priv->fs.l2;
	struct net_device *ndev = priv->netdev;

	bool rx_mode_enable   = test_bit(MLX5E_STATE_OPENED, &priv->state);
	bool promisc_enabled   = rx_mode_enable && (ndev->flags & IFF_PROMISC);
	bool allmulti_enabled  = rx_mode_enable && (ndev->flags & IFF_ALLMULTI);
	bool broadcast_enabled = rx_mode_enable;

	bool enable_promisc    = !l2_table->promisc_enabled   &&  promisc_enabled;
	bool disable_promisc   =  l2_table->promisc_enabled   && !promisc_enabled;
	bool enable_allmulti   = !l2_table->allmulti_enabled  &&  allmulti_enabled;
	bool disable_allmulti  =  l2_table->allmulti_enabled  && !allmulti_enabled;
	bool enable_broadcast  = !l2_table->broadcast_enabled &&  broadcast_enabled;
	bool disable_broadcast =  l2_table->broadcast_enabled && !broadcast_enabled;

	if (enable_promisc) {
		mlx5e_add_l2_flow_rule(priv, &l2_table->promisc, MLX5E_PROMISC);
		if (!priv->fs.vlan.filter_disabled)
			mlx5e_add_any_vid_rules(priv);
	}
	if (enable_allmulti)
		mlx5e_add_l2_flow_rule(priv, &l2_table->allmulti, MLX5E_ALLMULTI);
	if (enable_broadcast)
		mlx5e_add_l2_flow_rule(priv, &l2_table->broadcast, MLX5E_FULLMATCH);

	mlx5e_handle_netdev_addr(priv);

	if (disable_broadcast)
		mlx5e_del_l2_flow_rule(priv, &l2_table->broadcast);
	if (disable_allmulti)
		mlx5e_del_l2_flow_rule(priv, &l2_table->allmulti);
	if (disable_promisc) {
		if (!priv->fs.vlan.filter_disabled)
			mlx5e_del_any_vid_rules(priv);
		mlx5e_del_l2_flow_rule(priv, &l2_table->promisc);
	}

	l2_table->promisc_enabled   = promisc_enabled;
	l2_table->allmulti_enabled  = allmulti_enabled;
	l2_table->broadcast_enabled = broadcast_enabled;

	mlx5e_vport_context_update(priv);
}

void mlx5e_set_rx_mode_work(struct work_struct *work)
{
	struct mlx5e_priv *priv = container_of(work, struct mlx5e_priv,
					       set_rx_mode_work);

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_set_rx_mode_core(priv);
	mutex_unlock(&priv->state_lock);
}

void mlx5e_init_eth_addr(struct mlx5e_priv *priv)
{
	ether_addr_copy(priv->fs.l2.broadcast.addr, priv->netdev->broadcast);
}

static void mlx5e_destroy_groups(struct mlx5e_flow_table *ft)
{
	int i;

	for (i = ft->num_groups - 1; i >= 0; i--) {
		if (!IS_ERR_OR_NULL(ft->g[i]))
			mlx5_destroy_flow_group(ft->g[i]);
		ft->g[i] = NULL;
	}
	ft->num_groups = 0;
}

void mlx5e_destroy_flow_table(struct mlx5e_flow_table *ft)
{
	mlx5e_destroy_groups(ft);
	kfree(ft->g);
	mlx5_destroy_flow_table(ft->t);
	ft->t = NULL;
}

#define MLX5E_NUM_TTC_GROUPS	4
#define MLX5E_TTC_GROUP0_SIZE	BIT(4)
#define MLX5E_TTC_GROUP1_SIZE	BIT(3)
#define MLX5E_TTC_GROUP2_SIZE	BIT(1)
#define MLX5E_TTC_GROUP3_SIZE	BIT(0)
#define MLX5E_TTC_TABLE_SIZE	(MLX5E_TTC_GROUP0_SIZE +\
				 MLX5E_TTC_GROUP1_SIZE +\
				 MLX5E_TTC_GROUP2_SIZE +\
				 MLX5E_TTC_GROUP3_SIZE)

static int __mlx5e_create_ttc_groups(struct mlx5e_flow_table *ft, u32 *in,
				     int inlen, bool is_inner)
{
	u8 *mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
	int mc_enable = is_inner ? MLX5_MATCH_INNER_HEADERS :
		MLX5_MATCH_OUTER_HEADERS;
	void *headers_c = is_inner ? MLX5_ADDR_OF(fte_match_param, mc, inner_headers)
		: MLX5_ADDR_OF(fte_match_param, mc, outer_headers);
	int err;
	int ix = 0;

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, match_criteria_enable, mc_enable);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_dport);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_TTC_GROUP0_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destory_groups;
	ft->num_groups++;

	MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_dport, 0);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_TTC_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destory_groups;
	ft->num_groups++;

	MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_protocol, 0);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_TTC_GROUP2_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destory_groups;
	ft->num_groups++;

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_TTC_GROUP3_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destory_groups;
	ft->num_groups++;

	return 0;

err_destory_groups:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
	mlx5e_destroy_groups(ft);

	return err;
}

static int mlx5e_create_ttc_groups(struct mlx5e_flow_table *ft, bool is_inner)
{
	u32 *in;
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	int err;

	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	err = __mlx5e_create_ttc_groups(ft, in, inlen, is_inner);

	kvfree(in);
	return err;
}

static int mlx5e_init_inner_ttc_table(struct mlx5e_priv *priv)
{
	return mlx5e_add_all_ttc_rules(priv, true);
}

static int mlx5e_init_outer_ttc_table(struct mlx5e_priv *priv)
{
	return mlx5e_add_all_ttc_rules(priv, false);
}

static int mlx5e_create_ttc_table(struct mlx5e_priv *priv, bool is_inner)
{
	struct mlx5e_flow_table *ft = is_inner ? &priv->fs.inner_ttc.ft :
		&priv->fs.outer_ttc.ft;
	int err;

	ft->num_groups = 0;
	ft->t = mlx5_create_flow_table(priv->fs.ns, 0,
				       is_inner ? "inner_ttc" : "outer_ttc",
				       MLX5E_TTC_TABLE_SIZE,
				       is_inner ? MLX5E_INNER_TTC_FT_LEVEL :
				       MLX5E_OUTER_TTC_FT_LEVEL);
	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}
	ft->g = kcalloc(MLX5E_NUM_TTC_GROUPS, sizeof(*ft->g),
			GFP_KERNEL);
	if (!ft->g) {
		err = -ENOMEM;
		goto err_destroy_ttc_table;
	}

	err = mlx5e_create_ttc_groups(ft, is_inner);
	if (err)
		goto err_free_g;

	return 0;

err_free_g:
	kfree(ft->g);
err_destroy_ttc_table:
	mlx5_destroy_flow_table(ft->t);
	ft->t = NULL;

	return err;
}

static int mlx5e_create_inner_ttc_table(struct mlx5e_priv *priv)
{
	return mlx5e_create_ttc_table(priv, true);
}

static int mlx5e_create_outer_ttc_table(struct mlx5e_priv *priv)
{
	return mlx5e_create_ttc_table(priv, false);
}

static void mlx5e_destroy_ttc_table(struct mlx5e_priv *priv, bool is_inner)
{
	struct mlx5e_ttc_table *ttc = is_inner ? &priv->fs.inner_ttc :
		&priv->fs.outer_ttc;

	mlx5e_destroy_flow_table(&ttc->ft);
}

static void mlx5e_shutdown_inner_ttc_table(struct mlx5e_priv *priv)
{
	mlx5e_del_all_ttc_rules(priv, true);
}

static void mlx5e_destroy_inner_ttc_table(struct mlx5e_priv *priv)
{
	mlx5e_destroy_ttc_table(priv, true);
}

static void mlx5e_shutdown_outer_ttc_table(struct mlx5e_priv *priv)
{
	mlx5e_del_all_ttc_rules(priv, false);
}

static void mlx5e_destroy_outer_ttc_table(struct mlx5e_priv *priv)
{
	mlx5e_destroy_ttc_table(priv, false);
}

static void mlx5e_del_l2_flow_rule(struct mlx5e_priv *priv,
				   struct mlx5e_l2_rule *ai)
{
	if (!IS_ERR_OR_NULL(ai->rule)) {
		mlx5_del_flow_rule(ai->rule);
		ai->rule = NULL;
	}
}

static int mlx5e_add_l2_flow_rule(struct mlx5e_priv *priv,
				  struct mlx5e_l2_rule *ai, int type)
{
	struct mlx5_flow_table *ft = priv->fs.l2.ft.t;
	struct mlx5_flow_destination dest;
	u8 match_criteria_enable = 0;
	u32 *match_criteria;
	u32 *match_value;
	int err = 0;
	u8 *mc_dmac;
	u8 *mv_dmac;

	match_value    = mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria = mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto add_l2_rule_out;
	}

	mc_dmac = MLX5_ADDR_OF(fte_match_param, match_criteria,
			       outer_headers.dmac_47_16);
	mv_dmac = MLX5_ADDR_OF(fte_match_param, match_value,
			       outer_headers.dmac_47_16);

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = priv->fs.outer_ttc.ft.t;

	switch (type) {
	case MLX5E_FULLMATCH:
		match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
		eth_broadcast_addr(mc_dmac);
		ether_addr_copy(mv_dmac, ai->addr);
		break;

	case MLX5E_ALLMULTI:
		match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
		mc_dmac[0] = 0x01;
		mv_dmac[0] = 0x01;
		break;

	case MLX5E_PROMISC:
		break;
	}

	ai->rule = mlx5_add_flow_rule(ft, match_criteria_enable, match_criteria,
				      match_value,
				      MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				      MLX5_FS_DEFAULT_FLOW_TAG, &dest);
	if (IS_ERR(ai->rule)) {
		netdev_err(priv->netdev, "%s: add l2 rule(mac:%pM) failed\n",
			   __func__, mv_dmac);
		err = PTR_ERR(ai->rule);
		ai->rule = NULL;
	}

add_l2_rule_out:
	kvfree(match_criteria);
	kvfree(match_value);

	return err;
}

#define MLX5E_NUM_L2_GROUPS	   3
#define MLX5E_L2_GROUP1_SIZE	   BIT(0)
#define MLX5E_L2_GROUP2_SIZE	   BIT(15)
#define MLX5E_L2_GROUP3_SIZE	   BIT(0)
#define MLX5E_L2_TABLE_SIZE	   (MLX5E_L2_GROUP1_SIZE +\
				    MLX5E_L2_GROUP2_SIZE +\
				    MLX5E_L2_GROUP3_SIZE)
static int mlx5e_create_l2_table_groups(struct mlx5e_l2_table *l2_table)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5e_flow_table *ft = &l2_table->ft;
	int ix = 0;
	u8 *mc_dmac;
	u32 *in;
	int err;
	u8 *mc;

	ft->g = kcalloc(MLX5E_NUM_L2_GROUPS, sizeof(*ft->g), GFP_KERNEL);
	if (!ft->g)
		return -ENOMEM;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		kfree(ft->g);
		return -ENOMEM;
	}

	mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
	mc_dmac = MLX5_ADDR_OF(fte_match_param, mc,
			       outer_headers.dmac_47_16);
	/* Flow Group for promiscuous */
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_L2_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	/* Flow Group for full match */
	eth_broadcast_addr(mc_dmac);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_L2_GROUP2_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	/* Flow Group for allmulti */
	eth_zero_addr(mc_dmac);
	mc_dmac[0] = 0x01;
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_L2_GROUP3_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	kvfree(in);
	return 0;

err_destroy_groups:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
	mlx5e_destroy_groups(ft);
	kvfree(in);

	return err;
}

static void mlx5e_destroy_l2_table(struct mlx5e_priv *priv)
{
	mlx5e_destroy_flow_table(&priv->fs.l2.ft);
}

static int mlx5e_create_l2_table(struct mlx5e_priv *priv)
{
	struct mlx5e_l2_table *l2_table = &priv->fs.l2;
	struct mlx5e_flow_table *ft = &l2_table->ft;
	int err;

	ft->num_groups = 0;
	ft->t = mlx5_create_flow_table(priv->fs.ns, 0, "l2",
				       MLX5E_L2_TABLE_SIZE, MLX5E_L2_FT_LEVEL);

	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}

	err = mlx5e_create_l2_table_groups(l2_table);
	if (err)
		goto err_destroy_flow_table;


	return 0;


err_destroy_flow_table:
	mlx5e_destroy_flow_table(ft);

	return err;
}

#define MLX5E_NUM_VLAN_GROUPS	3
#define MLX5E_VLAN_GROUP0_SIZE	BIT(12)
#define MLX5E_VLAN_GROUP1_SIZE	BIT(1)
#define MLX5E_VLAN_GROUP2_SIZE	BIT(0)
#define MLX5E_VLAN_TABLE_SIZE	(MLX5E_VLAN_GROUP0_SIZE +\
				 MLX5E_VLAN_GROUP1_SIZE +\
				 MLX5E_VLAN_GROUP2_SIZE)

static int __mlx5e_create_vlan_table_groups(struct mlx5e_flow_table *ft, u32 *in,
					    int inlen)
{
	int err;
	int ix = 0;
	u8 *mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.first_vid);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_VLAN_GROUP0_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.cvlan_tag);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_VLAN_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.svlan_tag);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_VLAN_GROUP2_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	return 0;

err_destroy_groups:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
	mlx5e_destroy_groups(ft);

	return err;
}

static int mlx5e_create_vlan_table_groups(struct mlx5e_flow_table *ft)
{
	u32 *in;
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	int err;

	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	err = __mlx5e_create_vlan_table_groups(ft, in, inlen);

	kvfree(in);
	return err;
}

static int mlx5e_init_vlan_table(struct mlx5e_priv *priv)
{
	return mlx5e_add_all_vlan_rules(priv);
}

static int mlx5e_create_vlan_table(struct mlx5e_priv *priv)
{
	struct mlx5e_flow_table *ft = &priv->fs.vlan.ft;
	int err;

	ft->num_groups = 0;
	ft->t = mlx5_create_flow_table(priv->fs.ns, 0, "vlan",
				       MLX5E_VLAN_TABLE_SIZE,
				       MLX5E_VLAN_FT_LEVEL);
	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}
	ft->g = kcalloc(MLX5E_NUM_VLAN_GROUPS, sizeof(*ft->g), GFP_KERNEL);
	if (!ft->g) {
		err = -ENOMEM;
		goto err_destroy_vlan_table;
	}

	err = mlx5e_create_vlan_table_groups(ft);
	if (err)
		goto err_free_g;

	return 0;

err_free_g:
	kfree(ft->g);

err_destroy_vlan_table:
	mlx5_destroy_flow_table(ft->t);
	ft->t = NULL;

	return err;
}

static void mlx5e_shutdown_vlan_table(struct mlx5e_priv *priv)
{
	mlx5e_del_all_vlan_rules(priv);
}

static void mlx5e_destroy_vlan_table(struct mlx5e_priv *priv)
{
	mlx5e_destroy_flow_table(&priv->fs.vlan.ft);
}

static int mlx5e_init_flow_tables(struct mlx5e_priv *priv)
{
	int err;

	err = mlx5e_arfs_init_tables(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to init arfs tables, err=%d\n",
			   err);
#ifdef HAVE_NETDEV_HW_FEATURES
		priv->netdev->hw_features &= ~NETIF_F_NTUPLE;
#endif
	}

	err = mlx5e_init_inner_ttc_table(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to init inner ttc table, err=%d\n",
			   err);
		goto err_shutdown_arfs_tables;
	}

	err = mlx5e_init_outer_ttc_table(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to init outer ttc table, err=%d\n",
			   err);
		goto err_shutdown_inner_ttc_table;
	}

	err = mlx5e_init_vlan_table(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to init vlan table, err=%d\n",
			   err);
		goto err_shutdown_outer_ttc_table;
	}

	return 0;

err_shutdown_outer_ttc_table:
	mlx5e_shutdown_outer_ttc_table(priv);
err_shutdown_inner_ttc_table:
	mlx5e_shutdown_inner_ttc_table(priv);
err_shutdown_arfs_tables:
	mlx5e_arfs_shutdown_tables(priv);

	return err;
}

static int mlx5e_create_flow_tables(struct mlx5e_priv *priv)
{
	int err;

	priv->fs.ns = mlx5_get_flow_namespace(priv->mdev,
					       MLX5_FLOW_NAMESPACE_KERNEL);
	if (!priv->fs.ns)
		return -EINVAL;

	err = mlx5e_arfs_create_tables(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to create arfs tables, err=%d\n",
			   err);
#ifdef HAVE_NETDEV_HW_FEATURES
		priv->netdev->hw_features &= ~NETIF_F_NTUPLE;
#endif
	}

	err = mlx5e_create_inner_ttc_table(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to create inner ttc table, err=%d\n",
			   err);
		goto err_destroy_arfs_tables;
	}

	err = mlx5e_create_outer_ttc_table(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to create outer ttc table, err=%d\n",
			   err);
		goto err_destroy_inner_ttc_table;
	}

	err = mlx5e_create_l2_table(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to create l2 table, err=%d\n",
			   err);
		goto err_destroy_outer_ttc_table;
	}

	err = mlx5e_create_vlan_table(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to create vlan table, err=%d\n",
			   err);
		goto err_destroy_l2_table;
	}

	return 0;

err_destroy_l2_table:
	mlx5e_destroy_l2_table(priv);
err_destroy_outer_ttc_table:
	mlx5e_destroy_outer_ttc_table(priv);
err_destroy_inner_ttc_table:
	mlx5e_destroy_inner_ttc_table(priv);
err_destroy_arfs_tables:
	mlx5e_arfs_destroy_tables(priv);

	return err;
}

void mlx5e_shutdown_flow_tables(struct mlx5e_priv *priv)
{
	mlx5e_shutdown_vlan_table(priv);
	mlx5e_shutdown_outer_ttc_table(priv);
	mlx5e_shutdown_inner_ttc_table(priv);
	mlx5e_arfs_shutdown_tables(priv);
}

static void mlx5e_destroy_flow_tables(struct mlx5e_priv *priv)
{
	mlx5e_destroy_vlan_table(priv);
	mlx5e_destroy_l2_table(priv);
	mlx5e_destroy_outer_ttc_table(priv);
	mlx5e_destroy_inner_ttc_table(priv);
	mlx5e_arfs_destroy_tables(priv);
}

int mlx5e_create_flow_steering(struct mlx5e_priv *priv)
{
	int err;

	err = mlx5e_create_flow_tables(priv);
	if (err) {
		netdev_err(priv->netdev, "Failed to create mlx5e flow tables, err=%d\n",
			   err);
		return err;
	}

	err = mlx5e_init_flow_tables(priv);
	if (err) {
		netdev_err(priv->netdev, "Init mlx5e low tables failed, err=%d\n",
			   err);
		mlx5e_destroy_flow_tables(priv);
	}

	return err;
}

void mlx5e_destroy_flow_steering(struct mlx5e_priv *priv)
{
	mlx5e_shutdown_flow_tables(priv);
	mlx5e_destroy_flow_tables(priv);
}

