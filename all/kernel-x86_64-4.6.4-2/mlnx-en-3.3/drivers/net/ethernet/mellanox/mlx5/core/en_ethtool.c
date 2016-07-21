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

#include "en.h"

static const char mlx5e_test_names[][ETH_GSTRING_LEN] = {
	"Speed Test",
	"Link Test",
	"Health Test",
	"Loopback Test",
	"Interrupt Test",
};

static void mlx5e_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	strlcpy(drvinfo->driver, DRIVER_NAME, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, DRIVER_VERSION " (" DRIVER_RELDATE ")",
		sizeof(drvinfo->version));
	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		 "%d.%d.%04d",
		 fw_rev_maj(mdev), fw_rev_min(mdev), fw_rev_sub(mdev));
	strlcpy(drvinfo->bus_info, pci_name(mdev->pdev),
		sizeof(drvinfo->bus_info));
}

static const struct {
	u32 supported;
	u32 advertised;
	u32 speed;
} ptys2ethtool_table[MLX5_LINK_MODES_NUMBER] = {
	[MLX5_1000BASE_CX_SGMII] = {
		.supported  = SUPPORTED_1000baseKX_Full,
		.advertised = ADVERTISED_1000baseKX_Full,
		.speed      = SPEED_1000,
	},
	[MLX5_1000BASE_KX] = {
		.supported  = SUPPORTED_1000baseKX_Full,
		.advertised = ADVERTISED_1000baseKX_Full,
		.speed      = SPEED_1000,
	},
	[MLX5_10GBASE_CX4] = {
		.supported  = SUPPORTED_10000baseKX4_Full,
		.advertised = ADVERTISED_10000baseKX4_Full,
		.speed      = SPEED_10000,
	},
	[MLX5_10GBASE_KX4] = {
		.supported  = SUPPORTED_10000baseKX4_Full,
		.advertised = ADVERTISED_10000baseKX4_Full,
		.speed      = SPEED_10000,
	},
	[MLX5_10GBASE_KR] = {
		.supported  = SUPPORTED_10000baseKR_Full,
		.advertised = ADVERTISED_10000baseKR_Full,
		.speed      = SPEED_10000,
	},
	[MLX5_20GBASE_KR2] = {
		.supported  = SUPPORTED_20000baseKR2_Full,
		.advertised = ADVERTISED_20000baseKR2_Full,
		.speed      = SPEED_20000,
	},
	[MLX5_40GBASE_CR4] = {
		.supported  = SUPPORTED_40000baseCR4_Full,
		.advertised = ADVERTISED_40000baseCR4_Full,
		.speed      = SPEED_40000,
	},
	[MLX5_40GBASE_KR4] = {
		.supported  = SUPPORTED_40000baseKR4_Full,
		.advertised = ADVERTISED_40000baseKR4_Full,
		.speed      = SPEED_40000,
	},
	[MLX5_56GBASE_R4] = {
		.supported  = SUPPORTED_56000baseKR4_Full,
		.advertised = ADVERTISED_56000baseKR4_Full,
		.speed      = SPEED_56000,
	},
	[MLX5_10GBASE_CR] = {
		.supported  = SUPPORTED_10000baseKR_Full,
		.advertised = ADVERTISED_10000baseKR_Full,
		.speed      = SPEED_10000,
	},
	[MLX5_10GBASE_SR] = {
		.supported  = SUPPORTED_10000baseKR_Full,
		.advertised = ADVERTISED_10000baseKR_Full,
		.speed      = SPEED_10000,
	},
	[MLX5_10GBASE_ER] = {
		.supported  = SUPPORTED_10000baseKR_Full,/* TODO: verify */
		.advertised = ADVERTISED_10000baseKR_Full,
		.speed      = SPEED_10000,
	},
	[MLX5_40GBASE_SR4] = {
		.supported  = SUPPORTED_40000baseSR4_Full,
		.advertised = ADVERTISED_40000baseSR4_Full,
		.speed      = SPEED_40000,
	},
	[MLX5_40GBASE_LR4] = {
		.supported  = SUPPORTED_40000baseLR4_Full,
		.advertised = ADVERTISED_40000baseLR4_Full,
		.speed      = SPEED_40000,
	},
	[MLX5_100GBASE_CR4] = {
		.supported  = /*SUPPORTED_100000baseCR4_Full*/ 0,
		.advertised = /*ADVERTISED_100000baseCR4_Full*/ 0,
		.speed      = SPEED_100000,
	},
	[MLX5_100GBASE_SR4] = {
		.supported  = /*SUPPORTED_100000baseSR4_Full*/ 0,
		.advertised = /*ADVERTISED_100000baseSR4_Full*/ 0,
		.speed      = SPEED_100000,
	},
	[MLX5_100GBASE_KR4] = {
		.supported  = /*SUPPORTED_100000baseKR4_Full*/ 0,
		.advertised = /*ADVERTISED_100000baseKR4_Full*/ 0,
		.speed      = SPEED_100000,
	},
	[MLX5_100GBASE_LR4] = {
		.supported  = /*SUPPORTED_1000000baseLR4_Full*/ 0,
		.advertised = /*ADVERTISED_1000000baseLR4_Full*/ 0,
		.speed      = SPEED_100000,
	},
	[MLX5_100BASE_TX]   = {
		.supported  = SUPPORTED_100baseT_Full,
		.advertised = ADVERTISED_100baseT_Full,
		.speed      = SPEED_100,
	},
	[MLX5_1000BASE_T]    = {
		.supported  = SUPPORTED_1000baseT_Full,
		.advertised = ADVERTISED_1000baseT_Full,
		.speed      = SPEED_1000,
	},
	[MLX5_10GBASE_T]    = {
		.supported  = SUPPORTED_10000baseT_Full,
		.advertised = ADVERTISED_10000baseT_Full,
		.speed      = SPEED_10000,
	},
	[MLX5_25GBASE_CR]   = {
		.supported  = /*SUPPORTED_25000baseCR_Full*/ 0,
		.advertised = /*ADVERTISED_25000baseCR_Full*/ 0,
		.speed      = SPEED_25000,
	},
	[MLX5_25GBASE_KR]   = {
		.supported  = /*SUPPORTED_25000baseKR_Full*/ 0,
		.advertised = /*ADVERTISED_25000baseKR_Full*/ 0,
		.speed      = SPEED_25000,
	},
	[MLX5_25GBASE_SR]   = {
		.supported  = /*SUPPORTED_25000baseSR_Full*/ 0,
		.advertised = /*ADVERTISED_25000baseSR_Full*/ 0,
		.speed      = SPEED_25000,
	},
	[MLX5_50GBASE_CR2]  = {
		.supported  = /*SUPPORTED_50000baseCR2_Full*/ 0,
		.advertised = /*ADVERTISED_50000baseCR2_Full*/ 0,
		.speed      = SPEED_50000,
	},
	[MLX5_50GBASE_KR2]  = {
		.supported  = /*SUPPORTED_50000baseKR2_Full*/ 0,
		.advertised = /*ADVERTISED_50000baseKR2_Full*/ 0,
		.speed      = SPEED_50000,
	},
};

static unsigned long mlx5e_query_pfc_combined(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u8 pfc_en_tx;
	u8 pfc_en_rx;
	int err;

	err = mlx5_query_port_pfc(mdev, &pfc_en_tx, &pfc_en_rx);

	return err ? 0 : pfc_en_tx | pfc_en_rx;
}

#define MLX5E_NUM_RQ_STATS(priv) \
	(NUM_RQ_STATS * priv->params.num_channels * \
	 test_bit(MLX5E_STATE_OPENED, &priv->state))
#define MLX5E_NUM_SQ_STATS(priv) \
	(NUM_SQ_STATS * (priv->params.num_channels * priv->params.num_tc + \
	 priv->params.num_rl_txqs) * test_bit(MLX5E_STATE_OPENED, &priv->state))
#define MLX5E_NUM_PFC_COUNTERS(priv) hweight8(mlx5e_query_pfc_combined(priv))

static int mlx5e_get_sset_count(struct net_device *dev, int sset)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return NUM_VPORT_COUNTERS + NUM_PPORT_COUNTERS +
		       MLX5E_NUM_RQ_STATS(priv) +
		       MLX5E_NUM_SQ_STATS(priv) +
		       NUM_Q_COUNTERS + NUM_SW_COUNTERS +
		       MLX5E_NUM_PFC_COUNTERS(priv);
	case ETH_SS_TEST:
		return MLX5E_NUM_SELF_TEST;
#ifdef HAVE_GET_SET_PRIV_FLAGS
	case ETH_SS_PRIV_FLAGS:
		return ARRAY_SIZE(mlx5e_priv_flags);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

static void mlx5e_fill_stats_strings(struct mlx5e_priv *priv, uint8_t *data)
{
	int i, j, tc, prio, idx = 0;
	unsigned long pfc_combined;

	/* SW counters */
	for (i = 0; i < NUM_SW_COUNTERS; i++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN, sw_stats_desc[i].name);

	/* Q counters */
	for (i = 0; i < NUM_Q_COUNTERS; i++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN, q_stats_desc[i].name);

	/* VPORT counters */
	for (i = 0; i < NUM_VPORT_COUNTERS; i++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN,
		       vport_stats_desc[i].name);

	/* PPORT counters */
	for (i = 0; i < NUM_PPORT_802_3_COUNTERS; i++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN,
		       pport_802_3_stats_desc[i].name);

	for (i = 0; i < NUM_PPORT_2863_COUNTERS; i++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN,
		       pport_2863_stats_desc[i].name);

	for (i = 0; i < NUM_PPORT_2819_COUNTERS; i++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN,
		       pport_2819_stats_desc[i].name);

	for (i = 0; i < NUM_PPORT_PHY_COUNTERS; i++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN,
		       pport_phy_stats_desc[i].name);

	for (prio = 0; prio < NUM_PPORT_PRIO; prio++) {
		for (i = 0; i < NUM_PPORT_PER_PRIO_TRAFFIC_COUNTERS; i++)
			sprintf(data + (idx++) * ETH_GSTRING_LEN, "prio%d_%s",
				prio,
				pport_per_prio_traffic_stats_desc[i].name);
	}

	pfc_combined = mlx5e_query_pfc_combined(priv);
	for_each_set_bit(prio, &pfc_combined, NUM_PPORT_PRIO) {
		for (i = 0; i < NUM_PPORT_PER_PRIO_PFC_COUNTERS; i++) {
			sprintf(data + (idx++) * ETH_GSTRING_LEN, "prio%d_%s",
				prio, pport_per_prio_pfc_stats_desc[i].name);
		}
	}

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		return;

	/* per channel counters */
	for (i = 0; i < priv->params.num_channels; i++)
		for (j = 0; j < NUM_RQ_STATS; j++)
			sprintf(data + (idx++) * ETH_GSTRING_LEN, "rx%d_%s", i,
				rq_stats_desc[j].name);

	for (tc = 0; tc < priv->params.num_tc; tc++)
		for (i = 0; i < priv->params.num_channels; i++)
			for (j = 0; j < NUM_SQ_STATS; j++)
				sprintf(data + (idx++) * ETH_GSTRING_LEN,
					"tx%d_%s",
					priv->tc_to_txq_map[i][tc],
					sq_stats_desc[j].name);

	/* Special TX queue counters */
	for (i = 0; i < priv->params.num_rl_txqs; i++)
		for (j = 0; j < NUM_SQ_STATS; j++)
			sprintf(data + (idx++) * ETH_GSTRING_LEN,
				"tx%d_%s",
				i + priv->params.num_channels * priv->params.num_tc,
				sq_stats_desc[j].name);
}

static void mlx5e_get_strings(struct net_device *dev,
			      uint32_t stringset, uint8_t *data)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int i;

	switch (stringset) {
#ifdef HAVE_GET_SET_PRIV_FLAGS
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < ARRAY_SIZE(mlx5e_priv_flags); i++)
			strcpy(data + i * ETH_GSTRING_LEN,
			       mlx5e_priv_flags[i]);
		break;
#endif

	case ETH_SS_TEST:
		for (i = 0; i < MLX5E_NUM_SELF_TEST; i++)
			strcpy(data + i * ETH_GSTRING_LEN, mlx5e_test_names[i]);
		break;

	case ETH_SS_STATS:
		mlx5e_fill_stats_strings(priv, data);
		break;
	}
}

static void mlx5e_get_ethtool_stats(struct net_device *dev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int i, j, tc, prio, idx = 0;
	unsigned long pfc_combined;

	if (!data)
		return;

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_update_stats(priv);
	mutex_unlock(&priv->state_lock);

	for (i = 0; i < NUM_SW_COUNTERS; i++)
		data[idx++] = MLX5E_READ_CTR64_CPU(&priv->stats.sw,
						   sw_stats_desc, i);

	for (i = 0; i < NUM_Q_COUNTERS; i++)
		data[idx++] = MLX5E_READ_CTR32_CPU(&priv->stats.qcnt,
						   q_stats_desc, i);

	for (i = 0; i < NUM_VPORT_COUNTERS; i++)
		data[idx++] = MLX5E_READ_CTR64_BE(priv->stats.vport.query_vport_out,
						  vport_stats_desc, i);

	for (i = 0; i < NUM_PPORT_802_3_COUNTERS; i++)
		data[idx++] = MLX5E_READ_CTR64_BE(&priv->stats.pport.IEEE_802_3_counters,
						  pport_802_3_stats_desc, i);

	for (i = 0; i < NUM_PPORT_2863_COUNTERS; i++)
		data[idx++] = MLX5E_READ_CTR64_BE(&priv->stats.pport.RFC_2863_counters,
						  pport_2863_stats_desc, i);

	for (i = 0; i < NUM_PPORT_2819_COUNTERS; i++)
		data[idx++] = MLX5E_READ_CTR64_BE(&priv->stats.pport.RFC_2819_counters,
						  pport_2819_stats_desc, i);

	for (i = 0; i < NUM_PPORT_PHY_COUNTERS; i++)
		data[idx++] = MLX5E_READ_CTR64_BE(&priv->stats.pport.phy_counters,
						  pport_phy_stats_desc, i);

	for (prio = 0; prio < NUM_PPORT_PRIO; prio++) {
		for (i = 0; i < NUM_PPORT_PER_PRIO_TRAFFIC_COUNTERS; i++)
			data[idx++] = MLX5E_READ_CTR64_BE(&priv->stats.pport.per_prio_counters[prio],
						 pport_per_prio_traffic_stats_desc, i);
	}

	pfc_combined = mlx5e_query_pfc_combined(priv);
	for_each_set_bit(prio, &pfc_combined, NUM_PPORT_PRIO) {
		for (i = 0; i < NUM_PPORT_PER_PRIO_PFC_COUNTERS; i++) {
			data[idx++] = MLX5E_READ_CTR64_BE(&priv->stats.pport.per_prio_counters[prio],
							  pport_per_prio_pfc_stats_desc, i);
		}
	}

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		return;

	/* per channel counters */
	for (i = 0; i < priv->params.num_channels; i++)
		for (j = 0; j < NUM_RQ_STATS; j++)
			data[idx++] =
				MLX5E_READ_CTR64_CPU(&priv->channel[i]->rq.stats,
						     rq_stats_desc, j);

	for (tc = 0; tc < priv->params.num_tc; tc++)
		for (i = 0; i < priv->params.num_channels; i++)
			for (j = 0; j < NUM_SQ_STATS; j++)
				data[idx++] = MLX5E_READ_CTR64_CPU(&priv->channel[i]->sq[tc].stats,
								   sq_stats_desc, j);

	/* Special TX queue counters */
	for (i = 0; i < priv->params.num_rl_txqs; i++) {
		int q_ix = i + priv->params.num_channels * priv->params.num_tc;

		for (j = 0; j < NUM_SQ_STATS; j++)
			data[idx++] = MLX5E_READ_CTR64_CPU(&priv->txq_to_sq_map[q_ix]->stats,
							   sq_stats_desc, j);
	}
}

static void mlx5e_get_mpwqe_size(int *stride_size, int *wqe_size)
{
	int num_strides;

	num_strides = MLX5E_PARAMS_HW_NUM_STRIDES_BASIC_VAL <<
		      MLX5E_PARAMS_DEFAULT_LOG_WQE_NUM_STRIDES;
	*stride_size = MLX5E_PARAMS_HW_STRIDE_SIZE_BASIC_VAL <<
		       MLX5E_PARAMS_DEFAULT_LOG_WQE_STRIDE_SIZE;
	*wqe_size = (*stride_size) * num_strides;
}

static int mlx5e_rx_wqes_to_packets(int rq_wq_type, int num_wqe)
{
	int wqe_size;
	int packets_per_wqe;
	int stride_size;

	if (rq_wq_type != RQ_TYPE_STRIDE)
		return num_wqe;

	mlx5e_get_mpwqe_size(&stride_size, &wqe_size);
	packets_per_wqe = wqe_size / ALIGN(MLX5E_PARAMS_STRIDING_MTU, stride_size);
	return (1 << (order_base_2(num_wqe * packets_per_wqe) - 1));
}

static int mlx5e_rx_packets_to_wqe(int rq_wq_type, int num_packets)
{
	int wqe_size;
	int num_wqes;
	int stride_size;
	int packets_per_wqe;

	if (rq_wq_type != RQ_TYPE_STRIDE)
		return num_packets;

	num_packets = (1 << order_base_2(num_packets));

	mlx5e_get_mpwqe_size(&stride_size, &wqe_size);
	packets_per_wqe = wqe_size /
			  ALIGN(MLX5E_PARAMS_STRIDING_MTU, stride_size);
	num_wqes = DIV_ROUND_UP(num_packets, packets_per_wqe);
	return 1 << (order_base_2(num_wqes));
}

static void mlx5e_get_ringparam(struct net_device *dev,
				struct ethtool_ringparam *param)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int rq_wq_type = MLX5_CAP_GEN(priv->mdev, striding_rq);

	param->rx_max_pending =
		mlx5e_rx_wqes_to_packets(rq_wq_type,
					   1 << mlx5_max_log_rq_size(rq_wq_type));
	param->tx_max_pending = 1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE;
	param->rx_pending     =
		mlx5e_rx_wqes_to_packets(rq_wq_type,
					   1 << priv->params.log_rq_size);
	param->tx_pending     = 1 << priv->params.log_sq_size;
}

static int mlx5e_set_ringparam(struct net_device *dev,
			       struct ethtool_ringparam *param)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_params new_params;
	int rq_wq_type = MLX5_CAP_GEN(priv->mdev, striding_rq);
	u16 min_rx_wqes;
	u8 log_rq_size;
	u8 log_sq_size;
	int err = 0;
	int min_rq_size =
		mlx5e_rx_wqes_to_packets(rq_wq_type,
					   1 << mlx5_min_log_rq_size(rq_wq_type));
	int max_rq_size =
		mlx5e_rx_wqes_to_packets(rq_wq_type,
					   1 << mlx5_max_log_rq_size(rq_wq_type));
	int rx_pending_wqes = mlx5e_rx_packets_to_wqe(rq_wq_type,
						      param->rx_pending);

	if (param->rx_jumbo_pending) {
		netdev_info(dev, "%s: rx_jumbo_pending not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (param->rx_mini_pending) {
		netdev_info(dev, "%s: rx_mini_pending not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (param->rx_pending < min_rq_size) {
		netdev_info(dev, "%s: rx_pending (%d) < min (%d)\n",
			    __func__, param->rx_pending,
			    min_rq_size);
		return -EINVAL;
	}
	if (param->rx_pending > max_rq_size) {
		netdev_info(dev, "%s: rx_pending (%d) > max (%d)\n",
			    __func__, param->rx_pending,
			    max_rq_size);
		return -EINVAL;
	}
	if (param->tx_pending < (1 << MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE)) {
		netdev_info(dev, "%s: tx_pending (%d) < min (%d)\n",
			    __func__, param->tx_pending,
			    1 << MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE);
		return -EINVAL;
	}
	if (param->tx_pending > (1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE)) {
		netdev_info(dev, "%s: tx_pending (%d) > max (%d)\n",
			    __func__, param->tx_pending,
			    1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE);
		return -EINVAL;
	}

	log_rq_size = order_base_2(rx_pending_wqes);
	log_sq_size = order_base_2(param->tx_pending);
	min_rx_wqes = mlx5_min_rx_wqes(rq_wq_type, rx_pending_wqes);

	if (log_rq_size == priv->params.log_rq_size &&
	    log_sq_size == priv->params.log_sq_size &&
	    min_rx_wqes == priv->params.min_rx_wqes)
		return 0;

	mutex_lock(&priv->state_lock);
	new_params = priv->params;
	new_params.log_rq_size = log_rq_size;
	new_params.log_sq_size = log_sq_size;
	new_params.min_rx_wqes = min_rx_wqes;
	err = mlx5e_update_priv_params(priv, &new_params);
	mutex_unlock(&priv->state_lock);

	return err;
}

#if defined(HAVE_GET_SET_CHANNELS) || defined(HAVE_GET_SET_CHANNELS_EXT)
static void mlx5e_get_channels(struct net_device *dev,
			       struct ethtool_channels *ch)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int ncv = priv->mdev->priv.eq_table.num_comp_vectors;

	ch->max_combined   = mlx5e_max_num_channels(ncv);
	ch->combined_count = priv->params.num_channels;
#ifdef HAVE_NDO_SET_TX_MAXRATE
	ch->max_other      = MLX5E_MAX_RL_QUEUES;
	ch->other_count    = priv->params.num_rl_txqs;
#endif
}

static int mlx5e_set_channels(struct net_device *dev,
			      struct ethtool_channels *ch)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int ncv = priv->mdev->priv.eq_table.num_comp_vectors;
	unsigned int count = ch->combined_count;
	struct mlx5e_params new_params;
	unsigned int rl_count = ch->other_count;
	int err = 0;

	if (!count) {
		netdev_info(dev, "%s: combined_count=0 not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (ch->rx_count || ch->tx_count) {
		netdev_info(dev, "%s: separate rx/tx count not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (count > mlx5e_max_num_channels(ncv)) {
		netdev_info(dev, "%s: count (%d) > max (%d)\n",
			    __func__, count, mlx5e_max_num_channels(ncv));
		return -EINVAL;
	}

	if (priv->params.num_channels == count &&
	    priv->params.num_rl_txqs == rl_count)
		return 0;

	mutex_lock(&priv->state_lock);
	new_params = priv->params;
	new_params.num_channels = count;
#ifdef HAVE_NDO_SET_TX_MAXRATE
	new_params.num_rl_txqs = rl_count;
#endif
	mlx5e_build_default_indir_rqt(priv->mdev, new_params.indirection_rqt,
				      MLX5E_INDIR_RQT_SIZE, count);
	err = mlx5e_update_priv_params(priv, &new_params);
	mutex_unlock(&priv->state_lock);

	return err;
}
#endif

static int mlx5e_get_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	if (!MLX5_CAP_GEN(priv->mdev, cq_moderation))
		return -ENOTSUPP;

	coal->rx_coalesce_usecs       = priv->params.rx_cq_moderation_usec;
	coal->rx_max_coalesced_frames = priv->params.rx_cq_moderation_pkts;
	coal->tx_coalesce_usecs       = priv->params.tx_cq_moderation_usec;
	coal->tx_max_coalesced_frames = priv->params.tx_cq_moderation_pkts;

	return 0;
}

static int mlx5e_set_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_channel *c;
	int tc;
	int i;

	if (!MLX5_CAP_GEN(mdev, cq_moderation))
		return -ENOTSUPP;

	mutex_lock(&priv->state_lock);
	priv->params.tx_cq_moderation_usec = coal->tx_coalesce_usecs;
	priv->params.tx_cq_moderation_pkts = coal->tx_max_coalesced_frames;
	priv->params.rx_cq_moderation_usec = coal->rx_coalesce_usecs;
	priv->params.rx_cq_moderation_pkts = coal->rx_max_coalesced_frames;

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		goto out;

	for (i = 0; i < priv->params.num_channels; ++i) {
		c = priv->channel[i];

		for (tc = 0; tc < c->num_tc; tc++) {
			mlx5_core_modify_cq_moderation(mdev,
						&c->sq[tc].cq.mcq,
						coal->tx_coalesce_usecs,
						coal->tx_max_coalesced_frames);
		}

		mlx5_core_modify_cq_moderation(mdev, &c->rq.cq.mcq,
					       coal->rx_coalesce_usecs,
					       coal->rx_max_coalesced_frames);
	}

out:
	mutex_unlock(&priv->state_lock);
	return 0;
}

static u32 ptys2ethtool_supported_link(u32 eth_proto_cap)
{
	int i;
	u32 supoprted_modes = 0;

	for (i = 0; i < MLX5_LINK_MODES_NUMBER; ++i) {
		if (eth_proto_cap & MLX5_PROT_MASK(i))
			supoprted_modes |= ptys2ethtool_table[i].supported;
	}
	return supoprted_modes;
}

static u32 ptys2ethtool_adver_link(u32 eth_proto_cap)
{
	int i;
	u32 advertising_modes = 0;

	for (i = 0; i < MLX5_LINK_MODES_NUMBER; ++i) {
		if (eth_proto_cap & MLX5_PROT_MASK(i))
			advertising_modes |= ptys2ethtool_table[i].advertised;
	}
	return advertising_modes;
}

static u32 ptys2ethtool_supported_port(u32 eth_proto_cap)
{
	/*
	TODO:
	MLX5E_40GBASE_LR4	 = 16,
	MLX5E_10GBASE_ER	 = 14,
	MLX5E_10GBASE_CX4	 = 2,
	*/

	if (eth_proto_cap & (MLX5_PROT_MASK(MLX5_10GBASE_CR)
			   | MLX5_PROT_MASK(MLX5_10GBASE_SR)
			   | MLX5_PROT_MASK(MLX5_40GBASE_CR4)
			   | MLX5_PROT_MASK(MLX5_40GBASE_SR4)
			   | MLX5_PROT_MASK(MLX5_100GBASE_SR4)
			   | MLX5_PROT_MASK(MLX5_1000BASE_CX_SGMII))) {
		return SUPPORTED_FIBRE;
	}

	if (eth_proto_cap & (MLX5_PROT_MASK(MLX5_100GBASE_KR4)
			   | MLX5_PROT_MASK(MLX5_40GBASE_KR4)
			   | MLX5_PROT_MASK(MLX5_10GBASE_KR)
			   | MLX5_PROT_MASK(MLX5_10GBASE_KX4)
			   | MLX5_PROT_MASK(MLX5_1000BASE_KX))) {
		return SUPPORTED_Backplane;
	}
	return 0;
}

static void get_speed_duplex(struct net_device *netdev,
			     u32 eth_proto_oper,
			     struct ethtool_cmd *cmd)
{
	int i;
	u32 speed = SPEED_UNKNOWN;
	u8 duplex = DUPLEX_UNKNOWN;

	if (!netif_carrier_ok(netdev))
		goto out;

	for (i = 0; i < MLX5_LINK_MODES_NUMBER; ++i) {
		if (eth_proto_oper & MLX5_PROT_MASK(i)) {
			speed = ptys2ethtool_table[i].speed;
			duplex = DUPLEX_FULL;
			break;
		}
	}
out:
	ethtool_cmd_speed_set(cmd, speed);
	cmd->duplex = duplex;
}

static void get_supported(u32 eth_proto_cap, u32 *supported)
{
	*supported |= ptys2ethtool_supported_port(eth_proto_cap);
	*supported |= ptys2ethtool_supported_link(eth_proto_cap);
	*supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
}

static void get_advertising(u32 eth_proto_cap, u8 tx_pause,
			    u8 rx_pause, u32 *advertising)
{
	*advertising |= ptys2ethtool_adver_link(eth_proto_cap);
	*advertising |= tx_pause ? ADVERTISED_Pause : 0;
	*advertising |= (tx_pause ^ rx_pause) ? ADVERTISED_Asym_Pause : 0;
}

static u8 get_connector_port(u32 eth_proto)
{
	/*
	TODO:
	MLX5E_40GBASE_LR4	 = 16,
	MLX5E_10GBASE_ER	 = 14,
	MLX5E_10GBASE_CX4	 = 2,
	*/

	if (eth_proto & (MLX5_PROT_MASK(MLX5_10GBASE_SR)
			 | MLX5_PROT_MASK(MLX5_40GBASE_SR4)
			 | MLX5_PROT_MASK(MLX5_100GBASE_SR4)
			 | MLX5_PROT_MASK(MLX5_1000BASE_CX_SGMII))) {
			return PORT_FIBRE;
	}

	if (eth_proto & (MLX5_PROT_MASK(MLX5_40GBASE_CR4)
			 | MLX5_PROT_MASK(MLX5_10GBASE_CR)
			 | MLX5_PROT_MASK(MLX5_100GBASE_CR4))) {
			return PORT_DA;
	}

	if (eth_proto & (MLX5_PROT_MASK(MLX5_10GBASE_KX4)
			 | MLX5_PROT_MASK(MLX5_10GBASE_KR)
			 | MLX5_PROT_MASK(MLX5_40GBASE_KR4)
			 | MLX5_PROT_MASK(MLX5_100GBASE_KR4))) {
			return PORT_NONE;
	}

	return PORT_OTHER;
}

static void get_lp_advertising(u32 eth_proto_lp, u32 *lp_advertising)
{

	*lp_advertising = ptys2ethtool_adver_link(eth_proto_lp);
}

static int mlx5e_get_settings(struct net_device *netdev,
			      struct ethtool_cmd *cmd)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	u32 eth_proto_cap;
	u32 eth_proto_admin;
	u32 eth_proto_lp;
	u32 eth_proto_oper;
	u8 an_disable_cap;
	u8 an_disable_admin;
	u8 an_status;
	int err;

	err = mlx5_query_port_ptys(mdev, out, sizeof(out), MLX5_PTYS_EN);

	if (err) {
		netdev_err(netdev, "%s: query port ptys failed: %d\n",
			   __func__, err);
		goto err_query_ptys;
	}

	eth_proto_cap   = MLX5_GET(ptys_reg, out, eth_proto_capability);
	eth_proto_admin = MLX5_GET(ptys_reg, out, eth_proto_admin);
	eth_proto_oper  = MLX5_GET(ptys_reg, out, eth_proto_oper);
	eth_proto_lp    = MLX5_GET(ptys_reg, out, eth_proto_lp_advertise);
	an_disable_admin = MLX5_GET(ptys_reg, out, an_disable_admin);
	an_disable_cap   = MLX5_GET(ptys_reg, out, an_disable_cap);
	an_status       = MLX5_GET(ptys_reg, out, an_status);

	cmd->supported   = 0;
	cmd->advertising = 0;

	get_supported(eth_proto_cap, &cmd->supported);
	get_advertising(eth_proto_admin, 0, 0, &cmd->advertising);
	get_speed_duplex(netdev, eth_proto_oper, cmd);

	eth_proto_oper = eth_proto_oper ? eth_proto_oper : eth_proto_cap;

	cmd->port = get_connector_port(eth_proto_oper);
	get_lp_advertising(eth_proto_lp, &cmd->lp_advertising);

	cmd->lp_advertising |= an_status == MLX5_AN_COMPLETE ?
			       ADVERTISED_Autoneg : 0;

	cmd->transceiver = XCVR_INTERNAL;
	cmd->autoneg = an_disable_admin ? AUTONEG_DISABLE : AUTONEG_ENABLE;
	cmd->supported   |= SUPPORTED_Autoneg;
	cmd->advertising |= !an_disable_admin ? ADVERTISED_Autoneg : 0;
	/* TODO
	set Pause
	cmd->supported ? SUPPORTED_Autoneg
	cmd->advertising ? ADVERTISED_Autoneg
	cmd->autoneg ?
	cmd->phy_address = 0;
	cmd->mdio_support = 0;
	cmd->maxtxpkt = 0;
	cmd->maxrxpkt = 0;
	cmd->eth_tp_mdix = ETH_TP_MDI_INVALID;
	cmd->eth_tp_mdix_ctrl = ETH_TP_MDI_AUTO;

	cmd->lp_advertising |= (priv->port_state.flags & MLX4_EN_PORT_ANC) ?
			ADVERTISED_Autoneg : 0;
	*/

err_query_ptys:
	return err;
}

static u32 mlx5e_ethtool2ptys_adver_link(u32 link_modes)
{
	u32 i, ptys_modes = 0;

	for (i = 0; i < MLX5_LINK_MODES_NUMBER; ++i) {
		if (ptys2ethtool_table[i].advertised & link_modes)
			ptys_modes |= MLX5_PROT_MASK(i);
	}

	return ptys_modes;
}

static u32 mlx5e_ethtool2ptys_speed_link(u32 speed)
{
	u32 i, speed_links = 0;

	for (i = 0; i < MLX5_LINK_MODES_NUMBER; ++i) {
		if (ptys2ethtool_table[i].speed == speed)
			speed_links |= MLX5_PROT_MASK(i);
	}

	return speed_links;
}

static int mlx5e_set_settings(struct net_device *netdev,
			      struct ethtool_cmd *cmd)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 link_modes;
	u32 speed;
	u32 eth_proto_cap, eth_proto_admin;
	u8 an_disable_status;
	u8 an_disable_cap;
	bool an_changes;
	int err;

	speed = ethtool_cmd_speed(cmd);

	link_modes = cmd->autoneg == AUTONEG_ENABLE ?
		mlx5e_ethtool2ptys_adver_link(cmd->advertising) :
		mlx5e_ethtool2ptys_speed_link(speed);

	err = mlx5_query_port_proto_cap(mdev, &eth_proto_cap, MLX5_PTYS_EN);
	if (err) {
		netdev_err(netdev, "%s: query port eth proto cap failed: %d\n",
			   __func__, err);
		goto out;
	}

	link_modes = link_modes & eth_proto_cap;
	if (!link_modes) {
		netdev_err(netdev, "%s: Not supported link mode(s) requested",
			   __func__);
		err = -EINVAL;
		goto out;
	}

	err = mlx5_query_port_proto_admin(mdev, &eth_proto_admin, MLX5_PTYS_EN);
	if (err) {
		netdev_err(netdev, "%s: query port eth proto admin failed: %d\n",
			   __func__, err);
		goto out;
	}

	err = mlx5_query_port_autoneg(mdev, MLX5_PTYS_EN,
				      &an_disable_cap, &an_disable_status);
	if (err) {
		netdev_err(netdev, "%s: query port eth proto admin failed: %d\n",
			   __func__, err);
		goto out;
	}

	if ((cmd->autoneg == AUTONEG_ENABLE) & (an_disable_status) ||
	    (cmd->autoneg == AUTONEG_DISABLE) & (!an_disable_status))
		an_changes = 1;

	if ((link_modes == eth_proto_admin) & (!an_changes))
		goto out;

	mlx5_set_port_status(mdev, MLX5_PORT_DOWN, 1);
	if (an_changes)
		mlx5_set_port_autoneg(mdev, !cmd->autoneg,
				link_modes, MLX5_PTYS_EN);
	else
		mlx5_set_port_proto(mdev, link_modes, MLX5_PTYS_EN);
	mlx5_set_port_status(mdev, MLX5_PORT_UP, 1);

out:
	return err;
}

static int mlx5e_set_pauseparam(struct net_device *netdev,
				struct ethtool_pauseparam *pauseparam)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int err;

	err = mlx5_set_port_pause(mdev, pauseparam->rx_pause,
				  pauseparam->tx_pause);
	if (err) {
		netdev_err(netdev, "%s: mlx5_set_port_pause failed:0x%x\n",
			   __func__, err);
	}

	return err;
}

static void mlx5e_get_pauseparam(struct net_device *netdev,
				 struct ethtool_pauseparam *pauseparam)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int err;

	err = mlx5_query_port_pause(mdev, &pauseparam->rx_pause,
				    &pauseparam->tx_pause);
	if (err) {
		netdev_err(netdev, "%s: mlx5_query_port_pause failed:0x%x\n",
			   __func__, err);
	}
}

#if defined(HAVE_GET_TS_INFO) || defined(HAVE_GET_TS_INFO_EXT)
static int mlx5e_get_ts_info(struct net_device *dev,
			     struct ethtool_ts_info *info)
{
#if defined (HAVE_PTP_CLOCK_INFO) && (defined (CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE))
	struct mlx5e_priv *priv = netdev_priv(dev);
#endif
	int ret;

	ret = ethtool_op_get_ts_info(dev, info);
	if (ret)
		return ret;

	info->so_timestamping |=
			SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;

	info->tx_types =
			(1 << HWTSTAMP_TX_OFF) |
			(1 << HWTSTAMP_TX_ON);

	info->rx_filters =
			(1 << HWTSTAMP_FILTER_NONE) |
			(1 << HWTSTAMP_FILTER_ALL);

#if defined (HAVE_PTP_CLOCK_INFO) && (defined (CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE))
	if (priv->tstamp.ptp)
		info->phc_index = ptp_clock_index(priv->tstamp.ptp);
#endif

	return ret;
}
#endif

static void mlx5e_fill_wol_supported(struct mlx5_core_dev *mdev,
				     struct ethtool_wolinfo *wol)
{

	if (MLX5_CAP_GEN(mdev, wol_g))
		wol->supported |= WAKE_MAGIC;

	if (MLX5_CAP_GEN(mdev, wol_s))
		wol->supported |= WAKE_MAGICSECURE;

	if (MLX5_CAP_GEN(mdev, wol_a))
		wol->supported |= WAKE_ARP;

	if (MLX5_CAP_GEN(mdev, wol_b))
		wol->supported |= WAKE_BCAST;

	if (MLX5_CAP_GEN(mdev, wol_m))
		wol->supported |= WAKE_MCAST;

	if (MLX5_CAP_GEN(mdev, wol_u))
		wol->supported |= WAKE_UCAST;

	if (MLX5_CAP_GEN(mdev, wol_p))
		wol->supported |= WAKE_PHY;
}

static void mlx5e_get_wol(struct net_device *netdev,
			  struct ethtool_wolinfo *wol)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u8 wol_mode;
	int err;

	wol->supported = 0;
	wol->wolopts = 0;

	mlx5e_fill_wol_supported(mdev, wol);

	err = mlx5_query_port_wol(mdev, &wol_mode);

	if (!err) {
		if (wol_mode == MLX5E_WOL_DISABLE) {
			wol->wolopts = 0;
			return;
		}

		if (wol_mode & MLX5E_WOL_MAGIC)
			wol->wolopts |= WAKE_MAGIC;

		if (wol_mode & MLX5E_WOL_SECURED_MAGIC)
			wol->wolopts |= WAKE_MAGICSECURE;

		if (wol_mode & MLX5E_WOL_ARP)
			wol->wolopts |= WAKE_ARP;

		if (wol_mode & MLX5E_WOL_BROADCAST)
			wol->wolopts |= WAKE_BCAST;

		if (wol_mode & MLX5E_WOL_MULTICAST)
			wol->wolopts |= WAKE_MCAST;

		if (wol_mode & MLX5E_WOL_UNICAST)
			wol->wolopts |= WAKE_UCAST;

		if (wol_mode & MLX5E_WOL_PHY_ACTIVITY)
			wol->wolopts |= WAKE_PHY;
	}
}

static int mlx5e_set_wol(struct net_device *netdev,
			 struct ethtool_wolinfo *wol)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 wol_supported = wol->supported;
	u8 wol_mode = 0;

	if (!wol_supported)
		return -ENOTSUPP;

	if (wol->wolopts & ~wol_supported)
		return -EINVAL;

	if (!wol->wolopts)
		wol_mode = MLX5E_WOL_DISABLE;

	if ((wol->wolopts & WAKE_MAGIC) && MLX5_CAP_GEN(mdev, wol_g))
		wol_mode |= MLX5E_WOL_MAGIC;

	if ((wol->wolopts & WAKE_MAGICSECURE) && MLX5_CAP_GEN(mdev, wol_s))
		wol_mode |= MLX5E_WOL_SECURED_MAGIC;

	if ((wol->wolopts & WAKE_ARP) && MLX5_CAP_GEN(mdev, wol_a))
		wol_mode |= MLX5E_WOL_ARP;

	if ((wol->wolopts & WAKE_BCAST) && MLX5_CAP_GEN(mdev, wol_b))
		wol_mode |= MLX5E_WOL_BROADCAST;

	if ((wol->wolopts & WAKE_MCAST) && MLX5_CAP_GEN(mdev, wol_m))
		wol_mode |= MLX5E_WOL_MULTICAST;

	if ((wol->wolopts & WAKE_UCAST) && MLX5_CAP_GEN(mdev, wol_u))
		wol_mode |= MLX5E_WOL_UNICAST;

	if ((wol->wolopts & WAKE_PHY) && MLX5_CAP_GEN(mdev, wol_p))
		wol_mode |= MLX5E_WOL_PHY_ACTIVITY;

	return mlx5_set_port_wol(mdev, wol_mode);
}

static u32 mlx5e_get_msglevel(struct net_device *dev)
{
	return ((struct mlx5e_priv *)netdev_priv(dev))->msg_level;
}

static void mlx5e_set_msglevel(struct net_device *dev, u32 val)
{
	((struct mlx5e_priv *)netdev_priv(dev))->msg_level = val;
}

#ifdef HAVE_IEEE_DCBNL_ETS
static void qos_with_dcbx_by_fw_handler(struct net_device *netdev,
					u32 wanted_flags)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	bool enable = !!(wanted_flags & MLX5E_PRIV_FLAGS_QOS_WITH_DCBX_BY_FW);

	if (!MLX5_CAP_GEN(priv->mdev, dcbx))
		return;

	/* Not allow to turn on the flag if the dcbx mode is host */
	if (enable && (priv->dcbx.mode == MLX5E_DCBX_PARAM_VER_OPER_HOST))
		return;

	 priv->pflags ^= MLX5E_PRIV_FLAGS_QOS_WITH_DCBX_BY_FW;
}

static void dcbx_handle_by_fw_handler(struct net_device *netdev,
				      u32 wanted_flags)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	bool enable = !!(wanted_flags & MLX5E_PRIV_FLAGS_DCBX_HANDLE_BY_FW);
	enum mlx5_dcbx_oper_mode mode;
	int err;

	if (!MLX5_CAP_GEN(priv->mdev, dcbx))
		return;

	mode = enable ? MLX5E_DCBX_PARAM_VER_OPER_AUTO
		      : MLX5E_DCBX_PARAM_VER_OPER_HOST;

	err = mlx5e_dcbnl_set_dcbx_mode(priv, mode);
	if (err)
		return;

	mlx5e_dcbnl_query_dcbx_mode(priv, &priv->dcbx.mode);

	/* Make sure the setting takes effect */
	if (priv->dcbx.mode != mode)
		return;

	/* Make sure qos_with_dcbx_by fw is off in host-controlled dcbx mode */
	if (priv->dcbx.mode == MLX5E_DCBX_PARAM_VER_OPER_HOST)
		priv->pflags &= (~MLX5E_PRIV_FLAGS_QOS_WITH_DCBX_BY_FW);

	priv->pflags ^= MLX5E_PRIV_FLAGS_DCBX_HANDLE_BY_FW;
}
#endif

#ifdef HAVE_GET_SET_PRIV_FLAGS
static int mlx5e_set_priv_flags(struct net_device *dev, u32 flags)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	u32 changes = flags ^ priv->pflags;
	struct mlx5e_params new_params;
	bool update_params = false;

	mutex_lock(&priv->state_lock);
	new_params = priv->params;

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
	if (changes & MLX5E_PRIV_FLAG_HWLRO) {
		priv->pflags ^= MLX5E_PRIV_FLAG_HWLRO;
		if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
			goto out;
		if (priv->params.lro_en)
			update_params = true;
	}
#endif

	if (changes & MLX5E_PRIV_FLAGS_SNIFFER_EN) {
		priv->pflags ^= MLX5E_PRIV_FLAGS_SNIFFER_EN;
		if (priv->pflags & MLX5E_PRIV_FLAGS_SNIFFER_EN) {
			if (mlx5e_sniffer_turn_on(dev))
				priv->pflags &= (~MLX5E_PRIV_FLAGS_SNIFFER_EN);
		} else {
			if (mlx5e_sniffer_turn_off(dev))
				priv->pflags |= MLX5E_PRIV_FLAGS_SNIFFER_EN;
		}
	}

#ifdef HAVE_IEEE_DCBNL_ETS
	if (changes & MLX5E_PRIV_FLAGS_QOS_WITH_DCBX_BY_FW)
		qos_with_dcbx_by_fw_handler(dev, flags);

	if (changes & MLX5E_PRIV_FLAGS_DCBX_HANDLE_BY_FW)
		dcbx_handle_by_fw_handler(dev, flags);
#endif

	/* will be added on future commits */
	if (update_params)
		mlx5e_update_priv_params(priv, &new_params);
#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
out:
#endif	
	mutex_unlock(&priv->state_lock);
	return !(flags == priv->pflags);
}

static u32 mlx5e_get_priv_flags(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	return priv->pflags;
}
#endif

#ifdef LEGACY_ETHTOOL_OPS
#if (defined(HAVE_GET_SET_FLAGS) || defined(HAVE_GET_SET_FLAGS_EXT))
static int mlx5e_set_flags(struct net_device *dev, u32 data)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_params new_params;
	u32 changes = data ^ dev->features;
	bool update_params = false;

	mutex_lock(&priv->state_lock);

	new_params = priv->params;

	if (changes & ETH_FLAG_LRO) {
		new_params.lro_en = !new_params.lro_en;
		update_params = true;
	}

	if (!update_params)
		goto out;

	mlx5e_update_priv_params(priv, &new_params);

	if (priv->params.lro_en)
		dev->features |= NETIF_F_LRO;
	else
		dev->features &= ~NETIF_F_LRO;

out:
	if (changes & ETH_FLAG_RXVLAN) {
		if (test_bit(MLX5E_STATE_OPENED, &priv->state))
			mlx5e_modify_rqs_vsd(priv, data & ETH_FLAG_RXVLAN ?
					     0 : 1);
		dev->features ^= NETIF_F_HW_VLAN_CTAG_RX;
	}

	if (changes & ETH_FLAG_TXVLAN)
		dev->features ^= NETIF_F_HW_VLAN_CTAG_TX;

	mutex_unlock(&priv->state_lock);
	return 0;
}

static u32 mlx5e_get_flags(struct net_device *dev)
{
	return ethtool_op_get_flags(dev) |
		(dev->features & NETIF_F_HW_VLAN_CTAG_RX) |
		(dev->features & NETIF_F_HW_VLAN_CTAG_TX);
}
#endif

#if (defined(HAVE_GET_SET_TSO) || defined(HAVE_GET_SET_TSO_EXT))
static u32 mlx5e_get_tso(struct net_device *dev)
{
       return (dev->features & NETIF_F_TSO) != 0;
}

static int mlx5e_set_tso(struct net_device *dev, u32 data)
{
       if (data)
               dev->features |= (NETIF_F_TSO | NETIF_F_TSO6);
       else
               dev->features &= ~(NETIF_F_TSO | NETIF_F_TSO6);
       return 0;
}
#endif
#endif

#ifdef LEGACY_ETHTOOL_OPS
#if defined(HAVE_GET_SET_RX_CSUM) || defined(HAVE_GET_SET_RX_CSUM_EXT)
static u32 mlx5e_get_rx_csum(struct net_device *dev)
{
       return dev->features & NETIF_F_RXCSUM;
}

static int mlx5e_set_rx_csum(struct net_device *dev, u32 data)
{
       if (!data) {
               dev->features &= ~NETIF_F_RXCSUM;
               return 0;
       }
       dev->features |= NETIF_F_RXCSUM;
       return 0;
}
#endif
#endif

#if defined(HAVE_SET_PHYS_ID) || defined(HAVE_SET_PHYS_ID_EXT)
static int mlx5e_set_phys_id(struct net_device *dev,
			     enum ethtool_phys_id_state state)
{
	int err;
	u16 beacon_duration;
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 out[MLX5_ST_SZ_DW(mlcr_reg)];

	if (!MLX5_CAP_GEN(mdev, beacon_led))
		return -EOPNOTSUPP;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		beacon_duration = 0xffff;
		break;
	case ETHTOOL_ID_INACTIVE:
		beacon_duration = 0x0;
		break;
	default:
		return -EOPNOTSUPP;
	}

	err = mlx5_set_port_beacon(mdev, out, sizeof(out), beacon_duration);
	return err;
}
#endif

#if defined(HAVE_RXFH_INDIR_SIZE) || defined(HAVE_RXFH_INDIR_SIZE_EXT)
static u32 mlx5e_get_rxfh_indir_size(struct net_device *netdev)
{
	return MLX5E_INDIR_RQT_SIZE;
}
#endif

#if defined(HAVE_GET_SET_RXFH) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT)
static u32 mlx5e_get_rxfh_key_size(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	return sizeof(priv->params.toeplitz_hash_key);
}
#endif

#if defined(HAVE_GET_SET_RXFH) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT)
static int mlx5e_get_rxfh(struct net_device *netdev, u32 *indir,
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
			  u8 *key, u8 *hfunc)
#else
			  u8 *key)
#endif
#elif defined(HAVE_GET_SET_RXFH_INDIR) || defined (HAVE_GET_SET_RXFH_INDIR_EXT)
static int mlx5e_get_rxfh_indir(struct net_device *netdev, u32 *indir)
#endif
#if defined(HAVE_GET_SET_RXFH) || defined(HAVE_GET_SET_RXFH_INDIR) || \
				  defined(HAVE_GET_SET_RXFH_INDIR_EXT)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	if (indir)
		memcpy(indir, priv->params.indirection_rqt,
		       sizeof(priv->params.indirection_rqt));

#if defined(HAVE_GET_SET_RXFH) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT)
	if (key)
		memcpy(key, priv->params.toeplitz_hash_key,
		       sizeof(priv->params.toeplitz_hash_key));

#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
	if (hfunc)
		*hfunc = priv->params.rss_hfunc;
#endif
#endif

	return 0;
}
#endif

#if defined(HAVE_GET_SET_RXFH) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT)
static int mlx5e_set_rxfh(struct net_device *netdev, const u32 *indir,
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
			  const u8 *key, const u8 hfunc)
#else
			  const u8 *key)
#endif
#elif defined(HAVE_GET_SET_RXFH_INDIR) || defined (HAVE_GET_SET_RXFH_INDIR_EXT)
static int mlx5e_set_rxfh_indir(struct net_device *netdev, const u32 *indir)
#endif
#if defined(HAVE_GET_SET_RXFH) || defined(HAVE_GET_SET_RXFH_INDIR) || \
				  defined(HAVE_GET_SET_RXFH_INDIR_EXT)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_params new_params;
	int err = 0;

#if defined(HAVE_GET_SET_RXFH) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT) && defined(HAVE_ETH_SS_RSS_HASH_FUNCS)
	if ((hfunc != ETH_RSS_HASH_NO_CHANGE) &&
	    (hfunc != ETH_RSS_HASH_XOR) &&
	    (hfunc != ETH_RSS_HASH_TOP))
		return -EINVAL;
#endif

	mutex_lock(&priv->state_lock);

	new_params = priv->params;

	if (indir)
		memcpy(new_params.indirection_rqt, indir,
		       sizeof(new_params.indirection_rqt));

#if defined(HAVE_GET_SET_RXFH) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT)
	if (key)
		memcpy(new_params.toeplitz_hash_key, key,
		       sizeof(new_params.toeplitz_hash_key));
#endif

#if defined(HAVE_GET_SET_RXFH) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT) && defined(HAVE_ETH_SS_RSS_HASH_FUNCS)
	if (hfunc != ETH_RSS_HASH_NO_CHANGE)
		new_params.rss_hfunc = hfunc;
#endif

	err = mlx5e_update_priv_params(priv, &new_params);

	mutex_unlock(&priv->state_lock);

	return err;
}
#endif

static int mlx5e_get_rxnfc(struct net_device *netdev,
#ifdef HAVE_ETHTOOL_OPS_GET_RXNFC_U32_RULE_LOCS
			   struct ethtool_rxnfc *info, u32 *rule_locs)
#else
			   struct ethtool_rxnfc *info, void *rule_locs)
#endif
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err = 0;

	switch (info->cmd) {
	case ETHTOOL_GRXRINGS:
		info->data = priv->params.num_channels;
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

#if defined(HAVE_GET_MODULE_EEPROM) || defined(HAVE_GET_MODULE_EEPROM_EXT)
static int mlx5e_get_module_info(struct net_device *netdev,
				 struct ethtool_modinfo *modinfo)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *dev = priv->mdev;
	int size_read = 0;
	u8 data[4];

	size_read = mlx5_query_module_eeprom(dev, 0, 2, data);
	if (size_read < 2)
		return -EIO;

	/* data[0] = identifier byte */
	switch (data[0]) {
	case MLX5_MODULE_ID_QSFP:
		modinfo->type       = ETH_MODULE_SFF_8436;
		modinfo->eeprom_len = ETH_MODULE_SFF_8436_LEN;
		break;
	case MLX5_MODULE_ID_QSFP_PLUS:
	case MLX5_MODULE_ID_QSFP28:
		/* data[1] = revision id */
		if (data[0] == MLX5_MODULE_ID_QSFP28 || data[1] >= 0x3) {
			modinfo->type       = ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = ETH_MODULE_SFF_8636_LEN;
		} else {
			modinfo->type       = ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = ETH_MODULE_SFF_8436_LEN;
		}
		break;
	case MLX5_MODULE_ID_SFP:
		modinfo->type       = ETH_MODULE_SFF_8472;
		modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
		break;
	default:
		netdev_err(priv->netdev, "%s: cable type not recognized:0x%x\n",
			   __func__, data[0]);
		return -EINVAL;
	}

	return 0;
}

static int mlx5e_get_module_eeprom(struct net_device *netdev,
				   struct ethtool_eeprom *ee,
				   u8 *data)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int offset = ee->offset;
	int size_read;
	int i = 0;

	if (!ee->len)
		return -EINVAL;

	memset(data, 0, ee->len);

	while (i < ee->len) {
		size_read = mlx5_query_module_eeprom(mdev, offset, ee->len - i,
						     data + i);

		if (!size_read)
			/* Done reading */
			return 0;

		if (size_read < 0) {
			netdev_err(priv->netdev, "%s: mlx5_query_eeprom failed:0x%x\n",
				   __func__, size_read);
			return 0;
		}

		i += size_read;
		offset += size_read;
	}

	return 0;
}
#endif

const struct ethtool_ops mlx5e_ethtool_ops = {
	.get_drvinfo       = mlx5e_get_drvinfo,
	.get_link          = ethtool_op_get_link,
	.get_strings       = mlx5e_get_strings,
	.get_sset_count    = mlx5e_get_sset_count,
	.get_ethtool_stats = mlx5e_get_ethtool_stats,
	.self_test         = mlx5e_self_test,
	.get_msglevel      = mlx5e_get_msglevel,
	.set_msglevel      = mlx5e_set_msglevel,
	.get_ringparam     = mlx5e_get_ringparam,
	.set_ringparam     = mlx5e_set_ringparam,
#ifdef HAVE_GET_SET_CHANNELS
	.get_channels      = mlx5e_get_channels,
	.set_channels      = mlx5e_set_channels,
#endif
	.get_coalesce      = mlx5e_get_coalesce,
	.set_coalesce      = mlx5e_set_coalesce,
	.get_settings      = mlx5e_get_settings,
	.set_settings      = mlx5e_set_settings,
#if defined(HAVE_GET_TS_INFO) && !defined(HAVE_GET_TS_INFO_EXT)
	.get_ts_info       = mlx5e_get_ts_info,
#endif
	.set_pauseparam    = mlx5e_set_pauseparam,
	.get_pauseparam    = mlx5e_get_pauseparam,
#if defined(HAVE_SET_PHYS_ID) && !defined(HAVE_SET_PHYS_ID_EXT)
	.set_phys_id       = mlx5e_set_phys_id,
#endif
	.get_wol	   = mlx5e_get_wol,
	.set_wol	   = mlx5e_set_wol,
#ifdef HAVE_GET_SET_PRIV_FLAGS
	.get_priv_flags	   = mlx5e_get_priv_flags,
	.set_priv_flags	   = mlx5e_set_priv_flags,
#endif
#ifdef LEGACY_ETHTOOL_OPS
#if defined(HAVE_GET_SET_FLAGS)
	.get_flags	   = mlx5e_get_flags,
	.set_flags	   = mlx5e_set_flags,
#endif
#if defined(HAVE_GET_SET_TSO)
	.get_tso	   = mlx5e_get_tso,
	.set_tso	   = mlx5e_set_tso,
#endif
#if defined(HAVE_GET_SET_SG)
	.get_sg = ethtool_op_get_sg,
	.set_sg = ethtool_op_set_sg,
#endif
#if defined(HAVE_GET_SET_RX_CSUM)
	.get_rx_csum = mlx5e_get_rx_csum,
	.set_rx_csum = mlx5e_set_rx_csum,
#endif
#if defined(HAVE_GET_SET_TX_CSUM)
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = ethtool_op_set_tx_ipv6_csum,
#endif
#endif
#if defined(HAVE_RXFH_INDIR_SIZE) && !defined(HAVE_RXFH_INDIR_SIZE_EXT)
	.get_rxfh_indir_size = mlx5e_get_rxfh_indir_size,
#endif
#if defined(HAVE_GET_SET_RXFH) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT)
	.get_rxfh_key_size = mlx5e_get_rxfh_key_size,
	.get_rxfh          = mlx5e_get_rxfh,
	.set_rxfh          = mlx5e_set_rxfh,
#elif defined(HAVE_GET_SET_RXFH_INDIR) && !defined(HAVE_GET_SET_RXFH_INDIR_EXT)
	.get_rxfh_indir = mlx5e_get_rxfh_indir,
	.set_rxfh_indir = mlx5e_set_rxfh_indir,
#endif
	.get_rxnfc         = mlx5e_get_rxnfc,
#ifdef HAVE_GET_MODULE_EEPROM
	.get_module_info   = mlx5e_get_module_info,
	.get_module_eeprom = mlx5e_get_module_eeprom,
#endif
};

#ifdef HAVE_ETHTOOL_OPS_EXT
const struct ethtool_ops_ext mlx5e_ethtool_ops_ext = {
	.size		   = sizeof(struct ethtool_ops_ext),
#ifdef HAVE_RXFH_INDIR_SIZE_EXT
	.get_rxfh_indir_size = mlx5e_get_rxfh_indir_size,
#endif
#ifdef HAVE_GET_SET_RXFH_INDIR_EXT
	.get_rxfh_indir = mlx5e_get_rxfh_indir,
	.set_rxfh_indir = mlx5e_set_rxfh_indir,
#endif
#ifdef HAVE_GET_SET_CHANNELS_EXT
	.get_channels	   = mlx5e_get_channels,
	.set_channels	   = mlx5e_set_channels,
#endif
#if defined(HAVE_GET_SET_FLAGS_EXT)
	.get_flags	   = mlx5e_get_flags,
	.set_flags	   = mlx5e_set_flags,
#endif
#if defined(HAVE_GET_SET_TSO_EXT)
	.get_tso	   = mlx5e_get_tso,
	.set_tso	   = mlx5e_set_tso,
#endif
#if defined(HAVE_GET_SET_SG_EXT)
	.get_sg = ethtool_op_get_sg,
	.set_sg = ethtool_op_set_sg,
#endif
#if defined(HAVE_GET_SET_RX_CSUM_EXT)
	.get_rx_csum = mlx5e_get_rx_csum,
	.set_rx_csum = mlx5e_set_rx_csum,
#endif
#if defined(HAVE_GET_SET_TX_CSUM_EXT)
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = ethtool_op_set_tx_ipv6_csum,
#endif
#ifdef HAVE_GET_TS_INFO_EXT
	.get_ts_info = mlx5e_get_ts_info,
#endif
#ifdef HAVE_GET_MODULE_EEPROM_EXT
	.get_module_info   = mlx5e_get_module_info,
	.get_module_eeprom = mlx5e_get_module_eeprom,
#endif
#if !defined(HAVE_SET_PHYS_ID) && defined(HAVE_SET_PHYS_ID_EXT)
	.set_phys_id       = mlx5e_set_phys_id,
#endif
};
#endif
