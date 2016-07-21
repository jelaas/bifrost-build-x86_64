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

#define MLX5E_LOOPBACK_RETRIES		5
#define MLX5E_LOOPBACK_TIMEOUT		100
#define MLX5E_NOP_PACKET_TIMEOUT  100

static int mlx5e_test_loopback_xmit(struct mlx5e_priv *priv)
{
	struct sk_buff *skb;
	struct ethhdr *ethh;
	unsigned char *packet;
	unsigned int packet_size = MLX5E_LOOPBACK_TEST_PAYLOAD;
	unsigned int i;
	int err;

	/* build the pkt before xmit */
	skb = netdev_alloc_skb(priv->netdev, MLX5E_LOOPBACK_TEST_PAYLOAD +
			       ETH_HLEN + NET_IP_ALIGN);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, NET_IP_ALIGN);

	ethh = (struct ethhdr *)skb_put(skb, sizeof(struct ethhdr));
	packet  = (unsigned char *)skb_put(skb, packet_size);
	ether_addr_copy(ethh->h_dest, priv->netdev->dev_addr);
	memset(ethh->h_source, 0, ETH_ALEN);
	ethh->h_proto = htons(ETH_P_ARP);
	skb_set_mac_header(skb, 0);

	/* fill our packet */
	for (i = 0; i < packet_size; ++i)
		packet[i] = (unsigned char)(i & 0xff);

	/* xmit the pkt */
	err = mlx5e_xmit(skb, priv->netdev);
	return err;
}

static int mlx5e_test_loopback(struct mlx5e_priv *priv)
{
	bool loopback_ok = false;
	int i;
#ifdef HAVE_GRO
	bool gro_enabled;
#endif

	/*Fail loopback test if firmware does not support*/
	if (!MLX5_CAP_ETH(priv->mdev, self_lb_uc))
		return 1;

	priv->loopback_ok = false;
	priv->validate_loopback = true;
#ifdef HAVE_GRO
	gro_enabled = priv->netdev->features & NETIF_F_GRO;
	priv->netdev->features &= ~NETIF_F_GRO;
#endif

	/* xmit */
	if (mlx5e_test_loopback_xmit(priv)) {
		netdev_err(priv->netdev,
			   "%s: Transmitting loopback packet failed\n",
			   __func__);
		goto mlx5e_test_loopback_exit;
	}

	/* polling for result */
	for (i = 0; i < MLX5E_LOOPBACK_RETRIES; ++i) {
		msleep(MLX5E_LOOPBACK_TIMEOUT);
		if (priv->loopback_ok) {
			loopback_ok = true;
			break;
		}
	}
	if (!loopback_ok)
		netdev_err(priv->netdev, "Loopback packet didn't arrive\n");

mlx5e_test_loopback_exit:
	priv->validate_loopback = false;

#ifdef HAVE_GRO
	if (gro_enabled)
		priv->netdev->features |= NETIF_F_GRO;
#endif

	return !loopback_ok;
}

static int mlx5e_test_interrupt_single_channel(
	struct mlx5e_priv *priv, int channel_ix)
{
	int temp;
	struct mlx5e_sq *sq = &priv->channel[channel_ix]->sq[0];

	temp = sq->stats.nop;
	mlx5e_send_nop(sq, true);
	msleep(MLX5E_NOP_PACKET_TIMEOUT);
	if (sq->stats.nop == (temp + 1))
		return 0;
	else {
		netdev_err(priv->netdev, "Interrupt for channel %d failed \n", channel_ix);
		return 1;
	}
}

static int mlx5e_test_interrupt(struct mlx5e_priv *priv)
{
	int i;
	int temp = 0;

	for (i = 0; i < priv->params.num_channels; i++)
		temp += mlx5e_test_interrupt_single_channel(priv, i);

	return temp;
}

static int mlx5e_test_link_state(struct mlx5_core_dev *mdev)
{
	u8 port_state;

	port_state = mlx5_query_vport_state(mdev,
		MLX5_QUERY_VPORT_STATE_IN_OP_MOD_VNIC_VPORT, 0);

	if (port_state == VPORT_STATE_UP)
		return 0;
	return 1;
}

static int mlx5e_test_link_speed(struct mlx5_core_dev *mdev)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	u32 eth_proto_oper;
	int err;
	int i;

	err = mlx5_query_port_ptys(mdev, out, sizeof(out), MLX5_PTYS_EN);
	if (err)
		return 1;

	eth_proto_oper  = MLX5_GET(ptys_reg, out, eth_proto_oper);

	for (i = 0; i < MLX5_LINK_MODES_NUMBER; ++i) {
		if (eth_proto_oper & MLX5_PROT_MASK(i))
			return 0;
	}
	return 1;
}

static int mlx5e_test_health_info(struct mlx5_core_dev *mdev)
{
	struct mlx5_core_health *health = &mdev->priv.health;

	if (health->sick)
		return 1;
	return 0;
}

void mlx5e_self_test(struct net_device *dev,
		     struct ethtool_test *etest,
		     u64 *buf)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int carrier_ok = 0;
	int i;

	memset(buf, 0, sizeof(u64) * MLX5E_NUM_SELF_TEST);

	if (netif_carrier_ok(dev)) {
		buf[MLX5E_LINK_SPEED]	= mlx5e_test_link_speed(mdev);
		buf[MLX5E_LINK_STATE]	= mlx5e_test_link_state(mdev);
	} else {
		buf[MLX5E_LINK_SPEED]	= 1;
		buf[MLX5E_LINK_STATE]	= 1;
	}
	
	buf[MLX5E_HEALTH_INFO]	= mlx5e_test_health_info(mdev);
	if (etest->flags & ETH_TEST_FL_OFFLINE) {
		/* save current state */
		carrier_ok = netif_carrier_ok(dev);

		/* disable the interface */
		netif_carrier_off(dev);

		/* Wait until all tx queues are empty.
		 * there should not be any additional incoming traffic
		 * since we turned the carrier off
		 */
		msleep(200);
		mutex_lock(&priv->state_lock);
		if (test_bit(MLX5E_STATE_OPENED, &priv->state)) {
			buf[MLX5E_LOOPBACK] = mlx5e_test_loopback(priv);
			buf[MLX5E_INTERRUPT] = mlx5e_test_interrupt(priv);
		} else {
			buf[MLX5E_LOOPBACK] = 1;
			buf[MLX5E_INTERRUPT] = 1;
		}
		mutex_unlock(&priv->state_lock);
		if (carrier_ok)
			netif_carrier_on(dev);
	}

	for (i = 0; i < MLX5E_NUM_SELF_TEST; i++) {
		if (buf[i])
			etest->flags |= ETH_TEST_FL_FAILED;
	}
}
