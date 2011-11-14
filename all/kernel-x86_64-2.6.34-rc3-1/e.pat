commit 1a0f80d25d5bf31b31109f7b830ae9dedbde0d92
Author: Robert Olsson <robert@herjulf.net>
Date:   Fri May 28 13:40:30 2010 +0200

    Flowdirector extra stats added

diff --git a/drivers/net/ixgbe/ixgbe_ethtool.c b/drivers/net/ixgbe/ixgbe_ethtool.c
index f5c2347..d88a914 100644
--- a/drivers/net/ixgbe/ixgbe_ethtool.c
+++ b/drivers/net/ixgbe/ixgbe_ethtool.c
@@ -84,8 +84,16 @@ static struct ixgbe_stats ixgbe_gstrings_stats[] = {
 	{"rx_frame_errors", IXGBE_NETDEV_STAT(stats.rx_frame_errors)},
 	{"hw_rsc_aggregated", IXGBE_STAT(rsc_total_count)},
 	{"hw_rsc_flushed", IXGBE_STAT(rsc_total_flush)},
+	{"fdir_maxlen", IXGBE_STAT(stats.fdir_maxlen)},
+	{"fdir_maxhash", IXGBE_STAT(stats.fdir_maxhash)},
+	{"fdir_free", IXGBE_STAT(stats.fdir_free)},
+	{"fdir_coll", IXGBE_STAT(stats.fdir_coll)},
 	{"fdir_match", IXGBE_STAT(stats.fdirmatch)},
 	{"fdir_miss", IXGBE_STAT(stats.fdirmiss)},
+	{"fdir_ustat_add", IXGBE_STAT(stats.fdirustat_add)},
+	{"fdir_ustat_remove", IXGBE_STAT(stats.fdirustat_remove)},
+	{"fdir_fstat_add", IXGBE_STAT(stats.fdirfstat_fadd)},
+	{"fdir_fstat_remove", IXGBE_STAT(stats.fdirfstat_fremove)},
 	{"rx_fifo_errors", IXGBE_NETDEV_STAT(stats.rx_fifo_errors)},
 	{"rx_missed_errors", IXGBE_NETDEV_STAT(stats.rx_missed_errors)},
 	{"tx_aborted_errors", IXGBE_NETDEV_STAT(stats.tx_aborted_errors)},
diff --git a/drivers/net/ixgbe/ixgbe_main.c b/drivers/net/ixgbe/ixgbe_main.c
index 7935284..bf009f1 100644
--- a/drivers/net/ixgbe/ixgbe_main.c
+++ b/drivers/net/ixgbe/ixgbe_main.c
@@ -4879,8 +4879,20 @@ void ixgbe_update_stats(struct ixgbe_adapter *adapter)
 		IXGBE_READ_REG(hw, IXGBE_TORH); /* to clear */
 		adapter->stats.lxonrxc += IXGBE_READ_REG(hw, IXGBE_LXONRXCNT);
 		adapter->stats.lxoffrxc += IXGBE_READ_REG(hw, IXGBE_LXOFFRXCNT);
+		tmp = IXGBE_READ_REG(hw, IXGBE_FDIRLEN);
+		adapter->stats.fdir_maxlen = tmp & 0x1F;
+		adapter->stats.fdir_maxlen = (tmp >> 16) & 0x7FFF;
+		tmp = IXGBE_READ_REG(hw, IXGBE_FDIRFREE);
+		adapter->stats.fdir_free = tmp & 0xFFFF;
+		adapter->stats.fdir_coll = (tmp >> 16) & 0x7FFF;
 		adapter->stats.fdirmatch += IXGBE_READ_REG(hw, IXGBE_FDIRMATCH);
 		adapter->stats.fdirmiss += IXGBE_READ_REG(hw, IXGBE_FDIRMISS);
+		tmp = IXGBE_READ_REG(hw, IXGBE_FDIRUSTAT);
+		adapter->stats.fdirustat_add += tmp & 0xFFFF;
+		adapter->stats.fdirustat_remove += tmp >> 16;
+		tmp = IXGBE_READ_REG(hw, IXGBE_FDIRFSTAT);
+		adapter->stats.fdirfstat_fadd += tmp & 0xFF;
+		adapter->stats.fdirfstat_fremove += tmp >> 8;
 #ifdef IXGBE_FCOE
 		adapter->stats.fccrc += IXGBE_READ_REG(hw, IXGBE_FCCRC);
 		adapter->stats.fcoerpdc += IXGBE_READ_REG(hw, IXGBE_FCOERPDC);
@@ -5555,6 +5567,11 @@ static void ixgbe_atr(struct ixgbe_adapter *adapter, struct sk_buff *skb,
 	u32 src_ipv4_addr, dst_ipv4_addr;
 	u8 l4type = 0;
 
+	if(!skb->sk) {
+	  /* ignore nonlocal traffic */
+	  return;
+	}
+
 	/* check if we're UDP or TCP */
 	if (iph->protocol == IPPROTO_TCP) {
 		th = tcp_hdr(skb);
diff --git a/drivers/net/ixgbe/ixgbe_type.h b/drivers/net/ixgbe/ixgbe_type.h
index aed4ed6..833a0bf 100644
--- a/drivers/net/ixgbe/ixgbe_type.h
+++ b/drivers/net/ixgbe/ixgbe_type.h
@@ -244,6 +244,7 @@
 #define IXGBE_FDIRDIP4M 0x0EE3C
 #define IXGBE_FDIRSIP4M 0x0EE40
 #define IXGBE_FDIRTCPM  0x0EE44
+#define IXGBE_FDIRLEN   0x0EE4C
 #define IXGBE_FDIRUDPM  0x0EE48
 #define IXGBE_FDIRIP6M  0x0EE74
 #define IXGBE_FDIRM     0x0EE70
@@ -2348,6 +2349,10 @@ struct ixgbe_hw_stats {
 	u64 qbtc[16];
 	u64 qprdc[16];
 	u64 pxon2offc[8];
+	u64 fdir_free;
+	u64 fdir_coll;
+	u64 fdir_maxlen;
+	u64 fdir_maxhash;
 	u64 fdirustat_add;
 	u64 fdirustat_remove;
 	u64 fdirfstat_fadd;
