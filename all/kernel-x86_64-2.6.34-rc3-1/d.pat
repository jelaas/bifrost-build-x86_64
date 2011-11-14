commit 6c9b71405cc92d6fad78a8315de6f2e800832b3d
Author: Robert Olsson <robert@herjulf.net>
Date:   Tue May 4 22:08:38 2010 +0200

    Removed debugging prink for DOM for ixgbe

diff --git a/drivers/net/ixgbe/ixgbe_ethtool.c b/drivers/net/ixgbe/ixgbe_ethtool.c
index b126917..f5c2347 100644
--- a/drivers/net/ixgbe/ixgbe_ethtool.c
+++ b/drivers/net/ixgbe/ixgbe_ethtool.c
@@ -2295,25 +2295,6 @@ static int ixgbe_set_rx_ntuple(struct net_device *dev,
 	return 0;
 }
 
-static s32 read_phy_diag_dump(struct ixgbe_hw *hw, u8 page)
-{
-	s32 status;
-	u8 hi;
-	u8 i;
-
-	for(i=0; i < 93; i++) {
-	  hi = 0;
-	  status = ixgbe_read_i2c_byte_generic(hw, i, page, &hi);
-
-	  if (status)
-	    break;
-	  
-	  printk("page=%d offset=%d data=%2X\n", page, i, hi);
-	  
-	}
-	return status;
-}
-
 static s32 read_phy_diag(struct ixgbe_hw *hw, u8 page, u8 offset, u16 *data)
 {
 	s32 status;
@@ -2330,9 +2311,6 @@ static s32 read_phy_diag(struct ixgbe_hw *hw, u8 page, u8 offset, u16 *data)
 
 	*data = (((u16)hi) << 8) | lo;
 out:
-	printk("read_phy_diag: status=%d page=%d offset=%d data=%4X\n", 
-	       status, page, offset, *data);
-
 	return status;
 }
 
@@ -2421,11 +2399,6 @@ int ixgb_get_phy_diag(struct net_device *netdev, struct ethtool_phy_diag *pd)
 		REG_OFFSET(DOM_A2_RX_PWR_WLT, rx_pwr_wlt),
 	};
 
-
-	//	read_phy_diag_dump(hw, 0xA0);
-	//return res;
-
-
 	res = read_phy_diag(hw, 0xA0, DOM_A0_DOM_TYPE, &pd->type);
 	if (res)
 		goto out;
