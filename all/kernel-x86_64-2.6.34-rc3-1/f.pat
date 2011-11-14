commit 3a940b439d05cbda05f3c36e989550720926e805
Author: Robert Olsson <robert@herjulf.net>
Date:   Thu Jun 3 18:24:51 2010 +0200

    Removed debug printout

diff --git a/drivers/net/ixgbe/ixgbe_ethtool.c b/drivers/net/ixgbe/ixgbe_ethtool.c
index d88a914..84cca1e 100644
--- a/drivers/net/ixgbe/ixgbe_ethtool.c
+++ b/drivers/net/ixgbe/ixgbe_ethtool.c
@@ -2339,8 +2339,6 @@ static s32 read_phy_diag_u32(struct ixgbe_hw *hw, u8 page, u8 offset, u32 *data)
 	*data = ((u32)p1) << 16 | p2;
 	
 out:
-	printk("u32_read_phy_diag: res=%d page=%d offset=%d date=%4X\n", 
-	       res, page, offset, *data);
 	return res;
 }
 
