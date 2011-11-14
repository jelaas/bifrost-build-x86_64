commit cb947d0b019ea21d0acece5981efbe54b9d2edb3
Author: Robert Olsson <robert@herjulf.net>
Date:   Fri Nov 12 14:40:30 2010 +0100

    Voravit fdir patch
    	modified:   drivers/net/ixgbe/ixgbe_main.c

diff --git a/drivers/net/ixgbe/ixgbe_main.c b/drivers/net/ixgbe/ixgbe_main.c
index bcab5ed..4d0e97a 100644
--- a/drivers/net/ixgbe/ixgbe_main.c
+++ b/drivers/net/ixgbe/ixgbe_main.c
@@ -5340,8 +5340,8 @@ void ixgbe_update_stats(struct ixgbe_adapter *adapter)
 		adapter->stats.lxonrxc += IXGBE_READ_REG(hw, IXGBE_LXONRXCNT);
 		adapter->stats.lxoffrxc += IXGBE_READ_REG(hw, IXGBE_LXOFFRXCNT);
 		tmp = IXGBE_READ_REG(hw, IXGBE_FDIRLEN);
-		adapter->stats.fdir_maxlen = tmp & 0x1F;
-		adapter->stats.fdir_maxlen = (tmp >> 16) & 0x7FFF;
+		adapter->stats.fdir_maxlen = tmp & 0x3F;
+		adapter->stats.fdir_maxhash = (tmp >> 16) & 0x7FFF;
 		tmp = IXGBE_READ_REG(hw, IXGBE_FDIRFREE);
 		adapter->stats.fdir_free = tmp & 0xFFFF;
 		adapter->stats.fdir_coll = (tmp >> 16) & 0x7FFF;
