commit ffcf8b682e3bc4e44e231e3cf64eeecc32502ae5
Author: Robert Olsson <robert@herjulf.net>
Date:   Tue Sep 7 15:12:16 2010 +0200

    removed DOM print-out

diff --git a/drivers/net/ixgbe/ixgbe_ethtool.c b/drivers/net/ixgbe/ixgbe_ethtool.c
index 4ab7969..6851d04 100644
--- a/drivers/net/ixgbe/ixgbe_ethtool.c
+++ b/drivers/net/ixgbe/ixgbe_ethtool.c
@@ -2483,7 +2483,7 @@ int ixgb_get_phy_diag(struct net_device *netdev, struct ethtool_phy_diag *pd)
 
 	type = pd->type >> 8;
 
-	printk("ixgbe_get_phy_diag: type=0x%X\n", pd->type);
+	//printk("ixgbe_get_phy_diag: type=0x%X\n", pd->type);
 
 	if ((~type & DOM_TYPE_DOM) || (type & DOM_TYPE_LEGAGY_DOM))
 		goto out;
@@ -2499,7 +2499,6 @@ int ixgb_get_phy_diag(struct net_device *netdev, struct ethtool_phy_diag *pd)
 	if (res)
 		goto out;
 
-
 	/* If supported. Read alarms and Warnings first*/
 	if (eo & DOM_EO_AW) {
 		res = read_phy_diag(hw, 0xA2, DOM_A2_ALARM, &pd->alarm);
