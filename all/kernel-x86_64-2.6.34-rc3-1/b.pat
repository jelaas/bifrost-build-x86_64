commit 9fb589c341adcc1592277bdbec18ab02dc10dd58
Author: root <root@gatling.(none)>
Date:   Tue Apr 13 14:45:31 2010 +0200

    DOM support added robert@herjulf.net

diff --git a/drivers/net/igb/igb_ethtool.c b/drivers/net/igb/igb_ethtool.c
index 55670ae..c7a8ce2 100644
--- a/drivers/net/igb/igb_ethtool.c
+++ b/drivers/net/igb/igb_ethtool.c
@@ -34,6 +34,7 @@
 #include <linux/interrupt.h>
 #include <linux/if_ether.h>
 #include <linux/ethtool.h>
+#include <net/dom.h>
 #include <linux/sched.h>
 #include <linux/slab.h>
 
@@ -2147,6 +2148,195 @@ static void igb_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
 	}
 }
 
+static s32 read_phy_diag(struct e1000_hw *hw, u8 page, u8 offset, u16 *data)
+{
+	u32 i, i2ccmd = 0;
+
+	if (offset > E1000_MAX_SGMII_PHY_REG_ADDR) {
+		hw_dbg("DOM Register Address %u is out of range\n", offset);
+		return -E1000_ERR_PARAM;
+	}
+
+	/*
+	 * Set up Op-code, Phy Address, and register address in the I2CCMD
+	 * register.  The MAC will take care of interfacing with the
+	 * PHY to retrieve the desired data.
+	 */
+
+	i2ccmd = (E1000_I2CCMD_OPCODE_READ) |
+		 (page << E1000_I2CCMD_PHY_ADDR_SHIFT) |
+		 (offset << E1000_I2CCMD_REG_ADDR_SHIFT);
+
+	wr32(E1000_I2CCMD, i2ccmd);
+
+	/* Poll the ready bit to see if the I2C read completed */
+	for (i = 0; i < E1000_I2CCMD_PHY_TIMEOUT; i++) {
+		udelay(50);
+		i2ccmd = rd32(E1000_I2CCMD);
+		//printk("DATA i2ccmd=0x%x\n", i2ccmd);
+		if (i2ccmd & E1000_I2CCMD_READY)
+			break;
+	}
+	if (!(i2ccmd & E1000_I2CCMD_READY)) {
+		hw_dbg("I2CCMD Read did not complete\n");
+		return -E1000_ERR_PHY;
+	}
+	if (i2ccmd & E1000_I2CCMD_ERROR) {
+		hw_dbg("I2CCMD Error bit set\n");
+		return -E1000_ERR_PHY;
+	}
+
+	/* Need to byte-swap the 16-bit value. */
+	*data = ((i2ccmd >> 8) & 0x00FF) | ((i2ccmd << 8) & 0xFF00);
+	return 0;
+}
+
+static s32 read_phy_diag_u32(struct e1000_hw *hw, u8 page, u8 offset, u32 *data)
+{
+	u16 p1;
+	u16 p2;
+	s32 res;
+
+	res = read_phy_diag(hw, page, offset, &p1);
+	if (res)
+		goto out;
+
+	res = read_phy_diag(hw, page, offset + 2, &p2);
+	if (res)
+		goto out;
+
+	*data = ((u32)p1) << 16 | p2;
+
+out:
+	return res;
+}
+
+struct reg_offset {
+	int reg;
+	size_t offset;
+};
+
+#define REG_OFFSET(a, b) \
+	{ .reg = a, .offset = offsetof(struct ethtool_phy_diag, b) }
+
+int igb_get_phy_diag(struct net_device *netdev, struct ethtool_phy_diag *pd)
+{
+	struct igb_adapter *adapter = netdev_priv(netdev);
+	struct e1000_hw *hw = &adapter->hw;
+	int res;
+	u8 type, eo;
+	int i;
+
+	static const struct reg_offset basic[] = {
+		REG_OFFSET(DOM_A2_TEMP, temp),
+		REG_OFFSET(DOM_A2_TEMP_SLOPE, temp_slope),
+		REG_OFFSET(DOM_A2_TEMP_OFFSET, temp_offset),
+		REG_OFFSET(DOM_A2_VCC, vcc),
+		REG_OFFSET(DOM_A2_VCC_SLOPE, vcc_slope),
+		REG_OFFSET(DOM_A2_VCC_OFFSET, vcc_offset),
+		REG_OFFSET(DOM_A2_TX_BIAS, tx_bias),
+		REG_OFFSET(DOM_A2_TX_I_SLOPE, tx_bias_slope),
+		REG_OFFSET(DOM_A2_TX_I_OFFSET, tx_bias_offset),
+		REG_OFFSET(DOM_A2_TX_PWR, tx_pwr),
+		REG_OFFSET(DOM_A2_TX_PWR_SLOPE, tx_pwr_slope),
+		REG_OFFSET(DOM_A2_TX_PWR_OFFSET, tx_pwr_offset),
+		REG_OFFSET(DOM_A2_RX_PWR, rx_pwr),
+	};
+
+	static const struct reg_offset power[] = {
+		REG_OFFSET(DOM_A2_RX_PWR_0, rx_pwr_cal[0]),
+		REG_OFFSET(DOM_A2_RX_PWR_1, rx_pwr_cal[1]),
+		REG_OFFSET(DOM_A2_RX_PWR_2, rx_pwr_cal[2]),
+		REG_OFFSET(DOM_A2_RX_PWR_3, rx_pwr_cal[3]),
+		REG_OFFSET(DOM_A2_RX_PWR_4, rx_pwr_cal[4]),
+	};
+
+	static const struct reg_offset aw[] = {
+		REG_OFFSET(DOM_A2_TEMP_AHT, temp_aht),
+		REG_OFFSET(DOM_A2_TEMP_ALT, temp_alt),
+		REG_OFFSET(DOM_A2_TEMP_WHT, temp_wht),
+		REG_OFFSET(DOM_A2_TEMP_WLT, temp_wlt),
+		REG_OFFSET(DOM_A2_VCC_AHT, vcc_aht),
+		REG_OFFSET(DOM_A2_VCC_ALT, vcc_alt),
+		REG_OFFSET(DOM_A2_VCC_WHT, vcc_wht),
+		REG_OFFSET(DOM_A2_VCC_WLT, vcc_wlt),
+		REG_OFFSET(DOM_A2_TX_BIAS_AHT, tx_bias_aht),
+		REG_OFFSET(DOM_A2_TX_BIAS_ALT, tx_bias_alt),
+		REG_OFFSET(DOM_A2_TX_BIAS_WHT, tx_bias_wht),
+		REG_OFFSET(DOM_A2_TX_BIAS_WLT, tx_bias_wlt),
+		REG_OFFSET(DOM_A2_TX_PWR_AHT, tx_pwr_aht),
+		REG_OFFSET(DOM_A2_TX_PWR_ALT, tx_pwr_alt),
+		REG_OFFSET(DOM_A2_TX_PWR_WHT, tx_pwr_wht),
+		REG_OFFSET(DOM_A2_TX_PWR_WLT, tx_pwr_wlt),
+		REG_OFFSET(DOM_A2_RX_PWR_AHT, rx_pwr_aht),
+		REG_OFFSET(DOM_A2_RX_PWR_ALT, rx_pwr_alt),
+		REG_OFFSET(DOM_A2_RX_PWR_WHT, rx_pwr_wht),
+		REG_OFFSET(DOM_A2_RX_PWR_WLT, rx_pwr_wlt),
+	};
+
+	res = read_phy_diag(hw, 0x0, DOM_A0_DOM_TYPE, &pd->type);
+	if (res)
+		goto out;
+
+	type = pd->type >> 8;
+
+	if ((~type & DOM_TYPE_DOM) || (type & DOM_TYPE_LEGAGY_DOM))
+		goto out;
+
+	if (type & DOM_TYPE_ADDR_CHNGE) {
+		hw_dbg("DOM module not supported (Address change)\n");
+		goto out;
+	}
+
+	eo = pd->type & 0xFF;
+
+	res = read_phy_diag(hw, 0x0, DOM_A0_WAVELENGTH, &pd->wavelength);
+	if (res)
+		goto out;
+
+	/* If supported. Read alarms and Warnings first*/
+	if (eo & DOM_EO_AW) {
+		res = read_phy_diag(hw, 0x1, DOM_A2_ALARM, &pd->alarm);
+		if (res)
+			goto out;
+		res = read_phy_diag(hw, 0x1, DOM_A2_WARNING, &pd->warning);
+		if (res)
+			goto out;
+	}
+
+	/* Basic diag */
+
+	for (i = 0; i < ARRAY_SIZE(basic); i++) {
+		res = read_phy_diag(hw, 0x1, basic[i].reg,
+				    (u16 *)((char *)pd + basic[i].offset));
+		if (res)
+			goto out;
+	}
+
+	/* Power */
+
+	for (i = 0; i < ARRAY_SIZE(power); i++) {
+		res = read_phy_diag_u32(hw, 0x1, power[i].reg,
+					(u32 *)((char *)pd + power[i].offset));
+		if (res)
+			goto out;
+	}
+
+	/* Thresholds for Alarms and Warnings */
+
+	if (eo & DOM_EO_AW) {
+		for (i = 0; i < ARRAY_SIZE(aw); i++) {
+			res = read_phy_diag(hw, 0x1, aw[i].reg,
+					    (u16 *)((char *)pd + aw[i].offset));
+			if (res)
+				goto out;
+		}
+	}
+
+out:
+	return res;
+}
+
 static const struct ethtool_ops igb_ethtool_ops = {
 	.get_settings           = igb_get_settings,
 	.set_settings           = igb_set_settings,
@@ -2181,6 +2371,7 @@ static const struct ethtool_ops igb_ethtool_ops = {
 	.get_ethtool_stats      = igb_get_ethtool_stats,
 	.get_coalesce           = igb_get_coalesce,
 	.set_coalesce           = igb_set_coalesce,
+	.get_phy_diag           = igb_get_phy_diag,
 };
 
 void igb_set_ethtool_ops(struct net_device *netdev)
diff --git a/drivers/net/ixgbe/ixgbe_ethtool.c b/drivers/net/ixgbe/ixgbe_ethtool.c
index 8f461d5..b126917 100644
--- a/drivers/net/ixgbe/ixgbe_ethtool.c
+++ b/drivers/net/ixgbe/ixgbe_ethtool.c
@@ -35,9 +35,11 @@
 #include <linux/ethtool.h>
 #include <linux/vmalloc.h>
 #include <linux/uaccess.h>
+#include <net/dom.h>
 
 #include "ixgbe.h"
-
+#include "ixgbe_phy.h"
+#include "ixgbe_common.h"
 
 #define IXGBE_ALL_RAR_ENTRIES 16
 
@@ -2293,6 +2295,206 @@ static int ixgbe_set_rx_ntuple(struct net_device *dev,
 	return 0;
 }
 
+static s32 read_phy_diag_dump(struct ixgbe_hw *hw, u8 page)
+{
+	s32 status;
+	u8 hi;
+	u8 i;
+
+	for(i=0; i < 93; i++) {
+	  hi = 0;
+	  status = ixgbe_read_i2c_byte_generic(hw, i, page, &hi);
+
+	  if (status)
+	    break;
+	  
+	  printk("page=%d offset=%d data=%2X\n", page, i, hi);
+	  
+	}
+	return status;
+}
+
+static s32 read_phy_diag(struct ixgbe_hw *hw, u8 page, u8 offset, u16 *data)
+{
+	s32 status;
+	u8 hi, lo;
+	hi = 0; lo = 0;
+
+	status = ixgbe_read_i2c_byte_generic(hw, offset, page, &hi);
+	if (status)
+		goto out;
+
+	status = ixgbe_read_i2c_byte_generic(hw, offset+1, page, &lo);
+	if (status)
+		goto out;
+
+	*data = (((u16)hi) << 8) | lo;
+out:
+	printk("read_phy_diag: status=%d page=%d offset=%d data=%4X\n", 
+	       status, page, offset, *data);
+
+	return status;
+}
+
+static s32 read_phy_diag_u32(struct ixgbe_hw *hw, u8 page, u8 offset, u32 *data)
+{
+	u16 p1;
+	u16 p2;
+	s32 res;
+
+	res = read_phy_diag(hw, page, offset, &p1);
+	if (res)
+		goto out;
+
+	res = read_phy_diag(hw, page, offset+1, &p2);
+	if (res)
+		goto out;
+
+	*data = ((u32)p1) << 16 | p2;
+	
+out:
+	printk("u32_read_phy_diag: res=%d page=%d offset=%d date=%4X\n", 
+	       res, page, offset, *data);
+	return res;
+}
+
+struct reg_offset {
+	int reg;
+	size_t offset;
+};
+
+#define REG_OFFSET(a, b) \
+	{ .reg = a, .offset = offsetof(struct ethtool_phy_diag, b) }
+
+int ixgb_get_phy_diag(struct net_device *netdev, struct ethtool_phy_diag *pd)
+{
+	struct ixgbe_adapter *adapter = netdev_priv(netdev);
+	struct ixgbe_hw *hw = &adapter->hw;
+	int res;
+	u8 type, eo;
+	int i;
+
+	static const struct reg_offset basic[] = {
+		REG_OFFSET(DOM_A2_TEMP, temp),
+		REG_OFFSET(DOM_A2_TEMP_SLOPE, temp_slope),
+		REG_OFFSET(DOM_A2_TEMP_OFFSET, temp_offset),
+		REG_OFFSET(DOM_A2_VCC, vcc),
+		REG_OFFSET(DOM_A2_VCC_SLOPE, vcc_slope),
+		REG_OFFSET(DOM_A2_VCC_OFFSET, vcc_offset),
+		REG_OFFSET(DOM_A2_TX_BIAS, tx_bias),
+		REG_OFFSET(DOM_A2_TX_I_SLOPE, tx_bias_slope),
+		REG_OFFSET(DOM_A2_TX_I_OFFSET, tx_bias_offset),
+		REG_OFFSET(DOM_A2_TX_PWR, tx_pwr),
+		REG_OFFSET(DOM_A2_TX_PWR_SLOPE, tx_pwr_slope),
+		REG_OFFSET(DOM_A2_TX_PWR_OFFSET, tx_pwr_offset),
+		REG_OFFSET(DOM_A2_RX_PWR, rx_pwr),
+	};
+
+	static const struct reg_offset power[] = {
+		REG_OFFSET(DOM_A2_RX_PWR_0, rx_pwr_cal[0]),
+		REG_OFFSET(DOM_A2_RX_PWR_1, rx_pwr_cal[1]),
+		REG_OFFSET(DOM_A2_RX_PWR_2, rx_pwr_cal[2]),
+		REG_OFFSET(DOM_A2_RX_PWR_3, rx_pwr_cal[3]),
+		REG_OFFSET(DOM_A2_RX_PWR_4, rx_pwr_cal[4]),
+	};
+
+	static const struct reg_offset aw[] = {
+		REG_OFFSET(DOM_A2_TEMP_AHT, temp_aht),
+		REG_OFFSET(DOM_A2_TEMP_ALT, temp_alt),
+		REG_OFFSET(DOM_A2_TEMP_WHT, temp_wht),
+		REG_OFFSET(DOM_A2_TEMP_WLT, temp_wlt),
+		REG_OFFSET(DOM_A2_VCC_AHT, vcc_aht),
+		REG_OFFSET(DOM_A2_VCC_ALT, vcc_alt),
+		REG_OFFSET(DOM_A2_VCC_WHT, vcc_wht),
+		REG_OFFSET(DOM_A2_VCC_WLT, vcc_wlt),
+		REG_OFFSET(DOM_A2_TX_BIAS_AHT, tx_bias_aht),
+		REG_OFFSET(DOM_A2_TX_BIAS_ALT, tx_bias_alt),
+		REG_OFFSET(DOM_A2_TX_BIAS_WHT, tx_bias_wht),
+		REG_OFFSET(DOM_A2_TX_BIAS_WLT, tx_bias_wlt),
+		REG_OFFSET(DOM_A2_TX_PWR_AHT, tx_pwr_aht),
+		REG_OFFSET(DOM_A2_TX_PWR_ALT, tx_pwr_alt),
+		REG_OFFSET(DOM_A2_TX_PWR_WHT, tx_pwr_wht),
+		REG_OFFSET(DOM_A2_TX_PWR_WLT, tx_pwr_wlt),
+		REG_OFFSET(DOM_A2_RX_PWR_AHT, rx_pwr_aht),
+		REG_OFFSET(DOM_A2_RX_PWR_ALT, rx_pwr_alt),
+		REG_OFFSET(DOM_A2_RX_PWR_WHT, rx_pwr_wht),
+		REG_OFFSET(DOM_A2_RX_PWR_WLT, rx_pwr_wlt),
+	};
+
+
+	//	read_phy_diag_dump(hw, 0xA0);
+	//return res;
+
+
+	res = read_phy_diag(hw, 0xA0, DOM_A0_DOM_TYPE, &pd->type);
+	if (res)
+		goto out;
+
+
+	type = pd->type >> 8;
+
+	printk("ixgbe_get_phy_diag: type=0x%X\n", pd->type);
+
+	if ((~type & DOM_TYPE_DOM) || (type & DOM_TYPE_LEGAGY_DOM))
+		goto out;
+
+	if (type & DOM_TYPE_ADDR_CHNGE)  {
+		hw_dbg(hw, "DOM module not supported (Address change)\n");
+		goto out;
+	}
+
+	eo = pd->type & 0xFF;
+
+	res = read_phy_diag(hw, 0xA0, DOM_A0_WAVELENGTH, &pd->wavelength);
+	if (res)
+		goto out;
+
+
+	/* If supported. Read alarms and Warnings first*/
+	if (eo & DOM_EO_AW) {
+		res = read_phy_diag(hw, 0xA2, DOM_A2_ALARM, &pd->alarm);
+		if (res)
+			goto out;
+
+		res = read_phy_diag(hw, 0xA2, DOM_A2_WARNING, &pd->warning);
+		if (res)
+			goto out;
+	}
+
+	/* Basic diag */
+
+	for (i = 0; i < ARRAY_SIZE(basic); i++) {
+		res = read_phy_diag(hw, 0xA2, basic[i].reg,
+				    (u16 *)((char *)pd + basic[i].offset));
+		if (res)
+			goto out;
+	}
+
+
+	/* Power */
+
+	for (i = 0; i < ARRAY_SIZE(power); i++) {
+		res = read_phy_diag_u32(hw, 0xA2, power[i].reg,
+					(u32 *)((char *)pd + power[i].offset));
+		if (res)
+			goto out;
+	}
+
+	/* Thresholds for Alarms and Warnings */
+
+	if (eo & DOM_EO_AW) {
+		for (i = 0; i < ARRAY_SIZE(aw); i++) {
+			res = read_phy_diag(hw, 0xA2, aw[i].reg,
+					    (u16 *)((char *)pd + aw[i].offset));
+			if (res)
+				goto out;
+		}
+	}
+
+out:
+	return res;
+}
+
 static const struct ethtool_ops ixgbe_ethtool_ops = {
 	.get_settings           = ixgbe_get_settings,
 	.set_settings           = ixgbe_set_settings,
@@ -2329,6 +2531,7 @@ static const struct ethtool_ops ixgbe_ethtool_ops = {
 	.get_flags              = ethtool_op_get_flags,
 	.set_flags              = ixgbe_set_flags,
 	.set_rx_ntuple          = ixgbe_set_rx_ntuple,
+	.get_phy_diag           = ixgb_get_phy_diag,
 };
 
 void ixgbe_set_ethtool_ops(struct net_device *netdev)
diff --git a/include/linux/ethtool.h b/include/linux/ethtool.h
index 276b40a..9c3012b 100644
--- a/include/linux/ethtool.h
+++ b/include/linux/ethtool.h
@@ -292,6 +292,53 @@ struct ethtool_stats {
 	__u64	data[0];
 };
 
+/* Diagmostic Monitoring Interface Data -- DOM */
+struct ethtool_phy_diag {
+	__u32 cmd;
+	/* A0 page */
+	__u16 type;
+	__u16 wavelength;
+	/* A2 page */
+	__u16 alarm;
+	__u16 warning;
+	__s16 temp;
+	__u16 temp_slope;
+	__s16 temp_offset;
+	__u16 vcc;
+	__u16 vcc_slope;
+	__s16 vcc_offset;
+	__u16 tx_bias;
+	__u16 tx_bias_slope;
+	__s16 tx_bias_offset;
+	__u16 tx_pwr;
+	__u16 tx_pwr_slope;
+	__s16 tx_pwr_offset;
+	__u16 rx_pwr;
+	__u32 rx_pwr_cal[5];
+
+	/* Thresholds */
+	__s16 temp_alt;
+	__s16 temp_aht;
+	__s16 temp_wlt;
+	__s16 temp_wht;
+	__u16 vcc_alt;
+	__u16 vcc_aht;
+	__u16 vcc_wlt;
+	__u16 vcc_wht;
+	__u16 tx_bias_alt;
+	__u16 tx_bias_aht;
+	__u16 tx_bias_wlt;
+	__u16 tx_bias_wht;
+	__u16 tx_pwr_alt;
+	__u16 tx_pwr_aht;
+	__u16 tx_pwr_wlt;
+	__u16 tx_pwr_wht;
+	__u16 rx_pwr_alt;
+	__u16 rx_pwr_aht;
+	__u16 rx_pwr_wlt;
+	__u16 rx_pwr_wht;
+};
+
 struct ethtool_perm_addr {
 	__u32	cmd;		/* ETHTOOL_GPERMADDR */
 	__u32	size;
@@ -576,6 +623,7 @@ struct ethtool_ops {
 	int	(*set_rx_ntuple)(struct net_device *,
 				 struct ethtool_rx_ntuple *);
 	int	(*get_rx_ntuple)(struct net_device *, u32 stringset, void *);
+	int     (*get_phy_diag)(struct net_device *, struct ethtool_phy_diag *);
 };
 #endif /* __KERNEL__ */
 
@@ -637,6 +685,7 @@ struct ethtool_ops {
 #define ETHTOOL_SRXNTUPLE	0x00000035 /* Add an n-tuple filter to device */
 #define ETHTOOL_GRXNTUPLE	0x00000036 /* Get n-tuple filters from device */
 #define ETHTOOL_GSSET_INFO	0x00000037 /* Get string set info */
+#define ETHTOOL_GPHYDIAG	0x00000100 /* Get PHY diagnostics */
 
 /* compatibility with older code */
 #define SPARC_ETH_GSET		ETHTOOL_GSET
diff --git a/net/core/ethtool.c b/net/core/ethtool.c
index 1a7db92..d2f7244 100644
--- a/net/core/ethtool.c
+++ b/net/core/ethtool.c
@@ -1314,6 +1314,21 @@ static noinline_for_stack int ethtool_flash_device(struct net_device *dev,
 	return dev->ethtool_ops->flash_device(dev, &efl);
 }
 
+static int ethtool_phy_diag(struct net_device *dev, void __user *useraddr)
+{
+	struct ethtool_phy_diag pd;
+
+	if (!dev->ethtool_ops->get_phy_diag)
+		return -EOPNOTSUPP;
+
+	dev->ethtool_ops->get_phy_diag(dev, &pd); /* FIXME */
+
+	if (copy_to_user(useraddr, &pd, sizeof(pd)))
+		 return -EFAULT;
+
+	return 0;
+}
+
 /* The main entry point in this file.  Called from net/core/dev.c */
 
 int dev_ethtool(struct net *net, struct ifreq *ifr)
@@ -1544,6 +1559,9 @@ int dev_ethtool(struct net *net, struct ifreq *ifr)
 	case ETHTOOL_GSSET_INFO:
 		rc = ethtool_get_sset_info(dev, useraddr);
 		break;
+	case ETHTOOL_GPHYDIAG:
+		rc = ethtool_phy_diag(dev, useraddr);
+		break;
 	default:
 		rc = -EOPNOTSUPP;
 	}
