commit 51a42b8089c2cea429681989967bd06bcdcf35f2
Author: Robert Olsson <robert@herjulf.net>
Date:   Thu Jun 10 08:38:35 2010 +0200

    Merged ixgbe from net-next-2.6 100609

diff --git a/drivers/net/ixgbe/ixgbe.h b/drivers/net/ixgbe/ixgbe.h
index 79c35ae..9270089 100644
--- a/drivers/net/ixgbe/ixgbe.h
+++ b/drivers/net/ixgbe/ixgbe.h
@@ -44,11 +44,9 @@
 #include <linux/dca.h>
 #endif
 
-#define PFX "ixgbe: "
-#define DPRINTK(nlevel, klevel, fmt, args...) \
-	((void)((NETIF_MSG_##nlevel & adapter->msg_enable) && \
-	printk(KERN_##klevel PFX "%s: %s: " fmt, adapter->netdev->name, \
-		__func__ , ## args)))
+/* common prefix used by pr_<> macros */
+#undef pr_fmt
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
 /* TX/RX descriptor defines */
 #define IXGBE_DEFAULT_TXD		    512
@@ -111,7 +109,10 @@ struct vf_data_storage {
 	u16 default_vf_vlan_id;
 	u16 vlans_enabled;
 	bool clear_to_send;
+	bool pf_set_mac;
 	int rar;
+	u16 pf_vlan; /* When set, guest VLAN config not allowed. */
+	u16 pf_qos;
 };
 
 /* wrapper around a pointer to a socket buffer,
@@ -357,6 +358,7 @@ struct ixgbe_adapter {
 	u32 flags2;
 #define IXGBE_FLAG2_RSC_CAPABLE                 (u32)(1)
 #define IXGBE_FLAG2_RSC_ENABLED                 (u32)(1 << 1)
+#define IXGBE_FLAG2_TEMP_SENSOR_CAPABLE         (u32)(1 << 2)
 /* default to trying for four seconds */
 #define IXGBE_TRY_LINK_TIMEOUT (4 * HZ)
 
@@ -404,6 +406,8 @@ struct ixgbe_adapter {
 	u16 eeprom_version;
 
 	int node;
+	struct work_struct check_overtemp_task;
+	u32 interrupt_event;
 
 	/* SR-IOV */
 	DECLARE_BITMAP(active_vfs, IXGBE_MAX_VF_FUNCTIONS);
diff --git a/drivers/net/ixgbe/ixgbe_82598.c b/drivers/net/ixgbe/ixgbe_82598.c
index 35a06b4..9c02d60 100644
--- a/drivers/net/ixgbe/ixgbe_82598.c
+++ b/drivers/net/ixgbe/ixgbe_82598.c
@@ -42,9 +42,9 @@ static s32 ixgbe_get_copper_link_capabilities_82598(struct ixgbe_hw *hw,
                                              ixgbe_link_speed *speed,
                                              bool *autoneg);
 static s32 ixgbe_setup_copper_link_82598(struct ixgbe_hw *hw,
-                                               ixgbe_link_speed speed,
-                                               bool autoneg,
-                                               bool autoneg_wait_to_complete);
+                                         ixgbe_link_speed speed,
+                                         bool autoneg,
+                                         bool autoneg_wait_to_complete);
 static s32 ixgbe_read_i2c_eeprom_82598(struct ixgbe_hw *hw, u8 byte_offset,
                                        u8 *eeprom_data);
 
@@ -1221,7 +1221,7 @@ static struct ixgbe_mac_operations mac_ops_82598 = {
 
 static struct ixgbe_eeprom_operations eeprom_ops_82598 = {
 	.init_params		= &ixgbe_init_eeprom_params_generic,
-	.read			= &ixgbe_read_eeprom_generic,
+	.read			= &ixgbe_read_eerd_generic,
 	.validate_checksum	= &ixgbe_validate_eeprom_checksum_generic,
 	.update_checksum	= &ixgbe_update_eeprom_checksum_generic,
 };
@@ -1236,6 +1236,7 @@ static struct ixgbe_phy_operations phy_ops_82598 = {
 	.setup_link		= &ixgbe_setup_phy_link_generic,
 	.setup_link_speed	= &ixgbe_setup_phy_link_speed_generic,
 	.read_i2c_eeprom	= &ixgbe_read_i2c_eeprom_82598,
+	.check_overtemp   = &ixgbe_tn_check_overtemp,
 };
 
 struct ixgbe_info ixgbe_82598_info = {
diff --git a/drivers/net/ixgbe/ixgbe_82599.c b/drivers/net/ixgbe/ixgbe_82599.c
index f894bb6..976fd9e 100644
--- a/drivers/net/ixgbe/ixgbe_82599.c
+++ b/drivers/net/ixgbe/ixgbe_82599.c
@@ -39,6 +39,8 @@
 #define IXGBE_82599_MC_TBL_SIZE   128
 #define IXGBE_82599_VFT_TBL_SIZE  128
 
+void ixgbe_disable_tx_laser_multispeed_fiber(struct ixgbe_hw *hw);
+void ixgbe_enable_tx_laser_multispeed_fiber(struct ixgbe_hw *hw);
 void ixgbe_flap_tx_laser_multispeed_fiber(struct ixgbe_hw *hw);
 s32 ixgbe_setup_mac_link_multispeed_fiber(struct ixgbe_hw *hw,
                                           ixgbe_link_speed speed,
@@ -69,8 +71,14 @@ static void ixgbe_init_mac_link_ops_82599(struct ixgbe_hw *hw)
 	if (hw->phy.multispeed_fiber) {
 		/* Set up dual speed SFP+ support */
 		mac->ops.setup_link = &ixgbe_setup_mac_link_multispeed_fiber;
+		mac->ops.disable_tx_laser =
+		                       &ixgbe_disable_tx_laser_multispeed_fiber;
+		mac->ops.enable_tx_laser =
+		                        &ixgbe_enable_tx_laser_multispeed_fiber;
 		mac->ops.flap_tx_laser = &ixgbe_flap_tx_laser_multispeed_fiber;
 	} else {
+		mac->ops.disable_tx_laser = NULL;
+		mac->ops.enable_tx_laser = NULL;
 		mac->ops.flap_tx_laser = NULL;
 		if ((mac->ops.get_media_type(hw) ==
 		     ixgbe_media_type_backplane) &&
@@ -125,27 +133,6 @@ setup_sfp_out:
 	return ret_val;
 }
 
-/**
- *  ixgbe_get_pcie_msix_count_82599 - Gets MSI-X vector count
- *  @hw: pointer to hardware structure
- *
- *  Read PCIe configuration space, and get the MSI-X vector count from
- *  the capabilities table.
- **/
-static u32 ixgbe_get_pcie_msix_count_82599(struct ixgbe_hw *hw)
-{
-	struct ixgbe_adapter *adapter = hw->back;
-	u16 msix_count;
-	pci_read_config_word(adapter->pdev, IXGBE_PCIE_MSIX_82599_CAPS,
-	                     &msix_count);
-	msix_count &= IXGBE_PCIE_MSIX_TBL_SZ_MASK;
-
-	/* MSI-X count is zero-based in HW, so increment to give proper value */
-	msix_count++;
-
-	return msix_count;
-}
-
 static s32 ixgbe_get_invariants_82599(struct ixgbe_hw *hw)
 {
 	struct ixgbe_mac_info *mac = &hw->mac;
@@ -157,7 +144,7 @@ static s32 ixgbe_get_invariants_82599(struct ixgbe_hw *hw)
 	mac->num_rar_entries = IXGBE_82599_RAR_ENTRIES;
 	mac->max_rx_queues = IXGBE_82599_MAX_RX_QUEUES;
 	mac->max_tx_queues = IXGBE_82599_MAX_TX_QUEUES;
-	mac->max_msix_vectors = ixgbe_get_pcie_msix_count_82599(hw);
+	mac->max_msix_vectors = ixgbe_get_pcie_msix_count_generic(hw);
 
 	return 0;
 }
@@ -415,6 +402,44 @@ s32 ixgbe_start_mac_link_82599(struct ixgbe_hw *hw,
 	return status;
 }
 
+ /**
+  *  ixgbe_disable_tx_laser_multispeed_fiber - Disable Tx laser
+  *  @hw: pointer to hardware structure
+  *
+  *  The base drivers may require better control over SFP+ module
+  *  PHY states.  This includes selectively shutting down the Tx
+  *  laser on the PHY, effectively halting physical link.
+  **/
+void ixgbe_disable_tx_laser_multispeed_fiber(struct ixgbe_hw *hw)
+{
+	u32 esdp_reg = IXGBE_READ_REG(hw, IXGBE_ESDP);
+
+	/* Disable tx laser; allow 100us to go dark per spec */
+	esdp_reg |= IXGBE_ESDP_SDP3;
+	IXGBE_WRITE_REG(hw, IXGBE_ESDP, esdp_reg);
+	IXGBE_WRITE_FLUSH(hw);
+	udelay(100);
+}
+
+/**
+ *  ixgbe_enable_tx_laser_multispeed_fiber - Enable Tx laser
+ *  @hw: pointer to hardware structure
+ *
+ *  The base drivers may require better control over SFP+ module
+ *  PHY states.  This includes selectively turning on the Tx
+ *  laser on the PHY, effectively starting physical link.
+ **/
+void ixgbe_enable_tx_laser_multispeed_fiber(struct ixgbe_hw *hw)
+{
+	u32 esdp_reg = IXGBE_READ_REG(hw, IXGBE_ESDP);
+
+	/* Enable tx laser; allow 100ms to light up */
+	esdp_reg &= ~IXGBE_ESDP_SDP3;
+	IXGBE_WRITE_REG(hw, IXGBE_ESDP, esdp_reg);
+	IXGBE_WRITE_FLUSH(hw);
+	msleep(100);
+}
+
 /**
  *  ixgbe_flap_tx_laser_multispeed_fiber - Flap Tx laser
  *  @hw: pointer to hardware structure
@@ -429,23 +454,11 @@ s32 ixgbe_start_mac_link_82599(struct ixgbe_hw *hw,
  **/
 void ixgbe_flap_tx_laser_multispeed_fiber(struct ixgbe_hw *hw)
 {
-	u32 esdp_reg = IXGBE_READ_REG(hw, IXGBE_ESDP);
-
 	hw_dbg(hw, "ixgbe_flap_tx_laser_multispeed_fiber\n");
 
 	if (hw->mac.autotry_restart) {
-		/* Disable tx laser; allow 100us to go dark per spec */
-		esdp_reg |= IXGBE_ESDP_SDP3;
-		IXGBE_WRITE_REG(hw, IXGBE_ESDP, esdp_reg);
-		IXGBE_WRITE_FLUSH(hw);
-		udelay(100);
-
-		/* Enable tx laser; allow 100ms to light up */
-		esdp_reg &= ~IXGBE_ESDP_SDP3;
-		IXGBE_WRITE_REG(hw, IXGBE_ESDP, esdp_reg);
-		IXGBE_WRITE_FLUSH(hw);
-		msleep(100);
-
+		ixgbe_disable_tx_laser_multispeed_fiber(hw);
+		ixgbe_enable_tx_laser_multispeed_fiber(hw);
 		hw->mac.autotry_restart = false;
 	}
 }
@@ -608,6 +621,7 @@ static s32 ixgbe_setup_mac_link_smartspeed(struct ixgbe_hw *hw,
 	s32 i, j;
 	bool link_up = false;
 	u32 autoc_reg = IXGBE_READ_REG(hw, IXGBE_AUTOC);
+	struct ixgbe_adapter *adapter = hw->back;
 
 	hw_dbg(hw, "ixgbe_setup_mac_link_smartspeed.\n");
 
@@ -692,64 +706,13 @@ static s32 ixgbe_setup_mac_link_smartspeed(struct ixgbe_hw *hw,
 					    autoneg_wait_to_complete);
 
 out:
+	if (link_up && (link_speed == IXGBE_LINK_SPEED_1GB_FULL))
+		e_info("Smartspeed has downgraded the link speed from "
+		       "the maximum advertised\n");
 	return status;
 }
 
 /**
- *  ixgbe_check_mac_link_82599 - Determine link and speed status
- *  @hw: pointer to hardware structure
- *  @speed: pointer to link speed
- *  @link_up: true when link is up
- *  @link_up_wait_to_complete: bool used to wait for link up or not
- *
- *  Reads the links register to determine if link is up and the current speed
- **/
-static s32 ixgbe_check_mac_link_82599(struct ixgbe_hw *hw,
-                                      ixgbe_link_speed *speed,
-                                      bool *link_up,
-                                      bool link_up_wait_to_complete)
-{
-	u32 links_reg;
-	u32 i;
-
-	links_reg = IXGBE_READ_REG(hw, IXGBE_LINKS);
-	if (link_up_wait_to_complete) {
-		for (i = 0; i < IXGBE_LINK_UP_TIME; i++) {
-			if (links_reg & IXGBE_LINKS_UP) {
-				*link_up = true;
-				break;
-			} else {
-				*link_up = false;
-			}
-			msleep(100);
-			links_reg = IXGBE_READ_REG(hw, IXGBE_LINKS);
-		}
-	} else {
-		if (links_reg & IXGBE_LINKS_UP)
-			*link_up = true;
-		else
-			*link_up = false;
-	}
-
-	if ((links_reg & IXGBE_LINKS_SPEED_82599) ==
-	    IXGBE_LINKS_SPEED_10G_82599)
-		*speed = IXGBE_LINK_SPEED_10GB_FULL;
-	else if ((links_reg & IXGBE_LINKS_SPEED_82599) ==
-	         IXGBE_LINKS_SPEED_1G_82599)
-		*speed = IXGBE_LINK_SPEED_1GB_FULL;
-	else
-		*speed = IXGBE_LINK_SPEED_100_FULL;
-
-	/* if link is down, zero out the current_mode */
-	if (*link_up == false) {
-		hw->fc.current_mode = ixgbe_fc_none;
-		hw->fc.fc_was_autonegged = false;
-	}
-
-	return 0;
-}
-
-/**
  *  ixgbe_setup_mac_link_82599 - Set MAC link speed
  *  @hw: pointer to hardware structure
  *  @speed: new link speed
@@ -1011,243 +974,6 @@ reset_hw_out:
 }
 
 /**
- *  ixgbe_clear_vmdq_82599 - Disassociate a VMDq pool index from a rx address
- *  @hw: pointer to hardware struct
- *  @rar: receive address register index to disassociate
- *  @vmdq: VMDq pool index to remove from the rar
- **/
-static s32 ixgbe_clear_vmdq_82599(struct ixgbe_hw *hw, u32 rar, u32 vmdq)
-{
-	u32 mpsar_lo, mpsar_hi;
-	u32 rar_entries = hw->mac.num_rar_entries;
-
-	if (rar < rar_entries) {
-		mpsar_lo = IXGBE_READ_REG(hw, IXGBE_MPSAR_LO(rar));
-		mpsar_hi = IXGBE_READ_REG(hw, IXGBE_MPSAR_HI(rar));
-
-		if (!mpsar_lo && !mpsar_hi)
-			goto done;
-
-		if (vmdq == IXGBE_CLEAR_VMDQ_ALL) {
-			if (mpsar_lo) {
-				IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(rar), 0);
-				mpsar_lo = 0;
-			}
-			if (mpsar_hi) {
-				IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(rar), 0);
-				mpsar_hi = 0;
-			}
-		} else if (vmdq < 32) {
-			mpsar_lo &= ~(1 << vmdq);
-			IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(rar), mpsar_lo);
-		} else {
-			mpsar_hi &= ~(1 << (vmdq - 32));
-			IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(rar), mpsar_hi);
-		}
-
-		/* was that the last pool using this rar? */
-		if (mpsar_lo == 0 && mpsar_hi == 0 && rar != 0)
-			hw->mac.ops.clear_rar(hw, rar);
-	} else {
-		hw_dbg(hw, "RAR index %d is out of range.\n", rar);
-	}
-
-done:
-	return 0;
-}
-
-/**
- *  ixgbe_set_vmdq_82599 - Associate a VMDq pool index with a rx address
- *  @hw: pointer to hardware struct
- *  @rar: receive address register index to associate with a VMDq index
- *  @vmdq: VMDq pool index
- **/
-static s32 ixgbe_set_vmdq_82599(struct ixgbe_hw *hw, u32 rar, u32 vmdq)
-{
-	u32 mpsar;
-	u32 rar_entries = hw->mac.num_rar_entries;
-
-	if (rar < rar_entries) {
-		if (vmdq < 32) {
-			mpsar = IXGBE_READ_REG(hw, IXGBE_MPSAR_LO(rar));
-			mpsar |= 1 << vmdq;
-			IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(rar), mpsar);
-		} else {
-			mpsar = IXGBE_READ_REG(hw, IXGBE_MPSAR_HI(rar));
-			mpsar |= 1 << (vmdq - 32);
-			IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(rar), mpsar);
-		}
-	} else {
-		hw_dbg(hw, "RAR index %d is out of range.\n", rar);
-	}
-	return 0;
-}
-
-/**
- *  ixgbe_set_vfta_82599 - Set VLAN filter table
- *  @hw: pointer to hardware structure
- *  @vlan: VLAN id to write to VLAN filter
- *  @vind: VMDq output index that maps queue to VLAN id in VFVFB
- *  @vlan_on: boolean flag to turn on/off VLAN in VFVF
- *
- *  Turn on/off specified VLAN in the VLAN filter table.
- **/
-static s32 ixgbe_set_vfta_82599(struct ixgbe_hw *hw, u32 vlan, u32 vind,
-                                bool vlan_on)
-{
-	u32 regindex;
-	u32 vlvf_index;
-	u32 bitindex;
-	u32 bits;
-	u32 first_empty_slot;
-	u32 vt_ctl;
-
-	if (vlan > 4095)
-		return IXGBE_ERR_PARAM;
-
-	/*
-	 * this is a 2 part operation - first the VFTA, then the
-	 * VLVF and VLVFB if vind is set
-	 */
-
-	/* Part 1
-	 * The VFTA is a bitstring made up of 128 32-bit registers
-	 * that enable the particular VLAN id, much like the MTA:
-	 *    bits[11-5]: which register
-	 *    bits[4-0]:  which bit in the register
-	 */
-	regindex = (vlan >> 5) & 0x7F;
-	bitindex = vlan & 0x1F;
-	bits = IXGBE_READ_REG(hw, IXGBE_VFTA(regindex));
-	if (vlan_on)
-		bits |= (1 << bitindex);
-	else
-		bits &= ~(1 << bitindex);
-	IXGBE_WRITE_REG(hw, IXGBE_VFTA(regindex), bits);
-
-
-	/* Part 2
-	 * If VT mode is set
-	 *   Either vlan_on
-	 *     make sure the vlan is in VLVF
-	 *     set the vind bit in the matching VLVFB
-	 *   Or !vlan_on
-	 *     clear the pool bit and possibly the vind
-	 */
-	vt_ctl = IXGBE_READ_REG(hw, IXGBE_VT_CTL);
-	if (!(vt_ctl & IXGBE_VT_CTL_VT_ENABLE))
-		goto out;
-
-	/* find the vlanid or the first empty slot */
-	first_empty_slot = 0;
-
-	for (vlvf_index = 1; vlvf_index < IXGBE_VLVF_ENTRIES; vlvf_index++) {
-		bits = IXGBE_READ_REG(hw, IXGBE_VLVF(vlvf_index));
-		if (!bits && !first_empty_slot)
-			first_empty_slot = vlvf_index;
-		else if ((bits & 0x0FFF) == vlan)
-			break;
-	}
-
-	if (vlvf_index >= IXGBE_VLVF_ENTRIES) {
-		if (first_empty_slot)
-			vlvf_index = first_empty_slot;
-		else {
-			hw_dbg(hw, "No space in VLVF.\n");
-			goto out;
-		}
-	}
-
-	if (vlan_on) {
-		/* set the pool bit */
-		if (vind < 32) {
-			bits = IXGBE_READ_REG(hw,
-					      IXGBE_VLVFB(vlvf_index * 2));
-			bits |= (1 << vind);
-			IXGBE_WRITE_REG(hw,
-					IXGBE_VLVFB(vlvf_index * 2), bits);
-		} else {
-			bits = IXGBE_READ_REG(hw,
-				IXGBE_VLVFB((vlvf_index * 2) + 1));
-			bits |= (1 << (vind - 32));
-			IXGBE_WRITE_REG(hw,
-				IXGBE_VLVFB((vlvf_index * 2) + 1), bits);
-		}
-	} else {
-		/* clear the pool bit */
-		if (vind < 32) {
-			bits = IXGBE_READ_REG(hw,
-					      IXGBE_VLVFB(vlvf_index * 2));
-			bits &= ~(1 << vind);
-			IXGBE_WRITE_REG(hw,
-					IXGBE_VLVFB(vlvf_index * 2), bits);
-			bits |= IXGBE_READ_REG(hw,
-					IXGBE_VLVFB((vlvf_index * 2) + 1));
-		} else {
-			bits = IXGBE_READ_REG(hw,
-				IXGBE_VLVFB((vlvf_index * 2) + 1));
-			bits &= ~(1 << (vind - 32));
-			IXGBE_WRITE_REG(hw,
-				IXGBE_VLVFB((vlvf_index * 2) + 1), bits);
-			bits |= IXGBE_READ_REG(hw,
-					       IXGBE_VLVFB(vlvf_index * 2));
-		}
-	}
-
-	if (bits) {
-		IXGBE_WRITE_REG(hw, IXGBE_VLVF(vlvf_index),
-				(IXGBE_VLVF_VIEN | vlan));
-		/* if bits is non-zero then some pools/VFs are still
-		 * using this VLAN ID.  Force the VFTA entry to on */
-		bits = IXGBE_READ_REG(hw, IXGBE_VFTA(regindex));
-		bits |= (1 << bitindex);
-		IXGBE_WRITE_REG(hw, IXGBE_VFTA(regindex), bits);
-	}
-	else
-		IXGBE_WRITE_REG(hw, IXGBE_VLVF(vlvf_index), 0);
-
-out:
-	return 0;
-}
-
-/**
- *  ixgbe_clear_vfta_82599 - Clear VLAN filter table
- *  @hw: pointer to hardware structure
- *
- *  Clears the VLAN filer table, and the VMDq index associated with the filter
- **/
-static s32 ixgbe_clear_vfta_82599(struct ixgbe_hw *hw)
-{
-	u32 offset;
-
-	for (offset = 0; offset < hw->mac.vft_size; offset++)
-		IXGBE_WRITE_REG(hw, IXGBE_VFTA(offset), 0);
-
-	for (offset = 0; offset < IXGBE_VLVF_ENTRIES; offset++) {
-		IXGBE_WRITE_REG(hw, IXGBE_VLVF(offset), 0);
-		IXGBE_WRITE_REG(hw, IXGBE_VLVFB(offset * 2), 0);
-		IXGBE_WRITE_REG(hw, IXGBE_VLVFB((offset * 2) + 1), 0);
-	}
-
-	return 0;
-}
-
-/**
- *  ixgbe_init_uta_tables_82599 - Initialize the Unicast Table Array
- *  @hw: pointer to hardware structure
- **/
-static s32 ixgbe_init_uta_tables_82599(struct ixgbe_hw *hw)
-{
-	int i;
-	hw_dbg(hw, " Clearing UTA\n");
-
-	for (i = 0; i < 128; i++)
-		IXGBE_WRITE_REG(hw, IXGBE_UTA(i), 0);
-
-	return 0;
-}
-
-/**
  *  ixgbe_reinit_fdir_tables_82599 - Reinitialize Flow Director tables.
  *  @hw: pointer to hardware structure
  **/
@@ -2428,10 +2154,14 @@ sfp_check:
 		goto out;
 
 	switch (hw->phy.type) {
-	case ixgbe_phy_tw_tyco:
-	case ixgbe_phy_tw_unknown:
+	case ixgbe_phy_sfp_passive_tyco:
+	case ixgbe_phy_sfp_passive_unknown:
 		physical_layer = IXGBE_PHYSICAL_LAYER_SFP_PLUS_CU;
 		break;
+	case ixgbe_phy_sfp_ftl_active:
+	case ixgbe_phy_sfp_active_unknown:
+		physical_layer = IXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA;
+		break;
 	case ixgbe_phy_sfp_avago:
 	case ixgbe_phy_sfp_ftl:
 	case ixgbe_phy_sfp_intel:
@@ -2511,75 +2241,6 @@ static s32 ixgbe_get_device_caps_82599(struct ixgbe_hw *hw, u16 *device_caps)
 }
 
 /**
- *  ixgbe_get_san_mac_addr_offset_82599 - SAN MAC address offset for 82599
- *  @hw: pointer to hardware structure
- *  @san_mac_offset: SAN MAC address offset
- *
- *  This function will read the EEPROM location for the SAN MAC address
- *  pointer, and returns the value at that location.  This is used in both
- *  get and set mac_addr routines.
- **/
-static s32 ixgbe_get_san_mac_addr_offset_82599(struct ixgbe_hw *hw,
-                                               u16 *san_mac_offset)
-{
-	/*
-	 * First read the EEPROM pointer to see if the MAC addresses are
-	 * available.
-	 */
-	hw->eeprom.ops.read(hw, IXGBE_SAN_MAC_ADDR_PTR, san_mac_offset);
-
-	return 0;
-}
-
-/**
- *  ixgbe_get_san_mac_addr_82599 - SAN MAC address retrieval for 82599
- *  @hw: pointer to hardware structure
- *  @san_mac_addr: SAN MAC address
- *
- *  Reads the SAN MAC address from the EEPROM, if it's available.  This is
- *  per-port, so set_lan_id() must be called before reading the addresses.
- *  set_lan_id() is called by identify_sfp(), but this cannot be relied
- *  upon for non-SFP connections, so we must call it here.
- **/
-static s32 ixgbe_get_san_mac_addr_82599(struct ixgbe_hw *hw, u8 *san_mac_addr)
-{
-	u16 san_mac_data, san_mac_offset;
-	u8 i;
-
-	/*
-	 * First read the EEPROM pointer to see if the MAC addresses are
-	 * available.  If they're not, no point in calling set_lan_id() here.
-	 */
-	ixgbe_get_san_mac_addr_offset_82599(hw, &san_mac_offset);
-
-	if ((san_mac_offset == 0) || (san_mac_offset == 0xFFFF)) {
-		/*
-		 * No addresses available in this EEPROM.  It's not an
-		 * error though, so just wipe the local address and return.
-		 */
-		for (i = 0; i < 6; i++)
-			san_mac_addr[i] = 0xFF;
-
-		goto san_mac_addr_out;
-	}
-
-	/* make sure we know which port we need to program */
-	hw->mac.ops.set_lan_id(hw);
-	/* apply the port offset to the address offset */
-	(hw->bus.func) ? (san_mac_offset += IXGBE_SAN_MAC_ADDR_PORT1_OFFSET) :
-	                 (san_mac_offset += IXGBE_SAN_MAC_ADDR_PORT0_OFFSET);
-	for (i = 0; i < 3; i++) {
-		hw->eeprom.ops.read(hw, san_mac_offset, &san_mac_data);
-		san_mac_addr[i * 2] = (u8)(san_mac_data);
-		san_mac_addr[i * 2 + 1] = (u8)(san_mac_data >> 8);
-		san_mac_offset++;
-	}
-
-san_mac_addr_out:
-	return 0;
-}
-
-/**
  *  ixgbe_verify_fw_version_82599 - verify fw version for 82599
  *  @hw: pointer to hardware structure
  *
@@ -2681,7 +2342,7 @@ static struct ixgbe_mac_operations mac_ops_82599 = {
 	.get_supported_physical_layer = &ixgbe_get_supported_physical_layer_82599,
 	.enable_rx_dma          = &ixgbe_enable_rx_dma_82599,
 	.get_mac_addr           = &ixgbe_get_mac_addr_generic,
-	.get_san_mac_addr       = &ixgbe_get_san_mac_addr_82599,
+	.get_san_mac_addr       = &ixgbe_get_san_mac_addr_generic,
 	.get_device_caps        = &ixgbe_get_device_caps_82599,
 	.get_wwn_prefix         = &ixgbe_get_wwn_prefix_82599,
 	.stop_adapter           = &ixgbe_stop_adapter_generic,
@@ -2690,7 +2351,7 @@ static struct ixgbe_mac_operations mac_ops_82599 = {
 	.read_analog_reg8       = &ixgbe_read_analog_reg8_82599,
 	.write_analog_reg8      = &ixgbe_write_analog_reg8_82599,
 	.setup_link             = &ixgbe_setup_mac_link_82599,
-	.check_link             = &ixgbe_check_mac_link_82599,
+	.check_link             = &ixgbe_check_mac_link_generic,
 	.get_link_capabilities  = &ixgbe_get_link_capabilities_82599,
 	.led_on                 = &ixgbe_led_on_generic,
 	.led_off                = &ixgbe_led_off_generic,
@@ -2698,23 +2359,23 @@ static struct ixgbe_mac_operations mac_ops_82599 = {
 	.blink_led_stop         = &ixgbe_blink_led_stop_generic,
 	.set_rar                = &ixgbe_set_rar_generic,
 	.clear_rar              = &ixgbe_clear_rar_generic,
-	.set_vmdq               = &ixgbe_set_vmdq_82599,
-	.clear_vmdq             = &ixgbe_clear_vmdq_82599,
+	.set_vmdq               = &ixgbe_set_vmdq_generic,
+	.clear_vmdq             = &ixgbe_clear_vmdq_generic,
 	.init_rx_addrs          = &ixgbe_init_rx_addrs_generic,
 	.update_uc_addr_list    = &ixgbe_update_uc_addr_list_generic,
 	.update_mc_addr_list    = &ixgbe_update_mc_addr_list_generic,
 	.enable_mc              = &ixgbe_enable_mc_generic,
 	.disable_mc             = &ixgbe_disable_mc_generic,
-	.clear_vfta             = &ixgbe_clear_vfta_82599,
-	.set_vfta               = &ixgbe_set_vfta_82599,
-	.fc_enable               = &ixgbe_fc_enable_generic,
-	.init_uta_tables        = &ixgbe_init_uta_tables_82599,
+	.clear_vfta             = &ixgbe_clear_vfta_generic,
+	.set_vfta               = &ixgbe_set_vfta_generic,
+	.fc_enable              = &ixgbe_fc_enable_generic,
+	.init_uta_tables        = &ixgbe_init_uta_tables_generic,
 	.setup_sfp              = &ixgbe_setup_sfp_modules_82599,
 };
 
 static struct ixgbe_eeprom_operations eeprom_ops_82599 = {
 	.init_params            = &ixgbe_init_eeprom_params_generic,
-	.read                   = &ixgbe_read_eeprom_generic,
+	.read                   = &ixgbe_read_eerd_generic,
 	.write                  = &ixgbe_write_eeprom_generic,
 	.validate_checksum      = &ixgbe_validate_eeprom_checksum_generic,
 	.update_checksum        = &ixgbe_update_eeprom_checksum_generic,
@@ -2723,7 +2384,7 @@ static struct ixgbe_eeprom_operations eeprom_ops_82599 = {
 static struct ixgbe_phy_operations phy_ops_82599 = {
 	.identify               = &ixgbe_identify_phy_82599,
 	.identify_sfp           = &ixgbe_identify_sfp_module_generic,
-	.init			= &ixgbe_init_phy_ops_82599,
+	.init			            = &ixgbe_init_phy_ops_82599,
 	.reset                  = &ixgbe_reset_phy_generic,
 	.read_reg               = &ixgbe_read_phy_reg_generic,
 	.write_reg              = &ixgbe_write_phy_reg_generic,
@@ -2733,6 +2394,7 @@ static struct ixgbe_phy_operations phy_ops_82599 = {
 	.write_i2c_byte         = &ixgbe_write_i2c_byte_generic,
 	.read_i2c_eeprom        = &ixgbe_read_i2c_eeprom_generic,
 	.write_i2c_eeprom       = &ixgbe_write_i2c_eeprom_generic,
+	.check_overtemp         = &ixgbe_tn_check_overtemp,
 };
 
 struct ixgbe_info ixgbe_82599_info = {
diff --git a/drivers/net/ixgbe/ixgbe_common.c b/drivers/net/ixgbe/ixgbe_common.c
index d240637..334d857 100644
--- a/drivers/net/ixgbe/ixgbe_common.c
+++ b/drivers/net/ixgbe/ixgbe_common.c
@@ -34,7 +34,6 @@
 #include "ixgbe_common.h"
 #include "ixgbe_phy.h"
 
-static s32 ixgbe_poll_eeprom_eerd_done(struct ixgbe_hw *hw);
 static s32 ixgbe_acquire_eeprom(struct ixgbe_hw *hw);
 static s32 ixgbe_get_eeprom_semaphore(struct ixgbe_hw *hw);
 static void ixgbe_release_eeprom_semaphore(struct ixgbe_hw *hw);
@@ -595,14 +594,14 @@ out:
 }
 
 /**
- *  ixgbe_read_eeprom_generic - Read EEPROM word using EERD
+ *  ixgbe_read_eerd_generic - Read EEPROM word using EERD
  *  @hw: pointer to hardware structure
  *  @offset: offset of  word in the EEPROM to read
  *  @data: word read from the EEPROM
  *
  *  Reads a 16 bit word from the EEPROM using the EERD register.
  **/
-s32 ixgbe_read_eeprom_generic(struct ixgbe_hw *hw, u16 offset, u16 *data)
+s32 ixgbe_read_eerd_generic(struct ixgbe_hw *hw, u16 offset, u16 *data)
 {
 	u32 eerd;
 	s32 status;
@@ -614,15 +613,15 @@ s32 ixgbe_read_eeprom_generic(struct ixgbe_hw *hw, u16 offset, u16 *data)
 		goto out;
 	}
 
-	eerd = (offset << IXGBE_EEPROM_READ_ADDR_SHIFT) +
-	       IXGBE_EEPROM_READ_REG_START;
+	eerd = (offset << IXGBE_EEPROM_RW_ADDR_SHIFT) +
+	       IXGBE_EEPROM_RW_REG_START;
 
 	IXGBE_WRITE_REG(hw, IXGBE_EERD, eerd);
-	status = ixgbe_poll_eeprom_eerd_done(hw);
+	status = ixgbe_poll_eerd_eewr_done(hw, IXGBE_NVM_POLL_READ);
 
 	if (status == 0)
 		*data = (IXGBE_READ_REG(hw, IXGBE_EERD) >>
-		         IXGBE_EEPROM_READ_REG_DATA);
+		         IXGBE_EEPROM_RW_REG_DATA);
 	else
 		hw_dbg(hw, "Eeprom read timed out\n");
 
@@ -631,20 +630,26 @@ out:
 }
 
 /**
- *  ixgbe_poll_eeprom_eerd_done - Poll EERD status
+ *  ixgbe_poll_eerd_eewr_done - Poll EERD read or EEWR write status
  *  @hw: pointer to hardware structure
+ *  @ee_reg: EEPROM flag for polling
  *
- *  Polls the status bit (bit 1) of the EERD to determine when the read is done.
+ *  Polls the status bit (bit 1) of the EERD or EEWR to determine when the
+ *  read or write is done respectively.
  **/
-static s32 ixgbe_poll_eeprom_eerd_done(struct ixgbe_hw *hw)
+s32 ixgbe_poll_eerd_eewr_done(struct ixgbe_hw *hw, u32 ee_reg)
 {
 	u32 i;
 	u32 reg;
 	s32 status = IXGBE_ERR_EEPROM;
 
-	for (i = 0; i < IXGBE_EERD_ATTEMPTS; i++) {
-		reg = IXGBE_READ_REG(hw, IXGBE_EERD);
-		if (reg & IXGBE_EEPROM_READ_REG_DONE) {
+	for (i = 0; i < IXGBE_EERD_EEWR_ATTEMPTS; i++) {
+		if (ee_reg == IXGBE_NVM_POLL_READ)
+			reg = IXGBE_READ_REG(hw, IXGBE_EERD);
+		else
+			reg = IXGBE_READ_REG(hw, IXGBE_EEWR);
+
+		if (reg & IXGBE_EEPROM_RW_REG_DONE) {
 			status = 0;
 			break;
 		}
@@ -1183,6 +1188,7 @@ s32 ixgbe_set_rar_generic(struct ixgbe_hw *hw, u32 index, u8 *addr, u32 vmdq,
 		IXGBE_WRITE_REG(hw, IXGBE_RAH(index), rar_high);
 	} else {
 		hw_dbg(hw, "RAR index %d is out of range.\n", index);
+		return IXGBE_ERR_RAR_INDEX;
 	}
 
 	return 0;
@@ -1214,6 +1220,7 @@ s32 ixgbe_clear_rar_generic(struct ixgbe_hw *hw, u32 index)
 		IXGBE_WRITE_REG(hw, IXGBE_RAH(index), rar_high);
 	} else {
 		hw_dbg(hw, "RAR index %d is out of range.\n", index);
+		return IXGBE_ERR_RAR_INDEX;
 	}
 
 	/* clear VMDq pool/queue selection for this RAR */
@@ -1392,14 +1399,17 @@ s32 ixgbe_update_uc_addr_list_generic(struct ixgbe_hw *hw,
 			fctrl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
 			fctrl |= IXGBE_FCTRL_UPE;
 			IXGBE_WRITE_REG(hw, IXGBE_FCTRL, fctrl);
+			hw->addr_ctrl.uc_set_promisc = true;
 		}
 	} else {
 		/* only disable if set by overflow, not by user */
-		if (old_promisc_setting && !hw->addr_ctrl.user_set_promisc) {
+		if ((old_promisc_setting && hw->addr_ctrl.uc_set_promisc) &&
+		   !(hw->addr_ctrl.user_set_promisc)) {
 			hw_dbg(hw, " Leaving address overflow promisc mode\n");
 			fctrl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
 			fctrl &= ~IXGBE_FCTRL_UPE;
 			IXGBE_WRITE_REG(hw, IXGBE_FCTRL, fctrl);
+			hw->addr_ctrl.uc_set_promisc = false;
 		}
 	}
 
@@ -2254,3 +2264,490 @@ s32 ixgbe_blink_led_stop_generic(struct ixgbe_hw *hw, u32 index)
 
 	return 0;
 }
+
+/**
+ *  ixgbe_get_san_mac_addr_offset - Get SAN MAC address offset from the EEPROM
+ *  @hw: pointer to hardware structure
+ *  @san_mac_offset: SAN MAC address offset
+ *
+ *  This function will read the EEPROM location for the SAN MAC address
+ *  pointer, and returns the value at that location.  This is used in both
+ *  get and set mac_addr routines.
+ **/
+static s32 ixgbe_get_san_mac_addr_offset(struct ixgbe_hw *hw,
+                                        u16 *san_mac_offset)
+{
+	/*
+	 * First read the EEPROM pointer to see if the MAC addresses are
+	 * available.
+	 */
+	hw->eeprom.ops.read(hw, IXGBE_SAN_MAC_ADDR_PTR, san_mac_offset);
+
+	return 0;
+}
+
+/**
+ *  ixgbe_get_san_mac_addr_generic - SAN MAC address retrieval from the EEPROM
+ *  @hw: pointer to hardware structure
+ *  @san_mac_addr: SAN MAC address
+ *
+ *  Reads the SAN MAC address from the EEPROM, if it's available.  This is
+ *  per-port, so set_lan_id() must be called before reading the addresses.
+ *  set_lan_id() is called by identify_sfp(), but this cannot be relied
+ *  upon for non-SFP connections, so we must call it here.
+ **/
+s32 ixgbe_get_san_mac_addr_generic(struct ixgbe_hw *hw, u8 *san_mac_addr)
+{
+	u16 san_mac_data, san_mac_offset;
+	u8 i;
+
+	/*
+	 * First read the EEPROM pointer to see if the MAC addresses are
+	 * available.  If they're not, no point in calling set_lan_id() here.
+	 */
+	ixgbe_get_san_mac_addr_offset(hw, &san_mac_offset);
+
+	if ((san_mac_offset == 0) || (san_mac_offset == 0xFFFF)) {
+		/*
+		 * No addresses available in this EEPROM.  It's not an
+		 * error though, so just wipe the local address and return.
+		 */
+		for (i = 0; i < 6; i++)
+			san_mac_addr[i] = 0xFF;
+
+		goto san_mac_addr_out;
+	}
+
+	/* make sure we know which port we need to program */
+	hw->mac.ops.set_lan_id(hw);
+	/* apply the port offset to the address offset */
+	(hw->bus.func) ? (san_mac_offset += IXGBE_SAN_MAC_ADDR_PORT1_OFFSET) :
+	                 (san_mac_offset += IXGBE_SAN_MAC_ADDR_PORT0_OFFSET);
+	for (i = 0; i < 3; i++) {
+		hw->eeprom.ops.read(hw, san_mac_offset, &san_mac_data);
+		san_mac_addr[i * 2] = (u8)(san_mac_data);
+		san_mac_addr[i * 2 + 1] = (u8)(san_mac_data >> 8);
+		san_mac_offset++;
+	}
+
+san_mac_addr_out:
+	return 0;
+}
+
+/**
+ *  ixgbe_get_pcie_msix_count_generic - Gets MSI-X vector count
+ *  @hw: pointer to hardware structure
+ *
+ *  Read PCIe configuration space, and get the MSI-X vector count from
+ *  the capabilities table.
+ **/
+u32 ixgbe_get_pcie_msix_count_generic(struct ixgbe_hw *hw)
+{
+	struct ixgbe_adapter *adapter = hw->back;
+	u16 msix_count;
+	pci_read_config_word(adapter->pdev, IXGBE_PCIE_MSIX_82599_CAPS,
+	                     &msix_count);
+	msix_count &= IXGBE_PCIE_MSIX_TBL_SZ_MASK;
+
+	/* MSI-X count is zero-based in HW, so increment to give proper value */
+	msix_count++;
+
+	return msix_count;
+}
+
+/**
+ *  ixgbe_clear_vmdq_generic - Disassociate a VMDq pool index from a rx address
+ *  @hw: pointer to hardware struct
+ *  @rar: receive address register index to disassociate
+ *  @vmdq: VMDq pool index to remove from the rar
+ **/
+s32 ixgbe_clear_vmdq_generic(struct ixgbe_hw *hw, u32 rar, u32 vmdq)
+{
+	u32 mpsar_lo, mpsar_hi;
+	u32 rar_entries = hw->mac.num_rar_entries;
+
+	if (rar < rar_entries) {
+		mpsar_lo = IXGBE_READ_REG(hw, IXGBE_MPSAR_LO(rar));
+		mpsar_hi = IXGBE_READ_REG(hw, IXGBE_MPSAR_HI(rar));
+
+		if (!mpsar_lo && !mpsar_hi)
+			goto done;
+
+		if (vmdq == IXGBE_CLEAR_VMDQ_ALL) {
+			if (mpsar_lo) {
+				IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(rar), 0);
+				mpsar_lo = 0;
+			}
+			if (mpsar_hi) {
+				IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(rar), 0);
+				mpsar_hi = 0;
+			}
+		} else if (vmdq < 32) {
+			mpsar_lo &= ~(1 << vmdq);
+			IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(rar), mpsar_lo);
+		} else {
+			mpsar_hi &= ~(1 << (vmdq - 32));
+			IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(rar), mpsar_hi);
+		}
+
+		/* was that the last pool using this rar? */
+		if (mpsar_lo == 0 && mpsar_hi == 0 && rar != 0)
+			hw->mac.ops.clear_rar(hw, rar);
+	} else {
+		hw_dbg(hw, "RAR index %d is out of range.\n", rar);
+	}
+
+done:
+	return 0;
+}
+
+/**
+ *  ixgbe_set_vmdq_generic - Associate a VMDq pool index with a rx address
+ *  @hw: pointer to hardware struct
+ *  @rar: receive address register index to associate with a VMDq index
+ *  @vmdq: VMDq pool index
+ **/
+s32 ixgbe_set_vmdq_generic(struct ixgbe_hw *hw, u32 rar, u32 vmdq)
+{
+	u32 mpsar;
+	u32 rar_entries = hw->mac.num_rar_entries;
+
+	if (rar < rar_entries) {
+		if (vmdq < 32) {
+			mpsar = IXGBE_READ_REG(hw, IXGBE_MPSAR_LO(rar));
+			mpsar |= 1 << vmdq;
+			IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(rar), mpsar);
+		} else {
+			mpsar = IXGBE_READ_REG(hw, IXGBE_MPSAR_HI(rar));
+			mpsar |= 1 << (vmdq - 32);
+			IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(rar), mpsar);
+		}
+	} else {
+		hw_dbg(hw, "RAR index %d is out of range.\n", rar);
+	}
+	return 0;
+}
+
+/**
+ *  ixgbe_init_uta_tables_generic - Initialize the Unicast Table Array
+ *  @hw: pointer to hardware structure
+ **/
+s32 ixgbe_init_uta_tables_generic(struct ixgbe_hw *hw)
+{
+	int i;
+
+
+	for (i = 0; i < 128; i++)
+		IXGBE_WRITE_REG(hw, IXGBE_UTA(i), 0);
+
+	return 0;
+}
+
+/**
+ *  ixgbe_find_vlvf_slot - find the vlanid or the first empty slot
+ *  @hw: pointer to hardware structure
+ *  @vlan: VLAN id to write to VLAN filter
+ *
+ *  return the VLVF index where this VLAN id should be placed
+ *
+ **/
+s32 ixgbe_find_vlvf_slot(struct ixgbe_hw *hw, u32 vlan)
+{
+	u32 bits = 0;
+	u32 first_empty_slot = 0;
+	s32 regindex;
+
+	/* short cut the special case */
+	if (vlan == 0)
+		return 0;
+
+	/*
+	  * Search for the vlan id in the VLVF entries. Save off the first empty
+	  * slot found along the way
+	  */
+	for (regindex = 1; regindex < IXGBE_VLVF_ENTRIES; regindex++) {
+		bits = IXGBE_READ_REG(hw, IXGBE_VLVF(regindex));
+		if (!bits && !(first_empty_slot))
+			first_empty_slot = regindex;
+		else if ((bits & 0x0FFF) == vlan)
+			break;
+	}
+
+	/*
+	  * If regindex is less than IXGBE_VLVF_ENTRIES, then we found the vlan
+	  * in the VLVF. Else use the first empty VLVF register for this
+	  * vlan id.
+	  */
+	if (regindex >= IXGBE_VLVF_ENTRIES) {
+		if (first_empty_slot)
+			regindex = first_empty_slot;
+		else {
+			hw_dbg(hw, "No space in VLVF.\n");
+			regindex = IXGBE_ERR_NO_SPACE;
+		}
+	}
+
+	return regindex;
+}
+
+/**
+ *  ixgbe_set_vfta_generic - Set VLAN filter table
+ *  @hw: pointer to hardware structure
+ *  @vlan: VLAN id to write to VLAN filter
+ *  @vind: VMDq output index that maps queue to VLAN id in VFVFB
+ *  @vlan_on: boolean flag to turn on/off VLAN in VFVF
+ *
+ *  Turn on/off specified VLAN in the VLAN filter table.
+ **/
+s32 ixgbe_set_vfta_generic(struct ixgbe_hw *hw, u32 vlan, u32 vind,
+                           bool vlan_on)
+{
+	s32 regindex;
+	u32 bitindex;
+	u32 vfta;
+	u32 bits;
+	u32 vt;
+	u32 targetbit;
+	bool vfta_changed = false;
+
+	if (vlan > 4095)
+		return IXGBE_ERR_PARAM;
+
+	/*
+	 * this is a 2 part operation - first the VFTA, then the
+	 * VLVF and VLVFB if VT Mode is set
+	 * We don't write the VFTA until we know the VLVF part succeeded.
+	 */
+
+	/* Part 1
+	 * The VFTA is a bitstring made up of 128 32-bit registers
+	 * that enable the particular VLAN id, much like the MTA:
+	 *    bits[11-5]: which register
+	 *    bits[4-0]:  which bit in the register
+	 */
+	regindex = (vlan >> 5) & 0x7F;
+	bitindex = vlan & 0x1F;
+	targetbit = (1 << bitindex);
+	vfta = IXGBE_READ_REG(hw, IXGBE_VFTA(regindex));
+
+	if (vlan_on) {
+		if (!(vfta & targetbit)) {
+			vfta |= targetbit;
+			vfta_changed = true;
+		}
+	} else {
+		if ((vfta & targetbit)) {
+			vfta &= ~targetbit;
+			vfta_changed = true;
+		}
+	}
+
+	/* Part 2
+	 * If VT Mode is set
+	 *   Either vlan_on
+	 *     make sure the vlan is in VLVF
+	 *     set the vind bit in the matching VLVFB
+	 *   Or !vlan_on
+	 *     clear the pool bit and possibly the vind
+	 */
+	vt = IXGBE_READ_REG(hw, IXGBE_VT_CTL);
+	if (vt & IXGBE_VT_CTL_VT_ENABLE) {
+		s32 vlvf_index;
+
+		vlvf_index = ixgbe_find_vlvf_slot(hw, vlan);
+		if (vlvf_index < 0)
+			return vlvf_index;
+
+		if (vlan_on) {
+			/* set the pool bit */
+			if (vind < 32) {
+				bits = IXGBE_READ_REG(hw,
+						IXGBE_VLVFB(vlvf_index*2));
+				bits |= (1 << vind);
+				IXGBE_WRITE_REG(hw,
+						IXGBE_VLVFB(vlvf_index*2),
+						bits);
+			} else {
+				bits = IXGBE_READ_REG(hw,
+						IXGBE_VLVFB((vlvf_index*2)+1));
+				bits |= (1 << (vind-32));
+				IXGBE_WRITE_REG(hw,
+						IXGBE_VLVFB((vlvf_index*2)+1),
+						bits);
+			}
+		} else {
+			/* clear the pool bit */
+			if (vind < 32) {
+				bits = IXGBE_READ_REG(hw,
+						IXGBE_VLVFB(vlvf_index*2));
+				bits &= ~(1 << vind);
+				IXGBE_WRITE_REG(hw,
+						IXGBE_VLVFB(vlvf_index*2),
+						bits);
+				bits |= IXGBE_READ_REG(hw,
+						IXGBE_VLVFB((vlvf_index*2)+1));
+			} else {
+				bits = IXGBE_READ_REG(hw,
+						IXGBE_VLVFB((vlvf_index*2)+1));
+				bits &= ~(1 << (vind-32));
+				IXGBE_WRITE_REG(hw,
+						IXGBE_VLVFB((vlvf_index*2)+1),
+						bits);
+				bits |= IXGBE_READ_REG(hw,
+						IXGBE_VLVFB(vlvf_index*2));
+			}
+		}
+
+		/*
+		 * If there are still bits set in the VLVFB registers
+		 * for the VLAN ID indicated we need to see if the
+		 * caller is requesting that we clear the VFTA entry bit.
+		 * If the caller has requested that we clear the VFTA
+		 * entry bit but there are still pools/VFs using this VLAN
+		 * ID entry then ignore the request.  We're not worried
+		 * about the case where we're turning the VFTA VLAN ID
+		 * entry bit on, only when requested to turn it off as
+		 * there may be multiple pools and/or VFs using the
+		 * VLAN ID entry.  In that case we cannot clear the
+		 * VFTA bit until all pools/VFs using that VLAN ID have also
+		 * been cleared.  This will be indicated by "bits" being
+		 * zero.
+		 */
+		if (bits) {
+			IXGBE_WRITE_REG(hw, IXGBE_VLVF(vlvf_index),
+					(IXGBE_VLVF_VIEN | vlan));
+			if (!vlan_on) {
+				/* someone wants to clear the vfta entry
+				 * but some pools/VFs are still using it.
+				 * Ignore it. */
+				vfta_changed = false;
+			}
+		}
+		else
+			IXGBE_WRITE_REG(hw, IXGBE_VLVF(vlvf_index), 0);
+	}
+
+	if (vfta_changed)
+		IXGBE_WRITE_REG(hw, IXGBE_VFTA(regindex), vfta);
+
+	return 0;
+}
+
+/**
+ *  ixgbe_clear_vfta_generic - Clear VLAN filter table
+ *  @hw: pointer to hardware structure
+ *
+ *  Clears the VLAN filer table, and the VMDq index associated with the filter
+ **/
+s32 ixgbe_clear_vfta_generic(struct ixgbe_hw *hw)
+{
+	u32 offset;
+
+	for (offset = 0; offset < hw->mac.vft_size; offset++)
+		IXGBE_WRITE_REG(hw, IXGBE_VFTA(offset), 0);
+
+	for (offset = 0; offset < IXGBE_VLVF_ENTRIES; offset++) {
+		IXGBE_WRITE_REG(hw, IXGBE_VLVF(offset), 0);
+		IXGBE_WRITE_REG(hw, IXGBE_VLVFB(offset*2), 0);
+		IXGBE_WRITE_REG(hw, IXGBE_VLVFB((offset*2)+1), 0);
+	}
+
+	return 0;
+}
+
+/**
+ *  ixgbe_check_mac_link_generic - Determine link and speed status
+ *  @hw: pointer to hardware structure
+ *  @speed: pointer to link speed
+ *  @link_up: true when link is up
+ *  @link_up_wait_to_complete: bool used to wait for link up or not
+ *
+ *  Reads the links register to determine if link is up and the current speed
+ **/
+s32 ixgbe_check_mac_link_generic(struct ixgbe_hw *hw, ixgbe_link_speed *speed,
+                               bool *link_up, bool link_up_wait_to_complete)
+{
+	u32 links_reg;
+	u32 i;
+
+	links_reg = IXGBE_READ_REG(hw, IXGBE_LINKS);
+	if (link_up_wait_to_complete) {
+		for (i = 0; i < IXGBE_LINK_UP_TIME; i++) {
+			if (links_reg & IXGBE_LINKS_UP) {
+				*link_up = true;
+				break;
+			} else {
+				*link_up = false;
+			}
+			msleep(100);
+			links_reg = IXGBE_READ_REG(hw, IXGBE_LINKS);
+		}
+	} else {
+		if (links_reg & IXGBE_LINKS_UP)
+			*link_up = true;
+		else
+			*link_up = false;
+	}
+
+	if ((links_reg & IXGBE_LINKS_SPEED_82599) ==
+	    IXGBE_LINKS_SPEED_10G_82599)
+		*speed = IXGBE_LINK_SPEED_10GB_FULL;
+	else if ((links_reg & IXGBE_LINKS_SPEED_82599) ==
+	         IXGBE_LINKS_SPEED_1G_82599)
+		*speed = IXGBE_LINK_SPEED_1GB_FULL;
+	else
+		*speed = IXGBE_LINK_SPEED_100_FULL;
+
+	/* if link is down, zero out the current_mode */
+	if (*link_up == false) {
+		hw->fc.current_mode = ixgbe_fc_none;
+		hw->fc.fc_was_autonegged = false;
+	}
+
+	return 0;
+}
+
+/**
+ *  ixgbe_get_wwn_prefix_generic - Get alternative WWNN/WWPN prefix from
+ *  the EEPROM
+ *  @hw: pointer to hardware structure
+ *  @wwnn_prefix: the alternative WWNN prefix
+ *  @wwpn_prefix: the alternative WWPN prefix
+ *
+ *  This function will read the EEPROM from the alternative SAN MAC address
+ *  block to check the support for the alternative WWNN/WWPN prefix support.
+ **/
+s32 ixgbe_get_wwn_prefix_generic(struct ixgbe_hw *hw, u16 *wwnn_prefix,
+                                 u16 *wwpn_prefix)
+{
+	u16 offset, caps;
+	u16 alt_san_mac_blk_offset;
+
+	/* clear output first */
+	*wwnn_prefix = 0xFFFF;
+	*wwpn_prefix = 0xFFFF;
+
+	/* check if alternative SAN MAC is supported */
+	hw->eeprom.ops.read(hw, IXGBE_ALT_SAN_MAC_ADDR_BLK_PTR,
+	                    &alt_san_mac_blk_offset);
+
+	if ((alt_san_mac_blk_offset == 0) ||
+	    (alt_san_mac_blk_offset == 0xFFFF))
+		goto wwn_prefix_out;
+
+	/* check capability in alternative san mac address block */
+	offset = alt_san_mac_blk_offset + IXGBE_ALT_SAN_MAC_ADDR_CAPS_OFFSET;
+	hw->eeprom.ops.read(hw, offset, &caps);
+	if (!(caps & IXGBE_ALT_SAN_MAC_ADDR_CAPS_ALTWWN))
+		goto wwn_prefix_out;
+
+	/* get the corresponding prefix for WWNN/WWPN */
+	offset = alt_san_mac_blk_offset + IXGBE_ALT_SAN_MAC_ADDR_WWNN_OFFSET;
+	hw->eeprom.ops.read(hw, offset, wwnn_prefix);
+
+	offset = alt_san_mac_blk_offset + IXGBE_ALT_SAN_MAC_ADDR_WWPN_OFFSET;
+	hw->eeprom.ops.read(hw, offset, wwpn_prefix);
+
+wwn_prefix_out:
+	return 0;
+}
diff --git a/drivers/net/ixgbe/ixgbe_common.h b/drivers/net/ixgbe/ixgbe_common.h
index 264eef5..d5d3aae 100644
--- a/drivers/net/ixgbe/ixgbe_common.h
+++ b/drivers/net/ixgbe/ixgbe_common.h
@@ -30,6 +30,7 @@
 
 #include "ixgbe_type.h"
 
+u32 ixgbe_get_pcie_msix_count_generic(struct ixgbe_hw *hw);
 s32 ixgbe_init_ops_generic(struct ixgbe_hw *hw);
 s32 ixgbe_init_hw_generic(struct ixgbe_hw *hw);
 s32 ixgbe_start_hw_generic(struct ixgbe_hw *hw);
@@ -45,12 +46,13 @@ s32 ixgbe_led_off_generic(struct ixgbe_hw *hw, u32 index);
 
 s32 ixgbe_init_eeprom_params_generic(struct ixgbe_hw *hw);
 s32 ixgbe_write_eeprom_generic(struct ixgbe_hw *hw, u16 offset, u16 data);
-s32 ixgbe_read_eeprom_generic(struct ixgbe_hw *hw, u16 offset, u16 *data);
+s32 ixgbe_read_eerd_generic(struct ixgbe_hw *hw, u16 offset, u16 *data);
 s32 ixgbe_read_eeprom_bit_bang_generic(struct ixgbe_hw *hw, u16 offset,
                                        u16 *data);
 s32 ixgbe_validate_eeprom_checksum_generic(struct ixgbe_hw *hw,
                                            u16 *checksum_val);
 s32 ixgbe_update_eeprom_checksum_generic(struct ixgbe_hw *hw);
+s32 ixgbe_poll_eerd_eewr_done(struct ixgbe_hw *hw, u32 ee_reg);
 
 s32 ixgbe_set_rar_generic(struct ixgbe_hw *hw, u32 index, u8 *addr, u32 vmdq,
                           u32 enable_addr);
@@ -70,9 +72,16 @@ s32 ixgbe_validate_mac_addr(u8 *mac_addr);
 s32 ixgbe_acquire_swfw_sync(struct ixgbe_hw *hw, u16 mask);
 void ixgbe_release_swfw_sync(struct ixgbe_hw *hw, u16 mask);
 s32 ixgbe_disable_pcie_master(struct ixgbe_hw *hw);
-
-s32 ixgbe_read_analog_reg8_generic(struct ixgbe_hw *hw, u32 reg, u8 *val);
-s32 ixgbe_write_analog_reg8_generic(struct ixgbe_hw *hw, u32 reg, u8 val);
+s32 ixgbe_get_san_mac_addr_generic(struct ixgbe_hw *hw, u8 *san_mac_addr);
+s32 ixgbe_set_vmdq_generic(struct ixgbe_hw *hw, u32 rar, u32 vmdq);
+s32 ixgbe_clear_vmdq_generic(struct ixgbe_hw *hw, u32 rar, u32 vmdq);
+s32 ixgbe_init_uta_tables_generic(struct ixgbe_hw *hw);
+s32 ixgbe_set_vfta_generic(struct ixgbe_hw *hw, u32 vlan,
+                           u32 vind, bool vlan_on);
+s32 ixgbe_clear_vfta_generic(struct ixgbe_hw *hw);
+s32 ixgbe_check_mac_link_generic(struct ixgbe_hw *hw,
+                                 ixgbe_link_speed *speed,
+                                 bool *link_up, bool link_up_wait_to_complete);
 
 s32 ixgbe_blink_led_start_generic(struct ixgbe_hw *hw, u32 index);
 s32 ixgbe_blink_led_stop_generic(struct ixgbe_hw *hw, u32 index);
@@ -96,12 +105,26 @@ s32 ixgbe_blink_led_stop_generic(struct ixgbe_hw *hw, u32 index);
 
 #define IXGBE_WRITE_FLUSH(a) IXGBE_READ_REG(a, IXGBE_STATUS)
 
-#ifdef DEBUG
-extern char *ixgbe_get_hw_dev_name(struct ixgbe_hw *hw);
+extern struct net_device *ixgbe_get_hw_dev(struct ixgbe_hw *hw);
 #define hw_dbg(hw, format, arg...) \
-	printk(KERN_DEBUG "%s: " format, ixgbe_get_hw_dev_name(hw), ##arg)
-#else
-#define hw_dbg(hw, format, arg...) do {} while (0)
-#endif
+	netdev_dbg(ixgbe_get_hw_dev(hw), format, ##arg)
+#define e_err(format, arg...) \
+	netdev_err(adapter->netdev, format, ## arg)
+#define e_info(format, arg...) \
+	netdev_info(adapter->netdev, format, ## arg)
+#define e_warn(format, arg...) \
+	netdev_warn(adapter->netdev, format, ## arg)
+#define e_notice(format, arg...) \
+	netdev_notice(adapter->netdev, format, ## arg)
+#define e_crit(format, arg...) \
+	netdev_crit(adapter->netdev, format, ## arg)
+#define e_dev_info(format, arg...) \
+	dev_info(&adapter->pdev->dev, format, ## arg)
+#define e_dev_warn(format, arg...) \
+	dev_warn(&adapter->pdev->dev, format, ## arg)
+#define e_dev_err(format, arg...) \
+	dev_err(&adapter->pdev->dev, format, ## arg)
+#define e_dev_notice(format, arg...) \
+	dev_notice(&adapter->pdev->dev, format, ## arg)
 
 #endif /* IXGBE_COMMON */
diff --git a/drivers/net/ixgbe/ixgbe_dcb_nl.c b/drivers/net/ixgbe/ixgbe_dcb_nl.c
index dd4883f..6576235 100644
--- a/drivers/net/ixgbe/ixgbe_dcb_nl.c
+++ b/drivers/net/ixgbe/ixgbe_dcb_nl.c
@@ -121,7 +121,7 @@ static u8 ixgbe_dcbnl_set_state(struct net_device *netdev, u8 state)
 			goto out;
 
 		if (!(adapter->flags & IXGBE_FLAG_MSIX_ENABLED)) {
-			DPRINTK(DRV, ERR, "Enable failed, needs MSI-X\n");
+			e_err("Enable failed, needs MSI-X\n");
 			err = 1;
 			goto out;
 		}
@@ -488,7 +488,6 @@ static void ixgbe_dcbnl_setpfcstate(struct net_device *netdev, u8 state)
 	if (adapter->temp_dcb_cfg.pfc_mode_enable !=
 		adapter->dcb_cfg.pfc_mode_enable)
 		adapter->dcb_set_bitmap |= BIT_PFC;
-	return;
 }
 
 /**
diff --git a/drivers/net/ixgbe/ixgbe_ethtool.c b/drivers/net/ixgbe/ixgbe_ethtool.c
index 84cca1e..4ab7969 100644
--- a/drivers/net/ixgbe/ixgbe_ethtool.c
+++ b/drivers/net/ixgbe/ixgbe_ethtool.c
@@ -222,8 +222,8 @@ static int ixgbe_get_settings(struct net_device *netdev,
 		ecmd->port = PORT_FIBRE;
 		break;
 	case ixgbe_phy_nl:
-	case ixgbe_phy_tw_tyco:
-	case ixgbe_phy_tw_unknown:
+	case ixgbe_phy_sfp_passive_tyco:
+	case ixgbe_phy_sfp_passive_unknown:
 	case ixgbe_phy_sfp_ftl:
 	case ixgbe_phy_sfp_avago:
 	case ixgbe_phy_sfp_intel:
@@ -304,8 +304,7 @@ static int ixgbe_set_settings(struct net_device *netdev,
 		hw->mac.autotry_restart = true;
 		err = hw->mac.ops.setup_link(hw, advertised, true, true);
 		if (err) {
-			DPRINTK(PROBE, INFO,
-			        "setup link failed with code %d\n", err);
+			e_info("setup link failed with code %d\n", err);
 			hw->mac.ops.setup_link(hw, old, true, true);
 		}
 	} else {
@@ -375,7 +374,7 @@ static int ixgbe_set_pauseparam(struct net_device *netdev,
 	else
 		fc.disable_fc_autoneg = false;
 
-	if (pause->rx_pause && pause->tx_pause)
+	if ((pause->rx_pause && pause->tx_pause) || pause->autoneg)
 		fc.requested_mode = ixgbe_fc_full;
 	else if (pause->rx_pause && !pause->tx_pause)
 		fc.requested_mode = ixgbe_fc_rx_pause;
@@ -1198,9 +1197,9 @@ static struct ixgbe_reg_test reg_test_82598[] = {
 		writel((_test[pat] & W), (adapter->hw.hw_addr + R));          \
 		val = readl(adapter->hw.hw_addr + R);                         \
 		if (val != (_test[pat] & W & M)) {                            \
-			DPRINTK(DRV, ERR, "pattern test reg %04X failed: got "\
-					  "0x%08X expected 0x%08X\n",         \
-				R, val, (_test[pat] & W & M));                \
+			e_err("pattern test reg %04X failed: got "	\
+			      "0x%08X expected 0x%08X\n",		\
+			      R, val, (_test[pat] & W & M));                \
 			*data = R;                                            \
 			writel(before, adapter->hw.hw_addr + R);              \
 			return 1;                                             \
@@ -1216,8 +1215,8 @@ static struct ixgbe_reg_test reg_test_82598[] = {
 	writel((W & M), (adapter->hw.hw_addr + R));                           \
 	val = readl(adapter->hw.hw_addr + R);                                 \
 	if ((W & M) != (val & M)) {                                           \
-		DPRINTK(DRV, ERR, "set/check reg %04X test failed: got 0x%08X "\
-				 "expected 0x%08X\n", R, (val & M), (W & M)); \
+		e_err("set/check reg %04X test failed: got 0x%08X "	\
+		      "expected 0x%08X\n", R, (val & M), (W & M));	\
 		*data = R;                                                    \
 		writel(before, (adapter->hw.hw_addr + R));                    \
 		return 1;                                                     \
@@ -1250,8 +1249,8 @@ static int ixgbe_reg_test(struct ixgbe_adapter *adapter, u64 *data)
 	IXGBE_WRITE_REG(&adapter->hw, IXGBE_STATUS, toggle);
 	after = IXGBE_READ_REG(&adapter->hw, IXGBE_STATUS) & toggle;
 	if (value != after) {
-		DPRINTK(DRV, ERR, "failed STATUS register test got: "
-		        "0x%08X expected: 0x%08X\n", after, value);
+		e_err("failed STATUS register test got: 0x%08X expected: "
+		      "0x%08X\n", after, value);
 		*data = 1;
 		return 1;
 	}
@@ -1351,8 +1350,8 @@ static int ixgbe_intr_test(struct ixgbe_adapter *adapter, u64 *data)
 		*data = 1;
 		return -1;
 	}
-	DPRINTK(HW, INFO, "testing %s interrupt\n",
-		(shared_int ? "shared" : "unshared"));
+	e_info("testing %s interrupt\n", shared_int ?
+		   "shared" : "unshared");
 
 	/* Disable all the interrupts */
 	IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC, 0xFFFFFFFF);
@@ -1468,8 +1467,8 @@ static void ixgbe_free_desc_rings(struct ixgbe_adapter *adapter)
 			struct ixgbe_tx_buffer *buf =
 					&(tx_ring->tx_buffer_info[i]);
 			if (buf->dma)
-				pci_unmap_single(pdev, buf->dma, buf->length,
-				                 PCI_DMA_TODEVICE);
+				dma_unmap_single(&pdev->dev, buf->dma,
+						 buf->length, DMA_TO_DEVICE);
 			if (buf->skb)
 				dev_kfree_skb(buf->skb);
 		}
@@ -1480,22 +1479,22 @@ static void ixgbe_free_desc_rings(struct ixgbe_adapter *adapter)
 			struct ixgbe_rx_buffer *buf =
 					&(rx_ring->rx_buffer_info[i]);
 			if (buf->dma)
-				pci_unmap_single(pdev, buf->dma,
+				dma_unmap_single(&pdev->dev, buf->dma,
 						 IXGBE_RXBUFFER_2048,
-						 PCI_DMA_FROMDEVICE);
+						 DMA_FROM_DEVICE);
 			if (buf->skb)
 				dev_kfree_skb(buf->skb);
 		}
 	}
 
 	if (tx_ring->desc) {
-		pci_free_consistent(pdev, tx_ring->size, tx_ring->desc,
-		                    tx_ring->dma);
+		dma_free_coherent(&pdev->dev, tx_ring->size, tx_ring->desc,
+				  tx_ring->dma);
 		tx_ring->desc = NULL;
 	}
 	if (rx_ring->desc) {
-		pci_free_consistent(pdev, rx_ring->size, rx_ring->desc,
-		                    rx_ring->dma);
+		dma_free_coherent(&pdev->dev, rx_ring->size, rx_ring->desc,
+				  rx_ring->dma);
 		rx_ring->desc = NULL;
 	}
 
@@ -1503,8 +1502,6 @@ static void ixgbe_free_desc_rings(struct ixgbe_adapter *adapter)
 	tx_ring->tx_buffer_info = NULL;
 	kfree(rx_ring->rx_buffer_info);
 	rx_ring->rx_buffer_info = NULL;
-
-	return;
 }
 
 static int ixgbe_setup_desc_rings(struct ixgbe_adapter *adapter)
@@ -1530,8 +1527,9 @@ static int ixgbe_setup_desc_rings(struct ixgbe_adapter *adapter)
 
 	tx_ring->size = tx_ring->count * sizeof(union ixgbe_adv_tx_desc);
 	tx_ring->size = ALIGN(tx_ring->size, 4096);
-	if (!(tx_ring->desc = pci_alloc_consistent(pdev, tx_ring->size,
-						   &tx_ring->dma))) {
+	tx_ring->desc = dma_alloc_coherent(&pdev->dev, tx_ring->size,
+					   &tx_ring->dma, GFP_KERNEL);
+	if (!(tx_ring->desc)) {
 		ret_val = 2;
 		goto err_nomem;
 	}
@@ -1573,8 +1571,8 @@ static int ixgbe_setup_desc_rings(struct ixgbe_adapter *adapter)
 		tx_ring->tx_buffer_info[i].skb = skb;
 		tx_ring->tx_buffer_info[i].length = skb->len;
 		tx_ring->tx_buffer_info[i].dma =
-			pci_map_single(pdev, skb->data, skb->len,
-			               PCI_DMA_TODEVICE);
+			dma_map_single(&pdev->dev, skb->data, skb->len,
+				       DMA_TO_DEVICE);
 		desc->read.buffer_addr =
 		                    cpu_to_le64(tx_ring->tx_buffer_info[i].dma);
 		desc->read.cmd_type_len = cpu_to_le32(skb->len);
@@ -1603,8 +1601,9 @@ static int ixgbe_setup_desc_rings(struct ixgbe_adapter *adapter)
 
 	rx_ring->size = rx_ring->count * sizeof(union ixgbe_adv_rx_desc);
 	rx_ring->size = ALIGN(rx_ring->size, 4096);
-	if (!(rx_ring->desc = pci_alloc_consistent(pdev, rx_ring->size,
-						   &rx_ring->dma))) {
+	rx_ring->desc = dma_alloc_coherent(&pdev->dev, rx_ring->size,
+					   &rx_ring->dma, GFP_KERNEL);
+	if (!(rx_ring->desc)) {
 		ret_val = 5;
 		goto err_nomem;
 	}
@@ -1671,8 +1670,8 @@ static int ixgbe_setup_desc_rings(struct ixgbe_adapter *adapter)
 		skb_reserve(skb, NET_IP_ALIGN);
 		rx_ring->rx_buffer_info[i].skb = skb;
 		rx_ring->rx_buffer_info[i].dma =
-			pci_map_single(pdev, skb->data, IXGBE_RXBUFFER_2048,
-			               PCI_DMA_FROMDEVICE);
+			dma_map_single(&pdev->dev, skb->data,
+				       IXGBE_RXBUFFER_2048, DMA_FROM_DEVICE);
 		rx_desc->read.pkt_addr =
 				cpu_to_le64(rx_ring->rx_buffer_info[i].dma);
 		memset(skb->data, 0x00, skb->len);
@@ -1785,10 +1784,10 @@ static int ixgbe_run_loopback_test(struct ixgbe_adapter *adapter)
 			ixgbe_create_lbtest_frame(
 					tx_ring->tx_buffer_info[k].skb,
 					1024);
-			pci_dma_sync_single_for_device(pdev,
+			dma_sync_single_for_device(&pdev->dev,
 				tx_ring->tx_buffer_info[k].dma,
 				tx_ring->tx_buffer_info[k].length,
-				PCI_DMA_TODEVICE);
+				DMA_TO_DEVICE);
 			if (unlikely(++k == tx_ring->count))
 				k = 0;
 		}
@@ -1799,10 +1798,10 @@ static int ixgbe_run_loopback_test(struct ixgbe_adapter *adapter)
 		good_cnt = 0;
 		do {
 			/* receive the sent packets */
-			pci_dma_sync_single_for_cpu(pdev,
+			dma_sync_single_for_cpu(&pdev->dev,
 					rx_ring->rx_buffer_info[l].dma,
 					IXGBE_RXBUFFER_2048,
-					PCI_DMA_FROMDEVICE);
+					DMA_FROM_DEVICE);
 			ret_val = ixgbe_check_lbtest_frame(
 					rx_ring->rx_buffer_info[l].skb, 1024);
 			if (!ret_val)
@@ -1857,7 +1856,7 @@ static void ixgbe_diag_test(struct net_device *netdev,
 	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
 		/* Offline tests */
 
-		DPRINTK(HW, INFO, "offline testing starting\n");
+		e_info("offline testing starting\n");
 
 		/* Link test performed before hardware reset so autoneg doesn't
 		 * interfere with test result */
@@ -1890,17 +1889,17 @@ static void ixgbe_diag_test(struct net_device *netdev,
 		else
 			ixgbe_reset(adapter);
 
-		DPRINTK(HW, INFO, "register testing starting\n");
+		e_info("register testing starting\n");
 		if (ixgbe_reg_test(adapter, &data[0]))
 			eth_test->flags |= ETH_TEST_FL_FAILED;
 
 		ixgbe_reset(adapter);
-		DPRINTK(HW, INFO, "eeprom testing starting\n");
+		e_info("eeprom testing starting\n");
 		if (ixgbe_eeprom_test(adapter, &data[1]))
 			eth_test->flags |= ETH_TEST_FL_FAILED;
 
 		ixgbe_reset(adapter);
-		DPRINTK(HW, INFO, "interrupt testing starting\n");
+		e_info("interrupt testing starting\n");
 		if (ixgbe_intr_test(adapter, &data[2]))
 			eth_test->flags |= ETH_TEST_FL_FAILED;
 
@@ -1908,14 +1907,13 @@ static void ixgbe_diag_test(struct net_device *netdev,
 		 * loopback diagnostic. */
 		if (adapter->flags & (IXGBE_FLAG_SRIOV_ENABLED |
 				      IXGBE_FLAG_VMDQ_ENABLED)) {
-			DPRINTK(HW, INFO, "Skip MAC loopback diagnostic in VT "
-				"mode\n");
+			e_info("Skip MAC loopback diagnostic in VT mode\n");
 			data[3] = 0;
 			goto skip_loopback;
 		}
 
 		ixgbe_reset(adapter);
-		DPRINTK(HW, INFO, "loopback testing starting\n");
+		e_info("loopback testing starting\n");
 		if (ixgbe_loopback_test(adapter, &data[3]))
 			eth_test->flags |= ETH_TEST_FL_FAILED;
 
@@ -1926,7 +1924,7 @@ skip_loopback:
 		if (if_running)
 			dev_open(netdev);
 	} else {
-		DPRINTK(HW, INFO, "online testing starting\n");
+		e_info("online testing starting\n");
 		/* Online tests */
 		if (ixgbe_link_test(adapter, &data[4]))
 			eth_test->flags |= ETH_TEST_FL_FAILED;
@@ -1981,8 +1979,6 @@ static void ixgbe_get_wol(struct net_device *netdev,
 		wol->wolopts |= WAKE_BCAST;
 	if (adapter->wol & IXGBE_WUFC_MAG)
 		wol->wolopts |= WAKE_MAGIC;
-
-	return;
 }
 
 static int ixgbe_set_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
@@ -2089,12 +2085,32 @@ static int ixgbe_get_coalesce(struct net_device *netdev,
 	return 0;
 }
 
+/*
+ * this function must be called before setting the new value of
+ * rx_itr_setting
+ */
+static bool ixgbe_reenable_rsc(struct ixgbe_adapter *adapter,
+                               struct ethtool_coalesce *ec)
+{
+	/* check the old value and enable RSC if necessary */
+	if ((adapter->rx_itr_setting == 0) &&
+	    (adapter->flags2 & IXGBE_FLAG2_RSC_CAPABLE)) {
+		adapter->flags2 |= IXGBE_FLAG2_RSC_ENABLED;
+		adapter->netdev->features |= NETIF_F_LRO;
+		e_info("rx-usecs set to %d, re-enabling RSC\n",
+		       ec->rx_coalesce_usecs);
+		return true;
+	}
+	return false;
+}
+
 static int ixgbe_set_coalesce(struct net_device *netdev,
                               struct ethtool_coalesce *ec)
 {
 	struct ixgbe_adapter *adapter = netdev_priv(netdev);
 	struct ixgbe_q_vector *q_vector;
 	int i;
+	bool need_reset = false;
 
 	/* don't accept tx specific changes if we've got mixed RxTx vectors */
 	if (adapter->q_vector[0]->txr_count && adapter->q_vector[0]->rxr_count
@@ -2105,11 +2121,20 @@ static int ixgbe_set_coalesce(struct net_device *netdev,
 		adapter->tx_ring[0]->work_limit = ec->tx_max_coalesced_frames_irq;
 
 	if (ec->rx_coalesce_usecs > 1) {
+		u32 max_int;
+		if (adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED)
+			max_int = IXGBE_MAX_RSC_INT_RATE;
+		else
+			max_int = IXGBE_MAX_INT_RATE;
+
 		/* check the limits */
-		if ((1000000/ec->rx_coalesce_usecs > IXGBE_MAX_INT_RATE) ||
+		if ((1000000/ec->rx_coalesce_usecs > max_int) ||
 		    (1000000/ec->rx_coalesce_usecs < IXGBE_MIN_INT_RATE))
 			return -EINVAL;
 
+		/* check the old value and enable RSC if necessary */
+		need_reset = ixgbe_reenable_rsc(adapter, ec);
+
 		/* store the value in ints/second */
 		adapter->rx_eitr_param = 1000000/ec->rx_coalesce_usecs;
 
@@ -2118,6 +2143,9 @@ static int ixgbe_set_coalesce(struct net_device *netdev,
 		/* clear the lower bit as its used for dynamic state */
 		adapter->rx_itr_setting &= ~1;
 	} else if (ec->rx_coalesce_usecs == 1) {
+		/* check the old value and enable RSC if necessary */
+		need_reset = ixgbe_reenable_rsc(adapter, ec);
+
 		/* 1 means dynamic mode */
 		adapter->rx_eitr_param = 20000;
 		adapter->rx_itr_setting = 1;
@@ -2126,14 +2154,29 @@ static int ixgbe_set_coalesce(struct net_device *netdev,
 		 * any other value means disable eitr, which is best
 		 * served by setting the interrupt rate very high
 		 */
-		if (adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED)
-			adapter->rx_eitr_param = IXGBE_MAX_RSC_INT_RATE;
-		else
-			adapter->rx_eitr_param = IXGBE_MAX_INT_RATE;
+		adapter->rx_eitr_param = IXGBE_MAX_INT_RATE;
 		adapter->rx_itr_setting = 0;
+
+		/*
+		 * if hardware RSC is enabled, disable it when
+		 * setting low latency mode, to avoid errata, assuming
+		 * that when the user set low latency mode they want
+		 * it at the cost of anything else
+		 */
+		if (adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED) {
+			adapter->flags2 &= ~IXGBE_FLAG2_RSC_ENABLED;
+			netdev->features &= ~NETIF_F_LRO;
+			e_info("rx-usecs set to 0, disabling RSC\n");
+
+			need_reset = true;
+		}
 	}
 
 	if (ec->tx_coalesce_usecs > 1) {
+		/*
+		 * don't have to worry about max_int as above because
+		 * tx vectors don't do hardware RSC (an rx function)
+		 */
 		/* check the limits */
 		if ((1000000/ec->tx_coalesce_usecs > IXGBE_MAX_INT_RATE) ||
 		    (1000000/ec->tx_coalesce_usecs < IXGBE_MIN_INT_RATE))
@@ -2177,6 +2220,18 @@ static int ixgbe_set_coalesce(struct net_device *netdev,
 		ixgbe_write_eitr(q_vector);
 	}
 
+	/*
+	 * do reset here at the end to make sure EITR==0 case is handled
+	 * correctly w.r.t stopping tx, and changing TXDCTL.WTHRESH settings
+	 * also locks in RSC enable/disable which requires reset
+	 */
+	if (need_reset) {
+		if (netif_running(netdev))
+			ixgbe_reinit_locked(adapter);
+		else
+			ixgbe_reset(adapter);
+	}
+
 	return 0;
 }
 
@@ -2188,10 +2243,26 @@ static int ixgbe_set_flags(struct net_device *netdev, u32 data)
 	ethtool_op_set_flags(netdev, data);
 
 	/* if state changes we need to update adapter->flags and reset */
-	if ((!!(data & ETH_FLAG_LRO)) != 
-	    (!!(adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED))) {
-		adapter->flags2 ^= IXGBE_FLAG2_RSC_ENABLED;
-		need_reset = true;
+	if (adapter->flags2 & IXGBE_FLAG2_RSC_CAPABLE) {
+		/*
+		 * cast both to bool and verify if they are set the same
+		 * but only enable RSC if itr is non-zero, as
+		 * itr=0 and RSC are mutually exclusive
+		 */
+		if (((!!(data & ETH_FLAG_LRO)) !=
+		     (!!(adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED))) &&
+		    adapter->rx_itr_setting) {
+			adapter->flags2 ^= IXGBE_FLAG2_RSC_ENABLED;
+			switch (adapter->hw.mac.type) {
+			case ixgbe_mac_82599EB:
+				need_reset = true;
+				break;
+			default:
+				break;
+			}
+		} else if (!adapter->rx_itr_setting) {
+			netdev->features &= ~ETH_FLAG_LRO;
+		}
 	}
 
 	/*
diff --git a/drivers/net/ixgbe/ixgbe_fcoe.c b/drivers/net/ixgbe/ixgbe_fcoe.c
index 6493049..84e1194 100644
--- a/drivers/net/ixgbe/ixgbe_fcoe.c
+++ b/drivers/net/ixgbe/ixgbe_fcoe.c
@@ -25,13 +25,13 @@
 
 *******************************************************************************/
 
-
 #include "ixgbe.h"
 #ifdef CONFIG_IXGBE_DCB
 #include "ixgbe_dcb_82599.h"
 #endif /* CONFIG_IXGBE_DCB */
 #include <linux/if_ether.h>
 #include <linux/gfp.h>
+#include <linux/if_vlan.h>
 #include <scsi/scsi_cmnd.h>
 #include <scsi/scsi_device.h>
 #include <scsi/fc/fc_fs.h>
@@ -164,20 +164,20 @@ int ixgbe_fcoe_ddp_get(struct net_device *netdev, u16 xid,
 
 	adapter = netdev_priv(netdev);
 	if (xid >= IXGBE_FCOE_DDP_MAX) {
-		DPRINTK(DRV, WARNING, "xid=0x%x out-of-range\n", xid);
+		e_warn("xid=0x%x out-of-range\n", xid);
 		return 0;
 	}
 
 	fcoe = &adapter->fcoe;
 	if (!fcoe->pool) {
-		DPRINTK(DRV, WARNING, "xid=0x%x no ddp pool for fcoe\n", xid);
+		e_warn("xid=0x%x no ddp pool for fcoe\n", xid);
 		return 0;
 	}
 
 	ddp = &fcoe->ddp[xid];
 	if (ddp->sgl) {
-		DPRINTK(DRV, ERR, "xid 0x%x w/ non-null sgl=%p nents=%d\n",
-			xid, ddp->sgl, ddp->sgc);
+		e_err("xid 0x%x w/ non-null sgl=%p nents=%d\n",
+			  xid, ddp->sgl, ddp->sgc);
 		return 0;
 	}
 	ixgbe_fcoe_clear_ddp(ddp);
@@ -185,14 +185,14 @@ int ixgbe_fcoe_ddp_get(struct net_device *netdev, u16 xid,
 	/* setup dma from scsi command sgl */
 	dmacount = pci_map_sg(adapter->pdev, sgl, sgc, DMA_FROM_DEVICE);
 	if (dmacount == 0) {
-		DPRINTK(DRV, ERR, "xid 0x%x DMA map error\n", xid);
+		e_err("xid 0x%x DMA map error\n", xid);
 		return 0;
 	}
 
 	/* alloc the udl from our ddp pool */
 	ddp->udl = pci_pool_alloc(fcoe->pool, GFP_KERNEL, &ddp->udp);
 	if (!ddp->udl) {
-		DPRINTK(DRV, ERR, "failed allocated ddp context\n");
+		e_err("failed allocated ddp context\n");
 		goto out_noddp_unmap;
 	}
 	ddp->sgl = sgl;
@@ -205,10 +205,9 @@ int ixgbe_fcoe_ddp_get(struct net_device *netdev, u16 xid,
 		while (len) {
 			/* max number of buffers allowed in one DDP context */
 			if (j >= IXGBE_BUFFCNT_MAX) {
-				netif_err(adapter, drv, adapter->netdev,
-					  "xid=%x:%d,%d,%d:addr=%llx "
-					  "not enough descriptors\n",
-					  xid, i, j, dmacount, (u64)addr);
+				e_err("xid=%x:%d,%d,%d:addr=%llx "
+				      "not enough descriptors\n",
+				      xid, i, j, dmacount, (u64)addr);
 				goto out_noddp_free;
 			}
 
@@ -312,10 +311,12 @@ int ixgbe_fcoe_ddp(struct ixgbe_adapter *adapter,
 	if (fcerr == IXGBE_FCERR_BADCRC)
 		skb->ip_summed = CHECKSUM_NONE;
 
-	skb_reset_network_header(skb);
-	skb_set_transport_header(skb, skb_network_offset(skb) +
-				 sizeof(struct fcoe_hdr));
-	fh = (struct fc_frame_header *)skb_transport_header(skb);
+	if (eth_hdr(skb)->h_proto == htons(ETH_P_8021Q))
+		fh = (struct fc_frame_header *)(skb->data +
+			sizeof(struct vlan_hdr) + sizeof(struct fcoe_hdr));
+	else
+		fh = (struct fc_frame_header *)(skb->data +
+			sizeof(struct fcoe_hdr));
 	fctl = ntoh24(fh->fh_f_ctl);
 	if (fctl & FC_FC_EX_CTX)
 		xid =  be16_to_cpu(fh->fh_ox_id);
@@ -384,8 +385,8 @@ int ixgbe_fso(struct ixgbe_adapter *adapter,
 	struct fc_frame_header *fh;
 
 	if (skb_is_gso(skb) && (skb_shinfo(skb)->gso_type != SKB_GSO_FCOE)) {
-		DPRINTK(DRV, ERR, "Wrong gso type %d:expecting SKB_GSO_FCOE\n",
-			skb_shinfo(skb)->gso_type);
+		e_err("Wrong gso type %d:expecting SKB_GSO_FCOE\n",
+		      skb_shinfo(skb)->gso_type);
 		return -EINVAL;
 	}
 
@@ -411,7 +412,7 @@ int ixgbe_fso(struct ixgbe_adapter *adapter,
 		fcoe_sof_eof |= IXGBE_ADVTXD_FCOEF_SOF;
 		break;
 	default:
-		DPRINTK(DRV, WARNING, "unknown sof = 0x%x\n", sof);
+		e_warn("unknown sof = 0x%x\n", sof);
 		return -EINVAL;
 	}
 
@@ -438,7 +439,7 @@ int ixgbe_fso(struct ixgbe_adapter *adapter,
 		fcoe_sof_eof |= IXGBE_ADVTXD_FCOEF_EOF_A;
 		break;
 	default:
-		DPRINTK(DRV, WARNING, "unknown eof = 0x%x\n", eof);
+		e_warn("unknown eof = 0x%x\n", eof);
 		return -EINVAL;
 	}
 
@@ -514,8 +515,7 @@ void ixgbe_configure_fcoe(struct ixgbe_adapter *adapter)
 					     adapter->pdev, IXGBE_FCPTR_MAX,
 					     IXGBE_FCPTR_ALIGN, PAGE_SIZE);
 		if (!fcoe->pool)
-			DPRINTK(DRV, ERR,
-				"failed to allocated FCoE DDP pool\n");
+			e_err("failed to allocated FCoE DDP pool\n");
 
 		spin_lock_init(&fcoe->lock);
 	}
@@ -536,12 +536,6 @@ void ixgbe_configure_fcoe(struct ixgbe_adapter *adapter)
 		}
 		IXGBE_WRITE_REG(hw, IXGBE_FCRECTL, IXGBE_FCRECTL_ENA);
 		IXGBE_WRITE_REG(hw, IXGBE_ETQS(IXGBE_ETQF_FILTER_FCOE), 0);
-		fcoe_i = f->mask;
-		fcoe_i &= IXGBE_FCRETA_ENTRY_MASK;
-		fcoe_q = adapter->rx_ring[fcoe_i]->reg_idx;
-		IXGBE_WRITE_REG(hw, IXGBE_ETQS(IXGBE_ETQF_FILTER_FIP),
-				IXGBE_ETQS_QUEUE_EN |
-				(fcoe_q << IXGBE_ETQS_RX_QUEUE_SHIFT));
 	} else  {
 		/* Use single rx queue for FCoE */
 		fcoe_i = f->mask;
@@ -617,7 +611,7 @@ int ixgbe_fcoe_enable(struct net_device *netdev)
 	if (adapter->flags & IXGBE_FLAG_FCOE_ENABLED)
 		goto out_enable;
 
-	DPRINTK(DRV, INFO, "Enabling FCoE offload features.\n");
+	e_info("Enabling FCoE offload features.\n");
 	if (netif_running(netdev))
 		netdev->netdev_ops->ndo_stop(netdev);
 
@@ -663,7 +657,7 @@ int ixgbe_fcoe_disable(struct net_device *netdev)
 	if (!(adapter->flags & IXGBE_FLAG_FCOE_ENABLED))
 		goto out_disable;
 
-	DPRINTK(DRV, INFO, "Disabling FCoE offload features.\n");
+	e_info("Disabling FCoE offload features.\n");
 	if (netif_running(netdev))
 		netdev->netdev_ops->ndo_stop(netdev);
 
diff --git a/drivers/net/ixgbe/ixgbe_main.c b/drivers/net/ixgbe/ixgbe_main.c
index bf009f1..bcab5ed 100644
--- a/drivers/net/ixgbe/ixgbe_main.c
+++ b/drivers/net/ixgbe/ixgbe_main.c
@@ -108,6 +108,8 @@ static DEFINE_PCI_DEVICE_TABLE(ixgbe_pci_tbl) = {
 	 board_82599 },
 	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_CX4),
 	 board_82599 },
+	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_T3_LOM),
+	 board_82599 },
 	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_COMBO_BACKPLANE),
 	 board_82599 },
 
@@ -175,6 +177,345 @@ static inline void ixgbe_disable_sriov(struct ixgbe_adapter *adapter)
 	adapter->flags &= ~IXGBE_FLAG_SRIOV_ENABLED;
 }
 
+struct ixgbe_reg_info {
+	u32 ofs;
+	char *name;
+};
+
+static const struct ixgbe_reg_info ixgbe_reg_info_tbl[] = {
+
+	/* General Registers */
+	{IXGBE_CTRL, "CTRL"},
+	{IXGBE_STATUS, "STATUS"},
+	{IXGBE_CTRL_EXT, "CTRL_EXT"},
+
+	/* Interrupt Registers */
+	{IXGBE_EICR, "EICR"},
+
+	/* RX Registers */
+	{IXGBE_SRRCTL(0), "SRRCTL"},
+	{IXGBE_DCA_RXCTRL(0), "DRXCTL"},
+	{IXGBE_RDLEN(0), "RDLEN"},
+	{IXGBE_RDH(0), "RDH"},
+	{IXGBE_RDT(0), "RDT"},
+	{IXGBE_RXDCTL(0), "RXDCTL"},
+	{IXGBE_RDBAL(0), "RDBAL"},
+	{IXGBE_RDBAH(0), "RDBAH"},
+
+	/* TX Registers */
+	{IXGBE_TDBAL(0), "TDBAL"},
+	{IXGBE_TDBAH(0), "TDBAH"},
+	{IXGBE_TDLEN(0), "TDLEN"},
+	{IXGBE_TDH(0), "TDH"},
+	{IXGBE_TDT(0), "TDT"},
+	{IXGBE_TXDCTL(0), "TXDCTL"},
+
+	/* List Terminator */
+	{}
+};
+
+
+/*
+ * ixgbe_regdump - register printout routine
+ */
+static void ixgbe_regdump(struct ixgbe_hw *hw, struct ixgbe_reg_info *reginfo)
+{
+	int i = 0, j = 0;
+	char rname[16];
+	u32 regs[64];
+
+	switch (reginfo->ofs) {
+	case IXGBE_SRRCTL(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_SRRCTL(i));
+		break;
+	case IXGBE_DCA_RXCTRL(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_DCA_RXCTRL(i));
+		break;
+	case IXGBE_RDLEN(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_RDLEN(i));
+		break;
+	case IXGBE_RDH(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_RDH(i));
+		break;
+	case IXGBE_RDT(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_RDT(i));
+		break;
+	case IXGBE_RXDCTL(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_RXDCTL(i));
+		break;
+	case IXGBE_RDBAL(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_RDBAL(i));
+		break;
+	case IXGBE_RDBAH(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_RDBAH(i));
+		break;
+	case IXGBE_TDBAL(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_TDBAL(i));
+		break;
+	case IXGBE_TDBAH(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_TDBAH(i));
+		break;
+	case IXGBE_TDLEN(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_TDLEN(i));
+		break;
+	case IXGBE_TDH(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_TDH(i));
+		break;
+	case IXGBE_TDT(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_TDT(i));
+		break;
+	case IXGBE_TXDCTL(0):
+		for (i = 0; i < 64; i++)
+			regs[i] = IXGBE_READ_REG(hw, IXGBE_TXDCTL(i));
+		break;
+	default:
+		printk(KERN_INFO "%-15s %08x\n", reginfo->name,
+			IXGBE_READ_REG(hw, reginfo->ofs));
+		return;
+	}
+
+	for (i = 0; i < 8; i++) {
+		snprintf(rname, 16, "%s[%d-%d]", reginfo->name, i*8, i*8+7);
+		printk(KERN_ERR "%-15s ", rname);
+		for (j = 0; j < 8; j++)
+			printk(KERN_CONT "%08x ", regs[i*8+j]);
+		printk(KERN_CONT "\n");
+	}
+
+}
+
+/*
+ * ixgbe_dump - Print registers, tx-rings and rx-rings
+ */
+static void ixgbe_dump(struct ixgbe_adapter *adapter)
+{
+	struct net_device *netdev = adapter->netdev;
+	struct ixgbe_hw *hw = &adapter->hw;
+	struct ixgbe_reg_info *reginfo;
+	int n = 0;
+	struct ixgbe_ring *tx_ring;
+	struct ixgbe_tx_buffer *tx_buffer_info;
+	union ixgbe_adv_tx_desc *tx_desc;
+	struct my_u0 { u64 a; u64 b; } *u0;
+	struct ixgbe_ring *rx_ring;
+	union ixgbe_adv_rx_desc *rx_desc;
+	struct ixgbe_rx_buffer *rx_buffer_info;
+	u32 staterr;
+	int i = 0;
+
+	if (!netif_msg_hw(adapter))
+		return;
+
+	/* Print netdevice Info */
+	if (netdev) {
+		dev_info(&adapter->pdev->dev, "Net device Info\n");
+		printk(KERN_INFO "Device Name     state            "
+			"trans_start      last_rx\n");
+		printk(KERN_INFO "%-15s %016lX %016lX %016lX\n",
+		netdev->name,
+		netdev->state,
+		netdev->trans_start,
+		netdev->last_rx);
+	}
+
+	/* Print Registers */
+	dev_info(&adapter->pdev->dev, "Register Dump\n");
+	printk(KERN_INFO " Register Name   Value\n");
+	for (reginfo = (struct ixgbe_reg_info *)ixgbe_reg_info_tbl;
+	     reginfo->name; reginfo++) {
+		ixgbe_regdump(hw, reginfo);
+	}
+
+	/* Print TX Ring Summary */
+	if (!netdev || !netif_running(netdev))
+		goto exit;
+
+	dev_info(&adapter->pdev->dev, "TX Rings Summary\n");
+	printk(KERN_INFO "Queue [NTU] [NTC] [bi(ntc)->dma  ] "
+		"leng ntw timestamp\n");
+	for (n = 0; n < adapter->num_tx_queues; n++) {
+		tx_ring = adapter->tx_ring[n];
+		tx_buffer_info =
+			&tx_ring->tx_buffer_info[tx_ring->next_to_clean];
+		printk(KERN_INFO " %5d %5X %5X %016llX %04X %3X %016llX\n",
+			   n, tx_ring->next_to_use, tx_ring->next_to_clean,
+			   (u64)tx_buffer_info->dma,
+			   tx_buffer_info->length,
+			   tx_buffer_info->next_to_watch,
+			   (u64)tx_buffer_info->time_stamp);
+	}
+
+	/* Print TX Rings */
+	if (!netif_msg_tx_done(adapter))
+		goto rx_ring_summary;
+
+	dev_info(&adapter->pdev->dev, "TX Rings Dump\n");
+
+	/* Transmit Descriptor Formats
+	 *
+	 * Advanced Transmit Descriptor
+	 *   +--------------------------------------------------------------+
+	 * 0 |         Buffer Address [63:0]                                |
+	 *   +--------------------------------------------------------------+
+	 * 8 |  PAYLEN  | PORTS  | IDX | STA | DCMD  |DTYP |  RSV |  DTALEN |
+	 *   +--------------------------------------------------------------+
+	 *   63       46 45    40 39 36 35 32 31   24 23 20 19              0
+	 */
+
+	for (n = 0; n < adapter->num_tx_queues; n++) {
+		tx_ring = adapter->tx_ring[n];
+		printk(KERN_INFO "------------------------------------\n");
+		printk(KERN_INFO "TX QUEUE INDEX = %d\n", tx_ring->queue_index);
+		printk(KERN_INFO "------------------------------------\n");
+		printk(KERN_INFO "T [desc]     [address 63:0  ] "
+			"[PlPOIdStDDt Ln] [bi->dma       ] "
+			"leng  ntw timestamp        bi->skb\n");
+
+		for (i = 0; tx_ring->desc && (i < tx_ring->count); i++) {
+			tx_desc = IXGBE_TX_DESC_ADV(*tx_ring, i);
+			tx_buffer_info = &tx_ring->tx_buffer_info[i];
+			u0 = (struct my_u0 *)tx_desc;
+			printk(KERN_INFO "T [0x%03X]    %016llX %016llX %016llX"
+				" %04X  %3X %016llX %p", i,
+				le64_to_cpu(u0->a),
+				le64_to_cpu(u0->b),
+				(u64)tx_buffer_info->dma,
+				tx_buffer_info->length,
+				tx_buffer_info->next_to_watch,
+				(u64)tx_buffer_info->time_stamp,
+				tx_buffer_info->skb);
+			if (i == tx_ring->next_to_use &&
+				i == tx_ring->next_to_clean)
+				printk(KERN_CONT " NTC/U\n");
+			else if (i == tx_ring->next_to_use)
+				printk(KERN_CONT " NTU\n");
+			else if (i == tx_ring->next_to_clean)
+				printk(KERN_CONT " NTC\n");
+			else
+				printk(KERN_CONT "\n");
+
+			if (netif_msg_pktdata(adapter) &&
+				tx_buffer_info->dma != 0)
+				print_hex_dump(KERN_INFO, "",
+					DUMP_PREFIX_ADDRESS, 16, 1,
+					phys_to_virt(tx_buffer_info->dma),
+					tx_buffer_info->length, true);
+		}
+	}
+
+	/* Print RX Rings Summary */
+rx_ring_summary:
+	dev_info(&adapter->pdev->dev, "RX Rings Summary\n");
+	printk(KERN_INFO "Queue [NTU] [NTC]\n");
+	for (n = 0; n < adapter->num_rx_queues; n++) {
+		rx_ring = adapter->rx_ring[n];
+		printk(KERN_INFO "%5d %5X %5X\n", n,
+			   rx_ring->next_to_use, rx_ring->next_to_clean);
+	}
+
+	/* Print RX Rings */
+	if (!netif_msg_rx_status(adapter))
+		goto exit;
+
+	dev_info(&adapter->pdev->dev, "RX Rings Dump\n");
+
+	/* Advanced Receive Descriptor (Read) Format
+	 *    63                                           1        0
+	 *    +-----------------------------------------------------+
+	 *  0 |       Packet Buffer Address [63:1]           |A0/NSE|
+	 *    +----------------------------------------------+------+
+	 *  8 |       Header Buffer Address [63:1]           |  DD  |
+	 *    +-----------------------------------------------------+
+	 *
+	 *
+	 * Advanced Receive Descriptor (Write-Back) Format
+	 *
+	 *   63       48 47    32 31  30      21 20 16 15   4 3     0
+	 *   +------------------------------------------------------+
+	 * 0 | Packet     IP     |SPH| HDR_LEN   | RSV|Packet|  RSS |
+	 *   | Checksum   Ident  |   |           |    | Type | Type |
+	 *   +------------------------------------------------------+
+	 * 8 | VLAN Tag | Length | Extended Error | Extended Status |
+	 *   +------------------------------------------------------+
+	 *   63       48 47    32 31            20 19               0
+	 */
+	for (n = 0; n < adapter->num_rx_queues; n++) {
+		rx_ring = adapter->rx_ring[n];
+		printk(KERN_INFO "------------------------------------\n");
+		printk(KERN_INFO "RX QUEUE INDEX = %d\n", rx_ring->queue_index);
+		printk(KERN_INFO "------------------------------------\n");
+		printk(KERN_INFO "R  [desc]      [ PktBuf     A0] "
+			"[  HeadBuf   DD] [bi->dma       ] [bi->skb] "
+			"<-- Adv Rx Read format\n");
+		printk(KERN_INFO "RWB[desc]      [PcsmIpSHl PtRs] "
+			"[vl er S cks ln] ---------------- [bi->skb] "
+			"<-- Adv Rx Write-Back format\n");
+
+		for (i = 0; i < rx_ring->count; i++) {
+			rx_buffer_info = &rx_ring->rx_buffer_info[i];
+			rx_desc = IXGBE_RX_DESC_ADV(*rx_ring, i);
+			u0 = (struct my_u0 *)rx_desc;
+			staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
+			if (staterr & IXGBE_RXD_STAT_DD) {
+				/* Descriptor Done */
+				printk(KERN_INFO "RWB[0x%03X]     %016llX "
+					"%016llX ---------------- %p", i,
+					le64_to_cpu(u0->a),
+					le64_to_cpu(u0->b),
+					rx_buffer_info->skb);
+			} else {
+				printk(KERN_INFO "R  [0x%03X]     %016llX "
+					"%016llX %016llX %p", i,
+					le64_to_cpu(u0->a),
+					le64_to_cpu(u0->b),
+					(u64)rx_buffer_info->dma,
+					rx_buffer_info->skb);
+
+				if (netif_msg_pktdata(adapter)) {
+					print_hex_dump(KERN_INFO, "",
+					   DUMP_PREFIX_ADDRESS, 16, 1,
+					   phys_to_virt(rx_buffer_info->dma),
+					   rx_ring->rx_buf_len, true);
+
+					if (rx_ring->rx_buf_len
+						< IXGBE_RXBUFFER_2048)
+						print_hex_dump(KERN_INFO, "",
+						  DUMP_PREFIX_ADDRESS, 16, 1,
+						  phys_to_virt(
+						    rx_buffer_info->page_dma +
+						    rx_buffer_info->page_offset
+						  ),
+						  PAGE_SIZE/2, true);
+				}
+			}
+
+			if (i == rx_ring->next_to_use)
+				printk(KERN_CONT " NTU\n");
+			else if (i == rx_ring->next_to_clean)
+				printk(KERN_CONT " NTC\n");
+			else
+				printk(KERN_CONT "\n");
+
+		}
+	}
+
+exit:
+	return;
+}
+
 static void ixgbe_release_hw_control(struct ixgbe_adapter *adapter)
 {
 	u32 ctrl_ext;
@@ -266,15 +607,15 @@ static void ixgbe_unmap_and_free_tx_resource(struct ixgbe_adapter *adapter,
 {
 	if (tx_buffer_info->dma) {
 		if (tx_buffer_info->mapped_as_page)
-			pci_unmap_page(adapter->pdev,
+			dma_unmap_page(&adapter->pdev->dev,
 				       tx_buffer_info->dma,
 				       tx_buffer_info->length,
-				       PCI_DMA_TODEVICE);
+				       DMA_TO_DEVICE);
 		else
-			pci_unmap_single(adapter->pdev,
+			dma_unmap_single(&adapter->pdev->dev,
 					 tx_buffer_info->dma,
 					 tx_buffer_info->length,
-					 PCI_DMA_TODEVICE);
+					 DMA_TO_DEVICE);
 		tx_buffer_info->dma = 0;
 	}
 	if (tx_buffer_info->skb) {
@@ -286,22 +627,22 @@ static void ixgbe_unmap_and_free_tx_resource(struct ixgbe_adapter *adapter,
 }
 
 /**
- * ixgbe_tx_is_paused - check if the tx ring is paused
+ * ixgbe_tx_xon_state - check the tx ring xon state
  * @adapter: the ixgbe adapter
  * @tx_ring: the corresponding tx_ring
  *
  * If not in DCB mode, checks TFCS.TXOFF, otherwise, find out the
  * corresponding TC of this tx_ring when checking TFCS.
  *
- * Returns : true if paused
+ * Returns : true if in xon state (currently not paused)
  */
-static inline bool ixgbe_tx_is_paused(struct ixgbe_adapter *adapter,
+static inline bool ixgbe_tx_xon_state(struct ixgbe_adapter *adapter,
                                       struct ixgbe_ring *tx_ring)
 {
 	u32 txoff = IXGBE_TFCS_TXOFF;
 
 #ifdef CONFIG_IXGBE_DCB
-	if (adapter->flags & IXGBE_FLAG_DCB_ENABLED) {
+	if (adapter->dcb_cfg.pfc_mode_enable) {
 		int tc;
 		int reg_idx = tx_ring->reg_idx;
 		int dcb_i = adapter->ring_feature[RING_F_DCB].indices;
@@ -351,23 +692,23 @@ static inline bool ixgbe_check_tx_hang(struct ixgbe_adapter *adapter,
 	adapter->detect_tx_hung = false;
 	if (tx_ring->tx_buffer_info[eop].time_stamp &&
 	    time_after(jiffies, tx_ring->tx_buffer_info[eop].time_stamp + HZ) &&
-	    !ixgbe_tx_is_paused(adapter, tx_ring)) {
+	    ixgbe_tx_xon_state(adapter, tx_ring)) {
 		/* detected Tx unit hang */
 		union ixgbe_adv_tx_desc *tx_desc;
 		tx_desc = IXGBE_TX_DESC_ADV(*tx_ring, eop);
-		DPRINTK(DRV, ERR, "Detected Tx Unit Hang\n"
-			"  Tx Queue             <%d>\n"
-			"  TDH, TDT             <%x>, <%x>\n"
-			"  next_to_use          <%x>\n"
-			"  next_to_clean        <%x>\n"
-			"tx_buffer_info[next_to_clean]\n"
-			"  time_stamp           <%lx>\n"
-			"  jiffies              <%lx>\n",
-			tx_ring->queue_index,
-			IXGBE_READ_REG(hw, tx_ring->head),
-			IXGBE_READ_REG(hw, tx_ring->tail),
-			tx_ring->next_to_use, eop,
-			tx_ring->tx_buffer_info[eop].time_stamp, jiffies);
+		e_err("Detected Tx Unit Hang\n"
+		      "  Tx Queue             <%d>\n"
+		      "  TDH, TDT             <%x>, <%x>\n"
+		      "  next_to_use          <%x>\n"
+		      "  next_to_clean        <%x>\n"
+		      "tx_buffer_info[next_to_clean]\n"
+		      "  time_stamp           <%lx>\n"
+		      "  jiffies              <%lx>\n",
+		      tx_ring->queue_index,
+		      IXGBE_READ_REG(hw, tx_ring->head),
+		      IXGBE_READ_REG(hw, tx_ring->tail),
+		      tx_ring->next_to_use, eop,
+		      tx_ring->tx_buffer_info[eop].time_stamp, jiffies);
 		return true;
 	}
 
@@ -471,9 +812,8 @@ static bool ixgbe_clean_tx_irq(struct ixgbe_q_vector *q_vector,
 	if (adapter->detect_tx_hung) {
 		if (ixgbe_check_tx_hang(adapter, tx_ring, i)) {
 			/* schedule immediate reset if we believe we hung */
-			DPRINTK(PROBE, INFO,
-			        "tx hang %d detected, resetting adapter\n",
-			        adapter->tx_timeout_count + 1);
+			e_info("tx hang %d detected, resetting adapter\n",
+			       adapter->tx_timeout_count + 1);
 			ixgbe_tx_timeout(adapter->netdev);
 		}
 	}
@@ -721,10 +1061,10 @@ static void ixgbe_alloc_rx_buffers(struct ixgbe_adapter *adapter,
 				bi->page_offset ^= (PAGE_SIZE / 2);
 			}
 
-			bi->page_dma = pci_map_page(pdev, bi->page,
+			bi->page_dma = dma_map_page(&pdev->dev, bi->page,
 			                            bi->page_offset,
 			                            (PAGE_SIZE / 2),
-			                            PCI_DMA_FROMDEVICE);
+						    DMA_FROM_DEVICE);
 		}
 
 		if (!bi->skb) {
@@ -743,9 +1083,9 @@ static void ixgbe_alloc_rx_buffers(struct ixgbe_adapter *adapter,
 			                  - skb->data));
 
 			bi->skb = skb;
-			bi->dma = pci_map_single(pdev, skb->data,
+			bi->dma = dma_map_single(&pdev->dev, skb->data,
 			                         rx_ring->rx_buf_len,
-			                         PCI_DMA_FROMDEVICE);
+						 DMA_FROM_DEVICE);
 		}
 		/* Refresh the desc even if buffer_addrs didn't change because
 		 * each write-back erases this info. */
@@ -821,6 +1161,7 @@ static inline struct sk_buff *ixgbe_transform_rsc_queue(struct sk_buff *skb,
 
 struct ixgbe_rsc_cb {
 	dma_addr_t dma;
+	bool delay_unmap;
 };
 
 #define IXGBE_RSC_CB(skb) ((struct ixgbe_rsc_cb *)(skb)->cb)
@@ -861,9 +1202,10 @@ static bool ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
 			hdr_info = le16_to_cpu(ixgbe_get_hdr_info(rx_desc));
 			len = (hdr_info & IXGBE_RXDADV_HDRBUFLEN_MASK) >>
 			       IXGBE_RXDADV_HDRBUFLEN_SHIFT;
-			if (len > IXGBE_RX_HDR_SIZE)
-				len = IXGBE_RX_HDR_SIZE;
 			upper_len = le16_to_cpu(rx_desc->wb.upper.length);
+			if ((len > IXGBE_RX_HDR_SIZE) ||
+			    (upper_len && !(hdr_info & IXGBE_RXDADV_SPH)))
+				len = IXGBE_RX_HDR_SIZE;
 		} else {
 			len = le16_to_cpu(rx_desc->wb.upper.length);
 		}
@@ -876,7 +1218,7 @@ static bool ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
 		if (rx_buffer_info->dma) {
 			if ((adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED) &&
 			    (!(staterr & IXGBE_RXD_STAT_EOP)) &&
-				 (!(skb->prev)))
+				 (!(skb->prev))) {
 				/*
 				 * When HWRSC is enabled, delay unmapping
 				 * of the first packet. It carries the
@@ -884,18 +1226,21 @@ static bool ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
 				 * access the header after the writeback.
 				 * Only unmap it when EOP is reached
 				 */
+				IXGBE_RSC_CB(skb)->delay_unmap = true;
 				IXGBE_RSC_CB(skb)->dma = rx_buffer_info->dma;
-			else
-				pci_unmap_single(pdev, rx_buffer_info->dma,
+			} else {
+				dma_unmap_single(&pdev->dev,
+				                 rx_buffer_info->dma,
 				                 rx_ring->rx_buf_len,
-				                 PCI_DMA_FROMDEVICE);
+				                 DMA_FROM_DEVICE);
+			}
 			rx_buffer_info->dma = 0;
 			skb_put(skb, len);
 		}
 
 		if (upper_len) {
-			pci_unmap_page(pdev, rx_buffer_info->page_dma,
-			               PAGE_SIZE / 2, PCI_DMA_FROMDEVICE);
+			dma_unmap_page(&pdev->dev, rx_buffer_info->page_dma,
+				       PAGE_SIZE / 2, DMA_FROM_DEVICE);
 			rx_buffer_info->page_dma = 0;
 			skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags,
 			                   rx_buffer_info->page,
@@ -936,11 +1281,13 @@ static bool ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
 			if (skb->prev)
 				skb = ixgbe_transform_rsc_queue(skb, &(rx_ring->rsc_count));
 			if (adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED) {
-				if (IXGBE_RSC_CB(skb)->dma) {
-					pci_unmap_single(pdev, IXGBE_RSC_CB(skb)->dma,
+				if (IXGBE_RSC_CB(skb)->delay_unmap) {
+					dma_unmap_single(&pdev->dev,
+							 IXGBE_RSC_CB(skb)->dma,
 					                 rx_ring->rx_buf_len,
-					                 PCI_DMA_FROMDEVICE);
+							 DMA_FROM_DEVICE);
 					IXGBE_RSC_CB(skb)->dma = 0;
+					IXGBE_RSC_CB(skb)->delay_unmap = false;
 				}
 				if (rx_ring->flags & IXGBE_RING_RX_PS_ENABLED)
 					rx_ring->rsc_count += skb_shinfo(skb)->nr_frags;
@@ -1190,6 +1537,15 @@ void ixgbe_write_eitr(struct ixgbe_q_vector *q_vector)
 		itr_reg |= (itr_reg << 16);
 	} else if (adapter->hw.mac.type == ixgbe_mac_82599EB) {
 		/*
+		 * 82599 can support a value of zero, so allow it for
+		 * max interrupt rate, but there is an errata where it can
+		 * not be zero with RSC
+		 */
+		if (itr_reg == 8 &&
+		    !(adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED))
+			itr_reg = 0;
+
+		/*
 		 * set the WDIS bit to not clear the timer bits and cause an
 		 * immediate assertion of the interrupt
 		 */
@@ -1261,8 +1617,48 @@ static void ixgbe_set_itr_msix(struct ixgbe_q_vector *q_vector)
 
 		ixgbe_write_eitr(q_vector);
 	}
+}
 
-	return;
+/**
+ * ixgbe_check_overtemp_task - worker thread to check over tempurature
+ * @work: pointer to work_struct containing our data
+ **/
+static void ixgbe_check_overtemp_task(struct work_struct *work)
+{
+	struct ixgbe_adapter *adapter = container_of(work,
+	                                             struct ixgbe_adapter,
+	                                             check_overtemp_task);
+	struct ixgbe_hw *hw = &adapter->hw;
+	u32 eicr = adapter->interrupt_event;
+
+	if (adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE) {
+		switch (hw->device_id) {
+		case IXGBE_DEV_ID_82599_T3_LOM: {
+			u32 autoneg;
+			bool link_up = false;
+
+			if (hw->mac.ops.check_link)
+				hw->mac.ops.check_link(hw, &autoneg, &link_up, false);
+
+			if (((eicr & IXGBE_EICR_GPI_SDP0) && (!link_up)) ||
+			    (eicr & IXGBE_EICR_LSC))
+				/* Check if this is due to overtemp */
+				if (hw->phy.ops.check_overtemp(hw) == IXGBE_ERR_OVERTEMP)
+					break;
+			}
+			return;
+		default:
+			if (!(eicr & IXGBE_EICR_GPI_SDP0))
+				return;
+			break;
+		}
+		e_crit("Network adapter has been stopped because it "
+		       "has over heated. Restart the computer. If the problem "
+		       "persists, power off the system and replace the "
+		       "adapter\n");
+		/* write to clear the interrupt */
+		IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_GPI_SDP0);
+	}
 }
 
 static void ixgbe_check_fan_failure(struct ixgbe_adapter *adapter, u32 eicr)
@@ -1271,7 +1667,7 @@ static void ixgbe_check_fan_failure(struct ixgbe_adapter *adapter, u32 eicr)
 
 	if ((adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE) &&
 	    (eicr & IXGBE_EICR_GPI_SDP1)) {
-		DPRINTK(PROBE, CRIT, "Fan has stopped, replace the adapter\n");
+		e_crit("Fan has stopped, replace the adapter\n");
 		/* write to clear the interrupt */
 		IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_GPI_SDP1);
 	}
@@ -1336,6 +1732,10 @@ static irqreturn_t ixgbe_msix_lsc(int irq, void *data)
 
 	if (hw->mac.type == ixgbe_mac_82599EB) {
 		ixgbe_check_sfp_event(adapter, eicr);
+		adapter->interrupt_event = eicr;
+		if ((adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE) &&
+		    ((eicr & IXGBE_EICR_GPI_SDP0) || (eicr & IXGBE_EICR_LSC)))
+			schedule_work(&adapter->check_overtemp_task);
 
 		/* Handle Flow Director Full threshold interrupt */
 		if (eicr & IXGBE_EICR_FLOW_DIR) {
@@ -1753,9 +2153,8 @@ static int ixgbe_request_msix_irqs(struct ixgbe_adapter *adapter)
 		                  handler, 0, adapter->name[vector],
 		                  adapter->q_vector[vector]);
 		if (err) {
-			DPRINTK(PROBE, ERR,
-			        "request_irq failed for MSIX interrupt "
-			        "Error: %d\n", err);
+			e_err("request_irq failed for MSIX interrupt: "
+			      "Error: %d\n", err);
 			goto free_queue_irqs;
 		}
 	}
@@ -1764,8 +2163,7 @@ static int ixgbe_request_msix_irqs(struct ixgbe_adapter *adapter)
 	err = request_irq(adapter->msix_entries[vector].vector,
 	                  ixgbe_msix_lsc, 0, adapter->name[vector], netdev);
 	if (err) {
-		DPRINTK(PROBE, ERR,
-			"request_irq for msix_lsc failed: %d\n", err);
+		e_err("request_irq for msix_lsc failed: %d\n", err);
 		goto free_queue_irqs;
 	}
 
@@ -1826,8 +2224,6 @@ static void ixgbe_set_itr(struct ixgbe_adapter *adapter)
 
 		ixgbe_write_eitr(q_vector);
 	}
-
-	return;
 }
 
 /**
@@ -1839,6 +2235,8 @@ static inline void ixgbe_irq_enable(struct ixgbe_adapter *adapter)
 	u32 mask;
 
 	mask = (IXGBE_EIMS_ENABLE_MASK & ~IXGBE_EIMS_RTX_QUEUE);
+	if (adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE)
+		mask |= IXGBE_EIMS_GPI_SDP0;
 	if (adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE)
 		mask |= IXGBE_EIMS_GPI_SDP1;
 	if (adapter->hw.mac.type == ixgbe_mac_82599EB) {
@@ -1899,6 +2297,9 @@ static irqreturn_t ixgbe_intr(int irq, void *data)
 		ixgbe_check_sfp_event(adapter, eicr);
 
 	ixgbe_check_fan_failure(adapter, eicr);
+	if ((adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE) &&
+	    ((eicr & IXGBE_EICR_GPI_SDP0) || (eicr & IXGBE_EICR_LSC)))
+		schedule_work(&adapter->check_overtemp_task);
 
 	if (napi_schedule_prep(&(q_vector->napi))) {
 		adapter->tx_ring[0]->total_packets = 0;
@@ -1948,7 +2349,7 @@ static int ixgbe_request_irq(struct ixgbe_adapter *adapter)
 	}
 
 	if (err)
-		DPRINTK(PROBE, ERR, "request_irq failed, Error %d\n", err);
+		e_err("request_irq failed, Error %d\n", err);
 
 	return err;
 }
@@ -2019,7 +2420,7 @@ static void ixgbe_configure_msi_and_legacy(struct ixgbe_adapter *adapter)
 	map_vector_to_rxq(adapter, 0, 0);
 	map_vector_to_txq(adapter, 0, 0);
 
-	DPRINTK(HW, INFO, "Legacy interrupt IVAR setup done\n");
+	e_info("Legacy interrupt IVAR setup done\n");
 }
 
 /**
@@ -2372,7 +2773,7 @@ static void ixgbe_configure_rx(struct ixgbe_adapter *adapter)
 		IXGBE_WRITE_REG(hw, IXGBE_VFRE(reg_offset), (1 << vf_shift));
 		IXGBE_WRITE_REG(hw, IXGBE_VFTE(reg_offset), (1 << vf_shift));
 		IXGBE_WRITE_REG(hw, IXGBE_PFDTXGSWC, IXGBE_PFDTXGSWC_VT_LBEN);
-		ixgbe_set_vmolr(hw, adapter->num_vfs);
+		ixgbe_set_vmolr(hw, adapter->num_vfs, true);
 	}
 
 	/* Program MRQC for the distribution of queues */
@@ -2482,12 +2883,82 @@ static void ixgbe_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
 	hw->mac.ops.set_vfta(&adapter->hw, vid, pool_ndx, false);
 }
 
+/**
+ * ixgbe_vlan_filter_disable - helper to disable hw vlan filtering
+ * @adapter: driver data
+ */
+static void ixgbe_vlan_filter_disable(struct ixgbe_adapter *adapter)
+{
+	struct ixgbe_hw *hw = &adapter->hw;
+	u32 vlnctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
+	int i, j;
+
+	switch (hw->mac.type) {
+	case ixgbe_mac_82598EB:
+		vlnctrl &= ~IXGBE_VLNCTRL_VFE;
+#ifdef CONFIG_IXGBE_DCB
+		if (!(adapter->flags & IXGBE_FLAG_DCB_ENABLED))
+			vlnctrl &= ~IXGBE_VLNCTRL_VME;
+#endif
+		vlnctrl &= ~IXGBE_VLNCTRL_CFIEN;
+		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
+		break;
+	case ixgbe_mac_82599EB:
+		vlnctrl &= ~IXGBE_VLNCTRL_VFE;
+		vlnctrl &= ~IXGBE_VLNCTRL_CFIEN;
+		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
+#ifdef CONFIG_IXGBE_DCB
+		if (adapter->flags & IXGBE_FLAG_DCB_ENABLED)
+			break;
+#endif
+		for (i = 0; i < adapter->num_rx_queues; i++) {
+			j = adapter->rx_ring[i]->reg_idx;
+			vlnctrl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(j));
+			vlnctrl &= ~IXGBE_RXDCTL_VME;
+			IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(j), vlnctrl);
+		}
+		break;
+	default:
+		break;
+	}
+}
+
+/**
+ * ixgbe_vlan_filter_enable - helper to enable hw vlan filtering
+ * @adapter: driver data
+ */
+static void ixgbe_vlan_filter_enable(struct ixgbe_adapter *adapter)
+{
+	struct ixgbe_hw *hw = &adapter->hw;
+	u32 vlnctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
+	int i, j;
+
+	switch (hw->mac.type) {
+	case ixgbe_mac_82598EB:
+		vlnctrl |= IXGBE_VLNCTRL_VME | IXGBE_VLNCTRL_VFE;
+		vlnctrl &= ~IXGBE_VLNCTRL_CFIEN;
+		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
+		break;
+	case ixgbe_mac_82599EB:
+		vlnctrl |= IXGBE_VLNCTRL_VFE;
+		vlnctrl &= ~IXGBE_VLNCTRL_CFIEN;
+		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
+		for (i = 0; i < adapter->num_rx_queues; i++) {
+			j = adapter->rx_ring[i]->reg_idx;
+			vlnctrl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(j));
+			vlnctrl |= IXGBE_RXDCTL_VME;
+			IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(j), vlnctrl);
+		}
+		break;
+	default:
+		break;
+	}
+}
+
 static void ixgbe_vlan_rx_register(struct net_device *netdev,
                                    struct vlan_group *grp)
 {
 	struct ixgbe_adapter *adapter = netdev_priv(netdev);
-	u32 ctrl;
-	int i, j;
 
 	if (!test_bit(__IXGBE_DOWN, &adapter->state))
 		ixgbe_irq_disable(adapter);
@@ -2498,25 +2969,7 @@ static void ixgbe_vlan_rx_register(struct net_device *netdev,
 	 * still receive traffic from a DCB-enabled host even if we're
 	 * not in DCB mode.
 	 */
-	ctrl = IXGBE_READ_REG(&adapter->hw, IXGBE_VLNCTRL);
-
-	/* Disable CFI check */
-	ctrl &= ~IXGBE_VLNCTRL_CFIEN;
-
-	/* enable VLAN tag stripping */
-	if (adapter->hw.mac.type == ixgbe_mac_82598EB) {
-		ctrl |= IXGBE_VLNCTRL_VME;
-	} else if (adapter->hw.mac.type == ixgbe_mac_82599EB) {
-		for (i = 0; i < adapter->num_rx_queues; i++) {
-			u32 ctrl;
-			j = adapter->rx_ring[i]->reg_idx;
-			ctrl = IXGBE_READ_REG(&adapter->hw, IXGBE_RXDCTL(j));
-			ctrl |= IXGBE_RXDCTL_VME;
-			IXGBE_WRITE_REG(&adapter->hw, IXGBE_RXDCTL(j), ctrl);
-		}
-	}
-
-	IXGBE_WRITE_REG(&adapter->hw, IXGBE_VLNCTRL, ctrl);
+	ixgbe_vlan_filter_enable(adapter);
 
 	ixgbe_vlan_rx_add_vid(netdev, 0);
 
@@ -2551,30 +3004,29 @@ void ixgbe_set_rx_mode(struct net_device *netdev)
 {
 	struct ixgbe_adapter *adapter = netdev_priv(netdev);
 	struct ixgbe_hw *hw = &adapter->hw;
-	u32 fctrl, vlnctrl;
+	u32 fctrl;
 
 	/* Check for Promiscuous and All Multicast modes */
 
 	fctrl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
-	vlnctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
 
 	if (netdev->flags & IFF_PROMISC) {
-		hw->addr_ctrl.user_set_promisc = 1;
+		hw->addr_ctrl.user_set_promisc = true;
 		fctrl |= (IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
-		vlnctrl &= ~IXGBE_VLNCTRL_VFE;
+		/* don't hardware filter vlans in promisc mode */
+		ixgbe_vlan_filter_disable(adapter);
 	} else {
 		if (netdev->flags & IFF_ALLMULTI) {
 			fctrl |= IXGBE_FCTRL_MPE;
 			fctrl &= ~IXGBE_FCTRL_UPE;
-		} else {
+		} else if (!hw->addr_ctrl.uc_set_promisc) {
 			fctrl &= ~(IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
 		}
-		vlnctrl |= IXGBE_VLNCTRL_VFE;
-		hw->addr_ctrl.user_set_promisc = 0;
+		ixgbe_vlan_filter_enable(adapter);
+		hw->addr_ctrl.user_set_promisc = false;
 	}
 
 	IXGBE_WRITE_REG(hw, IXGBE_FCTRL, fctrl);
-	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
 
 	/* reprogram secondary unicast list */
 	hw->mac.ops.update_uc_addr_list(hw, netdev);
@@ -2641,7 +3093,7 @@ static void ixgbe_napi_disable_all(struct ixgbe_adapter *adapter)
 static void ixgbe_configure_dcb(struct ixgbe_adapter *adapter)
 {
 	struct ixgbe_hw *hw = &adapter->hw;
-	u32 txdctl, vlnctrl;
+	u32 txdctl;
 	int i, j;
 
 	ixgbe_dcb_check_config(&adapter->dcb_cfg);
@@ -2659,22 +3111,8 @@ static void ixgbe_configure_dcb(struct ixgbe_adapter *adapter)
 		IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(j), txdctl);
 	}
 	/* Enable VLAN tag insert/strip */
-	vlnctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
-	if (hw->mac.type == ixgbe_mac_82598EB) {
-		vlnctrl |= IXGBE_VLNCTRL_VME | IXGBE_VLNCTRL_VFE;
-		vlnctrl &= ~IXGBE_VLNCTRL_CFIEN;
-		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
-	} else if (hw->mac.type == ixgbe_mac_82599EB) {
-		vlnctrl |= IXGBE_VLNCTRL_VFE;
-		vlnctrl &= ~IXGBE_VLNCTRL_CFIEN;
-		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
-		for (i = 0; i < adapter->num_rx_queues; i++) {
-			j = adapter->rx_ring[i]->reg_idx;
-			vlnctrl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(j));
-			vlnctrl |= IXGBE_RXDCTL_VME;
-			IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(j), vlnctrl);
-		}
-	}
+	ixgbe_vlan_filter_enable(adapter);
+
 	hw->mac.ops.set_vfta(&adapter->hw, 0, 0, true);
 }
 
@@ -2730,8 +3168,10 @@ static inline bool ixgbe_is_sfp(struct ixgbe_hw *hw)
 	case ixgbe_phy_sfp_ftl:
 	case ixgbe_phy_sfp_intel:
 	case ixgbe_phy_sfp_unknown:
-	case ixgbe_phy_tw_tyco:
-	case ixgbe_phy_tw_unknown:
+	case ixgbe_phy_sfp_passive_tyco:
+	case ixgbe_phy_sfp_passive_unknown:
+	case ixgbe_phy_sfp_active_unknown:
+	case ixgbe_phy_sfp_ftl_active:
 		return true;
 	default:
 		return false;
@@ -2814,8 +3254,8 @@ static inline void ixgbe_rx_desc_queue_enable(struct ixgbe_adapter *adapter,
 			msleep(1);
 	}
 	if (k >= IXGBE_MAX_RX_DESC_POLL) {
-		DPRINTK(DRV, ERR, "RXDCTL.ENABLE on Rx queue %d "
-		        "not set within the polling period\n", rxr);
+		e_err("RXDCTL.ENABLE on Rx queue %d not set within "
+		      "the polling period\n", rxr);
 	}
 	ixgbe_release_rx_desc(&adapter->hw, adapter->rx_ring[rxr],
 	                      (adapter->rx_ring[rxr]->count - 1));
@@ -2875,6 +3315,13 @@ static int ixgbe_up_complete(struct ixgbe_adapter *adapter)
 		IXGBE_WRITE_REG(hw, IXGBE_EIAM, IXGBE_EICS_RTX_QUEUE);
 	}
 
+	/* Enable Thermal over heat sensor interrupt */
+	if (adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE) {
+		gpie = IXGBE_READ_REG(hw, IXGBE_GPIE);
+		gpie |= IXGBE_SDP0_GPIEN;
+		IXGBE_WRITE_REG(hw, IXGBE_GPIE, gpie);
+	}
+
 	/* Enable fan failure interrupt if media type is copper */
 	if (adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE) {
 		gpie = IXGBE_READ_REG(hw, IXGBE_GPIE);
@@ -2907,8 +3354,13 @@ static int ixgbe_up_complete(struct ixgbe_adapter *adapter)
 	for (i = 0; i < adapter->num_tx_queues; i++) {
 		j = adapter->tx_ring[i]->reg_idx;
 		txdctl = IXGBE_READ_REG(hw, IXGBE_TXDCTL(j));
-		/* enable WTHRESH=8 descriptors, to encourage burst writeback */
-		txdctl |= (8 << 16);
+		if (adapter->rx_itr_setting == 0) {
+			/* cannot set wthresh when itr==0 */
+			txdctl &= ~0x007F0000;
+		} else {
+			/* enable WTHRESH=8 descriptors, to encourage burst writeback */
+			txdctl |= (8 << 16);
+		}
 		IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(j), txdctl);
 	}
 
@@ -2932,8 +3384,7 @@ static int ixgbe_up_complete(struct ixgbe_adapter *adapter)
 			} while (--wait_loop &&
 			         !(txdctl & IXGBE_TXDCTL_ENABLE));
 			if (!wait_loop)
-				DPRINTK(DRV, ERR, "Could not enable "
-				        "Tx Queue %d\n", j);
+				e_err("Could not enable Tx Queue %d\n", j);
 		}
 	}
 
@@ -2962,6 +3413,10 @@ static int ixgbe_up_complete(struct ixgbe_adapter *adapter)
 	else
 		ixgbe_configure_msi_and_legacy(adapter);
 
+	/* enable the optics */
+	if (hw->phy.multispeed_fiber)
+		hw->mac.ops.enable_tx_laser(hw);
+
 	clear_bit(__IXGBE_DOWN, &adapter->state);
 	ixgbe_napi_enable_all(adapter);
 
@@ -2977,8 +3432,7 @@ static int ixgbe_up_complete(struct ixgbe_adapter *adapter)
 	if (adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE) {
 		u32 esdp = IXGBE_READ_REG(hw, IXGBE_ESDP);
 		if (esdp & IXGBE_ESDP_SDP1)
-			DPRINTK(DRV, CRIT,
-				"Fan has stopped, replace the adapter\n");
+			e_crit("Fan has stopped, replace the adapter\n");
 	}
 
 	/*
@@ -3007,7 +3461,7 @@ static int ixgbe_up_complete(struct ixgbe_adapter *adapter)
 	} else {
 		err = ixgbe_non_sfp_link_config(hw);
 		if (err)
-			DPRINTK(PROBE, ERR, "link_config FAILED %d\n", err);
+			e_err("link_config FAILED %d\n", err);
 	}
 
 	for (i = 0; i < adapter->num_tx_queues; i++)
@@ -3068,19 +3522,19 @@ void ixgbe_reset(struct ixgbe_adapter *adapter)
 	case IXGBE_ERR_SFP_NOT_PRESENT:
 		break;
 	case IXGBE_ERR_MASTER_REQUESTS_PENDING:
-		dev_err(&adapter->pdev->dev, "master disable timed out\n");
+		e_dev_err("master disable timed out\n");
 		break;
 	case IXGBE_ERR_EEPROM_VERSION:
 		/* We are running on a pre-production device, log a warning */
-		dev_warn(&adapter->pdev->dev, "This device is a pre-production "
-		         "adapter/LOM.  Please be aware there may be issues "
-		         "associated with your hardware.  If you are "
-		         "experiencing problems please contact your Intel or "
-		         "hardware representative who provided you with this "
-		         "hardware.\n");
+		e_dev_warn("This device is a pre-production adapter/LOM. "
+			   "Please be aware there may be issuesassociated with "
+			   "your hardware.  If you are experiencing problems "
+			   "please contact your Intel or hardware "
+			   "representative who provided you with this "
+			   "hardware.\n");
 		break;
 	default:
-		dev_err(&adapter->pdev->dev, "Hardware Error: %d\n", err);
+		e_dev_err("Hardware Error: %d\n", err);
 	}
 
 	/* reprogram the RAR[0] in case user changed it. */
@@ -3107,9 +3561,9 @@ static void ixgbe_clean_rx_ring(struct ixgbe_adapter *adapter,
 
 		rx_buffer_info = &rx_ring->rx_buffer_info[i];
 		if (rx_buffer_info->dma) {
-			pci_unmap_single(pdev, rx_buffer_info->dma,
+			dma_unmap_single(&pdev->dev, rx_buffer_info->dma,
 			                 rx_ring->rx_buf_len,
-			                 PCI_DMA_FROMDEVICE);
+					 DMA_FROM_DEVICE);
 			rx_buffer_info->dma = 0;
 		}
 		if (rx_buffer_info->skb) {
@@ -3117,11 +3571,13 @@ static void ixgbe_clean_rx_ring(struct ixgbe_adapter *adapter,
 			rx_buffer_info->skb = NULL;
 			do {
 				struct sk_buff *this = skb;
-				if (IXGBE_RSC_CB(this)->dma) {
-					pci_unmap_single(pdev, IXGBE_RSC_CB(this)->dma,
+				if (IXGBE_RSC_CB(this)->delay_unmap) {
+					dma_unmap_single(&pdev->dev,
+							 IXGBE_RSC_CB(this)->dma,
 					                 rx_ring->rx_buf_len,
-					                 PCI_DMA_FROMDEVICE);
+							 DMA_FROM_DEVICE);
 					IXGBE_RSC_CB(this)->dma = 0;
+					IXGBE_RSC_CB(skb)->delay_unmap = false;
 				}
 				skb = skb->prev;
 				dev_kfree_skb(this);
@@ -3130,8 +3586,8 @@ static void ixgbe_clean_rx_ring(struct ixgbe_adapter *adapter,
 		if (!rx_buffer_info->page)
 			continue;
 		if (rx_buffer_info->page_dma) {
-			pci_unmap_page(pdev, rx_buffer_info->page_dma,
-			               PAGE_SIZE / 2, PCI_DMA_FROMDEVICE);
+			dma_unmap_page(&pdev->dev, rx_buffer_info->page_dma,
+				       PAGE_SIZE / 2, DMA_FROM_DEVICE);
 			rx_buffer_info->page_dma = 0;
 		}
 		put_page(rx_buffer_info->page);
@@ -3223,6 +3679,10 @@ void ixgbe_down(struct ixgbe_adapter *adapter)
 	/* signal that we are down to the interrupt handler */
 	set_bit(__IXGBE_DOWN, &adapter->state);
 
+	/* power down the optics */
+	if (hw->phy.multispeed_fiber)
+		hw->mac.ops.disable_tx_laser(hw);
+
 	/* disable receive for all VFs and wait one second */
 	if (adapter->num_vfs) {
 		/* ping all the active vfs to let them know we are going down */
@@ -3240,26 +3700,30 @@ void ixgbe_down(struct ixgbe_adapter *adapter)
 	rxctrl = IXGBE_READ_REG(hw, IXGBE_RXCTRL);
 	IXGBE_WRITE_REG(hw, IXGBE_RXCTRL, rxctrl & ~IXGBE_RXCTRL_RXEN);
 
-	netif_tx_disable(netdev);
-
 	IXGBE_WRITE_FLUSH(hw);
 	msleep(10);
 
 	netif_tx_stop_all_queues(netdev);
 
-	ixgbe_irq_disable(adapter);
-
-	ixgbe_napi_disable_all(adapter);
-
 	clear_bit(__IXGBE_SFP_MODULE_NOT_FOUND, &adapter->state);
 	del_timer_sync(&adapter->sfp_timer);
 	del_timer_sync(&adapter->watchdog_timer);
 	cancel_work_sync(&adapter->watchdog_task);
 
+	netif_carrier_off(netdev);
+	netif_tx_disable(netdev);
+
+	ixgbe_irq_disable(adapter);
+
+	ixgbe_napi_disable_all(adapter);
+
 	if (adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE ||
 	    adapter->flags & IXGBE_FLAG_FDIR_PERFECT_CAPABLE)
 		cancel_work_sync(&adapter->fdir_reinit_task);
 
+	if (adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE)
+		cancel_work_sync(&adapter->check_overtemp_task);
+
 	/* disable transmits in the hardware now that interrupts are off */
 	for (i = 0; i < adapter->num_tx_queues; i++) {
 		j = adapter->tx_ring[i]->reg_idx;
@@ -3273,8 +3737,6 @@ void ixgbe_down(struct ixgbe_adapter *adapter)
 		                (IXGBE_READ_REG(hw, IXGBE_DMATXCTL) &
 		                 ~IXGBE_DMATXCTL_TE));
 
-	netif_carrier_off(netdev);
-
 	/* clear n-tuple filters that are cached */
 	ethtool_ntuple_flush(netdev);
 
@@ -3351,6 +3813,8 @@ static void ixgbe_reset_task(struct work_struct *work)
 
 	adapter->tx_timeout_count++;
 
+	ixgbe_dump(adapter);
+	netdev_err(adapter->netdev, "Reset adapter\n");
 	ixgbe_reinit_locked(adapter);
 }
 
@@ -3451,12 +3915,12 @@ static inline bool ixgbe_set_fcoe_queues(struct ixgbe_adapter *adapter)
 		adapter->num_tx_queues = 1;
 #ifdef CONFIG_IXGBE_DCB
 		if (adapter->flags & IXGBE_FLAG_DCB_ENABLED) {
-			DPRINTK(PROBE, INFO, "FCoE enabled with DCB\n");
+			e_info("FCoE enabled with DCB\n");
 			ixgbe_set_dcb_queues(adapter);
 		}
 #endif
 		if (adapter->flags & IXGBE_FLAG_RSS_ENABLED) {
-			DPRINTK(PROBE, INFO, "FCoE enabled with RSS\n");
+			e_info("FCoE enabled with RSS\n");
 			if ((adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE) ||
 			    (adapter->flags & IXGBE_FLAG_FDIR_PERFECT_CAPABLE))
 				ixgbe_set_fdir_queues(adapter);
@@ -3569,7 +4033,8 @@ static void ixgbe_acquire_msix_vectors(struct ixgbe_adapter *adapter,
 		 * This just means we'll go with either a single MSI
 		 * vector or fall back to legacy interrupts.
 		 */
-		DPRINTK(HW, DEBUG, "Unable to allocate MSI-X interrupts\n");
+		netif_printk(adapter, hw, KERN_DEBUG, adapter->netdev,
+			     "Unable to allocate MSI-X interrupts\n");
 		adapter->flags &= ~IXGBE_FLAG_MSIX_ENABLED;
 		kfree(adapter->msix_entries);
 		adapter->msix_entries = NULL;
@@ -3966,8 +4431,9 @@ static int ixgbe_set_interrupt_capability(struct ixgbe_adapter *adapter)
 	if (!err) {
 		adapter->flags |= IXGBE_FLAG_MSI_ENABLED;
 	} else {
-		DPRINTK(HW, DEBUG, "Unable to allocate MSI interrupt, "
-		        "falling back to legacy.  Error: %d\n", err);
+		netif_printk(adapter, hw, KERN_DEBUG, adapter->netdev,
+			     "Unable to allocate MSI interrupt, "
+			     "falling back to legacy.  Error: %d\n", err);
 		/* reset err */
 		err = 0;
 	}
@@ -4067,7 +4533,6 @@ static void ixgbe_reset_interrupt_capability(struct ixgbe_adapter *adapter)
 		adapter->flags &= ~IXGBE_FLAG_MSI_ENABLED;
 		pci_disable_msi(adapter->pdev);
 	}
-	return;
 }
 
 /**
@@ -4089,27 +4554,25 @@ int ixgbe_init_interrupt_scheme(struct ixgbe_adapter *adapter)
 
 	err = ixgbe_set_interrupt_capability(adapter);
 	if (err) {
-		DPRINTK(PROBE, ERR, "Unable to setup interrupt capabilities\n");
+		e_dev_err("Unable to setup interrupt capabilities\n");
 		goto err_set_interrupt;
 	}
 
 	err = ixgbe_alloc_q_vectors(adapter);
 	if (err) {
-		DPRINTK(PROBE, ERR, "Unable to allocate memory for queue "
-		        "vectors\n");
+		e_dev_err("Unable to allocate memory for queue vectors\n");
 		goto err_alloc_q_vectors;
 	}
 
 	err = ixgbe_alloc_queues(adapter);
 	if (err) {
-		DPRINTK(PROBE, ERR, "Unable to allocate memory for queues\n");
+		e_dev_err("Unable to allocate memory for queues\n");
 		goto err_alloc_queues;
 	}
 
-	DPRINTK(DRV, INFO, "Multiqueue %s: Rx Queue count = %u, "
-	        "Tx Queue count = %u\n",
-	        (adapter->num_rx_queues > 1) ? "Enabled" :
-	        "Disabled", adapter->num_rx_queues, adapter->num_tx_queues);
+	e_dev_info("Multiqueue %s: Rx Queue count = %u, Tx Queue count = %u\n",
+	       (adapter->num_rx_queues > 1) ? "Enabled" : "Disabled",
+	       adapter->num_rx_queues, adapter->num_tx_queues);
 
 	set_bit(__IXGBE_DOWN, &adapter->state);
 
@@ -4180,15 +4643,13 @@ static void ixgbe_sfp_task(struct work_struct *work)
 			goto reschedule;
 		ret = hw->phy.ops.reset(hw);
 		if (ret == IXGBE_ERR_SFP_NOT_SUPPORTED) {
-			dev_err(&adapter->pdev->dev, "failed to initialize "
-				"because an unsupported SFP+ module type "
-				"was detected.\n"
-				"Reload the driver after installing a "
-				"supported module.\n");
+			e_dev_err("failed to initialize because an unsupported "
+				  "SFP+ module type was detected.\n");
+			e_dev_err("Reload the driver after installing a "
+				  "supported module.\n");
 			unregister_netdev(adapter->netdev);
 		} else {
-			DPRINTK(PROBE, INFO, "detected SFP+: %d\n",
-			        hw->phy.sfp_type);
+			e_info("detected SFP+: %d\n", hw->phy.sfp_type);
 		}
 		/* don't need this routine any more */
 		clear_bit(__IXGBE_SFP_MODULE_NOT_FOUND, &adapter->state);
@@ -4240,6 +4701,8 @@ static int __devinit ixgbe_sw_init(struct ixgbe_adapter *adapter)
 		adapter->max_msix_q_vectors = MAX_MSIX_Q_VECTORS_82599;
 		adapter->flags2 |= IXGBE_FLAG2_RSC_CAPABLE;
 		adapter->flags2 |= IXGBE_FLAG2_RSC_ENABLED;
+		if (hw->device_id == IXGBE_DEV_ID_82599_T3_LOM)
+			adapter->flags2 |= IXGBE_FLAG2_TEMP_SENSOR_CAPABLE;
 		if (dev->features & NETIF_F_NTUPLE) {
 			/* Flow Director perfect filter enabled */
 			adapter->flags |= IXGBE_FLAG_FDIR_PERFECT_CAPABLE;
@@ -4313,7 +4776,7 @@ static int __devinit ixgbe_sw_init(struct ixgbe_adapter *adapter)
 
 	/* initialize eeprom parameters */
 	if (ixgbe_init_eeprom_params_generic(hw)) {
-		dev_err(&pdev->dev, "EEPROM initialization failed\n");
+		e_dev_err("EEPROM initialization failed\n");
 		return -EIO;
 	}
 
@@ -4353,8 +4816,8 @@ int ixgbe_setup_tx_resources(struct ixgbe_adapter *adapter,
 	tx_ring->size = tx_ring->count * sizeof(union ixgbe_adv_tx_desc);
 	tx_ring->size = ALIGN(tx_ring->size, 4096);
 
-	tx_ring->desc = pci_alloc_consistent(pdev, tx_ring->size,
-	                                     &tx_ring->dma);
+	tx_ring->desc = dma_alloc_coherent(&pdev->dev, tx_ring->size,
+					   &tx_ring->dma, GFP_KERNEL);
 	if (!tx_ring->desc)
 		goto err;
 
@@ -4366,8 +4829,7 @@ int ixgbe_setup_tx_resources(struct ixgbe_adapter *adapter,
 err:
 	vfree(tx_ring->tx_buffer_info);
 	tx_ring->tx_buffer_info = NULL;
-	DPRINTK(PROBE, ERR, "Unable to allocate memory for the transmit "
-	                    "descriptor ring\n");
+	e_err("Unable to allocate memory for the Tx descriptor ring\n");
 	return -ENOMEM;
 }
 
@@ -4389,7 +4851,7 @@ static int ixgbe_setup_all_tx_resources(struct ixgbe_adapter *adapter)
 		err = ixgbe_setup_tx_resources(adapter, adapter->tx_ring[i]);
 		if (!err)
 			continue;
-		DPRINTK(PROBE, ERR, "Allocation for Tx Queue %u failed\n", i);
+		e_err("Allocation for Tx Queue %u failed\n", i);
 		break;
 	}
 
@@ -4414,8 +4876,7 @@ int ixgbe_setup_rx_resources(struct ixgbe_adapter *adapter,
 	if (!rx_ring->rx_buffer_info)
 		rx_ring->rx_buffer_info = vmalloc(size);
 	if (!rx_ring->rx_buffer_info) {
-		DPRINTK(PROBE, ERR,
-		        "vmalloc allocation failed for the rx desc ring\n");
+		e_err("vmalloc allocation failed for the Rx desc ring\n");
 		goto alloc_failed;
 	}
 	memset(rx_ring->rx_buffer_info, 0, size);
@@ -4424,11 +4885,11 @@ int ixgbe_setup_rx_resources(struct ixgbe_adapter *adapter,
 	rx_ring->size = rx_ring->count * sizeof(union ixgbe_adv_rx_desc);
 	rx_ring->size = ALIGN(rx_ring->size, 4096);
 
-	rx_ring->desc = pci_alloc_consistent(pdev, rx_ring->size, &rx_ring->dma);
+	rx_ring->desc = dma_alloc_coherent(&pdev->dev, rx_ring->size,
+					   &rx_ring->dma, GFP_KERNEL);
 
 	if (!rx_ring->desc) {
-		DPRINTK(PROBE, ERR,
-		        "Memory allocation failed for the rx desc ring\n");
+		e_err("Memory allocation failed for the Rx desc ring\n");
 		vfree(rx_ring->rx_buffer_info);
 		goto alloc_failed;
 	}
@@ -4461,7 +4922,7 @@ static int ixgbe_setup_all_rx_resources(struct ixgbe_adapter *adapter)
 		err = ixgbe_setup_rx_resources(adapter, adapter->rx_ring[i]);
 		if (!err)
 			continue;
-		DPRINTK(PROBE, ERR, "Allocation for Rx Queue %u failed\n", i);
+		e_err("Allocation for Rx Queue %u failed\n", i);
 		break;
 	}
 
@@ -4485,7 +4946,8 @@ void ixgbe_free_tx_resources(struct ixgbe_adapter *adapter,
 	vfree(tx_ring->tx_buffer_info);
 	tx_ring->tx_buffer_info = NULL;
 
-	pci_free_consistent(pdev, tx_ring->size, tx_ring->desc, tx_ring->dma);
+	dma_free_coherent(&pdev->dev, tx_ring->size, tx_ring->desc,
+			  tx_ring->dma);
 
 	tx_ring->desc = NULL;
 }
@@ -4522,7 +4984,8 @@ void ixgbe_free_rx_resources(struct ixgbe_adapter *adapter,
 	vfree(rx_ring->rx_buffer_info);
 	rx_ring->rx_buffer_info = NULL;
 
-	pci_free_consistent(pdev, rx_ring->size, rx_ring->desc, rx_ring->dma);
+	dma_free_coherent(&pdev->dev, rx_ring->size, rx_ring->desc,
+			  rx_ring->dma);
 
 	rx_ring->desc = NULL;
 }
@@ -4558,8 +5021,7 @@ static int ixgbe_change_mtu(struct net_device *netdev, int new_mtu)
 	if ((new_mtu < 68) || (max_frame > IXGBE_MAX_JUMBO_FRAME_SIZE))
 		return -EINVAL;
 
-	DPRINTK(PROBE, INFO, "changing MTU from %d to %d\n",
-	        netdev->mtu, new_mtu);
+	e_info("changing MTU from %d to %d\n", netdev->mtu, new_mtu);
 	/* must set new MTU before calling down or up */
 	netdev->mtu = new_mtu;
 
@@ -4672,8 +5134,7 @@ static int ixgbe_resume(struct pci_dev *pdev)
 
 	err = pci_enable_device_mem(pdev);
 	if (err) {
-		printk(KERN_ERR "ixgbe: Cannot enable PCI device from "
-				"suspend\n");
+		e_dev_err("Cannot enable PCI device from suspend\n");
 		return err;
 	}
 	pci_set_master(pdev);
@@ -4682,8 +5143,7 @@ static int ixgbe_resume(struct pci_dev *pdev)
 
 	err = ixgbe_init_interrupt_scheme(adapter);
 	if (err) {
-		printk(KERN_ERR "ixgbe: Cannot initialize interrupts for "
-		                "device\n");
+		e_dev_err("Cannot initialize interrupts for device\n");
 		return err;
 	}
 
@@ -5051,10 +5511,10 @@ static void ixgbe_sfp_config_module_task(struct work_struct *work)
 	err = hw->phy.ops.identify_sfp(hw);
 
 	if (err == IXGBE_ERR_SFP_NOT_SUPPORTED) {
-		dev_err(&adapter->pdev->dev, "failed to initialize because "
-			"an unsupported SFP+ module type was detected.\n"
-			"Reload the driver after installing a supported "
-			"module.\n");
+		e_dev_err("failed to initialize because an unsupported SFP+ "
+			  "module type was detected.\n");
+		e_dev_err("Reload the driver after installing a supported "
+			  "module.\n");
 		unregister_netdev(adapter->netdev);
 		return;
 	}
@@ -5083,8 +5543,8 @@ static void ixgbe_fdir_reinit_task(struct work_struct *work)
 			set_bit(__IXGBE_FDIR_INIT_DONE,
 			        &(adapter->tx_ring[i]->reinit_state));
 	} else {
-		DPRINTK(PROBE, ERR, "failed to finish FDIR re-initialization, "
-			"ignored adding FDIR ATR filters\n");
+		e_err("failed to finish FDIR re-initialization, "
+		      "ignored adding FDIR ATR filters\n");
 	}
 	/* Done FDIR Re-initialization, enable transmits */
 	netif_tx_start_all_queues(adapter->netdev);
@@ -5155,16 +5615,14 @@ static void ixgbe_watchdog_task(struct work_struct *work)
 				flow_tx = !!(rmcs & IXGBE_RMCS_TFCE_802_3X);
 			}
 
-			printk(KERN_INFO "ixgbe: %s NIC Link is Up %s, "
-			       "Flow Control: %s\n",
-			       netdev->name,
+			e_info("NIC Link is Up %s, Flow Control: %s\n",
 			       (link_speed == IXGBE_LINK_SPEED_10GB_FULL ?
-			        "10 Gbps" :
-			        (link_speed == IXGBE_LINK_SPEED_1GB_FULL ?
-			         "1 Gbps" : "unknown speed")),
+			       "10 Gbps" :
+			       (link_speed == IXGBE_LINK_SPEED_1GB_FULL ?
+			       "1 Gbps" : "unknown speed")),
 			       ((flow_rx && flow_tx) ? "RX/TX" :
-			        (flow_rx ? "RX" :
-			        (flow_tx ? "TX" : "None"))));
+			       (flow_rx ? "RX" :
+			       (flow_tx ? "TX" : "None"))));
 
 			netif_carrier_on(netdev);
 		} else {
@@ -5175,8 +5633,7 @@ static void ixgbe_watchdog_task(struct work_struct *work)
 		adapter->link_up = false;
 		adapter->link_speed = 0;
 		if (netif_carrier_ok(netdev)) {
-			printk(KERN_INFO "ixgbe: %s NIC Link is Down\n",
-			       netdev->name);
+			e_info("NIC Link is Down\n");
 			netif_carrier_off(netdev);
 		}
 	}
@@ -5352,9 +5809,8 @@ static bool ixgbe_tx_csum(struct ixgbe_adapter *adapter,
 				break;
 			default:
 				if (unlikely(net_ratelimit())) {
-					DPRINTK(PROBE, WARNING,
-					 "partial checksum but proto=%x!\n",
-					 skb->protocol);
+					e_warn("partial checksum but "
+					       "proto=%x!\n", skb->protocol);
 				}
 				break;
 			}
@@ -5404,10 +5860,10 @@ static int ixgbe_tx_map(struct ixgbe_adapter *adapter,
 
 		tx_buffer_info->length = size;
 		tx_buffer_info->mapped_as_page = false;
-		tx_buffer_info->dma = pci_map_single(pdev,
+		tx_buffer_info->dma = dma_map_single(&pdev->dev,
 						     skb->data + offset,
-						     size, PCI_DMA_TODEVICE);
-		if (pci_dma_mapping_error(pdev, tx_buffer_info->dma))
+						     size, DMA_TO_DEVICE);
+		if (dma_mapping_error(&pdev->dev, tx_buffer_info->dma))
 			goto dma_error;
 		tx_buffer_info->time_stamp = jiffies;
 		tx_buffer_info->next_to_watch = i;
@@ -5440,12 +5896,12 @@ static int ixgbe_tx_map(struct ixgbe_adapter *adapter,
 			size = min(len, (uint)IXGBE_MAX_DATA_PER_TXD);
 
 			tx_buffer_info->length = size;
-			tx_buffer_info->dma = pci_map_page(adapter->pdev,
+			tx_buffer_info->dma = dma_map_page(&adapter->pdev->dev,
 							   frag->page,
 							   offset, size,
-							   PCI_DMA_TODEVICE);
+							   DMA_TO_DEVICE);
 			tx_buffer_info->mapped_as_page = true;
-			if (pci_dma_mapping_error(pdev, tx_buffer_info->dma))
+			if (dma_mapping_error(&pdev->dev, tx_buffer_info->dma))
 				goto dma_error;
 			tx_buffer_info->time_stamp = jiffies;
 			tx_buffer_info->next_to_watch = i;
@@ -5465,7 +5921,7 @@ static int ixgbe_tx_map(struct ixgbe_adapter *adapter,
 	return count;
 
 dma_error:
-	dev_err(&pdev->dev, "TX DMA map failed\n");
+	e_dev_err("TX DMA map failed\n");
 
 	/* clear timestamp and dma mappings for failed tx_buffer_info map */
 	tx_buffer_info->dma = 0;
@@ -5686,7 +6142,8 @@ static netdev_tx_t ixgbe_xmit_frame(struct sk_buff *skb,
 		}
 		tx_flags <<= IXGBE_TX_FLAGS_VLAN_SHIFT;
 		tx_flags |= IXGBE_TX_FLAGS_VLAN;
-	} else if (adapter->flags & IXGBE_FLAG_DCB_ENABLED) {
+	} else if (adapter->flags & IXGBE_FLAG_DCB_ENABLED &&
+		   skb->priority != TC_PRIO_CONTROL) {
 		tx_flags |= ((skb->queue_mapping & 0x7) << 13);
 		tx_flags <<= IXGBE_TX_FLAGS_VLAN_SHIFT;
 		tx_flags |= IXGBE_TX_FLAGS_VLAN;
@@ -5931,6 +6388,10 @@ static const struct net_device_ops ixgbe_netdev_ops = {
 	.ndo_vlan_rx_add_vid	= ixgbe_vlan_rx_add_vid,
 	.ndo_vlan_rx_kill_vid	= ixgbe_vlan_rx_kill_vid,
 	.ndo_do_ioctl		= ixgbe_ioctl,
+	.ndo_set_vf_mac		= ixgbe_ndo_set_vf_mac,
+	.ndo_set_vf_vlan	= ixgbe_ndo_set_vf_vlan,
+	.ndo_set_vf_tx_rate	= ixgbe_ndo_set_vf_bw,
+	.ndo_get_vf_config	= ixgbe_ndo_get_vf_config,
 #ifdef CONFIG_NET_POLL_CONTROLLER
 	.ndo_poll_controller	= ixgbe_netpoll,
 #endif
@@ -5962,8 +6423,7 @@ static void __devinit ixgbe_probe_vf(struct ixgbe_adapter *adapter,
 	adapter->flags |= IXGBE_FLAG_SRIOV_ENABLED;
 	err = pci_enable_sriov(adapter->pdev, adapter->num_vfs);
 	if (err) {
-		DPRINTK(PROBE, ERR,
-			"Failed to enable PCI sriov: %d\n", err);
+		e_err("Failed to enable PCI sriov: %d\n", err);
 		goto err_novfs;
 	}
 	/* If call to enable VFs succeeded then allocate memory
@@ -5987,9 +6447,8 @@ static void __devinit ixgbe_probe_vf(struct ixgbe_adapter *adapter,
 	}
 
 	/* Oh oh */
-	DPRINTK(PROBE, ERR,
-		"Unable to allocate memory for VF "
-		"Data Storage - SRIOV disabled\n");
+	e_err("Unable to allocate memory for VF Data Storage - SRIOV "
+	      "disabled\n");
 	pci_disable_sriov(adapter->pdev);
 
 err_novfs:
@@ -6028,16 +6487,17 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	if (err)
 		return err;
 
-	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64)) &&
-	    !pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64))) {
+	if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(64)) &&
+	    !dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64))) {
 		pci_using_dac = 1;
 	} else {
-		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
+		err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
 		if (err) {
-			err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
+			err = dma_set_coherent_mask(&pdev->dev,
+						    DMA_BIT_MASK(32));
 			if (err) {
-				dev_err(&pdev->dev, "No usable DMA "
-				        "configuration, aborting\n");
+				e_dev_err("No usable DMA configuration, "
+					  "aborting\n");
 				goto err_dma;
 			}
 		}
@@ -6047,8 +6507,7 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	err = pci_request_selected_regions(pdev, pci_select_bars(pdev,
 	                                   IORESOURCE_MEM), ixgbe_driver_name);
 	if (err) {
-		dev_err(&pdev->dev,
-		        "pci_request_selected_regions failed 0x%x\n", err);
+		e_dev_err("pci_request_selected_regions failed 0x%x\n", err);
 		goto err_pci_reg;
 	}
 
@@ -6159,12 +6618,13 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	if (adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE) {
 		u32 esdp = IXGBE_READ_REG(hw, IXGBE_ESDP);
 		if (esdp & IXGBE_ESDP_SDP1)
-			DPRINTK(PROBE, CRIT,
-				"Fan has stopped, replace the adapter\n");
+			e_crit("Fan has stopped, replace the adapter\n");
 	}
 
 	/* reset_hw fills in the perm_addr as well */
+	hw->phy.reset_if_overtemp = true;
 	err = hw->mac.ops.reset_hw(hw);
+	hw->phy.reset_if_overtemp = false;
 	if (err == IXGBE_ERR_SFP_NOT_PRESENT &&
 	    hw->mac.type == ixgbe_mac_82598EB) {
 		/*
@@ -6177,19 +6637,19 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 			  round_jiffies(jiffies + (2 * HZ)));
 		err = 0;
 	} else if (err == IXGBE_ERR_SFP_NOT_SUPPORTED) {
-		dev_err(&adapter->pdev->dev, "failed to initialize because "
-			"an unsupported SFP+ module type was detected.\n"
-			"Reload the driver after installing a supported "
-			"module.\n");
+		e_dev_err("failed to initialize because an unsupported SFP+ "
+			  "module type was detected.\n");
+		e_dev_err("Reload the driver after installing a supported "
+			  "module.\n");
 		goto err_sw_init;
 	} else if (err) {
-		dev_err(&adapter->pdev->dev, "HW Init failed: %d\n", err);
+		e_dev_err("HW Init failed: %d\n", err);
 		goto err_sw_init;
 	}
 
 	ixgbe_probe_vf(adapter, ii);
 
-	netdev->features = NETIF_F_SG |
+	netdev->features =    NETIF_F_SG |
 	                   NETIF_F_IP_CSUM |
 	                   NETIF_F_HW_VLAN_TX |
 	                   NETIF_F_HW_VLAN_RX |
@@ -6236,7 +6696,7 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 
 	/* make sure the EEPROM is good */
 	if (hw->eeprom.ops.validate_checksum(hw, NULL) < 0) {
-		dev_err(&pdev->dev, "The EEPROM Checksum Is Not Valid\n");
+		e_dev_err("The EEPROM Checksum Is Not Valid\n");
 		err = -EIO;
 		goto err_eeprom;
 	}
@@ -6245,11 +6705,15 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	memcpy(netdev->perm_addr, hw->mac.perm_addr, netdev->addr_len);
 
 	if (ixgbe_validate_mac_addr(netdev->perm_addr)) {
-		dev_err(&pdev->dev, "invalid MAC address\n");
+		e_dev_err("invalid MAC address\n");
 		err = -EIO;
 		goto err_eeprom;
 	}
 
+	/* power down the optics */
+	if (hw->phy.multispeed_fiber)
+		hw->mac.ops.disable_tx_laser(hw);
+
 	init_timer(&adapter->watchdog_timer);
 	adapter->watchdog_timer.function = &ixgbe_watchdog;
 	adapter->watchdog_timer.data = (unsigned long)adapter;
@@ -6276,7 +6740,7 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	hw->mac.ops.get_bus_info(hw);
 
 	/* print bus type/speed/width info */
-	dev_info(&pdev->dev, "(PCI Express:%s:%s) %pM\n",
+	e_dev_info("(PCI Express:%s:%s) %pM\n",
 	        ((hw->bus.speed == ixgbe_bus_speed_5000) ? "5.0Gb/s":
 	         (hw->bus.speed == ixgbe_bus_speed_2500) ? "2.5Gb/s":"Unknown"),
 	        ((hw->bus.width == ixgbe_bus_width_pcie_x8) ? "Width x8" :
@@ -6286,20 +6750,20 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	        netdev->dev_addr);
 	ixgbe_read_pba_num_generic(hw, &part_num);
 	if (ixgbe_is_sfp(hw) && hw->phy.sfp_type != ixgbe_sfp_type_not_present)
-		dev_info(&pdev->dev, "MAC: %d, PHY: %d, SFP+: %d, PBA No: %06x-%03x\n",
-		         hw->mac.type, hw->phy.type, hw->phy.sfp_type,
-		         (part_num >> 8), (part_num & 0xff));
+		e_dev_info("MAC: %d, PHY: %d, SFP+: %d, "
+			   "PBA No: %06x-%03x\n",
+			   hw->mac.type, hw->phy.type, hw->phy.sfp_type,
+			   (part_num >> 8), (part_num & 0xff));
 	else
-		dev_info(&pdev->dev, "MAC: %d, PHY: %d, PBA No: %06x-%03x\n",
-		         hw->mac.type, hw->phy.type,
-		         (part_num >> 8), (part_num & 0xff));
+		e_dev_info("MAC: %d, PHY: %d, PBA No: %06x-%03x\n",
+			   hw->mac.type, hw->phy.type,
+			   (part_num >> 8), (part_num & 0xff));
 
 	if (hw->bus.width <= ixgbe_bus_width_pcie_x4) {
-		dev_warn(&pdev->dev, "PCI-Express bandwidth available for "
-		         "this card is not sufficient for optimal "
-		         "performance.\n");
-		dev_warn(&pdev->dev, "For optimal performance a x8 "
-		         "PCI-Express slot is required.\n");
+		e_dev_warn("PCI-Express bandwidth available for this card is "
+			   "not sufficient for optimal performance.\n");
+		e_dev_warn("For optimal performance a x8 PCI-Express slot "
+			   "is required.\n");
 	}
 
 	/* save off EEPROM version number */
@@ -6310,12 +6774,12 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 
 	if (err == IXGBE_ERR_EEPROM_VERSION) {
 		/* We are running on a pre-production device, log a warning */
-		dev_warn(&pdev->dev, "This device is a pre-production "
-		         "adapter/LOM.  Please be aware there may be issues "
-		         "associated with your hardware.  If you are "
-		         "experiencing problems please contact your Intel or "
-		         "hardware representative who provided you with this "
-		         "hardware.\n");
+		e_dev_warn("This device is a pre-production adapter/LOM. "
+			   "Please be aware there may be issues associated "
+			   "with your hardware.  If you are experiencing "
+			   "problems please contact your Intel or hardware "
+			   "representative who provided you with this "
+			   "hardware.\n");
 	}
 	strcpy(netdev->name, "eth%d");
 	err = register_netdev(netdev);
@@ -6329,6 +6793,8 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	    adapter->flags & IXGBE_FLAG_FDIR_PERFECT_CAPABLE)
 		INIT_WORK(&adapter->fdir_reinit_task, ixgbe_fdir_reinit_task);
 
+	if (adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE)
+		INIT_WORK(&adapter->check_overtemp_task, ixgbe_check_overtemp_task);
 #ifdef CONFIG_IXGBE_DCA
 	if (dca_add_requester(&pdev->dev) == 0) {
 		adapter->flags |= IXGBE_FLAG_DCA_ENABLED;
@@ -6336,8 +6802,7 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	}
 #endif
 	if (adapter->flags & IXGBE_FLAG_SRIOV_ENABLED) {
-		DPRINTK(PROBE, INFO, "IOV is enabled with %d VFs\n",
-			adapter->num_vfs);
+		e_info("IOV is enabled with %d VFs\n", adapter->num_vfs);
 		for (i = 0; i < adapter->num_vfs; i++)
 			ixgbe_vf_configuration(pdev, (i | 0x10000000));
 	}
@@ -6345,7 +6810,7 @@ static int __devinit ixgbe_probe(struct pci_dev *pdev,
 	/* add san mac addr to netdev */
 	ixgbe_add_sanmac_netdev(netdev);
 
-	dev_info(&pdev->dev, "Intel(R) 10 Gigabit Network Connection\n");
+	e_dev_info("Intel(R) 10 Gigabit Network Connection\n");
 	cards_found++;
 	return 0;
 
@@ -6397,16 +6862,6 @@ static void __devexit ixgbe_remove(struct pci_dev *pdev)
 	del_timer_sync(&adapter->sfp_timer);
 	cancel_work_sync(&adapter->watchdog_task);
 	cancel_work_sync(&adapter->sfp_task);
-	if (adapter->hw.phy.multispeed_fiber) {
-		struct ixgbe_hw *hw = &adapter->hw;
-		/*
-		 * Restart clause 37 autoneg, disable and re-enable
-		 * the tx laser, to clear & alert the link partner
-		 * that it needs to restart autotry
-		 */
-		hw->mac.autotry_restart = true;
-		hw->mac.ops.flap_tx_laser(hw);
-	}
 	cancel_work_sync(&adapter->multispeed_fiber_task);
 	cancel_work_sync(&adapter->sfp_config_module_task);
 	if (adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE ||
@@ -6445,7 +6900,7 @@ static void __devexit ixgbe_remove(struct pci_dev *pdev)
 	pci_release_selected_regions(pdev, pci_select_bars(pdev,
 	                             IORESOURCE_MEM));
 
-	DPRINTK(PROBE, INFO, "complete\n");
+	e_dev_info("complete\n");
 
 	free_netdev(netdev);
 
@@ -6495,8 +6950,7 @@ static pci_ers_result_t ixgbe_io_slot_reset(struct pci_dev *pdev)
 	int err;
 
 	if (pci_enable_device_mem(pdev)) {
-		DPRINTK(PROBE, ERR,
-		        "Cannot re-enable PCI device after reset.\n");
+		e_err("Cannot re-enable PCI device after reset.\n");
 		result = PCI_ERS_RESULT_DISCONNECT;
 	} else {
 		pci_set_master(pdev);
@@ -6512,8 +6966,8 @@ static pci_ers_result_t ixgbe_io_slot_reset(struct pci_dev *pdev)
 
 	err = pci_cleanup_aer_uncorrect_error_status(pdev);
 	if (err) {
-		dev_err(&pdev->dev,
-		  "pci_cleanup_aer_uncorrect_error_status failed 0x%0x\n", err);
+		e_dev_err("pci_cleanup_aer_uncorrect_error_status "
+			  "failed 0x%0x\n", err);
 		/* non-fatal, continue */
 	}
 
@@ -6534,7 +6988,7 @@ static void ixgbe_io_resume(struct pci_dev *pdev)
 
 	if (netif_running(netdev)) {
 		if (ixgbe_up(adapter)) {
-			DPRINTK(PROBE, INFO, "ixgbe_up failed after reset\n");
+			e_info("ixgbe_up failed after reset\n");
 			return;
 		}
 	}
@@ -6570,10 +7024,9 @@ static struct pci_driver ixgbe_driver = {
 static int __init ixgbe_init_module(void)
 {
 	int ret;
-	printk(KERN_INFO "%s: %s - version %s\n", ixgbe_driver_name,
-	       ixgbe_driver_string, ixgbe_driver_version);
-
-	printk(KERN_INFO "%s: %s\n", ixgbe_driver_name, ixgbe_copyright);
+	pr_info("%s - version %s\n", ixgbe_driver_string,
+		   ixgbe_driver_version);
+	pr_info("%s\n", ixgbe_copyright);
 
 #ifdef CONFIG_IXGBE_DCA
 	dca_register_notify(&dca_notifier);
@@ -6612,18 +7065,17 @@ static int ixgbe_notify_dca(struct notifier_block *nb, unsigned long event,
 }
 
 #endif /* CONFIG_IXGBE_DCA */
-#ifdef DEBUG
+
 /**
- * ixgbe_get_hw_dev_name - return device name string
+ * ixgbe_get_hw_dev return device
  * used by hardware layer to print debugging information
  **/
-char *ixgbe_get_hw_dev_name(struct ixgbe_hw *hw)
+struct net_device *ixgbe_get_hw_dev(struct ixgbe_hw *hw)
 {
 	struct ixgbe_adapter *adapter = hw->back;
-	return adapter->netdev->name;
+	return adapter->netdev;
 }
 
-#endif
 module_exit(ixgbe_exit_module);
 
 /* ixgbe_main.c */
diff --git a/drivers/net/ixgbe/ixgbe_phy.c b/drivers/net/ixgbe/ixgbe_phy.c
index 306d0ee..9d91ed5 100644
--- a/drivers/net/ixgbe/ixgbe_phy.c
+++ b/drivers/net/ixgbe/ixgbe_phy.c
@@ -135,6 +135,11 @@ static enum ixgbe_phy_type ixgbe_get_phy_type_from_id(u32 phy_id)
  **/
 s32 ixgbe_reset_phy_generic(struct ixgbe_hw *hw)
 {
+	/* Don't reset PHY if it's shut down due to overtemp. */
+	if (!hw->phy.reset_if_overtemp &&
+	    (IXGBE_ERR_OVERTEMP == hw->phy.ops.check_overtemp(hw)))
+		return 0;
+
 	/*
 	 * Perform soft PHY reset to the PHY_XS.
 	 * This will cause a soft reset to the PHY
@@ -531,6 +536,7 @@ s32 ixgbe_identify_sfp_module_generic(struct ixgbe_hw *hw)
 	u8 comp_codes_10g = 0;
 	u8 oui_bytes[3] = {0, 0, 0};
 	u8 cable_tech = 0;
+	u8 cable_spec = 0;
 	u16 enforce_sfp = 0;
 
 	if (hw->mac.ops.get_media_type(hw) != ixgbe_media_type_fiber) {
@@ -580,14 +586,30 @@ s32 ixgbe_identify_sfp_module_generic(struct ixgbe_hw *hw)
 			else
 				hw->phy.sfp_type = ixgbe_sfp_type_unknown;
 		} else if (hw->mac.type == ixgbe_mac_82599EB) {
-			if (cable_tech & IXGBE_SFF_DA_PASSIVE_CABLE)
+			if (cable_tech & IXGBE_SFF_DA_PASSIVE_CABLE) {
 				if (hw->bus.lan_id == 0)
 					hw->phy.sfp_type =
 					             ixgbe_sfp_type_da_cu_core0;
 				else
 					hw->phy.sfp_type =
 					             ixgbe_sfp_type_da_cu_core1;
-			else if (comp_codes_10g & IXGBE_SFF_10GBASESR_CAPABLE)
+			} else if (cable_tech & IXGBE_SFF_DA_ACTIVE_CABLE) {
+				hw->phy.ops.read_i2c_eeprom(
+						hw, IXGBE_SFF_CABLE_SPEC_COMP,
+						&cable_spec);
+				if (cable_spec &
+				    IXGBE_SFF_DA_SPEC_ACTIVE_LIMITING) {
+					if (hw->bus.lan_id == 0)
+						hw->phy.sfp_type =
+						ixgbe_sfp_type_da_act_lmt_core0;
+					else
+						hw->phy.sfp_type =
+						ixgbe_sfp_type_da_act_lmt_core1;
+				} else {
+					hw->phy.sfp_type =
+						ixgbe_sfp_type_unknown;
+				}
+			} else if (comp_codes_10g & IXGBE_SFF_10GBASESR_CAPABLE)
 				if (hw->bus.lan_id == 0)
 					hw->phy.sfp_type =
 					              ixgbe_sfp_type_srlr_core0;
@@ -637,10 +659,14 @@ s32 ixgbe_identify_sfp_module_generic(struct ixgbe_hw *hw)
 			switch (vendor_oui) {
 			case IXGBE_SFF_VENDOR_OUI_TYCO:
 				if (cable_tech & IXGBE_SFF_DA_PASSIVE_CABLE)
-					hw->phy.type = ixgbe_phy_tw_tyco;
+					hw->phy.type =
+						ixgbe_phy_sfp_passive_tyco;
 				break;
 			case IXGBE_SFF_VENDOR_OUI_FTL:
-				hw->phy.type = ixgbe_phy_sfp_ftl;
+				if (cable_tech & IXGBE_SFF_DA_ACTIVE_CABLE)
+					hw->phy.type = ixgbe_phy_sfp_ftl_active;
+				else
+					hw->phy.type = ixgbe_phy_sfp_ftl;
 				break;
 			case IXGBE_SFF_VENDOR_OUI_AVAGO:
 				hw->phy.type = ixgbe_phy_sfp_avago;
@@ -650,7 +676,11 @@ s32 ixgbe_identify_sfp_module_generic(struct ixgbe_hw *hw)
 				break;
 			default:
 				if (cable_tech & IXGBE_SFF_DA_PASSIVE_CABLE)
-					hw->phy.type = ixgbe_phy_tw_unknown;
+					hw->phy.type =
+						ixgbe_phy_sfp_passive_unknown;
+				else if (cable_tech & IXGBE_SFF_DA_ACTIVE_CABLE)
+					hw->phy.type =
+						ixgbe_phy_sfp_active_unknown;
 				else
 					hw->phy.type = ixgbe_phy_sfp_unknown;
 				break;
@@ -658,7 +688,8 @@ s32 ixgbe_identify_sfp_module_generic(struct ixgbe_hw *hw)
 		}
 
 		/* All passive DA cables are supported */
-		if (cable_tech & IXGBE_SFF_DA_PASSIVE_CABLE) {
+		if (cable_tech & (IXGBE_SFF_DA_PASSIVE_CABLE |
+		    IXGBE_SFF_DA_ACTIVE_CABLE)) {
 			status = 0;
 			goto out;
 		}
@@ -1323,3 +1354,28 @@ s32 ixgbe_get_phy_firmware_version_tnx(struct ixgbe_hw *hw,
 	return status;
 }
 
+/**
+ *  ixgbe_tn_check_overtemp - Checks if an overtemp occured.
+ *  @hw: pointer to hardware structure
+ *
+ *  Checks if the LASI temp alarm status was triggered due to overtemp
+ **/
+s32 ixgbe_tn_check_overtemp(struct ixgbe_hw *hw)
+{
+	s32 status = 0;
+	u16 phy_data = 0;
+
+	if (hw->device_id != IXGBE_DEV_ID_82599_T3_LOM)
+		goto out;
+
+	/* Check that the LASI temp alarm status was triggered */
+	hw->phy.ops.read_reg(hw, IXGBE_TN_LASI_STATUS_REG,
+	                     MDIO_MMD_PMAPMD, &phy_data);
+
+	if (!(phy_data & IXGBE_TN_LASI_STATUS_TEMP_ALARM))
+		goto out;
+
+	status = IXGBE_ERR_OVERTEMP;
+out:
+	return status;
+}
diff --git a/drivers/net/ixgbe/ixgbe_phy.h b/drivers/net/ixgbe/ixgbe_phy.h
index 9cf5f3b..ef4ba83 100644
--- a/drivers/net/ixgbe/ixgbe_phy.h
+++ b/drivers/net/ixgbe/ixgbe_phy.h
@@ -40,9 +40,12 @@
 #define IXGBE_SFF_1GBE_COMP_CODES    0x6
 #define IXGBE_SFF_10GBE_COMP_CODES   0x3
 #define IXGBE_SFF_CABLE_TECHNOLOGY   0x8
+#define IXGBE_SFF_CABLE_SPEC_COMP    0x3C
 
 /* Bitmasks */
 #define IXGBE_SFF_DA_PASSIVE_CABLE           0x4
+#define IXGBE_SFF_DA_ACTIVE_CABLE            0x8
+#define IXGBE_SFF_DA_SPEC_ACTIVE_LIMITING    0x4
 #define IXGBE_SFF_1GBASESX_CAPABLE           0x1
 #define IXGBE_SFF_1GBASELX_CAPABLE           0x2
 #define IXGBE_SFF_10GBASESR_CAPABLE          0x10
@@ -77,6 +80,8 @@
 #define IXGBE_I2C_T_SU_STO  4
 #define IXGBE_I2C_T_BUF     5
 
+#define IXGBE_TN_LASI_STATUS_REG        0x9005
+#define IXGBE_TN_LASI_STATUS_TEMP_ALARM 0x0008
 
 s32 ixgbe_init_phy_ops_generic(struct ixgbe_hw *hw);
 s32 ixgbe_identify_phy_generic(struct ixgbe_hw *hw);
@@ -103,6 +108,7 @@ s32 ixgbe_identify_sfp_module_generic(struct ixgbe_hw *hw);
 s32 ixgbe_get_sfp_init_sequence_offsets(struct ixgbe_hw *hw,
                                         u16 *list_offset,
                                         u16 *data_offset);
+s32 ixgbe_tn_check_overtemp(struct ixgbe_hw *hw);
 s32 ixgbe_read_i2c_byte_generic(struct ixgbe_hw *hw, u8 byte_offset,
                                 u8 dev_addr, u8 *data);
 s32 ixgbe_write_i2c_byte_generic(struct ixgbe_hw *hw, u8 byte_offset,
diff --git a/drivers/net/ixgbe/ixgbe_sriov.c b/drivers/net/ixgbe/ixgbe_sriov.c
index d4cd20f..66f6e62 100644
--- a/drivers/net/ixgbe/ixgbe_sriov.c
+++ b/drivers/net/ixgbe/ixgbe_sriov.c
@@ -25,7 +25,6 @@
 
 *******************************************************************************/
 
-
 #include <linux/types.h>
 #include <linux/module.h>
 #include <linux/pci.h>
@@ -48,7 +47,11 @@ int ixgbe_set_vf_multicasts(struct ixgbe_adapter *adapter,
 			    int entries, u16 *hash_list, u32 vf)
 {
 	struct vf_data_storage *vfinfo = &adapter->vfinfo[vf];
+	struct ixgbe_hw *hw = &adapter->hw;
 	int i;
+	u32 vector_bit;
+	u32 vector_reg;
+	u32 mta_reg;
 
 	/* only so many hash values supported */
 	entries = min(entries, IXGBE_MAX_VF_MC_ENTRIES);
@@ -68,8 +71,13 @@ int ixgbe_set_vf_multicasts(struct ixgbe_adapter *adapter,
 		vfinfo->vf_mc_hashes[i] = hash_list[i];;
 	}
 
-	/* Flush and reset the mta with the new values */
-	ixgbe_set_rx_mode(adapter->netdev);
+	for (i = 0; i < vfinfo->num_vf_mc_hashes; i++) {
+		vector_reg = (vfinfo->vf_mc_hashes[i] >> 5) & 0x7F;
+		vector_bit = vfinfo->vf_mc_hashes[i] & 0x1F;
+		mta_reg = IXGBE_READ_REG(hw, IXGBE_MTA(vector_reg));
+		mta_reg |= (1 << vector_bit);
+		IXGBE_WRITE_REG(hw, IXGBE_MTA(vector_reg), mta_reg);
+	}
 
 	return 0;
 }
@@ -98,38 +106,51 @@ void ixgbe_restore_vf_multicasts(struct ixgbe_adapter *adapter)
 
 int ixgbe_set_vf_vlan(struct ixgbe_adapter *adapter, int add, int vid, u32 vf)
 {
-	u32 ctrl;
-
-	/* Check if global VLAN already set, if not set it */
-	ctrl = IXGBE_READ_REG(&adapter->hw, IXGBE_VLNCTRL);
-	if (!(ctrl & IXGBE_VLNCTRL_VFE)) {
-		/* enable VLAN tag insert/strip */
-		ctrl |= IXGBE_VLNCTRL_VFE;
-		ctrl &= ~IXGBE_VLNCTRL_CFIEN;
-		IXGBE_WRITE_REG(&adapter->hw, IXGBE_VLNCTRL, ctrl);
-	}
-
 	return adapter->hw.mac.ops.set_vfta(&adapter->hw, vid, vf, (bool)add);
 }
 
 
-void ixgbe_set_vmolr(struct ixgbe_hw *hw, u32 vf)
+void ixgbe_set_vmolr(struct ixgbe_hw *hw, u32 vf, bool aupe)
 {
 	u32 vmolr = IXGBE_READ_REG(hw, IXGBE_VMOLR(vf));
-	vmolr |= (IXGBE_VMOLR_AUPE |
-		  IXGBE_VMOLR_ROMPE |
+	vmolr |= (IXGBE_VMOLR_ROMPE |
 		  IXGBE_VMOLR_ROPE |
 		  IXGBE_VMOLR_BAM);
+	if (aupe)
+		vmolr |= IXGBE_VMOLR_AUPE;
+	else
+		vmolr &= ~IXGBE_VMOLR_AUPE;
 	IXGBE_WRITE_REG(hw, IXGBE_VMOLR(vf), vmolr);
 }
 
+static void ixgbe_set_vmvir(struct ixgbe_adapter *adapter, u32 vid, u32 vf)
+{
+	struct ixgbe_hw *hw = &adapter->hw;
+
+	if (vid)
+		IXGBE_WRITE_REG(hw, IXGBE_VMVIR(vf),
+				(vid | IXGBE_VMVIR_VLANA_DEFAULT));
+	else
+		IXGBE_WRITE_REG(hw, IXGBE_VMVIR(vf), 0);
+}
+
 inline void ixgbe_vf_reset_event(struct ixgbe_adapter *adapter, u32 vf)
 {
 	struct ixgbe_hw *hw = &adapter->hw;
 
 	/* reset offloads to defaults */
-	ixgbe_set_vmolr(hw, vf);
-
+	if (adapter->vfinfo[vf].pf_vlan) {
+		ixgbe_set_vf_vlan(adapter, true,
+				  adapter->vfinfo[vf].pf_vlan, vf);
+		ixgbe_set_vmvir(adapter,
+				(adapter->vfinfo[vf].pf_vlan |
+				 (adapter->vfinfo[vf].pf_qos <<
+				  VLAN_PRIO_SHIFT)), vf);
+		ixgbe_set_vmolr(hw, vf, false);
+	} else {
+		ixgbe_set_vmvir(adapter, 0, vf);
+		ixgbe_set_vmolr(hw, vf, true);
+	}
 
 	/* reset multicast table array for vf */
 	adapter->vfinfo[vf].num_vf_mc_hashes = 0;
@@ -152,7 +173,7 @@ int ixgbe_set_vf_mac(struct ixgbe_adapter *adapter,
 	adapter->vfinfo[vf].rar = hw->mac.ops.set_rar(hw, vf + 1, mac_addr,
 	                                              vf, IXGBE_RAH_AV);
 	if (adapter->vfinfo[vf].rar < 0) {
-		DPRINTK(DRV, ERR, "Could not set MAC Filter for VF %d\n", vf);
+		e_err("Could not set MAC Filter for VF %d\n", vf);
 		return -1;
 	}
 
@@ -172,11 +193,7 @@ int ixgbe_vf_configuration(struct pci_dev *pdev, unsigned int event_mask)
 
 	if (enable) {
 		random_ether_addr(vf_mac_addr);
-		DPRINTK(PROBE, INFO, "IOV: VF %d is enabled "
-		       "mac %02X:%02X:%02X:%02X:%02X:%02X\n",
-		       vfn,
-		       vf_mac_addr[0], vf_mac_addr[1], vf_mac_addr[2],
-		       vf_mac_addr[3], vf_mac_addr[4], vf_mac_addr[5]);
+		e_info("IOV: VF %d is enabled MAC %pM\n", vfn, vf_mac_addr);
 		/*
 		 * Store away the VF "permananet" MAC address, it will ask
 		 * for it later.
@@ -221,7 +238,7 @@ static int ixgbe_rcv_msg_from_vf(struct ixgbe_adapter *adapter, u32 vf)
 	retval = ixgbe_read_mbx(hw, msgbuf, mbx_size, vf);
 
 	if (retval)
-		printk(KERN_ERR "Error receiving message from VF\n");
+		pr_err("Error receiving message from VF\n");
 
 	/* this is a message we already processed, do nothing */
 	if (msgbuf[0] & (IXGBE_VT_MSGTYPE_ACK | IXGBE_VT_MSGTYPE_NACK))
@@ -235,7 +252,7 @@ static int ixgbe_rcv_msg_from_vf(struct ixgbe_adapter *adapter, u32 vf)
 	if (msgbuf[0] == IXGBE_VF_RESET) {
 		unsigned char *vf_mac = adapter->vfinfo[vf].vf_mac_addresses;
 		u8 *addr = (u8 *)(&msgbuf[1]);
-		DPRINTK(PROBE, INFO, "VF Reset msg received from vf %d\n", vf);
+		e_info("VF Reset msg received from vf %d\n", vf);
 		adapter->vfinfo[vf].clear_to_send = false;
 		ixgbe_vf_reset_msg(adapter, vf);
 		adapter->vfinfo[vf].clear_to_send = true;
@@ -263,10 +280,12 @@ static int ixgbe_rcv_msg_from_vf(struct ixgbe_adapter *adapter, u32 vf)
 	case IXGBE_VF_SET_MAC_ADDR:
 		{
 			u8 *new_mac = ((u8 *)(&msgbuf[1]));
-			if (is_valid_ether_addr(new_mac))
+			if (is_valid_ether_addr(new_mac) &&
+			    !adapter->vfinfo[vf].pf_set_mac)
 				ixgbe_set_vf_mac(adapter, vf, new_mac);
 			else
-				retval = -1;
+				ixgbe_set_vf_mac(adapter,
+				  vf, adapter->vfinfo[vf].vf_mac_addresses);
 		}
 		break;
 	case IXGBE_VF_SET_MULTICAST:
@@ -286,7 +305,7 @@ static int ixgbe_rcv_msg_from_vf(struct ixgbe_adapter *adapter, u32 vf)
 		retval = ixgbe_set_vf_vlan(adapter, add, vid, vf);
 		break;
 	default:
-		DPRINTK(DRV, ERR, "Unhandled Msg %8.8x\n", msgbuf[0]);
+		e_err("Unhandled Msg %8.8x\n", msgbuf[0]);
 		retval = IXGBE_ERR_MBX;
 		break;
 	}
@@ -360,3 +379,76 @@ void ixgbe_ping_all_vfs(struct ixgbe_adapter *adapter)
 	}
 }
 
+int ixgbe_ndo_set_vf_mac(struct net_device *netdev, int vf, u8 *mac)
+{
+	struct ixgbe_adapter *adapter = netdev_priv(netdev);
+	if (!is_valid_ether_addr(mac) || (vf >= adapter->num_vfs))
+		return -EINVAL;
+	adapter->vfinfo[vf].pf_set_mac = true;
+	dev_info(&adapter->pdev->dev, "setting MAC %pM on VF %d\n", mac, vf);
+	dev_info(&adapter->pdev->dev, "Reload the VF driver to make this"
+				      " change effective.");
+	if (test_bit(__IXGBE_DOWN, &adapter->state)) {
+		dev_warn(&adapter->pdev->dev, "The VF MAC address has been set,"
+			 " but the PF device is not up.\n");
+		dev_warn(&adapter->pdev->dev, "Bring the PF device up before"
+			 " attempting to use the VF device.\n");
+	}
+	return ixgbe_set_vf_mac(adapter, vf, mac);
+}
+
+int ixgbe_ndo_set_vf_vlan(struct net_device *netdev, int vf, u16 vlan, u8 qos)
+{
+	int err = 0;
+	struct ixgbe_adapter *adapter = netdev_priv(netdev);
+
+	if ((vf >= adapter->num_vfs) || (vlan > 4095) || (qos > 7))
+		return -EINVAL;
+	if (vlan || qos) {
+		err = ixgbe_set_vf_vlan(adapter, true, vlan, vf);
+		if (err)
+			goto out;
+		ixgbe_set_vmvir(adapter, vlan | (qos << VLAN_PRIO_SHIFT), vf);
+		ixgbe_set_vmolr(&adapter->hw, vf, false);
+		adapter->vfinfo[vf].pf_vlan = vlan;
+		adapter->vfinfo[vf].pf_qos = qos;
+		dev_info(&adapter->pdev->dev,
+			 "Setting VLAN %d, QOS 0x%x on VF %d\n", vlan, qos, vf);
+		if (test_bit(__IXGBE_DOWN, &adapter->state)) {
+			dev_warn(&adapter->pdev->dev,
+				 "The VF VLAN has been set,"
+				 " but the PF device is not up.\n");
+			dev_warn(&adapter->pdev->dev,
+				 "Bring the PF device up before"
+				 " attempting to use the VF device.\n");
+		}
+	} else {
+		err = ixgbe_set_vf_vlan(adapter, false,
+					adapter->vfinfo[vf].pf_vlan, vf);
+		ixgbe_set_vmvir(adapter, vlan, vf);
+		ixgbe_set_vmolr(&adapter->hw, vf, true);
+		adapter->vfinfo[vf].pf_vlan = 0;
+		adapter->vfinfo[vf].pf_qos = 0;
+       }
+out:
+       return err;
+}
+
+int ixgbe_ndo_set_vf_bw(struct net_device *netdev, int vf, int tx_rate)
+{
+	return -EOPNOTSUPP;
+}
+
+int ixgbe_ndo_get_vf_config(struct net_device *netdev,
+			    int vf, struct ifla_vf_info *ivi)
+{
+	struct ixgbe_adapter *adapter = netdev_priv(netdev);
+	if (vf >= adapter->num_vfs)
+		return -EINVAL;
+	ivi->vf = vf;
+	memcpy(&ivi->mac, adapter->vfinfo[vf].vf_mac_addresses, ETH_ALEN);
+	ivi->tx_rate = 0;
+	ivi->vlan = adapter->vfinfo[vf].pf_vlan;
+	ivi->qos = adapter->vfinfo[vf].pf_qos;
+	return 0;
+}
diff --git a/drivers/net/ixgbe/ixgbe_sriov.h b/drivers/net/ixgbe/ixgbe_sriov.h
index 51d1106..184730e 100644
--- a/drivers/net/ixgbe/ixgbe_sriov.h
+++ b/drivers/net/ixgbe/ixgbe_sriov.h
@@ -32,7 +32,7 @@ int ixgbe_set_vf_multicasts(struct ixgbe_adapter *adapter,
                             int entries, u16 *hash_list, u32 vf);
 void ixgbe_restore_vf_multicasts(struct ixgbe_adapter *adapter);
 int ixgbe_set_vf_vlan(struct ixgbe_adapter *adapter, int add, int vid, u32 vf);
-void ixgbe_set_vmolr(struct ixgbe_hw *hw, u32 vf);
+void ixgbe_set_vmolr(struct ixgbe_hw *hw, u32 vf, bool aupe);
 void ixgbe_vf_reset_event(struct ixgbe_adapter *adapter, u32 vf);
 void ixgbe_vf_reset_msg(struct ixgbe_adapter *adapter, u32 vf);
 void ixgbe_msg_task(struct ixgbe_adapter *adapter);
@@ -42,6 +42,12 @@ int ixgbe_vf_configuration(struct pci_dev *pdev, unsigned int event_mask);
 void ixgbe_disable_tx_rx(struct ixgbe_adapter *adapter);
 void ixgbe_ping_all_vfs(struct ixgbe_adapter *adapter);
 void ixgbe_dump_registers(struct ixgbe_adapter *adapter);
+int ixgbe_ndo_set_vf_mac(struct net_device *netdev, int queue, u8 *mac);
+int ixgbe_ndo_set_vf_vlan(struct net_device *netdev, int queue, u16 vlan,
+			   u8 qos);
+int ixgbe_ndo_set_vf_bw(struct net_device *netdev, int vf, int tx_rate);
+int ixgbe_ndo_get_vf_config(struct net_device *netdev,
+			    int vf, struct ifla_vf_info *ivi);
 
 #endif /* _IXGBE_SRIOV_H_ */
 
diff --git a/drivers/net/ixgbe/ixgbe_type.h b/drivers/net/ixgbe/ixgbe_type.h
index 833a0bf..9c0693c 100644
--- a/drivers/net/ixgbe/ixgbe_type.h
+++ b/drivers/net/ixgbe/ixgbe_type.h
@@ -51,6 +51,7 @@
 #define IXGBE_DEV_ID_82599_KX4           0x10F7
 #define IXGBE_DEV_ID_82599_KX4_MEZZ      0x1514
 #define IXGBE_DEV_ID_82599_KR            0x1517
+#define IXGBE_DEV_ID_82599_T3_LOM        0x151C
 #define IXGBE_DEV_ID_82599_CX4           0x10F9
 #define IXGBE_DEV_ID_82599_SFP           0x10FB
 #define IXGBE_DEV_ID_82599_SFP_EM        0x1507
@@ -73,6 +74,7 @@
 /* NVM Registers */
 #define IXGBE_EEC       0x10010
 #define IXGBE_EERD      0x10014
+#define IXGBE_EEWR      0x10018
 #define IXGBE_FLA       0x1001C
 #define IXGBE_EEMNGCTL  0x10110
 #define IXGBE_EEMNGDATA 0x10114
@@ -219,6 +221,7 @@
 #define IXGBE_MTQC      0x08120
 #define IXGBE_VLVF(_i)  (0x0F100 + ((_i) * 4))  /* 64 of these (0-63) */
 #define IXGBE_VLVFB(_i) (0x0F200 + ((_i) * 4))  /* 128 of these (0-127) */
+#define IXGBE_VMVIR(_i) (0x08000 + ((_i) * 4))  /* 64 of these (0-63) */
 #define IXGBE_VT_CTL    0x051B0
 #define IXGBE_VFRE(_i)  (0x051E0 + ((_i) * 4))
 #define IXGBE_VFTE(_i)  (0x08110 + ((_i) * 4))
@@ -699,6 +702,7 @@
 #define IXGBE_MREVID    0x11064
 #define IXGBE_DCA_ID    0x11070
 #define IXGBE_DCA_CTRL  0x11074
+#define IXGBE_SWFW_SYNC IXGBE_GSSR
 
 /* PCIe registers 82599-specific */
 #define IXGBE_GCR_EXT           0x11050
@@ -1312,6 +1316,10 @@
 #define IXGBE_VLVF_ENTRIES      64
 #define IXGBE_VLVF_VLANID_MASK  0x00000FFF
 
+/* Per VF Port VLAN insertion rules */
+#define IXGBE_VMVIR_VLANA_DEFAULT 0x40000000 /* Always use default VLAN */
+#define IXGBE_VMVIR_VLANA_NEVER   0x80000000 /* Never insert VLAN tag */
+
 #define IXGBE_ETHERNET_IEEE_VLAN_TYPE 0x8100  /* 802.1q protocol */
 
 /* STATUS Bit Masks */
@@ -1459,8 +1467,9 @@
 #define IXGBE_SWSM_SMBI 0x00000001 /* Driver Semaphore bit */
 #define IXGBE_SWSM_SWESMBI 0x00000002 /* FW Semaphore bit */
 #define IXGBE_SWSM_WMNG 0x00000004 /* Wake MNG Clock */
+#define IXGBE_SWFW_REGSMP 0x80000000 /* Register Semaphore bit 31 */
 
-/* GSSR definitions */
+/* SW_FW_SYNC/GSSR definitions */
 #define IXGBE_GSSR_EEP_SM     0x0001
 #define IXGBE_GSSR_PHY0_SM    0x0002
 #define IXGBE_GSSR_PHY1_SM    0x0004
@@ -1480,6 +1489,8 @@
 #define IXGBE_EEC_GNT       0x00000080 /* EEPROM Access Grant */
 #define IXGBE_EEC_PRES      0x00000100 /* EEPROM Present */
 #define IXGBE_EEC_ARD       0x00000200 /* EEPROM Auto Read Done */
+#define IXGBE_EEC_FLUP      0x00800000 /* Flash update command */
+#define IXGBE_EEC_FLUDONE   0x04000000 /* Flash update done */
 /* EEPROM Addressing bits based on type (0-small, 1-large) */
 #define IXGBE_EEC_ADDR_SIZE 0x00000400
 #define IXGBE_EEC_SIZE      0x00007800 /* EEPROM Size */
@@ -1535,10 +1546,12 @@
 #define IXGBE_EEPROM_ERASE256_OPCODE_SPI  0xDB  /* EEPROM ERASE 256B */
 
 /* EEPROM Read Register */
-#define IXGBE_EEPROM_READ_REG_DATA   16   /* data offset in EEPROM read reg */
-#define IXGBE_EEPROM_READ_REG_DONE   2    /* Offset to READ done bit */
-#define IXGBE_EEPROM_READ_REG_START  1    /* First bit to start operation */
-#define IXGBE_EEPROM_READ_ADDR_SHIFT 2    /* Shift to the address bits */
+#define IXGBE_EEPROM_RW_REG_DATA   16 /* data offset in EEPROM read reg */
+#define IXGBE_EEPROM_RW_REG_DONE   2  /* Offset to READ done bit */
+#define IXGBE_EEPROM_RW_REG_START  1  /* First bit to start operation */
+#define IXGBE_EEPROM_RW_ADDR_SHIFT 2  /* Shift to the address bits */
+#define IXGBE_NVM_POLL_WRITE       1  /* Flag for polling for write complete */
+#define IXGBE_NVM_POLL_READ        0  /* Flag for polling for read complete */
 
 #define IXGBE_ETH_LENGTH_OF_ADDRESS   6
 
@@ -1546,9 +1559,15 @@
 #define IXGBE_EEPROM_GRANT_ATTEMPTS 1000 /* EEPROM # attempts to gain grant */
 #endif
 
-#ifndef IXGBE_EERD_ATTEMPTS
-/* Number of 5 microseconds we wait for EERD read to complete */
-#define IXGBE_EERD_ATTEMPTS 100000
+#ifndef IXGBE_EERD_EEWR_ATTEMPTS
+/* Number of 5 microseconds we wait for EERD read and
+ * EERW write to complete */
+#define IXGBE_EERD_EEWR_ATTEMPTS 100000
+#endif
+
+#ifndef IXGBE_FLUDONE_ATTEMPTS
+/* # attempts we wait for flush update to complete */
+#define IXGBE_FLUDONE_ATTEMPTS 20000
 #endif
 
 #define IXGBE_SAN_MAC_ADDR_PORT0_OFFSET  0x0
@@ -2091,6 +2110,7 @@ typedef u32 ixgbe_physical_layer;
 #define IXGBE_PHYSICAL_LAYER_1000BASE_BX  0x0400
 #define IXGBE_PHYSICAL_LAYER_10GBASE_KR   0x0800
 #define IXGBE_PHYSICAL_LAYER_10GBASE_XAUI 0x1000
+#define IXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA 0x2000
 
 /* Software ATR hash keys */
 #define IXGBE_ATR_BUCKET_HASH_KEY    0xE214AD3D
@@ -2160,10 +2180,12 @@ enum ixgbe_phy_type {
 	ixgbe_phy_qt,
 	ixgbe_phy_xaui,
 	ixgbe_phy_nl,
-	ixgbe_phy_tw_tyco,
-	ixgbe_phy_tw_unknown,
+	ixgbe_phy_sfp_passive_tyco,
+	ixgbe_phy_sfp_passive_unknown,
+	ixgbe_phy_sfp_active_unknown,
 	ixgbe_phy_sfp_avago,
 	ixgbe_phy_sfp_ftl,
+	ixgbe_phy_sfp_ftl_active,
 	ixgbe_phy_sfp_unknown,
 	ixgbe_phy_sfp_intel,
 	ixgbe_phy_sfp_unsupported,
@@ -2191,6 +2213,8 @@ enum ixgbe_sfp_type {
 	ixgbe_sfp_type_da_cu_core1 = 4,
 	ixgbe_sfp_type_srlr_core0 = 5,
 	ixgbe_sfp_type_srlr_core1 = 6,
+	ixgbe_sfp_type_da_act_lmt_core0 = 7,
+	ixgbe_sfp_type_da_act_lmt_core1 = 8,
 	ixgbe_sfp_type_not_present = 0xFFFE,
 	ixgbe_sfp_type_unknown = 0xFFFF
 };
@@ -2264,6 +2288,7 @@ struct ixgbe_addr_filter_info {
 	u32 mc_addr_in_rar_count;
 	u32 mta_in_use;
 	u32 overflow_promisc;
+	bool uc_set_promisc;
 	bool user_set_promisc;
 };
 
@@ -2403,6 +2428,8 @@ struct ixgbe_mac_operations {
 	s32 (*enable_rx_dma)(struct ixgbe_hw *, u32);
 
 	/* Link */
+	void (*disable_tx_laser)(struct ixgbe_hw *);
+	void (*enable_tx_laser)(struct ixgbe_hw *);
 	void (*flap_tx_laser)(struct ixgbe_hw *);
 	s32 (*setup_link)(struct ixgbe_hw *, ixgbe_link_speed, bool, bool);
 	s32 (*check_link)(struct ixgbe_hw *, ixgbe_link_speed *, bool *, bool);
@@ -2449,6 +2476,7 @@ struct ixgbe_phy_operations {
 	s32 (*write_i2c_byte)(struct ixgbe_hw *, u8, u8, u8);
 	s32 (*read_i2c_eeprom)(struct ixgbe_hw *, u8 , u8 *);
 	s32 (*write_i2c_eeprom)(struct ixgbe_hw *, u8, u8);
+	s32 (*check_overtemp)(struct ixgbe_hw *);
 };
 
 struct ixgbe_eeprom_info {
@@ -2473,6 +2501,7 @@ struct ixgbe_mac_info {
 	u32                             mcft_size;
 	u32                             vft_size;
 	u32                             num_rar_entries;
+	u32                             rar_highwater;
 	u32                             max_tx_queues;
 	u32                             max_rx_queues;
 	u32                             max_msix_vectors;
@@ -2496,6 +2525,7 @@ struct ixgbe_phy_info {
 	enum ixgbe_smart_speed          smart_speed;
 	bool                            smart_speed_active;
 	bool                            multispeed_fiber;
+	bool                            reset_if_overtemp;
 };
 
 #include "ixgbe_mbx.h"
@@ -2579,8 +2609,12 @@ struct ixgbe_info {
 #define IXGBE_ERR_SFP_NOT_SUPPORTED             -19
 #define IXGBE_ERR_SFP_NOT_PRESENT               -20
 #define IXGBE_ERR_SFP_NO_INIT_SEQ_PRESENT       -21
+#define IXGBE_ERR_NO_SAN_ADDR_PTR               -22
 #define IXGBE_ERR_FDIR_REINIT_FAILED            -23
 #define IXGBE_ERR_EEPROM_VERSION                -24
+#define IXGBE_ERR_NO_SPACE                      -25
+#define IXGBE_ERR_OVERTEMP                      -26
+#define IXGBE_ERR_RAR_INDEX                     -27
 #define IXGBE_NOT_IMPLEMENTED                   0x7FFFFFFF
 
 #endif /* _IXGBE_TYPE_H_ */
