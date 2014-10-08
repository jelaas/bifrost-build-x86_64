diff -urN linux/include/linux/bcma/bcma_driver_chipcommon.h net-next-2.6/include/linux/bcma/bcma_driver_chipcommon.h
--- linux/include/linux/bcma/bcma_driver_chipcommon.h	2014-09-24 09:52:38.368593867 +0200
+++ net-next-2.6/include/linux/bcma/bcma_driver_chipcommon.h	2014-10-06 10:48:54.420841242 +0200
@@ -644,6 +644,12 @@
 #endif
 };
 
+struct bcma_drv_cc_b {
+	struct bcma_device *core;
+	u8 setup_done:1;
+	void __iomem *mii;
+};
+
 /* Register access */
 #define bcma_cc_read32(cc, offset) \
 	bcma_read32((cc)->core, offset)
@@ -699,4 +705,6 @@
 
 extern u32 bcma_pmu_get_bus_clock(struct bcma_drv_cc *cc);
 
+void bcma_chipco_b_mii_write(struct bcma_drv_cc_b *ccb, u32 offset, u32 value);
+
 #endif /* LINUX_BCMA_DRIVER_CC_H_ */
diff -urN linux/include/linux/bcma/bcma.h net-next-2.6/include/linux/bcma/bcma.h
--- linux/include/linux/bcma/bcma.h	2014-09-24 09:52:38.368593867 +0200
+++ net-next-2.6/include/linux/bcma/bcma.h	2014-10-06 10:48:54.420841242 +0200
@@ -267,7 +267,7 @@
 	u8 core_unit;
 
 	u32 addr;
-	u32 addr1;
+	u32 addr_s[8];
 	u32 wrap;
 
 	void __iomem *io_addr;
@@ -323,6 +323,8 @@
 		struct pci_dev *host_pci;
 		/* Pointer to the SDIO device (only for BCMA_HOSTTYPE_SDIO) */
 		struct sdio_func *host_sdio;
+		/* Pointer to platform device (only for BCMA_HOSTTYPE_SOC) */
+		struct platform_device *host_pdev;
 	};
 
 	struct bcma_chipinfo chipinfo;
@@ -332,10 +334,10 @@
 	struct bcma_device *mapped_core;
 	struct list_head cores;
 	u8 nr_cores;
-	u8 init_done:1;
 	u8 num;
 
 	struct bcma_drv_cc drv_cc;
+	struct bcma_drv_cc_b drv_cc_b;
 	struct bcma_drv_pci drv_pci[2];
 	struct bcma_drv_pcie2 drv_pcie2;
 	struct bcma_drv_mips drv_mips;
diff -urN linux/include/linux/bcma/bcma_regs.h net-next-2.6/include/linux/bcma/bcma_regs.h
--- linux/include/linux/bcma/bcma_regs.h	2013-05-02 09:43:16.213515186 +0200
+++ net-next-2.6/include/linux/bcma/bcma_regs.h	2014-10-06 10:48:54.420841242 +0200
@@ -39,6 +39,11 @@
 #define  BCMA_RESET_CTL_RESET		0x0001
 #define BCMA_RESET_ST			0x0804
 
+#define BCMA_NS_ROM_IOST_BOOT_DEV_MASK	0x0003
+#define BCMA_NS_ROM_IOST_BOOT_DEV_NOR	0x0000
+#define BCMA_NS_ROM_IOST_BOOT_DEV_NAND	0x0001
+#define BCMA_NS_ROM_IOST_BOOT_DEV_ROM	0x0002
+
 /* BCMA PCI config space registers. */
 #define BCMA_PCI_PMCSR			0x44
 #define  BCMA_PCI_PE			0x100
diff -urN linux/include/linux/bcma/bcma_soc.h net-next-2.6/include/linux/bcma/bcma_soc.h
--- linux/include/linux/bcma/bcma_soc.h	2013-05-02 09:43:16.213515186 +0200
+++ net-next-2.6/include/linux/bcma/bcma_soc.h	2014-10-06 10:48:54.420841242 +0200
@@ -10,6 +10,7 @@
 };
 
 int __init bcma_host_soc_register(struct bcma_soc *soc);
+int __init bcma_host_soc_init(struct bcma_soc *soc);
 
 int bcma_bus_register(struct bcma_bus *bus);
 
diff -urN linux/include/linux/bpf.h net-next-2.6/include/linux/bpf.h
--- linux/include/linux/bpf.h	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/include/linux/bpf.h	2014-10-06 10:48:54.420841242 +0200
@@ -0,0 +1,136 @@
+/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
+ *
+ * This program is free software; you can redistribute it and/or
+ * modify it under the terms of version 2 of the GNU General Public
+ * License as published by the Free Software Foundation.
+ */
+#ifndef _LINUX_BPF_H
+#define _LINUX_BPF_H 1
+
+#include <uapi/linux/bpf.h>
+#include <linux/workqueue.h>
+#include <linux/file.h>
+
+struct bpf_map;
+
+/* map is generic key/value storage optionally accesible by eBPF programs */
+struct bpf_map_ops {
+	/* funcs callable from userspace (via syscall) */
+	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
+	void (*map_free)(struct bpf_map *);
+	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
+
+	/* funcs callable from userspace and from eBPF programs */
+	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
+	int (*map_update_elem)(struct bpf_map *map, void *key, void *value);
+	int (*map_delete_elem)(struct bpf_map *map, void *key);
+};
+
+struct bpf_map {
+	atomic_t refcnt;
+	enum bpf_map_type map_type;
+	u32 key_size;
+	u32 value_size;
+	u32 max_entries;
+	struct bpf_map_ops *ops;
+	struct work_struct work;
+};
+
+struct bpf_map_type_list {
+	struct list_head list_node;
+	struct bpf_map_ops *ops;
+	enum bpf_map_type type;
+};
+
+void bpf_register_map_type(struct bpf_map_type_list *tl);
+void bpf_map_put(struct bpf_map *map);
+struct bpf_map *bpf_map_get(struct fd f);
+
+/* function argument constraints */
+enum bpf_arg_type {
+	ARG_ANYTHING = 0,	/* any argument is ok */
+
+	/* the following constraints used to prototype
+	 * bpf_map_lookup/update/delete_elem() functions
+	 */
+	ARG_CONST_MAP_PTR,	/* const argument used as pointer to bpf_map */
+	ARG_PTR_TO_MAP_KEY,	/* pointer to stack used as map key */
+	ARG_PTR_TO_MAP_VALUE,	/* pointer to stack used as map value */
+
+	/* the following constraints used to prototype bpf_memcmp() and other
+	 * functions that access data on eBPF program stack
+	 */
+	ARG_PTR_TO_STACK,	/* any pointer to eBPF program stack */
+	ARG_CONST_STACK_SIZE,	/* number of bytes accessed from stack */
+};
+
+/* type of values returned from helper functions */
+enum bpf_return_type {
+	RET_INTEGER,			/* function returns integer */
+	RET_VOID,			/* function doesn't return anything */
+	RET_PTR_TO_MAP_VALUE_OR_NULL,	/* returns a pointer to map elem value or NULL */
+};
+
+/* eBPF function prototype used by verifier to allow BPF_CALLs from eBPF programs
+ * to in-kernel helper functions and for adjusting imm32 field in BPF_CALL
+ * instructions after verifying
+ */
+struct bpf_func_proto {
+	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
+	bool gpl_only;
+	enum bpf_return_type ret_type;
+	enum bpf_arg_type arg1_type;
+	enum bpf_arg_type arg2_type;
+	enum bpf_arg_type arg3_type;
+	enum bpf_arg_type arg4_type;
+	enum bpf_arg_type arg5_type;
+};
+
+/* bpf_context is intentionally undefined structure. Pointer to bpf_context is
+ * the first argument to eBPF programs.
+ * For socket filters: 'struct bpf_context *' == 'struct sk_buff *'
+ */
+struct bpf_context;
+
+enum bpf_access_type {
+	BPF_READ = 1,
+	BPF_WRITE = 2
+};
+
+struct bpf_verifier_ops {
+	/* return eBPF function prototype for verification */
+	const struct bpf_func_proto *(*get_func_proto)(enum bpf_func_id func_id);
+
+	/* return true if 'size' wide access at offset 'off' within bpf_context
+	 * with 'type' (read or write) is allowed
+	 */
+	bool (*is_valid_access)(int off, int size, enum bpf_access_type type);
+};
+
+struct bpf_prog_type_list {
+	struct list_head list_node;
+	struct bpf_verifier_ops *ops;
+	enum bpf_prog_type type;
+};
+
+void bpf_register_prog_type(struct bpf_prog_type_list *tl);
+
+struct bpf_prog;
+
+struct bpf_prog_aux {
+	atomic_t refcnt;
+	bool is_gpl_compatible;
+	enum bpf_prog_type prog_type;
+	struct bpf_verifier_ops *ops;
+	struct bpf_map **used_maps;
+	u32 used_map_cnt;
+	struct bpf_prog *prog;
+	struct work_struct work;
+};
+
+void bpf_prog_put(struct bpf_prog *prog);
+struct bpf_prog *bpf_prog_get(u32 ufd);
+/* verify correctness of eBPF program */
+int bpf_check(struct bpf_prog *fp, union bpf_attr *attr);
+
+#endif /* _LINUX_BPF_H */
diff -urN linux/include/linux/brcmphy.h net-next-2.6/include/linux/brcmphy.h
--- linux/include/linux/brcmphy.h	2014-09-24 09:52:38.372593909 +0200
+++ net-next-2.6/include/linux/brcmphy.h	2014-10-06 10:48:54.420841242 +0200
@@ -13,7 +13,11 @@
 #define PHY_ID_BCM5461			0x002060c0
 #define PHY_ID_BCM57780			0x03625d90
 
+#define PHY_ID_BCM7250			0xae025280
+#define PHY_ID_BCM7364			0xae025260
 #define PHY_ID_BCM7366			0x600d8490
+#define PHY_ID_BCM7425			0x03625e60
+#define PHY_ID_BCM7429			0x600d8730
 #define PHY_ID_BCM7439			0x600d8480
 #define PHY_ID_BCM7445			0x600d8510
 
@@ -21,9 +25,9 @@
 #define PHY_BCM_OUI_1			0x00206000
 #define PHY_BCM_OUI_2			0x0143bc00
 #define PHY_BCM_OUI_3			0x03625c00
-#define PHY_BCM_OUI_4			0x600d0000
+#define PHY_BCM_OUI_4			0x600d8400
 #define PHY_BCM_OUI_5			0x03625e00
-
+#define PHY_BCM_OUI_6			0xae025000
 
 #define PHY_BCM_FLAGS_MODE_COPPER	0x00000001
 #define PHY_BCM_FLAGS_MODE_1000BX	0x00000002
@@ -38,7 +42,8 @@
 #define PHY_BRCM_CLEAR_RGMII_MODE	0x00004000
 #define PHY_BRCM_DIS_TXCRXC_NOENRGY	0x00008000
 /* Broadcom BCM7xxx specific workarounds */
-#define PHY_BRCM_100MBPS_WAR		0x00010000
+#define PHY_BRCM_7XXX_REV(x)		(((x) >> 8) & 0xff)
+#define PHY_BRCM_7XXX_PATCH(x)		((x) & 0xff)
 #define PHY_BCM_FLAGS_VALID		0x80000000
 
 /* Broadcom BCM54XX register definitions, common to most Broadcom PHYs */
@@ -92,4 +97,130 @@
 
 #define MII_BCM54XX_AUXCTL_SHDWSEL_AUXCTL	0x0000
 
+/*
+ * Broadcom LED source encodings.  These are used in BCM5461, BCM5481,
+ * BCM5482, and possibly some others.
+ */
+#define BCM_LED_SRC_LINKSPD1	0x0
+#define BCM_LED_SRC_LINKSPD2	0x1
+#define BCM_LED_SRC_XMITLED	0x2
+#define BCM_LED_SRC_ACTIVITYLED	0x3
+#define BCM_LED_SRC_FDXLED	0x4
+#define BCM_LED_SRC_SLAVE	0x5
+#define BCM_LED_SRC_INTR	0x6
+#define BCM_LED_SRC_QUALITY	0x7
+#define BCM_LED_SRC_RCVLED	0x8
+#define BCM_LED_SRC_MULTICOLOR1	0xa
+#define BCM_LED_SRC_OPENSHORT	0xb
+#define BCM_LED_SRC_OFF		0xe	/* Tied high */
+#define BCM_LED_SRC_ON		0xf	/* Tied low */
+
+
+/*
+ * BCM5482: Shadow registers
+ * Shadow values go into bits [14:10] of register 0x1c to select a shadow
+ * register to access.
+ */
+/* 00101: Spare Control Register 3 */
+#define BCM54XX_SHD_SCR3		0x05
+#define  BCM54XX_SHD_SCR3_DEF_CLK125	0x0001
+#define  BCM54XX_SHD_SCR3_DLLAPD_DIS	0x0002
+#define  BCM54XX_SHD_SCR3_TRDDAPD	0x0004
+
+/* 01010: Auto Power-Down */
+#define BCM54XX_SHD_APD			0x0a
+#define  BCM54XX_SHD_APD_EN		0x0020
+
+#define BCM5482_SHD_LEDS1	0x0d	/* 01101: LED Selector 1 */
+					/* LED3 / ~LINKSPD[2] selector */
+#define BCM5482_SHD_LEDS1_LED3(src)	((src & 0xf) << 4)
+					/* LED1 / ~LINKSPD[1] selector */
+#define BCM5482_SHD_LEDS1_LED1(src)	((src & 0xf) << 0)
+#define BCM54XX_SHD_RGMII_MODE	0x0b	/* 01011: RGMII Mode Selector */
+#define BCM5482_SHD_SSD		0x14	/* 10100: Secondary SerDes control */
+#define BCM5482_SHD_SSD_LEDM	0x0008	/* SSD LED Mode enable */
+#define BCM5482_SHD_SSD_EN	0x0001	/* SSD enable */
+#define BCM5482_SHD_MODE	0x1f	/* 11111: Mode Control Register */
+#define BCM5482_SHD_MODE_1000BX	0x0001	/* Enable 1000BASE-X registers */
+
+
+/*
+ * EXPANSION SHADOW ACCESS REGISTERS.  (PHY REG 0x15, 0x16, and 0x17)
+ */
+#define MII_BCM54XX_EXP_AADJ1CH0		0x001f
+#define  MII_BCM54XX_EXP_AADJ1CH0_SWP_ABCD_OEN	0x0200
+#define  MII_BCM54XX_EXP_AADJ1CH0_SWSEL_THPF	0x0100
+#define MII_BCM54XX_EXP_AADJ1CH3		0x601f
+#define  MII_BCM54XX_EXP_AADJ1CH3_ADCCKADJ	0x0002
+#define MII_BCM54XX_EXP_EXP08			0x0F08
+#define  MII_BCM54XX_EXP_EXP08_RJCT_2MHZ	0x0001
+#define  MII_BCM54XX_EXP_EXP08_EARLY_DAC_WAKE	0x0200
+#define MII_BCM54XX_EXP_EXP75			0x0f75
+#define  MII_BCM54XX_EXP_EXP75_VDACCTRL		0x003c
+#define  MII_BCM54XX_EXP_EXP75_CM_OSC		0x0001
+#define MII_BCM54XX_EXP_EXP96			0x0f96
+#define  MII_BCM54XX_EXP_EXP96_MYST		0x0010
+#define MII_BCM54XX_EXP_EXP97			0x0f97
+#define  MII_BCM54XX_EXP_EXP97_MYST		0x0c0c
+
+/*
+ * BCM5482: Secondary SerDes registers
+ */
+#define BCM5482_SSD_1000BX_CTL		0x00	/* 1000BASE-X Control */
+#define BCM5482_SSD_1000BX_CTL_PWRDOWN	0x0800	/* Power-down SSD */
+#define BCM5482_SSD_SGMII_SLAVE		0x15	/* SGMII Slave Register */
+#define BCM5482_SSD_SGMII_SLAVE_EN	0x0002	/* Slave mode enable */
+#define BCM5482_SSD_SGMII_SLAVE_AD	0x0001	/* Slave auto-detection */
+
+
+/*****************************************************************************/
+/* Fast Ethernet Transceiver definitions. */
+/*****************************************************************************/
+
+#define MII_BRCM_FET_INTREG		0x1a	/* Interrupt register */
+#define MII_BRCM_FET_IR_MASK		0x0100	/* Mask all interrupts */
+#define MII_BRCM_FET_IR_LINK_EN		0x0200	/* Link status change enable */
+#define MII_BRCM_FET_IR_SPEED_EN	0x0400	/* Link speed change enable */
+#define MII_BRCM_FET_IR_DUPLEX_EN	0x0800	/* Duplex mode change enable */
+#define MII_BRCM_FET_IR_ENABLE		0x4000	/* Interrupt enable */
+
+#define MII_BRCM_FET_BRCMTEST		0x1f	/* Brcm test register */
+#define MII_BRCM_FET_BT_SRE		0x0080	/* Shadow register enable */
+
+
+/*** Shadow register definitions ***/
+
+#define MII_BRCM_FET_SHDW_MISCCTRL	0x10	/* Shadow misc ctrl */
+#define MII_BRCM_FET_SHDW_MC_FAME	0x4000	/* Force Auto MDIX enable */
+
+#define MII_BRCM_FET_SHDW_AUXMODE4	0x1a	/* Auxiliary mode 4 */
+#define MII_BRCM_FET_SHDW_AM4_LED_MASK	0x0003
+#define MII_BRCM_FET_SHDW_AM4_LED_MODE1 0x0001
+
+#define MII_BRCM_FET_SHDW_AUXSTAT2	0x1b	/* Auxiliary status 2 */
+#define MII_BRCM_FET_SHDW_AS2_APDE	0x0020	/* Auto power down enable */
+
+/*
+ * Indirect register access functions for the 1000BASE-T/100BASE-TX/10BASE-T
+ * 0x1c shadow registers.
+ */
+static inline int bcm54xx_shadow_read(struct phy_device *phydev, u16 shadow)
+{
+	phy_write(phydev, MII_BCM54XX_SHD, MII_BCM54XX_SHD_VAL(shadow));
+	return MII_BCM54XX_SHD_DATA(phy_read(phydev, MII_BCM54XX_SHD));
+}
+
+static inline int bcm54xx_shadow_write(struct phy_device *phydev, u16 shadow,
+				       u16 val)
+{
+	return phy_write(phydev, MII_BCM54XX_SHD,
+			 MII_BCM54XX_SHD_WRITE |
+			 MII_BCM54XX_SHD_VAL(shadow) |
+			 MII_BCM54XX_SHD_DATA(val));
+}
+
+#define BRCM_CL45VEN_EEE_CONTROL	0x803d
+#define LPI_FEATURE_EN			0x8000
+#define LPI_FEATURE_EN_DIG1000X		0x4000
+
 #endif /* _LINUX_BRCMPHY_H */
diff -urN linux/include/linux/com20020.h net-next-2.6/include/linux/com20020.h
--- linux/include/linux/com20020.h	2011-07-22 09:59:43.553385777 +0200
+++ net-next-2.6/include/linux/com20020.h	2014-10-06 10:48:54.424841283 +0200
@@ -41,6 +41,35 @@
 #define BUS_ALIGN  1
 #endif
 
+#define PLX_PCI_MAX_CARDS 2
+
+struct com20020_pci_channel_map {
+	u32 bar;
+	u32 offset;
+	u32 size;               /* 0x00 - auto, e.g. length of entire bar */
+};
+
+struct com20020_pci_card_info {
+	const char *name;
+	int devcount;
+
+	struct com20020_pci_channel_map chan_map_tbl[PLX_PCI_MAX_CARDS];
+
+	unsigned int flags;
+};
+
+struct com20020_priv {
+	struct com20020_pci_card_info *ci;
+	struct list_head list_dev;
+};
+
+struct com20020_dev {
+	struct list_head list;
+	struct net_device *dev;
+
+	struct com20020_priv *pci_priv;
+	int index;
+};
 
 #define _INTMASK  (ioaddr+BUS_ALIGN*0)	/* writable */
 #define _STATUS   (ioaddr+BUS_ALIGN*0)	/* readable */
diff -urN linux/include/linux/cycx_x25.h net-next-2.6/include/linux/cycx_x25.h
--- linux/include/linux/cycx_x25.h	2011-07-22 09:59:43.553385777 +0200
+++ net-next-2.6/include/linux/cycx_x25.h	1970-01-01 01:00:00.000000000 +0100
@@ -1,125 +0,0 @@
-#ifndef	_CYCX_X25_H
-#define	_CYCX_X25_H
-/*
-* cycx_x25.h	Cyclom X.25 firmware API definitions.
-*
-* Author:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
-*
-* Copyright:	(c) 1998-2003 Arnaldo Carvalho de Melo
-*
-* Based on sdla_x25.h by Gene Kozin <74604.152@compuserve.com>
-*
-*		This program is free software; you can redistribute it and/or
-*		modify it under the terms of the GNU General Public License
-*		as published by the Free Software Foundation; either version
-*		2 of the License, or (at your option) any later version.
-* ============================================================================
-* 2000/04/02	acme		dprintk and cycx_debug
-* 1999/01/03	acme		judicious use of data types
-* 1999/01/02	acme		#define X25_ACK_N3	0x4411
-* 1998/12/28	acme		cleanup: lot'o'things removed
-*					 commands listed,
-*					 TX25Cmd & TX25Config structs
-*					 typedef'ed
-*/
-#ifndef PACKED
-#define PACKED __attribute__((packed))
-#endif 
-
-/* X.25 shared memory layout. */
-#define	X25_MBOX_OFFS	0x300	/* general mailbox block */
-#define	X25_RXMBOX_OFFS	0x340	/* receive mailbox */
-
-/* Debug */
-#define dprintk(level, format, a...) if (cycx_debug >= level) printk(format, ##a)
-
-extern unsigned int cycx_debug;
-
-/* Data Structures */
-/* X.25 Command Block. */
-struct cycx_x25_cmd {
-	u16 command;
-	u16 link;	/* values: 0 or 1 */
-	u16 len;	/* values: 0 thru 0x205 (517) */
-	u32 buf;
-} PACKED;
-
-/* Defines for the 'command' field. */
-#define X25_CONNECT_REQUEST             0x4401
-#define X25_CONNECT_RESPONSE            0x4402
-#define X25_DISCONNECT_REQUEST          0x4403
-#define X25_DISCONNECT_RESPONSE         0x4404
-#define X25_DATA_REQUEST                0x4405
-#define X25_ACK_TO_VC			0x4406
-#define X25_INTERRUPT_RESPONSE          0x4407
-#define X25_CONFIG                      0x4408
-#define X25_CONNECT_INDICATION          0x4409
-#define X25_CONNECT_CONFIRM             0x440A
-#define X25_DISCONNECT_INDICATION       0x440B
-#define X25_DISCONNECT_CONFIRM          0x440C
-#define X25_DATA_INDICATION             0x440E
-#define X25_INTERRUPT_INDICATION        0x440F
-#define X25_ACK_FROM_VC			0x4410
-#define X25_ACK_N3			0x4411
-#define X25_CONNECT_COLLISION           0x4413
-#define X25_N3WIN                       0x4414
-#define X25_LINE_ON                     0x4415
-#define X25_LINE_OFF                    0x4416
-#define X25_RESET_REQUEST               0x4417
-#define X25_LOG                         0x4500
-#define X25_STATISTIC                   0x4600
-#define X25_TRACE                       0x4700
-#define X25_N2TRACEXC                   0x4702
-#define X25_N3TRACEXC                   0x4703
-
-/**
- *	struct cycx_x25_config - cyclom2x x25 firmware configuration
- *	@link - link number
- *	@speed - line speed
- *	@clock - internal/external
- *	@n2 - # of level 2 retransm.(values: 1 thru FF)
- *	@n2win - level 2 window (values: 1 thru 7)
- *	@n3win - level 3 window (values: 1 thru 7)
- *	@nvc - # of logical channels (values: 1 thru 64)
- *	@pktlen - level 3 packet length - log base 2 of size
- *	@locaddr - my address
- *	@remaddr - remote address
- *	@t1 - time, in seconds
- *	@t2 - time, in seconds
- *	@t21 - time, in seconds
- *	@npvc - # of permanent virt. circuits (1 thru nvc)
- *	@t23 - time, in seconds
- *	@flags - see dosx25.doc, in portuguese, for details
- */
-struct cycx_x25_config {
-	u8  link;
-	u8  speed;
-	u8  clock;
-	u8  n2;
-	u8  n2win;
-	u8  n3win;
-	u8  nvc;
-	u8  pktlen;
-	u8  locaddr;
-	u8  remaddr;
-	u16 t1;
-	u16 t2;
-	u8  t21;
-	u8  npvc;
-	u8  t23;
-	u8  flags;
-} PACKED;
-
-struct cycx_x25_stats {
-	u16 rx_crc_errors;
-	u16 rx_over_errors;
-	u16 n2_tx_frames;
-	u16 n2_rx_frames;
-	u16 tx_timeouts;
-	u16 rx_timeouts;
-	u16 n3_tx_packets;
-	u16 n3_rx_packets;
-	u16 tx_aborts;
-	u16 rx_aborts;
-} PACKED;
-#endif	/* _CYCX_X25_H */
diff -urN linux/include/linux/dynamic_queue_limits.h net-next-2.6/include/linux/dynamic_queue_limits.h
--- linux/include/linux/dynamic_queue_limits.h	2013-05-02 09:43:16.229515186 +0200
+++ net-next-2.6/include/linux/dynamic_queue_limits.h	2014-10-06 10:48:54.440841446 +0200
@@ -73,14 +73,22 @@
 {
 	BUG_ON(count > DQL_MAX_OBJECT);
 
-	dql->num_queued += count;
 	dql->last_obj_cnt = count;
+
+	/* We want to force a write first, so that cpu do not attempt
+	 * to get cache line containing last_obj_cnt, num_queued, adj_limit
+	 * in Shared state, but directly does a Request For Ownership
+	 * It is only a hint, we use barrier() only.
+	 */
+	barrier();
+
+	dql->num_queued += count;
 }
 
 /* Returns how many objects can be queued, < 0 indicates over limit. */
 static inline int dql_avail(const struct dql *dql)
 {
-	return dql->adj_limit - dql->num_queued;
+	return ACCESS_ONCE(dql->adj_limit) - ACCESS_ONCE(dql->num_queued);
 }
 
 /* Record number of completed objects and recalculate the limit. */
diff -urN linux/include/linux/etherdevice.h net-next-2.6/include/linux/etherdevice.h
--- linux/include/linux/etherdevice.h	2014-09-24 09:52:38.456594791 +0200
+++ net-next-2.6/include/linux/etherdevice.h	2014-10-06 10:48:54.444841487 +0200
@@ -29,6 +29,7 @@
 #include <asm/bitsperlong.h>
 
 #ifdef __KERNEL__
+u32 eth_get_headlen(void *data, unsigned int max_len);
 __be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev);
 extern const struct header_ops eth_header_ops;
 
diff -urN linux/include/linux/ethtool.h net-next-2.6/include/linux/ethtool.h
--- linux/include/linux/ethtool.h	2014-09-24 09:52:38.456594791 +0200
+++ net-next-2.6/include/linux/ethtool.h	2014-10-06 10:48:54.444841487 +0200
@@ -257,6 +257,10 @@
 				     struct ethtool_eeprom *, u8 *);
 	int	(*get_eee)(struct net_device *, struct ethtool_eee *);
 	int	(*set_eee)(struct net_device *, struct ethtool_eee *);
+	int	(*get_tunable)(struct net_device *,
+			       const struct ethtool_tunable *, void *);
+	int	(*set_tunable)(struct net_device *,
+			       const struct ethtool_tunable *, const void *);
 
 
 };
diff -urN linux/include/linux/filter.h net-next-2.6/include/linux/filter.h
--- linux/include/linux/filter.h	2014-09-24 09:52:38.476595000 +0200
+++ net-next-2.6/include/linux/filter.h	2014-10-06 10:48:54.444841487 +0200
@@ -4,58 +4,24 @@
 #ifndef __LINUX_FILTER_H__
 #define __LINUX_FILTER_H__
 
+#include <stdarg.h>
+
 #include <linux/atomic.h>
 #include <linux/compat.h>
 #include <linux/skbuff.h>
+#include <linux/linkage.h>
+#include <linux/printk.h>
 #include <linux/workqueue.h>
-#include <uapi/linux/filter.h>
-
-/* Internally used and optimized filter representation with extended
- * instruction set based on top of classic BPF.
- */
 
-/* instruction classes */
-#define BPF_ALU64	0x07	/* alu mode in double word width */
+#include <asm/cacheflush.h>
 
-/* ld/ldx fields */
-#define BPF_DW		0x18	/* double word */
-#define BPF_XADD	0xc0	/* exclusive add */
-
-/* alu/jmp fields */
-#define BPF_MOV		0xb0	/* mov reg to reg */
-#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */
-
-/* change endianness of a register */
-#define BPF_END		0xd0	/* flags for endianness conversion: */
-#define BPF_TO_LE	0x00	/* convert to little-endian */
-#define BPF_TO_BE	0x08	/* convert to big-endian */
-#define BPF_FROM_LE	BPF_TO_LE
-#define BPF_FROM_BE	BPF_TO_BE
-
-#define BPF_JNE		0x50	/* jump != */
-#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
-#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
-#define BPF_CALL	0x80	/* function call */
-#define BPF_EXIT	0x90	/* function return */
-
-/* Register numbers */
-enum {
-	BPF_REG_0 = 0,
-	BPF_REG_1,
-	BPF_REG_2,
-	BPF_REG_3,
-	BPF_REG_4,
-	BPF_REG_5,
-	BPF_REG_6,
-	BPF_REG_7,
-	BPF_REG_8,
-	BPF_REG_9,
-	BPF_REG_10,
-	__MAX_BPF_REG,
-};
+#include <uapi/linux/filter.h>
+#include <uapi/linux/bpf.h>
 
-/* BPF has 10 general purpose 64-bit registers and stack frame. */
-#define MAX_BPF_REG	__MAX_BPF_REG
+struct sk_buff;
+struct sock;
+struct seccomp_data;
+struct bpf_prog_aux;
 
 /* ArgX, context and stack frame pointer register positions. Note,
  * Arg1, Arg2, Arg3, etc are used as argument mappings of function
@@ -161,6 +127,30 @@
 		.off   = 0,					\
 		.imm   = IMM })
 
+/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
+#define BPF_LD_IMM64(DST, IMM)					\
+	BPF_LD_IMM64_RAW(DST, 0, IMM)
+
+#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
+	((struct bpf_insn) {					\
+		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
+		.dst_reg = DST,					\
+		.src_reg = SRC,					\
+		.off   = 0,					\
+		.imm   = (__u32) (IMM) }),			\
+	((struct bpf_insn) {					\
+		.code  = 0, /* zero is reserved opcode */	\
+		.dst_reg = 0,					\
+		.src_reg = 0,					\
+		.off   = 0,					\
+		.imm   = ((__u64) (IMM)) >> 32 })
+
+#define BPF_PSEUDO_MAP_FD	1
+
+/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
+#define BPF_LD_MAP_FD(DST, MAP_FD)				\
+	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
+
 /* Short form of mov based on type, BPF_X: dst_reg = src_reg, BPF_K: dst_reg = imm32 */
 
 #define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\
@@ -299,14 +289,6 @@
 #define SK_RUN_FILTER(filter, ctx) \
 	(*filter->prog->bpf_func)(ctx, filter->prog->insnsi)
 
-struct bpf_insn {
-	__u8	code;		/* opcode */
-	__u8	dst_reg:4;	/* dest register */
-	__u8	src_reg:4;	/* source register */
-	__s16	off;		/* signed offset */
-	__s32	imm;		/* signed immediate constant */
-};
-
 #ifdef CONFIG_COMPAT
 /* A struct sock_filter is architecture independent. */
 struct compat_sock_fprog {
@@ -320,20 +302,23 @@
 	struct sock_filter	*filter;
 };
 
-struct sk_buff;
-struct sock;
-struct seccomp_data;
+struct bpf_binary_header {
+	unsigned int pages;
+	u8 image[];
+};
 
 struct bpf_prog {
-	u32			jited:1,	/* Is our filter JIT'ed? */
-				len:31;		/* Number of filter blocks */
+	u16			pages;		/* Number of allocated pages */
+	bool			jited;		/* Is our filter JIT'ed? */
+	u32			len;		/* Number of filter blocks */
 	struct sock_fprog_kern	*orig_prog;	/* Original BPF program */
+	struct bpf_prog_aux	*aux;		/* Auxiliary fields */
 	unsigned int		(*bpf_func)(const struct sk_buff *skb,
 					    const struct bpf_insn *filter);
+	/* Instructions for interpreter */
 	union {
 		struct sock_filter	insns[0];
 		struct bpf_insn		insnsi[0];
-		struct work_struct	work;
 	};
 };
 
@@ -353,6 +338,26 @@
 
 #define bpf_classic_proglen(fprog) (fprog->len * sizeof(fprog->filter[0]))
 
+#ifdef CONFIG_DEBUG_SET_MODULE_RONX
+static inline void bpf_prog_lock_ro(struct bpf_prog *fp)
+{
+	set_memory_ro((unsigned long)fp, fp->pages);
+}
+
+static inline void bpf_prog_unlock_ro(struct bpf_prog *fp)
+{
+	set_memory_rw((unsigned long)fp, fp->pages);
+}
+#else
+static inline void bpf_prog_lock_ro(struct bpf_prog *fp)
+{
+}
+
+static inline void bpf_prog_unlock_ro(struct bpf_prog *fp)
+{
+}
+#endif /* CONFIG_DEBUG_SET_MODULE_RONX */
+
 int sk_filter(struct sock *sk, struct sk_buff *skb);
 
 void bpf_prog_select_runtime(struct bpf_prog *fp);
@@ -361,6 +366,17 @@
 int bpf_convert_filter(struct sock_filter *prog, int len,
 		       struct bpf_insn *new_prog, int *new_len);
 
+struct bpf_prog *bpf_prog_alloc(unsigned int size, gfp_t gfp_extra_flags);
+struct bpf_prog *bpf_prog_realloc(struct bpf_prog *fp_old, unsigned int size,
+				  gfp_t gfp_extra_flags);
+void __bpf_prog_free(struct bpf_prog *fp);
+
+static inline void bpf_prog_unlock_free(struct bpf_prog *fp)
+{
+	bpf_prog_unlock_ro(fp);
+	__bpf_prog_free(fp);
+}
+
 int bpf_prog_create(struct bpf_prog **pfp, struct sock_fprog_kern *fprog);
 void bpf_prog_destroy(struct bpf_prog *fp);
 
@@ -377,6 +393,38 @@
 u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
 void bpf_int_jit_compile(struct bpf_prog *fp);
 
+#ifdef CONFIG_BPF_JIT
+typedef void (*bpf_jit_fill_hole_t)(void *area, unsigned int size);
+
+struct bpf_binary_header *
+bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
+		     unsigned int alignment,
+		     bpf_jit_fill_hole_t bpf_fill_ill_insns);
+void bpf_jit_binary_free(struct bpf_binary_header *hdr);
+
+void bpf_jit_compile(struct bpf_prog *fp);
+void bpf_jit_free(struct bpf_prog *fp);
+
+static inline void bpf_jit_dump(unsigned int flen, unsigned int proglen,
+				u32 pass, void *image)
+{
+	pr_err("flen=%u proglen=%u pass=%u image=%pK\n",
+	       flen, proglen, pass, image);
+	if (image)
+		print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_OFFSET,
+			       16, 1, image, proglen, false);
+}
+#else
+static inline void bpf_jit_compile(struct bpf_prog *fp)
+{
+}
+
+static inline void bpf_jit_free(struct bpf_prog *fp)
+{
+	bpf_prog_unlock_free(fp);
+}
+#endif /* CONFIG_BPF_JIT */
+
 #define BPF_ANC		BIT(15)
 
 static inline u16 bpf_anc_helper(const struct sock_filter *ftest)
@@ -424,36 +472,6 @@
 	return bpf_internal_load_pointer_neg_helper(skb, k, size);
 }
 
-#ifdef CONFIG_BPF_JIT
-#include <stdarg.h>
-#include <linux/linkage.h>
-#include <linux/printk.h>
-
-void bpf_jit_compile(struct bpf_prog *fp);
-void bpf_jit_free(struct bpf_prog *fp);
-
-static inline void bpf_jit_dump(unsigned int flen, unsigned int proglen,
-				u32 pass, void *image)
-{
-	pr_err("flen=%u proglen=%u pass=%u image=%pK\n",
-	       flen, proglen, pass, image);
-	if (image)
-		print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_OFFSET,
-			       16, 1, image, proglen, false);
-}
-#else
-#include <linux/slab.h>
-
-static inline void bpf_jit_compile(struct bpf_prog *fp)
-{
-}
-
-static inline void bpf_jit_free(struct bpf_prog *fp)
-{
-	kfree(fp);
-}
-#endif /* CONFIG_BPF_JIT */
-
 static inline int bpf_tell_extensions(void)
 {
 	return SKF_AD_MAX;
diff -urN linux/include/linux/i82593.h net-next-2.6/include/linux/i82593.h
--- linux/include/linux/i82593.h	2011-07-22 09:59:43.873383088 +0200
+++ net-next-2.6/include/linux/i82593.h	1970-01-01 01:00:00.000000000 +0100
@@ -1,229 +0,0 @@
-/*
- * Definitions for Intel 82593 CSMA/CD Core LAN Controller
- * The definitions are taken from the 1992 users manual with Intel
- * order number 297125-001.
- *
- * /usr/src/pc/RCS/i82593.h,v 1.1 1996/07/17 15:23:12 root Exp
- *
- * Copyright 1994, Anders Klemets <klemets@it.kth.se>
- *
- * HISTORY
- * i82593.h,v
- * Revision 1.4  2005/11/4  09:15:00  baroniunas
- * Modified copyright with permission of author as follows:
- *
- *   "If I82539.H is the only file with my copyright statement
- *    that is included in the Source Forge project, then you have
- *    my approval to change the copyright statement to be a GPL
- *    license, in the way you proposed on October 10."
- *
- * Revision 1.1  1996/07/17 15:23:12  root
- * Initial revision
- *
- * Revision 1.3  1995/04/05  15:13:58  adj
- * Initial alpha release
- *
- * Revision 1.2  1994/06/16  23:57:31  klemets
- * Mirrored all the fields in the configuration block.
- *
- * Revision 1.1  1994/06/02  20:25:34  klemets
- * Initial revision
- *
- *
- */
-#ifndef	_I82593_H
-#define	_I82593_H
-
-/* Intel 82593 CSMA/CD Core LAN Controller */
-
-/* Port 0 Command Register definitions */
-
-/* Execution operations */
-#define OP0_NOP			0	/* CHNL = 0 */
-#define OP0_SWIT_TO_PORT_1	0	/* CHNL = 1 */
-#define OP0_IA_SETUP		1
-#define OP0_CONFIGURE		2
-#define OP0_MC_SETUP		3
-#define OP0_TRANSMIT		4
-#define OP0_TDR			5
-#define OP0_DUMP		6
-#define OP0_DIAGNOSE		7
-#define OP0_TRANSMIT_NO_CRC	9
-#define OP0_RETRANSMIT		12
-#define OP0_ABORT		13
-/* Reception operations */
-#define OP0_RCV_ENABLE		8
-#define OP0_RCV_DISABLE		10
-#define OP0_STOP_RCV		11
-/* Status pointer control operations */
-#define OP0_FIX_PTR		15	/* CHNL = 1 */
-#define OP0_RLS_PTR		15	/* CHNL = 0 */
-#define OP0_RESET		14
-
-#define CR0_CHNL		(1 << 4)	/* 0=Channel 0, 1=Channel 1 */
-#define CR0_STATUS_0		0x00
-#define CR0_STATUS_1		0x20
-#define CR0_STATUS_2		0x40
-#define CR0_STATUS_3		0x60
-#define CR0_INT_ACK		(1 << 7)	/* 0=No ack, 1=acknowledge */
-
-/* Port 0 Status Register definitions */
-
-#define SR0_NO_RESULT		0		/* dummy */
-#define SR0_EVENT_MASK		0x0f
-#define SR0_IA_SETUP_DONE	1
-#define SR0_CONFIGURE_DONE	2
-#define SR0_MC_SETUP_DONE	3
-#define SR0_TRANSMIT_DONE	4
-#define SR0_TDR_DONE		5
-#define SR0_DUMP_DONE		6
-#define SR0_DIAGNOSE_PASSED	7
-#define SR0_TRANSMIT_NO_CRC_DONE 9
-#define SR0_RETRANSMIT_DONE	12
-#define SR0_EXECUTION_ABORTED	13
-#define SR0_END_OF_FRAME	8
-#define SR0_RECEPTION_ABORTED	10
-#define SR0_DIAGNOSE_FAILED	15
-#define SR0_STOP_REG_HIT	11
-
-#define SR0_CHNL		(1 << 4)
-#define SR0_EXECUTION		(1 << 5)
-#define SR0_RECEPTION		(1 << 6)
-#define SR0_INTERRUPT		(1 << 7)
-#define SR0_BOTH_RX_TX		(SR0_EXECUTION | SR0_RECEPTION)
-
-#define SR3_EXEC_STATE_MASK	0x03
-#define SR3_EXEC_IDLE		0
-#define SR3_TX_ABORT_IN_PROGRESS 1
-#define SR3_EXEC_ACTIVE		2
-#define SR3_ABORT_IN_PROGRESS	3
-#define SR3_EXEC_CHNL		(1 << 2)
-#define SR3_STP_ON_NO_RSRC	(1 << 3)
-#define SR3_RCVING_NO_RSRC	(1 << 4)
-#define SR3_RCV_STATE_MASK	0x60
-#define SR3_RCV_IDLE		0x00
-#define SR3_RCV_READY		0x20
-#define SR3_RCV_ACTIVE		0x40
-#define SR3_RCV_STOP_IN_PROG	0x60
-#define SR3_RCV_CHNL		(1 << 7)
-
-/* Port 1 Command Register definitions */
-
-#define OP1_NOP			0
-#define OP1_SWIT_TO_PORT_0	1
-#define OP1_INT_DISABLE		2
-#define OP1_INT_ENABLE		3
-#define OP1_SET_TS		5
-#define OP1_RST_TS		7
-#define OP1_POWER_DOWN		8
-#define OP1_RESET_RING_MNGMT	11
-#define OP1_RESET		14
-#define OP1_SEL_RST		15
-
-#define CR1_STATUS_4		0x00
-#define CR1_STATUS_5		0x20
-#define CR1_STATUS_6		0x40
-#define CR1_STOP_REG_UPDATE	(1 << 7)
-
-/* Receive frame status bits */
-
-#define	RX_RCLD			(1 << 0)
-#define RX_IA_MATCH		(1 << 1)
-#define	RX_NO_AD_MATCH		(1 << 2)
-#define RX_NO_SFD		(1 << 3)
-#define RX_SRT_FRM		(1 << 7)
-#define RX_OVRRUN		(1 << 8)
-#define RX_ALG_ERR		(1 << 10)
-#define RX_CRC_ERR		(1 << 11)
-#define RX_LEN_ERR		(1 << 12)
-#define RX_RCV_OK		(1 << 13)
-#define RX_TYP_LEN		(1 << 15)
-
-/* Transmit status bits */
-
-#define TX_NCOL_MASK		0x0f
-#define TX_FRTL			(1 << 4)
-#define TX_MAX_COL		(1 << 5)
-#define TX_HRT_BEAT		(1 << 6)
-#define TX_DEFER		(1 << 7)
-#define TX_UND_RUN		(1 << 8)
-#define TX_LOST_CTS		(1 << 9)
-#define TX_LOST_CRS		(1 << 10)
-#define TX_LTCOL		(1 << 11)
-#define TX_OK			(1 << 13)
-#define TX_COLL			(1 << 15)
-
-struct i82593_conf_block {
-  u_char fifo_limit : 4,
-  	 forgnesi   : 1,
-  	 fifo_32    : 1,
-  	 d6mod      : 1,
-  	 throttle_enb : 1;
-  u_char throttle   : 6,
-	 cntrxint   : 1,
-	 contin	    : 1;
-  u_char addr_len   : 3,
-  	 acloc 	    : 1,
- 	 preamb_len : 2,
-  	 loopback   : 2;
-  u_char lin_prio   : 3,
-	 tbofstop   : 1,
-	 exp_prio   : 3,
-	 bof_met    : 1;
-  u_char	    : 4,
-	 ifrm_spc   : 4;
-  u_char	    : 5,
-	 slottim_low : 3;
-  u_char slottim_hi : 3,
-		    : 1,
-	 max_retr   : 4;
-  u_char prmisc     : 1,
-	 bc_dis     : 1,
-  		    : 1,
-	 crs_1	    : 1,
-	 nocrc_ins  : 1,
-	 crc_1632   : 1,
-  	 	    : 1,
-  	 crs_cdt    : 1;
-  u_char cs_filter  : 3,
-	 crs_src    : 1,
-	 cd_filter  : 3,
-		    : 1;
-  u_char	    : 2,
-  	 min_fr_len : 6;
-  u_char lng_typ    : 1,
-	 lng_fld    : 1,
-	 rxcrc_xf   : 1,
-	 artx	    : 1,
-	 sarec	    : 1,
-	 tx_jabber  : 1,	/* why is this called max_len in the manual? */
-	 hash_1	    : 1,
-  	 lbpkpol    : 1;
-  u_char	    : 6,
-  	 fdx	    : 1,
-  	  	    : 1;
-  u_char dummy_6    : 6,	/* supposed to be ones */
-  	 mult_ia    : 1,
-  	 dis_bof    : 1;
-  u_char dummy_1    : 1,	/* supposed to be one */
-	 tx_ifs_retrig : 2,
-	 mc_all     : 1,
-	 rcv_mon    : 2,
-	 frag_acpt  : 1,
-  	 tstrttrs   : 1;
-  u_char fretx	    : 1,
-	 runt_eop   : 1,
-	 hw_sw_pin  : 1,
-	 big_endn   : 1,
-	 syncrqs    : 1,
-	 sttlen     : 1,
-	 tx_eop     : 1,
-  	 rx_eop	    : 1;
-  u_char rbuf_size  : 5,
-	 rcvstop    : 1,
-  	 	    : 2;
-};
-
-#define I82593_MAX_MULTICAST_ADDRESSES	128	/* Hardware hashed filter */
-
-#endif /* _I82593_H */
diff -urN linux/include/linux/ieee80211.h net-next-2.6/include/linux/ieee80211.h
--- linux/include/linux/ieee80211.h	2014-09-24 09:52:38.592596219 +0200
+++ net-next-2.6/include/linux/ieee80211.h	2014-10-06 10:48:54.536842425 +0200
@@ -6,6 +6,7 @@
  * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
  * Copyright (c) 2005, Devicescape Software, Inc.
  * Copyright (c) 2006, Michael Wu <flamingice@sourmilk.net>
+ * Copyright (c) 2013 - 2014 Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -165,8 +166,12 @@
 
 #define IEEE80211_MAX_MESH_ID_LEN	32
 
+#define IEEE80211_FIRST_TSPEC_TSID	8
 #define IEEE80211_NUM_TIDS		16
 
+/* number of user priorities 802.11 uses */
+#define IEEE80211_NUM_UPS		8
+
 #define IEEE80211_QOS_CTL_LEN		2
 /* 1d tag mask */
 #define IEEE80211_QOS_CTL_TAG1D_MASK		0x0007
@@ -838,6 +843,16 @@
 
 #define WLAN_SA_QUERY_TR_ID_LEN 2
 
+/**
+ * struct ieee80211_tpc_report_ie
+ *
+ * This structure refers to "TPC Report element"
+ */
+struct ieee80211_tpc_report_ie {
+	u8 tx_power;
+	u8 link_margin;
+} __packed;
+
 struct ieee80211_mgmt {
 	__le16 frame_control;
 	__le16 duration;
@@ -973,6 +988,13 @@
 					u8 action_code;
 					u8 operating_mode;
 				} __packed vht_opmode_notif;
+				struct {
+					u8 action_code;
+					u8 dialog_token;
+					u8 tpc_elem_id;
+					u8 tpc_elem_length;
+					struct ieee80211_tpc_report_ie tpc;
+				} __packed tpc_report;
 			} u;
 		} __packed action;
 	} u;
@@ -1806,7 +1828,8 @@
 	WLAN_EID_DMG_TSPEC = 146,
 	WLAN_EID_DMG_AT = 147,
 	WLAN_EID_DMG_CAP = 148,
-	/* 149-150 reserved for Cisco */
+	/* 149 reserved for Cisco */
+	WLAN_EID_CISCO_VENDOR_SPECIFIC = 150,
 	WLAN_EID_DMG_OPERATION = 151,
 	WLAN_EID_DMG_BSS_PARAM_CHANGE = 152,
 	WLAN_EID_DMG_BEAM_REFINEMENT = 153,
@@ -1865,6 +1888,7 @@
 	WLAN_CATEGORY_DLS = 2,
 	WLAN_CATEGORY_BACK = 3,
 	WLAN_CATEGORY_PUBLIC = 4,
+	WLAN_CATEGORY_RADIO_MEASUREMENT = 5,
 	WLAN_CATEGORY_HT = 7,
 	WLAN_CATEGORY_SA_QUERY = 8,
 	WLAN_CATEGORY_PROTECTED_DUAL_OF_ACTION = 9,
@@ -2378,4 +2402,51 @@
 #define TU_TO_JIFFIES(x)	(usecs_to_jiffies((x) * 1024))
 #define TU_TO_EXP_TIME(x)	(jiffies + TU_TO_JIFFIES(x))
 
+/**
+ * ieee80211_action_contains_tpc - checks if the frame contains TPC element
+ * @skb: the skb containing the frame, length will be checked
+ *
+ * This function checks if it's either TPC report action frame or Link
+ * Measurement report action frame as defined in IEEE Std. 802.11-2012 8.5.2.5
+ * and 8.5.7.5 accordingly.
+ */
+static inline bool ieee80211_action_contains_tpc(struct sk_buff *skb)
+{
+	struct ieee80211_mgmt *mgmt = (void *)skb->data;
+
+	if (!ieee80211_is_action(mgmt->frame_control))
+		return false;
+
+	if (skb->len < IEEE80211_MIN_ACTION_SIZE +
+		       sizeof(mgmt->u.action.u.tpc_report))
+		return false;
+
+	/*
+	 * TPC report - check that:
+	 * category = 0 (Spectrum Management) or 5 (Radio Measurement)
+	 * spectrum management action = 3 (TPC/Link Measurement report)
+	 * TPC report EID = 35
+	 * TPC report element length = 2
+	 *
+	 * The spectrum management's tpc_report struct is used here both for
+	 * parsing tpc_report and radio measurement's link measurement report
+	 * frame, since the relevant part is identical in both frames.
+	 */
+	if (mgmt->u.action.category != WLAN_CATEGORY_SPECTRUM_MGMT &&
+	    mgmt->u.action.category != WLAN_CATEGORY_RADIO_MEASUREMENT)
+		return false;
+
+	/* both spectrum mgmt and link measurement have same action code */
+	if (mgmt->u.action.u.tpc_report.action_code !=
+	    WLAN_ACTION_SPCT_TPC_RPRT)
+		return false;
+
+	if (mgmt->u.action.u.tpc_report.tpc_elem_id != WLAN_EID_TPC_REPORT ||
+	    mgmt->u.action.u.tpc_report.tpc_elem_length !=
+	    sizeof(struct ieee80211_tpc_report_ie))
+		return false;
+
+	return true;
+}
+
 #endif /* LINUX_IEEE80211_H */
diff -urN linux/include/linux/if_macvlan.h net-next-2.6/include/linux/if_macvlan.h
--- linux/include/linux/if_macvlan.h	2014-09-24 09:52:38.592596219 +0200
+++ net-next-2.6/include/linux/if_macvlan.h	2014-10-06 10:48:54.536842425 +0200
@@ -60,6 +60,7 @@
 #ifdef CONFIG_NET_POLL_CONTROLLER
 	struct netpoll		*netpoll;
 #endif
+	unsigned int		macaddr_count;
 };
 
 static inline void macvlan_count_rx(const struct macvlan_dev *vlan,
diff -urN linux/include/linux/igmp.h net-next-2.6/include/linux/igmp.h
--- linux/include/linux/igmp.h	2013-11-29 12:59:35.699359049 +0100
+++ net-next-2.6/include/linux/igmp.h	2014-10-06 10:48:54.536842425 +0200
@@ -39,6 +39,7 @@
 
 extern int sysctl_igmp_max_memberships;
 extern int sysctl_igmp_max_msf;
+extern int sysctl_igmp_qrv;
 
 struct ip_sf_socklist {
 	unsigned int		sl_max;
diff -urN linux/include/linux/mlx4/device.h net-next-2.6/include/linux/mlx4/device.h
--- linux/include/linux/mlx4/device.h	2014-09-24 09:52:38.708597436 +0200
+++ net-next-2.6/include/linux/mlx4/device.h	2014-10-06 10:48:54.628843362 +0200
@@ -38,6 +38,7 @@
 #include <linux/completion.h>
 #include <linux/radix-tree.h>
 #include <linux/cpu_rmap.h>
+#include <linux/crash_dump.h>
 
 #include <linux/atomic.h>
 
@@ -184,19 +185,24 @@
 	MLX4_DEV_CAP_FLAG2_DMFS_IPOIB		= 1LL <<  9,
 	MLX4_DEV_CAP_FLAG2_VXLAN_OFFLOADS	= 1LL <<  10,
 	MLX4_DEV_CAP_FLAG2_MAD_DEMUX		= 1LL <<  11,
+	MLX4_DEV_CAP_FLAG2_CQE_STRIDE		= 1LL <<  12,
+	MLX4_DEV_CAP_FLAG2_EQE_STRIDE		= 1LL <<  13
 };
 
 enum {
 	MLX4_DEV_CAP_64B_EQE_ENABLED	= 1LL << 0,
-	MLX4_DEV_CAP_64B_CQE_ENABLED	= 1LL << 1
+	MLX4_DEV_CAP_64B_CQE_ENABLED	= 1LL << 1,
+	MLX4_DEV_CAP_CQE_STRIDE_ENABLED	= 1LL << 2,
+	MLX4_DEV_CAP_EQE_STRIDE_ENABLED	= 1LL << 3
 };
 
 enum {
-	MLX4_USER_DEV_CAP_64B_CQE	= 1L << 0
+	MLX4_USER_DEV_CAP_LARGE_CQE	= 1L << 0
 };
 
 enum {
-	MLX4_FUNC_CAP_64B_EQE_CQE	= 1L << 0
+	MLX4_FUNC_CAP_64B_EQE_CQE	= 1L << 0,
+	MLX4_FUNC_CAP_EQE_CQE_STRIDE	= 1L << 1
 };
 
 
@@ -577,7 +583,7 @@
 };
 
 struct mlx4_bf {
-	unsigned long		offset;
+	unsigned int		offset;
 	int			buf_size;
 	struct mlx4_uar	       *uar;
 	void __iomem	       *reg;
@@ -701,6 +707,7 @@
 	u64			regid_promisc_array[MLX4_MAX_PORTS + 1];
 	u64			regid_allmulti_array[MLX4_MAX_PORTS + 1];
 	struct mlx4_vf_dev     *dev_vfs;
+	int                     nvfs[MLX4_MAX_PORTS + 1];
 };
 
 struct mlx4_eqe {
@@ -1279,7 +1286,7 @@
 /* Returns true if running in low memory profile (kdump kernel) */
 static inline bool mlx4_low_memory_profile(void)
 {
-	return reset_devices;
+	return is_kdump_kernel();
 }
 
 #endif /* MLX4_DEVICE_H */
diff -urN linux/include/linux/mlx5/device.h net-next-2.6/include/linux/mlx5/device.h
--- linux/include/linux/mlx5/device.h	2014-09-24 09:52:38.724597604 +0200
+++ net-next-2.6/include/linux/mlx5/device.h	2014-10-06 10:48:54.628843362 +0200
@@ -44,6 +44,50 @@
 #error Host endianness not defined
 #endif
 
+/* helper macros */
+#define __mlx5_nullp(typ) ((struct mlx5_ifc_##typ##_bits *)0)
+#define __mlx5_bit_sz(typ, fld) sizeof(__mlx5_nullp(typ)->fld)
+#define __mlx5_bit_off(typ, fld) ((unsigned)(unsigned long)(&(__mlx5_nullp(typ)->fld)))
+#define __mlx5_dw_off(typ, fld) (__mlx5_bit_off(typ, fld) / 32)
+#define __mlx5_64_off(typ, fld) (__mlx5_bit_off(typ, fld) / 64)
+#define __mlx5_dw_bit_off(typ, fld) (32 - __mlx5_bit_sz(typ, fld) - (__mlx5_bit_off(typ, fld) & 0x1f))
+#define __mlx5_mask(typ, fld) ((u32)((1ull << __mlx5_bit_sz(typ, fld)) - 1))
+#define __mlx5_dw_mask(typ, fld) (__mlx5_mask(typ, fld) << __mlx5_dw_bit_off(typ, fld))
+#define __mlx5_st_sz_bits(typ) sizeof(struct mlx5_ifc_##typ##_bits)
+
+#define MLX5_FLD_SZ_BYTES(typ, fld) (__mlx5_bit_sz(typ, fld) / 8)
+#define MLX5_ST_SZ_BYTES(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 8)
+#define MLX5_ST_SZ_DW(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 32)
+#define MLX5_BYTE_OFF(typ, fld) (__mlx5_bit_off(typ, fld) / 8)
+#define MLX5_ADDR_OF(typ, p, fld) ((char *)(p) + MLX5_BYTE_OFF(typ, fld))
+
+/* insert a value to a struct */
+#define MLX5_SET(typ, p, fld, v) do { \
+	BUILD_BUG_ON(__mlx5_st_sz_bits(typ) % 32);             \
+	*((__be32 *)(p) + __mlx5_dw_off(typ, fld)) = \
+	cpu_to_be32((be32_to_cpu(*((__be32 *)(p) + __mlx5_dw_off(typ, fld))) & \
+		     (~__mlx5_dw_mask(typ, fld))) | (((v) & __mlx5_mask(typ, fld)) \
+		     << __mlx5_dw_bit_off(typ, fld))); \
+} while (0)
+
+#define MLX5_GET(typ, p, fld) ((be32_to_cpu(*((__be32 *)(p) +\
+__mlx5_dw_off(typ, fld))) >> __mlx5_dw_bit_off(typ, fld)) & \
+__mlx5_mask(typ, fld))
+
+#define MLX5_GET_PR(typ, p, fld) ({ \
+	u32 ___t = MLX5_GET(typ, p, fld); \
+	pr_debug(#fld " = 0x%x\n", ___t); \
+	___t; \
+})
+
+#define MLX5_SET64(typ, p, fld, v) do { \
+	BUILD_BUG_ON(__mlx5_bit_sz(typ, fld) != 64); \
+	BUILD_BUG_ON(__mlx5_bit_off(typ, fld) % 64); \
+	*((__be64 *)(p) + __mlx5_64_off(typ, fld)) = cpu_to_be64(v); \
+} while (0)
+
+#define MLX5_GET64(typ, p, fld) be64_to_cpu(*((__be64 *)(p) + __mlx5_64_off(typ, fld)))
+
 enum {
 	MLX5_MAX_COMMANDS		= 32,
 	MLX5_CMD_DATA_BLOCK_SIZE	= 512,
@@ -71,6 +115,11 @@
 };
 
 enum {
+	MLX5_MIN_PKEY_TABLE_SIZE = 128,
+	MLX5_MAX_LOG_PKEY_TABLE  = 5,
+};
+
+enum {
 	MLX5_PERM_LOCAL_READ	= 1 << 2,
 	MLX5_PERM_LOCAL_WRITE	= 1 << 3,
 	MLX5_PERM_REMOTE_READ	= 1 << 4,
@@ -184,10 +233,10 @@
 	MLX5_DEV_CAP_FLAG_CQ_MODER	= 1LL << 29,
 	MLX5_DEV_CAP_FLAG_RESIZE_CQ	= 1LL << 30,
 	MLX5_DEV_CAP_FLAG_RESIZE_SRQ	= 1LL << 32,
+	MLX5_DEV_CAP_FLAG_DCT		= 1LL << 37,
 	MLX5_DEV_CAP_FLAG_REMOTE_FENCE	= 1LL << 38,
 	MLX5_DEV_CAP_FLAG_TLP_HINTS	= 1LL << 39,
 	MLX5_DEV_CAP_FLAG_SIG_HAND_OVER	= 1LL << 40,
-	MLX5_DEV_CAP_FLAG_DCT		= 1LL << 41,
 	MLX5_DEV_CAP_FLAG_CMDIF_CSUM	= 3LL << 46,
 };
 
@@ -243,10 +292,14 @@
 };
 
 enum {
-	MLX5_CAP_OFF_DCT		= 41,
 	MLX5_CAP_OFF_CMDIF_CSUM		= 46,
 };
 
+enum {
+	HCA_CAP_OPMOD_GET_MAX	= 0,
+	HCA_CAP_OPMOD_GET_CUR	= 1,
+};
+
 struct mlx5_inbox_hdr {
 	__be16		opcode;
 	u8		rsvd[4];
@@ -274,101 +327,6 @@
 	u8			vsd_psid[16];
 };
 
-struct mlx5_hca_cap {
-	u8	rsvd1[16];
-	u8	log_max_srq_sz;
-	u8	log_max_qp_sz;
-	u8	rsvd2;
-	u8	log_max_qp;
-	u8	log_max_strq_sz;
-	u8	log_max_srqs;
-	u8	rsvd4[2];
-	u8	rsvd5;
-	u8	log_max_cq_sz;
-	u8	rsvd6;
-	u8	log_max_cq;
-	u8	log_max_eq_sz;
-	u8	log_max_mkey;
-	u8	rsvd7;
-	u8	log_max_eq;
-	u8	max_indirection;
-	u8	log_max_mrw_sz;
-	u8	log_max_bsf_list_sz;
-	u8	log_max_klm_list_sz;
-	u8	rsvd_8_0;
-	u8	log_max_ra_req_dc;
-	u8	rsvd_8_1;
-	u8	log_max_ra_res_dc;
-	u8	rsvd9;
-	u8	log_max_ra_req_qp;
-	u8	rsvd10;
-	u8	log_max_ra_res_qp;
-	u8	rsvd11[4];
-	__be16	max_qp_count;
-	__be16	rsvd12;
-	u8	rsvd13;
-	u8	local_ca_ack_delay;
-	u8	rsvd14;
-	u8	num_ports;
-	u8	log_max_msg;
-	u8	rsvd15[3];
-	__be16	stat_rate_support;
-	u8	rsvd16[2];
-	__be64	flags;
-	u8	rsvd17;
-	u8	uar_sz;
-	u8	rsvd18;
-	u8	log_pg_sz;
-	__be16	bf_log_bf_reg_size;
-	u8	rsvd19[4];
-	__be16	max_desc_sz_sq;
-	u8	rsvd20[2];
-	__be16	max_desc_sz_rq;
-	u8	rsvd21[2];
-	__be16	max_desc_sz_sq_dc;
-	__be32	max_qp_mcg;
-	u8	rsvd22[3];
-	u8	log_max_mcg;
-	u8	rsvd23;
-	u8	log_max_pd;
-	u8	rsvd24;
-	u8	log_max_xrcd;
-	u8	rsvd25[42];
-	__be16  log_uar_page_sz;
-	u8	rsvd26[28];
-	u8	log_max_atomic_size_qp;
-	u8	rsvd27[2];
-	u8	log_max_atomic_size_dc;
-	u8	rsvd28[76];
-};
-
-
-struct mlx5_cmd_query_hca_cap_mbox_in {
-	struct mlx5_inbox_hdr	hdr;
-	u8			rsvd[8];
-};
-
-
-struct mlx5_cmd_query_hca_cap_mbox_out {
-	struct mlx5_outbox_hdr	hdr;
-	u8			rsvd0[8];
-	struct mlx5_hca_cap     hca_cap;
-};
-
-
-struct mlx5_cmd_set_hca_cap_mbox_in {
-	struct mlx5_inbox_hdr	hdr;
-	u8			rsvd[8];
-	struct mlx5_hca_cap     hca_cap;
-};
-
-
-struct mlx5_cmd_set_hca_cap_mbox_out {
-	struct mlx5_outbox_hdr	hdr;
-	u8			rsvd0[8];
-};
-
-
 struct mlx5_cmd_init_hca_mbox_in {
 	struct mlx5_inbox_hdr	hdr;
 	u8			rsvd0[2];
diff -urN linux/include/linux/mlx5/driver.h net-next-2.6/include/linux/mlx5/driver.h
--- linux/include/linux/mlx5/driver.h	2014-09-24 09:52:38.724597604 +0200
+++ net-next-2.6/include/linux/mlx5/driver.h	2014-10-06 10:48:54.632843402 +0200
@@ -44,6 +44,7 @@
 
 #include <linux/mlx5/device.h>
 #include <linux/mlx5/doorbell.h>
+#include <linux/mlx5/mlx5_ifc.h>
 
 enum {
 	MLX5_BOARD_ID_LEN = 64,
@@ -99,81 +100,6 @@
 };
 
 enum {
-	MLX5_CMD_OP_QUERY_HCA_CAP		= 0x100,
-	MLX5_CMD_OP_QUERY_ADAPTER		= 0x101,
-	MLX5_CMD_OP_INIT_HCA			= 0x102,
-	MLX5_CMD_OP_TEARDOWN_HCA		= 0x103,
-	MLX5_CMD_OP_ENABLE_HCA			= 0x104,
-	MLX5_CMD_OP_DISABLE_HCA			= 0x105,
-	MLX5_CMD_OP_QUERY_PAGES			= 0x107,
-	MLX5_CMD_OP_MANAGE_PAGES		= 0x108,
-	MLX5_CMD_OP_SET_HCA_CAP			= 0x109,
-
-	MLX5_CMD_OP_CREATE_MKEY			= 0x200,
-	MLX5_CMD_OP_QUERY_MKEY			= 0x201,
-	MLX5_CMD_OP_DESTROY_MKEY		= 0x202,
-	MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS	= 0x203,
-
-	MLX5_CMD_OP_CREATE_EQ			= 0x301,
-	MLX5_CMD_OP_DESTROY_EQ			= 0x302,
-	MLX5_CMD_OP_QUERY_EQ			= 0x303,
-
-	MLX5_CMD_OP_CREATE_CQ			= 0x400,
-	MLX5_CMD_OP_DESTROY_CQ			= 0x401,
-	MLX5_CMD_OP_QUERY_CQ			= 0x402,
-	MLX5_CMD_OP_MODIFY_CQ			= 0x403,
-
-	MLX5_CMD_OP_CREATE_QP			= 0x500,
-	MLX5_CMD_OP_DESTROY_QP			= 0x501,
-	MLX5_CMD_OP_RST2INIT_QP			= 0x502,
-	MLX5_CMD_OP_INIT2RTR_QP			= 0x503,
-	MLX5_CMD_OP_RTR2RTS_QP			= 0x504,
-	MLX5_CMD_OP_RTS2RTS_QP			= 0x505,
-	MLX5_CMD_OP_SQERR2RTS_QP		= 0x506,
-	MLX5_CMD_OP_2ERR_QP			= 0x507,
-	MLX5_CMD_OP_RTS2SQD_QP			= 0x508,
-	MLX5_CMD_OP_SQD2RTS_QP			= 0x509,
-	MLX5_CMD_OP_2RST_QP			= 0x50a,
-	MLX5_CMD_OP_QUERY_QP			= 0x50b,
-	MLX5_CMD_OP_CONF_SQP			= 0x50c,
-	MLX5_CMD_OP_MAD_IFC			= 0x50d,
-	MLX5_CMD_OP_INIT2INIT_QP		= 0x50e,
-	MLX5_CMD_OP_SUSPEND_QP			= 0x50f,
-	MLX5_CMD_OP_UNSUSPEND_QP		= 0x510,
-	MLX5_CMD_OP_SQD2SQD_QP			= 0x511,
-	MLX5_CMD_OP_ALLOC_QP_COUNTER_SET	= 0x512,
-	MLX5_CMD_OP_DEALLOC_QP_COUNTER_SET	= 0x513,
-	MLX5_CMD_OP_QUERY_QP_COUNTER_SET	= 0x514,
-
-	MLX5_CMD_OP_CREATE_PSV			= 0x600,
-	MLX5_CMD_OP_DESTROY_PSV			= 0x601,
-	MLX5_CMD_OP_QUERY_PSV			= 0x602,
-	MLX5_CMD_OP_QUERY_SIG_RULE_TABLE	= 0x603,
-	MLX5_CMD_OP_QUERY_BLOCK_SIZE_TABLE	= 0x604,
-
-	MLX5_CMD_OP_CREATE_SRQ			= 0x700,
-	MLX5_CMD_OP_DESTROY_SRQ			= 0x701,
-	MLX5_CMD_OP_QUERY_SRQ			= 0x702,
-	MLX5_CMD_OP_ARM_RQ			= 0x703,
-	MLX5_CMD_OP_RESIZE_SRQ			= 0x704,
-
-	MLX5_CMD_OP_ALLOC_PD			= 0x800,
-	MLX5_CMD_OP_DEALLOC_PD			= 0x801,
-	MLX5_CMD_OP_ALLOC_UAR			= 0x802,
-	MLX5_CMD_OP_DEALLOC_UAR			= 0x803,
-
-	MLX5_CMD_OP_ATTACH_TO_MCG		= 0x806,
-	MLX5_CMD_OP_DETACH_FROM_MCG		= 0x807,
-
-
-	MLX5_CMD_OP_ALLOC_XRCD			= 0x80e,
-	MLX5_CMD_OP_DEALLOC_XRCD		= 0x80f,
-
-	MLX5_CMD_OP_ACCESS_REG			= 0x805,
-	MLX5_CMD_OP_MAX				= 0x810,
-};
-
-enum {
 	MLX5_REG_PCAP		 = 0x5001,
 	MLX5_REG_PMTU		 = 0x5003,
 	MLX5_REG_PTYS		 = 0x5004,
@@ -335,23 +261,30 @@
 	int	pkey_table_len;
 };
 
-struct mlx5_caps {
+struct mlx5_general_caps {
 	u8	log_max_eq;
 	u8	log_max_cq;
 	u8	log_max_qp;
 	u8	log_max_mkey;
 	u8	log_max_pd;
 	u8	log_max_srq;
+	u8	log_max_strq;
+	u8	log_max_mrw_sz;
+	u8	log_max_bsf_list_size;
+	u8	log_max_klm_list_size;
 	u32	max_cqes;
 	int	max_wqes;
+	u32	max_eqes;
+	u32	max_indirection;
 	int	max_sq_desc_sz;
 	int	max_rq_desc_sz;
+	int	max_dc_sq_desc_sz;
 	u64	flags;
 	u16	stat_rate_support;
 	int	log_max_msg;
 	int	num_ports;
-	int	max_ra_res_qp;
-	int	max_ra_req_qp;
+	u8	log_max_ra_res_qp;
+	u8	log_max_ra_req_qp;
 	int	max_srq_wqes;
 	int	bf_reg_size;
 	int	bf_regs_per_page;
@@ -363,6 +296,19 @@
 	u8	log_max_mcg;
 	u32	max_qp_mcg;
 	int	min_page_sz;
+	int	pd_cap;
+	u32	max_qp_counters;
+	u32	pkey_table_size;
+	u8	log_max_ra_req_dc;
+	u8	log_max_ra_res_dc;
+	u32	uar_sz;
+	u8	min_log_pg_sz;
+	u8	log_max_xrcd;
+	u16	log_uar_page_sz;
+};
+
+struct mlx5_caps {
+	struct mlx5_general_caps gen;
 };
 
 struct mlx5_cmd_mailbox {
@@ -429,6 +375,16 @@
 	u32			pd;
 };
 
+enum mlx5_res_type {
+	MLX5_RES_QP,
+};
+
+struct mlx5_core_rsc_common {
+	enum mlx5_res_type	res;
+	atomic_t		refcount;
+	struct completion	free;
+};
+
 struct mlx5_core_srq {
 	u32		srqn;
 	int		max;
@@ -695,6 +651,9 @@
 void mlx5_cmd_use_events(struct mlx5_core_dev *dev);
 void mlx5_cmd_use_polling(struct mlx5_core_dev *dev);
 int mlx5_cmd_status_to_err(struct mlx5_outbox_hdr *hdr);
+int mlx5_cmd_status_to_err_v2(void *ptr);
+int mlx5_core_get_caps(struct mlx5_core_dev *dev, struct mlx5_caps *caps,
+		       u16 opmod);
 int mlx5_cmd_exec(struct mlx5_core_dev *dev, void *in, int in_size, void *out,
 		  int out_size);
 int mlx5_cmd_exec_cb(struct mlx5_core_dev *dev, void *in, int in_size,
@@ -751,7 +710,7 @@
 void mlx5_eq_cleanup(struct mlx5_core_dev *dev);
 void mlx5_fill_page_array(struct mlx5_buf *buf, __be64 *pas);
 void mlx5_cq_completion(struct mlx5_core_dev *dev, u32 cqn);
-void mlx5_qp_event(struct mlx5_core_dev *dev, u32 qpn, int event_type);
+void mlx5_rsc_event(struct mlx5_core_dev *dev, u32 rsn, int event_type);
 void mlx5_srq_event(struct mlx5_core_dev *dev, u32 srqn, int event_type);
 struct mlx5_core_srq *mlx5_core_get_srq(struct mlx5_core_dev *dev, u32 srqn);
 void mlx5_cmd_comp_handler(struct mlx5_core_dev *dev, unsigned long vector);
@@ -788,6 +747,7 @@
 int mlx5_core_create_psv(struct mlx5_core_dev *dev, u32 pdn,
 			 int npsvs, u32 *sig_index);
 int mlx5_core_destroy_psv(struct mlx5_core_dev *dev, int psv_num);
+void mlx5_core_put_rsc(struct mlx5_core_rsc_common *common);
 
 static inline u32 mlx5_mkey_to_idx(u32 mkey)
 {
diff -urN linux/include/linux/mlx5/mlx5_ifc.h net-next-2.6/include/linux/mlx5/mlx5_ifc.h
--- linux/include/linux/mlx5/mlx5_ifc.h	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/include/linux/mlx5/mlx5_ifc.h	2014-10-06 10:48:54.632843402 +0200
@@ -0,0 +1,349 @@
+/*
+ * Copyright (c) 2014, Mellanox Technologies inc.  All rights reserved.
+ *
+ * This software is available to you under a choice of one of two
+ * licenses.  You may choose to be licensed under the terms of the GNU
+ * General Public License (GPL) Version 2, available from the file
+ * COPYING in the main directory of this source tree, or the
+ * OpenIB.org BSD license below:
+ *
+ *     Redistribution and use in source and binary forms, with or
+ *     without modification, are permitted provided that the following
+ *     conditions are met:
+ *
+ *      - Redistributions of source code must retain the above
+ *        copyright notice, this list of conditions and the following
+ *        disclaimer.
+ *
+ *      - Redistributions in binary form must reproduce the above
+ *        copyright notice, this list of conditions and the following
+ *        disclaimer in the documentation and/or other materials
+ *        provided with the distribution.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
+ * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
+ * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
+ * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
+ * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
+ * SOFTWARE.
+ */
+
+#ifndef MLX5_IFC_H
+#define MLX5_IFC_H
+
+enum {
+	MLX5_CMD_OP_QUERY_HCA_CAP                 = 0x100,
+	MLX5_CMD_OP_QUERY_ADAPTER                 = 0x101,
+	MLX5_CMD_OP_INIT_HCA                      = 0x102,
+	MLX5_CMD_OP_TEARDOWN_HCA                  = 0x103,
+	MLX5_CMD_OP_ENABLE_HCA                    = 0x104,
+	MLX5_CMD_OP_DISABLE_HCA                   = 0x105,
+	MLX5_CMD_OP_QUERY_PAGES                   = 0x107,
+	MLX5_CMD_OP_MANAGE_PAGES                  = 0x108,
+	MLX5_CMD_OP_SET_HCA_CAP                   = 0x109,
+	MLX5_CMD_OP_CREATE_MKEY                   = 0x200,
+	MLX5_CMD_OP_QUERY_MKEY                    = 0x201,
+	MLX5_CMD_OP_DESTROY_MKEY                  = 0x202,
+	MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS        = 0x203,
+	MLX5_CMD_OP_PAGE_FAULT_RESUME             = 0x204,
+	MLX5_CMD_OP_CREATE_EQ                     = 0x301,
+	MLX5_CMD_OP_DESTROY_EQ                    = 0x302,
+	MLX5_CMD_OP_QUERY_EQ                      = 0x303,
+	MLX5_CMD_OP_GEN_EQE                       = 0x304,
+	MLX5_CMD_OP_CREATE_CQ                     = 0x400,
+	MLX5_CMD_OP_DESTROY_CQ                    = 0x401,
+	MLX5_CMD_OP_QUERY_CQ                      = 0x402,
+	MLX5_CMD_OP_MODIFY_CQ                     = 0x403,
+	MLX5_CMD_OP_CREATE_QP                     = 0x500,
+	MLX5_CMD_OP_DESTROY_QP                    = 0x501,
+	MLX5_CMD_OP_RST2INIT_QP                   = 0x502,
+	MLX5_CMD_OP_INIT2RTR_QP                   = 0x503,
+	MLX5_CMD_OP_RTR2RTS_QP                    = 0x504,
+	MLX5_CMD_OP_RTS2RTS_QP                    = 0x505,
+	MLX5_CMD_OP_SQERR2RTS_QP                  = 0x506,
+	MLX5_CMD_OP_2ERR_QP                       = 0x507,
+	MLX5_CMD_OP_2RST_QP                       = 0x50a,
+	MLX5_CMD_OP_QUERY_QP                      = 0x50b,
+	MLX5_CMD_OP_INIT2INIT_QP                  = 0x50e,
+	MLX5_CMD_OP_CREATE_PSV                    = 0x600,
+	MLX5_CMD_OP_DESTROY_PSV                   = 0x601,
+	MLX5_CMD_OP_CREATE_SRQ                    = 0x700,
+	MLX5_CMD_OP_DESTROY_SRQ                   = 0x701,
+	MLX5_CMD_OP_QUERY_SRQ                     = 0x702,
+	MLX5_CMD_OP_ARM_RQ                        = 0x703,
+	MLX5_CMD_OP_RESIZE_SRQ                    = 0x704,
+	MLX5_CMD_OP_CREATE_DCT                    = 0x710,
+	MLX5_CMD_OP_DESTROY_DCT                   = 0x711,
+	MLX5_CMD_OP_DRAIN_DCT                     = 0x712,
+	MLX5_CMD_OP_QUERY_DCT                     = 0x713,
+	MLX5_CMD_OP_ARM_DCT_FOR_KEY_VIOLATION     = 0x714,
+	MLX5_CMD_OP_QUERY_VPORT_STATE             = 0x750,
+	MLX5_CMD_OP_MODIFY_VPORT_STATE            = 0x751,
+	MLX5_CMD_OP_QUERY_ESW_VPORT_CONTEXT       = 0x752,
+	MLX5_CMD_OP_MODIFY_ESW_VPORT_CONTEXT      = 0x753,
+	MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT       = 0x754,
+	MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT      = 0x755,
+	MLX5_CMD_OP_QUERY_RCOE_ADDRESS            = 0x760,
+	MLX5_CMD_OP_SET_ROCE_ADDRESS              = 0x761,
+	MLX5_CMD_OP_QUERY_VPORT_COUNTER           = 0x770,
+	MLX5_CMD_OP_ALLOC_Q_COUNTER               = 0x771,
+	MLX5_CMD_OP_DEALLOC_Q_COUNTER             = 0x772,
+	MLX5_CMD_OP_QUERY_Q_COUNTER               = 0x773,
+	MLX5_CMD_OP_ALLOC_PD                      = 0x800,
+	MLX5_CMD_OP_DEALLOC_PD                    = 0x801,
+	MLX5_CMD_OP_ALLOC_UAR                     = 0x802,
+	MLX5_CMD_OP_DEALLOC_UAR                   = 0x803,
+	MLX5_CMD_OP_CONFIG_INT_MODERATION         = 0x804,
+	MLX5_CMD_OP_ACCESS_REG                    = 0x805,
+	MLX5_CMD_OP_ATTACH_TO_MCG                 = 0x806,
+	MLX5_CMD_OP_DETACH_FROM_MCG               = 0x807,
+	MLX5_CMD_OP_GET_DROPPED_PACKET_LOG        = 0x80a,
+	MLX5_CMD_OP_MAD_IFC                       = 0x50d,
+	MLX5_CMD_OP_QUERY_MAD_DEMUX               = 0x80b,
+	MLX5_CMD_OP_SET_MAD_DEMUX                 = 0x80c,
+	MLX5_CMD_OP_NOP                           = 0x80d,
+	MLX5_CMD_OP_ALLOC_XRCD                    = 0x80e,
+	MLX5_CMD_OP_DEALLOC_XRCD                  = 0x80f,
+	MLX5_CMD_OP_SET_BURST_SIZE                = 0x812,
+	MLX5_CMD_OP_QUERY_BURST_SZIE              = 0x813,
+	MLX5_CMD_OP_ACTIVATE_TRACER               = 0x814,
+	MLX5_CMD_OP_DEACTIVATE_TRACER             = 0x815,
+	MLX5_CMD_OP_CREATE_SNIFFER_RULE           = 0x820,
+	MLX5_CMD_OP_DESTROY_SNIFFER_RULE          = 0x821,
+	MLX5_CMD_OP_QUERY_CONG_PARAMS             = 0x822,
+	MLX5_CMD_OP_MODIFY_CONG_PARAMS            = 0x823,
+	MLX5_CMD_OP_QUERY_CONG_STATISTICS         = 0x824,
+	MLX5_CMD_OP_CREATE_TIR                    = 0x900,
+	MLX5_CMD_OP_MODIFY_TIR                    = 0x901,
+	MLX5_CMD_OP_DESTROY_TIR                   = 0x902,
+	MLX5_CMD_OP_QUERY_TIR                     = 0x903,
+	MLX5_CMD_OP_CREATE_TIS                    = 0x912,
+	MLX5_CMD_OP_MODIFY_TIS                    = 0x913,
+	MLX5_CMD_OP_DESTROY_TIS                   = 0x914,
+	MLX5_CMD_OP_QUERY_TIS                     = 0x915,
+	MLX5_CMD_OP_CREATE_SQ                     = 0x904,
+	MLX5_CMD_OP_MODIFY_SQ                     = 0x905,
+	MLX5_CMD_OP_DESTROY_SQ                    = 0x906,
+	MLX5_CMD_OP_QUERY_SQ                      = 0x907,
+	MLX5_CMD_OP_CREATE_RQ                     = 0x908,
+	MLX5_CMD_OP_MODIFY_RQ                     = 0x909,
+	MLX5_CMD_OP_DESTROY_RQ                    = 0x90a,
+	MLX5_CMD_OP_QUERY_RQ                      = 0x90b,
+	MLX5_CMD_OP_CREATE_RMP                    = 0x90c,
+	MLX5_CMD_OP_MODIFY_RMP                    = 0x90d,
+	MLX5_CMD_OP_DESTROY_RMP                   = 0x90e,
+	MLX5_CMD_OP_QUERY_RMP                     = 0x90f,
+	MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY          = 0x910,
+	MLX5_CMD_OP_QUERY_FLOW_TABLE_ENTRY        = 0x911,
+	MLX5_CMD_OP_MAX				  = 0x911
+};
+
+struct mlx5_ifc_cmd_hca_cap_bits {
+	u8         reserved_0[0x80];
+
+	u8         log_max_srq_sz[0x8];
+	u8         log_max_qp_sz[0x8];
+	u8         reserved_1[0xb];
+	u8         log_max_qp[0x5];
+
+	u8         log_max_strq_sz[0x8];
+	u8         reserved_2[0x3];
+	u8         log_max_srqs[0x5];
+	u8         reserved_3[0x10];
+
+	u8         reserved_4[0x8];
+	u8         log_max_cq_sz[0x8];
+	u8         reserved_5[0xb];
+	u8         log_max_cq[0x5];
+
+	u8         log_max_eq_sz[0x8];
+	u8         reserved_6[0x2];
+	u8         log_max_mkey[0x6];
+	u8         reserved_7[0xc];
+	u8         log_max_eq[0x4];
+
+	u8         max_indirection[0x8];
+	u8         reserved_8[0x1];
+	u8         log_max_mrw_sz[0x7];
+	u8         reserved_9[0x2];
+	u8         log_max_bsf_list_size[0x6];
+	u8         reserved_10[0x2];
+	u8         log_max_klm_list_size[0x6];
+
+	u8         reserved_11[0xa];
+	u8         log_max_ra_req_dc[0x6];
+	u8         reserved_12[0xa];
+	u8         log_max_ra_res_dc[0x6];
+
+	u8         reserved_13[0xa];
+	u8         log_max_ra_req_qp[0x6];
+	u8         reserved_14[0xa];
+	u8         log_max_ra_res_qp[0x6];
+
+	u8         pad_cap[0x1];
+	u8         cc_query_allowed[0x1];
+	u8         cc_modify_allowed[0x1];
+	u8         reserved_15[0x1d];
+
+	u8         reserved_16[0x6];
+	u8         max_qp_cnt[0xa];
+	u8         pkey_table_size[0x10];
+
+	u8         eswitch_owner[0x1];
+	u8         reserved_17[0xa];
+	u8         local_ca_ack_delay[0x5];
+	u8         reserved_18[0x8];
+	u8         num_ports[0x8];
+
+	u8         reserved_19[0x3];
+	u8         log_max_msg[0x5];
+	u8         reserved_20[0x18];
+
+	u8         stat_rate_support[0x10];
+	u8         reserved_21[0x10];
+
+	u8         reserved_22[0x10];
+	u8         cmdif_checksum[0x2];
+	u8         sigerr_cqe[0x1];
+	u8         reserved_23[0x1];
+	u8         wq_signature[0x1];
+	u8         sctr_data_cqe[0x1];
+	u8         reserved_24[0x1];
+	u8         sho[0x1];
+	u8         tph[0x1];
+	u8         rf[0x1];
+	u8         dc[0x1];
+	u8         reserved_25[0x2];
+	u8         roce[0x1];
+	u8         atomic[0x1];
+	u8         rsz_srq[0x1];
+
+	u8         cq_oi[0x1];
+	u8         cq_resize[0x1];
+	u8         cq_moderation[0x1];
+	u8         sniffer_rule_flow[0x1];
+	u8         sniffer_rule_vport[0x1];
+	u8         sniffer_rule_phy[0x1];
+	u8         reserved_26[0x1];
+	u8         pg[0x1];
+	u8         block_lb_mc[0x1];
+	u8         reserved_27[0x3];
+	u8         cd[0x1];
+	u8         reserved_28[0x1];
+	u8         apm[0x1];
+	u8         reserved_29[0x7];
+	u8         qkv[0x1];
+	u8         pkv[0x1];
+	u8         reserved_30[0x4];
+	u8         xrc[0x1];
+	u8         ud[0x1];
+	u8         uc[0x1];
+	u8         rc[0x1];
+
+	u8         reserved_31[0xa];
+	u8         uar_sz[0x6];
+	u8         reserved_32[0x8];
+	u8         log_pg_sz[0x8];
+
+	u8         bf[0x1];
+	u8         reserved_33[0xa];
+	u8         log_bf_reg_size[0x5];
+	u8         reserved_34[0x10];
+
+	u8         reserved_35[0x10];
+	u8         max_wqe_sz_sq[0x10];
+
+	u8         reserved_36[0x10];
+	u8         max_wqe_sz_rq[0x10];
+
+	u8         reserved_37[0x10];
+	u8         max_wqe_sz_sq_dc[0x10];
+
+	u8         reserved_38[0x7];
+	u8         max_qp_mcg[0x19];
+
+	u8         reserved_39[0x18];
+	u8         log_max_mcg[0x8];
+
+	u8         reserved_40[0xb];
+	u8         log_max_pd[0x5];
+	u8         reserved_41[0xb];
+	u8         log_max_xrcd[0x5];
+
+	u8         reserved_42[0x20];
+
+	u8         reserved_43[0x3];
+	u8         log_max_rq[0x5];
+	u8         reserved_44[0x3];
+	u8         log_max_sq[0x5];
+	u8         reserved_45[0x3];
+	u8         log_max_tir[0x5];
+	u8         reserved_46[0x3];
+	u8         log_max_tis[0x5];
+
+	u8         reserved_47[0x13];
+	u8         log_max_rq_per_tir[0x5];
+	u8         reserved_48[0x3];
+	u8         log_max_tis_per_sq[0x5];
+
+	u8         reserved_49[0xe0];
+
+	u8         reserved_50[0x10];
+	u8         log_uar_page_sz[0x10];
+
+	u8         reserved_51[0x100];
+
+	u8         reserved_52[0x1f];
+	u8         cqe_zip[0x1];
+
+	u8         cqe_zip_timeout[0x10];
+	u8         cqe_zip_max_num[0x10];
+
+	u8         reserved_53[0x220];
+};
+
+struct mlx5_ifc_set_hca_cap_in_bits {
+	u8         opcode[0x10];
+	u8         reserved_0[0x10];
+
+	u8         reserved_1[0x10];
+	u8         op_mod[0x10];
+
+	u8         reserved_2[0x40];
+
+	struct mlx5_ifc_cmd_hca_cap_bits hca_capability_struct;
+};
+
+struct mlx5_ifc_query_hca_cap_in_bits {
+	u8         opcode[0x10];
+	u8         reserved_0[0x10];
+
+	u8         reserved_1[0x10];
+	u8         op_mod[0x10];
+
+	u8         reserved_2[0x40];
+};
+
+struct mlx5_ifc_query_hca_cap_out_bits {
+	u8         status[0x8];
+	u8         reserved_0[0x18];
+
+	u8         syndrome[0x20];
+
+	u8         reserved_1[0x40];
+
+	u8         capability_struct[256][0x8];
+};
+
+struct mlx5_ifc_set_hca_cap_out_bits {
+	u8         status[0x8];
+	u8         reserved_0[0x18];
+
+	u8         syndrome[0x20];
+
+	u8         reserved_1[0x40];
+};
+
+#endif /* MLX5_IFC_H */
diff -urN linux/include/linux/mlx5/qp.h net-next-2.6/include/linux/mlx5/qp.h
--- linux/include/linux/mlx5/qp.h	2014-09-24 09:52:38.724597604 +0200
+++ net-next-2.6/include/linux/mlx5/qp.h	2014-10-06 10:48:54.632843402 +0200
@@ -342,10 +342,9 @@
 };
 
 struct mlx5_core_qp {
+	struct mlx5_core_rsc_common	common; /* must be first */
 	void (*event)		(struct mlx5_core_qp *, int);
 	int			qpn;
-	atomic_t		refcount;
-	struct completion	free;
 	struct mlx5_rsc_debug	*dbg;
 	int			pid;
 };
diff -urN linux/include/linux/netdevice.h net-next-2.6/include/linux/netdevice.h
--- linux/include/linux/netdevice.h	2014-09-24 09:52:38.772598108 +0200
+++ net-next-2.6/include/linux/netdevice.h	2014-10-06 10:48:54.656843648 +0200
@@ -543,7 +543,7 @@
  * read mostly part
  */
 	struct net_device	*dev;
-	struct Qdisc		*qdisc;
+	struct Qdisc __rcu	*qdisc;
 	struct Qdisc		*qdisc_sleeping;
 #ifdef CONFIG_SYSFS
 	struct kobject		kobj;
@@ -1747,6 +1747,12 @@
 	return &dev->_tx[index];
 }
 
+static inline struct netdev_queue *skb_get_tx_queue(const struct net_device *dev,
+						    const struct sk_buff *skb)
+{
+	return netdev_get_tx_queue(dev, skb_get_queue_mapping(skb));
+}
+
 static inline void netdev_for_each_tx_queue(struct net_device *dev,
 					    void (*f)(struct net_device *,
 						      struct netdev_queue *,
@@ -1781,24 +1787,13 @@
 #endif
 }
 
-static inline bool netdev_uses_dsa_tags(struct net_device *dev)
+static inline bool netdev_uses_dsa(struct net_device *dev)
 {
-#ifdef CONFIG_NET_DSA_TAG_DSA
-	if (dev->dsa_ptr != NULL)
-		return dsa_uses_dsa_tags(dev->dsa_ptr);
-#endif
-
-	return 0;
-}
-
-static inline bool netdev_uses_trailer_tags(struct net_device *dev)
-{
-#ifdef CONFIG_NET_DSA_TAG_TRAILER
+#if IS_ENABLED(CONFIG_NET_DSA)
 	if (dev->dsa_ptr != NULL)
-		return dsa_uses_trailer_tags(dev->dsa_ptr);
+		return dsa_uses_tagged_protocol(dev->dsa_ptr);
 #endif
-
-	return 0;
+	return false;
 }
 
 /**
@@ -1879,11 +1874,20 @@
 	/* jiffies when first packet was created/queued */
 	unsigned long age;
 
-	/* Used in ipv6_gro_receive() */
+	/* Used in ipv6_gro_receive() and foo-over-udp */
 	u16	proto;
 
 	/* Used in udp_gro_receive */
-	u16	udp_mark;
+	u8	udp_mark:1;
+
+	/* GRO checksum is valid */
+	u8	csum_valid:1;
+
+	/* Number of checksums via CHECKSUM_UNNECESSARY */
+	u8	csum_cnt:3;
+
+	/* Used in foo-over-udp, set in udp[46]_gro_receive */
+	u8	is_ipv6:1;
 
 	/* used to support CHECKSUM_COMPLETE for tunneling protocols */
 	__wsum	csum;
@@ -1910,7 +1914,6 @@
 struct offload_callbacks {
 	struct sk_buff		*(*gso_segment)(struct sk_buff *skb,
 						netdev_features_t features);
-	int			(*gso_send_check)(struct sk_buff *skb);
 	struct sk_buff		**(*gro_receive)(struct sk_buff **head,
 					       struct sk_buff *skb);
 	int			(*gro_complete)(struct sk_buff *skb, int nhoff);
@@ -1924,6 +1927,7 @@
 
 struct udp_offload {
 	__be16			 port;
+	u8			 ipproto;
 	struct offload_callbacks callbacks;
 };
 
@@ -1982,6 +1986,7 @@
 #define NETDEV_CHANGEUPPER	0x0015
 #define NETDEV_RESEND_IGMP	0x0016
 #define NETDEV_PRECHANGEMTU	0x0017 /* notify before mtu change happened */
+#define NETDEV_CHANGEINFODATA	0x0018
 
 int register_netdevice_notifier(struct notifier_block *nb);
 int unregister_netdevice_notifier(struct notifier_block *nb);
@@ -2074,8 +2079,8 @@
 void dev_add_offload(struct packet_offload *po);
 void dev_remove_offload(struct packet_offload *po);
 
-struct net_device *dev_get_by_flags_rcu(struct net *net, unsigned short flags,
-					unsigned short mask);
+struct net_device *__dev_get_by_flags(struct net *net, unsigned short flags,
+				      unsigned short mask);
 struct net_device *dev_get_by_name(struct net *net, const char *name);
 struct net_device *dev_get_by_name_rcu(struct net *net, const char *name);
 struct net_device *__dev_get_by_name(struct net *net, const char *name);
@@ -2153,11 +2158,97 @@
 static inline void skb_gro_postpull_rcsum(struct sk_buff *skb,
 					const void *start, unsigned int len)
 {
-	if (skb->ip_summed == CHECKSUM_COMPLETE)
+	if (NAPI_GRO_CB(skb)->csum_valid)
 		NAPI_GRO_CB(skb)->csum = csum_sub(NAPI_GRO_CB(skb)->csum,
 						  csum_partial(start, len, 0));
 }
 
+/* GRO checksum functions. These are logical equivalents of the normal
+ * checksum functions (in skbuff.h) except that they operate on the GRO
+ * offsets and fields in sk_buff.
+ */
+
+__sum16 __skb_gro_checksum_complete(struct sk_buff *skb);
+
+static inline bool __skb_gro_checksum_validate_needed(struct sk_buff *skb,
+						      bool zero_okay,
+						      __sum16 check)
+{
+	return (skb->ip_summed != CHECKSUM_PARTIAL &&
+		NAPI_GRO_CB(skb)->csum_cnt == 0 &&
+		(!zero_okay || check));
+}
+
+static inline __sum16 __skb_gro_checksum_validate_complete(struct sk_buff *skb,
+							   __wsum psum)
+{
+	if (NAPI_GRO_CB(skb)->csum_valid &&
+	    !csum_fold(csum_add(psum, NAPI_GRO_CB(skb)->csum)))
+		return 0;
+
+	NAPI_GRO_CB(skb)->csum = psum;
+
+	return __skb_gro_checksum_complete(skb);
+}
+
+static inline void skb_gro_incr_csum_unnecessary(struct sk_buff *skb)
+{
+	if (NAPI_GRO_CB(skb)->csum_cnt > 0) {
+		/* Consume a checksum from CHECKSUM_UNNECESSARY */
+		NAPI_GRO_CB(skb)->csum_cnt--;
+	} else {
+		/* Update skb for CHECKSUM_UNNECESSARY and csum_level when we
+		 * verified a new top level checksum or an encapsulated one
+		 * during GRO. This saves work if we fallback to normal path.
+		 */
+		__skb_incr_checksum_unnecessary(skb);
+	}
+}
+
+#define __skb_gro_checksum_validate(skb, proto, zero_okay, check,	\
+				    compute_pseudo)			\
+({									\
+	__sum16 __ret = 0;						\
+	if (__skb_gro_checksum_validate_needed(skb, zero_okay, check))	\
+		__ret = __skb_gro_checksum_validate_complete(skb,	\
+				compute_pseudo(skb, proto));		\
+	if (__ret)							\
+		__skb_mark_checksum_bad(skb);				\
+	else								\
+		skb_gro_incr_csum_unnecessary(skb);			\
+	__ret;								\
+})
+
+#define skb_gro_checksum_validate(skb, proto, compute_pseudo)		\
+	__skb_gro_checksum_validate(skb, proto, false, 0, compute_pseudo)
+
+#define skb_gro_checksum_validate_zero_check(skb, proto, check,		\
+					     compute_pseudo)		\
+	__skb_gro_checksum_validate(skb, proto, true, check, compute_pseudo)
+
+#define skb_gro_checksum_simple_validate(skb)				\
+	__skb_gro_checksum_validate(skb, 0, false, 0, null_compute_pseudo)
+
+static inline bool __skb_gro_checksum_convert_check(struct sk_buff *skb)
+{
+	return (NAPI_GRO_CB(skb)->csum_cnt == 0 &&
+		!NAPI_GRO_CB(skb)->csum_valid);
+}
+
+static inline void __skb_gro_checksum_convert(struct sk_buff *skb,
+					      __sum16 check, __wsum pseudo)
+{
+	NAPI_GRO_CB(skb)->csum = ~pseudo;
+	NAPI_GRO_CB(skb)->csum_valid = 1;
+}
+
+#define skb_gro_checksum_try_convert(skb, proto, check, compute_pseudo)	\
+do {									\
+	if (__skb_gro_checksum_convert_check(skb))			\
+		__skb_gro_checksum_convert(skb, check,			\
+					   compute_pseudo(skb, proto));	\
+} while (0)
+
 static inline int dev_hard_header(struct sk_buff *skb, struct net_device *dev,
 				  unsigned short type,
 				  const void *daddr, const void *saddr,
@@ -2261,12 +2352,7 @@
 DECLARE_PER_CPU_ALIGNED(struct softnet_data, softnet_data);
 
 void __netif_schedule(struct Qdisc *q);
-
-static inline void netif_schedule_queue(struct netdev_queue *txq)
-{
-	if (!(txq->state & QUEUE_STATE_ANY_XOFF))
-		__netif_schedule(txq->qdisc);
-}
+void netif_schedule_queue(struct netdev_queue *txq);
 
 static inline void netif_tx_schedule_all(struct net_device *dev)
 {
@@ -2302,11 +2388,7 @@
 	}
 }
 
-static inline void netif_tx_wake_queue(struct netdev_queue *dev_queue)
-{
-	if (test_and_clear_bit(__QUEUE_STATE_DRV_XOFF, &dev_queue->state))
-		__netif_schedule(dev_queue->qdisc);
-}
+void netif_tx_wake_queue(struct netdev_queue *dev_queue);
 
 /**
  *	netif_wake_queue - restart transmit
@@ -2578,19 +2660,7 @@
 	return __netif_subqueue_stopped(dev, skb_get_queue_mapping(skb));
 }
 
-/**
- *	netif_wake_subqueue - allow sending packets on subqueue
- *	@dev: network device
- *	@queue_index: sub queue index
- *
- * Resume individual transmit queue of a device with multiple transmit queues.
- */
-static inline void netif_wake_subqueue(struct net_device *dev, u16 queue_index)
-{
-	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);
-	if (test_and_clear_bit(__QUEUE_STATE_DRV_XOFF, &txq->state))
-		__netif_schedule(txq->qdisc);
-}
+void netif_wake_subqueue(struct net_device *dev, u16 queue_index);
 
 #ifdef CONFIG_XPS
 int netif_set_xps_queue(struct net_device *dev, const struct cpumask *mask,
@@ -2754,8 +2824,9 @@
 int dev_change_carrier(struct net_device *, bool new_carrier);
 int dev_get_phys_port_id(struct net_device *dev,
 			 struct netdev_phys_port_id *ppid);
-int dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev,
-			struct netdev_queue *txq);
+struct sk_buff *validate_xmit_skb_list(struct sk_buff *skb, struct net_device *dev);
+struct sk_buff *dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev,
+				    struct netdev_queue *txq, int *ret);
 int __dev_forward_skb(struct net_device *dev, struct sk_buff *skb);
 int dev_forward_skb(struct net_device *dev, struct sk_buff *skb);
 bool is_skb_forwardable(struct net_device *dev, struct sk_buff *skb);
@@ -3357,6 +3428,27 @@
 #define dev_proc_init() 0
 #endif
 
+static inline netdev_tx_t __netdev_start_xmit(const struct net_device_ops *ops,
+					      struct sk_buff *skb, struct net_device *dev,
+					      bool more)
+{
+	skb->xmit_more = more ? 1 : 0;
+	return ops->ndo_start_xmit(skb, dev);
+}
+
+static inline netdev_tx_t netdev_start_xmit(struct sk_buff *skb, struct net_device *dev,
+					    struct netdev_queue *txq, bool more)
+{
+	const struct net_device_ops *ops = dev->netdev_ops;
+	int rc;
+
+	rc = __netdev_start_xmit(ops, skb, dev, more);
+	if (rc == NETDEV_TX_OK)
+		txq_trans_update(txq);
+
+	return rc;
+}
+
 int netdev_class_create_file_ns(struct class_attribute *class_attr,
 				const void *ns);
 void netdev_class_remove_file_ns(struct class_attribute *class_attr,
@@ -3523,22 +3615,22 @@
 }
 
 __printf(3, 4)
-int netdev_printk(const char *level, const struct net_device *dev,
-		  const char *format, ...);
+void netdev_printk(const char *level, const struct net_device *dev,
+		   const char *format, ...);
 __printf(2, 3)
-int netdev_emerg(const struct net_device *dev, const char *format, ...);
+void netdev_emerg(const struct net_device *dev, const char *format, ...);
 __printf(2, 3)
-int netdev_alert(const struct net_device *dev, const char *format, ...);
+void netdev_alert(const struct net_device *dev, const char *format, ...);
 __printf(2, 3)
-int netdev_crit(const struct net_device *dev, const char *format, ...);
+void netdev_crit(const struct net_device *dev, const char *format, ...);
 __printf(2, 3)
-int netdev_err(const struct net_device *dev, const char *format, ...);
+void netdev_err(const struct net_device *dev, const char *format, ...);
 __printf(2, 3)
-int netdev_warn(const struct net_device *dev, const char *format, ...);
+void netdev_warn(const struct net_device *dev, const char *format, ...);
 __printf(2, 3)
-int netdev_notice(const struct net_device *dev, const char *format, ...);
+void netdev_notice(const struct net_device *dev, const char *format, ...);
 __printf(2, 3)
-int netdev_info(const struct net_device *dev, const char *format, ...);
+void netdev_info(const struct net_device *dev, const char *format, ...);
 
 #define MODULE_ALIAS_NETDEV(device) \
 	MODULE_ALIAS("netdev-" device)
@@ -3556,7 +3648,6 @@
 ({								\
 	if (0)							\
 		netdev_printk(KERN_DEBUG, __dev, format, ##args); \
-	0;							\
 })
 #endif
 
diff -urN linux/include/linux/netfilter/ipset/ip_set.h net-next-2.6/include/linux/netfilter/ipset/ip_set.h
--- linux/include/linux/netfilter/ipset/ip_set.h	2014-09-24 09:52:38.792598318 +0200
+++ net-next-2.6/include/linux/netfilter/ipset/ip_set.h	2014-10-06 10:48:54.656843648 +0200
@@ -57,6 +57,8 @@
 	IPSET_EXT_COUNTER = (1 << IPSET_EXT_BIT_COUNTER),
 	IPSET_EXT_BIT_COMMENT = 2,
 	IPSET_EXT_COMMENT = (1 << IPSET_EXT_BIT_COMMENT),
+	IPSET_EXT_BIT_SKBINFO = 3,
+	IPSET_EXT_SKBINFO = (1 << IPSET_EXT_BIT_SKBINFO),
 	/* Mark set with an extension which needs to call destroy */
 	IPSET_EXT_BIT_DESTROY = 7,
 	IPSET_EXT_DESTROY = (1 << IPSET_EXT_BIT_DESTROY),
@@ -65,12 +67,14 @@
 #define SET_WITH_TIMEOUT(s)	((s)->extensions & IPSET_EXT_TIMEOUT)
 #define SET_WITH_COUNTER(s)	((s)->extensions & IPSET_EXT_COUNTER)
 #define SET_WITH_COMMENT(s)	((s)->extensions & IPSET_EXT_COMMENT)
+#define SET_WITH_SKBINFO(s)	((s)->extensions & IPSET_EXT_SKBINFO)
 #define SET_WITH_FORCEADD(s)	((s)->flags & IPSET_CREATE_FLAG_FORCEADD)
 
 /* Extension id, in size order */
 enum ip_set_ext_id {
 	IPSET_EXT_ID_COUNTER = 0,
 	IPSET_EXT_ID_TIMEOUT,
+	IPSET_EXT_ID_SKBINFO,
 	IPSET_EXT_ID_COMMENT,
 	IPSET_EXT_ID_MAX,
 };
@@ -92,6 +96,10 @@
 	u64 packets;
 	u64 bytes;
 	u32 timeout;
+	u32 skbmark;
+	u32 skbmarkmask;
+	u32 skbprio;
+	u16 skbqueue;
 	char *comment;
 };
 
@@ -104,6 +112,13 @@
 	char *str;
 };
 
+struct ip_set_skbinfo {
+	u32 skbmark;
+	u32 skbmarkmask;
+	u32 skbprio;
+	u16 skbqueue;
+};
+
 struct ip_set;
 
 #define ext_timeout(e, s)	\
@@ -112,7 +127,8 @@
 (struct ip_set_counter *)(((void *)(e)) + (s)->offset[IPSET_EXT_ID_COUNTER])
 #define ext_comment(e, s)	\
 (struct ip_set_comment *)(((void *)(e)) + (s)->offset[IPSET_EXT_ID_COMMENT])
-
+#define ext_skbinfo(e, s)	\
+(struct ip_set_skbinfo *)(((void *)(e)) + (s)->offset[IPSET_EXT_ID_SKBINFO])
 
 typedef int (*ipset_adtfn)(struct ip_set *set, void *value,
 			   const struct ip_set_ext *ext,
@@ -256,6 +272,8 @@
 		cadt_flags |= IPSET_FLAG_WITH_COUNTERS;
 	if (SET_WITH_COMMENT(set))
 		cadt_flags |= IPSET_FLAG_WITH_COMMENT;
+	if (SET_WITH_SKBINFO(set))
+		cadt_flags |= IPSET_FLAG_WITH_SKBINFO;
 	if (SET_WITH_FORCEADD(set))
 		cadt_flags |= IPSET_FLAG_WITH_FORCEADD;
 
@@ -304,6 +322,43 @@
 	}
 }
 
+static inline void
+ip_set_get_skbinfo(struct ip_set_skbinfo *skbinfo,
+		      const struct ip_set_ext *ext,
+		      struct ip_set_ext *mext, u32 flags)
+{
+		mext->skbmark = skbinfo->skbmark;
+		mext->skbmarkmask = skbinfo->skbmarkmask;
+		mext->skbprio = skbinfo->skbprio;
+		mext->skbqueue = skbinfo->skbqueue;
+}
+static inline bool
+ip_set_put_skbinfo(struct sk_buff *skb, struct ip_set_skbinfo *skbinfo)
+{
+	/* Send nonzero parameters only */
+	return ((skbinfo->skbmark || skbinfo->skbmarkmask) &&
+		nla_put_net64(skb, IPSET_ATTR_SKBMARK,
+			      cpu_to_be64((u64)skbinfo->skbmark << 32 |
+					  skbinfo->skbmarkmask))) ||
+	       (skbinfo->skbprio &&
+	        nla_put_net32(skb, IPSET_ATTR_SKBPRIO,
+			      cpu_to_be32(skbinfo->skbprio))) ||
+	       (skbinfo->skbqueue &&
+	        nla_put_net16(skb, IPSET_ATTR_SKBQUEUE,
+			     cpu_to_be16(skbinfo->skbqueue)));
+
+}
+
+static inline void
+ip_set_init_skbinfo(struct ip_set_skbinfo *skbinfo,
+		    const struct ip_set_ext *ext)
+{
+	skbinfo->skbmark = ext->skbmark;
+	skbinfo->skbmarkmask = ext->skbmarkmask;
+	skbinfo->skbprio = ext->skbprio;
+	skbinfo->skbqueue = ext->skbqueue;
+}
+
 static inline bool
 ip_set_put_counter(struct sk_buff *skb, struct ip_set_counter *counter)
 {
@@ -497,6 +552,9 @@
 	if (SET_WITH_COMMENT(set) &&
 	    ip_set_put_comment(skb, ext_comment(e, set)))
 		return -EMSGSIZE;
+	if (SET_WITH_SKBINFO(set) &&
+	    ip_set_put_skbinfo(skb, ext_skbinfo(e, set)))
+		return -EMSGSIZE;
 	return 0;
 }
 
diff -urN linux/include/linux/netfilter/ipset/ip_set_list.h net-next-2.6/include/linux/netfilter/ipset/ip_set_list.h
--- linux/include/linux/netfilter/ipset/ip_set_list.h	2013-05-02 09:43:16.789515184 +0200
+++ net-next-2.6/include/linux/netfilter/ipset/ip_set_list.h	2014-10-06 10:48:54.656843648 +0200
@@ -6,5 +6,6 @@
 
 #define IP_SET_LIST_DEFAULT_SIZE	8
 #define IP_SET_LIST_MIN_SIZE		4
+#define IP_SET_LIST_MAX_SIZE		65536
 
 #endif /* __IP_SET_LIST_H */
diff -urN linux/include/linux/netfilter_bridge.h net-next-2.6/include/linux/netfilter_bridge.h
--- linux/include/linux/netfilter_bridge.h	2013-11-29 12:59:35.771359790 +0100
+++ net-next-2.6/include/linux/netfilter_bridge.h	2014-10-06 10:48:54.656843648 +0200
@@ -15,7 +15,7 @@
 	NF_BR_PRI_LAST = INT_MAX,
 };
 
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 
 #define BRNF_PKT_TYPE			0x01
 #define BRNF_BRIDGED_DNAT		0x02
@@ -24,16 +24,6 @@
 #define BRNF_8021Q			0x10
 #define BRNF_PPPoE			0x20
 
-/* Only used in br_forward.c */
-int nf_bridge_copy_header(struct sk_buff *skb);
-static inline int nf_bridge_maybe_copy_header(struct sk_buff *skb)
-{
-	if (skb->nf_bridge &&
-	    skb->nf_bridge->mask & (BRNF_BRIDGED | BRNF_BRIDGED_DNAT))
-		return nf_bridge_copy_header(skb);
-  	return 0;
-}
-
 static inline unsigned int nf_bridge_encap_header_len(const struct sk_buff *skb)
 {
 	switch (skb->protocol) {
@@ -46,6 +36,44 @@
 	}
 }
 
+static inline void nf_bridge_update_protocol(struct sk_buff *skb)
+{
+	if (skb->nf_bridge->mask & BRNF_8021Q)
+		skb->protocol = htons(ETH_P_8021Q);
+	else if (skb->nf_bridge->mask & BRNF_PPPoE)
+		skb->protocol = htons(ETH_P_PPP_SES);
+}
+
+/* Fill in the header for fragmented IP packets handled by
+ * the IPv4 connection tracking code.
+ *
+ * Only used in br_forward.c
+ */
+static inline int nf_bridge_copy_header(struct sk_buff *skb)
+{
+	int err;
+	unsigned int header_size;
+
+	nf_bridge_update_protocol(skb);
+	header_size = ETH_HLEN + nf_bridge_encap_header_len(skb);
+	err = skb_cow_head(skb, header_size);
+	if (err)
+		return err;
+
+	skb_copy_to_linear_data_offset(skb, -header_size,
+				       skb->nf_bridge->data, header_size);
+	__skb_push(skb, nf_bridge_encap_header_len(skb));
+	return 0;
+}
+
+static inline int nf_bridge_maybe_copy_header(struct sk_buff *skb)
+{
+	if (skb->nf_bridge &&
+	    skb->nf_bridge->mask & (BRNF_BRIDGED | BRNF_BRIDGED_DNAT))
+		return nf_bridge_copy_header(skb);
+  	return 0;
+}
+
 static inline unsigned int nf_bridge_mtu_reduction(const struct sk_buff *skb)
 {
 	if (unlikely(skb->nf_bridge->mask & BRNF_PPPoE))
diff -urN linux/include/linux/phonedev.h net-next-2.6/include/linux/phonedev.h
--- linux/include/linux/phonedev.h	2011-07-22 09:59:44.044010728 +0200
+++ net-next-2.6/include/linux/phonedev.h	1970-01-01 01:00:00.000000000 +0100
@@ -1,25 +0,0 @@
-#ifndef __LINUX_PHONEDEV_H
-#define __LINUX_PHONEDEV_H
-
-#include <linux/types.h>
-
-#ifdef __KERNEL__
-
-#include <linux/poll.h>
-
-struct phone_device {
-	struct phone_device *next;
-	const struct file_operations *f_op;
-	int (*open) (struct phone_device *, struct file *);
-	int board;		/* Device private index */
-	int minor;
-};
-
-extern int phonedev_init(void);
-#define PHONE_MAJOR	100
-extern int phone_register_device(struct phone_device *, int unit);
-#define PHONE_UNIT_ANY	-1
-extern void phone_unregister_device(struct phone_device *);
-
-#endif
-#endif
diff -urN linux/include/linux/phy_fixed.h net-next-2.6/include/linux/phy_fixed.h
--- linux/include/linux/phy_fixed.h	2014-09-24 09:52:38.800598401 +0200
+++ net-next-2.6/include/linux/phy_fixed.h	2014-10-06 10:48:54.684843933 +0200
@@ -18,6 +18,9 @@
 			      struct fixed_phy_status *status,
 			      struct device_node *np);
 extern void fixed_phy_del(int phy_addr);
+extern int fixed_phy_set_link_update(struct phy_device *phydev,
+			int (*link_update)(struct net_device *,
+					   struct fixed_phy_status *));
 #else
 static inline int fixed_phy_add(unsigned int irq, int phy_id,
 				struct fixed_phy_status *status)
@@ -34,14 +37,12 @@
 {
 	return -ENODEV;
 }
-#endif /* CONFIG_FIXED_PHY */
-
-/*
- * This function issued only by fixed_phy-aware drivers, no need
- * protect it with #ifdef
- */
-extern int fixed_phy_set_link_update(struct phy_device *phydev,
+static inline int fixed_phy_set_link_update(struct phy_device *phydev,
 			int (*link_update)(struct net_device *,
-					   struct fixed_phy_status *));
+					   struct fixed_phy_status *))
+{
+	return -ENODEV;
+}
+#endif /* CONFIG_FIXED_PHY */
 
 #endif /* __PHY_FIXED_H */
diff -urN linux/include/linux/phy.h net-next-2.6/include/linux/phy.h
--- linux/include/linux/phy.h	2014-09-24 09:52:38.800598401 +0200
+++ net-next-2.6/include/linux/phy.h	2014-10-06 10:48:54.684843933 +0200
@@ -598,6 +598,19 @@
 }
 
 /**
+ * phy_read_mmd_indirect - reads data from the MMD registers
+ * @phydev: The PHY device bus
+ * @prtad: MMD Address
+ * @devad: MMD DEVAD
+ * @addr: PHY address on the MII bus
+ *
+ * Description: it reads data from the MMD registers (clause 22 to access to
+ * clause 45) of the specified phy address.
+ */
+int phy_read_mmd_indirect(struct phy_device *phydev, int prtad,
+			  int devad, int addr);
+
+/**
  * phy_read - Convenience function for reading a given PHY register
  * @phydev: the phy_device struct
  * @regnum: register number to read
@@ -668,6 +681,20 @@
 	return mdiobus_write(phydev->bus, phydev->addr, regnum, val);
 }
 
+/**
+ * phy_write_mmd_indirect - writes data to the MMD registers
+ * @phydev: The PHY device
+ * @prtad: MMD Address
+ * @devad: MMD DEVAD
+ * @addr: PHY address on the MII bus
+ * @data: data to write in the MMD register
+ *
+ * Description: Write data from the MMD registers of the specified
+ * phy address.
+ */
+void phy_write_mmd_indirect(struct phy_device *phydev, int prtad,
+			    int devad, int addr, u32 data);
+
 struct phy_device *phy_device_create(struct mii_bus *bus, int addr, int phy_id,
 				     bool is_c45,
 				     struct phy_c45_device_ids *c45_ids);
diff -urN linux/include/linux/random.h net-next-2.6/include/linux/random.h
--- linux/include/linux/random.h	2014-09-24 09:52:38.868599115 +0200
+++ net-next-2.6/include/linux/random.h	2014-10-06 10:48:54.812845238 +0200
@@ -26,7 +26,7 @@
 unsigned long randomize_range(unsigned long start, unsigned long end, unsigned long len);
 
 u32 prandom_u32(void);
-void prandom_bytes(void *buf, int nbytes);
+void prandom_bytes(void *buf, size_t nbytes);
 void prandom_seed(u32 seed);
 void prandom_reseed_late(void);
 
@@ -35,7 +35,7 @@
 };
 
 u32 prandom_u32_state(struct rnd_state *state);
-void prandom_bytes_state(struct rnd_state *state, void *buf, int nbytes);
+void prandom_bytes_state(struct rnd_state *state, void *buf, size_t nbytes);
 
 /**
  * prandom_u32_max - returns a pseudo-random number in interval [0, ep_ro)
diff -urN linux/include/linux/rhashtable.h net-next-2.6/include/linux/rhashtable.h
--- linux/include/linux/rhashtable.h	2014-09-24 09:52:38.872599157 +0200
+++ net-next-2.6/include/linux/rhashtable.h	2014-10-06 10:48:54.816845278 +0200
@@ -44,6 +44,7 @@
  * @head_offset: Offset of rhash_head in struct to be hashed
  * @hash_rnd: Seed to use while hashing
  * @max_shift: Maximum number of shifts while expanding
+ * @min_shift: Minimum number of shifts while shrinking
  * @hashfn: Function to hash key
  * @obj_hashfn: Function to hash object
  * @grow_decision: If defined, may return true if table should expand
@@ -57,6 +58,7 @@
 	size_t			head_offset;
 	u32			hash_rnd;
 	size_t			max_shift;
+	size_t			min_shift;
 	rht_hashfn_t		hashfn;
 	rht_obj_hashfn_t	obj_hashfn;
 	bool			(*grow_decision)(const struct rhashtable *ht,
diff -urN linux/include/linux/rtnetlink.h net-next-2.6/include/linux/rtnetlink.h
--- linux/include/linux/rtnetlink.h	2014-09-24 09:52:38.872599157 +0200
+++ net-next-2.6/include/linux/rtnetlink.h	2014-10-06 10:48:54.816845278 +0200
@@ -47,6 +47,16 @@
 	rcu_dereference_check(p, lockdep_rtnl_is_held())
 
 /**
+ * rcu_dereference_bh_rtnl - rcu_dereference_bh with debug checking
+ * @p: The pointer to read, prior to dereference
+ *
+ * Do an rcu_dereference_bh(p), but check caller either holds rcu_read_lock_bh()
+ * or RTNL. Note : Please prefer rtnl_dereference() or rcu_dereference_bh()
+ */
+#define rcu_dereference_bh_rtnl(p)				\
+	rcu_dereference_bh_check(p, lockdep_rtnl_is_held())
+
+/**
  * rtnl_dereference - fetch RCU pointer when updates are prevented by RTNL
  * @p: The pointer to read, prior to dereferencing
  *
diff -urN linux/include/linux/skbuff.h net-next-2.6/include/linux/skbuff.h
--- linux/include/linux/skbuff.h	2014-09-24 09:52:38.880599242 +0200
+++ net-next-2.6/include/linux/skbuff.h	2014-10-06 10:48:54.820845318 +0200
@@ -47,11 +47,29 @@
  *
  *   The hardware you're dealing with doesn't calculate the full checksum
  *   (as in CHECKSUM_COMPLETE), but it does parse headers and verify checksums
- *   for specific protocols e.g. TCP/UDP/SCTP, then, for such packets it will
- *   set CHECKSUM_UNNECESSARY if their checksums are okay. skb->csum is still
- *   undefined in this case though. It is a bad option, but, unfortunately,
- *   nowadays most vendors do this. Apparently with the secret goal to sell
- *   you new devices, when you will add new protocol to your host, f.e. IPv6 8)
+ *   for specific protocols. For such packets it will set CHECKSUM_UNNECESSARY
+ *   if their checksums are okay. skb->csum is still undefined in this case
+ *   though. It is a bad option, but, unfortunately, nowadays most vendors do
+ *   this. Apparently with the secret goal to sell you new devices, when you
+ *   will add new protocol to your host, f.e. IPv6 8)
+ *
+ *   CHECKSUM_UNNECESSARY is applicable to following protocols:
+ *     TCP: IPv6 and IPv4.
+ *     UDP: IPv4 and IPv6. A device may apply CHECKSUM_UNNECESSARY to a
+ *       zero UDP checksum for either IPv4 or IPv6, the networking stack
+ *       may perform further validation in this case.
+ *     GRE: only if the checksum is present in the header.
+ *     SCTP: indicates the CRC in SCTP header has been validated.
+ *
+ *   skb->csum_level indicates the number of consecutive checksums found in
+ *   the packet minus one that have been verified as CHECKSUM_UNNECESSARY.
+ *   For instance if a device receives an IPv6->UDP->GRE->IPv4->TCP packet
+ *   and a device is able to verify the checksums for UDP (possibly zero),
+ *   GRE (checksum flag is set), and TCP-- skb->csum_level would be set to
+ *   two. If the device were only able to verify the UDP checksum and not
+ *   GRE, either because it doesn't support GRE checksum of because GRE
+ *   checksum is bad, skb->csum_level would be set to zero (TCP checksum is
+ *   not considered in this case).
  *
  * CHECKSUM_COMPLETE:
  *
@@ -112,6 +130,9 @@
 #define CHECKSUM_COMPLETE	2
 #define CHECKSUM_PARTIAL	3
 
+/* Maximum value in skb->csum_level */
+#define SKB_MAX_CSUM_LEVEL	3
+
 #define SKB_DATA_ALIGN(X)	ALIGN(X, SMP_CACHE_BYTES)
 #define SKB_WITH_OVERHEAD(X)	\
 	((X) - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
@@ -135,7 +156,7 @@
 };
 #endif
 
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 struct nf_bridge_info {
 	atomic_t		use;
 	unsigned int		mask;
@@ -318,9 +339,10 @@
 
 
 enum {
-	SKB_FCLONE_UNAVAILABLE,
-	SKB_FCLONE_ORIG,
-	SKB_FCLONE_CLONE,
+	SKB_FCLONE_UNAVAILABLE,	/* skb has no fclone (from head_cache) */
+	SKB_FCLONE_ORIG,	/* orig skb (from fclone_cache) */
+	SKB_FCLONE_CLONE,	/* companion fclone skb (from fclone_cache) */
+	SKB_FCLONE_FREE,	/* this companion fclone skb is available */
 };
 
 enum {
@@ -452,6 +474,7 @@
  *	@tc_verd: traffic control verdict
  *	@hash: the packet hash
  *	@queue_mapping: Queue mapping for multiqueue devices
+ *	@xmit_more: More SKBs are pending for this queue
  *	@ndisc_nodetype: router type (from link layer)
  *	@ooo_okay: allow the mapping of a socket to a queue to be changed
  *	@l4_hash: indicate hash is a canonical 4-tuple hash over transport
@@ -505,82 +528,97 @@
 	char			cb[48] __aligned(8);
 
 	unsigned long		_skb_refdst;
+	void			(*destructor)(struct sk_buff *skb);
 #ifdef CONFIG_XFRM
 	struct	sec_path	*sp;
 #endif
+#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
+	struct nf_conntrack	*nfct;
+#endif
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
+	struct nf_bridge_info	*nf_bridge;
+#endif
 	unsigned int		len,
 				data_len;
 	__u16			mac_len,
 				hdr_len;
-	union {
-		__wsum		csum;
-		struct {
-			__u16	csum_start;
-			__u16	csum_offset;
-		};
-	};
-	__u32			priority;
+
+	/* Following fields are _not_ copied in __copy_skb_header()
+	 * Note that queue_mapping is here mostly to fill a hole.
+	 */
 	kmemcheck_bitfield_begin(flags1);
-	__u8			ignore_df:1,
-				cloned:1,
-				ip_summed:2,
+	__u16			queue_mapping;
+	__u8			cloned:1,
 				nohdr:1,
-				nfctinfo:3;
-	__u8			pkt_type:3,
 				fclone:2,
-				ipvs_property:1,
 				peeked:1,
-				nf_trace:1;
+				head_frag:1,
+				xmit_more:1;
+	/* one bit hole */
 	kmemcheck_bitfield_end(flags1);
-	__be16			protocol;
-
-	void			(*destructor)(struct sk_buff *skb);
-#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
-	struct nf_conntrack	*nfct;
-#endif
-#ifdef CONFIG_BRIDGE_NETFILTER
-	struct nf_bridge_info	*nf_bridge;
-#endif
-
-	int			skb_iif;
-
-	__u32			hash;
 
-	__be16			vlan_proto;
-	__u16			vlan_tci;
+	/* fields enclosed in headers_start/headers_end are copied
+	 * using a single memcpy() in __copy_skb_header()
+	 */
+	__u32			headers_start[0];
 
-#ifdef CONFIG_NET_SCHED
-	__u16			tc_index;	/* traffic control index */
-#ifdef CONFIG_NET_CLS_ACT
-	__u16			tc_verd;	/* traffic control verdict */
-#endif
+/* if you move pkt_type around you also must adapt those constants */
+#ifdef __BIG_ENDIAN_BITFIELD
+#define PKT_TYPE_MAX	(7 << 5)
+#else
+#define PKT_TYPE_MAX	7
 #endif
+#define PKT_TYPE_OFFSET()	offsetof(struct sk_buff, __pkt_type_offset)
 
-	__u16			queue_mapping;
-	kmemcheck_bitfield_begin(flags2);
-#ifdef CONFIG_IPV6_NDISC_NODETYPE
-	__u8			ndisc_nodetype:2;
-#endif
+	__u8			__pkt_type_offset[0];
+	__u8			pkt_type:3;
 	__u8			pfmemalloc:1;
+	__u8			ignore_df:1;
+	__u8			nfctinfo:3;
+
+	__u8			nf_trace:1;
+	__u8			ip_summed:2;
 	__u8			ooo_okay:1;
 	__u8			l4_hash:1;
 	__u8			sw_hash:1;
 	__u8			wifi_acked_valid:1;
 	__u8			wifi_acked:1;
+
 	__u8			no_fcs:1;
-	__u8			head_frag:1;
-	/* Encapsulation protocol and NIC drivers should use
-	 * this flag to indicate to each other if the skb contains
-	 * encapsulated packet or not and maybe use the inner packet
-	 * headers if needed
-	 */
+	/* Indicates the inner headers are valid in the skbuff. */
 	__u8			encapsulation:1;
 	__u8			encap_hdr_csum:1;
 	__u8			csum_valid:1;
 	__u8			csum_complete_sw:1;
-	/* 2/4 bit hole (depending on ndisc_nodetype presence) */
-	kmemcheck_bitfield_end(flags2);
+	__u8			csum_level:2;
+	__u8			csum_bad:1;
+
+#ifdef CONFIG_IPV6_NDISC_NODETYPE
+	__u8			ndisc_nodetype:2;
+#endif
+	__u8			ipvs_property:1;
+	__u8			inner_protocol_type:1;
+	/* 4 or 6 bit hole */
 
+#ifdef CONFIG_NET_SCHED
+	__u16			tc_index;	/* traffic control index */
+#ifdef CONFIG_NET_CLS_ACT
+	__u16			tc_verd;	/* traffic control verdict */
+#endif
+#endif
+
+	union {
+		__wsum		csum;
+		struct {
+			__u16	csum_start;
+			__u16	csum_offset;
+		};
+	};
+	__u32			priority;
+	int			skb_iif;
+	__u32			hash;
+	__be16			vlan_proto;
+	__u16			vlan_tci;
 #if defined CONFIG_NET_DMA || defined CONFIG_NET_RX_BUSY_POLL
 	union {
 		unsigned int	napi_id;
@@ -596,13 +634,22 @@
 		__u32		reserved_tailroom;
 	};
 
-	__be16			inner_protocol;
+	union {
+		__be16		inner_protocol;
+		__u8		inner_ipproto;
+	};
+
 	__u16			inner_transport_header;
 	__u16			inner_network_header;
 	__u16			inner_mac_header;
+
+	__be16			protocol;
 	__u16			transport_header;
 	__u16			network_header;
 	__u16			mac_header;
+
+	__u32			headers_end[0];
+
 	/* These elements must be at the end, see alloc_skb() for details.  */
 	sk_buff_data_t		tail;
 	sk_buff_data_t		end;
@@ -734,6 +781,37 @@
 	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
 }
 
+struct sk_buff *alloc_skb_with_frags(unsigned long header_len,
+				     unsigned long data_len,
+				     int max_page_order,
+				     int *errcode,
+				     gfp_t gfp_mask);
+
+/* Layout of fast clones : [skb1][skb2][fclone_ref] */
+struct sk_buff_fclones {
+	struct sk_buff	skb1;
+
+	struct sk_buff	skb2;
+
+	atomic_t	fclone_ref;
+};
+
+/**
+ *	skb_fclone_busy - check if fclone is busy
+ *	@skb: buffer
+ *
+ * Returns true is skb is a fast clone, and its clone is not freed.
+ */
+static inline bool skb_fclone_busy(const struct sk_buff *skb)
+{
+	const struct sk_buff_fclones *fclones;
+
+	fclones = container_of(skb, struct sk_buff_fclones, skb1);
+
+	return skb->fclone == SKB_FCLONE_ORIG &&
+	       fclones->skb2.fclone == SKB_FCLONE_CLONE;
+}
+
 static inline struct sk_buff *alloc_skb_fclone(unsigned int size,
 					       gfp_t priority)
 {
@@ -1042,6 +1120,7 @@
  *	Drop a reference to the header part of the buffer.  This is done
  *	by acquiring a payload reference.  You must not read from the header
  *	part of skb->data after this.
+ *	Note : Check if you can use __skb_header_release() instead.
  */
 static inline void skb_header_release(struct sk_buff *skb)
 {
@@ -1051,6 +1130,20 @@
 }
 
 /**
+ *	__skb_header_release - release reference to header
+ *	@skb: buffer to operate on
+ *
+ *	Variant of skb_header_release() assuming skb is private to caller.
+ *	We can avoid one atomic operation.
+ */
+static inline void __skb_header_release(struct sk_buff *skb)
+{
+	skb->nohdr = 1;
+	atomic_set(&skb_shinfo(skb)->dataref, 1 + (1 << SKB_DATAREF_SHIFT));
+}
+
+
+/**
  *	skb_shared - is the buffer shared
  *	@skb: buffer to check
  *
@@ -1675,6 +1768,23 @@
 	skb->tail += len;
 }
 
+#define ENCAP_TYPE_ETHER	0
+#define ENCAP_TYPE_IPPROTO	1
+
+static inline void skb_set_inner_protocol(struct sk_buff *skb,
+					  __be16 protocol)
+{
+	skb->inner_protocol = protocol;
+	skb->inner_protocol_type = ENCAP_TYPE_ETHER;
+}
+
+static inline void skb_set_inner_ipproto(struct sk_buff *skb,
+					 __u8 ipproto)
+{
+	skb->inner_ipproto = ipproto;
+	skb->inner_protocol_type = ENCAP_TYPE_IPPROTO;
+}
+
 static inline void skb_reset_inner_headers(struct sk_buff *skb)
 {
 	skb->inner_mac_header = skb->mac_header;
@@ -1860,18 +1970,6 @@
 	return pskb_may_pull(skb, skb_network_offset(skb) + len);
 }
 
-static inline void skb_pop_rcv_encapsulation(struct sk_buff *skb)
-{
-	/* Only continue with checksum unnecessary if device indicated
-	 * it is valid across encapsulation (skb->encapsulation was set).
-	 */
-	if (skb->ip_summed == CHECKSUM_UNNECESSARY && !skb->encapsulation)
-		skb->ip_summed = CHECKSUM_NONE;
-
-	skb->encapsulation = 0;
-	skb->csum_valid = 0;
-}
-
 /*
  * CPUs often take a performance hit when accessing unaligned memory
  * locations. The actual performance hit varies, it can be small if the
@@ -2567,20 +2665,26 @@
 __wsum skb_checksum(const struct sk_buff *skb, int offset, int len,
 		    __wsum csum);
 
-static inline void *skb_header_pointer(const struct sk_buff *skb, int offset,
-				       int len, void *buffer)
+static inline void *__skb_header_pointer(const struct sk_buff *skb, int offset,
+					 int len, void *data, int hlen, void *buffer)
 {
-	int hlen = skb_headlen(skb);
-
 	if (hlen - offset >= len)
-		return skb->data + offset;
+		return data + offset;
 
-	if (skb_copy_bits(skb, offset, buffer, len) < 0)
+	if (!skb ||
+	    skb_copy_bits(skb, offset, buffer, len) < 0)
 		return NULL;
 
 	return buffer;
 }
 
+static inline void *skb_header_pointer(const struct sk_buff *skb, int offset,
+				       int len, void *buffer)
+{
+	return __skb_header_pointer(skb, offset, len, skb->data,
+				    skb_headlen(skb), buffer);
+}
+
 /**
  *	skb_needs_linearize - check if we need to linearize a given skb
  *			      depending on the given device features.
@@ -2671,6 +2775,8 @@
 	return ktime_set(0, 0);
 }
 
+struct sk_buff *skb_clone_sk(struct sk_buff *skb);
+
 #ifdef CONFIG_NETWORK_PHY_TIMESTAMPING
 
 void skb_clone_tx_timestamp(struct sk_buff *skb);
@@ -2786,6 +2892,42 @@
 	       0 : __skb_checksum_complete(skb);
 }
 
+static inline void __skb_decr_checksum_unnecessary(struct sk_buff *skb)
+{
+	if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
+		if (skb->csum_level == 0)
+			skb->ip_summed = CHECKSUM_NONE;
+		else
+			skb->csum_level--;
+	}
+}
+
+static inline void __skb_incr_checksum_unnecessary(struct sk_buff *skb)
+{
+	if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
+		if (skb->csum_level < SKB_MAX_CSUM_LEVEL)
+			skb->csum_level++;
+	} else if (skb->ip_summed == CHECKSUM_NONE) {
+		skb->ip_summed = CHECKSUM_UNNECESSARY;
+		skb->csum_level = 0;
+	}
+}
+
+static inline void __skb_mark_checksum_bad(struct sk_buff *skb)
+{
+	/* Mark current checksum as bad (typically called from GRO
+	 * path). In the case that ip_summed is CHECKSUM_NONE
+	 * this must be the first checksum encountered in the packet.
+	 * When ip_summed is CHECKSUM_UNNECESSARY, this is the first
+	 * checksum after the last one validated. For UDP, a zero
+	 * checksum can not be marked as bad.
+	 */
+
+	if (skb->ip_summed == CHECKSUM_NONE ||
+	    skb->ip_summed == CHECKSUM_UNNECESSARY)
+		skb->csum_bad = 1;
+}
+
 /* Check if we need to perform checksum complete validation.
  *
  * Returns true if checksum complete is needed, false otherwise
@@ -2797,6 +2939,7 @@
 {
 	if (skb_csum_unnecessary(skb) || (zero_okay && !check)) {
 		skb->csum_valid = 1;
+		__skb_decr_checksum_unnecessary(skb);
 		return false;
 	}
 
@@ -2826,6 +2969,9 @@
 			skb->csum_valid = 1;
 			return 0;
 		}
+	} else if (skb->csum_bad) {
+		/* ip_summed == CHECKSUM_NONE in this case */
+		return 1;
 	}
 
 	skb->csum = psum;
@@ -2883,6 +3029,26 @@
 #define skb_checksum_simple_validate(skb)				\
 	__skb_checksum_validate(skb, 0, true, false, 0, null_compute_pseudo)
 
+static inline bool __skb_checksum_convert_check(struct sk_buff *skb)
+{
+	return (skb->ip_summed == CHECKSUM_NONE &&
+		skb->csum_valid && !skb->csum_bad);
+}
+
+static inline void __skb_checksum_convert(struct sk_buff *skb,
+					  __sum16 check, __wsum pseudo)
+{
+	skb->csum = ~pseudo;
+	skb->ip_summed = CHECKSUM_COMPLETE;
+}
+
+#define skb_checksum_try_convert(skb, proto, check, compute_pseudo)	\
+do {									\
+	if (__skb_checksum_convert_check(skb))				\
+		__skb_checksum_convert(skb, check,			\
+				       compute_pseudo(skb, proto));	\
+} while (0)
+
 #if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
 void nf_conntrack_destroy(struct nf_conntrack *nfct);
 static inline void nf_conntrack_put(struct nf_conntrack *nfct)
@@ -2896,7 +3062,7 @@
 		atomic_inc(&nfct->use);
 }
 #endif
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 static inline void nf_bridge_put(struct nf_bridge_info *nf_bridge)
 {
 	if (nf_bridge && atomic_dec_and_test(&nf_bridge->use))
@@ -2914,7 +3080,7 @@
 	nf_conntrack_put(skb->nfct);
 	skb->nfct = NULL;
 #endif
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	nf_bridge_put(skb->nf_bridge);
 	skb->nf_bridge = NULL;
 #endif
@@ -2928,19 +3094,22 @@
 }
 
 /* Note: This doesn't put any conntrack and bridge info in dst. */
-static inline void __nf_copy(struct sk_buff *dst, const struct sk_buff *src)
+static inline void __nf_copy(struct sk_buff *dst, const struct sk_buff *src,
+			     bool copy)
 {
 #if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
 	dst->nfct = src->nfct;
 	nf_conntrack_get(src->nfct);
-	dst->nfctinfo = src->nfctinfo;
+	if (copy)
+		dst->nfctinfo = src->nfctinfo;
 #endif
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	dst->nf_bridge  = src->nf_bridge;
 	nf_bridge_get(src->nf_bridge);
 #endif
 #if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_TRACE) || defined(CONFIG_NF_TABLES)
-	dst->nf_trace = src->nf_trace;
+	if (copy)
+		dst->nf_trace = src->nf_trace;
 #endif
 }
 
@@ -2949,10 +3118,10 @@
 #if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
 	nf_conntrack_put(dst->nfct);
 #endif
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	nf_bridge_put(dst->nf_bridge);
 #endif
-	__nf_copy(dst, src);
+	__nf_copy(dst, src, true);
 }
 
 #ifdef CONFIG_NETWORK_SECMARK
@@ -3137,7 +3306,9 @@
 
 int skb_checksum_setup(struct sk_buff *skb, bool recalculate);
 
-u32 __skb_get_poff(const struct sk_buff *skb);
+u32 skb_get_poff(const struct sk_buff *skb);
+u32 __skb_get_poff(const struct sk_buff *skb, void *data,
+		   const struct flow_keys *keys, int hlen);
 
 /**
  * skb_head_is_locked - Determine if the skb->head is locked down
diff -urN linux/include/linux/syscalls.h net-next-2.6/include/linux/syscalls.h
--- linux/include/linux/syscalls.h	2014-09-24 09:52:38.948599956 +0200
+++ net-next-2.6/include/linux/syscalls.h	2014-10-06 10:48:54.836845482 +0200
@@ -65,6 +65,7 @@
 struct perf_event_attr;
 struct file_handle;
 struct sigaltstack;
+union bpf_attr;
 
 #include <linux/types.h>
 #include <linux/aio_abi.h>
@@ -875,5 +876,5 @@
 			    const char __user *uargs);
 asmlinkage long sys_getrandom(char __user *buf, size_t count,
 			      unsigned int flags);
-
+asmlinkage long sys_bpf(int cmd, union bpf_attr *attr, unsigned int size);
 #endif
diff -urN linux/include/linux/tcp.h net-next-2.6/include/linux/tcp.h
--- linux/include/linux/tcp.h	2014-09-24 09:52:38.948599956 +0200
+++ net-next-2.6/include/linux/tcp.h	2014-10-06 10:48:55.348850700 +0200
@@ -276,7 +276,7 @@
 	u32	retrans_stamp;	/* Timestamp of the last retransmit,
 				 * also used in SYN-SENT to remember stamp of
 				 * the first SYN. */
-	u32	undo_marker;	/* tracking retrans started here. */
+	u32	undo_marker;	/* snd_una upon a new recovery episode. */
 	int	undo_retrans;	/* number of undoable retransmissions. */
 	u32	total_retrans;	/* Total retransmits for entire connection */
 
diff -urN linux/include/linux/udp.h net-next-2.6/include/linux/udp.h
--- linux/include/linux/udp.h	2014-09-24 09:52:38.948599956 +0200
+++ net-next-2.6/include/linux/udp.h	2014-10-06 10:48:55.348850700 +0200
@@ -49,7 +49,11 @@
 	unsigned int	 corkflag;	/* Cork is required */
 	__u8		 encap_type;	/* Is this an Encapsulation socket? */
 	unsigned char	 no_check6_tx:1,/* Send zero UDP6 checksums on TX? */
-			 no_check6_rx:1;/* Allow zero UDP6 checksums on RX? */
+			 no_check6_rx:1,/* Allow zero UDP6 checksums on RX? */
+			 convert_csum:1;/* On receive, convert checksum
+					 * unnecessary to checksum complete
+					 * if possible.
+					 */
 	/*
 	 * Following member retains the information to create a UDP header
 	 * when the socket is uncorked.
@@ -98,6 +102,16 @@
 	return udp_sk(sk)->no_check6_rx;
 }
 
+static inline void udp_set_convert_csum(struct sock *sk, bool val)
+{
+	udp_sk(sk)->convert_csum = val;
+}
+
+static inline bool udp_get_convert_csum(struct sock *sk)
+{
+	return udp_sk(sk)->convert_csum;
+}
+
 #define udp_portaddr_for_each_entry(__sk, node, list) \
 	hlist_nulls_for_each_entry(__sk, node, list, __sk_common.skc_portaddr_node)
 
