commit 6ae37c53fb6f3409e7714eb5f9a9f2c33876a7a8
Author: root <root@gatling.(none)>
Date:   Tue Apr 13 13:40:38 2010 +0200

    Added Documentation/networking/dom.txt and include/net/dom.h

diff --git a/Documentation/networking/dom.txt b/Documentation/networking/dom.txt
new file mode 100644
index 0000000..4bf24de
--- /dev/null
+++ b/Documentation/networking/dom.txt
@@ -0,0 +1,41 @@
+Diagnostic Monitoring Interface Monitoring also called DOM is a specification
+for optical transceivers to allow link and other diagnostics related to the
+transceiver's to standardized and communicated. For communication the I2C
+bus is used. The SFF specifications is available at ftp://ftp.seagate.com/
+Specification is generic and should work for many types of optical modules
+as GBIC, SFP, SFp+, XFP etc
+
+In short DOM spec adds a memory page where the diagnostics's is kept (address
+0xA2 bytes 66 to 105) but there are lot's of option's and variants. For example
+alarm and warnings are optional. See example below.
+
+Not all SFP's (SFP is for GIGE) have DOM support normally long range supports
+DOM. And of course your board and driver needs this support too.
+For SFP+ (10G) DOM is mandatory.
+
+Linux kernel support is via ethertool.
+
+include/net/dom.h        # Basic definitions
+net/core/ethtool.c       # adds ethtool_phy_diag()
+include/linux/ethtool.h  # adds ETHTOOL_GPHYDIAG
+
+And drivers hooks exists currently in igb and ixgbe driver
+
+Usage example: ethtool -D eth5
+
+Ext-Calbr: Avr RX-Power: Alarm & Warn: RX_LOS: 	Wavelength: 1310 nm
+Alarms, warnings in beginning of line, Ie. AH = Alarm High, WL == Warn Low etc
+	Temp:  35.9 C			Thresh: Lo: -12.0/-8.0   Hi: 103.0/110.0 C
+	Vcc:  3.33 V			Thresh: Lo:   3.0/3.0    Hi:   3.7/4.0   V
+	Tx-Bias:  13.4 mA		Thresh: Lo:   2.0/4.0    Hi:  70.0/84.0  mA
+ALWL	TX-pwr:  -5.9 dBm ( 0.26 mW)	Thresh: Lo:  -4.0/-2.0   Hi:   7.0/8.2   dBm
+AHWH	RX-pwr:  -5.0 dBm ( 0.31 mW) 	Thresh: Lo: -35.2/-28.0  Hi:  -8.2/-6.0  dBm
+
+
+First line shows the options supported by the module. As we see this module
+supports Alarms and warnings as a consequence thresholds are printed. As example
+RX-pwr: -35.2 < no_alarm < -6.0 dBm and -28.0 < no_warning < -8.2 dBm. (dBm yields
+1 mW == 0 dBm)
+
+In the example above we see both warnings for both TX-pwr (low) and RX-Pwr high.
+The Rx side would need some attenuation.
diff --git a/include/net/dom.h b/include/net/dom.h
new file mode 100644
index 0000000..61540c3
--- /dev/null
+++ b/include/net/dom.h
@@ -0,0 +1,109 @@
+#ifndef _LINUX_DOM_H
+#define _LINUX_DOM_H
+
+/*
+   Diagnostic Monitoring Interface for Optical Tranceivers
+   SFF-8472 v. 10.4 (Jan 2009)
+   ftp://ftp.seagate.com/sff/SFF-8472.PDF
+
+   Licensce GPL. Copyright Robert Olsson robert@herjulf.net
+*/
+
+#define  DOM_A0_IDENTIFIER  0
+#define  DOM_A0_WAVELENGTH 60
+#define  DOM_A0_CC_BASE    63
+#define  DOM_A0_DOM_TYPE   92
+
+/* DOM_TYPE codings in DOM_A0_DOM_TYPE */
+#define     DOM_TYPE_LEGAGY_DOM     (1<<7)
+#define     DOM_TYPE_DOM            (1<<6)  /* Has DOM support */
+#define     DOM_TYPE_INT_CAL        (1<<5)  /* Internally calibrated */
+#define     DOM_TYPE_EXT_CAL        (1<<4)  /* Externally calibrated */
+#define     DOM_TYPE_RX_PWR         (1<<3)  /* Received Power OMA=0,  1=average */
+#define     DOM_TYPE_ADDR_CHNGE     (1<<2)  /* Address change required */
+
+#define  DOM_A0_EO   93                     /* Enhanced options */
+#define     DOM_EO_AW               (1<<7)  /* Alarm & Warnings */
+#define     DOM_EO_TX_DISABLE       (1<<6)
+#define     DOM_EO_TX_FAULT         (1<<5)
+#define     DOM_EO_RX_LOS           (1<<4)
+#define     DOM_EO_RATE_SELECT_MON  (1<<3)
+#define     DOM_EO_APP_SELECT       (1<<2)
+#define     DOM_EO_RATE_SELECT      (1<<1)
+
+#define  DOM_A0_CC_EXT     95
+
+#define  DOM_A2_TEMP_AHT    0  /* Temp alarm high threshold */
+#define  DOM_A2_TEMP_ALT    2
+#define  DOM_A2_TEMP_WHT    4  /* Temp warning high threshold */
+#define  DOM_A2_TEMP_WLT    6
+
+#define  DOM_A2_VCC_AHT    8  /* VCC alarm high threshold */
+#define  DOM_A2_VCC_ALT   10
+#define  DOM_A2_VCC_WHT   12  /* VCC warning high threshold */
+#define  DOM_A2_VCC_WLT   14
+
+#define  DOM_A2_TX_BIAS_AHT   16  /* TX_BIAS alarm high threshold */
+#define  DOM_A2_TX_BIAS_ALT   18
+#define  DOM_A2_TX_BIAS_WHT   20  /* TX_BIAS warning high threshold */
+#define  DOM_A2_TX_BIAS_WLT   22
+
+#define  DOM_A2_TX_PWR_AHT   24  /* TX_PWR alarm high threshold */
+#define  DOM_A2_TX_PWR_ALT   26
+#define  DOM_A2_TX_PWR_WHT   28  /* TX_PWR warning high threshold */
+#define  DOM_A2_TX_PWR_WLT   30
+
+#define  DOM_A2_RX_PWR_AHT   32  /* RX_PWR alarm high threshold */
+#define  DOM_A2_RX_PWR_ALT   34
+#define  DOM_A2_RX_PWR_WHT   36  /* RX_PWR warning high threshold */
+#define  DOM_A2_RX_PWR_WLT   38
+
+#define  DOM_A2_RX_PWR_4   56  /* 4 bytes  Calibration constants*/
+#define  DOM_A2_RX_PWR_3   60  /* 4 bytes */
+#define  DOM_A2_RX_PWR_2   64  /* 4 bytes */
+#define  DOM_A2_RX_PWR_1   68  /* 4 bytes */
+#define  DOM_A2_RX_PWR_0   72  /* 4 bytes */
+
+#define  DOM_A2_TX_I_SLOPE   76  /* 2 bytes */
+#define  DOM_A2_TX_I_OFFSET  78  /* 2 bytes */
+#define  DOM_A2_TX_PWR_SLOPE   80  /* 2 bytes */
+#define  DOM_A2_TX_PWR_OFFSET  82  /* 2 bytes */
+#define  DOM_A2_TEMP_SLOPE   84  /* 2 bytes */
+#define  DOM_A2_TEMP_OFFSET  86  /* 2 bytes */
+#define  DOM_A2_VCC_SLOPE   88  /* 2 bytes */
+#define  DOM_A2_VCC_OFFSET  90  /* 2 bytes */
+
+#define  DOM_A2_CC_DMI    95
+#define  DOM_A2_TEMP      96   /* 2 bytes */
+#define  DOM_A2_VCC       98   /* 2 bytes */
+#define  DOM_A2_TX_BIAS  100   /* 2 bytes */
+#define  DOM_A2_TX_PWR   102   /* 2 bytes */
+#define  DOM_A2_RX_PWR   104   /* 2 bytes */
+
+#define  DOM_A2_ALARM    112   /* 2 bytes */
+#define     DOM_TYPE_TEMP_AH       (1<<7)  /* Temp alarm high */
+#define     DOM_TYPE_TEMP_AL       (1<<6)  /* low */
+#define     DOM_TYPE_VCC_AH        (1<<5)
+#define     DOM_TYPE_VCC_AL        (1<<4)
+#define     DOM_TYPE_TX_BIAS_AH    (1<<3)
+#define     DOM_TYPE_TX_BIAS_AL    (1<<2)
+#define     DOM_TYPE_TX_PWR_AH     (1<<1)
+#define     DOM_TYPE_TX_PWR_AL     (1<<0)
+/* Next byte 113 */
+#define     DOM_TYPE_RX_PWR_AH     (1<<7)
+#define     DOM_TYPE_RX_PWR_AL     (1<<6)
+
+#define  DOM_A2_WARNING  116   /* 2 bytes */
+#define     DOM_TYPE_TEMP_WH       (1<<7)  /* Temp warning high */
+#define     DOM_TYPE_TEMP_WL       (1<<6)  /* low */
+#define     DOM_TYPE_VCC_WH        (1<<5)
+#define     DOM_TYPE_VCC_WL        (1<<4)
+#define     DOM_TYPE_TX_BIAS_WH    (1<<3)
+#define     DOM_TYPE_TX_BIAS_WL    (1<<2)
+#define     DOM_TYPE_TX_PWR_WH     (1<<1)
+#define     DOM_TYPE_TX_PWR_WL     (1<<0)
+/* Next byte 117 */
+#define     DOM_TYPE_RX_PWR_WH     (1<<7)
+#define     DOM_TYPE_RX_PWR_WL     (1<<6)
+
+#endif /* _LINUX_DOM_H */
