diff -urN linux/include/uapi/linux/bpf.h net-next-2.6/include/uapi/linux/bpf.h
--- linux/include/uapi/linux/bpf.h	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/include/uapi/linux/bpf.h	2014-10-06 10:48:55.880856122 +0200
@@ -0,0 +1,155 @@
+/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
+ *
+ * This program is free software; you can redistribute it and/or
+ * modify it under the terms of version 2 of the GNU General Public
+ * License as published by the Free Software Foundation.
+ */
+#ifndef _UAPI__LINUX_BPF_H__
+#define _UAPI__LINUX_BPF_H__
+
+#include <linux/types.h>
+
+/* Extended instruction set based on top of classic BPF */
+
+/* instruction classes */
+#define BPF_ALU64	0x07	/* alu mode in double word width */
+
+/* ld/ldx fields */
+#define BPF_DW		0x18	/* double word */
+#define BPF_XADD	0xc0	/* exclusive add */
+
+/* alu/jmp fields */
+#define BPF_MOV		0xb0	/* mov reg to reg */
+#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */
+
+/* change endianness of a register */
+#define BPF_END		0xd0	/* flags for endianness conversion: */
+#define BPF_TO_LE	0x00	/* convert to little-endian */
+#define BPF_TO_BE	0x08	/* convert to big-endian */
+#define BPF_FROM_LE	BPF_TO_LE
+#define BPF_FROM_BE	BPF_TO_BE
+
+#define BPF_JNE		0x50	/* jump != */
+#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
+#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
+#define BPF_CALL	0x80	/* function call */
+#define BPF_EXIT	0x90	/* function return */
+
+/* Register numbers */
+enum {
+	BPF_REG_0 = 0,
+	BPF_REG_1,
+	BPF_REG_2,
+	BPF_REG_3,
+	BPF_REG_4,
+	BPF_REG_5,
+	BPF_REG_6,
+	BPF_REG_7,
+	BPF_REG_8,
+	BPF_REG_9,
+	BPF_REG_10,
+	__MAX_BPF_REG,
+};
+
+/* BPF has 10 general purpose 64-bit registers and stack frame. */
+#define MAX_BPF_REG	__MAX_BPF_REG
+
+struct bpf_insn {
+	__u8	code;		/* opcode */
+	__u8	dst_reg:4;	/* dest register */
+	__u8	src_reg:4;	/* source register */
+	__s16	off;		/* signed offset */
+	__s32	imm;		/* signed immediate constant */
+};
+
+/* BPF syscall commands */
+enum bpf_cmd {
+	/* create a map with given type and attributes
+	 * fd = bpf(BPF_MAP_CREATE, union bpf_attr *, u32 size)
+	 * returns fd or negative error
+	 * map is deleted when fd is closed
+	 */
+	BPF_MAP_CREATE,
+
+	/* lookup key in a given map
+	 * err = bpf(BPF_MAP_LOOKUP_ELEM, union bpf_attr *attr, u32 size)
+	 * Using attr->map_fd, attr->key, attr->value
+	 * returns zero and stores found elem into value
+	 * or negative error
+	 */
+	BPF_MAP_LOOKUP_ELEM,
+
+	/* create or update key/value pair in a given map
+	 * err = bpf(BPF_MAP_UPDATE_ELEM, union bpf_attr *attr, u32 size)
+	 * Using attr->map_fd, attr->key, attr->value
+	 * returns zero or negative error
+	 */
+	BPF_MAP_UPDATE_ELEM,
+
+	/* find and delete elem by key in a given map
+	 * err = bpf(BPF_MAP_DELETE_ELEM, union bpf_attr *attr, u32 size)
+	 * Using attr->map_fd, attr->key
+	 * returns zero or negative error
+	 */
+	BPF_MAP_DELETE_ELEM,
+
+	/* lookup key in a given map and return next key
+	 * err = bpf(BPF_MAP_GET_NEXT_KEY, union bpf_attr *attr, u32 size)
+	 * Using attr->map_fd, attr->key, attr->next_key
+	 * returns zero and stores next key or negative error
+	 */
+	BPF_MAP_GET_NEXT_KEY,
+
+	/* verify and load eBPF program
+	 * prog_fd = bpf(BPF_PROG_LOAD, union bpf_attr *attr, u32 size)
+	 * Using attr->prog_type, attr->insns, attr->license
+	 * returns fd or negative error
+	 */
+	BPF_PROG_LOAD,
+};
+
+enum bpf_map_type {
+	BPF_MAP_TYPE_UNSPEC,
+};
+
+enum bpf_prog_type {
+	BPF_PROG_TYPE_UNSPEC,
+};
+
+union bpf_attr {
+	struct { /* anonymous struct used by BPF_MAP_CREATE command */
+		__u32	map_type;	/* one of enum bpf_map_type */
+		__u32	key_size;	/* size of key in bytes */
+		__u32	value_size;	/* size of value in bytes */
+		__u32	max_entries;	/* max number of entries in a map */
+	};
+
+	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
+		__u32		map_fd;
+		__aligned_u64	key;
+		union {
+			__aligned_u64 value;
+			__aligned_u64 next_key;
+		};
+	};
+
+	struct { /* anonymous struct used by BPF_PROG_LOAD command */
+		__u32		prog_type;	/* one of enum bpf_prog_type */
+		__u32		insn_cnt;
+		__aligned_u64	insns;
+		__aligned_u64	license;
+		__u32		log_level;	/* verbosity level of verifier */
+		__u32		log_size;	/* size of user buffer */
+		__aligned_u64	log_buf;	/* user supplied buffer */
+	};
+} __attribute__((aligned(8)));
+
+/* integer value in 'imm' field of BPF_CALL instruction selects which helper
+ * function eBPF program intends to call
+ */
+enum bpf_func_id {
+	BPF_FUNC_unspec,
+	__BPF_FUNC_MAX_ID,
+};
+
+#endif /* _UAPI__LINUX_BPF_H__ */
diff -urN linux/include/uapi/linux/ethtool.h net-next-2.6/include/uapi/linux/ethtool.h
--- linux/include/uapi/linux/ethtool.h	2014-09-24 09:52:39.968610661 +0200
+++ net-next-2.6/include/uapi/linux/ethtool.h	2014-10-06 10:48:56.588863338 +0200
@@ -209,6 +209,33 @@
 	__u32	data;
 };
 
+enum tunable_id {
+	ETHTOOL_ID_UNSPEC,
+	ETHTOOL_RX_COPYBREAK,
+	ETHTOOL_TX_COPYBREAK,
+};
+
+enum tunable_type_id {
+	ETHTOOL_TUNABLE_UNSPEC,
+	ETHTOOL_TUNABLE_U8,
+	ETHTOOL_TUNABLE_U16,
+	ETHTOOL_TUNABLE_U32,
+	ETHTOOL_TUNABLE_U64,
+	ETHTOOL_TUNABLE_STRING,
+	ETHTOOL_TUNABLE_S8,
+	ETHTOOL_TUNABLE_S16,
+	ETHTOOL_TUNABLE_S32,
+	ETHTOOL_TUNABLE_S64,
+};
+
+struct ethtool_tunable {
+	__u32	cmd;
+	__u32	id;
+	__u32	type_id;
+	__u32	len;
+	void	*data[0];
+};
+
 /**
  * struct ethtool_regs - hardware register dump
  * @cmd: Command number = %ETHTOOL_GREGS
@@ -1152,6 +1179,8 @@
 
 #define ETHTOOL_GRSSH		0x00000046 /* Get RX flow hash configuration */
 #define ETHTOOL_SRSSH		0x00000047 /* Set RX flow hash configuration */
+#define ETHTOOL_GTUNABLE	0x00000048 /* Get tunable configuration */
+#define ETHTOOL_STUNABLE	0x00000049 /* Set tunable configuration */
 
 /* compatibility with older code */
 #define SPARC_ETH_GSET		ETHTOOL_GSET
diff -urN linux/include/uapi/linux/fou.h net-next-2.6/include/uapi/linux/fou.h
--- linux/include/uapi/linux/fou.h	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/include/uapi/linux/fou.h	2014-10-06 10:48:56.592863378 +0200
@@ -0,0 +1,39 @@
+/* fou.h - FOU Interface */
+
+#ifndef _UAPI_LINUX_FOU_H
+#define _UAPI_LINUX_FOU_H
+
+/* NETLINK_GENERIC related info
+ */
+#define FOU_GENL_NAME		"fou"
+#define FOU_GENL_VERSION	0x1
+
+enum {
+	FOU_ATTR_UNSPEC,
+	FOU_ATTR_PORT,				/* u16 */
+	FOU_ATTR_AF,				/* u8 */
+	FOU_ATTR_IPPROTO,			/* u8 */
+	FOU_ATTR_TYPE,				/* u8 */
+
+	__FOU_ATTR_MAX,
+};
+
+#define FOU_ATTR_MAX		(__FOU_ATTR_MAX - 1)
+
+enum {
+	FOU_CMD_UNSPEC,
+	FOU_CMD_ADD,
+	FOU_CMD_DEL,
+
+	__FOU_CMD_MAX,
+};
+
+enum {
+	FOU_ENCAP_UNSPEC,
+	FOU_ENCAP_DIRECT,
+	FOU_ENCAP_GUE,
+};
+
+#define FOU_CMD_MAX	(__FOU_CMD_MAX - 1)
+
+#endif /* _UAPI_LINUX_FOU_H */
diff -urN linux/include/uapi/linux/if_ether.h net-next-2.6/include/uapi/linux/if_ether.h
--- linux/include/uapi/linux/if_ether.h	2014-09-24 09:52:39.972610703 +0200
+++ net-next-2.6/include/uapi/linux/if_ether.h	2014-10-06 10:48:56.592863378 +0200
@@ -128,6 +128,7 @@
 #define ETH_P_PHONET	0x00F5		/* Nokia Phonet frames          */
 #define ETH_P_IEEE802154 0x00F6		/* IEEE802.15.4 frame		*/
 #define ETH_P_CAIF	0x00F7		/* ST-Ericsson CAIF protocol	*/
+#define ETH_P_XDSA	0x00F8		/* Multiplexed DSA protocol	*/
 
 /*
  *	This is an Ethernet frame header.
diff -urN linux/include/uapi/linux/if_link.h net-next-2.6/include/uapi/linux/if_link.h
--- linux/include/uapi/linux/if_link.h	2014-09-24 09:52:39.972610703 +0200
+++ net-next-2.6/include/uapi/linux/if_link.h	2014-10-06 10:48:56.592863378 +0200
@@ -215,6 +215,18 @@
 	IN6_ADDR_GEN_MODE_NONE,
 };
 
+/* Bridge section */
+
+enum {
+	IFLA_BR_UNSPEC,
+	IFLA_BR_FORWARD_DELAY,
+	IFLA_BR_HELLO_TIME,
+	IFLA_BR_MAX_AGE,
+	__IFLA_BR_MAX,
+};
+
+#define IFLA_BR_MAX	(__IFLA_BR_MAX - 1)
+
 enum {
 	BRIDGE_MODE_UNSPEC,
 	BRIDGE_MODE_HAIRPIN,
@@ -291,6 +303,10 @@
 	IFLA_MACVLAN_UNSPEC,
 	IFLA_MACVLAN_MODE,
 	IFLA_MACVLAN_FLAGS,
+	IFLA_MACVLAN_MACADDR_MODE,
+	IFLA_MACVLAN_MACADDR,
+	IFLA_MACVLAN_MACADDR_DATA,
+	IFLA_MACVLAN_MACADDR_COUNT,
 	__IFLA_MACVLAN_MAX,
 };
 
@@ -301,6 +317,14 @@
 	MACVLAN_MODE_VEPA    = 2, /* talk to other ports through ext bridge */
 	MACVLAN_MODE_BRIDGE  = 4, /* talk to bridge ports directly */
 	MACVLAN_MODE_PASSTHRU = 8,/* take over the underlying device */
+	MACVLAN_MODE_SOURCE  = 16,/* use source MAC address list to assign */
+};
+
+enum macvlan_macaddr_mode {
+	MACVLAN_MACADDR_ADD,
+	MACVLAN_MACADDR_DEL,
+	MACVLAN_MACADDR_FLUSH,
+	MACVLAN_MACADDR_SET,
 };
 
 #define MACVLAN_FLAG_NOPROMISC	1
diff -urN linux/include/uapi/linux/if_tunnel.h net-next-2.6/include/uapi/linux/if_tunnel.h
--- linux/include/uapi/linux/if_tunnel.h	2014-09-24 09:52:39.972610703 +0200
+++ net-next-2.6/include/uapi/linux/if_tunnel.h	2014-10-06 10:48:56.592863378 +0200
@@ -53,10 +53,23 @@
 	IFLA_IPTUN_6RD_RELAY_PREFIX,
 	IFLA_IPTUN_6RD_PREFIXLEN,
 	IFLA_IPTUN_6RD_RELAY_PREFIXLEN,
+	IFLA_IPTUN_ENCAP_TYPE,
+	IFLA_IPTUN_ENCAP_FLAGS,
+	IFLA_IPTUN_ENCAP_SPORT,
+	IFLA_IPTUN_ENCAP_DPORT,
 	__IFLA_IPTUN_MAX,
 };
 #define IFLA_IPTUN_MAX	(__IFLA_IPTUN_MAX - 1)
 
+enum tunnel_encap_types {
+	TUNNEL_ENCAP_NONE,
+	TUNNEL_ENCAP_FOU,
+	TUNNEL_ENCAP_GUE,
+};
+
+#define TUNNEL_ENCAP_FLAG_CSUM		(1<<0)
+#define TUNNEL_ENCAP_FLAG_CSUM6		(1<<1)
+
 /* SIT-mode i_flags */
 #define	SIT_ISATAP	0x0001
 
@@ -94,6 +107,10 @@
 	IFLA_GRE_ENCAP_LIMIT,
 	IFLA_GRE_FLOWINFO,
 	IFLA_GRE_FLAGS,
+	IFLA_GRE_ENCAP_TYPE,
+	IFLA_GRE_ENCAP_FLAGS,
+	IFLA_GRE_ENCAP_SPORT,
+	IFLA_GRE_ENCAP_DPORT,
 	__IFLA_GRE_MAX,
 };
 
diff -urN linux/include/uapi/linux/inet_diag.h net-next-2.6/include/uapi/linux/inet_diag.h
--- linux/include/uapi/linux/inet_diag.h	2013-05-02 09:43:18.841515176 +0200
+++ net-next-2.6/include/uapi/linux/inet_diag.h	2014-10-06 10:48:56.596863418 +0200
@@ -110,10 +110,10 @@
 	INET_DIAG_TCLASS,
 	INET_DIAG_SKMEMINFO,
 	INET_DIAG_SHUTDOWN,
+	INET_DIAG_DCTCPINFO,
 };
 
-#define INET_DIAG_MAX INET_DIAG_SHUTDOWN
-
+#define INET_DIAG_MAX INET_DIAG_DCTCPINFO
 
 /* INET_DIAG_MEM */
 
@@ -133,5 +133,14 @@
 	__u32	tcpv_minrtt;
 };
 
+/* INET_DIAG_DCTCPINFO */
+
+struct tcp_dctcp_info {
+	__u16	dctcp_enabled;
+	__u16	dctcp_ce_state;
+	__u32	dctcp_alpha;
+	__u32	dctcp_ab_ecn;
+	__u32	dctcp_ab_tot;
+};
 
 #endif /* _UAPI_INET_DIAG_H_ */
diff -urN linux/include/uapi/linux/ip_vs.h net-next-2.6/include/uapi/linux/ip_vs.h
--- linux/include/uapi/linux/ip_vs.h	2013-11-29 12:59:36.151363705 +0100
+++ net-next-2.6/include/uapi/linux/ip_vs.h	2014-10-06 10:48:56.596863418 +0200
@@ -384,6 +384,9 @@
 	IPVS_DEST_ATTR_PERSIST_CONNS,	/* persistent connections */
 
 	IPVS_DEST_ATTR_STATS,		/* nested attribute for dest stats */
+
+	IPVS_DEST_ATTR_ADDR_FAMILY,	/* Address family of address */
+
 	__IPVS_DEST_ATTR_MAX,
 };
 
diff -urN linux/include/uapi/linux/Kbuild net-next-2.6/include/uapi/linux/Kbuild
--- linux/include/uapi/linux/Kbuild	2014-09-24 09:52:39.964610620 +0200
+++ net-next-2.6/include/uapi/linux/Kbuild	2014-10-06 10:48:55.880856122 +0200
@@ -67,6 +67,7 @@
 header-y += binfmts.h
 header-y += blkpg.h
 header-y += blktrace_api.h
+header-y += bpf.h
 header-y += bpqether.h
 header-y += bsg.h
 header-y += btrfs.h
diff -urN linux/include/uapi/linux/netfilter/ipset/ip_set.h net-next-2.6/include/uapi/linux/netfilter/ipset/ip_set.h
--- linux/include/uapi/linux/netfilter/ipset/ip_set.h	2014-09-24 09:52:39.976610744 +0200
+++ net-next-2.6/include/uapi/linux/netfilter/ipset/ip_set.h	2014-10-06 10:48:56.600863458 +0200
@@ -115,6 +115,9 @@
 	IPSET_ATTR_BYTES,
 	IPSET_ATTR_PACKETS,
 	IPSET_ATTR_COMMENT,
+	IPSET_ATTR_SKBMARK,
+	IPSET_ATTR_SKBPRIO,
+	IPSET_ATTR_SKBQUEUE,
 	__IPSET_ATTR_ADT_MAX,
 };
 #define IPSET_ATTR_ADT_MAX	(__IPSET_ATTR_ADT_MAX - 1)
@@ -147,6 +150,7 @@
 	IPSET_ERR_COUNTER,
 	IPSET_ERR_COMMENT,
 	IPSET_ERR_INVALID_MARKMASK,
+	IPSET_ERR_SKBINFO,
 
 	/* Type specific error codes */
 	IPSET_ERR_TYPE_SPECIFIC = 4352,
@@ -170,6 +174,12 @@
 	IPSET_FLAG_MATCH_COUNTERS = (1 << IPSET_FLAG_BIT_MATCH_COUNTERS),
 	IPSET_FLAG_BIT_RETURN_NOMATCH = 7,
 	IPSET_FLAG_RETURN_NOMATCH = (1 << IPSET_FLAG_BIT_RETURN_NOMATCH),
+	IPSET_FLAG_BIT_MAP_SKBMARK = 8,
+	IPSET_FLAG_MAP_SKBMARK = (1 << IPSET_FLAG_BIT_MAP_SKBMARK),
+	IPSET_FLAG_BIT_MAP_SKBPRIO = 9,
+	IPSET_FLAG_MAP_SKBPRIO = (1 << IPSET_FLAG_BIT_MAP_SKBPRIO),
+	IPSET_FLAG_BIT_MAP_SKBQUEUE = 10,
+	IPSET_FLAG_MAP_SKBQUEUE = (1 << IPSET_FLAG_BIT_MAP_SKBQUEUE),
 	IPSET_FLAG_CMD_MAX = 15,
 };
 
@@ -187,6 +197,8 @@
 	IPSET_FLAG_WITH_COMMENT = (1 << IPSET_FLAG_BIT_WITH_COMMENT),
 	IPSET_FLAG_BIT_WITH_FORCEADD = 5,
 	IPSET_FLAG_WITH_FORCEADD = (1 << IPSET_FLAG_BIT_WITH_FORCEADD),
+	IPSET_FLAG_BIT_WITH_SKBINFO = 6,
+	IPSET_FLAG_WITH_SKBINFO = (1 << IPSET_FLAG_BIT_WITH_SKBINFO),
 	IPSET_FLAG_CADT_MAX	= 15,
 };
 
diff -urN linux/include/uapi/linux/netfilter/nf_nat.h net-next-2.6/include/uapi/linux/netfilter/nf_nat.h
--- linux/include/uapi/linux/netfilter/nf_nat.h	2014-09-24 09:52:39.976610744 +0200
+++ net-next-2.6/include/uapi/linux/netfilter/nf_nat.h	2014-10-06 10:48:56.600863458 +0200
@@ -13,6 +13,11 @@
 #define NF_NAT_RANGE_PROTO_RANDOM_ALL		\
 	(NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY)
 
+#define NF_NAT_RANGE_MASK					\
+	(NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED |	\
+	 NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PERSISTENT |	\
+	 NF_NAT_RANGE_PROTO_RANDOM_FULLY)
+
 struct nf_nat_ipv4_range {
 	unsigned int			flags;
 	__be32				min_ip;
diff -urN linux/include/uapi/linux/netfilter/nfnetlink_acct.h net-next-2.6/include/uapi/linux/netfilter/nfnetlink_acct.h
--- linux/include/uapi/linux/netfilter/nfnetlink_acct.h	2014-09-24 09:52:39.976610744 +0200
+++ net-next-2.6/include/uapi/linux/netfilter/nfnetlink_acct.h	2014-10-06 10:48:56.600863458 +0200
@@ -28,9 +28,17 @@
 	NFACCT_USE,
 	NFACCT_FLAGS,
 	NFACCT_QUOTA,
+	NFACCT_FILTER,
 	__NFACCT_MAX
 };
 #define NFACCT_MAX (__NFACCT_MAX - 1)
 
+enum nfnl_attr_filter_type {
+	NFACCT_FILTER_UNSPEC,
+	NFACCT_FILTER_MASK,
+	NFACCT_FILTER_VALUE,
+	__NFACCT_FILTER_MAX
+};
+#define NFACCT_FILTER_MAX (__NFACCT_FILTER_MAX - 1)
 
 #endif /* _UAPI_NFNL_ACCT_H_ */
diff -urN linux/include/uapi/linux/netfilter/nf_tables.h net-next-2.6/include/uapi/linux/netfilter/nf_tables.h
--- linux/include/uapi/linux/netfilter/nf_tables.h	2014-09-24 09:52:39.976610744 +0200
+++ net-next-2.6/include/uapi/linux/netfilter/nf_tables.h	2014-10-06 10:48:56.600863458 +0200
@@ -51,6 +51,8 @@
  * @NFT_MSG_NEWSETELEM: create a new set element (enum nft_set_elem_attributes)
  * @NFT_MSG_GETSETELEM: get a set element (enum nft_set_elem_attributes)
  * @NFT_MSG_DELSETELEM: delete a set element (enum nft_set_elem_attributes)
+ * @NFT_MSG_NEWGEN: announce a new generation, only for events (enum nft_gen_attributes)
+ * @NFT_MSG_GETGEN: get the rule-set generation (enum nft_gen_attributes)
  */
 enum nf_tables_msg_types {
 	NFT_MSG_NEWTABLE,
@@ -68,6 +70,8 @@
 	NFT_MSG_NEWSETELEM,
 	NFT_MSG_GETSETELEM,
 	NFT_MSG_DELSETELEM,
+	NFT_MSG_NEWGEN,
+	NFT_MSG_GETGEN,
 	NFT_MSG_MAX,
 };
 
@@ -571,6 +575,10 @@
  * @NFT_META_L4PROTO: layer 4 protocol number
  * @NFT_META_BRI_IIFNAME: packet input bridge interface name
  * @NFT_META_BRI_OIFNAME: packet output bridge interface name
+ * @NFT_META_PKTTYPE: packet type (skb->pkt_type), special handling for loopback
+ * @NFT_META_CPU: cpu id through smp_processor_id()
+ * @NFT_META_IIFGROUP: packet input interface group
+ * @NFT_META_OIFGROUP: packet output interface group
  */
 enum nft_meta_keys {
 	NFT_META_LEN,
@@ -592,6 +600,10 @@
 	NFT_META_L4PROTO,
 	NFT_META_BRI_IIFNAME,
 	NFT_META_BRI_OIFNAME,
+	NFT_META_PKTTYPE,
+	NFT_META_CPU,
+	NFT_META_IIFGROUP,
+	NFT_META_OIFGROUP,
 };
 
 /**
@@ -737,13 +749,34 @@
  *
  * @NFT_REJECT_ICMP_UNREACH: reject using ICMP unreachable
  * @NFT_REJECT_TCP_RST: reject using TCP RST
+ * @NFT_REJECT_ICMPX_UNREACH: abstracted ICMP unreachable for bridge and inet
  */
 enum nft_reject_types {
 	NFT_REJECT_ICMP_UNREACH,
 	NFT_REJECT_TCP_RST,
+	NFT_REJECT_ICMPX_UNREACH,
 };
 
 /**
+ * enum nft_reject_code - Generic reject codes for IPv4/IPv6
+ *
+ * @NFT_REJECT_ICMPX_NO_ROUTE: no route to host / network unreachable
+ * @NFT_REJECT_ICMPX_PORT_UNREACH: port unreachable
+ * @NFT_REJECT_ICMPX_HOST_UNREACH: host unreachable
+ * @NFT_REJECT_ICMPX_ADMIN_PROHIBITED: administratively prohibited
+ *
+ * These codes are mapped to real ICMP and ICMPv6 codes.
+ */
+enum nft_reject_inet_code {
+	NFT_REJECT_ICMPX_NO_ROUTE	= 0,
+	NFT_REJECT_ICMPX_PORT_UNREACH,
+	NFT_REJECT_ICMPX_HOST_UNREACH,
+	NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
+	__NFT_REJECT_ICMPX_MAX
+};
+#define NFT_REJECT_ICMPX_MAX	(__NFT_REJECT_ICMPX_MAX + 1)
+
+/**
  * enum nft_reject_attributes - nf_tables reject expression netlink attributes
  *
  * @NFTA_REJECT_TYPE: packet type to use (NLA_U32: nft_reject_types)
@@ -777,6 +810,7 @@
  * @NFTA_NAT_REG_ADDR_MAX: source register of address range end (NLA_U32: nft_registers)
  * @NFTA_NAT_REG_PROTO_MIN: source register of proto range start (NLA_U32: nft_registers)
  * @NFTA_NAT_REG_PROTO_MAX: source register of proto range end (NLA_U32: nft_registers)
+ * @NFTA_NAT_FLAGS: NAT flags (see NF_NAT_RANGE_* in linux/netfilter/nf_nat.h) (NLA_U32)
  */
 enum nft_nat_attributes {
 	NFTA_NAT_UNSPEC,
@@ -786,8 +820,33 @@
 	NFTA_NAT_REG_ADDR_MAX,
 	NFTA_NAT_REG_PROTO_MIN,
 	NFTA_NAT_REG_PROTO_MAX,
+	NFTA_NAT_FLAGS,
 	__NFTA_NAT_MAX
 };
 #define NFTA_NAT_MAX		(__NFTA_NAT_MAX - 1)
 
+/**
+ * enum nft_masq_attributes - nf_tables masquerade expression attributes
+ *
+ * @NFTA_MASQ_FLAGS: NAT flags (see NF_NAT_RANGE_* in linux/netfilter/nf_nat.h) (NLA_U32)
+ */
+enum nft_masq_attributes {
+	NFTA_MASQ_UNSPEC,
+	NFTA_MASQ_FLAGS,
+	__NFTA_MASQ_MAX
+};
+#define NFTA_MASQ_MAX		(__NFTA_MASQ_MAX - 1)
+
+/**
+ * enum nft_gen_attributes - nf_tables ruleset generation attributes
+ *
+ * @NFTA_GEN_ID: Ruleset generation ID (NLA_U32)
+ */
+enum nft_gen_attributes {
+	NFTA_GEN_UNSPEC,
+	NFTA_GEN_ID,
+	__NFTA_GEN_MAX
+};
+#define NFTA_GEN_MAX		(__NFTA_GEN_MAX - 1)
+
 #endif /* _LINUX_NF_TABLES_H */
diff -urN linux/include/uapi/linux/netfilter/xt_set.h net-next-2.6/include/uapi/linux/netfilter/xt_set.h
--- linux/include/uapi/linux/netfilter/xt_set.h	2013-05-02 09:43:18.849515176 +0200
+++ net-next-2.6/include/uapi/linux/netfilter/xt_set.h	2014-10-06 10:48:56.636863826 +0200
@@ -71,4 +71,14 @@
 	__u32 flags;
 };
 
+/* Revision 3 target */
+
+struct xt_set_info_target_v3 {
+	struct xt_set_info add_set;
+	struct xt_set_info del_set;
+	struct xt_set_info map_set;
+	__u32 flags;
+	__u32 timeout;
+};
+
 #endif /*_XT_SET_H*/
diff -urN linux/include/uapi/linux/netfilter_arp/arpt_mangle.h net-next-2.6/include/uapi/linux/netfilter_arp/arpt_mangle.h
--- linux/include/uapi/linux/netfilter_arp/arpt_mangle.h	2013-05-02 09:43:18.849515176 +0200
+++ net-next-2.6/include/uapi/linux/netfilter_arp/arpt_mangle.h	2014-10-06 10:48:56.636863826 +0200
@@ -13,7 +13,7 @@
 	union {
 		struct in_addr tgt_ip;
 	} u_t;
-	u_int8_t flags;
+	__u8 flags;
 	int target;
 };
 
diff -urN linux/include/uapi/linux/nl80211.h net-next-2.6/include/uapi/linux/nl80211.h
--- linux/include/uapi/linux/nl80211.h	2014-09-24 09:52:39.980610787 +0200
+++ net-next-2.6/include/uapi/linux/nl80211.h	2014-10-06 10:48:56.640863866 +0200
@@ -722,6 +722,22 @@
  *	QoS mapping is relevant for IP packets, it is only valid during an
  *	association. This is cleared on disassociation and AP restart.
  *
+ * @NL80211_CMD_ADD_TX_TS: Ask the kernel to add a traffic stream for the given
+ *	%NL80211_ATTR_TSID and %NL80211_ATTR_MAC with %NL80211_ATTR_USER_PRIO
+ *	and %NL80211_ATTR_ADMITTED_TIME parameters.
+ *	Note that the action frame handshake with the AP shall be handled by
+ *	userspace via the normal management RX/TX framework, this only sets
+ *	up the TX TS in the driver/device.
+ *	If the admitted time attribute is not added then the request just checks
+ *	if a subsequent setup could be successful, the intent is to use this to
+ *	avoid setting up a session with the AP when local restrictions would
+ *	make that impossible. However, the subsequent "real" setup may still
+ *	fail even if the check was successful.
+ * @NL80211_CMD_DEL_TX_TS: Remove an existing TS with the %NL80211_ATTR_TSID
+ *	and %NL80211_ATTR_MAC parameters. It isn't necessary to call this
+ *	before removing a station entry entirely, or before disassociating
+ *	or similar, cleanup will happen in the driver/device in this case.
+ *
  * @NL80211_CMD_MAX: highest used command number
  * @__NL80211_CMD_AFTER_LAST: internal use
  */
@@ -893,6 +909,9 @@
 
 	NL80211_CMD_SET_QOS_MAP,
 
+	NL80211_CMD_ADD_TX_TS,
+	NL80211_CMD_DEL_TX_TS,
+
 	/* add new commands above here */
 
 	/* used to define NL80211_CMD_MAX below */
@@ -1594,6 +1613,31 @@
  * @NL80211_ATTR_TDLS_INITIATOR: flag attribute indicating the current end is
  *	the TDLS link initiator.
  *
+ * @NL80211_ATTR_USE_RRM: flag for indicating whether the current connection
+ *	shall support Radio Resource Measurements (11k). This attribute can be
+ *	used with %NL80211_CMD_ASSOCIATE and %NL80211_CMD_CONNECT requests.
+ *	User space applications are expected to use this flag only if the
+ *	underlying device supports these minimal RRM features:
+ *		%NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES,
+ *		%NL80211_FEATURE_QUIET,
+ *	If this flag is used, driver must add the Power Capabilities IE to the
+ *	association request. In addition, it must also set the RRM capability
+ *	flag in the association request's Capability Info field.
+ *
+ * @NL80211_ATTR_WIPHY_DYN_ACK: flag attribute used to enable ACK timeout
+ *	estimation algorithm (dynack). In order to activate dynack
+ *	%NL80211_FEATURE_ACKTO_ESTIMATION feature flag must be set by lower
+ *	drivers to indicate dynack capability. Dynack is automatically disabled
+ *	setting valid value for coverage class.
+ *
+ * @NL80211_ATTR_TSID: a TSID value (u8 attribute)
+ * @NL80211_ATTR_USER_PRIO: user priority value (u8 attribute)
+ * @NL80211_ATTR_ADMITTED_TIME: admitted time in units of 32 microseconds
+ *	(per second) (u16 attribute)
+ *
+ * @NL80211_ATTR_SMPS_MODE: SMPS mode to use (ap mode). see
+ *	&enum nl80211_smps_mode.
+ *
  * @NL80211_ATTR_MAX: highest attribute number currently defined
  * @__NL80211_ATTR_AFTER_LAST: internal use
  */
@@ -1936,6 +1980,16 @@
 
 	NL80211_ATTR_TDLS_INITIATOR,
 
+	NL80211_ATTR_USE_RRM,
+
+	NL80211_ATTR_WIPHY_DYN_ACK,
+
+	NL80211_ATTR_TSID,
+	NL80211_ATTR_USER_PRIO,
+	NL80211_ATTR_ADMITTED_TIME,
+
+	NL80211_ATTR_SMPS_MODE,
+
 	/* add attributes here, update the policy in nl80211.c */
 
 	__NL80211_ATTR_AFTER_LAST,
@@ -3055,14 +3109,20 @@
  * @NL80211_BSS_BSSID: BSSID of the BSS (6 octets)
  * @NL80211_BSS_FREQUENCY: frequency in MHz (u32)
  * @NL80211_BSS_TSF: TSF of the received probe response/beacon (u64)
+ *	(if @NL80211_BSS_PRESP_DATA is present then this is known to be
+ *	from a probe response, otherwise it may be from the same beacon
+ *	that the NL80211_BSS_BEACON_TSF will be from)
  * @NL80211_BSS_BEACON_INTERVAL: beacon interval of the (I)BSS (u16)
  * @NL80211_BSS_CAPABILITY: capability field (CPU order, u16)
  * @NL80211_BSS_INFORMATION_ELEMENTS: binary attribute containing the
  *	raw information elements from the probe response/beacon (bin);
- *	if the %NL80211_BSS_BEACON_IES attribute is present, the IEs here are
- *	from a Probe Response frame; otherwise they are from a Beacon frame.
+ *	if the %NL80211_BSS_BEACON_IES attribute is present and the data is
+ *	different then the IEs here are from a Probe Response frame; otherwise
+ *	they are from a Beacon frame.
  *	However, if the driver does not indicate the source of the IEs, these
  *	IEs may be from either frame subtype.
+ *	If present, the @NL80211_BSS_PRESP_DATA attribute indicates that the
+ *	data here is known to be from a probe response, without any heuristics.
  * @NL80211_BSS_SIGNAL_MBM: signal strength of probe response/beacon
  *	in mBm (100 * dBm) (s32)
  * @NL80211_BSS_SIGNAL_UNSPEC: signal strength of the probe response/beacon
@@ -3074,6 +3134,10 @@
  *	yet been received
  * @NL80211_BSS_CHAN_WIDTH: channel width of the control channel
  *	(u32, enum nl80211_bss_scan_width)
+ * @NL80211_BSS_BEACON_TSF: TSF of the last received beacon (u64)
+ *	(not present if no beacon frame has been received yet)
+ * @NL80211_BSS_PRESP_DATA: the data in @NL80211_BSS_INFORMATION_ELEMENTS and
+ *	@NL80211_BSS_TSF is known to be from a probe response (flag attribute)
  * @__NL80211_BSS_AFTER_LAST: internal
  * @NL80211_BSS_MAX: highest BSS attribute
  */
@@ -3091,6 +3155,8 @@
 	NL80211_BSS_SEEN_MS_AGO,
 	NL80211_BSS_BEACON_IES,
 	NL80211_BSS_CHAN_WIDTH,
+	NL80211_BSS_BEACON_TSF,
+	NL80211_BSS_PRESP_DATA,
 
 	/* keep last */
 	__NL80211_BSS_AFTER_LAST,
@@ -3956,6 +4022,26 @@
  * @NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE: This driver supports dynamic
  *	channel bandwidth change (e.g., HT 20 <-> 40 MHz channel) during the
  *	lifetime of a BSS.
+ * @NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES: This device adds a DS Parameter
+ *	Set IE to probe requests.
+ * @NL80211_FEATURE_WFA_TPC_IE_IN_PROBES: This device adds a WFA TPC Report IE
+ *	to probe requests.
+ * @NL80211_FEATURE_QUIET: This device, in client mode, supports Quiet Period
+ *	requests sent to it by an AP.
+ * @NL80211_FEATURE_TX_POWER_INSERTION: This device is capable of inserting the
+ *	current tx power value into the TPC Report IE in the spectrum
+ *	management TPC Report action frame, and in the Radio Measurement Link
+ *	Measurement Report action frame.
+ * @NL80211_FEATURE_ACKTO_ESTIMATION: This driver supports dynamic ACK timeout
+ *	estimation (dynack). %NL80211_ATTR_WIPHY_DYN_ACK flag attribute is used
+ *	to enable dynack.
+ * @NL80211_FEATURE_STATIC_SMPS: Device supports static spatial
+ *	multiplexing powersave, ie. can turn off all but one chain
+ *	even on HT connections that should be using more chains.
+ * @NL80211_FEATURE_DYNAMIC_SMPS: Device supports dynamic spatial
+ *	multiplexing powersave, ie. can turn off all but one chain
+ *	and then wake the rest up as required after, for example,
+ *	rts/cts handshake.
  */
 enum nl80211_feature_flags {
 	NL80211_FEATURE_SK_TX_STATUS			= 1 << 0,
@@ -3977,6 +4063,13 @@
 	NL80211_FEATURE_USERSPACE_MPM			= 1 << 16,
 	NL80211_FEATURE_ACTIVE_MONITOR			= 1 << 17,
 	NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE	= 1 << 18,
+	NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES	= 1 << 19,
+	NL80211_FEATURE_WFA_TPC_IE_IN_PROBES		= 1 << 20,
+	NL80211_FEATURE_QUIET				= 1 << 21,
+	NL80211_FEATURE_TX_POWER_INSERTION		= 1 << 22,
+	NL80211_FEATURE_ACKTO_ESTIMATION		= 1 << 23,
+	NL80211_FEATURE_STATIC_SMPS			= 1 << 24,
+	NL80211_FEATURE_DYNAMIC_SMPS			= 1 << 25,
 };
 
 /**
@@ -4051,6 +4144,25 @@
 };
 
 /**
+ * enum nl80211_smps_mode - SMPS mode
+ *
+ * Requested SMPS mode (for AP mode)
+ *
+ * @NL80211_SMPS_OFF: SMPS off (use all antennas).
+ * @NL80211_SMPS_STATIC: static SMPS (use a single antenna)
+ * @NL80211_SMPS_DYNAMIC: dynamic smps (start with a single antenna and
+ *	turn on other antennas after CTS/RTS).
+ */
+enum nl80211_smps_mode {
+	NL80211_SMPS_OFF,
+	NL80211_SMPS_STATIC,
+	NL80211_SMPS_DYNAMIC,
+
+	__NL80211_SMPS_AFTER_LAST,
+	NL80211_SMPS_MAX = __NL80211_SMPS_AFTER_LAST - 1
+};
+
+/**
  * enum nl80211_radar_event - type of radar event for DFS operation
  *
  * Type of event to be used with NL80211_ATTR_RADAR_EVENT to inform userspace
diff -urN linux/include/uapi/linux/openvswitch.h net-next-2.6/include/uapi/linux/openvswitch.h
--- linux/include/uapi/linux/openvswitch.h	2014-09-24 09:52:39.980610787 +0200
+++ net-next-2.6/include/uapi/linux/openvswitch.h	2014-10-06 10:48:56.640863866 +0200
@@ -192,6 +192,7 @@
 	OVS_VPORT_TYPE_INTERNAL, /* network device implemented by datapath */
 	OVS_VPORT_TYPE_GRE,      /* GRE tunnel. */
 	OVS_VPORT_TYPE_VXLAN,	 /* VXLAN tunnel. */
+	OVS_VPORT_TYPE_GENEVE,	 /* Geneve tunnel. */
 	__OVS_VPORT_TYPE_MAX
 };
 
@@ -289,9 +290,12 @@
 	OVS_KEY_ATTR_TUNNEL,    /* Nested set of ovs_tunnel attributes */
 	OVS_KEY_ATTR_SCTP,      /* struct ovs_key_sctp */
 	OVS_KEY_ATTR_TCP_FLAGS,	/* be16 TCP flags. */
+	OVS_KEY_ATTR_DP_HASH,      /* u32 hash value. Value 0 indicates the hash
+				   is not computed by the datapath. */
+	OVS_KEY_ATTR_RECIRC_ID, /* u32 recirc id */
 
 #ifdef __KERNEL__
-	OVS_KEY_ATTR_IPV4_TUNNEL,  /* struct ovs_key_ipv4_tunnel */
+	OVS_KEY_ATTR_TUNNEL_INFO,  /* struct ovs_tunnel_info */
 #endif
 	__OVS_KEY_ATTR_MAX
 };
@@ -306,6 +310,8 @@
 	OVS_TUNNEL_KEY_ATTR_TTL,                /* u8 Tunnel IP TTL. */
 	OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT,      /* No argument, set DF. */
 	OVS_TUNNEL_KEY_ATTR_CSUM,               /* No argument. CSUM packet. */
+	OVS_TUNNEL_KEY_ATTR_OAM,                /* No argument. OAM frame.  */
+	OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,        /* Array of Geneve options. */
 	__OVS_TUNNEL_KEY_ATTR_MAX
 };
 
@@ -493,6 +499,27 @@
 	__be16 vlan_tci;	/* 802.1Q TCI (VLAN ID and priority). */
 };
 
+/* Data path hash algorithm for computing Datapath hash.
+ *
+ * The algorithm type only specifies the fields in a flow
+ * will be used as part of the hash. Each datapath is free
+ * to use its own hash algorithm. The hash value will be
+ * opaque to the user space daemon.
+ */
+enum ovs_hash_alg {
+	OVS_HASH_ALG_L4,
+};
+
+/*
+ * struct ovs_action_hash - %OVS_ACTION_ATTR_HASH action argument.
+ * @hash_alg: Algorithm used to compute hash prior to recirculation.
+ * @hash_basis: basis used for computing hash.
+ */
+struct ovs_action_hash {
+	uint32_t  hash_alg;     /* One of ovs_hash_alg. */
+	uint32_t  hash_basis;
+};
+
 /**
  * enum ovs_action_attr - Action types.
  *
@@ -521,6 +548,8 @@
 	OVS_ACTION_ATTR_PUSH_VLAN,    /* struct ovs_action_push_vlan. */
 	OVS_ACTION_ATTR_POP_VLAN,     /* No argument. */
 	OVS_ACTION_ATTR_SAMPLE,       /* Nested OVS_SAMPLE_ATTR_*. */
+	OVS_ACTION_ATTR_RECIRC,       /* u32 recirc_id. */
+	OVS_ACTION_ATTR_HASH,	      /* struct ovs_action_hash. */
 	__OVS_ACTION_ATTR_MAX
 };
 
diff -urN linux/include/uapi/linux/wil6210_uapi.h net-next-2.6/include/uapi/linux/wil6210_uapi.h
--- linux/include/uapi/linux/wil6210_uapi.h	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/include/uapi/linux/wil6210_uapi.h	2014-10-06 10:48:56.656864030 +0200
@@ -0,0 +1,87 @@
+/*
+ * Copyright (c) 2014 Qualcomm Atheros, Inc.
+ *
+ * Permission to use, copy, modify, and/or distribute this software for any
+ * purpose with or without fee is hereby granted, provided that the above
+ * copyright notice and this permission notice appear in all copies.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
+ * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
+ * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
+ * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
+ * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
+ * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
+ * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
+ */
+
+#ifndef __WIL6210_UAPI_H__
+#define __WIL6210_UAPI_H__
+
+#if !defined(__KERNEL__)
+#define __user
+#endif
+
+#include <linux/sockios.h>
+
+/* Numbers SIOCDEVPRIVATE and SIOCDEVPRIVATE + 1
+ * are used by Android devices to implement PNO (preferred network offload).
+ * Albeit it is temporary solution, use different numbers to avoid conflicts
+ */
+
+/**
+ * Perform 32-bit I/O operation to the card memory
+ *
+ * User code should arrange data in memory like this:
+ *
+ *	struct wil_memio io;
+ *	struct ifreq ifr = {
+ *		.ifr_data = &io,
+ *	};
+ */
+#define WIL_IOCTL_MEMIO (SIOCDEVPRIVATE + 2)
+
+/**
+ * Perform block I/O operation to the card memory
+ *
+ * User code should arrange data in memory like this:
+ *
+ *	void *buf;
+ *	struct wil_memio_block io = {
+ *		.block = buf,
+ *	};
+ *	struct ifreq ifr = {
+ *		.ifr_data = &io,
+ *	};
+ */
+#define WIL_IOCTL_MEMIO_BLOCK (SIOCDEVPRIVATE + 3)
+
+/**
+ * operation to perform
+ *
+ * @wil_mmio_op_mask - bits defining operation,
+ * @wil_mmio_addr_mask - bits defining addressing mode
+ */
+enum wil_memio_op {
+	wil_mmio_read = 0,
+	wil_mmio_write = 1,
+	wil_mmio_op_mask = 0xff,
+	wil_mmio_addr_linker = 0 << 8,
+	wil_mmio_addr_ahb = 1 << 8,
+	wil_mmio_addr_bar = 2 << 8,
+	wil_mmio_addr_mask = 0xff00,
+};
+
+struct wil_memio {
+	uint32_t op; /* enum wil_memio_op */
+	uint32_t addr; /* should be 32-bit aligned */
+	uint32_t val;
+};
+
+struct wil_memio_block {
+	uint32_t op; /* enum wil_memio_op */
+	uint32_t addr; /* should be 32-bit aligned */
+	uint32_t size; /* should be multiple of 4 */
+	void __user *block; /* block address */
+};
+
+#endif /* __WIL6210_UAPI_H__ */
diff -urN linux/include/uapi/linux/xfrm.h net-next-2.6/include/uapi/linux/xfrm.h
--- linux/include/uapi/linux/xfrm.h	2014-09-24 09:52:40.032611332 +0200
+++ net-next-2.6/include/uapi/linux/xfrm.h	2014-10-06 10:48:56.656864030 +0200
@@ -328,6 +328,8 @@
 	XFRMA_SPD_UNSPEC,
 	XFRMA_SPD_INFO,
 	XFRMA_SPD_HINFO,
+	XFRMA_SPD_IPV4_HTHRESH,
+	XFRMA_SPD_IPV6_HTHRESH,
 	__XFRMA_SPD_MAX
 
 #define XFRMA_SPD_MAX (__XFRMA_SPD_MAX - 1)
@@ -347,6 +349,11 @@
 	__u32 spdhmcnt;
 };
 
+struct xfrmu_spdhthresh {
+	__u8 lbits;
+	__u8 rbits;
+};
+
 struct xfrm_usersa_info {
 	struct xfrm_selector		sel;
 	struct xfrm_id			id;
