diff -urN linux/net/bridge/br.c net-next-2.6/net/bridge/br.c
--- linux/net/bridge/br.c	2014-09-24 09:52:43.080643326 +0200
+++ net-next-2.6/net/bridge/br.c	2014-10-06 10:48:59.672894766 +0200
@@ -161,7 +161,7 @@
 	if (err)
 		goto err_out1;
 
-	err = br_netfilter_init();
+	err = br_nf_core_init();
 	if (err)
 		goto err_out2;
 
@@ -179,11 +179,16 @@
 	br_fdb_test_addr_hook = br_fdb_test_addr;
 #endif
 
+	pr_info("bridge: automatic filtering via arp/ip/ip6tables has been "
+		"deprecated. Update your scripts to load br_netfilter if you "
+		"need this.\n");
+
 	return 0;
+
 err_out4:
 	unregister_netdevice_notifier(&br_device_notifier);
 err_out3:
-	br_netfilter_fini();
+	br_nf_core_fini();
 err_out2:
 	unregister_pernet_subsys(&br_net_ops);
 err_out1:
@@ -196,20 +201,17 @@
 static void __exit br_deinit(void)
 {
 	stp_proto_unregister(&br_stp_proto);
-
 	br_netlink_fini();
 	unregister_netdevice_notifier(&br_device_notifier);
 	brioctl_set(NULL);
-
 	unregister_pernet_subsys(&br_net_ops);
 
 	rcu_barrier(); /* Wait for completion of call_rcu()'s */
 
-	br_netfilter_fini();
+	br_nf_core_fini();
 #if IS_ENABLED(CONFIG_ATM_LANE)
 	br_fdb_test_addr_hook = NULL;
 #endif
-
 	br_fdb_fini();
 }
 
diff -urN linux/net/bridge/br_device.c net-next-2.6/net/bridge/br_device.c
--- linux/net/bridge/br_device.c	2014-09-24 09:52:43.080643326 +0200
+++ net-next-2.6/net/bridge/br_device.c	2014-10-06 10:48:59.672894766 +0200
@@ -36,7 +36,7 @@
 	u16 vid = 0;
 
 	rcu_read_lock();
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	if (skb->nf_bridge && (skb->nf_bridge->mask & BRNF_BRIDGED_DNAT)) {
 		br_nf_pre_routing_finish_bridge_slow(skb);
 		rcu_read_unlock();
@@ -88,12 +88,17 @@
 static int br_dev_init(struct net_device *dev)
 {
 	struct net_bridge *br = netdev_priv(dev);
+	int err;
 
 	br->stats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
 	if (!br->stats)
 		return -ENOMEM;
 
-	return 0;
+	err = br_vlan_init(br);
+	if (err)
+		free_percpu(br->stats);
+
+	return err;
 }
 
 static int br_dev_open(struct net_device *dev)
@@ -167,7 +172,7 @@
 
 	dev->mtu = new_mtu;
 
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	/* remember the MTU in the rtable for PMTU */
 	dst_metric_set(&br->fake_rtable.dst, RTAX_MTU, new_mtu);
 #endif
@@ -389,5 +394,4 @@
 	br_netfilter_rtable_init(br);
 	br_stp_timer_init(br);
 	br_multicast_init(br);
-	br_vlan_init(br);
 }
diff -urN linux/net/bridge/br_forward.c net-next-2.6/net/bridge/br_forward.c
--- linux/net/bridge/br_forward.c	2014-09-24 09:52:43.080643326 +0200
+++ net-next-2.6/net/bridge/br_forward.c	2014-10-06 10:48:59.672894766 +0200
@@ -49,6 +49,7 @@
 
 	return 0;
 }
+EXPORT_SYMBOL_GPL(br_dev_queue_push_xmit);
 
 int br_forward_finish(struct sk_buff *skb)
 {
@@ -56,6 +57,7 @@
 		       br_dev_queue_push_xmit);
 
 }
+EXPORT_SYMBOL_GPL(br_forward_finish);
 
 static void __br_deliver(const struct net_bridge_port *to, struct sk_buff *skb)
 {
diff -urN linux/net/bridge/br_if.c net-next-2.6/net/bridge/br_if.c
--- linux/net/bridge/br_if.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_if.c	2014-10-06 10:48:59.672894766 +0200
@@ -252,12 +252,12 @@
 	br_fdb_delete_by_port(br, p, 1);
 	nbp_update_port_count(br);
 
+	netdev_upper_dev_unlink(dev, br->dev);
+
 	dev->priv_flags &= ~IFF_BRIDGE_PORT;
 
 	netdev_rx_handler_unregister(dev);
 
-	netdev_upper_dev_unlink(dev, br->dev);
-
 	br_multicast_del_port(p);
 
 	kobject_uevent(&p->kobj, KOBJ_REMOVE);
@@ -332,7 +332,7 @@
 	p->port_no = index;
 	p->flags = BR_LEARNING | BR_FLOOD;
 	br_init_port(p);
-	p->state = BR_STATE_DISABLED;
+	br_set_state(p, BR_STATE_DISABLED);
 	br_stp_port_timer_init(p);
 	br_multicast_add_port(p);
 
@@ -476,16 +476,16 @@
 	if (err)
 		goto err3;
 
-	err = netdev_master_upper_dev_link(dev, br->dev);
+	err = netdev_rx_handler_register(dev, br_handle_frame, p);
 	if (err)
 		goto err4;
 
-	err = netdev_rx_handler_register(dev, br_handle_frame, p);
+	dev->priv_flags |= IFF_BRIDGE_PORT;
+
+	err = netdev_master_upper_dev_link(dev, br->dev);
 	if (err)
 		goto err5;
 
-	dev->priv_flags |= IFF_BRIDGE_PORT;
-
 	dev_disable_lro(dev);
 
 	list_add_rcu(&p->list, &br->port_list);
@@ -500,6 +500,9 @@
 	if (br_fdb_insert(br, p, dev->dev_addr, 0))
 		netdev_err(dev, "failed insert local address bridge forwarding table\n");
 
+	if (nbp_vlan_init(p))
+		netdev_err(dev, "failed to initialize vlan filtering on this port\n");
+
 	spin_lock_bh(&br->lock);
 	changed_addr = br_stp_recalculate_bridge_id(br);
 
@@ -520,7 +523,8 @@
 	return 0;
 
 err5:
-	netdev_upper_dev_unlink(dev, br->dev);
+	dev->priv_flags &= ~IFF_BRIDGE_PORT;
+	netdev_rx_handler_unregister(dev);
 err4:
 	br_netpoll_disable(p);
 err3:
diff -urN linux/net/bridge/br_input.c net-next-2.6/net/bridge/br_input.c
--- linux/net/bridge/br_input.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_input.c	2014-10-06 10:48:59.672894766 +0200
@@ -140,6 +140,7 @@
 	kfree_skb(skb);
 	goto out;
 }
+EXPORT_SYMBOL_GPL(br_handle_frame_finish);
 
 /* note: already called with rcu_read_lock */
 static int br_handle_local_finish(struct sk_buff *skb)
diff -urN linux/net/bridge/br_multicast.c net-next-2.6/net/bridge/br_multicast.c
--- linux/net/bridge/br_multicast.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_multicast.c	2014-10-06 10:48:59.672894766 +0200
@@ -1822,7 +1822,7 @@
 	if (query->startup_sent < br->multicast_startup_query_count)
 		query->startup_sent++;
 
-	rcu_assign_pointer(querier, NULL);
+	RCU_INIT_POINTER(querier, NULL);
 	br_multicast_send_query(br, NULL, query);
 	spin_unlock(&br->multicast_lock);
 }
diff -urN linux/net/bridge/br_netfilter.c net-next-2.6/net/bridge/br_netfilter.c
--- linux/net/bridge/br_netfilter.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_netfilter.c	2014-10-06 10:48:59.676894807 +0200
@@ -111,66 +111,6 @@
 	 pppoe_proto(skb) == htons(PPP_IPV6) && \
 	 brnf_filter_pppoe_tagged)
 
-static void fake_update_pmtu(struct dst_entry *dst, struct sock *sk,
-			     struct sk_buff *skb, u32 mtu)
-{
-}
-
-static void fake_redirect(struct dst_entry *dst, struct sock *sk,
-			  struct sk_buff *skb)
-{
-}
-
-static u32 *fake_cow_metrics(struct dst_entry *dst, unsigned long old)
-{
-	return NULL;
-}
-
-static struct neighbour *fake_neigh_lookup(const struct dst_entry *dst,
-					   struct sk_buff *skb,
-					   const void *daddr)
-{
-	return NULL;
-}
-
-static unsigned int fake_mtu(const struct dst_entry *dst)
-{
-	return dst->dev->mtu;
-}
-
-static struct dst_ops fake_dst_ops = {
-	.family =		AF_INET,
-	.protocol =		cpu_to_be16(ETH_P_IP),
-	.update_pmtu =		fake_update_pmtu,
-	.redirect =		fake_redirect,
-	.cow_metrics =		fake_cow_metrics,
-	.neigh_lookup =		fake_neigh_lookup,
-	.mtu =			fake_mtu,
-};
-
-/*
- * Initialize bogus route table used to keep netfilter happy.
- * Currently, we fill in the PMTU entry because netfilter
- * refragmentation needs it, and the rt_flags entry because
- * ipt_REJECT needs it.  Future netfilter modules might
- * require us to fill additional fields.
- */
-static const u32 br_dst_default_metrics[RTAX_MAX] = {
-	[RTAX_MTU - 1] = 1500,
-};
-
-void br_netfilter_rtable_init(struct net_bridge *br)
-{
-	struct rtable *rt = &br->fake_rtable;
-
-	atomic_set(&rt->dst.__refcnt, 1);
-	rt->dst.dev = br->dev;
-	rt->dst.path = &rt->dst;
-	dst_init_metrics(&rt->dst, br_dst_default_metrics, true);
-	rt->dst.flags	= DST_NOXFRM | DST_FAKE_RTABLE;
-	rt->dst.ops = &fake_dst_ops;
-}
-
 static inline struct rtable *bridge_parent_rtable(const struct net_device *dev)
 {
 	struct net_bridge_port *port;
@@ -245,14 +185,6 @@
 					 skb->nf_bridge->data, header_size);
 }
 
-static inline void nf_bridge_update_protocol(struct sk_buff *skb)
-{
-	if (skb->nf_bridge->mask & BRNF_8021Q)
-		skb->protocol = htons(ETH_P_8021Q);
-	else if (skb->nf_bridge->mask & BRNF_PPPoE)
-		skb->protocol = htons(ETH_P_PPP_SES);
-}
-
 /* When handing a packet over to the IP layer
  * check whether we have a skb that is in the
  * expected format
@@ -320,26 +252,6 @@
 	return -1;
 }
 
-/* Fill in the header for fragmented IP packets handled by
- * the IPv4 connection tracking code.
- */
-int nf_bridge_copy_header(struct sk_buff *skb)
-{
-	int err;
-	unsigned int header_size;
-
-	nf_bridge_update_protocol(skb);
-	header_size = ETH_HLEN + nf_bridge_encap_header_len(skb);
-	err = skb_cow_head(skb, header_size);
-	if (err)
-		return err;
-
-	skb_copy_to_linear_data_offset(skb, -header_size,
-				       skb->nf_bridge->data, header_size);
-	__skb_push(skb, nf_bridge_encap_header_len(skb));
-	return 0;
-}
-
 /* PF_BRIDGE/PRE_ROUTING *********************************************/
 /* Undo the changes made for ip6tables PREROUTING and continue the
  * bridge PRE_ROUTING hook. */
@@ -944,6 +856,11 @@
 	return NF_ACCEPT;
 }
 
+void br_netfilter_enable(void)
+{
+}
+EXPORT_SYMBOL_GPL(br_netfilter_enable);
+
 /* For br_nf_post_routing, we need (prio = NF_BR_PRI_LAST), because
  * br_dev_queue_push_xmit is called afterwards */
 static struct nf_hook_ops br_nf_ops[] __read_mostly = {
@@ -1059,38 +976,42 @@
 };
 #endif
 
-int __init br_netfilter_init(void)
+static int __init br_netfilter_init(void)
 {
 	int ret;
 
-	ret = dst_entries_init(&fake_dst_ops);
+	ret = nf_register_hooks(br_nf_ops, ARRAY_SIZE(br_nf_ops));
 	if (ret < 0)
 		return ret;
 
-	ret = nf_register_hooks(br_nf_ops, ARRAY_SIZE(br_nf_ops));
-	if (ret < 0) {
-		dst_entries_destroy(&fake_dst_ops);
-		return ret;
-	}
 #ifdef CONFIG_SYSCTL
 	brnf_sysctl_header = register_net_sysctl(&init_net, "net/bridge", brnf_table);
 	if (brnf_sysctl_header == NULL) {
 		printk(KERN_WARNING
 		       "br_netfilter: can't register to sysctl.\n");
-		nf_unregister_hooks(br_nf_ops, ARRAY_SIZE(br_nf_ops));
-		dst_entries_destroy(&fake_dst_ops);
-		return -ENOMEM;
+		ret = -ENOMEM;
+		goto err1;
 	}
 #endif
 	printk(KERN_NOTICE "Bridge firewalling registered\n");
 	return 0;
+err1:
+	nf_unregister_hooks(br_nf_ops, ARRAY_SIZE(br_nf_ops));
+	return ret;
 }
 
-void br_netfilter_fini(void)
+static void __exit br_netfilter_fini(void)
 {
 	nf_unregister_hooks(br_nf_ops, ARRAY_SIZE(br_nf_ops));
 #ifdef CONFIG_SYSCTL
 	unregister_net_sysctl_table(brnf_sysctl_header);
 #endif
-	dst_entries_destroy(&fake_dst_ops);
 }
+
+module_init(br_netfilter_init);
+module_exit(br_netfilter_fini);
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Lennert Buytenhek <buytenh@gnu.org>");
+MODULE_AUTHOR("Bart De Schuymer <bdschuym@pandora.be>");
+MODULE_DESCRIPTION("Linux ethernet netfilter firewall bridge");
diff -urN linux/net/bridge/br_netlink.c net-next-2.6/net/bridge/br_netlink.c
--- linux/net/bridge/br_netlink.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_netlink.c	2014-10-06 10:48:59.676894807 +0200
@@ -257,9 +257,6 @@
 			} else
 				err = br_vlan_add(br, vinfo->vid, vinfo->flags);
 
-			if (err)
-				break;
-
 			break;
 
 		case RTM_DELLINK:
@@ -276,7 +273,7 @@
 	return err;
 }
 
-static const struct nla_policy ifla_brport_policy[IFLA_BRPORT_MAX + 1] = {
+static const struct nla_policy br_port_policy[IFLA_BRPORT_MAX + 1] = {
 	[IFLA_BRPORT_STATE]	= { .type = NLA_U8 },
 	[IFLA_BRPORT_COST]	= { .type = NLA_U32 },
 	[IFLA_BRPORT_PRIORITY]	= { .type = NLA_U16 },
@@ -304,7 +301,7 @@
 	    (!netif_oper_up(p->dev) && state != BR_STATE_DISABLED))
 		return -ENETDOWN;
 
-	p->state = state;
+	br_set_state(p, state);
 	br_log_state(p);
 	br_port_state_selection(p->br);
 	return 0;
@@ -382,7 +379,7 @@
 	if (p && protinfo) {
 		if (protinfo->nla_type & NLA_F_NESTED) {
 			err = nla_parse_nested(tb, IFLA_BRPORT_MAX,
-					       protinfo, ifla_brport_policy);
+					       protinfo, br_port_policy);
 			if (err)
 				return err;
 
@@ -461,6 +458,88 @@
 	return register_netdevice(dev);
 }
 
+static int br_port_slave_changelink(struct net_device *brdev,
+				    struct net_device *dev,
+				    struct nlattr *tb[],
+				    struct nlattr *data[])
+{
+	if (!data)
+		return 0;
+	return br_setport(br_port_get_rtnl(dev), data);
+}
+
+static int br_port_fill_slave_info(struct sk_buff *skb,
+				   const struct net_device *brdev,
+				   const struct net_device *dev)
+{
+	return br_port_fill_attrs(skb, br_port_get_rtnl(dev));
+}
+
+static size_t br_port_get_slave_size(const struct net_device *brdev,
+				     const struct net_device *dev)
+{
+	return br_port_info_size();
+}
+
+static const struct nla_policy br_policy[IFLA_BR_MAX + 1] = {
+	[IFLA_BR_FORWARD_DELAY]	= { .type = NLA_U32 },
+	[IFLA_BR_HELLO_TIME]	= { .type = NLA_U32 },
+	[IFLA_BR_MAX_AGE]	= { .type = NLA_U32 },
+};
+
+static int br_changelink(struct net_device *brdev, struct nlattr *tb[],
+			 struct nlattr *data[])
+{
+	struct net_bridge *br = netdev_priv(brdev);
+	int err;
+
+	if (!data)
+		return 0;
+
+	if (data[IFLA_BR_FORWARD_DELAY]) {
+		err = br_set_forward_delay(br, nla_get_u32(data[IFLA_BR_FORWARD_DELAY]));
+		if (err)
+			return err;
+	}
+
+	if (data[IFLA_BR_HELLO_TIME]) {
+		err = br_set_hello_time(br, nla_get_u32(data[IFLA_BR_HELLO_TIME]));
+		if (err)
+			return err;
+	}
+
+	if (data[IFLA_BR_MAX_AGE]) {
+		err = br_set_max_age(br, nla_get_u32(data[IFLA_BR_MAX_AGE]));
+		if (err)
+			return err;
+	}
+
+	return 0;
+}
+
+static size_t br_get_size(const struct net_device *brdev)
+{
+	return nla_total_size(sizeof(u32)) +	/* IFLA_BR_FORWARD_DELAY  */
+	       nla_total_size(sizeof(u32)) +	/* IFLA_BR_HELLO_TIME */
+	       nla_total_size(sizeof(u32)) +	/* IFLA_BR_MAX_AGE */
+	       0;
+}
+
+static int br_fill_info(struct sk_buff *skb, const struct net_device *brdev)
+{
+	struct net_bridge *br = netdev_priv(brdev);
+	u32 forward_delay = jiffies_to_clock_t(br->forward_delay);
+	u32 hello_time = jiffies_to_clock_t(br->hello_time);
+	u32 age_time = jiffies_to_clock_t(br->max_age);
+
+	if (nla_put_u32(skb, IFLA_BR_FORWARD_DELAY, forward_delay) ||
+	    nla_put_u32(skb, IFLA_BR_HELLO_TIME, hello_time) ||
+	    nla_put_u32(skb, IFLA_BR_MAX_AGE, age_time))
+		return -EMSGSIZE;
+
+	return 0;
+}
+
 static size_t br_get_link_af_size(const struct net_device *dev)
 {
 	struct net_port_vlans *pv;
@@ -485,12 +564,23 @@
 };
 
 struct rtnl_link_ops br_link_ops __read_mostly = {
-	.kind		= "bridge",
-	.priv_size	= sizeof(struct net_bridge),
-	.setup		= br_dev_setup,
-	.validate	= br_validate,
-	.newlink	= br_dev_newlink,
-	.dellink	= br_dev_delete,
+	.kind			= "bridge",
+	.priv_size		= sizeof(struct net_bridge),
+	.setup			= br_dev_setup,
+	.maxtype		= IFLA_BRPORT_MAX,
+	.policy			= br_policy,
+	.validate		= br_validate,
+	.newlink		= br_dev_newlink,
+	.changelink		= br_changelink,
+	.dellink		= br_dev_delete,
+	.get_size		= br_get_size,
+	.fill_info		= br_fill_info,
+
+	.slave_maxtype		= IFLA_BRPORT_MAX,
+	.slave_policy		= br_port_policy,
+	.slave_changelink	= br_port_slave_changelink,
+	.get_slave_size		= br_port_get_slave_size,
+	.fill_slave_info	= br_port_fill_slave_info,
 };
 
 int __init br_netlink_init(void)
@@ -512,7 +602,7 @@
 	return err;
 }
 
-void __exit br_netlink_fini(void)
+void br_netlink_fini(void)
 {
 	br_mdb_uninit();
 	rtnl_af_unregister(&br_af_ops);
diff -urN linux/net/bridge/br_nf_core.c net-next-2.6/net/bridge/br_nf_core.c
--- linux/net/bridge/br_nf_core.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/bridge/br_nf_core.c	2014-10-06 10:48:59.676894807 +0200
@@ -0,0 +1,96 @@
+/*
+ *	Handle firewalling core
+ *	Linux ethernet bridge
+ *
+ *	Authors:
+ *	Lennert Buytenhek		<buytenh@gnu.org>
+ *	Bart De Schuymer		<bdschuym@pandora.be>
+ *
+ *	This program is free software; you can redistribute it and/or
+ *	modify it under the terms of the GNU General Public License
+ *	as published by the Free Software Foundation; either version
+ *	2 of the License, or (at your option) any later version.
+ *
+ *	Lennert dedicates this file to Kerstin Wurdinger.
+ */
+
+#include <linux/module.h>
+#include <linux/kernel.h>
+#include <linux/in_route.h>
+#include <linux/inetdevice.h>
+#include <net/route.h>
+
+#include "br_private.h"
+#ifdef CONFIG_SYSCTL
+#include <linux/sysctl.h>
+#endif
+
+static void fake_update_pmtu(struct dst_entry *dst, struct sock *sk,
+			     struct sk_buff *skb, u32 mtu)
+{
+}
+
+static void fake_redirect(struct dst_entry *dst, struct sock *sk,
+			  struct sk_buff *skb)
+{
+}
+
+static u32 *fake_cow_metrics(struct dst_entry *dst, unsigned long old)
+{
+	return NULL;
+}
+
+static struct neighbour *fake_neigh_lookup(const struct dst_entry *dst,
+					   struct sk_buff *skb,
+					   const void *daddr)
+{
+	return NULL;
+}
+
+static unsigned int fake_mtu(const struct dst_entry *dst)
+{
+	return dst->dev->mtu;
+}
+
+static struct dst_ops fake_dst_ops = {
+	.family		= AF_INET,
+	.protocol	= cpu_to_be16(ETH_P_IP),
+	.update_pmtu	= fake_update_pmtu,
+	.redirect	= fake_redirect,
+	.cow_metrics	= fake_cow_metrics,
+	.neigh_lookup	= fake_neigh_lookup,
+	.mtu		= fake_mtu,
+};
+
+/*
+ * Initialize bogus route table used to keep netfilter happy.
+ * Currently, we fill in the PMTU entry because netfilter
+ * refragmentation needs it, and the rt_flags entry because
+ * ipt_REJECT needs it.  Future netfilter modules might
+ * require us to fill additional fields.
+ */
+static const u32 br_dst_default_metrics[RTAX_MAX] = {
+	[RTAX_MTU - 1] = 1500,
+};
+
+void br_netfilter_rtable_init(struct net_bridge *br)
+{
+	struct rtable *rt = &br->fake_rtable;
+
+	atomic_set(&rt->dst.__refcnt, 1);
+	rt->dst.dev = br->dev;
+	rt->dst.path = &rt->dst;
+	dst_init_metrics(&rt->dst, br_dst_default_metrics, true);
+	rt->dst.flags	= DST_NOXFRM | DST_FAKE_RTABLE;
+	rt->dst.ops = &fake_dst_ops;
+}
+
+int __init br_nf_core_init(void)
+{
+	return dst_entries_init(&fake_dst_ops);
+}
+
+void br_nf_core_fini(void)
+{
+	dst_entries_destroy(&fake_dst_ops);
+}
diff -urN linux/net/bridge/br_private.h net-next-2.6/net/bridge/br_private.h
--- linux/net/bridge/br_private.h	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_private.h	2014-10-06 10:48:59.676894807 +0200
@@ -221,7 +221,7 @@
 	struct pcpu_sw_netstats		__percpu *stats;
 	spinlock_t			hash_lock;
 	struct hlist_head		hash[BR_HASH_SIZE];
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	struct rtable 			fake_rtable;
 	bool				nf_call_iptables;
 	bool				nf_call_ip6tables;
@@ -299,6 +299,7 @@
 #ifdef CONFIG_BRIDGE_VLAN_FILTERING
 	u8				vlan_enabled;
 	__be16				vlan_proto;
+	u16				default_pvid;
 	struct net_port_vlans __rcu	*vlan_info;
 #endif
 };
@@ -604,11 +605,13 @@
 void br_recalculate_fwd_mask(struct net_bridge *br);
 int br_vlan_filter_toggle(struct net_bridge *br, unsigned long val);
 int br_vlan_set_proto(struct net_bridge *br, unsigned long val);
-void br_vlan_init(struct net_bridge *br);
+int br_vlan_init(struct net_bridge *br);
+int br_vlan_set_default_pvid(struct net_bridge *br, unsigned long val);
 int nbp_vlan_add(struct net_bridge_port *port, u16 vid, u16 flags);
 int nbp_vlan_delete(struct net_bridge_port *port, u16 vid);
 void nbp_vlan_flush(struct net_bridge_port *port);
 bool nbp_vlan_find(struct net_bridge_port *port, u16 vid);
+int nbp_vlan_init(struct net_bridge_port *port);
 
 static inline struct net_port_vlans *br_get_vlan_info(
 						const struct net_bridge *br)
@@ -641,11 +644,11 @@
 
 static inline u16 br_get_pvid(const struct net_port_vlans *v)
 {
-	/* Return just the VID if it is set, or VLAN_N_VID (invalid vid) if
-	 * vid wasn't set
-	 */
+	if (!v)
+		return 0;
+
 	smp_rmb();
-	return v->pvid ?: VLAN_N_VID;
+	return v->pvid;
 }
 
 static inline int br_vlan_enabled(struct net_bridge *br)
@@ -704,8 +707,9 @@
 {
 }
 
-static inline void br_vlan_init(struct net_bridge *br)
+static inline int br_vlan_init(struct net_bridge *br)
 {
+	return 0;
 }
 
 static inline int nbp_vlan_add(struct net_bridge_port *port, u16 vid, u16 flags)
@@ -738,13 +742,18 @@
 	return false;
 }
 
+static inline int nbp_vlan_init(struct net_bridge_port *port)
+{
+	return 0;
+}
+
 static inline u16 br_vlan_get_tag(const struct sk_buff *skb, u16 *tag)
 {
 	return 0;
 }
 static inline u16 br_get_pvid(const struct net_port_vlans *v)
 {
-	return VLAN_N_VID;	/* Returns invalid vid */
+	return 0;
 }
 
 static inline int br_vlan_enabled(struct net_bridge *br)
@@ -754,18 +763,19 @@
 #endif
 
 /* br_netfilter.c */
-#ifdef CONFIG_BRIDGE_NETFILTER
-int br_netfilter_init(void);
-void br_netfilter_fini(void);
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
+int br_nf_core_init(void);
+void br_nf_core_fini(void);
 void br_netfilter_rtable_init(struct net_bridge *);
 #else
-#define br_netfilter_init()	(0)
-#define br_netfilter_fini()	do { } while (0)
+static inline int br_nf_core_init(void) { return 0; }
+static inline void br_nf_core_fini(void) {}
 #define br_netfilter_rtable_init(x)
 #endif
 
 /* br_stp.c */
 void br_log_state(const struct net_bridge_port *p);
+void br_set_state(struct net_bridge_port *p, unsigned int state);
 struct net_bridge_port *br_get_port(struct net_bridge *br, u16 port_no);
 void br_init_port(struct net_bridge_port *p);
 void br_become_designated_port(struct net_bridge_port *p);
diff -urN linux/net/bridge/br_stp.c net-next-2.6/net/bridge/br_stp.c
--- linux/net/bridge/br_stp.c	2013-11-29 12:59:37.167374173 +0100
+++ net-next-2.6/net/bridge/br_stp.c	2014-10-06 10:48:59.676894807 +0200
@@ -36,6 +36,11 @@
 		br_port_state_names[p->state]);
 }
 
+void br_set_state(struct net_bridge_port *p, unsigned int state)
+{
+	p->state = state;
+}
+
 /* called under bridge lock */
 struct net_bridge_port *br_get_port(struct net_bridge *br, u16 port_no)
 {
@@ -107,7 +112,7 @@
 	br_notice(br, "port %u(%s) tried to become root port (blocked)",
 		  (unsigned int) p->port_no, p->dev->name);
 
-	p->state = BR_STATE_LISTENING;
+	br_set_state(p, BR_STATE_LISTENING);
 	br_log_state(p);
 	br_ifinfo_notify(RTM_NEWLINK, p);
 
@@ -387,7 +392,7 @@
 		    p->state == BR_STATE_LEARNING)
 			br_topology_change_detection(p->br);
 
-		p->state = BR_STATE_BLOCKING;
+		br_set_state(p, BR_STATE_BLOCKING);
 		br_log_state(p);
 		br_ifinfo_notify(RTM_NEWLINK, p);
 
@@ -404,13 +409,13 @@
 		return;
 
 	if (br->stp_enabled == BR_NO_STP || br->forward_delay == 0) {
-		p->state = BR_STATE_FORWARDING;
+		br_set_state(p, BR_STATE_FORWARDING);
 		br_topology_change_detection(br);
 		del_timer(&p->forward_delay_timer);
 	} else if (br->stp_enabled == BR_KERNEL_STP)
-		p->state = BR_STATE_LISTENING;
+		br_set_state(p, BR_STATE_LISTENING);
 	else
-		p->state = BR_STATE_LEARNING;
+		br_set_state(p, BR_STATE_LEARNING);
 
 	br_multicast_enable_port(p);
 	br_log_state(p);
diff -urN linux/net/bridge/br_stp_if.c net-next-2.6/net/bridge/br_stp_if.c
--- linux/net/bridge/br_stp_if.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_stp_if.c	2014-10-06 10:48:59.676894807 +0200
@@ -37,7 +37,7 @@
 {
 	p->port_id = br_make_port_id(p->priority, p->port_no);
 	br_become_designated_port(p);
-	p->state = BR_STATE_BLOCKING;
+	br_set_state(p, BR_STATE_BLOCKING);
 	p->topology_change_ack = 0;
 	p->config_pending = 0;
 }
@@ -100,7 +100,7 @@
 
 	wasroot = br_is_root_bridge(br);
 	br_become_designated_port(p);
-	p->state = BR_STATE_DISABLED;
+	br_set_state(p, BR_STATE_DISABLED);
 	p->topology_change_ack = 0;
 	p->config_pending = 0;
 
diff -urN linux/net/bridge/br_stp_timer.c net-next-2.6/net/bridge/br_stp_timer.c
--- linux/net/bridge/br_stp_timer.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_stp_timer.c	2014-10-06 10:48:59.676894807 +0200
@@ -87,11 +87,11 @@
 		 (unsigned int) p->port_no, p->dev->name);
 	spin_lock(&br->lock);
 	if (p->state == BR_STATE_LISTENING) {
-		p->state = BR_STATE_LEARNING;
+		br_set_state(p, BR_STATE_LEARNING);
 		mod_timer(&p->forward_delay_timer,
 			  jiffies + br->forward_delay);
 	} else if (p->state == BR_STATE_LEARNING) {
-		p->state = BR_STATE_FORWARDING;
+		br_set_state(p, BR_STATE_FORWARDING);
 		if (br_is_designated_for_some_port(br))
 			br_topology_change_detection(br);
 		netif_carrier_on(br->dev);
diff -urN linux/net/bridge/br_sysfs_br.c net-next-2.6/net/bridge/br_sysfs_br.c
--- linux/net/bridge/br_sysfs_br.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_sysfs_br.c	2014-10-06 10:48:59.676894807 +0200
@@ -629,7 +629,7 @@
 }
 static DEVICE_ATTR_RW(multicast_startup_query_interval);
 #endif
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 static ssize_t nf_call_iptables_show(
 	struct device *d, struct device_attribute *attr, char *buf)
 {
@@ -725,6 +725,22 @@
 	return store_bridge_parm(d, buf, len, br_vlan_set_proto);
 }
 static DEVICE_ATTR_RW(vlan_protocol);
+
+static ssize_t default_pvid_show(struct device *d,
+				 struct device_attribute *attr,
+				 char *buf)
+{
+	struct net_bridge *br = to_bridge(d);
+	return sprintf(buf, "%d\n", br->default_pvid);
+}
+
+static ssize_t default_pvid_store(struct device *d,
+				  struct device_attribute *attr,
+				  const char *buf, size_t len)
+{
+	return store_bridge_parm(d, buf, len, br_vlan_set_default_pvid);
+}
+static DEVICE_ATTR_RW(default_pvid);
 #endif
 
 static struct attribute *bridge_attrs[] = {
@@ -763,7 +779,7 @@
 	&dev_attr_multicast_query_response_interval.attr,
 	&dev_attr_multicast_startup_query_interval.attr,
 #endif
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	&dev_attr_nf_call_iptables.attr,
 	&dev_attr_nf_call_ip6tables.attr,
 	&dev_attr_nf_call_arptables.attr,
@@ -771,6 +787,7 @@
 #ifdef CONFIG_BRIDGE_VLAN_FILTERING
 	&dev_attr_vlan_filtering.attr,
 	&dev_attr_vlan_protocol.attr,
+	&dev_attr_default_pvid.attr,
 #endif
 	NULL
 };
diff -urN linux/net/bridge/br_vlan.c net-next-2.6/net/bridge/br_vlan.c
--- linux/net/bridge/br_vlan.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/br_vlan.c	2014-10-06 10:48:59.676894807 +0200
@@ -223,7 +223,7 @@
 		 * See if pvid is set on this port.  That tells us which
 		 * vlan untagged or priority-tagged traffic belongs to.
 		 */
-		if (pvid == VLAN_N_VID)
+		if (!pvid)
 			goto drop;
 
 		/* PVID is set on this port.  Any untagged or priority-tagged
@@ -292,7 +292,7 @@
 
 	if (!*vid) {
 		*vid = br_get_pvid(v);
-		if (*vid == VLAN_N_VID)
+		if (!*vid)
 			return false;
 
 		return true;
@@ -499,9 +499,141 @@
 	goto unlock;
 }
 
-void br_vlan_init(struct net_bridge *br)
+static bool vlan_default_pvid(struct net_port_vlans *pv, u16 vid)
+{
+	return pv && vid == pv->pvid && test_bit(vid, pv->untagged_bitmap);
+}
+
+static void br_vlan_disable_default_pvid(struct net_bridge *br)
+{
+	struct net_bridge_port *p;
+	u16 pvid = br->default_pvid;
+
+	/* Disable default_pvid on all ports where it is still
+	 * configured.
+	 */
+	if (vlan_default_pvid(br_get_vlan_info(br), pvid))
+		br_vlan_delete(br, pvid);
+
+	list_for_each_entry(p, &br->port_list, list) {
+		if (vlan_default_pvid(nbp_get_vlan_info(p), pvid))
+			nbp_vlan_delete(p, pvid);
+	}
+
+	br->default_pvid = 0;
+}
+
+static int __br_vlan_set_default_pvid(struct net_bridge *br, u16 pvid)
+{
+	struct net_bridge_port *p;
+	u16 old_pvid;
+	int err = 0;
+	unsigned long *changed;
+
+	changed = kcalloc(BITS_TO_LONGS(BR_MAX_PORTS), sizeof(unsigned long),
+			  GFP_KERNEL);
+	if (!changed)
+		return -ENOMEM;
+
+	old_pvid = br->default_pvid;
+
+	/* Update default_pvid config only if we do not conflict with
+	 * user configuration.
+	 */
+	if ((!old_pvid || vlan_default_pvid(br_get_vlan_info(br), old_pvid)) &&
+	    !br_vlan_find(br, pvid)) {
+		err = br_vlan_add(br, pvid,
+				  BRIDGE_VLAN_INFO_PVID |
+				  BRIDGE_VLAN_INFO_UNTAGGED);
+		if (err)
+			goto out;
+		br_vlan_delete(br, old_pvid);
+		set_bit(0, changed);
+	}
+
+	list_for_each_entry(p, &br->port_list, list) {
+		/* Update default_pvid config only if we do not conflict with
+		 * user configuration.
+		 */
+		if ((old_pvid &&
+		     !vlan_default_pvid(nbp_get_vlan_info(p), old_pvid)) ||
+		    nbp_vlan_find(p, pvid))
+			continue;
+
+		err = nbp_vlan_add(p, pvid,
+				   BRIDGE_VLAN_INFO_PVID |
+				   BRIDGE_VLAN_INFO_UNTAGGED);
+		if (err)
+			goto err_port;
+		nbp_vlan_delete(p, old_pvid);
+		set_bit(p->port_no, changed);
+	}
+
+	br->default_pvid = pvid;
+
+out:
+	kfree(changed);
+	return err;
+
+err_port:
+	list_for_each_entry_continue_reverse(p, &br->port_list, list) {
+		if (!test_bit(p->port_no, changed))
+			continue;
+
+		if (old_pvid)
+			nbp_vlan_add(p, old_pvid,
+				     BRIDGE_VLAN_INFO_PVID |
+				     BRIDGE_VLAN_INFO_UNTAGGED);
+		nbp_vlan_delete(p, pvid);
+	}
+
+	if (test_bit(0, changed)) {
+		if (old_pvid)
+			br_vlan_add(br, old_pvid,
+				    BRIDGE_VLAN_INFO_PVID |
+				    BRIDGE_VLAN_INFO_UNTAGGED);
+		br_vlan_delete(br, pvid);
+	}
+	goto out;
+}
+
+int br_vlan_set_default_pvid(struct net_bridge *br, unsigned long val)
+{
+	u16 pvid = val;
+	int err = 0;
+
+	if (val >= VLAN_VID_MASK)
+		return -EINVAL;
+
+	if (!rtnl_trylock())
+		return restart_syscall();
+
+	if (pvid == br->default_pvid)
+		goto unlock;
+
+	/* Only allow default pvid change when filtering is disabled */
+	if (br->vlan_enabled) {
+		pr_info_once("Please disable vlan filtering to change default_pvid\n");
+		err = -EPERM;
+		goto unlock;
+	}
+
+	if (!pvid)
+		br_vlan_disable_default_pvid(br);
+	else
+		err = __br_vlan_set_default_pvid(br, pvid);
+
+unlock:
+	rtnl_unlock();
+	return err;
+}
+
+int br_vlan_init(struct net_bridge *br)
 {
 	br->vlan_proto = htons(ETH_P_8021Q);
+	br->default_pvid = 1;
+	return br_vlan_add(br, 1,
+			   BRIDGE_VLAN_INFO_PVID | BRIDGE_VLAN_INFO_UNTAGGED);
 }
 
 /* Must be protected by RTNL.
@@ -593,3 +725,12 @@
 	rcu_read_unlock();
 	return found;
 }
+
+int nbp_vlan_init(struct net_bridge_port *p)
+{
+	return p->br->default_pvid ?
+			nbp_vlan_add(p, p->br->default_pvid,
+				     BRIDGE_VLAN_INFO_PVID |
+				     BRIDGE_VLAN_INFO_UNTAGGED) :
+			0;
+}
diff -urN linux/net/bridge/Makefile net-next-2.6/net/bridge/Makefile
--- linux/net/bridge/Makefile	2014-09-24 09:52:43.080643326 +0200
+++ net-next-2.6/net/bridge/Makefile	2014-10-06 10:48:59.672894766 +0200
@@ -10,7 +10,9 @@
 
 bridge-$(CONFIG_SYSFS) += br_sysfs_if.o br_sysfs_br.o
 
-bridge-$(CONFIG_BRIDGE_NETFILTER) += br_netfilter.o
+bridge-$(subst m,y,$(CONFIG_BRIDGE_NETFILTER)) += br_nf_core.o
+
+obj-$(CONFIG_BRIDGE_NETFILTER) += br_netfilter.o
 
 bridge-$(CONFIG_BRIDGE_IGMP_SNOOPING) += br_multicast.o br_mdb.o
 
diff -urN linux/net/bridge/netfilter/ebtables.c net-next-2.6/net/bridge/netfilter/ebtables.c
--- linux/net/bridge/netfilter/ebtables.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/netfilter/ebtables.c	2014-10-06 10:48:59.680894847 +0200
@@ -26,6 +26,7 @@
 #include <asm/uaccess.h>
 #include <linux/smp.h>
 #include <linux/cpumask.h>
+#include <linux/audit.h>
 #include <net/sock.h>
 /* needed for logical [in,out]-dev filtering */
 #include "../br_private.h"
@@ -1058,6 +1059,20 @@
 	vfree(table);
 
 	vfree(counterstmp);
+
+#ifdef CONFIG_AUDIT
+	if (audit_enabled) {
+		struct audit_buffer *ab;
+
+		ab = audit_log_start(current->audit_context, GFP_KERNEL,
+				     AUDIT_NETFILTER_CFG);
+		if (ab) {
+			audit_log_format(ab, "table=%s family=%u entries=%u",
+					 repl->name, AF_BRIDGE, repl->nentries);
+			audit_log_end(ab);
+		}
+	}
+#endif
 	return ret;
 
 free_unlock:
diff -urN linux/net/bridge/netfilter/nf_tables_bridge.c net-next-2.6/net/bridge/netfilter/nf_tables_bridge.c
--- linux/net/bridge/netfilter/nf_tables_bridge.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/netfilter/nf_tables_bridge.c	2014-10-06 10:48:59.680894847 +0200
@@ -34,9 +34,11 @@
 	.owner		= THIS_MODULE,
 	.nops		= 1,
 	.hooks		= {
+		[NF_BR_PRE_ROUTING]	= nft_do_chain_bridge,
 		[NF_BR_LOCAL_IN]	= nft_do_chain_bridge,
 		[NF_BR_FORWARD]		= nft_do_chain_bridge,
 		[NF_BR_LOCAL_OUT]	= nft_do_chain_bridge,
+		[NF_BR_POST_ROUTING]	= nft_do_chain_bridge,
 	},
 };
 
diff -urN linux/net/bridge/netfilter/nft_reject_bridge.c net-next-2.6/net/bridge/netfilter/nft_reject_bridge.c
--- linux/net/bridge/netfilter/nft_reject_bridge.c	2014-09-24 09:52:43.084643367 +0200
+++ net-next-2.6/net/bridge/netfilter/nft_reject_bridge.c	2014-10-06 10:48:59.680894847 +0200
@@ -14,21 +14,106 @@
 #include <linux/netfilter/nf_tables.h>
 #include <net/netfilter/nf_tables.h>
 #include <net/netfilter/nft_reject.h>
+#include <net/netfilter/ipv4/nf_reject.h>
+#include <net/netfilter/ipv6/nf_reject.h>
 
 static void nft_reject_bridge_eval(const struct nft_expr *expr,
 				 struct nft_data data[NFT_REG_MAX + 1],
 				 const struct nft_pktinfo *pkt)
 {
+	struct nft_reject *priv = nft_expr_priv(expr);
+	struct net *net = dev_net((pkt->in != NULL) ? pkt->in : pkt->out);
+
 	switch (eth_hdr(pkt->skb)->h_proto) {
 	case htons(ETH_P_IP):
-		return nft_reject_ipv4_eval(expr, data, pkt);
+		switch (priv->type) {
+		case NFT_REJECT_ICMP_UNREACH:
+			nf_send_unreach(pkt->skb, priv->icmp_code);
+			break;
+		case NFT_REJECT_TCP_RST:
+			nf_send_reset(pkt->skb, pkt->ops->hooknum);
+			break;
+		case NFT_REJECT_ICMPX_UNREACH:
+			nf_send_unreach(pkt->skb,
+					nft_reject_icmp_code(priv->icmp_code));
+			break;
+		}
+		break;
 	case htons(ETH_P_IPV6):
-		return nft_reject_ipv6_eval(expr, data, pkt);
+		switch (priv->type) {
+		case NFT_REJECT_ICMP_UNREACH:
+			nf_send_unreach6(net, pkt->skb, priv->icmp_code,
+					 pkt->ops->hooknum);
+			break;
+		case NFT_REJECT_TCP_RST:
+			nf_send_reset6(net, pkt->skb, pkt->ops->hooknum);
+			break;
+		case NFT_REJECT_ICMPX_UNREACH:
+			nf_send_unreach6(net, pkt->skb,
+					 nft_reject_icmpv6_code(priv->icmp_code),
+					 pkt->ops->hooknum);
+			break;
+		}
+		break;
 	default:
 		/* No explicit way to reject this protocol, drop it. */
-		data[NFT_REG_VERDICT].verdict = NF_DROP;
 		break;
 	}
+	data[NFT_REG_VERDICT].verdict = NF_DROP;
+}
+
+static int nft_reject_bridge_init(const struct nft_ctx *ctx,
+				  const struct nft_expr *expr,
+				  const struct nlattr * const tb[])
+{
+	struct nft_reject *priv = nft_expr_priv(expr);
+	int icmp_code;
+
+	if (tb[NFTA_REJECT_TYPE] == NULL)
+		return -EINVAL;
+
+	priv->type = ntohl(nla_get_be32(tb[NFTA_REJECT_TYPE]));
+	switch (priv->type) {
+	case NFT_REJECT_ICMP_UNREACH:
+	case NFT_REJECT_ICMPX_UNREACH:
+		if (tb[NFTA_REJECT_ICMP_CODE] == NULL)
+			return -EINVAL;
+
+		icmp_code = nla_get_u8(tb[NFTA_REJECT_ICMP_CODE]);
+		if (priv->type == NFT_REJECT_ICMPX_UNREACH &&
+		    icmp_code > NFT_REJECT_ICMPX_MAX)
+			return -EINVAL;
+
+		priv->icmp_code = icmp_code;
+		break;
+	case NFT_REJECT_TCP_RST:
+		break;
+	default:
+		return -EINVAL;
+	}
+	return 0;
+}
+
+static int nft_reject_bridge_dump(struct sk_buff *skb,
+				  const struct nft_expr *expr)
+{
+	const struct nft_reject *priv = nft_expr_priv(expr);
+
+	if (nla_put_be32(skb, NFTA_REJECT_TYPE, htonl(priv->type)))
+		goto nla_put_failure;
+
+	switch (priv->type) {
+	case NFT_REJECT_ICMP_UNREACH:
+	case NFT_REJECT_ICMPX_UNREACH:
+		if (nla_put_u8(skb, NFTA_REJECT_ICMP_CODE, priv->icmp_code))
+			goto nla_put_failure;
+		break;
+	}
+
+	return 0;
+
+nla_put_failure:
+	return -1;
 }
 
 static struct nft_expr_type nft_reject_bridge_type;
@@ -36,8 +121,8 @@
 	.type		= &nft_reject_bridge_type,
 	.size		= NFT_EXPR_SIZE(sizeof(struct nft_reject)),
 	.eval		= nft_reject_bridge_eval,
-	.init		= nft_reject_init,
-	.dump		= nft_reject_dump,
+	.init		= nft_reject_bridge_init,
+	.dump		= nft_reject_bridge_dump,
 };
 
 static struct nft_expr_type nft_reject_bridge_type __read_mostly = {
diff -urN linux/net/netfilter/ipset/ip_set_bitmap_gen.h net-next-2.6/net/netfilter/ipset/ip_set_bitmap_gen.h
--- linux/net/netfilter/ipset/ip_set_bitmap_gen.h	2013-11-29 12:59:37.963382374 +0100
+++ net-next-2.6/net/netfilter/ipset/ip_set_bitmap_gen.h	2014-10-06 10:49:03.424933002 +0200
@@ -128,6 +128,8 @@
 		return 0;
 	if (SET_WITH_COUNTER(set))
 		ip_set_update_counter(ext_counter(x, set), ext, mext, flags);
+	if (SET_WITH_SKBINFO(set))
+		ip_set_get_skbinfo(ext_skbinfo(x, set), ext, mext, flags);
 	return 1;
 }
 
@@ -161,6 +163,8 @@
 		ip_set_init_counter(ext_counter(x, set), ext);
 	if (SET_WITH_COMMENT(set))
 		ip_set_init_comment(ext_comment(x, set), ext);
+	if (SET_WITH_SKBINFO(set))
+		ip_set_init_skbinfo(ext_skbinfo(x, set), ext);
 	return 0;
 }
 
diff -urN linux/net/netfilter/ipset/ip_set_bitmap_ip.c net-next-2.6/net/netfilter/ipset/ip_set_bitmap_ip.c
--- linux/net/netfilter/ipset/ip_set_bitmap_ip.c	2013-11-29 12:59:37.963382374 +0100
+++ net-next-2.6/net/netfilter/ipset/ip_set_bitmap_ip.c	2014-10-06 10:49:03.424933002 +0200
@@ -27,7 +27,8 @@
 
 #define IPSET_TYPE_REV_MIN	0
 /*				1	   Counter support added */
-#define IPSET_TYPE_REV_MAX	2	/* Comment support added */
+/*				2	   Comment support added */
+#define IPSET_TYPE_REV_MAX	3	/* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -112,7 +113,7 @@
 {
 	struct bitmap_ip *map = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct bitmap_ip_adt_elem e = { };
+	struct bitmap_ip_adt_elem e = { .id = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 	u32 ip;
 
@@ -132,14 +133,17 @@
 	struct bitmap_ip *map = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
 	u32 ip = 0, ip_to = 0;
-	struct bitmap_ip_adt_elem e = { };
+	struct bitmap_ip_adt_elem e = { .id = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	int ret = 0;
 
 	if (unlikely(!tb[IPSET_ATTR_IP] ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)   ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -357,6 +361,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_bitmap_ipmac.c net-next-2.6/net/netfilter/ipset/ip_set_bitmap_ipmac.c
--- linux/net/netfilter/ipset/ip_set_bitmap_ipmac.c	2013-11-29 12:59:37.963382374 +0100
+++ net-next-2.6/net/netfilter/ipset/ip_set_bitmap_ipmac.c	2014-10-06 10:49:03.424933002 +0200
@@ -27,7 +27,8 @@
 
 #define IPSET_TYPE_REV_MIN	0
 /*				1	   Counter support added */
-#define IPSET_TYPE_REV_MAX	2	/* Comment support added */
+/*				2	   Comment support added */
+#define IPSET_TYPE_REV_MAX	3	/* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -203,7 +204,7 @@
 {
 	struct bitmap_ipmac *map = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct bitmap_ipmac_adt_elem e = {};
+	struct bitmap_ipmac_adt_elem e = { .id = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 	u32 ip;
 
@@ -232,7 +233,7 @@
 {
 	const struct bitmap_ipmac *map = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct bitmap_ipmac_adt_elem e = {};
+	struct bitmap_ipmac_adt_elem e = { .id = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	u32 ip = 0;
 	int ret = 0;
@@ -240,7 +241,10 @@
 	if (unlikely(!tb[IPSET_ATTR_IP] ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)   ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -394,6 +398,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_bitmap_port.c net-next-2.6/net/netfilter/ipset/ip_set_bitmap_port.c
--- linux/net/netfilter/ipset/ip_set_bitmap_port.c	2013-11-29 12:59:37.963382374 +0100
+++ net-next-2.6/net/netfilter/ipset/ip_set_bitmap_port.c	2014-10-06 10:49:03.424933002 +0200
@@ -22,7 +22,8 @@
 
 #define IPSET_TYPE_REV_MIN	0
 /*				1	   Counter support added */
-#define IPSET_TYPE_REV_MAX	2	/* Comment support added */
+/*				2	   Comment support added */
+#define IPSET_TYPE_REV_MAX	3	/* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -104,7 +105,7 @@
 {
 	struct bitmap_port *map = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct bitmap_port_adt_elem e = {};
+	struct bitmap_port_adt_elem e = { .id = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 	__be16 __port;
 	u16 port = 0;
@@ -129,7 +130,7 @@
 {
 	struct bitmap_port *map = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct bitmap_port_adt_elem e = {};
+	struct bitmap_port_adt_elem e = { .id = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	u32 port;	/* wraparound */
 	u16 port_to;
@@ -139,7 +140,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PORT_TO) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)   ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -291,6 +295,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_core.c net-next-2.6/net/netfilter/ipset/ip_set_core.c
--- linux/net/netfilter/ipset/ip_set_core.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_core.c	2014-10-06 10:49:03.424933002 +0200
@@ -101,7 +101,7 @@
 	nfnl_unlock(NFNL_SUBSYS_IPSET);
 	pr_debug("try to load ip_set_%s\n", name);
 	if (request_module("ip_set_%s", name) < 0) {
-		pr_warning("Can't find ip_set type %s\n", name);
+		pr_warn("Can't find ip_set type %s\n", name);
 		nfnl_lock(NFNL_SUBSYS_IPSET);
 		return false;
 	}
@@ -195,20 +195,19 @@
 	int ret = 0;
 
 	if (type->protocol != IPSET_PROTOCOL) {
-		pr_warning("ip_set type %s, family %s, revision %u:%u uses "
-			   "wrong protocol version %u (want %u)\n",
-			   type->name, family_name(type->family),
-			   type->revision_min, type->revision_max,
-			   type->protocol, IPSET_PROTOCOL);
+		pr_warn("ip_set type %s, family %s, revision %u:%u uses wrong protocol version %u (want %u)\n",
+			type->name, family_name(type->family),
+			type->revision_min, type->revision_max,
+			type->protocol, IPSET_PROTOCOL);
 		return -EINVAL;
 	}
 
 	ip_set_type_lock();
 	if (find_set_type(type->name, type->family, type->revision_min)) {
 		/* Duplicate! */
-		pr_warning("ip_set type %s, family %s with revision min %u "
-			   "already registered!\n", type->name,
-			   family_name(type->family), type->revision_min);
+		pr_warn("ip_set type %s, family %s with revision min %u already registered!\n",
+			type->name, family_name(type->family),
+			type->revision_min);
 		ret = -EINVAL;
 		goto unlock;
 	}
@@ -228,9 +227,9 @@
 {
 	ip_set_type_lock();
 	if (!find_set_type(type->name, type->family, type->revision_min)) {
-		pr_warning("ip_set type %s, family %s with revision min %u "
-			   "not registered\n", type->name,
-			   family_name(type->family), type->revision_min);
+		pr_warn("ip_set type %s, family %s with revision min %u not registered\n",
+			type->name, family_name(type->family),
+			type->revision_min);
 		goto unlock;
 	}
 	list_del_rcu(&type->list);
@@ -338,6 +337,12 @@
 		.len	= sizeof(unsigned long),
 		.align	= __alignof__(unsigned long),
 	},
+	[IPSET_EXT_ID_SKBINFO] = {
+		.type	= IPSET_EXT_SKBINFO,
+		.flag	= IPSET_FLAG_WITH_SKBINFO,
+		.len	= sizeof(struct ip_set_skbinfo),
+		.align	= __alignof__(struct ip_set_skbinfo),
+	},
 	[IPSET_EXT_ID_COMMENT] = {
 		.type	 = IPSET_EXT_COMMENT | IPSET_EXT_DESTROY,
 		.flag	 = IPSET_FLAG_WITH_COMMENT,
@@ -383,6 +388,7 @@
 ip_set_get_extensions(struct ip_set *set, struct nlattr *tb[],
 		      struct ip_set_ext *ext)
 {
+	u64 fullmark;
 	if (tb[IPSET_ATTR_TIMEOUT]) {
 		if (!(set->extensions & IPSET_EXT_TIMEOUT))
 			return -IPSET_ERR_TIMEOUT;
@@ -403,7 +409,25 @@
 			return -IPSET_ERR_COMMENT;
 		ext->comment = ip_set_comment_uget(tb[IPSET_ATTR_COMMENT]);
 	}
-
+	if (tb[IPSET_ATTR_SKBMARK]) {
+		if (!(set->extensions & IPSET_EXT_SKBINFO))
+			return -IPSET_ERR_SKBINFO;
+		fullmark = be64_to_cpu(nla_get_be64(tb[IPSET_ATTR_SKBMARK]));
+		ext->skbmark = fullmark >> 32;
+		ext->skbmarkmask = fullmark & 0xffffffff;
+	}
+	if (tb[IPSET_ATTR_SKBPRIO]) {
+		if (!(set->extensions & IPSET_EXT_SKBINFO))
+			return -IPSET_ERR_SKBINFO;
+		ext->skbprio = be32_to_cpu(nla_get_be32(
+					    tb[IPSET_ATTR_SKBPRIO]));
+	}
+	if (tb[IPSET_ATTR_SKBQUEUE]) {
+		if (!(set->extensions & IPSET_EXT_SKBINFO))
+			return -IPSET_ERR_SKBINFO;
+		ext->skbqueue = be16_to_cpu(nla_get_be16(
+					    tb[IPSET_ATTR_SKBQUEUE]));
+	}
 	return 0;
 }
 EXPORT_SYMBOL_GPL(ip_set_get_extensions);
@@ -1398,7 +1422,8 @@
 		struct nlmsghdr *rep, *nlh = nlmsg_hdr(skb);
 		struct sk_buff *skb2;
 		struct nlmsgerr *errmsg;
-		size_t payload = sizeof(*errmsg) + nlmsg_len(nlh);
+		size_t payload = min(SIZE_MAX,
+				     sizeof(*errmsg) + nlmsg_len(nlh));
 		int min_len = nlmsg_total_size(sizeof(struct nfgenmsg));
 		struct nlattr *cda[IPSET_ATTR_CMD_MAX+1];
 		struct nlattr *cmdattr;
diff -urN linux/net/netfilter/ipset/ip_set_hash_gen.h net-next-2.6/net/netfilter/ipset/ip_set_hash_gen.h
--- linux/net/netfilter/ipset/ip_set_hash_gen.h	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_gen.h	2014-10-06 10:49:03.424933002 +0200
@@ -565,8 +565,8 @@
 		 set->name, orig->htable_bits, htable_bits, orig);
 	if (!htable_bits) {
 		/* In case we have plenty of memory :-) */
-		pr_warning("Cannot increase the hashsize of set %s further\n",
-			   set->name);
+		pr_warn("Cannot increase the hashsize of set %s further\n",
+			set->name);
 		return -IPSET_ERR_HASH_FULL;
 	}
 	t = ip_set_alloc(sizeof(*t)
@@ -651,8 +651,8 @@
 
 	if (h->elements >= h->maxelem) {
 		if (net_ratelimit())
-			pr_warning("Set %s is full, maxelem %u reached\n",
-				   set->name, h->maxelem);
+			pr_warn("Set %s is full, maxelem %u reached\n",
+				set->name, h->maxelem);
 		return -IPSET_ERR_HASH_FULL;
 	}
 
@@ -720,6 +720,8 @@
 		ip_set_init_counter(ext_counter(data, set), ext);
 	if (SET_WITH_COMMENT(set))
 		ip_set_init_comment(ext_comment(data, set), ext);
+	if (SET_WITH_SKBINFO(set))
+		ip_set_init_skbinfo(ext_skbinfo(data, set), ext);
 
 out:
 	rcu_read_unlock_bh();
@@ -797,6 +799,9 @@
 	if (SET_WITH_COUNTER(set))
 		ip_set_update_counter(ext_counter(data, set),
 				      ext, mext, flags);
+	if (SET_WITH_SKBINFO(set))
+		ip_set_get_skbinfo(ext_skbinfo(data, set),
+				   ext, mext, flags);
 	return mtype_do_data_match(data);
 }
 
@@ -998,8 +1003,8 @@
 nla_put_failure:
 	nlmsg_trim(skb, incomplete);
 	if (unlikely(first == cb->args[IPSET_CB_ARG0])) {
-		pr_warning("Can't list set %s: one bucket does not fit into "
-			   "a message. Please report it!\n", set->name);
+		pr_warn("Can't list set %s: one bucket does not fit into a message. Please report it!\n",
+			set->name);
 		cb->args[IPSET_CB_ARG0] = 0;
 		return -EMSGSIZE;
 	}
@@ -1049,8 +1054,10 @@
 	struct HTYPE *h;
 	struct htable *t;
 
+#ifndef IP_SET_PROTO_UNDEF
 	if (!(set->family == NFPROTO_IPV4 || set->family == NFPROTO_IPV6))
 		return -IPSET_ERR_INVALID_FAMILY;
+#endif
 
 #ifdef IP_SET_HASH_WITH_MARKMASK
 	markmask = 0xffffffff;
@@ -1093,7 +1100,7 @@
 	if (tb[IPSET_ATTR_MARKMASK]) {
 		markmask = ntohl(nla_get_u32(tb[IPSET_ATTR_MARKMASK]));
 
-		if ((markmask > 4294967295u) || markmask == 0)
+		if (markmask == 0)
 			return -IPSET_ERR_INVALID_MARKMASK;
 	}
 #endif
@@ -1132,25 +1139,32 @@
 	rcu_assign_pointer(h->table, t);
 
 	set->data = h;
+#ifndef IP_SET_PROTO_UNDEF
 	if (set->family == NFPROTO_IPV4) {
+#endif
 		set->variant = &IPSET_TOKEN(HTYPE, 4_variant);
 		set->dsize = ip_set_elem_len(set, tb,
 				sizeof(struct IPSET_TOKEN(HTYPE, 4_elem)));
+#ifndef IP_SET_PROTO_UNDEF
 	} else {
 		set->variant = &IPSET_TOKEN(HTYPE, 6_variant);
 		set->dsize = ip_set_elem_len(set, tb,
 				sizeof(struct IPSET_TOKEN(HTYPE, 6_elem)));
 	}
+#endif
 	if (tb[IPSET_ATTR_TIMEOUT]) {
 		set->timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
+#ifndef IP_SET_PROTO_UNDEF
 		if (set->family == NFPROTO_IPV4)
+#endif
 			IPSET_TOKEN(HTYPE, 4_gc_init)(set,
 				IPSET_TOKEN(HTYPE, 4_gc));
+#ifndef IP_SET_PROTO_UNDEF
 		else
 			IPSET_TOKEN(HTYPE, 6_gc_init)(set,
 				IPSET_TOKEN(HTYPE, 6_gc));
+#endif
 	}
-
 	pr_debug("create %s hashsize %u (%u) maxelem %u: %p(%p)\n",
 		 set->name, jhash_size(t->htable_bits),
 		 t->htable_bits, h->maxelem, set->data, t);
diff -urN linux/net/netfilter/ipset/ip_set_hash_ip.c net-next-2.6/net/netfilter/ipset/ip_set_hash_ip.c
--- linux/net/netfilter/ipset/ip_set_hash_ip.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_ip.c	2014-10-06 10:49:03.424933002 +0200
@@ -26,7 +26,8 @@
 #define IPSET_TYPE_REV_MIN	0
 /*				1	   Counters support */
 /*				2	   Comments support */
-#define IPSET_TYPE_REV_MAX	3	/* Forceadd support */
+/*				3	   Forceadd support */
+#define IPSET_TYPE_REV_MAX	4	/* skbinfo support  */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -84,7 +85,7 @@
 {
 	const struct hash_ip *h = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ip4_elem e = {};
+	struct hash_ip4_elem e = { 0 };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 	__be32 ip;
 
@@ -103,7 +104,7 @@
 {
 	const struct hash_ip *h = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ip4_elem e = {};
+	struct hash_ip4_elem e = { 0 };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	u32 ip = 0, ip_to = 0, hosts;
 	int ret = 0;
@@ -111,7 +112,10 @@
 	if (unlikely(!tb[IPSET_ATTR_IP] ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)   ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -222,7 +226,7 @@
 {
 	const struct hash_ip *h = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ip6_elem e = {};
+	struct hash_ip6_elem e = { { .all = { 0 } } };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 
 	ip6addrptr(skb, opt->flags & IPSET_DIM_ONE_SRC, &e.ip.in6);
@@ -239,7 +243,7 @@
 {
 	const struct hash_ip *h = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ip6_elem e = {};
+	struct hash_ip6_elem e = { { .all = { 0 } } };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	int ret;
 
@@ -247,6 +251,9 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE) ||
 		     tb[IPSET_ATTR_IP_TO] ||
 		     tb[IPSET_ATTR_CIDR]))
 		return -IPSET_ERR_PROTOCOL;
@@ -295,6 +302,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_ipmark.c net-next-2.6/net/netfilter/ipset/ip_set_hash_ipmark.c
--- linux/net/netfilter/ipset/ip_set_hash_ipmark.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_ipmark.c	2014-10-06 10:49:03.424933002 +0200
@@ -25,7 +25,8 @@
 #include <linux/netfilter/ipset/ip_set_hash.h>
 
 #define IPSET_TYPE_REV_MIN	0
-#define IPSET_TYPE_REV_MAX	1	/* Forceadd support */
+/*				1	   Forceadd support */
+#define IPSET_TYPE_REV_MAX	2	/* skbinfo support  */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Vytas Dauksa <vytas.dauksa@smoothwall.net>");
@@ -113,7 +114,10 @@
 		     !ip_set_attr_netorder(tb, IPSET_ATTR_MARK) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -244,6 +248,9 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE) ||
 		     tb[IPSET_ATTR_IP_TO] ||
 		     tb[IPSET_ATTR_CIDR]))
 		return -IPSET_ERR_PROTOCOL;
@@ -301,6 +308,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_ipport.c net-next-2.6/net/netfilter/ipset/ip_set_hash_ipport.c
--- linux/net/netfilter/ipset/ip_set_hash_ipport.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_ipport.c	2014-10-06 10:49:03.424933002 +0200
@@ -28,7 +28,8 @@
 /*				1    SCTP and UDPLITE support added */
 /*				2    Counters support added */
 /*				3    Comments support added */
-#define IPSET_TYPE_REV_MAX	4 /* Forceadd support added */
+/*				4    Forceadd support added */
+#define IPSET_TYPE_REV_MAX	5 /* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -94,7 +95,7 @@
 		  enum ipset_adt adt, struct ip_set_adt_opt *opt)
 {
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ipport4_elem e = { };
+	struct hash_ipport4_elem e = { .ip = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 
 	if (!ip_set_get_ip4_port(skb, opt->flags & IPSET_DIM_TWO_SRC,
@@ -111,7 +112,7 @@
 {
 	const struct hash_ipport *h = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ipport4_elem e = { };
+	struct hash_ipport4_elem e = { .ip = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	u32 ip, ip_to = 0, p = 0, port, port_to;
 	bool with_ports = false;
@@ -122,7 +123,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PORT_TO) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -258,7 +262,7 @@
 		  enum ipset_adt adt, struct ip_set_adt_opt *opt)
 {
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ipport6_elem e = { };
+	struct hash_ipport6_elem e = { .ip = { .all = { 0 } } };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 
 	if (!ip_set_get_ip6_port(skb, opt->flags & IPSET_DIM_TWO_SRC,
@@ -275,7 +279,7 @@
 {
 	const struct hash_ipport *h = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ipport6_elem e = { };
+	struct hash_ipport6_elem e = { .ip = { .all = { 0 } } };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	u32 port, port_to;
 	bool with_ports = false;
@@ -287,6 +291,9 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE) ||
 		     tb[IPSET_ATTR_IP_TO] ||
 		     tb[IPSET_ATTR_CIDR]))
 		return -IPSET_ERR_PROTOCOL;
@@ -370,6 +377,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_ipportip.c net-next-2.6/net/netfilter/ipset/ip_set_hash_ipportip.c
--- linux/net/netfilter/ipset/ip_set_hash_ipportip.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_ipportip.c	2014-10-06 10:49:03.424933002 +0200
@@ -28,7 +28,8 @@
 /*				1    SCTP and UDPLITE support added */
 /*				2    Counters support added */
 /*				3    Comments support added */
-#define IPSET_TYPE_REV_MAX	4 /* Forceadd support added */
+/*				4    Forceadd support added */
+#define IPSET_TYPE_REV_MAX	5 /* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -95,7 +96,7 @@
 		    enum ipset_adt adt, struct ip_set_adt_opt *opt)
 {
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ipportip4_elem e = { };
+	struct hash_ipportip4_elem e = { .ip = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 
 	if (!ip_set_get_ip4_port(skb, opt->flags & IPSET_DIM_TWO_SRC,
@@ -113,7 +114,7 @@
 {
 	const struct hash_ipportip *h = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ipportip4_elem e = { };
+	struct hash_ipportip4_elem e = { .ip = 0 };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	u32 ip, ip_to = 0, p = 0, port, port_to;
 	bool with_ports = false;
@@ -124,7 +125,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PORT_TO) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -265,7 +269,7 @@
 		    enum ipset_adt adt, struct ip_set_adt_opt *opt)
 {
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ipportip6_elem e = { };
+	struct hash_ipportip6_elem e = { .ip = { .all = { 0 } } };
 	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
 
 	if (!ip_set_get_ip6_port(skb, opt->flags & IPSET_DIM_TWO_SRC,
@@ -283,7 +287,7 @@
 {
 	const struct hash_ipportip *h = set->data;
 	ipset_adtfn adtfn = set->variant->adt[adt];
-	struct hash_ipportip6_elem e = { };
+	struct hash_ipportip6_elem e = {  .ip = { .all = { 0 } } };
 	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
 	u32 port, port_to;
 	bool with_ports = false;
@@ -295,6 +299,9 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE) ||
 		     tb[IPSET_ATTR_IP_TO] ||
 		     tb[IPSET_ATTR_CIDR]))
 		return -IPSET_ERR_PROTOCOL;
@@ -382,6 +389,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_ipportnet.c net-next-2.6/net/netfilter/ipset/ip_set_hash_ipportnet.c
--- linux/net/netfilter/ipset/ip_set_hash_ipportnet.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_ipportnet.c	2014-10-06 10:49:03.424933002 +0200
@@ -30,7 +30,8 @@
 /*				3    nomatch flag support added */
 /*				4    Counters support added */
 /*				5    Comments support added */
-#define IPSET_TYPE_REV_MAX	6 /* Forceadd support added */
+/*				6    Forceadd support added */
+#define IPSET_TYPE_REV_MAX	7 /* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -179,7 +180,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -432,6 +436,9 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE) ||
 		     tb[IPSET_ATTR_IP_TO] ||
 		     tb[IPSET_ATTR_CIDR]))
 		return -IPSET_ERR_PROTOCOL;
@@ -541,6 +548,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_mac.c net-next-2.6/net/netfilter/ipset/ip_set_hash_mac.c
--- linux/net/netfilter/ipset/ip_set_hash_mac.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_mac.c	2014-10-06 10:49:03.424933002 +0200
@@ -0,0 +1,173 @@
+/* Copyright (C) 2014 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ */
+
+/* Kernel module implementing an IP set type: the hash:mac type */
+
+#include <linux/jhash.h>
+#include <linux/module.h>
+#include <linux/etherdevice.h>
+#include <linux/skbuff.h>
+#include <linux/errno.h>
+#include <linux/if_ether.h>
+#include <net/netlink.h>
+
+#include <linux/netfilter.h>
+#include <linux/netfilter/ipset/ip_set.h>
+#include <linux/netfilter/ipset/ip_set_hash.h>
+
+#define IPSET_TYPE_REV_MIN	0
+#define IPSET_TYPE_REV_MAX	0
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
+IP_SET_MODULE_DESC("hash:mac", IPSET_TYPE_REV_MIN, IPSET_TYPE_REV_MAX);
+MODULE_ALIAS("ip_set_hash:mac");
+
+/* Type specific function prefix */
+#define HTYPE		hash_mac
+
+/* Member elements */
+struct hash_mac4_elem {
+	/* Zero valued IP addresses cannot be stored */
+	union {
+		unsigned char ether[ETH_ALEN];
+		__be32 foo[2];
+	};
+};
+
+/* Common functions */
+
+static inline bool
+hash_mac4_data_equal(const struct hash_mac4_elem *e1,
+		     const struct hash_mac4_elem *e2,
+		     u32 *multi)
+{
+	return ether_addr_equal(e1->ether, e2->ether);
+}
+
+static inline bool
+hash_mac4_data_list(struct sk_buff *skb, const struct hash_mac4_elem *e)
+{
+	return nla_put(skb, IPSET_ATTR_ETHER, ETH_ALEN, e->ether);
+}
+
+static inline void
+hash_mac4_data_next(struct hash_mac4_elem *next,
+		    const struct hash_mac4_elem *e)
+{
+}
+
+#define MTYPE		hash_mac4
+#define PF		4
+#define HOST_MASK	32
+#define IP_SET_EMIT_CREATE
+#define IP_SET_PROTO_UNDEF
+#include "ip_set_hash_gen.h"
+
+/* Zero valued element is not supported */
+static const unsigned char invalid_ether[ETH_ALEN] = { 0 };
+
+static int
+hash_mac4_kadt(struct ip_set *set, const struct sk_buff *skb,
+	       const struct xt_action_param *par,
+	       enum ipset_adt adt, struct ip_set_adt_opt *opt)
+{
+	ipset_adtfn adtfn = set->variant->adt[adt];
+	struct hash_mac4_elem e = { { .foo[0] = 0, .foo[1] = 0 } };
+	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
+
+	 /* MAC can be src only */
+	if (!(opt->flags & IPSET_DIM_ONE_SRC))
+		return 0;
+
+	if (skb_mac_header(skb) < skb->head ||
+	     (skb_mac_header(skb) + ETH_HLEN) > skb->data)
+		return -EINVAL;
+
+	memcpy(e.ether, eth_hdr(skb)->h_source, ETH_ALEN);
+	if (memcmp(e.ether, invalid_ether, ETH_ALEN) == 0)
+		return -EINVAL;
+	return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
+}
+
+static int
+hash_mac4_uadt(struct ip_set *set, struct nlattr *tb[],
+	       enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
+{
+	ipset_adtfn adtfn = set->variant->adt[adt];
+	struct hash_mac4_elem e = { { .foo[0] = 0, .foo[1] = 0 } };
+	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
+	int ret;
+
+	if (unlikely(!tb[IPSET_ATTR_ETHER] ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)   ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
+		return -IPSET_ERR_PROTOCOL;
+
+	if (tb[IPSET_ATTR_LINENO])
+		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);
+
+	ret = ip_set_get_extensions(set, tb, &ext);
+	if (ret)
+		return ret;
+	memcpy(e.ether, nla_data(tb[IPSET_ATTR_ETHER]), ETH_ALEN);
+	if (memcmp(e.ether, invalid_ether, ETH_ALEN) == 0)
+		return -IPSET_ERR_HASH_ELEM;
+
+	return adtfn(set, &e, &ext, &ext, flags);
+}
+
+static struct ip_set_type hash_mac_type __read_mostly = {
+	.name		= "hash:mac",
+	.protocol	= IPSET_PROTOCOL,
+	.features	= IPSET_TYPE_MAC,
+	.dimension	= IPSET_DIM_ONE,
+	.family		= NFPROTO_UNSPEC,
+	.revision_min	= IPSET_TYPE_REV_MIN,
+	.revision_max	= IPSET_TYPE_REV_MAX,
+	.create		= hash_mac_create,
+	.create_policy	= {
+		[IPSET_ATTR_HASHSIZE]	= { .type = NLA_U32 },
+		[IPSET_ATTR_MAXELEM]	= { .type = NLA_U32 },
+		[IPSET_ATTR_PROBES]	= { .type = NLA_U8 },
+		[IPSET_ATTR_RESIZE]	= { .type = NLA_U8  },
+		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
+		[IPSET_ATTR_CADT_FLAGS]	= { .type = NLA_U32 },
+	},
+	.adt_policy	= {
+		[IPSET_ATTR_ETHER]	= { .type = NLA_BINARY,
+					    .len  = ETH_ALEN },
+		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
+		[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
+		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
+		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
+	},
+	.me		= THIS_MODULE,
+};
+
+static int __init
+hash_mac_init(void)
+{
+	return ip_set_type_register(&hash_mac_type);
+}
+
+static void __exit
+hash_mac_fini(void)
+{
+	ip_set_type_unregister(&hash_mac_type);
+}
+
+module_init(hash_mac_init);
+module_exit(hash_mac_fini);
diff -urN linux/net/netfilter/ipset/ip_set_hash_net.c net-next-2.6/net/netfilter/ipset/ip_set_hash_net.c
--- linux/net/netfilter/ipset/ip_set_hash_net.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_net.c	2014-10-06 10:49:03.428933043 +0200
@@ -27,7 +27,8 @@
 /*				2    nomatch flag support added */
 /*				3    Counters support added */
 /*				4    Comments support added */
-#define IPSET_TYPE_REV_MAX	5 /* Forceadd support added */
+/*				5    Forceadd support added */
+#define IPSET_TYPE_REV_MAX	6 /* skbinfo mapping support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -150,7 +151,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -318,7 +322,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 	if (unlikely(tb[IPSET_ATTR_IP_TO]))
 		return -IPSET_ERR_HASH_RANGE_UNSUPPORTED;
@@ -377,6 +384,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_netiface.c net-next-2.6/net/netfilter/ipset/ip_set_hash_netiface.c
--- linux/net/netfilter/ipset/ip_set_hash_netiface.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_netiface.c	2014-10-06 10:49:03.428933043 +0200
@@ -28,7 +28,8 @@
 /*				2    /0 support added */
 /*				3    Counters support added */
 /*				4    Comments support added */
-#define IPSET_TYPE_REV_MAX	5 /* Forceadd support added */
+/*				5    Forceadd support added */
+#define IPSET_TYPE_REV_MAX	6 /* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -236,7 +237,7 @@
 #define SRCDIR		(opt->flags & IPSET_DIM_TWO_SRC)
 
 	if (opt->cmdflags & IPSET_FLAG_PHYSDEV) {
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 		const struct nf_bridge_info *nf_bridge = skb->nf_bridge;
 
 		if (!nf_bridge)
@@ -281,7 +282,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -470,7 +474,7 @@
 	ip6_netmask(&e.ip, e.cidr);
 
 	if (opt->cmdflags & IPSET_FLAG_PHYSDEV) {
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 		const struct nf_bridge_info *nf_bridge = skb->nf_bridge;
 
 		if (!nf_bridge)
@@ -514,7 +518,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 	if (unlikely(tb[IPSET_ATTR_IP_TO]))
 		return -IPSET_ERR_HASH_RANGE_UNSUPPORTED;
@@ -590,6 +597,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_netnet.c net-next-2.6/net/netfilter/ipset/ip_set_hash_netnet.c
--- linux/net/netfilter/ipset/ip_set_hash_netnet.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_netnet.c	2014-10-06 10:49:03.428933043 +0200
@@ -24,7 +24,8 @@
 #include <linux/netfilter/ipset/ip_set_hash.h>
 
 #define IPSET_TYPE_REV_MIN	0
-#define IPSET_TYPE_REV_MAX	1	/* Forceadd support added */
+/*				1	   Forceadd support added */
+#define IPSET_TYPE_REV_MAX	2	/* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Oliver Smith <oliver@8.c.9.b.0.7.4.0.1.0.0.2.ip6.arpa>");
@@ -171,7 +172,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -203,7 +207,7 @@
 			flags |= (IPSET_FLAG_NOMATCH << 16);
 	}
 
-	if (adt == IPSET_TEST || !(tb[IPSET_ATTR_IP_TO] &&
+	if (adt == IPSET_TEST || !(tb[IPSET_ATTR_IP_TO] ||
 				   tb[IPSET_ATTR_IP2_TO])) {
 		e.ip[0] = htonl(ip & ip_set_hostmask(e.cidr[0]));
 		e.ip[1] = htonl(ip2_from & ip_set_hostmask(e.cidr[1]));
@@ -219,9 +223,10 @@
 			return ret;
 		if (ip_to < ip)
 			swap(ip, ip_to);
-		if (ip + UINT_MAX == ip_to)
+		if (unlikely(ip + UINT_MAX == ip_to))
 			return -IPSET_ERR_HASH_RANGE;
-	}
+	} else
+		ip_set_mask_from_to(ip, ip_to, e.cidr[0]);
 
 	ip2_to = ip2_from;
 	if (tb[IPSET_ATTR_IP2_TO]) {
@@ -230,10 +235,10 @@
 			return ret;
 		if (ip2_to < ip2_from)
 			swap(ip2_from, ip2_to);
-		if (ip2_from + UINT_MAX == ip2_to)
+		if (unlikely(ip2_from + UINT_MAX == ip2_to))
 			return -IPSET_ERR_HASH_RANGE;
-
-	}
+	} else
+		ip_set_mask_from_to(ip2_from, ip2_to, e.cidr[1]);
 
 	if (retried)
 		ip = ntohl(h->next.ip[0]);
@@ -393,7 +398,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 	if (unlikely(tb[IPSET_ATTR_IP_TO] || tb[IPSET_ATTR_IP2_TO]))
 		return -IPSET_ERR_HASH_RANGE_UNSUPPORTED;
@@ -461,6 +469,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_netport.c net-next-2.6/net/netfilter/ipset/ip_set_hash_netport.c
--- linux/net/netfilter/ipset/ip_set_hash_netport.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_netport.c	2014-10-06 10:49:03.428933043 +0200
@@ -29,7 +29,8 @@
 /*				3    nomatch flag support added */
 /*				4    Counters support added */
 /*				5    Comments support added */
-#define IPSET_TYPE_REV_MAX	6 /* Forceadd support added */
+/*				6    Forceadd support added */
+#define IPSET_TYPE_REV_MAX	7 /* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -172,7 +173,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -389,7 +393,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 	if (unlikely(tb[IPSET_ATTR_IP_TO]))
 		return -IPSET_ERR_HASH_RANGE_UNSUPPORTED;
@@ -489,6 +496,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_hash_netportnet.c net-next-2.6/net/netfilter/ipset/ip_set_hash_netportnet.c
--- linux/net/netfilter/ipset/ip_set_hash_netportnet.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/ipset/ip_set_hash_netportnet.c	2014-10-06 10:49:03.428933043 +0200
@@ -26,7 +26,8 @@
 
 #define IPSET_TYPE_REV_MIN	0
 /*				0    Comments support added */
-#define IPSET_TYPE_REV_MAX	1 /* Forceadd support added */
+/*				1    Forceadd support added */
+#define IPSET_TYPE_REV_MAX	2 /* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Oliver Smith <oliver@8.c.9.b.0.7.4.0.1.0.0.2.ip6.arpa>");
@@ -189,7 +190,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -257,7 +261,8 @@
 			swap(ip, ip_to);
 		if (unlikely(ip + UINT_MAX == ip_to))
 			return -IPSET_ERR_HASH_RANGE;
-	}
+	} else
+		ip_set_mask_from_to(ip, ip_to, e.cidr[0]);
 
 	port_to = port = ntohs(e.port);
 	if (tb[IPSET_ATTR_PORT_TO]) {
@@ -275,7 +280,8 @@
 			swap(ip2_from, ip2_to);
 		if (unlikely(ip2_from + UINT_MAX == ip2_to))
 			return -IPSET_ERR_HASH_RANGE;
-	}
+	} else
+		ip_set_mask_from_to(ip2_from, ip2_to, e.cidr[1]);
 
 	if (retried)
 		ip = ntohl(h->next.ip[0]);
@@ -458,7 +464,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 	if (unlikely(tb[IPSET_ATTR_IP_TO] || tb[IPSET_ATTR_IP2_TO]))
 		return -IPSET_ERR_HASH_RANGE_UNSUPPORTED;
@@ -567,6 +576,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/ip_set_list_set.c net-next-2.6/net/netfilter/ipset/ip_set_list_set.c
--- linux/net/netfilter/ipset/ip_set_list_set.c	2013-11-29 12:59:37.971382457 +0100
+++ net-next-2.6/net/netfilter/ipset/ip_set_list_set.c	2014-10-06 10:49:03.428933043 +0200
@@ -17,7 +17,8 @@
 
 #define IPSET_TYPE_REV_MIN	0
 /*				1    Counters support added */
-#define IPSET_TYPE_REV_MAX	2 /* Comments support added */
+/*				2    Comments support added */
+#define IPSET_TYPE_REV_MAX	3 /* skbinfo support added */
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
@@ -73,6 +74,10 @@
 				ip_set_update_counter(ext_counter(e, set),
 						      ext, &opt->ext,
 						      cmdflags);
+			if (SET_WITH_SKBINFO(set))
+				ip_set_get_skbinfo(ext_skbinfo(e, set),
+						   ext, &opt->ext,
+						   cmdflags);
 			return ret;
 		}
 	}
@@ -197,6 +202,8 @@
 		ip_set_init_counter(ext_counter(e, set), ext);
 	if (SET_WITH_COMMENT(set))
 		ip_set_init_comment(ext_comment(e, set), ext);
+	if (SET_WITH_SKBINFO(set))
+		ip_set_init_skbinfo(ext_skbinfo(e, set), ext);
 	return 0;
 }
 
@@ -307,6 +314,8 @@
 			ip_set_init_counter(ext_counter(e, set), ext);
 		if (SET_WITH_COMMENT(set))
 			ip_set_init_comment(ext_comment(e, set), ext);
+		if (SET_WITH_SKBINFO(set))
+			ip_set_init_skbinfo(ext_skbinfo(e, set), ext);
 		/* Set is already added to the list */
 		ip_set_put_byindex(map->net, d->id);
 		return 0;
@@ -378,7 +387,10 @@
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS) ||
 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
-		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBPRIO) ||
+		     !ip_set_optattr_netorder(tb, IPSET_ATTR_SKBQUEUE)))
 		return -IPSET_ERR_PROTOCOL;
 
 	if (tb[IPSET_ATTR_LINENO])
@@ -597,7 +609,9 @@
 	struct set_elem *e;
 	u32 i;
 
-	map = kzalloc(sizeof(*map) + size * set->dsize, GFP_KERNEL);
+	map = kzalloc(sizeof(*map) +
+		      min_t(u32, size, IP_SET_LIST_MAX_SIZE) * set->dsize,
+		      GFP_KERNEL);
 	if (!map)
 		return false;
 
@@ -665,6 +679,9 @@
 		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
 		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
 		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING },
+		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
+		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
+		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
 	},
 	.me		= THIS_MODULE,
 };
diff -urN linux/net/netfilter/ipset/Kconfig net-next-2.6/net/netfilter/ipset/Kconfig
--- linux/net/netfilter/ipset/Kconfig	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/Kconfig	2014-10-06 10:49:03.424933002 +0200
@@ -99,6 +99,15 @@
 
 	  To compile it as a module, choose M here.  If unsure, say N.
 
+config IP_SET_HASH_MAC
+	tristate "hash:mac set support"
+	depends on IP_SET
+	help
+	  This option adds the hash:mac set type support, by which
+	  one can store MAC (ethernet address) elements in a set.
+
+	  To compile it as a module, choose M here.  If unsure, say N.
+
 config IP_SET_HASH_NETPORTNET
 	tristate "hash:net,port,net set support"
 	depends on IP_SET
diff -urN linux/net/netfilter/ipset/Makefile net-next-2.6/net/netfilter/ipset/Makefile
--- linux/net/netfilter/ipset/Makefile	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/ipset/Makefile	2014-10-06 10:49:03.424933002 +0200
@@ -18,6 +18,7 @@
 obj-$(CONFIG_IP_SET_HASH_IPPORT) += ip_set_hash_ipport.o
 obj-$(CONFIG_IP_SET_HASH_IPPORTIP) += ip_set_hash_ipportip.o
 obj-$(CONFIG_IP_SET_HASH_IPPORTNET) += ip_set_hash_ipportnet.o
+obj-$(CONFIG_IP_SET_HASH_MAC) += ip_set_hash_mac.o
 obj-$(CONFIG_IP_SET_HASH_NET) += ip_set_hash_net.o
 obj-$(CONFIG_IP_SET_HASH_NETPORT) += ip_set_hash_netport.o
 obj-$(CONFIG_IP_SET_HASH_NETIFACE) += ip_set_hash_netiface.o
diff -urN linux/net/netfilter/ipvs/ip_vs_conn.c net-next-2.6/net/netfilter/ipvs/ip_vs_conn.c
--- linux/net/netfilter/ipvs/ip_vs_conn.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_conn.c	2014-10-06 10:49:03.428933043 +0200
@@ -27,6 +27,7 @@
 
 #include <linux/interrupt.h>
 #include <linux/in.h>
+#include <linux/inet.h>
 #include <linux/net.h>
 #include <linux/kernel.h>
 #include <linux/module.h>
@@ -77,6 +78,13 @@
 #define CT_LOCKARRAY_SIZE  (1<<CT_LOCKARRAY_BITS)
 #define CT_LOCKARRAY_MASK  (CT_LOCKARRAY_SIZE-1)
 
+/* We need an addrstrlen that works with or without v6 */
+#ifdef CONFIG_IP_VS_IPV6
+#define IP_VS_ADDRSTRLEN INET6_ADDRSTRLEN
+#else
+#define IP_VS_ADDRSTRLEN (8+1)
+#endif
+
 struct ip_vs_aligned_lock
 {
 	spinlock_t	l;
@@ -488,7 +496,12 @@
 		break;
 
 	case IP_VS_CONN_F_TUNNEL:
-		cp->packet_xmit = ip_vs_tunnel_xmit;
+#ifdef CONFIG_IP_VS_IPV6
+		if (cp->daf == AF_INET6)
+			cp->packet_xmit = ip_vs_tunnel_xmit_v6;
+		else
+#endif
+			cp->packet_xmit = ip_vs_tunnel_xmit;
 		break;
 
 	case IP_VS_CONN_F_DROUTE:
@@ -514,7 +527,10 @@
 		break;
 
 	case IP_VS_CONN_F_TUNNEL:
-		cp->packet_xmit = ip_vs_tunnel_xmit_v6;
+		if (cp->daf == AF_INET6)
+			cp->packet_xmit = ip_vs_tunnel_xmit_v6;
+		else
+			cp->packet_xmit = ip_vs_tunnel_xmit;
 		break;
 
 	case IP_VS_CONN_F_DROUTE:
@@ -580,7 +596,7 @@
 		      ip_vs_proto_name(cp->protocol),
 		      IP_VS_DBG_ADDR(cp->af, &cp->caddr), ntohs(cp->cport),
 		      IP_VS_DBG_ADDR(cp->af, &cp->vaddr), ntohs(cp->vport),
-		      IP_VS_DBG_ADDR(cp->af, &cp->daddr), ntohs(cp->dport),
+		      IP_VS_DBG_ADDR(cp->daf, &cp->daddr), ntohs(cp->dport),
 		      ip_vs_fwd_tag(cp), cp->state,
 		      cp->flags, atomic_read(&cp->refcnt),
 		      atomic_read(&dest->refcnt));
@@ -616,7 +632,13 @@
 	struct ip_vs_dest *dest;
 
 	rcu_read_lock();
-	dest = ip_vs_find_dest(ip_vs_conn_net(cp), cp->af, &cp->daddr,
+
+	/* This function is only invoked by the synchronization code. We do
+	 * not currently support heterogeneous pools with synchronization,
+	 * so we can make the assumption that the svc_af is the same as the
+	 * dest_af
+	 */
+	dest = ip_vs_find_dest(ip_vs_conn_net(cp), cp->af, cp->af, &cp->daddr,
 			       cp->dport, &cp->vaddr, cp->vport,
 			       cp->protocol, cp->fwmark, cp->flags);
 	if (dest) {
@@ -671,7 +693,7 @@
 		      ip_vs_proto_name(cp->protocol),
 		      IP_VS_DBG_ADDR(cp->af, &cp->caddr), ntohs(cp->cport),
 		      IP_VS_DBG_ADDR(cp->af, &cp->vaddr), ntohs(cp->vport),
-		      IP_VS_DBG_ADDR(cp->af, &cp->daddr), ntohs(cp->dport),
+		      IP_VS_DBG_ADDR(cp->daf, &cp->daddr), ntohs(cp->dport),
 		      ip_vs_fwd_tag(cp), cp->state,
 		      cp->flags, atomic_read(&cp->refcnt),
 		      atomic_read(&dest->refcnt));
@@ -740,7 +762,7 @@
 			      ntohs(ct->cport),
 			      IP_VS_DBG_ADDR(ct->af, &ct->vaddr),
 			      ntohs(ct->vport),
-			      IP_VS_DBG_ADDR(ct->af, &ct->daddr),
+			      IP_VS_DBG_ADDR(ct->daf, &ct->daddr),
 			      ntohs(ct->dport));
 
 		/*
@@ -848,7 +870,7 @@
  *	Create a new connection entry and hash it into the ip_vs_conn_tab
  */
 struct ip_vs_conn *
-ip_vs_conn_new(const struct ip_vs_conn_param *p,
+ip_vs_conn_new(const struct ip_vs_conn_param *p, int dest_af,
 	       const union nf_inet_addr *daddr, __be16 dport, unsigned int flags,
 	       struct ip_vs_dest *dest, __u32 fwmark)
 {
@@ -867,6 +889,7 @@
 	setup_timer(&cp->timer, ip_vs_conn_expire, (unsigned long)cp);
 	ip_vs_conn_net_set(cp, p->net);
 	cp->af		   = p->af;
+	cp->daf		   = dest_af;
 	cp->protocol	   = p->protocol;
 	ip_vs_addr_set(p->af, &cp->caddr, p->caddr);
 	cp->cport	   = p->cport;
@@ -874,7 +897,7 @@
 	ip_vs_addr_set(p->protocol == IPPROTO_IP ? AF_UNSPEC : p->af,
 		       &cp->vaddr, p->vaddr);
 	cp->vport	   = p->vport;
-	ip_vs_addr_set(p->af, &cp->daddr, daddr);
+	ip_vs_addr_set(cp->daf, &cp->daddr, daddr);
 	cp->dport          = dport;
 	cp->flags	   = flags;
 	cp->fwmark         = fwmark;
@@ -1036,6 +1059,7 @@
 		struct net *net = seq_file_net(seq);
 		char pe_data[IP_VS_PENAME_MAXLEN + IP_VS_PEDATA_MAXLEN + 3];
 		size_t len = 0;
+		char dbuf[IP_VS_ADDRSTRLEN];
 
 		if (!ip_vs_conn_net_eq(cp, net))
 			return 0;
@@ -1050,24 +1074,32 @@
 		pe_data[len] = '\0';
 
 #ifdef CONFIG_IP_VS_IPV6
+		if (cp->daf == AF_INET6)
+			snprintf(dbuf, sizeof(dbuf), "%pI6", &cp->daddr.in6);
+		else
+#endif
+			snprintf(dbuf, sizeof(dbuf), "%08X",
+				 ntohl(cp->daddr.ip));
+
+#ifdef CONFIG_IP_VS_IPV6
 		if (cp->af == AF_INET6)
 			seq_printf(seq, "%-3s %pI6 %04X %pI6 %04X "
-				"%pI6 %04X %-11s %7lu%s\n",
+				"%s %04X %-11s %7lu%s\n",
 				ip_vs_proto_name(cp->protocol),
 				&cp->caddr.in6, ntohs(cp->cport),
 				&cp->vaddr.in6, ntohs(cp->vport),
-				&cp->daddr.in6, ntohs(cp->dport),
+				dbuf, ntohs(cp->dport),
 				ip_vs_state_name(cp->protocol, cp->state),
 				(cp->timer.expires-jiffies)/HZ, pe_data);
 		else
 #endif
 			seq_printf(seq,
 				"%-3s %08X %04X %08X %04X"
-				" %08X %04X %-11s %7lu%s\n",
+				" %s %04X %-11s %7lu%s\n",
 				ip_vs_proto_name(cp->protocol),
 				ntohl(cp->caddr.ip), ntohs(cp->cport),
 				ntohl(cp->vaddr.ip), ntohs(cp->vport),
-				ntohl(cp->daddr.ip), ntohs(cp->dport),
+				dbuf, ntohs(cp->dport),
 				ip_vs_state_name(cp->protocol, cp->state),
 				(cp->timer.expires-jiffies)/HZ, pe_data);
 	}
@@ -1105,6 +1137,7 @@
 
 static int ip_vs_conn_sync_seq_show(struct seq_file *seq, void *v)
 {
+	char dbuf[IP_VS_ADDRSTRLEN];
 
 	if (v == SEQ_START_TOKEN)
 		seq_puts(seq,
@@ -1117,12 +1150,21 @@
 			return 0;
 
 #ifdef CONFIG_IP_VS_IPV6
+		if (cp->daf == AF_INET6)
+			snprintf(dbuf, sizeof(dbuf), "%pI6", &cp->daddr.in6);
+		else
+#endif
+			snprintf(dbuf, sizeof(dbuf), "%08X",
+				 ntohl(cp->daddr.ip));
+
+#ifdef CONFIG_IP_VS_IPV6
 		if (cp->af == AF_INET6)
-			seq_printf(seq, "%-3s %pI6 %04X %pI6 %04X %pI6 %04X %-11s %-6s %7lu\n",
+			seq_printf(seq, "%-3s %pI6 %04X %pI6 %04X "
+				"%s %04X %-11s %-6s %7lu\n",
 				ip_vs_proto_name(cp->protocol),
 				&cp->caddr.in6, ntohs(cp->cport),
 				&cp->vaddr.in6, ntohs(cp->vport),
-				&cp->daddr.in6, ntohs(cp->dport),
+				dbuf, ntohs(cp->dport),
 				ip_vs_state_name(cp->protocol, cp->state),
 				ip_vs_origin_name(cp->flags),
 				(cp->timer.expires-jiffies)/HZ);
@@ -1130,11 +1172,11 @@
 #endif
 			seq_printf(seq,
 				"%-3s %08X %04X %08X %04X "
-				"%08X %04X %-11s %-6s %7lu\n",
+				"%s %04X %-11s %-6s %7lu\n",
 				ip_vs_proto_name(cp->protocol),
 				ntohl(cp->caddr.ip), ntohs(cp->cport),
 				ntohl(cp->vaddr.ip), ntohs(cp->vport),
-				ntohl(cp->daddr.ip), ntohs(cp->dport),
+				dbuf, ntohs(cp->dport),
 				ip_vs_state_name(cp->protocol, cp->state),
 				ip_vs_origin_name(cp->flags),
 				(cp->timer.expires-jiffies)/HZ);
diff -urN linux/net/netfilter/ipvs/ip_vs_core.c net-next-2.6/net/netfilter/ipvs/ip_vs_core.c
--- linux/net/netfilter/ipvs/ip_vs_core.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_core.c	2014-10-06 10:49:03.956938424 +0200
@@ -328,7 +328,7 @@
 		 * This adds param.pe_data to the template,
 		 * and thus param.pe_data will be destroyed
 		 * when the template expires */
-		ct = ip_vs_conn_new(&param, &dest->addr, dport,
+		ct = ip_vs_conn_new(&param, dest->af, &dest->addr, dport,
 				    IP_VS_CONN_F_TEMPLATE, dest, skb->mark);
 		if (ct == NULL) {
 			kfree(param.pe_data);
@@ -357,7 +357,8 @@
 	ip_vs_conn_fill_param(svc->net, svc->af, iph->protocol, &iph->saddr,
 			      src_port, &iph->daddr, dst_port, &param);
 
-	cp = ip_vs_conn_new(&param, &dest->addr, dport, flags, dest, skb->mark);
+	cp = ip_vs_conn_new(&param, dest->af, &dest->addr, dport, flags, dest,
+			    skb->mark);
 	if (cp == NULL) {
 		ip_vs_conn_put(ct);
 		*ignored = -1;
@@ -479,7 +480,7 @@
 		ip_vs_conn_fill_param(svc->net, svc->af, iph->protocol,
 				      &iph->saddr, pptr[0], &iph->daddr,
 				      pptr[1], &p);
-		cp = ip_vs_conn_new(&p, &dest->addr,
+		cp = ip_vs_conn_new(&p, dest->af, &dest->addr,
 				    dest->port ? dest->port : pptr[1],
 				    flags, dest, skb->mark);
 		if (!cp) {
@@ -491,9 +492,9 @@
 	IP_VS_DBG_BUF(6, "Schedule fwd:%c c:%s:%u v:%s:%u "
 		      "d:%s:%u conn->flags:%X conn->refcnt:%d\n",
 		      ip_vs_fwd_tag(cp),
-		      IP_VS_DBG_ADDR(svc->af, &cp->caddr), ntohs(cp->cport),
-		      IP_VS_DBG_ADDR(svc->af, &cp->vaddr), ntohs(cp->vport),
-		      IP_VS_DBG_ADDR(svc->af, &cp->daddr), ntohs(cp->dport),
+		      IP_VS_DBG_ADDR(cp->af, &cp->caddr), ntohs(cp->cport),
+		      IP_VS_DBG_ADDR(cp->af, &cp->vaddr), ntohs(cp->vport),
+		      IP_VS_DBG_ADDR(cp->daf, &cp->daddr), ntohs(cp->dport),
 		      cp->flags, atomic_read(&cp->refcnt));
 
 	ip_vs_conn_stats(cp, svc);
@@ -550,7 +551,7 @@
 			ip_vs_conn_fill_param(svc->net, svc->af, iph->protocol,
 					      &iph->saddr, pptr[0],
 					      &iph->daddr, pptr[1], &p);
-			cp = ip_vs_conn_new(&p, &daddr, 0,
+			cp = ip_vs_conn_new(&p, svc->af, &daddr, 0,
 					    IP_VS_CONN_F_BYPASS | flags,
 					    NULL, skb->mark);
 			if (!cp)
diff -urN linux/net/netfilter/ipvs/ip_vs_ctl.c net-next-2.6/net/netfilter/ipvs/ip_vs_ctl.c
--- linux/net/netfilter/ipvs/ip_vs_ctl.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_ctl.c	2014-10-06 10:49:03.972938587 +0200
@@ -574,8 +574,8 @@
  * Called under RCU lock.
  */
 static struct ip_vs_dest *
-ip_vs_lookup_dest(struct ip_vs_service *svc, const union nf_inet_addr *daddr,
-		  __be16 dport)
+ip_vs_lookup_dest(struct ip_vs_service *svc, int dest_af,
+		  const union nf_inet_addr *daddr, __be16 dport)
 {
 	struct ip_vs_dest *dest;
 
@@ -583,9 +583,9 @@
 	 * Find the destination for the given service
 	 */
 	list_for_each_entry_rcu(dest, &svc->destinations, n_list) {
-		if ((dest->af == svc->af)
-		    && ip_vs_addr_equal(svc->af, &dest->addr, daddr)
-		    && (dest->port == dport)) {
+		if ((dest->af == dest_af) &&
+		    ip_vs_addr_equal(dest_af, &dest->addr, daddr) &&
+		    (dest->port == dport)) {
 			/* HIT */
 			return dest;
 		}
@@ -602,7 +602,7 @@
  * on the backup.
  * Called under RCU lock, no refcnt is returned.
  */
-struct ip_vs_dest *ip_vs_find_dest(struct net  *net, int af,
+struct ip_vs_dest *ip_vs_find_dest(struct net  *net, int svc_af, int dest_af,
 				   const union nf_inet_addr *daddr,
 				   __be16 dport,
 				   const union nf_inet_addr *vaddr,
@@ -613,14 +613,14 @@
 	struct ip_vs_service *svc;
 	__be16 port = dport;
 
-	svc = ip_vs_service_find(net, af, fwmark, protocol, vaddr, vport);
+	svc = ip_vs_service_find(net, svc_af, fwmark, protocol, vaddr, vport);
 	if (!svc)
 		return NULL;
 	if (fwmark && (flags & IP_VS_CONN_F_FWD_MASK) != IP_VS_CONN_F_MASQ)
 		port = 0;
-	dest = ip_vs_lookup_dest(svc, daddr, port);
+	dest = ip_vs_lookup_dest(svc, dest_af, daddr, port);
 	if (!dest)
-		dest = ip_vs_lookup_dest(svc, daddr, port ^ dport);
+		dest = ip_vs_lookup_dest(svc, dest_af, daddr, port ^ dport);
 	return dest;
 }
 
@@ -657,8 +657,8 @@
  *  scheduling.
  */
 static struct ip_vs_dest *
-ip_vs_trash_get_dest(struct ip_vs_service *svc, const union nf_inet_addr *daddr,
-		     __be16 dport)
+ip_vs_trash_get_dest(struct ip_vs_service *svc, int dest_af,
+		     const union nf_inet_addr *daddr, __be16 dport)
 {
 	struct ip_vs_dest *dest;
 	struct netns_ipvs *ipvs = net_ipvs(svc->net);
@@ -671,11 +671,11 @@
 		IP_VS_DBG_BUF(3, "Destination %u/%s:%u still in trash, "
 			      "dest->refcnt=%d\n",
 			      dest->vfwmark,
-			      IP_VS_DBG_ADDR(svc->af, &dest->addr),
+			      IP_VS_DBG_ADDR(dest->af, &dest->addr),
 			      ntohs(dest->port),
 			      atomic_read(&dest->refcnt));
-		if (dest->af == svc->af &&
-		    ip_vs_addr_equal(svc->af, &dest->addr, daddr) &&
+		if (dest->af == dest_af &&
+		    ip_vs_addr_equal(dest_af, &dest->addr, daddr) &&
 		    dest->port == dport &&
 		    dest->vfwmark == svc->fwmark &&
 		    dest->protocol == svc->protocol &&
@@ -779,6 +779,12 @@
 	struct ip_vs_scheduler *sched;
 	int conn_flags;
 
+	/* We cannot modify an address and change the address family */
+	BUG_ON(!add && udest->af != dest->af);
+
+	if (add && udest->af != svc->af)
+		ipvs->mixed_address_family_dests++;
+
 	/* set the weight and the flags */
 	atomic_set(&dest->weight, udest->weight);
 	conn_flags = udest->conn_flags & IP_VS_CONN_F_DEST_MASK;
@@ -816,6 +822,8 @@
 	dest->u_threshold = udest->u_threshold;
 	dest->l_threshold = udest->l_threshold;
 
+	dest->af = udest->af;
+
 	spin_lock_bh(&dest->dst_lock);
 	__ip_vs_dst_cache_reset(dest);
 	spin_unlock_bh(&dest->dst_lock);
@@ -847,7 +855,7 @@
 	EnterFunction(2);
 
 #ifdef CONFIG_IP_VS_IPV6
-	if (svc->af == AF_INET6) {
+	if (udest->af == AF_INET6) {
 		atype = ipv6_addr_type(&udest->addr.in6);
 		if ((!(atype & IPV6_ADDR_UNICAST) ||
 			atype & IPV6_ADDR_LINKLOCAL) &&
@@ -875,12 +883,12 @@
 		u64_stats_init(&ip_vs_dest_stats->syncp);
 	}
 
-	dest->af = svc->af;
+	dest->af = udest->af;
 	dest->protocol = svc->protocol;
 	dest->vaddr = svc->addr;
 	dest->vport = svc->port;
 	dest->vfwmark = svc->fwmark;
-	ip_vs_addr_copy(svc->af, &dest->addr, &udest->addr);
+	ip_vs_addr_copy(udest->af, &dest->addr, &udest->addr);
 	dest->port = udest->port;
 
 	atomic_set(&dest->activeconns, 0);
@@ -928,11 +936,11 @@
 		return -ERANGE;
 	}
 
-	ip_vs_addr_copy(svc->af, &daddr, &udest->addr);
+	ip_vs_addr_copy(udest->af, &daddr, &udest->addr);
 
 	/* We use function that requires RCU lock */
 	rcu_read_lock();
-	dest = ip_vs_lookup_dest(svc, &daddr, dport);
+	dest = ip_vs_lookup_dest(svc, udest->af, &daddr, dport);
 	rcu_read_unlock();
 
 	if (dest != NULL) {
@@ -944,12 +952,12 @@
 	 * Check if the dest already exists in the trash and
 	 * is from the same service
 	 */
-	dest = ip_vs_trash_get_dest(svc, &daddr, dport);
+	dest = ip_vs_trash_get_dest(svc, udest->af, &daddr, dport);
 
 	if (dest != NULL) {
 		IP_VS_DBG_BUF(3, "Get destination %s:%u from trash, "
 			      "dest->refcnt=%d, service %u/%s:%u\n",
-			      IP_VS_DBG_ADDR(svc->af, &daddr), ntohs(dport),
+			      IP_VS_DBG_ADDR(udest->af, &daddr), ntohs(dport),
 			      atomic_read(&dest->refcnt),
 			      dest->vfwmark,
 			      IP_VS_DBG_ADDR(svc->af, &dest->vaddr),
@@ -992,11 +1000,11 @@
 		return -ERANGE;
 	}
 
-	ip_vs_addr_copy(svc->af, &daddr, &udest->addr);
+	ip_vs_addr_copy(udest->af, &daddr, &udest->addr);
 
 	/* We use function that requires RCU lock */
 	rcu_read_lock();
-	dest = ip_vs_lookup_dest(svc, &daddr, dport);
+	dest = ip_vs_lookup_dest(svc, udest->af, &daddr, dport);
 	rcu_read_unlock();
 
 	if (dest == NULL) {
@@ -1055,6 +1063,9 @@
 	list_del_rcu(&dest->n_list);
 	svc->num_dests--;
 
+	if (dest->af != svc->af)
+		net_ipvs(svc->net)->mixed_address_family_dests--;
+
 	if (svcupd) {
 		struct ip_vs_scheduler *sched;
 
@@ -1078,7 +1089,7 @@
 
 	/* We use function that requires RCU lock */
 	rcu_read_lock();
-	dest = ip_vs_lookup_dest(svc, &udest->addr, dport);
+	dest = ip_vs_lookup_dest(svc, udest->af, &udest->addr, dport);
 	rcu_read_unlock();
 
 	if (dest == NULL) {
@@ -2179,29 +2190,41 @@
 	return 0;
 }
 
+#define CMDID(cmd)		(cmd - IP_VS_BASE_CTL)
+
+struct ip_vs_svcdest_user {
+	struct ip_vs_service_user	s;
+	struct ip_vs_dest_user		d;
+};
+
+static const unsigned char set_arglen[CMDID(IP_VS_SO_SET_MAX) + 1] = {
+	[CMDID(IP_VS_SO_SET_ADD)]         = sizeof(struct ip_vs_service_user),
+	[CMDID(IP_VS_SO_SET_EDIT)]        = sizeof(struct ip_vs_service_user),
+	[CMDID(IP_VS_SO_SET_DEL)]         = sizeof(struct ip_vs_service_user),
+	[CMDID(IP_VS_SO_SET_ADDDEST)]     = sizeof(struct ip_vs_svcdest_user),
+	[CMDID(IP_VS_SO_SET_DELDEST)]     = sizeof(struct ip_vs_svcdest_user),
+	[CMDID(IP_VS_SO_SET_EDITDEST)]    = sizeof(struct ip_vs_svcdest_user),
+	[CMDID(IP_VS_SO_SET_TIMEOUT)]     = sizeof(struct ip_vs_timeout_user),
+	[CMDID(IP_VS_SO_SET_STARTDAEMON)] = sizeof(struct ip_vs_daemon_user),
+	[CMDID(IP_VS_SO_SET_STOPDAEMON)]  = sizeof(struct ip_vs_daemon_user),
+	[CMDID(IP_VS_SO_SET_ZERO)]        = sizeof(struct ip_vs_service_user),
+};
 
-#define SET_CMDID(cmd)		(cmd - IP_VS_BASE_CTL)
-#define SERVICE_ARG_LEN		(sizeof(struct ip_vs_service_user))
-#define SVCDEST_ARG_LEN		(sizeof(struct ip_vs_service_user) +	\
-				 sizeof(struct ip_vs_dest_user))
-#define TIMEOUT_ARG_LEN		(sizeof(struct ip_vs_timeout_user))
-#define DAEMON_ARG_LEN		(sizeof(struct ip_vs_daemon_user))
-#define MAX_ARG_LEN		SVCDEST_ARG_LEN
-
-static const unsigned char set_arglen[SET_CMDID(IP_VS_SO_SET_MAX)+1] = {
-	[SET_CMDID(IP_VS_SO_SET_ADD)]		= SERVICE_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_EDIT)]		= SERVICE_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_DEL)]		= SERVICE_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_FLUSH)]		= 0,
-	[SET_CMDID(IP_VS_SO_SET_ADDDEST)]	= SVCDEST_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_DELDEST)]	= SVCDEST_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_EDITDEST)]	= SVCDEST_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_TIMEOUT)]	= TIMEOUT_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_STARTDAEMON)]	= DAEMON_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_STOPDAEMON)]	= DAEMON_ARG_LEN,
-	[SET_CMDID(IP_VS_SO_SET_ZERO)]		= SERVICE_ARG_LEN,
+union ip_vs_set_arglen {
+	struct ip_vs_service_user	field_IP_VS_SO_SET_ADD;
+	struct ip_vs_service_user	field_IP_VS_SO_SET_EDIT;
+	struct ip_vs_service_user	field_IP_VS_SO_SET_DEL;
+	struct ip_vs_svcdest_user	field_IP_VS_SO_SET_ADDDEST;
+	struct ip_vs_svcdest_user	field_IP_VS_SO_SET_DELDEST;
+	struct ip_vs_svcdest_user	field_IP_VS_SO_SET_EDITDEST;
+	struct ip_vs_timeout_user	field_IP_VS_SO_SET_TIMEOUT;
+	struct ip_vs_daemon_user	field_IP_VS_SO_SET_STARTDAEMON;
+	struct ip_vs_daemon_user	field_IP_VS_SO_SET_STOPDAEMON;
+	struct ip_vs_service_user	field_IP_VS_SO_SET_ZERO;
 };
 
+#define MAX_SET_ARGLEN	sizeof(union ip_vs_set_arglen)
+
 static void ip_vs_copy_usvc_compat(struct ip_vs_service_user_kern *usvc,
 				  struct ip_vs_service_user *usvc_compat)
 {
@@ -2232,6 +2255,7 @@
 	udest->weight		= udest_compat->weight;
 	udest->u_threshold	= udest_compat->u_threshold;
 	udest->l_threshold	= udest_compat->l_threshold;
+	udest->af		= AF_INET;
 }
 
 static int
@@ -2239,7 +2263,7 @@
 {
 	struct net *net = sock_net(sk);
 	int ret;
-	unsigned char arg[MAX_ARG_LEN];
+	unsigned char arg[MAX_SET_ARGLEN];
 	struct ip_vs_service_user *usvc_compat;
 	struct ip_vs_service_user_kern usvc;
 	struct ip_vs_service *svc;
@@ -2247,16 +2271,15 @@
 	struct ip_vs_dest_user_kern udest;
 	struct netns_ipvs *ipvs = net_ipvs(net);
 
+	BUILD_BUG_ON(sizeof(arg) > 255);
 	if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
 		return -EPERM;
 
 	if (cmd < IP_VS_BASE_CTL || cmd > IP_VS_SO_SET_MAX)
 		return -EINVAL;
-	if (len < 0 || len >  MAX_ARG_LEN)
-		return -EINVAL;
-	if (len != set_arglen[SET_CMDID(cmd)]) {
-		pr_err("set_ctl: len %u != %u\n",
-		       len, set_arglen[SET_CMDID(cmd)]);
+	if (len != set_arglen[CMDID(cmd)]) {
+		IP_VS_DBG(1, "set_ctl: len %u != %u\n",
+			  len, set_arglen[CMDID(cmd)]);
 		return -EINVAL;
 	}
 
@@ -2469,6 +2492,12 @@
 			if (count >= get->num_dests)
 				break;
 
+			/* Cannot expose heterogeneous members via sockopt
+			 * interface
+			 */
+			if (dest->af != svc->af)
+				continue;
+
 			entry.addr = dest->addr.ip;
 			entry.port = dest->port;
 			entry.conn_flags = atomic_read(&dest->conn_flags);
@@ -2512,51 +2541,51 @@
 #endif
 }
 
+static const unsigned char get_arglen[CMDID(IP_VS_SO_GET_MAX) + 1] = {
+	[CMDID(IP_VS_SO_GET_VERSION)]  = 64,
+	[CMDID(IP_VS_SO_GET_INFO)]     = sizeof(struct ip_vs_getinfo),
+	[CMDID(IP_VS_SO_GET_SERVICES)] = sizeof(struct ip_vs_get_services),
+	[CMDID(IP_VS_SO_GET_SERVICE)]  = sizeof(struct ip_vs_service_entry),
+	[CMDID(IP_VS_SO_GET_DESTS)]    = sizeof(struct ip_vs_get_dests),
+	[CMDID(IP_VS_SO_GET_TIMEOUT)]  = sizeof(struct ip_vs_timeout_user),
+	[CMDID(IP_VS_SO_GET_DAEMON)]   = 2 * sizeof(struct ip_vs_daemon_user),
+};
 
-#define GET_CMDID(cmd)		(cmd - IP_VS_BASE_CTL)
-#define GET_INFO_ARG_LEN	(sizeof(struct ip_vs_getinfo))
-#define GET_SERVICES_ARG_LEN	(sizeof(struct ip_vs_get_services))
-#define GET_SERVICE_ARG_LEN	(sizeof(struct ip_vs_service_entry))
-#define GET_DESTS_ARG_LEN	(sizeof(struct ip_vs_get_dests))
-#define GET_TIMEOUT_ARG_LEN	(sizeof(struct ip_vs_timeout_user))
-#define GET_DAEMON_ARG_LEN	(sizeof(struct ip_vs_daemon_user) * 2)
-
-static const unsigned char get_arglen[GET_CMDID(IP_VS_SO_GET_MAX)+1] = {
-	[GET_CMDID(IP_VS_SO_GET_VERSION)]	= 64,
-	[GET_CMDID(IP_VS_SO_GET_INFO)]		= GET_INFO_ARG_LEN,
-	[GET_CMDID(IP_VS_SO_GET_SERVICES)]	= GET_SERVICES_ARG_LEN,
-	[GET_CMDID(IP_VS_SO_GET_SERVICE)]	= GET_SERVICE_ARG_LEN,
-	[GET_CMDID(IP_VS_SO_GET_DESTS)]		= GET_DESTS_ARG_LEN,
-	[GET_CMDID(IP_VS_SO_GET_TIMEOUT)]	= GET_TIMEOUT_ARG_LEN,
-	[GET_CMDID(IP_VS_SO_GET_DAEMON)]	= GET_DAEMON_ARG_LEN,
+union ip_vs_get_arglen {
+	char				field_IP_VS_SO_GET_VERSION[64];
+	struct ip_vs_getinfo		field_IP_VS_SO_GET_INFO;
+	struct ip_vs_get_services	field_IP_VS_SO_GET_SERVICES;
+	struct ip_vs_service_entry	field_IP_VS_SO_GET_SERVICE;
+	struct ip_vs_get_dests		field_IP_VS_SO_GET_DESTS;
+	struct ip_vs_timeout_user	field_IP_VS_SO_GET_TIMEOUT;
+	struct ip_vs_daemon_user	field_IP_VS_SO_GET_DAEMON[2];
 };
 
+#define MAX_GET_ARGLEN	sizeof(union ip_vs_get_arglen)
+
 static int
 do_ip_vs_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
 {
-	unsigned char arg[128];
+	unsigned char arg[MAX_GET_ARGLEN];
 	int ret = 0;
 	unsigned int copylen;
 	struct net *net = sock_net(sk);
 	struct netns_ipvs *ipvs = net_ipvs(net);
 
 	BUG_ON(!net);
+	BUILD_BUG_ON(sizeof(arg) > 255);
 	if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
 		return -EPERM;
 
 	if (cmd < IP_VS_BASE_CTL || cmd > IP_VS_SO_GET_MAX)
 		return -EINVAL;
 
-	if (*len < get_arglen[GET_CMDID(cmd)]) {
-		pr_err("get_ctl: len %u < %u\n",
-		       *len, get_arglen[GET_CMDID(cmd)]);
+	copylen = get_arglen[CMDID(cmd)];
+	if (*len < (int) copylen) {
+		IP_VS_DBG(1, "get_ctl: len %d < %u\n", *len, copylen);
 		return -EINVAL;
 	}
 
-	copylen = get_arglen[GET_CMDID(cmd)];
-	if (copylen > 128)
-		return -EINVAL;
-
 	if (copy_from_user(arg, user, copylen) != 0)
 		return -EFAULT;
 	/*
@@ -2766,6 +2795,7 @@
 	[IPVS_DEST_ATTR_INACT_CONNS]	= { .type = NLA_U32 },
 	[IPVS_DEST_ATTR_PERSIST_CONNS]	= { .type = NLA_U32 },
 	[IPVS_DEST_ATTR_STATS]		= { .type = NLA_NESTED },
+	[IPVS_DEST_ATTR_ADDR_FAMILY]	= { .type = NLA_U16 },
 };
 
 static int ip_vs_genl_fill_stats(struct sk_buff *skb, int container_type,
@@ -3021,7 +3051,8 @@
 	    nla_put_u32(skb, IPVS_DEST_ATTR_INACT_CONNS,
 			atomic_read(&dest->inactconns)) ||
 	    nla_put_u32(skb, IPVS_DEST_ATTR_PERSIST_CONNS,
-			atomic_read(&dest->persistconns)))
+			atomic_read(&dest->persistconns)) ||
+	    nla_put_u16(skb, IPVS_DEST_ATTR_ADDR_FAMILY, dest->af))
 		goto nla_put_failure;
 	if (ip_vs_genl_fill_stats(skb, IPVS_DEST_ATTR_STATS, &dest->stats))
 		goto nla_put_failure;
@@ -3102,6 +3133,7 @@
 {
 	struct nlattr *attrs[IPVS_DEST_ATTR_MAX + 1];
 	struct nlattr *nla_addr, *nla_port;
+	struct nlattr *nla_addr_family;
 
 	/* Parse mandatory identifying destination fields first */
 	if (nla == NULL ||
@@ -3110,6 +3142,7 @@
 
 	nla_addr	= attrs[IPVS_DEST_ATTR_ADDR];
 	nla_port	= attrs[IPVS_DEST_ATTR_PORT];
+	nla_addr_family	= attrs[IPVS_DEST_ATTR_ADDR_FAMILY];
 
 	if (!(nla_addr && nla_port))
 		return -EINVAL;
@@ -3119,6 +3152,11 @@
 	nla_memcpy(&udest->addr, nla_addr, sizeof(udest->addr));
 	udest->port = nla_get_be16(nla_port);
 
+	if (nla_addr_family)
+		udest->af = nla_get_u16(nla_addr_family);
+	else
+		udest->af = 0;
+
 	/* If a full entry was requested, check for the additional fields */
 	if (full_entry) {
 		struct nlattr *nla_fwd, *nla_weight, *nla_u_thresh,
@@ -3223,6 +3261,12 @@
 	      attrs[IPVS_DAEMON_ATTR_SYNC_ID]))
 		return -EINVAL;
 
+	/* The synchronization protocol is incompatible with mixed family
+	 * services
+	 */
+	if (net_ipvs(net)->mixed_address_family_dests > 0)
+		return -EINVAL;
+
 	return start_sync_thread(net,
 				 nla_get_u32(attrs[IPVS_DAEMON_ATTR_STATE]),
 				 nla_data(attrs[IPVS_DAEMON_ATTR_MCAST_IFN]),
@@ -3346,6 +3390,35 @@
 					    need_full_dest);
 		if (ret)
 			goto out;
+
+		/* Old protocols did not allow the user to specify address
+		 * family, so we set it to zero instead.  We also didn't
+		 * allow heterogeneous pools in the old code, so it's safe
+		 * to assume that this will have the same address family as
+		 * the service.
+		 */
+		if (udest.af == 0)
+			udest.af = svc->af;
+
+		if (udest.af != svc->af) {
+			/* The synchronization protocol is incompatible
+			 * with mixed family services
+			 */
+			if (net_ipvs(net)->sync_state) {
+				ret = -EINVAL;
+				goto out;
+			}
+
+			/* Which connection types do we support? */
+			switch (udest.conn_flags) {
+			case IP_VS_CONN_F_TUNNEL:
+				/* We are able to forward this */
+				break;
+			default:
+				ret = -EINVAL;
+				goto out;
+			}
+		}
 	}
 
 	switch (cmd) {
diff -urN linux/net/netfilter/ipvs/ip_vs_dh.c net-next-2.6/net/netfilter/ipvs/ip_vs_dh.c
--- linux/net/netfilter/ipvs/ip_vs_dh.c	2013-11-29 12:59:37.971382457 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_dh.c	2014-10-06 10:49:03.972938587 +0200
@@ -234,7 +234,7 @@
 
 	IP_VS_DBG_BUF(6, "DH: destination IP address %s --> server %s:%d\n",
 		      IP_VS_DBG_ADDR(svc->af, &iph->daddr),
-		      IP_VS_DBG_ADDR(svc->af, &dest->addr),
+		      IP_VS_DBG_ADDR(dest->af, &dest->addr),
 		      ntohs(dest->port));
 
 	return dest;
diff -urN linux/net/netfilter/ipvs/ip_vs_fo.c net-next-2.6/net/netfilter/ipvs/ip_vs_fo.c
--- linux/net/netfilter/ipvs/ip_vs_fo.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_fo.c	2014-10-06 10:49:03.972938587 +0200
@@ -0,0 +1,79 @@
+/*
+ * IPVS:        Weighted Fail Over module
+ *
+ * Authors:     Kenny Mathis <kmathis@chokepoint.net>
+ *
+ *              This program is free software; you can redistribute it and/or
+ *              modify it under the terms of the GNU General Public License
+ *              as published by the Free Software Foundation; either version
+ *              2 of the License, or (at your option) any later version.
+ *
+ * Changes:
+ *     Kenny Mathis            :     added initial functionality based on weight
+ *
+ */
+
+#define KMSG_COMPONENT "IPVS"
+#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt
+
+#include <linux/module.h>
+#include <linux/kernel.h>
+
+#include <net/ip_vs.h>
+
+/* Weighted Fail Over Module */
+static struct ip_vs_dest *
+ip_vs_fo_schedule(struct ip_vs_service *svc, const struct sk_buff *skb,
+		  struct ip_vs_iphdr *iph)
+{
+	struct ip_vs_dest *dest, *hweight = NULL;
+	int hw = 0; /* Track highest weight */
+
+	IP_VS_DBG(6, "ip_vs_fo_schedule(): Scheduling...\n");
+
+	/* Basic failover functionality
+	 * Find virtual server with highest weight and send it traffic
+	 */
+	list_for_each_entry_rcu(dest, &svc->destinations, n_list) {
+		if (!(dest->flags & IP_VS_DEST_F_OVERLOAD) &&
+		    atomic_read(&dest->weight) > hw) {
+			hweight = dest;
+			hw = atomic_read(&dest->weight);
+		}
+	}
+
+	if (hweight) {
+		IP_VS_DBG_BUF(6, "FO: server %s:%u activeconns %d weight %d\n",
+			      IP_VS_DBG_ADDR(hweight->af, &hweight->addr),
+			      ntohs(hweight->port),
+			      atomic_read(&hweight->activeconns),
+			      atomic_read(&hweight->weight));
+		return hweight;
+	}
+
+	ip_vs_scheduler_err(svc, "no destination available");
+	return NULL;
+}
+
+static struct ip_vs_scheduler ip_vs_fo_scheduler = {
+	.name =			"fo",
+	.refcnt =		ATOMIC_INIT(0),
+	.module =		THIS_MODULE,
+	.n_list =		LIST_HEAD_INIT(ip_vs_fo_scheduler.n_list),
+	.schedule =		ip_vs_fo_schedule,
+};
+
+static int __init ip_vs_fo_init(void)
+{
+	return register_ip_vs_scheduler(&ip_vs_fo_scheduler);
+}
+
+static void __exit ip_vs_fo_cleanup(void)
+{
+	unregister_ip_vs_scheduler(&ip_vs_fo_scheduler);
+	synchronize_rcu();
+}
+
+module_init(ip_vs_fo_init);
+module_exit(ip_vs_fo_cleanup);
+MODULE_LICENSE("GPL");
diff -urN linux/net/netfilter/ipvs/ip_vs_ftp.c net-next-2.6/net/netfilter/ipvs/ip_vs_ftp.c
--- linux/net/netfilter/ipvs/ip_vs_ftp.c	2013-05-02 09:43:21.649515164 +0200
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_ftp.c	2014-10-06 10:49:03.972938587 +0200
@@ -233,7 +233,8 @@
 			ip_vs_conn_fill_param(ip_vs_conn_net(cp),
 					      AF_INET, IPPROTO_TCP, &cp->caddr,
 					      0, &cp->vaddr, port, &p);
-			n_cp = ip_vs_conn_new(&p, &from, port,
+			/* As above, this is ipv4 only */
+			n_cp = ip_vs_conn_new(&p, AF_INET, &from, port,
 					      IP_VS_CONN_F_NO_CPORT |
 					      IP_VS_CONN_F_NFCT,
 					      cp->dest, skb->mark);
@@ -396,7 +397,8 @@
 				      htons(ntohs(cp->vport)-1), &p);
 		n_cp = ip_vs_conn_in_get(&p);
 		if (!n_cp) {
-			n_cp = ip_vs_conn_new(&p, &cp->daddr,
+			/* This is ipv4 only */
+			n_cp = ip_vs_conn_new(&p, AF_INET, &cp->daddr,
 					      htons(ntohs(cp->dport)-1),
 					      IP_VS_CONN_F_NFCT, cp->dest,
 					      skb->mark);
diff -urN linux/net/netfilter/ipvs/ip_vs_lblc.c net-next-2.6/net/netfilter/ipvs/ip_vs_lblc.c
--- linux/net/netfilter/ipvs/ip_vs_lblc.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_lblc.c	2014-10-06 10:49:03.972938587 +0200
@@ -199,11 +199,11 @@
  */
 static inline struct ip_vs_lblc_entry *
 ip_vs_lblc_new(struct ip_vs_lblc_table *tbl, const union nf_inet_addr *daddr,
-	       struct ip_vs_dest *dest)
+	       u16 af, struct ip_vs_dest *dest)
 {
 	struct ip_vs_lblc_entry *en;
 
-	en = ip_vs_lblc_get(dest->af, tbl, daddr);
+	en = ip_vs_lblc_get(af, tbl, daddr);
 	if (en) {
 		if (en->dest == dest)
 			return en;
@@ -213,8 +213,8 @@
 	if (!en)
 		return NULL;
 
-	en->af = dest->af;
-	ip_vs_addr_copy(dest->af, &en->addr, daddr);
+	en->af = af;
+	ip_vs_addr_copy(af, &en->addr, daddr);
 	en->lastuse = jiffies;
 
 	ip_vs_dest_hold(dest);
@@ -521,13 +521,13 @@
 	/* If we fail to create a cache entry, we'll just use the valid dest */
 	spin_lock_bh(&svc->sched_lock);
 	if (!tbl->dead)
-		ip_vs_lblc_new(tbl, &iph->daddr, dest);
+		ip_vs_lblc_new(tbl, &iph->daddr, svc->af, dest);
 	spin_unlock_bh(&svc->sched_lock);
 
 out:
 	IP_VS_DBG_BUF(6, "LBLC: destination IP address %s --> server %s:%d\n",
 		      IP_VS_DBG_ADDR(svc->af, &iph->daddr),
-		      IP_VS_DBG_ADDR(svc->af, &dest->addr), ntohs(dest->port));
+		      IP_VS_DBG_ADDR(dest->af, &dest->addr), ntohs(dest->port));
 
 	return dest;
 }
diff -urN linux/net/netfilter/ipvs/ip_vs_lblcr.c net-next-2.6/net/netfilter/ipvs/ip_vs_lblcr.c
--- linux/net/netfilter/ipvs/ip_vs_lblcr.c	2013-11-29 12:59:37.971382457 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_lblcr.c	2014-10-06 10:49:03.976938627 +0200
@@ -362,18 +362,18 @@
  */
 static inline struct ip_vs_lblcr_entry *
 ip_vs_lblcr_new(struct ip_vs_lblcr_table *tbl, const union nf_inet_addr *daddr,
-		struct ip_vs_dest *dest)
+		u16 af, struct ip_vs_dest *dest)
 {
 	struct ip_vs_lblcr_entry *en;
 
-	en = ip_vs_lblcr_get(dest->af, tbl, daddr);
+	en = ip_vs_lblcr_get(af, tbl, daddr);
 	if (!en) {
 		en = kmalloc(sizeof(*en), GFP_ATOMIC);
 		if (!en)
 			return NULL;
 
-		en->af = dest->af;
-		ip_vs_addr_copy(dest->af, &en->addr, daddr);
+		en->af = af;
+		ip_vs_addr_copy(af, &en->addr, daddr);
 		en->lastuse = jiffies;
 
 		/* initialize its dest set */
@@ -706,13 +706,13 @@
 	/* If we fail to create a cache entry, we'll just use the valid dest */
 	spin_lock_bh(&svc->sched_lock);
 	if (!tbl->dead)
-		ip_vs_lblcr_new(tbl, &iph->daddr, dest);
+		ip_vs_lblcr_new(tbl, &iph->daddr, svc->af, dest);
 	spin_unlock_bh(&svc->sched_lock);
 
 out:
 	IP_VS_DBG_BUF(6, "LBLCR: destination IP address %s --> server %s:%d\n",
 		      IP_VS_DBG_ADDR(svc->af, &iph->daddr),
-		      IP_VS_DBG_ADDR(svc->af, &dest->addr), ntohs(dest->port));
+		      IP_VS_DBG_ADDR(dest->af, &dest->addr), ntohs(dest->port));
 
 	return dest;
 }
diff -urN linux/net/netfilter/ipvs/ip_vs_lc.c net-next-2.6/net/netfilter/ipvs/ip_vs_lc.c
--- linux/net/netfilter/ipvs/ip_vs_lc.c	2013-11-29 12:59:37.971382457 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_lc.c	2014-10-06 10:49:03.976938627 +0200
@@ -59,7 +59,7 @@
 	else
 		IP_VS_DBG_BUF(6, "LC: server %s:%u activeconns %d "
 			      "inactconns %d\n",
-			      IP_VS_DBG_ADDR(svc->af, &least->addr),
+			      IP_VS_DBG_ADDR(least->af, &least->addr),
 			      ntohs(least->port),
 			      atomic_read(&least->activeconns),
 			      atomic_read(&least->inactconns));
diff -urN linux/net/netfilter/ipvs/ip_vs_nq.c net-next-2.6/net/netfilter/ipvs/ip_vs_nq.c
--- linux/net/netfilter/ipvs/ip_vs_nq.c	2013-11-29 12:59:37.971382457 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_nq.c	2014-10-06 10:49:03.976938627 +0200
@@ -107,7 +107,8 @@
   out:
 	IP_VS_DBG_BUF(6, "NQ: server %s:%u "
 		      "activeconns %d refcnt %d weight %d overhead %d\n",
-		      IP_VS_DBG_ADDR(svc->af, &least->addr), ntohs(least->port),
+		      IP_VS_DBG_ADDR(least->af, &least->addr),
+		      ntohs(least->port),
 		      atomic_read(&least->activeconns),
 		      atomic_read(&least->refcnt),
 		      atomic_read(&least->weight), loh);
diff -urN linux/net/netfilter/ipvs/ip_vs_proto_sctp.c net-next-2.6/net/netfilter/ipvs/ip_vs_proto_sctp.c
--- linux/net/netfilter/ipvs/ip_vs_proto_sctp.c	2013-11-29 12:59:37.975382498 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_proto_sctp.c	2014-10-06 10:49:03.976938627 +0200
@@ -432,7 +432,7 @@
 				pd->pp->name,
 				((direction == IP_VS_DIR_OUTPUT) ?
 				 "output " : "input "),
-				IP_VS_DBG_ADDR(cp->af, &cp->daddr),
+				IP_VS_DBG_ADDR(cp->daf, &cp->daddr),
 				ntohs(cp->dport),
 				IP_VS_DBG_ADDR(cp->af, &cp->caddr),
 				ntohs(cp->cport),
diff -urN linux/net/netfilter/ipvs/ip_vs_proto_tcp.c net-next-2.6/net/netfilter/ipvs/ip_vs_proto_tcp.c
--- linux/net/netfilter/ipvs/ip_vs_proto_tcp.c	2013-11-29 12:59:37.975382498 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_proto_tcp.c	2014-10-06 10:49:03.976938627 +0200
@@ -510,7 +510,7 @@
 			      th->fin ? 'F' : '.',
 			      th->ack ? 'A' : '.',
 			      th->rst ? 'R' : '.',
-			      IP_VS_DBG_ADDR(cp->af, &cp->daddr),
+			      IP_VS_DBG_ADDR(cp->daf, &cp->daddr),
 			      ntohs(cp->dport),
 			      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
 			      ntohs(cp->cport),
diff -urN linux/net/netfilter/ipvs/ip_vs_rr.c net-next-2.6/net/netfilter/ipvs/ip_vs_rr.c
--- linux/net/netfilter/ipvs/ip_vs_rr.c	2013-11-29 12:59:37.975382498 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_rr.c	2014-10-06 10:49:03.976938627 +0200
@@ -95,7 +95,7 @@
 	spin_unlock_bh(&svc->sched_lock);
 	IP_VS_DBG_BUF(6, "RR: server %s:%u "
 		      "activeconns %d refcnt %d weight %d\n",
-		      IP_VS_DBG_ADDR(svc->af, &dest->addr), ntohs(dest->port),
+		      IP_VS_DBG_ADDR(dest->af, &dest->addr), ntohs(dest->port),
 		      atomic_read(&dest->activeconns),
 		      atomic_read(&dest->refcnt), atomic_read(&dest->weight));
 
diff -urN linux/net/netfilter/ipvs/ip_vs_sed.c net-next-2.6/net/netfilter/ipvs/ip_vs_sed.c
--- linux/net/netfilter/ipvs/ip_vs_sed.c	2013-11-29 12:59:37.975382498 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_sed.c	2014-10-06 10:49:03.976938627 +0200
@@ -108,7 +108,8 @@
 
 	IP_VS_DBG_BUF(6, "SED: server %s:%u "
 		      "activeconns %d refcnt %d weight %d overhead %d\n",
-		      IP_VS_DBG_ADDR(svc->af, &least->addr), ntohs(least->port),
+		      IP_VS_DBG_ADDR(least->af, &least->addr),
+		      ntohs(least->port),
 		      atomic_read(&least->activeconns),
 		      atomic_read(&least->refcnt),
 		      atomic_read(&least->weight), loh);
diff -urN linux/net/netfilter/ipvs/ip_vs_sh.c net-next-2.6/net/netfilter/ipvs/ip_vs_sh.c
--- linux/net/netfilter/ipvs/ip_vs_sh.c	2013-11-29 12:59:37.975382498 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_sh.c	2014-10-06 10:49:03.976938627 +0200
@@ -138,7 +138,7 @@
 		return dest;
 
 	IP_VS_DBG_BUF(6, "SH: selected unavailable server %s:%d, reselecting",
-		      IP_VS_DBG_ADDR(svc->af, &dest->addr), ntohs(dest->port));
+		      IP_VS_DBG_ADDR(dest->af, &dest->addr), ntohs(dest->port));
 
 	/* if the original dest is unavailable, loop around the table
 	 * starting from ihash to find a new dest
@@ -153,7 +153,7 @@
 			return dest;
 		IP_VS_DBG_BUF(6, "SH: selected unavailable "
 			      "server %s:%d (offset %d), reselecting",
-			      IP_VS_DBG_ADDR(svc->af, &dest->addr),
+			      IP_VS_DBG_ADDR(dest->af, &dest->addr),
 			      ntohs(dest->port), roffset);
 	}
 
@@ -192,7 +192,7 @@
 			RCU_INIT_POINTER(b->dest, dest);
 
 			IP_VS_DBG_BUF(6, "assigned i: %d dest: %s weight: %d\n",
-				      i, IP_VS_DBG_ADDR(svc->af, &dest->addr),
+				      i, IP_VS_DBG_ADDR(dest->af, &dest->addr),
 				      atomic_read(&dest->weight));
 
 			/* Don't move to next dest until filling weight */
@@ -342,7 +342,7 @@
 
 	IP_VS_DBG_BUF(6, "SH: source IP address %s --> server %s:%d\n",
 		      IP_VS_DBG_ADDR(svc->af, &iph->saddr),
-		      IP_VS_DBG_ADDR(svc->af, &dest->addr),
+		      IP_VS_DBG_ADDR(dest->af, &dest->addr),
 		      ntohs(dest->port));
 
 	return dest;
diff -urN linux/net/netfilter/ipvs/ip_vs_sync.c net-next-2.6/net/netfilter/ipvs/ip_vs_sync.c
--- linux/net/netfilter/ipvs/ip_vs_sync.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_sync.c	2014-10-06 10:49:03.976938627 +0200
@@ -880,10 +880,17 @@
 		 * but still handled.
 		 */
 		rcu_read_lock();
-		dest = ip_vs_find_dest(net, type, daddr, dport, param->vaddr,
-				       param->vport, protocol, fwmark, flags);
+		/* This function is only invoked by the synchronization
+		 * code. We do not currently support heterogeneous pools
+		 * with synchronization, so we can make the assumption that
+		 * the svc_af is the same as the dest_af
+		 */
+		dest = ip_vs_find_dest(net, type, type, daddr, dport,
+				       param->vaddr, param->vport, protocol,
+				       fwmark, flags);
 
-		cp = ip_vs_conn_new(param, daddr, dport, flags, dest, fwmark);
+		cp = ip_vs_conn_new(param, type, daddr, dport, flags, dest,
+				    fwmark);
 		rcu_read_unlock();
 		if (!cp) {
 			kfree(param->pe_data);
diff -urN linux/net/netfilter/ipvs/ip_vs_wlc.c net-next-2.6/net/netfilter/ipvs/ip_vs_wlc.c
--- linux/net/netfilter/ipvs/ip_vs_wlc.c	2013-11-29 12:59:37.975382498 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_wlc.c	2014-10-06 10:49:03.980938668 +0200
@@ -80,7 +80,8 @@
 
 	IP_VS_DBG_BUF(6, "WLC: server %s:%u "
 		      "activeconns %d refcnt %d weight %d overhead %d\n",
-		      IP_VS_DBG_ADDR(svc->af, &least->addr), ntohs(least->port),
+		      IP_VS_DBG_ADDR(least->af, &least->addr),
+		      ntohs(least->port),
 		      atomic_read(&least->activeconns),
 		      atomic_read(&least->refcnt),
 		      atomic_read(&least->weight), loh);
diff -urN linux/net/netfilter/ipvs/ip_vs_wrr.c net-next-2.6/net/netfilter/ipvs/ip_vs_wrr.c
--- linux/net/netfilter/ipvs/ip_vs_wrr.c	2013-11-29 12:59:37.975382498 +0100
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_wrr.c	2014-10-06 10:49:03.980938668 +0200
@@ -216,7 +216,7 @@
 found:
 	IP_VS_DBG_BUF(6, "WRR: server %s:%u "
 		      "activeconns %d refcnt %d weight %d\n",
-		      IP_VS_DBG_ADDR(svc->af, &dest->addr), ntohs(dest->port),
+		      IP_VS_DBG_ADDR(dest->af, &dest->addr), ntohs(dest->port),
 		      atomic_read(&dest->activeconns),
 		      atomic_read(&dest->refcnt),
 		      atomic_read(&dest->weight));
diff -urN linux/net/netfilter/ipvs/ip_vs_xmit.c net-next-2.6/net/netfilter/ipvs/ip_vs_xmit.c
--- linux/net/netfilter/ipvs/ip_vs_xmit.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/ipvs/ip_vs_xmit.c	2014-10-06 10:49:04.160940504 +0200
@@ -157,18 +157,113 @@
 	return rt;
 }
 
+#ifdef CONFIG_IP_VS_IPV6
+static inline int __ip_vs_is_local_route6(struct rt6_info *rt)
+{
+	return rt->dst.dev && rt->dst.dev->flags & IFF_LOOPBACK;
+}
+#endif
+
+static inline bool crosses_local_route_boundary(int skb_af, struct sk_buff *skb,
+						int rt_mode,
+						bool new_rt_is_local)
+{
+	bool rt_mode_allow_local = !!(rt_mode & IP_VS_RT_MODE_LOCAL);
+	bool rt_mode_allow_non_local = !!(rt_mode & IP_VS_RT_MODE_LOCAL);
+	bool rt_mode_allow_redirect = !!(rt_mode & IP_VS_RT_MODE_RDR);
+	bool source_is_loopback;
+	bool old_rt_is_local;
+
+#ifdef CONFIG_IP_VS_IPV6
+	if (skb_af == AF_INET6) {
+		int addr_type = ipv6_addr_type(&ipv6_hdr(skb)->saddr);
+
+		source_is_loopback =
+			(!skb->dev || skb->dev->flags & IFF_LOOPBACK) &&
+			(addr_type & IPV6_ADDR_LOOPBACK);
+		old_rt_is_local = __ip_vs_is_local_route6(
+			(struct rt6_info *)skb_dst(skb));
+	} else
+#endif
+	{
+		source_is_loopback = ipv4_is_loopback(ip_hdr(skb)->saddr);
+		old_rt_is_local = skb_rtable(skb)->rt_flags & RTCF_LOCAL;
+	}
+
+	if (unlikely(new_rt_is_local)) {
+		if (!rt_mode_allow_local)
+			return true;
+		if (!rt_mode_allow_redirect && !old_rt_is_local)
+			return true;
+	} else {
+		if (!rt_mode_allow_non_local)
+			return true;
+		if (source_is_loopback)
+			return true;
+	}
+	return false;
+}
+
+static inline void maybe_update_pmtu(int skb_af, struct sk_buff *skb, int mtu)
+{
+	struct sock *sk = skb->sk;
+	struct rtable *ort = skb_rtable(skb);
+
+	if (!skb->dev && sk && sk->sk_state != TCP_TIME_WAIT)
+		ort->dst.ops->update_pmtu(&ort->dst, sk, NULL, mtu);
+}
+
+static inline bool ensure_mtu_is_adequate(int skb_af, int rt_mode,
+					  struct ip_vs_iphdr *ipvsh,
+					  struct sk_buff *skb, int mtu)
+{
+#ifdef CONFIG_IP_VS_IPV6
+	if (skb_af == AF_INET6) {
+		struct net *net = dev_net(skb_dst(skb)->dev);
+
+		if (unlikely(__mtu_check_toobig_v6(skb, mtu))) {
+			if (!skb->dev)
+				skb->dev = net->loopback_dev;
+			/* only send ICMP too big on first fragment */
+			if (!ipvsh->fragoffs)
+				icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
+			IP_VS_DBG(1, "frag needed for %pI6c\n",
+				  &ipv6_hdr(skb)->saddr);
+			return false;
+		}
+	} else
+#endif
+	{
+		struct netns_ipvs *ipvs = net_ipvs(skb_net(skb));
+
+		/* If we're going to tunnel the packet and pmtu discovery
+		 * is disabled, we'll just fragment it anyway
+		 */
+		if ((rt_mode & IP_VS_RT_MODE_TUNNEL) && !sysctl_pmtu_disc(ipvs))
+			return true;
+
+		if (unlikely(ip_hdr(skb)->frag_off & htons(IP_DF) &&
+			     skb->len > mtu && !skb_is_gso(skb))) {
+			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
+				  htonl(mtu));
+			IP_VS_DBG(1, "frag needed for %pI4\n",
+				  &ip_hdr(skb)->saddr);
+			return false;
+		}
+	}
+
+	return true;
+}
+
 /* Get route to destination or remote server */
 static int
-__ip_vs_get_out_rt(struct sk_buff *skb, struct ip_vs_dest *dest,
-		   __be32 daddr, int rt_mode, __be32 *ret_saddr)
+__ip_vs_get_out_rt(int skb_af, struct sk_buff *skb, struct ip_vs_dest *dest,
+		   __be32 daddr, int rt_mode, __be32 *ret_saddr,
+		   struct ip_vs_iphdr *ipvsh)
 {
 	struct net *net = dev_net(skb_dst(skb)->dev);
-	struct netns_ipvs *ipvs = net_ipvs(net);
 	struct ip_vs_dest_dst *dest_dst;
 	struct rtable *rt;			/* Route to the other host */
-	struct rtable *ort;			/* Original route */
-	struct iphdr *iph;
-	__be16 df;
 	int mtu;
 	int local, noref = 1;
 
@@ -218,30 +313,14 @@
 	}
 
 	local = (rt->rt_flags & RTCF_LOCAL) ? 1 : 0;
-	if (!((local ? IP_VS_RT_MODE_LOCAL : IP_VS_RT_MODE_NON_LOCAL) &
-	      rt_mode)) {
-		IP_VS_DBG_RL("Stopping traffic to %s address, dest: %pI4\n",
-			     (rt->rt_flags & RTCF_LOCAL) ?
-			     "local":"non-local", &daddr);
+	if (unlikely(crosses_local_route_boundary(skb_af, skb, rt_mode,
+						  local))) {
+		IP_VS_DBG_RL("We are crossing local and non-local addresses"
+			     " daddr=%pI4\n", &dest->addr.ip);
 		goto err_put;
 	}
-	iph = ip_hdr(skb);
-	if (likely(!local)) {
-		if (unlikely(ipv4_is_loopback(iph->saddr))) {
-			IP_VS_DBG_RL("Stopping traffic from loopback address "
-				     "%pI4 to non-local address, dest: %pI4\n",
-				     &iph->saddr, &daddr);
-			goto err_put;
-		}
-	} else {
-		ort = skb_rtable(skb);
-		if (!(rt_mode & IP_VS_RT_MODE_RDR) &&
-		    !(ort->rt_flags & RTCF_LOCAL)) {
-			IP_VS_DBG_RL("Redirect from non-local address %pI4 to "
-				     "local requires NAT method, dest: %pI4\n",
-				     &iph->daddr, &daddr);
-			goto err_put;
-		}
+
+	if (unlikely(local)) {
 		/* skb to local stack, preserve old route */
 		if (!noref)
 			ip_rt_put(rt);
@@ -250,28 +329,17 @@
 
 	if (likely(!(rt_mode & IP_VS_RT_MODE_TUNNEL))) {
 		mtu = dst_mtu(&rt->dst);
-		df = iph->frag_off & htons(IP_DF);
 	} else {
-		struct sock *sk = skb->sk;
-
 		mtu = dst_mtu(&rt->dst) - sizeof(struct iphdr);
 		if (mtu < 68) {
 			IP_VS_DBG_RL("%s(): mtu less than 68\n", __func__);
 			goto err_put;
 		}
-		ort = skb_rtable(skb);
-		if (!skb->dev && sk && sk->sk_state != TCP_TIME_WAIT)
-			ort->dst.ops->update_pmtu(&ort->dst, sk, NULL, mtu);
-		/* MTU check allowed? */
-		df = sysctl_pmtu_disc(ipvs) ? iph->frag_off & htons(IP_DF) : 0;
+		maybe_update_pmtu(skb_af, skb, mtu);
 	}
 
-	/* MTU checking */
-	if (unlikely(df && skb->len > mtu && !skb_is_gso(skb))) {
-		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
-		IP_VS_DBG(1, "frag needed for %pI4\n", &iph->saddr);
+	if (!ensure_mtu_is_adequate(skb_af, rt_mode, ipvsh, skb, mtu))
 		goto err_put;
-	}
 
 	skb_dst_drop(skb);
 	if (noref) {
@@ -295,12 +363,6 @@
 }
 
 #ifdef CONFIG_IP_VS_IPV6
-
-static inline int __ip_vs_is_local_route6(struct rt6_info *rt)
-{
-	return rt->dst.dev && rt->dst.dev->flags & IFF_LOOPBACK;
-}
-
 static struct dst_entry *
 __ip_vs_route_output_v6(struct net *net, struct in6_addr *daddr,
 			struct in6_addr *ret_saddr, int do_xfrm)
@@ -339,14 +401,13 @@
  * Get route to destination or remote server
  */
 static int
-__ip_vs_get_out_rt_v6(struct sk_buff *skb, struct ip_vs_dest *dest,
+__ip_vs_get_out_rt_v6(int skb_af, struct sk_buff *skb, struct ip_vs_dest *dest,
 		      struct in6_addr *daddr, struct in6_addr *ret_saddr,
 		      struct ip_vs_iphdr *ipvsh, int do_xfrm, int rt_mode)
 {
 	struct net *net = dev_net(skb_dst(skb)->dev);
 	struct ip_vs_dest_dst *dest_dst;
 	struct rt6_info *rt;			/* Route to the other host */
-	struct rt6_info *ort;			/* Original route */
 	struct dst_entry *dst;
 	int mtu;
 	int local, noref = 1;
@@ -393,32 +454,15 @@
 	}
 
 	local = __ip_vs_is_local_route6(rt);
-	if (!((local ? IP_VS_RT_MODE_LOCAL : IP_VS_RT_MODE_NON_LOCAL) &
-	      rt_mode)) {
-		IP_VS_DBG_RL("Stopping traffic to %s address, dest: %pI6c\n",
-			     local ? "local":"non-local", daddr);
+
+	if (unlikely(crosses_local_route_boundary(skb_af, skb, rt_mode,
+						  local))) {
+		IP_VS_DBG_RL("We are crossing local and non-local addresses"
+			     " daddr=%pI6\n", &dest->addr.in6);
 		goto err_put;
 	}
-	if (likely(!local)) {
-		if (unlikely((!skb->dev || skb->dev->flags & IFF_LOOPBACK) &&
-			     ipv6_addr_type(&ipv6_hdr(skb)->saddr) &
-					    IPV6_ADDR_LOOPBACK)) {
-			IP_VS_DBG_RL("Stopping traffic from loopback address "
-				     "%pI6c to non-local address, "
-				     "dest: %pI6c\n",
-				     &ipv6_hdr(skb)->saddr, daddr);
-			goto err_put;
-		}
-	} else {
-		ort = (struct rt6_info *) skb_dst(skb);
-		if (!(rt_mode & IP_VS_RT_MODE_RDR) &&
-		    !__ip_vs_is_local_route6(ort)) {
-			IP_VS_DBG_RL("Redirect from non-local address %pI6c "
-				     "to local requires NAT method, "
-				     "dest: %pI6c\n",
-				     &ipv6_hdr(skb)->daddr, daddr);
-			goto err_put;
-		}
+
+	if (unlikely(local)) {
 		/* skb to local stack, preserve old route */
 		if (!noref)
 			dst_release(&rt->dst);
@@ -429,28 +473,17 @@
 	if (likely(!(rt_mode & IP_VS_RT_MODE_TUNNEL)))
 		mtu = dst_mtu(&rt->dst);
 	else {
-		struct sock *sk = skb->sk;
-
 		mtu = dst_mtu(&rt->dst) - sizeof(struct ipv6hdr);
 		if (mtu < IPV6_MIN_MTU) {
 			IP_VS_DBG_RL("%s(): mtu less than %d\n", __func__,
 				     IPV6_MIN_MTU);
 			goto err_put;
 		}
-		ort = (struct rt6_info *) skb_dst(skb);
-		if (!skb->dev && sk && sk->sk_state != TCP_TIME_WAIT)
-			ort->dst.ops->update_pmtu(&ort->dst, sk, NULL, mtu);
+		maybe_update_pmtu(skb_af, skb, mtu);
 	}
 
-	if (unlikely(__mtu_check_toobig_v6(skb, mtu))) {
-		if (!skb->dev)
-			skb->dev = net->loopback_dev;
-		/* only send ICMP too big on first fragment */
-		if (!ipvsh->fragoffs)
-			icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
-		IP_VS_DBG(1, "frag needed for %pI6c\n", &ipv6_hdr(skb)->saddr);
+	if (!ensure_mtu_is_adequate(skb_af, rt_mode, ipvsh, skb, mtu))
 		goto err_put;
-	}
 
 	skb_dst_drop(skb);
 	if (noref) {
@@ -556,8 +589,8 @@
 	EnterFunction(10);
 
 	rcu_read_lock();
-	if (__ip_vs_get_out_rt(skb, NULL, iph->daddr, IP_VS_RT_MODE_NON_LOCAL,
-			       NULL) < 0)
+	if (__ip_vs_get_out_rt(cp->af, skb, NULL, iph->daddr,
+			       IP_VS_RT_MODE_NON_LOCAL, NULL, ipvsh) < 0)
 		goto tx_error;
 
 	ip_send_check(iph);
@@ -586,7 +619,7 @@
 	EnterFunction(10);
 
 	rcu_read_lock();
-	if (__ip_vs_get_out_rt_v6(skb, NULL, &ipvsh->daddr.in6, NULL,
+	if (__ip_vs_get_out_rt_v6(cp->af, skb, NULL, &ipvsh->daddr.in6, NULL,
 				  ipvsh, 0, IP_VS_RT_MODE_NON_LOCAL) < 0)
 		goto tx_error;
 
@@ -633,10 +666,10 @@
 	}
 
 	was_input = rt_is_input_route(skb_rtable(skb));
-	local = __ip_vs_get_out_rt(skb, cp->dest, cp->daddr.ip,
+	local = __ip_vs_get_out_rt(cp->af, skb, cp->dest, cp->daddr.ip,
 				   IP_VS_RT_MODE_LOCAL |
 				   IP_VS_RT_MODE_NON_LOCAL |
-				   IP_VS_RT_MODE_RDR, NULL);
+				   IP_VS_RT_MODE_RDR, NULL, ipvsh);
 	if (local < 0)
 		goto tx_error;
 	rt = skb_rtable(skb);
@@ -721,8 +754,8 @@
 		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
 	}
 
-	local = __ip_vs_get_out_rt_v6(skb, cp->dest, &cp->daddr.in6, NULL,
-				      ipvsh, 0,
+	local = __ip_vs_get_out_rt_v6(cp->af, skb, cp->dest, &cp->daddr.in6,
+				      NULL, ipvsh, 0,
 				      IP_VS_RT_MODE_LOCAL |
 				      IP_VS_RT_MODE_NON_LOCAL |
 				      IP_VS_RT_MODE_RDR);
@@ -791,6 +824,81 @@
 }
 #endif
 
+/* When forwarding a packet, we must ensure that we've got enough headroom
+ * for the encapsulation packet in the skb.  This also gives us an
+ * opportunity to figure out what the payload_len, dsfield, ttl, and df
+ * values should be, so that we won't need to look at the old ip header
+ * again
+ */
+static struct sk_buff *
+ip_vs_prepare_tunneled_skb(struct sk_buff *skb, int skb_af,
+			   unsigned int max_headroom, __u8 *next_protocol,
+			   __u32 *payload_len, __u8 *dsfield, __u8 *ttl,
+			   __be16 *df)
+{
+	struct sk_buff *new_skb = NULL;
+	struct iphdr *old_iph = NULL;
+#ifdef CONFIG_IP_VS_IPV6
+	struct ipv6hdr *old_ipv6h = NULL;
+#endif
+
+	if (skb_headroom(skb) < max_headroom || skb_cloned(skb)) {
+		new_skb = skb_realloc_headroom(skb, max_headroom);
+		if (!new_skb)
+			goto error;
+		consume_skb(skb);
+		skb = new_skb;
+	}
+
+#ifdef CONFIG_IP_VS_IPV6
+	if (skb_af == AF_INET6) {
+		old_ipv6h = ipv6_hdr(skb);
+		*next_protocol = IPPROTO_IPV6;
+		if (payload_len)
+			*payload_len =
+				ntohs(old_ipv6h->payload_len) +
+				sizeof(*old_ipv6h);
+		*dsfield = ipv6_get_dsfield(old_ipv6h);
+		*ttl = old_ipv6h->hop_limit;
+		if (df)
+			*df = 0;
+	} else
+#endif
+	{
+		old_iph = ip_hdr(skb);
+		/* Copy DF, reset fragment offset and MF */
+		if (df)
+			*df = (old_iph->frag_off & htons(IP_DF));
+		*next_protocol = IPPROTO_IPIP;
+
+		/* fix old IP header checksum */
+		ip_send_check(old_iph);
+		*dsfield = ipv4_get_dsfield(old_iph);
+		*ttl = old_iph->ttl;
+		if (payload_len)
+			*payload_len = ntohs(old_iph->tot_len);
+	}
+
+	return skb;
+error:
+	kfree_skb(skb);
+	return ERR_PTR(-ENOMEM);
+}
+
+static inline int __tun_gso_type_mask(int encaps_af, int orig_af)
+{
+	if (encaps_af == AF_INET) {
+		if (orig_af == AF_INET)
+			return SKB_GSO_IPIP;
+
+		return SKB_GSO_SIT;
+	}
+
+	/* GSO: we need to provide proper SKB_GSO_ value for IPv6:
+	 * SKB_GSO_SIT/IPV6
+	 */
+	return 0;
+}
 
 /*
  *   IP Tunneling transmitter
@@ -819,9 +927,11 @@
 	struct rtable *rt;			/* Route to the other host */
 	__be32 saddr;				/* Source for tunnel */
 	struct net_device *tdev;		/* Device to other host */
-	struct iphdr  *old_iph = ip_hdr(skb);
-	u8     tos = old_iph->tos;
-	__be16 df;
+	__u8 next_protocol = 0;
+	__u8 dsfield = 0;
+	__u8 ttl = 0;
+	__be16 df = 0;
+	__be16 *dfp = NULL;
 	struct iphdr  *iph;			/* Our new IP header */
 	unsigned int max_headroom;		/* The extra header space needed */
 	int ret, local;
@@ -829,11 +939,11 @@
 	EnterFunction(10);
 
 	rcu_read_lock();
-	local = __ip_vs_get_out_rt(skb, cp->dest, cp->daddr.ip,
+	local = __ip_vs_get_out_rt(cp->af, skb, cp->dest, cp->daddr.ip,
 				   IP_VS_RT_MODE_LOCAL |
 				   IP_VS_RT_MODE_NON_LOCAL |
 				   IP_VS_RT_MODE_CONNECT |
-				   IP_VS_RT_MODE_TUNNEL, &saddr);
+				   IP_VS_RT_MODE_TUNNEL, &saddr, ipvsh);
 	if (local < 0)
 		goto tx_error;
 	if (local) {
@@ -844,29 +954,21 @@
 	rt = skb_rtable(skb);
 	tdev = rt->dst.dev;
 
-	/* Copy DF, reset fragment offset and MF */
-	df = sysctl_pmtu_disc(ipvs) ? old_iph->frag_off & htons(IP_DF) : 0;
-
 	/*
 	 * Okay, now see if we can stuff it in the buffer as-is.
 	 */
 	max_headroom = LL_RESERVED_SPACE(tdev) + sizeof(struct iphdr);
 
-	if (skb_headroom(skb) < max_headroom || skb_cloned(skb)) {
-		struct sk_buff *new_skb =
-			skb_realloc_headroom(skb, max_headroom);
-
-		if (!new_skb)
-			goto tx_error;
-		consume_skb(skb);
-		skb = new_skb;
-		old_iph = ip_hdr(skb);
-	}
-
-	/* fix old IP header checksum */
-	ip_send_check(old_iph);
+	/* We only care about the df field if sysctl_pmtu_disc(ipvs) is set */
+	dfp = sysctl_pmtu_disc(ipvs) ? &df : NULL;
+	skb = ip_vs_prepare_tunneled_skb(skb, cp->af, max_headroom,
+					 &next_protocol, NULL, &dsfield,
+					 &ttl, dfp);
+	if (IS_ERR(skb))
+		goto tx_error;
 
-	skb = iptunnel_handle_offloads(skb, false, SKB_GSO_IPIP);
+	skb = iptunnel_handle_offloads(
+		skb, false, __tun_gso_type_mask(AF_INET, cp->af));
 	if (IS_ERR(skb))
 		goto tx_error;
 
@@ -883,11 +985,11 @@
 	iph->version		=	4;
 	iph->ihl		=	sizeof(struct iphdr)>>2;
 	iph->frag_off		=	df;
-	iph->protocol		=	IPPROTO_IPIP;
-	iph->tos		=	tos;
+	iph->protocol		=	next_protocol;
+	iph->tos		=	dsfield;
 	iph->daddr		=	cp->daddr.ip;
 	iph->saddr		=	saddr;
-	iph->ttl		=	old_iph->ttl;
+	iph->ttl		=	ttl;
 	ip_select_ident(skb, NULL);
 
 	/* Another hack: avoid icmp_send in ip_fragment */
@@ -920,7 +1022,10 @@
 	struct rt6_info *rt;		/* Route to the other host */
 	struct in6_addr saddr;		/* Source for tunnel */
 	struct net_device *tdev;	/* Device to other host */
-	struct ipv6hdr  *old_iph = ipv6_hdr(skb);
+	__u8 next_protocol = 0;
+	__u32 payload_len = 0;
+	__u8 dsfield = 0;
+	__u8 ttl = 0;
 	struct ipv6hdr  *iph;		/* Our new IP header */
 	unsigned int max_headroom;	/* The extra header space needed */
 	int ret, local;
@@ -928,7 +1033,7 @@
 	EnterFunction(10);
 
 	rcu_read_lock();
-	local = __ip_vs_get_out_rt_v6(skb, cp->dest, &cp->daddr.in6,
+	local = __ip_vs_get_out_rt_v6(cp->af, skb, cp->dest, &cp->daddr.in6,
 				      &saddr, ipvsh, 1,
 				      IP_VS_RT_MODE_LOCAL |
 				      IP_VS_RT_MODE_NON_LOCAL |
@@ -948,19 +1053,14 @@
 	 */
 	max_headroom = LL_RESERVED_SPACE(tdev) + sizeof(struct ipv6hdr);
 
-	if (skb_headroom(skb) < max_headroom || skb_cloned(skb)) {
-		struct sk_buff *new_skb =
-			skb_realloc_headroom(skb, max_headroom);
-
-		if (!new_skb)
-			goto tx_error;
-		consume_skb(skb);
-		skb = new_skb;
-		old_iph = ipv6_hdr(skb);
-	}
+	skb = ip_vs_prepare_tunneled_skb(skb, cp->af, max_headroom,
+					 &next_protocol, &payload_len,
+					 &dsfield, &ttl, NULL);
+	if (IS_ERR(skb))
+		goto tx_error;
 
-	/* GSO: we need to provide proper SKB_GSO_ value for IPv6 */
-	skb = iptunnel_handle_offloads(skb, false, 0); /* SKB_GSO_SIT/IPV6 */
+	skb = iptunnel_handle_offloads(
+		skb, false, __tun_gso_type_mask(AF_INET6, cp->af));
 	if (IS_ERR(skb))
 		goto tx_error;
 
@@ -975,14 +1075,13 @@
 	 */
 	iph			=	ipv6_hdr(skb);
 	iph->version		=	6;
-	iph->nexthdr		=	IPPROTO_IPV6;
-	iph->payload_len	=	old_iph->payload_len;
-	be16_add_cpu(&iph->payload_len, sizeof(*old_iph));
+	iph->nexthdr		=	next_protocol;
+	iph->payload_len	=	htons(payload_len);
 	memset(&iph->flow_lbl, 0, sizeof(iph->flow_lbl));
-	ipv6_change_dsfield(iph, 0, ipv6_get_dsfield(old_iph));
+	ipv6_change_dsfield(iph, 0, dsfield);
 	iph->daddr = cp->daddr.in6;
 	iph->saddr = saddr;
-	iph->hop_limit		=	old_iph->hop_limit;
+	iph->hop_limit		=	ttl;
 
 	/* Another hack: avoid icmp_send in ip_fragment */
 	skb->ignore_df = 1;
@@ -1021,10 +1120,10 @@
 	EnterFunction(10);
 
 	rcu_read_lock();
-	local = __ip_vs_get_out_rt(skb, cp->dest, cp->daddr.ip,
+	local = __ip_vs_get_out_rt(cp->af, skb, cp->dest, cp->daddr.ip,
 				   IP_VS_RT_MODE_LOCAL |
 				   IP_VS_RT_MODE_NON_LOCAL |
-				   IP_VS_RT_MODE_KNOWN_NH, NULL);
+				   IP_VS_RT_MODE_KNOWN_NH, NULL, ipvsh);
 	if (local < 0)
 		goto tx_error;
 	if (local) {
@@ -1060,8 +1159,8 @@
 	EnterFunction(10);
 
 	rcu_read_lock();
-	local = __ip_vs_get_out_rt_v6(skb, cp->dest, &cp->daddr.in6, NULL,
-				      ipvsh, 0,
+	local = __ip_vs_get_out_rt_v6(cp->af, skb, cp->dest, &cp->daddr.in6,
+				      NULL, ipvsh, 0,
 				      IP_VS_RT_MODE_LOCAL |
 				      IP_VS_RT_MODE_NON_LOCAL);
 	if (local < 0)
@@ -1128,7 +1227,8 @@
 		  IP_VS_RT_MODE_LOCAL | IP_VS_RT_MODE_NON_LOCAL |
 		  IP_VS_RT_MODE_RDR : IP_VS_RT_MODE_NON_LOCAL;
 	rcu_read_lock();
-	local = __ip_vs_get_out_rt(skb, cp->dest, cp->daddr.ip, rt_mode, NULL);
+	local = __ip_vs_get_out_rt(cp->af, skb, cp->dest, cp->daddr.ip, rt_mode,
+				   NULL, iph);
 	if (local < 0)
 		goto tx_error;
 	rt = skb_rtable(skb);
@@ -1219,8 +1319,8 @@
 		  IP_VS_RT_MODE_LOCAL | IP_VS_RT_MODE_NON_LOCAL |
 		  IP_VS_RT_MODE_RDR : IP_VS_RT_MODE_NON_LOCAL;
 	rcu_read_lock();
-	local = __ip_vs_get_out_rt_v6(skb, cp->dest, &cp->daddr.in6, NULL,
-				      ipvsh, 0, rt_mode);
+	local = __ip_vs_get_out_rt_v6(cp->af, skb, cp->dest, &cp->daddr.in6,
+				      NULL, ipvsh, 0, rt_mode);
 	if (local < 0)
 		goto tx_error;
 	rt = (struct rt6_info *) skb_dst(skb);
diff -urN linux/net/netfilter/ipvs/Kconfig net-next-2.6/net/netfilter/ipvs/Kconfig
--- linux/net/netfilter/ipvs/Kconfig	2013-05-02 09:43:21.645515164 +0200
+++ net-next-2.6/net/netfilter/ipvs/Kconfig	2014-10-06 10:49:03.428933043 +0200
@@ -152,6 +152,16 @@
 	  If you want to compile it in kernel, say Y. To compile it as a
 	  module, choose M here. If unsure, say N.
 
+config  IP_VS_FO
+		tristate "weighted failover scheduling"
+	---help---
+	  The weighted failover scheduling algorithm directs network
+	  connections to the server with the highest weight that is
+	  currently available.
+
+	  If you want to compile it in kernel, say Y. To compile it as a
+	  module, choose M here. If unsure, say N.
+
 config	IP_VS_LBLC
 	tristate "locality-based least-connection scheduling"
 	---help---
diff -urN linux/net/netfilter/ipvs/Makefile net-next-2.6/net/netfilter/ipvs/Makefile
--- linux/net/netfilter/ipvs/Makefile	2011-07-22 09:59:45.554009968 +0200
+++ net-next-2.6/net/netfilter/ipvs/Makefile	2014-10-06 10:49:03.428933043 +0200
@@ -26,6 +26,7 @@
 obj-$(CONFIG_IP_VS_WRR) += ip_vs_wrr.o
 obj-$(CONFIG_IP_VS_LC) += ip_vs_lc.o
 obj-$(CONFIG_IP_VS_WLC) += ip_vs_wlc.o
+obj-$(CONFIG_IP_VS_FO) += ip_vs_fo.o
 obj-$(CONFIG_IP_VS_LBLC) += ip_vs_lblc.o
 obj-$(CONFIG_IP_VS_LBLCR) += ip_vs_lblcr.o
 obj-$(CONFIG_IP_VS_DH) += ip_vs_dh.o
diff -urN linux/net/netfilter/Kconfig net-next-2.6/net/netfilter/Kconfig
--- linux/net/netfilter/Kconfig	2014-10-06 10:59:24.275259167 +0200
+++ net-next-2.6/net/netfilter/Kconfig	2014-10-06 10:49:03.424933002 +0200
@@ -496,6 +496,15 @@
 	  This option adds the "limit" expression that you can use to
 	  ratelimit rule matchings.
 
+config NFT_MASQ
+	depends on NF_TABLES
+	depends on NF_CONNTRACK
+	depends on NF_NAT
+	tristate "Netfilter nf_tables masquerade support"
+	help
+	  This option adds the "masquerade" expression that you can use
+	  to perform NAT in the masquerade flavour.
+
 config NFT_NAT
 	depends on NF_TABLES
 	depends on NF_CONNTRACK
diff -urN linux/net/netfilter/Makefile net-next-2.6/net/netfilter/Makefile
--- linux/net/netfilter/Makefile	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/netfilter/Makefile	2014-10-06 10:49:03.424933002 +0200
@@ -87,6 +87,7 @@
 obj-$(CONFIG_NFT_HASH)		+= nft_hash.o
 obj-$(CONFIG_NFT_COUNTER)	+= nft_counter.o
 obj-$(CONFIG_NFT_LOG)		+= nft_log.o
+obj-$(CONFIG_NFT_MASQ)		+= nft_masq.o
 
 # generic X tables 
 obj-$(CONFIG_NETFILTER_XTABLES) += x_tables.o xt_tcpudp.o
diff -urN linux/net/netfilter/nf_conntrack_core.c net-next-2.6/net/netfilter/nf_conntrack_core.c
--- linux/net/netfilter/nf_conntrack_core.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/nf_conntrack_core.c	2014-10-06 10:49:04.160940504 +0200
@@ -142,7 +142,7 @@
 
 static u32 __hash_bucket(u32 hash, unsigned int size)
 {
-	return ((u64)hash * size) >> 32;
+	return reciprocal_scale(hash, size);
 }
 
 static u32 hash_bucket(u32 hash, const struct net *net)
@@ -358,7 +358,7 @@
 
 	tstamp = nf_conn_tstamp_find(ct);
 	if (tstamp && tstamp->stop == 0)
-		tstamp->stop = ktime_to_ns(ktime_get_real());
+		tstamp->stop = ktime_get_real_ns();
 
 	if (nf_ct_is_dying(ct))
 		goto delete;
diff -urN linux/net/netfilter/nf_conntrack_expect.c net-next-2.6/net/netfilter/nf_conntrack_expect.c
--- linux/net/netfilter/nf_conntrack_expect.c	2014-09-24 09:52:43.248645088 +0200
+++ net-next-2.6/net/netfilter/nf_conntrack_expect.c	2014-10-06 10:49:04.160940504 +0200
@@ -83,7 +83,8 @@
 	hash = jhash2(tuple->dst.u3.all, ARRAY_SIZE(tuple->dst.u3.all),
 		      (((tuple->dst.protonum ^ tuple->src.l3num) << 16) |
 		       (__force __u16)tuple->dst.u.all) ^ nf_conntrack_hash_rnd);
-	return ((u64)hash * nf_ct_expect_hsize) >> 32;
+
+	return reciprocal_scale(hash, nf_ct_expect_hsize);
 }
 
 struct nf_conntrack_expect *
diff -urN linux/net/netfilter/nf_conntrack_netlink.c net-next-2.6/net/netfilter/nf_conntrack_netlink.c
--- linux/net/netfilter/nf_conntrack_netlink.c	2014-09-24 09:52:43.252645131 +0200
+++ net-next-2.6/net/netfilter/nf_conntrack_netlink.c	2014-10-06 10:49:04.160940504 +0200
@@ -1737,7 +1737,7 @@
 	}
 	tstamp = nf_conn_tstamp_find(ct);
 	if (tstamp)
-		tstamp->start = ktime_to_ns(ktime_get_real());
+		tstamp->start = ktime_get_real_ns();
 
 	err = nf_conntrack_hash_check_insert(ct);
 	if (err < 0)
diff -urN linux/net/netfilter/nf_conntrack_proto_generic.c net-next-2.6/net/netfilter/nf_conntrack_proto_generic.c
--- linux/net/netfilter/nf_conntrack_proto_generic.c	2013-05-02 09:43:21.653515164 +0200
+++ net-next-2.6/net/netfilter/nf_conntrack_proto_generic.c	2014-10-06 10:49:04.164940544 +0200
@@ -14,6 +14,30 @@
 
 static unsigned int nf_ct_generic_timeout __read_mostly = 600*HZ;
 
+static bool nf_generic_should_process(u8 proto)
+{
+	switch (proto) {
+#ifdef CONFIG_NF_CT_PROTO_SCTP_MODULE
+	case IPPROTO_SCTP:
+		return false;
+#endif
+#ifdef CONFIG_NF_CT_PROTO_DCCP_MODULE
+	case IPPROTO_DCCP:
+		return false;
+#endif
+#ifdef CONFIG_NF_CT_PROTO_GRE_MODULE
+	case IPPROTO_GRE:
+		return false;
+#endif
+#ifdef CONFIG_NF_CT_PROTO_UDPLITE_MODULE
+	case IPPROTO_UDPLITE:
+		return false;
+#endif
+	default:
+		return true;
+	}
+}
+
 static inline struct nf_generic_net *generic_pernet(struct net *net)
 {
 	return &net->ct.nf_ct_proto.generic;
@@ -67,7 +91,7 @@
 static bool generic_new(struct nf_conn *ct, const struct sk_buff *skb,
 			unsigned int dataoff, unsigned int *timeouts)
 {
-	return true;
+	return nf_generic_should_process(nf_ct_protonum(ct));
 }
 
 #if IS_ENABLED(CONFIG_NF_CT_NETLINK_TIMEOUT)
diff -urN linux/net/netfilter/nf_conntrack_standalone.c net-next-2.6/net/netfilter/nf_conntrack_standalone.c
--- linux/net/netfilter/nf_conntrack_standalone.c	2013-11-29 12:59:37.979382538 +0100
+++ net-next-2.6/net/netfilter/nf_conntrack_standalone.c	2014-10-06 10:49:04.164940544 +0200
@@ -101,7 +101,7 @@
 {
 	struct ct_iter_state *st = seq->private;
 
-	st->time_now = ktime_to_ns(ktime_get_real());
+	st->time_now = ktime_get_real_ns();
 	rcu_read_lock();
 	return ct_get_idx(seq, *pos);
 }
diff -urN linux/net/netfilter/nf_log_common.c net-next-2.6/net/netfilter/nf_log_common.c
--- linux/net/netfilter/nf_log_common.c	2014-09-24 09:52:43.252645131 +0200
+++ net-next-2.6/net/netfilter/nf_log_common.c	2014-10-06 10:49:04.168940584 +0200
@@ -158,7 +158,7 @@
 	       '0' + loginfo->u.log.level, prefix,
 	       in ? in->name : "",
 	       out ? out->name : "");
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	if (skb->nf_bridge) {
 		const struct net_device *physindev;
 		const struct net_device *physoutdev;
diff -urN linux/net/netfilter/nf_nat_core.c net-next-2.6/net/netfilter/nf_nat_core.c
--- linux/net/netfilter/nf_nat_core.c	2014-09-24 09:52:43.252645131 +0200
+++ net-next-2.6/net/netfilter/nf_nat_core.c	2014-10-06 10:49:04.168940584 +0200
@@ -126,7 +126,8 @@
 	/* Original src, to ensure we map it consistently if poss. */
 	hash = jhash2((u32 *)&tuple->src, sizeof(tuple->src) / sizeof(u32),
 		      tuple->dst.protonum ^ zone ^ nf_conntrack_hash_rnd);
-	return ((u64)hash * net->ct.nat_htable_size) >> 32;
+
+	return reciprocal_scale(hash, net->ct.nat_htable_size);
 }
 
 /* Is this tuple already taken? (not by us) */
@@ -274,7 +275,7 @@
 		}
 
 		var_ipp->all[i] = (__force __u32)
-			htonl(minip + (((u64)j * dist) >> 32));
+			htonl(minip + reciprocal_scale(j, dist));
 		if (var_ipp->all[i] != range->max_addr.all[i])
 			full_range = true;
 
diff -urN linux/net/netfilter/nfnetlink_acct.c net-next-2.6/net/netfilter/nfnetlink_acct.c
--- linux/net/netfilter/nfnetlink_acct.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nfnetlink_acct.c	2014-10-06 10:49:04.172940625 +0200
@@ -40,6 +40,11 @@
 	char			data[0];
 };
 
+struct nfacct_filter {
+	u32 value;
+	u32 mask;
+};
+
 #define NFACCT_F_QUOTA (NFACCT_F_QUOTA_PKTS | NFACCT_F_QUOTA_BYTES)
 #define NFACCT_OVERQUOTA_BIT	2	/* NFACCT_F_OVERQUOTA */
 
@@ -181,6 +186,7 @@
 nfnl_acct_dump(struct sk_buff *skb, struct netlink_callback *cb)
 {
 	struct nf_acct *cur, *last;
+	const struct nfacct_filter *filter = cb->data;
 
 	if (cb->args[2])
 		return 0;
@@ -197,6 +203,10 @@
 
 			last = NULL;
 		}
+
+		if (filter && (cur->flags & filter->mask) != filter->value)
+			continue;
+
 		if (nfnl_acct_fill_info(skb, NETLINK_CB(cb->skb).portid,
 				       cb->nlh->nlmsg_seq,
 				       NFNL_MSG_TYPE(cb->nlh->nlmsg_type),
@@ -211,6 +221,38 @@
 	return skb->len;
 }
 
+static int nfnl_acct_done(struct netlink_callback *cb)
+{
+	kfree(cb->data);
+	return 0;
+}
+
+static const struct nla_policy filter_policy[NFACCT_FILTER_MAX + 1] = {
+	[NFACCT_FILTER_MASK]	= { .type = NLA_U32 },
+	[NFACCT_FILTER_VALUE]	= { .type = NLA_U32 },
+};
+
+static struct nfacct_filter *
+nfacct_filter_alloc(const struct nlattr * const attr)
+{
+	struct nfacct_filter *filter;
+	struct nlattr *tb[NFACCT_FILTER_MAX + 1];
+	int err;
+
+	err = nla_parse_nested(tb, NFACCT_FILTER_MAX, attr, filter_policy);
+	if (err < 0)
+		return ERR_PTR(err);
+
+	filter = kzalloc(sizeof(struct nfacct_filter), GFP_KERNEL);
+	if (!filter)
+		return ERR_PTR(-ENOMEM);
+
+	filter->mask = ntohl(nla_get_be32(tb[NFACCT_FILTER_MASK]));
+	filter->value = ntohl(nla_get_be32(tb[NFACCT_FILTER_VALUE]));
+
+	return filter;
+}
+
 static int
 nfnl_acct_get(struct sock *nfnl, struct sk_buff *skb,
 	     const struct nlmsghdr *nlh, const struct nlattr * const tb[])
@@ -222,7 +264,18 @@
 	if (nlh->nlmsg_flags & NLM_F_DUMP) {
 		struct netlink_dump_control c = {
 			.dump = nfnl_acct_dump,
+			.done = nfnl_acct_done,
 		};
+
+		if (tb[NFACCT_FILTER]) {
+			struct nfacct_filter *filter;
+
+			filter = nfacct_filter_alloc(tb[NFACCT_FILTER]);
+			if (IS_ERR(filter))
+				return PTR_ERR(filter);
+
+			c.data = filter;
+		}
 		return netlink_dump_start(nfnl, skb, nlh, &c);
 	}
 
@@ -314,6 +367,7 @@
 	[NFACCT_PKTS] = { .type = NLA_U64 },
 	[NFACCT_FLAGS] = { .type = NLA_U32 },
 	[NFACCT_QUOTA] = { .type = NLA_U64 },
+	[NFACCT_FILTER] = {.type = NLA_NESTED },
 };
 
 static const struct nfnl_callback nfnl_acct_cb[NFNL_MSG_ACCT_MAX] = {
diff -urN linux/net/netfilter/nfnetlink.c net-next-2.6/net/netfilter/nfnetlink.c
--- linux/net/netfilter/nfnetlink.c	2014-10-06 10:59:24.275259167 +0200
+++ net-next-2.6/net/netfilter/nfnetlink.c	2014-10-06 10:49:04.172940625 +0200
@@ -381,7 +381,7 @@
 			 */
 			if (err == -EAGAIN) {
 				nfnl_err_reset(&err_list);
-				ss->abort(skb);
+				ss->abort(oskb);
 				nfnl_unlock(subsys_id);
 				kfree_skb(nskb);
 				goto replay;
@@ -418,9 +418,9 @@
 	}
 done:
 	if (success && done)
-		ss->commit(skb);
+		ss->commit(oskb);
 	else
-		ss->abort(skb);
+		ss->abort(oskb);
 
 	nfnl_err_deliver(&err_list, oskb);
 	nfnl_unlock(subsys_id);
diff -urN linux/net/netfilter/nfnetlink_log.c net-next-2.6/net/netfilter/nfnetlink_log.c
--- linux/net/netfilter/nfnetlink_log.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nfnetlink_log.c	2014-10-06 10:49:04.172940625 +0200
@@ -36,7 +36,7 @@
 
 #include <linux/atomic.h>
 
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 #include "../bridge/br_private.h"
 #endif
 
@@ -429,7 +429,7 @@
 		goto nla_put_failure;
 
 	if (indev) {
-#ifndef CONFIG_BRIDGE_NETFILTER
+#if !IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 		if (nla_put_be32(inst->skb, NFULA_IFINDEX_INDEV,
 				 htonl(indev->ifindex)))
 			goto nla_put_failure;
@@ -460,7 +460,7 @@
 	}
 
 	if (outdev) {
-#ifndef CONFIG_BRIDGE_NETFILTER
+#if !IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 		if (nla_put_be32(inst->skb, NFULA_IFINDEX_OUTDEV,
 				 htonl(outdev->ifindex)))
 			goto nla_put_failure;
@@ -640,7 +640,7 @@
 		+ nla_total_size(sizeof(struct nfulnl_msg_packet_hdr))
 		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
 		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
 		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
 #endif
diff -urN linux/net/netfilter/nfnetlink_queue_core.c net-next-2.6/net/netfilter/nfnetlink_queue_core.c
--- linux/net/netfilter/nfnetlink_queue_core.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nfnetlink_queue_core.c	2014-10-06 10:49:04.172940625 +0200
@@ -36,7 +36,7 @@
 
 #include <linux/atomic.h>
 
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 #include "../bridge/br_private.h"
 #endif
 
@@ -302,7 +302,7 @@
 		+ nla_total_size(sizeof(struct nfqnl_msg_packet_hdr))
 		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
 		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
 		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
 #endif
@@ -380,7 +380,7 @@
 
 	indev = entry->indev;
 	if (indev) {
-#ifndef CONFIG_BRIDGE_NETFILTER
+#if !IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 		if (nla_put_be32(skb, NFQA_IFINDEX_INDEV, htonl(indev->ifindex)))
 			goto nla_put_failure;
 #else
@@ -410,7 +410,7 @@
 	}
 
 	if (outdev) {
-#ifndef CONFIG_BRIDGE_NETFILTER
+#if !IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 		if (nla_put_be32(skb, NFQA_IFINDEX_OUTDEV, htonl(outdev->ifindex)))
 			goto nla_put_failure;
 #else
@@ -569,7 +569,7 @@
 	return NULL;
 }
 
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 /* When called from bridge netfilter, skb->data must point to MAC header
  * before calling skb_gso_segment(). Else, original MAC header is lost
  * and segmented skbs will be sent to wrong destination.
@@ -763,7 +763,7 @@
 	if (entry->outdev)
 		if (entry->outdev->ifindex == ifindex)
 			return 1;
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	if (entry->skb->nf_bridge) {
 		if (entry->skb->nf_bridge->physindev &&
 		    entry->skb->nf_bridge->physindev->ifindex == ifindex)
diff -urN linux/net/netfilter/nf_queue.c net-next-2.6/net/netfilter/nf_queue.c
--- linux/net/netfilter/nf_queue.c	2013-05-02 09:43:21.657515164 +0200
+++ net-next-2.6/net/netfilter/nf_queue.c	2014-10-06 10:49:04.168940584 +0200
@@ -52,7 +52,7 @@
 		dev_put(entry->indev);
 	if (entry->outdev)
 		dev_put(entry->outdev);
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	if (entry->skb->nf_bridge) {
 		struct nf_bridge_info *nf_bridge = entry->skb->nf_bridge;
 
@@ -77,7 +77,7 @@
 		dev_hold(entry->indev);
 	if (entry->outdev)
 		dev_hold(entry->outdev);
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	if (entry->skb->nf_bridge) {
 		struct nf_bridge_info *nf_bridge = entry->skb->nf_bridge;
 		struct net_device *physdev;
diff -urN linux/net/netfilter/nf_tables_api.c net-next-2.6/net/netfilter/nf_tables_api.c
--- linux/net/netfilter/nf_tables_api.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nf_tables_api.c	2014-10-06 10:49:04.172940625 +0200
@@ -127,6 +127,204 @@
 	kfree(trans);
 }
 
+static void nf_tables_unregister_hooks(const struct nft_table *table,
+				       const struct nft_chain *chain,
+				       unsigned int hook_nops)
+{
+	if (!(table->flags & NFT_TABLE_F_DORMANT) &&
+	    chain->flags & NFT_BASE_CHAIN)
+		nf_unregister_hooks(nft_base_chain(chain)->ops, hook_nops);
+}
+
+/* Internal table flags */
+#define NFT_TABLE_INACTIVE	(1 << 15)
+
+static int nft_trans_table_add(struct nft_ctx *ctx, int msg_type)
+{
+	struct nft_trans *trans;
+
+	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_table));
+	if (trans == NULL)
+		return -ENOMEM;
+
+	if (msg_type == NFT_MSG_NEWTABLE)
+		ctx->table->flags |= NFT_TABLE_INACTIVE;
+
+	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
+	return 0;
+}
+
+static int nft_deltable(struct nft_ctx *ctx)
+{
+	int err;
+
+	err = nft_trans_table_add(ctx, NFT_MSG_DELTABLE);
+	if (err < 0)
+		return err;
+
+	list_del_rcu(&ctx->table->list);
+	return err;
+}
+
+static int nft_trans_chain_add(struct nft_ctx *ctx, int msg_type)
+{
+	struct nft_trans *trans;
+
+	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_chain));
+	if (trans == NULL)
+		return -ENOMEM;
+
+	if (msg_type == NFT_MSG_NEWCHAIN)
+		ctx->chain->flags |= NFT_CHAIN_INACTIVE;
+
+	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
+	return 0;
+}
+
+static int nft_delchain(struct nft_ctx *ctx)
+{
+	int err;
+
+	err = nft_trans_chain_add(ctx, NFT_MSG_DELCHAIN);
+	if (err < 0)
+		return err;
+
+	ctx->table->use--;
+	list_del_rcu(&ctx->chain->list);
+
+	return err;
+}
+
+static inline bool
+nft_rule_is_active(struct net *net, const struct nft_rule *rule)
+{
+	return (rule->genmask & (1 << net->nft.gencursor)) == 0;
+}
+
+static inline int gencursor_next(struct net *net)
+{
+	return net->nft.gencursor+1 == 1 ? 1 : 0;
+}
+
+static inline int
+nft_rule_is_active_next(struct net *net, const struct nft_rule *rule)
+{
+	return (rule->genmask & (1 << gencursor_next(net))) == 0;
+}
+
+static inline void
+nft_rule_activate_next(struct net *net, struct nft_rule *rule)
+{
+	/* Now inactive, will be active in the future */
+	rule->genmask = (1 << net->nft.gencursor);
+}
+
+static inline void
+nft_rule_deactivate_next(struct net *net, struct nft_rule *rule)
+{
+	rule->genmask = (1 << gencursor_next(net));
+}
+
+static inline void nft_rule_clear(struct net *net, struct nft_rule *rule)
+{
+	rule->genmask = 0;
+}
+
+static int
+nf_tables_delrule_deactivate(struct nft_ctx *ctx, struct nft_rule *rule)
+{
+	/* You cannot delete the same rule twice */
+	if (nft_rule_is_active_next(ctx->net, rule)) {
+		nft_rule_deactivate_next(ctx->net, rule);
+		ctx->chain->use--;
+		return 0;
+	}
+	return -ENOENT;
+}
+
+static struct nft_trans *nft_trans_rule_add(struct nft_ctx *ctx, int msg_type,
+					    struct nft_rule *rule)
+{
+	struct nft_trans *trans;
+
+	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_rule));
+	if (trans == NULL)
+		return NULL;
+
+	nft_trans_rule(trans) = rule;
+	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
+
+	return trans;
+}
+
+static int nft_delrule(struct nft_ctx *ctx, struct nft_rule *rule)
+{
+	struct nft_trans *trans;
+	int err;
+
+	trans = nft_trans_rule_add(ctx, NFT_MSG_DELRULE, rule);
+	if (trans == NULL)
+		return -ENOMEM;
+
+	err = nf_tables_delrule_deactivate(ctx, rule);
+	if (err < 0) {
+		nft_trans_destroy(trans);
+		return err;
+	}
+
+	return 0;
+}
+
+static int nft_delrule_by_chain(struct nft_ctx *ctx)
+{
+	struct nft_rule *rule;
+	int err;
+
+	list_for_each_entry(rule, &ctx->chain->rules, list) {
+		err = nft_delrule(ctx, rule);
+		if (err < 0)
+			return err;
+	}
+	return 0;
+}
+
+/* Internal set flag */
+#define NFT_SET_INACTIVE	(1 << 15)
+
+static int nft_trans_set_add(struct nft_ctx *ctx, int msg_type,
+			     struct nft_set *set)
+{
+	struct nft_trans *trans;
+
+	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_set));
+	if (trans == NULL)
+		return -ENOMEM;
+
+	if (msg_type == NFT_MSG_NEWSET && ctx->nla[NFTA_SET_ID] != NULL) {
+		nft_trans_set_id(trans) =
+			ntohl(nla_get_be32(ctx->nla[NFTA_SET_ID]));
+		set->flags |= NFT_SET_INACTIVE;
+	}
+	nft_trans_set(trans) = set;
+	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
+
+	return 0;
+}
+
+static int nft_delset(struct nft_ctx *ctx, struct nft_set *set)
+{
+	int err;
+
+	err = nft_trans_set_add(ctx, NFT_MSG_DELSET, set);
+	if (err < 0)
+		return err;
+
+	list_del_rcu(&set->list);
+	ctx->table->use--;
+
+	return err;
+}
+
 /*
  * Tables
  */
@@ -207,9 +405,9 @@
 	[NFTA_TABLE_FLAGS]	= { .type = NLA_U32 },
 };
 
-static int nf_tables_fill_table_info(struct sk_buff *skb, u32 portid, u32 seq,
-				     int event, u32 flags, int family,
-				     const struct nft_table *table)
+static int nf_tables_fill_table_info(struct sk_buff *skb, struct net *net,
+				     u32 portid, u32 seq, int event, u32 flags,
+				     int family, const struct nft_table *table)
 {
 	struct nlmsghdr *nlh;
 	struct nfgenmsg *nfmsg;
@@ -222,7 +420,7 @@
 	nfmsg = nlmsg_data(nlh);
 	nfmsg->nfgen_family	= family;
 	nfmsg->version		= NFNETLINK_V0;
-	nfmsg->res_id		= 0;
+	nfmsg->res_id		= htons(net->nft.base_seq & 0xffff);
 
 	if (nla_put_string(skb, NFTA_TABLE_NAME, table->name) ||
 	    nla_put_be32(skb, NFTA_TABLE_FLAGS, htonl(table->flags)) ||
@@ -250,8 +448,8 @@
 	if (skb == NULL)
 		goto err;
 
-	err = nf_tables_fill_table_info(skb, ctx->portid, ctx->seq, event, 0,
-					ctx->afi->family, ctx->table);
+	err = nf_tables_fill_table_info(skb, ctx->net, ctx->portid, ctx->seq,
+					event, 0, ctx->afi->family, ctx->table);
 	if (err < 0) {
 		kfree_skb(skb);
 		goto err;
@@ -290,7 +488,7 @@
 			if (idx > s_idx)
 				memset(&cb->args[1], 0,
 				       sizeof(cb->args) - sizeof(cb->args[0]));
-			if (nf_tables_fill_table_info(skb,
+			if (nf_tables_fill_table_info(skb, net,
 						      NETLINK_CB(cb->skb).portid,
 						      cb->nlh->nlmsg_seq,
 						      NFT_MSG_NEWTABLE,
@@ -309,9 +507,6 @@
 	return skb->len;
 }
 
-/* Internal table flags */
-#define NFT_TABLE_INACTIVE	(1 << 15)
-
 static int nf_tables_gettable(struct sock *nlsk, struct sk_buff *skb,
 			      const struct nlmsghdr *nlh,
 			      const struct nlattr * const nla[])
@@ -345,7 +540,7 @@
 	if (!skb2)
 		return -ENOMEM;
 
-	err = nf_tables_fill_table_info(skb2, NETLINK_CB(skb).portid,
+	err = nf_tables_fill_table_info(skb2, net, NETLINK_CB(skb).portid,
 					nlh->nlmsg_seq, NFT_MSG_NEWTABLE, 0,
 					family, table);
 	if (err < 0)
@@ -443,21 +638,6 @@
 	return ret;
 }
 
-static int nft_trans_table_add(struct nft_ctx *ctx, int msg_type)
-{
-	struct nft_trans *trans;
-
-	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_table));
-	if (trans == NULL)
-		return -ENOMEM;
-
-	if (msg_type == NFT_MSG_NEWTABLE)
-		ctx->table->flags |= NFT_TABLE_INACTIVE;
-
-	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
-	return 0;
-}
-
 static int nf_tables_newtable(struct sock *nlsk, struct sk_buff *skb,
 			      const struct nlmsghdr *nlh,
 			      const struct nlattr * const nla[])
@@ -527,6 +707,67 @@
 	return 0;
 }
 
+static int nft_flush_table(struct nft_ctx *ctx)
+{
+	int err;
+	struct nft_chain *chain, *nc;
+	struct nft_set *set, *ns;
+
+	list_for_each_entry_safe(chain, nc, &ctx->table->chains, list) {
+		ctx->chain = chain;
+
+		err = nft_delrule_by_chain(ctx);
+		if (err < 0)
+			goto out;
+
+		err = nft_delchain(ctx);
+		if (err < 0)
+			goto out;
+	}
+
+	list_for_each_entry_safe(set, ns, &ctx->table->sets, list) {
+		if (set->flags & NFT_SET_ANONYMOUS &&
+		    !list_empty(&set->bindings))
+			continue;
+
+		err = nft_delset(ctx, set);
+		if (err < 0)
+			goto out;
+	}
+
+	err = nft_deltable(ctx);
+out:
+	return err;
+}
+
+static int nft_flush(struct nft_ctx *ctx, int family)
+{
+	struct nft_af_info *afi;
+	struct nft_table *table, *nt;
+	const struct nlattr * const *nla = ctx->nla;
+	int err = 0;
+
+	list_for_each_entry(afi, &ctx->net->nft.af_info, list) {
+		if (family != AF_UNSPEC && afi->family != family)
+			continue;
+
+		ctx->afi = afi;
+		list_for_each_entry_safe(table, nt, &afi->tables, list) {
+			if (nla[NFTA_TABLE_NAME] &&
+			    nla_strcmp(nla[NFTA_TABLE_NAME], table->name) != 0)
+				continue;
+
+			ctx->table = table;
+
+			err = nft_flush_table(ctx);
+			if (err < 0)
+				goto out;
+		}
+	}
+out:
+	return err;
+}
+
 static int nf_tables_deltable(struct sock *nlsk, struct sk_buff *skb,
 			      const struct nlmsghdr *nlh,
 			      const struct nlattr * const nla[])
@@ -535,9 +776,13 @@
 	struct nft_af_info *afi;
 	struct nft_table *table;
 	struct net *net = sock_net(skb->sk);
-	int family = nfmsg->nfgen_family, err;
+	int family = nfmsg->nfgen_family;
 	struct nft_ctx ctx;
 
+	nft_ctx_init(&ctx, skb, nlh, NULL, NULL, NULL, nla);
+	if (family == AF_UNSPEC || nla[NFTA_TABLE_NAME] == NULL)
+		return nft_flush(&ctx, family);
+
 	afi = nf_tables_afinfo_lookup(net, family, false);
 	if (IS_ERR(afi))
 		return PTR_ERR(afi);
@@ -547,16 +792,11 @@
 		return PTR_ERR(table);
 	if (table->flags & NFT_TABLE_INACTIVE)
 		return -ENOENT;
-	if (table->use > 0)
-		return -EBUSY;
 
-	nft_ctx_init(&ctx, skb, nlh, afi, table, NULL, nla);
-	err = nft_trans_table_add(&ctx, NFT_MSG_DELTABLE);
-	if (err < 0)
-		return err;
+	ctx.afi = afi;
+	ctx.table = table;
 
-	list_del_rcu(&table->list);
-	return 0;
+	return nft_flush_table(&ctx);
 }
 
 static void nf_tables_table_destroy(struct nft_ctx *ctx)
@@ -674,9 +914,9 @@
 	return -ENOSPC;
 }
 
-static int nf_tables_fill_chain_info(struct sk_buff *skb, u32 portid, u32 seq,
-				     int event, u32 flags, int family,
-				     const struct nft_table *table,
+static int nf_tables_fill_chain_info(struct sk_buff *skb, struct net *net,
+				     u32 portid, u32 seq, int event, u32 flags,
+				     int family, const struct nft_table *table,
 				     const struct nft_chain *chain)
 {
 	struct nlmsghdr *nlh;
@@ -690,7 +930,7 @@
 	nfmsg = nlmsg_data(nlh);
 	nfmsg->nfgen_family	= family;
 	nfmsg->version		= NFNETLINK_V0;
-	nfmsg->res_id		= 0;
+	nfmsg->res_id		= htons(net->nft.base_seq & 0xffff);
 
 	if (nla_put_string(skb, NFTA_CHAIN_TABLE, table->name))
 		goto nla_put_failure;
@@ -748,8 +988,8 @@
 	if (skb == NULL)
 		goto err;
 
-	err = nf_tables_fill_chain_info(skb, ctx->portid, ctx->seq, event, 0,
-					ctx->afi->family, ctx->table,
+	err = nf_tables_fill_chain_info(skb, ctx->net, ctx->portid, ctx->seq,
+					event, 0, ctx->afi->family, ctx->table,
 					ctx->chain);
 	if (err < 0) {
 		kfree_skb(skb);
@@ -791,7 +1031,8 @@
 				if (idx > s_idx)
 					memset(&cb->args[1], 0,
 					       sizeof(cb->args) - sizeof(cb->args[0]));
-				if (nf_tables_fill_chain_info(skb, NETLINK_CB(cb->skb).portid,
+				if (nf_tables_fill_chain_info(skb, net,
+							      NETLINK_CB(cb->skb).portid,
 							      cb->nlh->nlmsg_seq,
 							      NFT_MSG_NEWCHAIN,
 							      NLM_F_MULTI,
@@ -850,7 +1091,7 @@
 	if (!skb2)
 		return -ENOMEM;
 
-	err = nf_tables_fill_chain_info(skb2, NETLINK_CB(skb).portid,
+	err = nf_tables_fill_chain_info(skb2, net, NETLINK_CB(skb).portid,
 					nlh->nlmsg_seq, NFT_MSG_NEWCHAIN, 0,
 					family, table, chain);
 	if (err < 0)
@@ -913,21 +1154,6 @@
 		rcu_assign_pointer(chain->stats, newstats);
 }
 
-static int nft_trans_chain_add(struct nft_ctx *ctx, int msg_type)
-{
-	struct nft_trans *trans;
-
-	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_chain));
-	if (trans == NULL)
-		return -ENOMEM;
-
-	if (msg_type == NFT_MSG_NEWCHAIN)
-		ctx->chain->flags |= NFT_CHAIN_INACTIVE;
-
-	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
-	return 0;
-}
-
 static void nf_tables_chain_destroy(struct nft_chain *chain)
 {
 	BUG_ON(chain->use > 0);
@@ -1157,11 +1383,7 @@
 	list_add_tail_rcu(&chain->list, &table->chains);
 	return 0;
 err2:
-	if (!(table->flags & NFT_TABLE_F_DORMANT) &&
-	    chain->flags & NFT_BASE_CHAIN) {
-		nf_unregister_hooks(nft_base_chain(chain)->ops,
-				    afi->nops);
-	}
+	nf_tables_unregister_hooks(table, chain, afi->nops);
 err1:
 	nf_tables_chain_destroy(chain);
 	return err;
@@ -1178,7 +1400,6 @@
 	struct net *net = sock_net(skb->sk);
 	int family = nfmsg->nfgen_family;
 	struct nft_ctx ctx;
-	int err;
 
 	afi = nf_tables_afinfo_lookup(net, family, false);
 	if (IS_ERR(afi))
@@ -1199,13 +1420,8 @@
 		return -EBUSY;
 
 	nft_ctx_init(&ctx, skb, nlh, afi, table, chain, nla);
-	err = nft_trans_chain_add(&ctx, NFT_MSG_DELCHAIN);
-	if (err < 0)
-		return err;
 
-	table->use--;
-	list_del_rcu(&chain->list);
-	return 0;
+	return nft_delchain(&ctx);
 }
 
 /*
@@ -1432,8 +1648,9 @@
 				    .len = NFT_USERDATA_MAXLEN },
 };
 
-static int nf_tables_fill_rule_info(struct sk_buff *skb, u32 portid, u32 seq,
-				    int event, u32 flags, int family,
+static int nf_tables_fill_rule_info(struct sk_buff *skb, struct net *net,
+				    u32 portid, u32 seq, int event,
+				    u32 flags, int family,
 				    const struct nft_table *table,
 				    const struct nft_chain *chain,
 				    const struct nft_rule *rule)
@@ -1453,7 +1670,7 @@
 	nfmsg = nlmsg_data(nlh);
 	nfmsg->nfgen_family	= family;
 	nfmsg->version		= NFNETLINK_V0;
-	nfmsg->res_id		= 0;
+	nfmsg->res_id		= htons(net->nft.base_seq & 0xffff);
 
 	if (nla_put_string(skb, NFTA_RULE_TABLE, table->name))
 		goto nla_put_failure;
@@ -1509,8 +1726,8 @@
 	if (skb == NULL)
 		goto err;
 
-	err = nf_tables_fill_rule_info(skb, ctx->portid, ctx->seq, event, 0,
-				       ctx->afi->family, ctx->table,
+	err = nf_tables_fill_rule_info(skb, ctx->net, ctx->portid, ctx->seq,
+				       event, 0, ctx->afi->family, ctx->table,
 				       ctx->chain, rule);
 	if (err < 0) {
 		kfree_skb(skb);
@@ -1527,41 +1744,6 @@
 	return err;
 }
 
-static inline bool
-nft_rule_is_active(struct net *net, const struct nft_rule *rule)
-{
-	return (rule->genmask & (1 << net->nft.gencursor)) == 0;
-}
-
-static inline int gencursor_next(struct net *net)
-{
-	return net->nft.gencursor+1 == 1 ? 1 : 0;
-}
-
-static inline int
-nft_rule_is_active_next(struct net *net, const struct nft_rule *rule)
-{
-	return (rule->genmask & (1 << gencursor_next(net))) == 0;
-}
-
-static inline void
-nft_rule_activate_next(struct net *net, struct nft_rule *rule)
-{
-	/* Now inactive, will be active in the future */
-	rule->genmask = (1 << net->nft.gencursor);
-}
-
-static inline void
-nft_rule_disactivate_next(struct net *net, struct nft_rule *rule)
-{
-	rule->genmask = (1 << gencursor_next(net));
-}
-
-static inline void nft_rule_clear(struct net *net, struct nft_rule *rule)
-{
-	rule->genmask = 0;
-}
-
 static int nf_tables_dump_rules(struct sk_buff *skb,
 				struct netlink_callback *cb)
 {
@@ -1591,7 +1773,7 @@
 					if (idx > s_idx)
 						memset(&cb->args[1], 0,
 						       sizeof(cb->args) - sizeof(cb->args[0]));
-					if (nf_tables_fill_rule_info(skb, NETLINK_CB(cb->skb).portid,
+					if (nf_tables_fill_rule_info(skb, net, NETLINK_CB(cb->skb).portid,
 								      cb->nlh->nlmsg_seq,
 								      NFT_MSG_NEWRULE,
 								      NLM_F_MULTI | NLM_F_APPEND,
@@ -1657,7 +1839,7 @@
 	if (!skb2)
 		return -ENOMEM;
 
-	err = nf_tables_fill_rule_info(skb2, NETLINK_CB(skb).portid,
+	err = nf_tables_fill_rule_info(skb2, net, NETLINK_CB(skb).portid,
 				       nlh->nlmsg_seq, NFT_MSG_NEWRULE, 0,
 				       family, table, chain, rule);
 	if (err < 0)
@@ -1687,21 +1869,6 @@
 	kfree(rule);
 }
 
-static struct nft_trans *nft_trans_rule_add(struct nft_ctx *ctx, int msg_type,
-					    struct nft_rule *rule)
-{
-	struct nft_trans *trans;
-
-	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_rule));
-	if (trans == NULL)
-		return NULL;
-
-	nft_trans_rule(trans) = rule;
-	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
-
-	return trans;
-}
-
 #define NFT_RULE_MAXEXPRS	128
 
 static struct nft_expr_info *info;
@@ -1823,7 +1990,7 @@
 				err = -ENOMEM;
 				goto err2;
 			}
-			nft_rule_disactivate_next(net, old_rule);
+			nft_rule_deactivate_next(net, old_rule);
 			chain->use--;
 			list_add_tail_rcu(&rule->list, &old_rule->list);
 		} else {
@@ -1867,33 +2034,6 @@
 	return err;
 }
 
-static int
-nf_tables_delrule_one(struct nft_ctx *ctx, struct nft_rule *rule)
-{
-	/* You cannot delete the same rule twice */
-	if (nft_rule_is_active_next(ctx->net, rule)) {
-		if (nft_trans_rule_add(ctx, NFT_MSG_DELRULE, rule) == NULL)
-			return -ENOMEM;
-		nft_rule_disactivate_next(ctx->net, rule);
-		ctx->chain->use--;
-		return 0;
-	}
-	return -ENOENT;
-}
-
-static int nf_table_delrule_by_chain(struct nft_ctx *ctx)
-{
-	struct nft_rule *rule;
-	int err;
-
-	list_for_each_entry(rule, &ctx->chain->rules, list) {
-		err = nf_tables_delrule_one(ctx, rule);
-		if (err < 0)
-			return err;
-	}
-	return 0;
-}
-
 static int nf_tables_delrule(struct sock *nlsk, struct sk_buff *skb,
 			     const struct nlmsghdr *nlh,
 			     const struct nlattr * const nla[])
@@ -1932,14 +2072,14 @@
 			if (IS_ERR(rule))
 				return PTR_ERR(rule);
 
-			err = nf_tables_delrule_one(&ctx, rule);
+			err = nft_delrule(&ctx, rule);
 		} else {
-			err = nf_table_delrule_by_chain(&ctx);
+			err = nft_delrule_by_chain(&ctx);
 		}
 	} else {
 		list_for_each_entry(chain, &table->chains, list) {
 			ctx.chain = chain;
-			err = nf_table_delrule_by_chain(&ctx);
+			err = nft_delrule_by_chain(&ctx);
 			if (err < 0)
 				break;
 		}
@@ -2183,7 +2323,7 @@
 	nfmsg = nlmsg_data(nlh);
 	nfmsg->nfgen_family	= ctx->afi->family;
 	nfmsg->version		= NFNETLINK_V0;
-	nfmsg->res_id		= 0;
+	nfmsg->res_id		= htons(ctx->net->nft.base_seq & 0xffff);
 
 	if (nla_put_string(skb, NFTA_SET_TABLE, ctx->table->name))
 		goto nla_put_failure;
@@ -2204,6 +2344,11 @@
 			goto nla_put_failure;
 	}
 
+	if (set->policy != NFT_SET_POL_PERFORMANCE) {
+		if (nla_put_be32(skb, NFTA_SET_POLICY, htonl(set->policy)))
+			goto nla_put_failure;
+	}
+
 	desc = nla_nest_start(skb, NFTA_SET_DESC);
 	if (desc == NULL)
 		goto nla_put_failure;
@@ -2322,8 +2467,6 @@
 	return 0;
 }
 
-#define NFT_SET_INACTIVE	(1 << 15)	/* Internal set flag */
-
 static int nf_tables_getset(struct sock *nlsk, struct sk_buff *skb,
 			    const struct nlmsghdr *nlh,
 			    const struct nlattr * const nla[])
@@ -2398,26 +2541,6 @@
 	return 0;
 }
 
-static int nft_trans_set_add(struct nft_ctx *ctx, int msg_type,
-			     struct nft_set *set)
-{
-	struct nft_trans *trans;
-
-	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_set));
-	if (trans == NULL)
-		return -ENOMEM;
-
-	if (msg_type == NFT_MSG_NEWSET && ctx->nla[NFTA_SET_ID] != NULL) {
-		nft_trans_set_id(trans) =
-			ntohl(nla_get_be32(ctx->nla[NFTA_SET_ID]));
-		set->flags |= NFT_SET_INACTIVE;
-	}
-	nft_trans_set(trans) = set;
-	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
-
-	return 0;
-}
-
 static int nf_tables_newset(struct sock *nlsk, struct sk_buff *skb,
 			    const struct nlmsghdr *nlh,
 			    const struct nlattr * const nla[])
@@ -2551,6 +2674,7 @@
 	set->dlen  = desc.dlen;
 	set->flags = flags;
 	set->size  = desc.size;
+	set->policy = policy;
 
 	err = ops->init(set, &desc, nla);
 	if (err < 0)
@@ -2611,13 +2735,7 @@
 	if (!list_empty(&set->bindings))
 		return -EBUSY;
 
-	err = nft_trans_set_add(&ctx, NFT_MSG_DELSET, set);
-	if (err < 0)
-		return err;
-
-	list_del_rcu(&set->list);
-	ctx.table->use--;
-	return 0;
+	return nft_delset(&ctx, set);
 }
 
 static int nf_tables_bind_check_setelem(const struct nft_ctx *ctx,
@@ -2815,7 +2933,7 @@
 	nfmsg = nlmsg_data(nlh);
 	nfmsg->nfgen_family = ctx.afi->family;
 	nfmsg->version      = NFNETLINK_V0;
-	nfmsg->res_id       = 0;
+	nfmsg->res_id	    = htons(ctx.net->nft.base_seq & 0xffff);
 
 	if (nla_put_string(skb, NFTA_SET_ELEM_LIST_TABLE, ctx.table->name))
 		goto nla_put_failure;
@@ -2896,7 +3014,7 @@
 	nfmsg = nlmsg_data(nlh);
 	nfmsg->nfgen_family	= ctx->afi->family;
 	nfmsg->version		= NFNETLINK_V0;
-	nfmsg->res_id		= 0;
+	nfmsg->res_id		= htons(ctx->net->nft.base_seq & 0xffff);
 
 	if (nla_put_string(skb, NFTA_SET_TABLE, ctx->table->name))
 		goto nla_put_failure;
@@ -3183,6 +3301,87 @@
 	return err;
 }
 
+static int nf_tables_fill_gen_info(struct sk_buff *skb, struct net *net,
+				   u32 portid, u32 seq)
+{
+	struct nlmsghdr *nlh;
+	struct nfgenmsg *nfmsg;
+	int event = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWGEN;
+
+	nlh = nlmsg_put(skb, portid, seq, event, sizeof(struct nfgenmsg), 0);
+	if (nlh == NULL)
+		goto nla_put_failure;
+
+	nfmsg = nlmsg_data(nlh);
+	nfmsg->nfgen_family	= AF_UNSPEC;
+	nfmsg->version		= NFNETLINK_V0;
+	nfmsg->res_id		= htons(net->nft.base_seq & 0xffff);
+
+	if (nla_put_be32(skb, NFTA_GEN_ID, htonl(net->nft.base_seq)))
+		goto nla_put_failure;
+
+	return nlmsg_end(skb, nlh);
+
+nla_put_failure:
+	nlmsg_trim(skb, nlh);
+	return -EMSGSIZE;
+}
+
+static int nf_tables_gen_notify(struct net *net, struct sk_buff *skb, int event)
+{
+	struct nlmsghdr *nlh = nlmsg_hdr(skb);
+	struct sk_buff *skb2;
+	int err;
+
+	if (nlmsg_report(nlh) &&
+	    !nfnetlink_has_listeners(net, NFNLGRP_NFTABLES))
+		return 0;
+
+	err = -ENOBUFS;
+	skb2 = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
+	if (skb2 == NULL)
+		goto err;
+
+	err = nf_tables_fill_gen_info(skb2, net, NETLINK_CB(skb).portid,
+				      nlh->nlmsg_seq);
+	if (err < 0) {
+		kfree_skb(skb2);
+		goto err;
+	}
+
+	err = nfnetlink_send(skb2, net, NETLINK_CB(skb).portid,
+			     NFNLGRP_NFTABLES, nlmsg_report(nlh), GFP_KERNEL);
+err:
+	if (err < 0) {
+		nfnetlink_set_err(net, NETLINK_CB(skb).portid, NFNLGRP_NFTABLES,
+				  err);
+	}
+	return err;
+}
+
+static int nf_tables_getgen(struct sock *nlsk, struct sk_buff *skb,
+			    const struct nlmsghdr *nlh,
+			    const struct nlattr * const nla[])
+{
+	struct net *net = sock_net(skb->sk);
+	struct sk_buff *skb2;
+	int err;
+
+	skb2 = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
+	if (skb2 == NULL)
+		return -ENOMEM;
+
+	err = nf_tables_fill_gen_info(skb2, net, NETLINK_CB(skb).portid,
+				      nlh->nlmsg_seq);
+	if (err < 0)
+		goto err;
+
+	return nlmsg_unicast(nlsk, skb2, NETLINK_CB(skb).portid);
+err:
+	kfree_skb(skb2);
+	return err;
+}
+
 static const struct nfnl_callback nf_tables_cb[NFT_MSG_MAX] = {
 	[NFT_MSG_NEWTABLE] = {
 		.call_batch	= nf_tables_newtable,
@@ -3259,6 +3458,9 @@
 		.attr_count	= NFTA_SET_ELEM_LIST_MAX,
 		.policy		= nft_set_elem_list_policy,
 	},
+	[NFT_MSG_GETGEN] = {
+		.call		= nf_tables_getgen,
+	},
 };
 
 static void nft_chain_commit_update(struct nft_trans *trans)
@@ -3352,11 +3554,9 @@
 			break;
 		case NFT_MSG_DELCHAIN:
 			nf_tables_chain_notify(&trans->ctx, NFT_MSG_DELCHAIN);
-			if (!(trans->ctx.table->flags & NFT_TABLE_F_DORMANT) &&
-			    trans->ctx.chain->flags & NFT_BASE_CHAIN) {
-				nf_unregister_hooks(nft_base_chain(trans->ctx.chain)->ops,
-						    trans->ctx.afi->nops);
-			}
+			nf_tables_unregister_hooks(trans->ctx.table,
+						   trans->ctx.chain,
+						   trans->ctx.afi->nops);
 			break;
 		case NFT_MSG_NEWRULE:
 			nft_rule_clear(trans->ctx.net, nft_trans_rule(trans));
@@ -3418,6 +3618,8 @@
 		call_rcu(&trans->rcu_head, nf_tables_commit_release_rcu);
 	}
 
+	nf_tables_gen_notify(net, skb, NFT_MSG_NEWGEN);
+
 	return 0;
 }
 
@@ -3479,11 +3681,9 @@
 			} else {
 				trans->ctx.table->use--;
 				list_del_rcu(&trans->ctx.chain->list);
-				if (!(trans->ctx.table->flags & NFT_TABLE_F_DORMANT) &&
-				    trans->ctx.chain->flags & NFT_BASE_CHAIN) {
-					nf_unregister_hooks(nft_base_chain(trans->ctx.chain)->ops,
-							    trans->ctx.afi->nops);
-				}
+				nf_tables_unregister_hooks(trans->ctx.table,
+							   trans->ctx.chain,
+							   trans->ctx.afi->nops);
 			}
 			break;
 		case NFT_MSG_DELCHAIN:
@@ -3963,6 +4163,7 @@
 {
 	unregister_pernet_subsys(&nf_tables_net_ops);
 	nfnetlink_subsys_unregister(&nf_tables_subsys);
+	rcu_barrier();
 	nf_tables_core_module_exit();
 	kfree(info);
 }
diff -urN linux/net/netfilter/nft_compat.c net-next-2.6/net/netfilter/nft_compat.c
--- linux/net/netfilter/nft_compat.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nft_compat.c	2014-10-06 10:49:04.172940625 +0200
@@ -101,26 +101,12 @@
 
 static void target_compat_from_user(struct xt_target *t, void *in, void *out)
 {
-#ifdef CONFIG_COMPAT
-	if (t->compat_from_user) {
-		int pad;
-
-		t->compat_from_user(out, in);
-		pad = XT_ALIGN(t->targetsize) - t->targetsize;
-		if (pad > 0)
-			memset(out + t->targetsize, 0, pad);
-	} else
-#endif
-		memcpy(out, in, XT_ALIGN(t->targetsize));
-}
-
-static inline int nft_compat_target_offset(struct xt_target *target)
-{
-#ifdef CONFIG_COMPAT
-	return xt_compat_target_offset(target);
-#else
-	return 0;
-#endif
+	int pad;
+
+	memcpy(out, in, t->targetsize);
+	pad = XT_ALIGN(t->targetsize) - t->targetsize;
+	if (pad > 0)
+		memset(out + t->targetsize, 0, pad);
 }
 
 static const struct nla_policy nft_rule_compat_policy[NFTA_RULE_COMPAT_MAX + 1] = {
@@ -208,34 +194,6 @@
 	module_put(target->me);
 }
 
-static int
-target_dump_info(struct sk_buff *skb, const struct xt_target *t, const void *in)
-{
-	int ret;
-
-#ifdef CONFIG_COMPAT
-	if (t->compat_to_user) {
-		mm_segment_t old_fs;
-		void *out;
-
-		out = kmalloc(XT_ALIGN(t->targetsize), GFP_ATOMIC);
-		if (out == NULL)
-			return -ENOMEM;
-
-		/* We want to reuse existing compat_to_user */
-		old_fs = get_fs();
-		set_fs(KERNEL_DS);
-		t->compat_to_user(out, in);
-		set_fs(old_fs);
-		ret = nla_put(skb, NFTA_TARGET_INFO, XT_ALIGN(t->targetsize), out);
-		kfree(out);
-	} else
-#endif
-		ret = nla_put(skb, NFTA_TARGET_INFO, XT_ALIGN(t->targetsize), in);
-
-	return ret;
-}
-
 static int nft_target_dump(struct sk_buff *skb, const struct nft_expr *expr)
 {
 	const struct xt_target *target = expr->ops->data;
@@ -243,7 +201,7 @@
 
 	if (nla_put_string(skb, NFTA_TARGET_NAME, target->name) ||
 	    nla_put_be32(skb, NFTA_TARGET_REV, htonl(target->revision)) ||
-	    target_dump_info(skb, target, info))
+	    nla_put(skb, NFTA_TARGET_INFO, XT_ALIGN(target->targetsize), info))
 		goto nla_put_failure;
 
 	return 0;
@@ -341,17 +299,12 @@
 
 static void match_compat_from_user(struct xt_match *m, void *in, void *out)
 {
-#ifdef CONFIG_COMPAT
-	if (m->compat_from_user) {
-		int pad;
-
-		m->compat_from_user(out, in);
-		pad = XT_ALIGN(m->matchsize) - m->matchsize;
-		if (pad > 0)
-			memset(out + m->matchsize, 0, pad);
-	} else
-#endif
-		memcpy(out, in, XT_ALIGN(m->matchsize));
+	int pad;
+
+	memcpy(out, in, m->matchsize);
+	pad = XT_ALIGN(m->matchsize) - m->matchsize;
+	if (pad > 0)
+		memset(out + m->matchsize, 0, pad);
 }
 
 static int
@@ -404,43 +357,6 @@
 	module_put(match->me);
 }
 
-static int
-match_dump_info(struct sk_buff *skb, const struct xt_match *m, const void *in)
-{
-	int ret;
-
-#ifdef CONFIG_COMPAT
-	if (m->compat_to_user) {
-		mm_segment_t old_fs;
-		void *out;
-
-		out = kmalloc(XT_ALIGN(m->matchsize), GFP_ATOMIC);
-		if (out == NULL)
-			return -ENOMEM;
-
-		/* We want to reuse existing compat_to_user */
-		old_fs = get_fs();
-		set_fs(KERNEL_DS);
-		m->compat_to_user(out, in);
-		set_fs(old_fs);
-		ret = nla_put(skb, NFTA_MATCH_INFO, XT_ALIGN(m->matchsize), out);
-		kfree(out);
-	} else
-#endif
-		ret = nla_put(skb, NFTA_MATCH_INFO, XT_ALIGN(m->matchsize), in);
-
-	return ret;
-}
-
-static inline int nft_compat_match_offset(struct xt_match *match)
-{
-#ifdef CONFIG_COMPAT
-	return xt_compat_match_offset(match);
-#else
-	return 0;
-#endif
-}
-
 static int nft_match_dump(struct sk_buff *skb, const struct nft_expr *expr)
 {
 	void *info = nft_expr_priv(expr);
@@ -448,7 +364,7 @@
 
 	if (nla_put_string(skb, NFTA_MATCH_NAME, match->name) ||
 	    nla_put_be32(skb, NFTA_MATCH_REV, htonl(match->revision)) ||
-	    match_dump_info(skb, match, info))
+	    nla_put(skb, NFTA_MATCH_INFO, XT_ALIGN(match->matchsize), info))
 		goto nla_put_failure;
 
 	return 0;
@@ -643,8 +559,7 @@
 		return ERR_PTR(-ENOMEM);
 
 	nft_match->ops.type = &nft_match_type;
-	nft_match->ops.size = NFT_EXPR_SIZE(XT_ALIGN(match->matchsize) +
-					    nft_compat_match_offset(match));
+	nft_match->ops.size = NFT_EXPR_SIZE(XT_ALIGN(match->matchsize));
 	nft_match->ops.eval = nft_match_eval;
 	nft_match->ops.init = nft_match_init;
 	nft_match->ops.destroy = nft_match_destroy;
@@ -714,8 +629,7 @@
 		return ERR_PTR(-ENOMEM);
 
 	nft_target->ops.type = &nft_target_type;
-	nft_target->ops.size = NFT_EXPR_SIZE(XT_ALIGN(target->targetsize) +
-					     nft_compat_target_offset(target));
+	nft_target->ops.size = NFT_EXPR_SIZE(XT_ALIGN(target->targetsize));
 	nft_target->ops.eval = nft_target_eval;
 	nft_target->ops.init = nft_target_init;
 	nft_target->ops.destroy = nft_target_destroy;
diff -urN linux/net/netfilter/nft_masq.c net-next-2.6/net/netfilter/nft_masq.c
--- linux/net/netfilter/nft_masq.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/netfilter/nft_masq.c	2014-10-06 10:49:04.172940625 +0200
@@ -0,0 +1,59 @@
+/*
+ * Copyright (c) 2014 Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ */
+
+#include <linux/kernel.h>
+#include <linux/init.h>
+#include <linux/module.h>
+#include <linux/netlink.h>
+#include <linux/netfilter.h>
+#include <linux/netfilter/nf_tables.h>
+#include <net/netfilter/nf_tables.h>
+#include <net/netfilter/nf_nat.h>
+#include <net/netfilter/nft_masq.h>
+
+const struct nla_policy nft_masq_policy[NFTA_MASQ_MAX + 1] = {
+	[NFTA_MASQ_FLAGS]	= { .type = NLA_U32 },
+};
+EXPORT_SYMBOL_GPL(nft_masq_policy);
+
+int nft_masq_init(const struct nft_ctx *ctx,
+		  const struct nft_expr *expr,
+		  const struct nlattr * const tb[])
+{
+	struct nft_masq *priv = nft_expr_priv(expr);
+
+	if (tb[NFTA_MASQ_FLAGS] == NULL)
+		return 0;
+
+	priv->flags = ntohl(nla_get_be32(tb[NFTA_MASQ_FLAGS]));
+	if (priv->flags & ~NF_NAT_RANGE_MASK)
+		return -EINVAL;
+
+	return 0;
+}
+EXPORT_SYMBOL_GPL(nft_masq_init);
+
+int nft_masq_dump(struct sk_buff *skb, const struct nft_expr *expr)
+{
+	const struct nft_masq *priv = nft_expr_priv(expr);
+
+	if (priv->flags == 0)
+		return 0;
+
+	if (nla_put_be32(skb, NFTA_MASQ_FLAGS, htonl(priv->flags)))
+		goto nla_put_failure;
+
+	return 0;
+
+nla_put_failure:
+	return -1;
+}
+EXPORT_SYMBOL_GPL(nft_masq_dump);
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>");
diff -urN linux/net/netfilter/nft_meta.c net-next-2.6/net/netfilter/nft_meta.c
--- linux/net/netfilter/nft_meta.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nft_meta.c	2014-10-06 10:49:04.172940625 +0200
@@ -14,6 +14,10 @@
 #include <linux/netlink.h>
 #include <linux/netfilter.h>
 #include <linux/netfilter/nf_tables.h>
+#include <linux/in.h>
+#include <linux/ip.h>
+#include <linux/ipv6.h>
+#include <linux/smp.h>
 #include <net/dst.h>
 #include <net/sock.h>
 #include <net/tcp_states.h> /* for TCP_TIME_WAIT */
@@ -124,6 +128,43 @@
 		dest->data[0] = skb->secmark;
 		break;
 #endif
+	case NFT_META_PKTTYPE:
+		if (skb->pkt_type != PACKET_LOOPBACK) {
+			dest->data[0] = skb->pkt_type;
+			break;
+		}
+
+		switch (pkt->ops->pf) {
+		case NFPROTO_IPV4:
+			if (ipv4_is_multicast(ip_hdr(skb)->daddr))
+				dest->data[0] = PACKET_MULTICAST;
+			else
+				dest->data[0] = PACKET_BROADCAST;
+			break;
+		case NFPROTO_IPV6:
+			if (ipv6_hdr(skb)->daddr.s6_addr[0] == 0xFF)
+				dest->data[0] = PACKET_MULTICAST;
+			else
+				dest->data[0] = PACKET_BROADCAST;
+			break;
+		default:
+			WARN_ON(1);
+			goto err;
+		}
+		break;
+	case NFT_META_CPU:
+		dest->data[0] = smp_processor_id();
+		break;
+	case NFT_META_IIFGROUP:
+		if (in == NULL)
+			goto err;
+		dest->data[0] = in->group;
+		break;
+	case NFT_META_OIFGROUP:
+		if (out == NULL)
+			goto err;
+		dest->data[0] = out->group;
+		break;
 	default:
 		WARN_ON(1);
 		goto err;
@@ -195,6 +236,10 @@
 #ifdef CONFIG_NETWORK_SECMARK
 	case NFT_META_SECMARK:
 #endif
+	case NFT_META_PKTTYPE:
+	case NFT_META_CPU:
+	case NFT_META_IIFGROUP:
+	case NFT_META_OIFGROUP:
 		break;
 	default:
 		return -EOPNOTSUPP;
diff -urN linux/net/netfilter/nft_nat.c net-next-2.6/net/netfilter/nft_nat.c
--- linux/net/netfilter/nft_nat.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nft_nat.c	2014-10-06 10:49:04.172940625 +0200
@@ -33,6 +33,7 @@
 	enum nft_registers      sreg_proto_max:8;
 	enum nf_nat_manip_type  type:8;
 	u8			family;
+	u16			flags;
 };
 
 static void nft_nat_eval(const struct nft_expr *expr,
@@ -71,6 +72,8 @@
 		range.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
 	}
 
+	range.flags |= priv->flags;
+
 	data[NFT_REG_VERDICT].verdict =
 		nf_nat_setup_info(ct, &range, priv->type);
 }
@@ -82,6 +85,7 @@
 	[NFTA_NAT_REG_ADDR_MAX]	 = { .type = NLA_U32 },
 	[NFTA_NAT_REG_PROTO_MIN] = { .type = NLA_U32 },
 	[NFTA_NAT_REG_PROTO_MAX] = { .type = NLA_U32 },
+	[NFTA_NAT_FLAGS]	 = { .type = NLA_U32 },
 };
 
 static int nft_nat_init(const struct nft_ctx *ctx, const struct nft_expr *expr,
@@ -149,6 +153,12 @@
 	} else
 		priv->sreg_proto_max = priv->sreg_proto_min;
 
+	if (tb[NFTA_NAT_FLAGS]) {
+		priv->flags = ntohl(nla_get_be32(tb[NFTA_NAT_FLAGS]));
+		if (priv->flags & ~NF_NAT_RANGE_MASK)
+			return -EINVAL;
+	}
+
 	return 0;
 }
 
@@ -183,6 +193,12 @@
 				 htonl(priv->sreg_proto_max)))
 			goto nla_put_failure;
 	}
+
+	if (priv->flags != 0) {
+		if (nla_put_be32(skb, NFTA_NAT_FLAGS, htonl(priv->flags)))
+			goto nla_put_failure;
+	}
+
 	return 0;
 
 nla_put_failure:
diff -urN linux/net/netfilter/nft_reject.c net-next-2.6/net/netfilter/nft_reject.c
--- linux/net/netfilter/nft_reject.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nft_reject.c	2014-10-06 10:49:04.172940625 +0200
@@ -17,6 +17,8 @@
 #include <linux/netfilter/nf_tables.h>
 #include <net/netfilter/nf_tables.h>
 #include <net/netfilter/nft_reject.h>
+#include <linux/icmp.h>
+#include <linux/icmpv6.h>
 
 const struct nla_policy nft_reject_policy[NFTA_REJECT_MAX + 1] = {
 	[NFTA_REJECT_TYPE]		= { .type = NLA_U32 },
@@ -70,5 +72,40 @@
 }
 EXPORT_SYMBOL_GPL(nft_reject_dump);
 
+static u8 icmp_code_v4[NFT_REJECT_ICMPX_MAX] = {
+	[NFT_REJECT_ICMPX_NO_ROUTE]		= ICMP_NET_UNREACH,
+	[NFT_REJECT_ICMPX_PORT_UNREACH]		= ICMP_PORT_UNREACH,
+	[NFT_REJECT_ICMPX_HOST_UNREACH]		= ICMP_HOST_UNREACH,
+	[NFT_REJECT_ICMPX_ADMIN_PROHIBITED]	= ICMP_PKT_FILTERED,
+};
+
+int nft_reject_icmp_code(u8 code)
+{
+	if (code > NFT_REJECT_ICMPX_MAX)
+		return -EINVAL;
+
+	return icmp_code_v4[code];
+}
+
+EXPORT_SYMBOL_GPL(nft_reject_icmp_code);
+
+
+static u8 icmp_code_v6[NFT_REJECT_ICMPX_MAX] = {
+	[NFT_REJECT_ICMPX_NO_ROUTE]		= ICMPV6_NOROUTE,
+	[NFT_REJECT_ICMPX_PORT_UNREACH]		= ICMPV6_PORT_UNREACH,
+	[NFT_REJECT_ICMPX_HOST_UNREACH]		= ICMPV6_ADDR_UNREACH,
+	[NFT_REJECT_ICMPX_ADMIN_PROHIBITED]	= ICMPV6_ADM_PROHIBITED,
+};
+
+int nft_reject_icmpv6_code(u8 code)
+{
+	if (code > NFT_REJECT_ICMPX_MAX)
+		return -EINVAL;
+
+	return icmp_code_v6[code];
+}
+
+EXPORT_SYMBOL_GPL(nft_reject_icmpv6_code);
+
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
diff -urN linux/net/netfilter/nft_reject_inet.c net-next-2.6/net/netfilter/nft_reject_inet.c
--- linux/net/netfilter/nft_reject_inet.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/nft_reject_inet.c	2014-10-06 10:49:04.172940625 +0200
@@ -14,17 +14,103 @@
 #include <linux/netfilter/nf_tables.h>
 #include <net/netfilter/nf_tables.h>
 #include <net/netfilter/nft_reject.h>
+#include <net/netfilter/ipv4/nf_reject.h>
+#include <net/netfilter/ipv6/nf_reject.h>
 
 static void nft_reject_inet_eval(const struct nft_expr *expr,
 				 struct nft_data data[NFT_REG_MAX + 1],
 				 const struct nft_pktinfo *pkt)
 {
+	struct nft_reject *priv = nft_expr_priv(expr);
+	struct net *net = dev_net((pkt->in != NULL) ? pkt->in : pkt->out);
+
 	switch (pkt->ops->pf) {
 	case NFPROTO_IPV4:
-		return nft_reject_ipv4_eval(expr, data, pkt);
+		switch (priv->type) {
+		case NFT_REJECT_ICMP_UNREACH:
+			nf_send_unreach(pkt->skb, priv->icmp_code);
+			break;
+		case NFT_REJECT_TCP_RST:
+			nf_send_reset(pkt->skb, pkt->ops->hooknum);
+			break;
+		case NFT_REJECT_ICMPX_UNREACH:
+			nf_send_unreach(pkt->skb,
+					nft_reject_icmp_code(priv->icmp_code));
+			break;
+		}
+		break;
 	case NFPROTO_IPV6:
-		return nft_reject_ipv6_eval(expr, data, pkt);
+		switch (priv->type) {
+		case NFT_REJECT_ICMP_UNREACH:
+			nf_send_unreach6(net, pkt->skb, priv->icmp_code,
+					 pkt->ops->hooknum);
+			break;
+		case NFT_REJECT_TCP_RST:
+			nf_send_reset6(net, pkt->skb, pkt->ops->hooknum);
+			break;
+		case NFT_REJECT_ICMPX_UNREACH:
+			nf_send_unreach6(net, pkt->skb,
+					 nft_reject_icmpv6_code(priv->icmp_code),
+					 pkt->ops->hooknum);
+			break;
+		}
+		break;
+	}
+	data[NFT_REG_VERDICT].verdict = NF_DROP;
+}
+
+static int nft_reject_inet_init(const struct nft_ctx *ctx,
+				const struct nft_expr *expr,
+				const struct nlattr * const tb[])
+{
+	struct nft_reject *priv = nft_expr_priv(expr);
+	int icmp_code;
+
+	if (tb[NFTA_REJECT_TYPE] == NULL)
+		return -EINVAL;
+
+	priv->type = ntohl(nla_get_be32(tb[NFTA_REJECT_TYPE]));
+	switch (priv->type) {
+	case NFT_REJECT_ICMP_UNREACH:
+	case NFT_REJECT_ICMPX_UNREACH:
+		if (tb[NFTA_REJECT_ICMP_CODE] == NULL)
+			return -EINVAL;
+
+		icmp_code = nla_get_u8(tb[NFTA_REJECT_ICMP_CODE]);
+		if (priv->type == NFT_REJECT_ICMPX_UNREACH &&
+		    icmp_code > NFT_REJECT_ICMPX_MAX)
+			return -EINVAL;
+
+		priv->icmp_code = icmp_code;
+		break;
+	case NFT_REJECT_TCP_RST:
+		break;
+	default:
+		return -EINVAL;
 	}
+	return 0;
+}
+
+static int nft_reject_inet_dump(struct sk_buff *skb,
+				const struct nft_expr *expr)
+{
+	const struct nft_reject *priv = nft_expr_priv(expr);
+
+	if (nla_put_be32(skb, NFTA_REJECT_TYPE, htonl(priv->type)))
+		goto nla_put_failure;
+
+	switch (priv->type) {
+	case NFT_REJECT_ICMP_UNREACH:
+	case NFT_REJECT_ICMPX_UNREACH:
+		if (nla_put_u8(skb, NFTA_REJECT_ICMP_CODE, priv->icmp_code))
+			goto nla_put_failure;
+		break;
+	}
+
+	return 0;
+
+nla_put_failure:
+	return -1;
 }
 
 static struct nft_expr_type nft_reject_inet_type;
@@ -32,8 +118,8 @@
 	.type		= &nft_reject_inet_type,
 	.size		= NFT_EXPR_SIZE(sizeof(struct nft_reject)),
 	.eval		= nft_reject_inet_eval,
-	.init		= nft_reject_init,
-	.dump		= nft_reject_dump,
+	.init		= nft_reject_inet_init,
+	.dump		= nft_reject_inet_dump,
 };
 
 static struct nft_expr_type nft_reject_inet_type __read_mostly = {
diff -urN linux/net/netfilter/x_tables.c net-next-2.6/net/netfilter/x_tables.c
--- linux/net/netfilter/x_tables.c	2014-09-24 09:52:43.256645173 +0200
+++ net-next-2.6/net/netfilter/x_tables.c	2014-10-06 10:49:04.172940625 +0200
@@ -1101,22 +1101,11 @@
 
 static int xt_match_open(struct inode *inode, struct file *file)
 {
-	struct seq_file *seq;
 	struct nf_mttg_trav *trav;
-	int ret;
-
-	trav = kmalloc(sizeof(*trav), GFP_KERNEL);
-	if (trav == NULL)
+	trav = __seq_open_private(file, &xt_match_seq_ops, sizeof(*trav));
+	if (!trav)
 		return -ENOMEM;
 
-	ret = seq_open(file, &xt_match_seq_ops);
-	if (ret < 0) {
-		kfree(trav);
-		return ret;
-	}
-
-	seq = file->private_data;
-	seq->private = trav;
 	trav->nfproto = (unsigned long)PDE_DATA(inode);
 	return 0;
 }
@@ -1165,22 +1154,11 @@
 
 static int xt_target_open(struct inode *inode, struct file *file)
 {
-	struct seq_file *seq;
 	struct nf_mttg_trav *trav;
-	int ret;
-
-	trav = kmalloc(sizeof(*trav), GFP_KERNEL);
-	if (trav == NULL)
+	trav = __seq_open_private(file, &xt_target_seq_ops, sizeof(*trav));
+	if (!trav)
 		return -ENOMEM;
 
-	ret = seq_open(file, &xt_target_seq_ops);
-	if (ret < 0) {
-		kfree(trav);
-		return ret;
-	}
-
-	seq = file->private_data;
-	seq->private = trav;
 	trav->nfproto = (unsigned long)PDE_DATA(inode);
 	return 0;
 }
diff -urN linux/net/netfilter/xt_cluster.c net-next-2.6/net/netfilter/xt_cluster.c
--- linux/net/netfilter/xt_cluster.c	2011-07-22 09:59:45.562757056 +0200
+++ net-next-2.6/net/netfilter/xt_cluster.c	2014-10-06 10:49:04.176940666 +0200
@@ -55,7 +55,8 @@
 		WARN_ON(1);
 		break;
 	}
-	return (((u64)hash * info->total_nodes) >> 32);
+
+	return reciprocal_scale(hash, info->total_nodes);
 }
 
 static inline bool
diff -urN linux/net/netfilter/xt_connbytes.c net-next-2.6/net/netfilter/xt_connbytes.c
--- linux/net/netfilter/xt_connbytes.c	2013-11-29 12:59:37.983382580 +0100
+++ net-next-2.6/net/netfilter/xt_connbytes.c	2014-10-06 10:49:04.176940666 +0200
@@ -120,7 +120,7 @@
 	 * accounting is enabled, so complain in the hope that someone notices.
 	 */
 	if (!nf_ct_acct_enabled(par->net)) {
-		pr_warning("Forcing CT accounting to be enabled\n");
+		pr_warn("Forcing CT accounting to be enabled\n");
 		nf_ct_set_acct(par->net, true);
 	}
 
diff -urN linux/net/netfilter/xt_hashlimit.c net-next-2.6/net/netfilter/xt_hashlimit.c
--- linux/net/netfilter/xt_hashlimit.c	2014-09-24 09:52:43.260645215 +0200
+++ net-next-2.6/net/netfilter/xt_hashlimit.c	2014-10-06 10:49:04.176940666 +0200
@@ -135,7 +135,7 @@
 	 * give results between [0 and cfg.size-1] and same hash distribution,
 	 * but using a multiply, less expensive than a divide
 	 */
-	return ((u64)hash * ht->cfg.size) >> 32;
+	return reciprocal_scale(hash, ht->cfg.size);
 }
 
 static struct dsthash_ent *
@@ -943,7 +943,7 @@
 					    sizeof(struct dsthash_ent), 0, 0,
 					    NULL);
 	if (!hashlimit_cachep) {
-		pr_warning("unable to create slab cache\n");
+		pr_warn("unable to create slab cache\n");
 		goto err2;
 	}
 	return 0;
diff -urN linux/net/netfilter/xt_HMARK.c net-next-2.6/net/netfilter/xt_HMARK.c
--- linux/net/netfilter/xt_HMARK.c	2013-05-02 09:43:21.657515164 +0200
+++ net-next-2.6/net/netfilter/xt_HMARK.c	2014-10-06 10:49:04.176940666 +0200
@@ -126,7 +126,7 @@
 	hash = jhash_3words(src, dst, t->uports.v32, info->hashrnd);
 	hash = hash ^ (t->proto & info->proto_mask);
 
-	return (((u64)hash * info->hmodulus) >> 32) + info->hoffset;
+	return reciprocal_scale(hash, info->hmodulus) + info->hoffset;
 }
 
 static void
diff -urN linux/net/netfilter/xt_physdev.c net-next-2.6/net/netfilter/xt_physdev.c
--- linux/net/netfilter/xt_physdev.c	2011-07-22 09:59:45.593382318 +0200
+++ net-next-2.6/net/netfilter/xt_physdev.c	2014-10-06 10:49:04.176940666 +0200
@@ -13,6 +13,7 @@
 #include <linux/netfilter_bridge.h>
 #include <linux/netfilter/xt_physdev.h>
 #include <linux/netfilter/x_tables.h>
+#include <net/netfilter/br_netfilter.h>
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Bart De Schuymer <bdschuym@pandora.be>");
@@ -87,6 +88,8 @@
 {
 	const struct xt_physdev_info *info = par->matchinfo;
 
+	br_netfilter_enable();
+
 	if (!(info->bitmask & XT_PHYSDEV_OP_MASK) ||
 	    info->bitmask & ~XT_PHYSDEV_OP_MASK)
 		return -EINVAL;
diff -urN linux/net/netfilter/xt_RATEEST.c net-next-2.6/net/netfilter/xt_RATEEST.c
--- linux/net/netfilter/xt_RATEEST.c	2013-05-02 09:43:21.661515164 +0200
+++ net-next-2.6/net/netfilter/xt_RATEEST.c	2014-10-06 10:49:04.176940666 +0200
@@ -136,7 +136,7 @@
 	cfg.est.interval	= info->interval;
 	cfg.est.ewma_log	= info->ewma_log;
 
-	ret = gen_new_estimator(&est->bstats, &est->rstats,
+	ret = gen_new_estimator(&est->bstats, NULL, &est->rstats,
 				&est->lock, &cfg.opt);
 	if (ret < 0)
 		goto err2;
diff -urN linux/net/netfilter/xt_set.c net-next-2.6/net/netfilter/xt_set.c
--- linux/net/netfilter/xt_set.c	2013-11-29 12:59:37.983382580 +0100
+++ net-next-2.6/net/netfilter/xt_set.c	2014-10-06 10:49:04.176940666 +0200
@@ -84,13 +84,12 @@
 	index = ip_set_nfnl_get_byindex(par->net, info->match_set.index);
 
 	if (index == IPSET_INVALID_ID) {
-		pr_warning("Cannot find set identified by id %u to match\n",
-			   info->match_set.index);
+		pr_warn("Cannot find set identified by id %u to match\n",
+			info->match_set.index);
 		return -ENOENT;
 	}
 	if (info->match_set.u.flags[IPSET_DIM_MAX-1] != 0) {
-		pr_warning("Protocol error: set match dimension "
-			   "is over the limit!\n");
+		pr_warn("Protocol error: set match dimension is over the limit!\n");
 		ip_set_nfnl_put(par->net, info->match_set.index);
 		return -ERANGE;
 	}
@@ -134,13 +133,12 @@
 	index = ip_set_nfnl_get_byindex(par->net, info->match_set.index);
 
 	if (index == IPSET_INVALID_ID) {
-		pr_warning("Cannot find set identified by id %u to match\n",
-			   info->match_set.index);
+		pr_warn("Cannot find set identified by id %u to match\n",
+			info->match_set.index);
 		return -ENOENT;
 	}
 	if (info->match_set.dim > IPSET_DIM_MAX) {
-		pr_warning("Protocol error: set match dimension "
-			   "is over the limit!\n");
+		pr_warn("Protocol error: set match dimension is over the limit!\n");
 		ip_set_nfnl_put(par->net, info->match_set.index);
 		return -ERANGE;
 	}
@@ -230,8 +228,8 @@
 	if (info->add_set.index != IPSET_INVALID_ID) {
 		index = ip_set_nfnl_get_byindex(par->net, info->add_set.index);
 		if (index == IPSET_INVALID_ID) {
-			pr_warning("Cannot find add_set index %u as target\n",
-				   info->add_set.index);
+			pr_warn("Cannot find add_set index %u as target\n",
+				info->add_set.index);
 			return -ENOENT;
 		}
 	}
@@ -239,8 +237,8 @@
 	if (info->del_set.index != IPSET_INVALID_ID) {
 		index = ip_set_nfnl_get_byindex(par->net, info->del_set.index);
 		if (index == IPSET_INVALID_ID) {
-			pr_warning("Cannot find del_set index %u as target\n",
-				   info->del_set.index);
+			pr_warn("Cannot find del_set index %u as target\n",
+				info->del_set.index);
 			if (info->add_set.index != IPSET_INVALID_ID)
 				ip_set_nfnl_put(par->net, info->add_set.index);
 			return -ENOENT;
@@ -248,8 +246,7 @@
 	}
 	if (info->add_set.u.flags[IPSET_DIM_MAX-1] != 0 ||
 	    info->del_set.u.flags[IPSET_DIM_MAX-1] != 0) {
-		pr_warning("Protocol error: SET target dimension "
-			   "is over the limit!\n");
+		pr_warn("Protocol error: SET target dimension is over the limit!\n");
 		if (info->add_set.index != IPSET_INVALID_ID)
 			ip_set_nfnl_put(par->net, info->add_set.index);
 		if (info->del_set.index != IPSET_INVALID_ID)
@@ -303,8 +300,8 @@
 	if (info->add_set.index != IPSET_INVALID_ID) {
 		index = ip_set_nfnl_get_byindex(par->net, info->add_set.index);
 		if (index == IPSET_INVALID_ID) {
-			pr_warning("Cannot find add_set index %u as target\n",
-				   info->add_set.index);
+			pr_warn("Cannot find add_set index %u as target\n",
+				info->add_set.index);
 			return -ENOENT;
 		}
 	}
@@ -312,8 +309,8 @@
 	if (info->del_set.index != IPSET_INVALID_ID) {
 		index = ip_set_nfnl_get_byindex(par->net, info->del_set.index);
 		if (index == IPSET_INVALID_ID) {
-			pr_warning("Cannot find del_set index %u as target\n",
-				   info->del_set.index);
+			pr_warn("Cannot find del_set index %u as target\n",
+				info->del_set.index);
 			if (info->add_set.index != IPSET_INVALID_ID)
 				ip_set_nfnl_put(par->net, info->add_set.index);
 			return -ENOENT;
@@ -321,8 +318,7 @@
 	}
 	if (info->add_set.dim > IPSET_DIM_MAX ||
 	    info->del_set.dim > IPSET_DIM_MAX) {
-		pr_warning("Protocol error: SET target dimension "
-			   "is over the limit!\n");
+		pr_warn("Protocol error: SET target dimension is over the limit!\n");
 		if (info->add_set.index != IPSET_INVALID_ID)
 			ip_set_nfnl_put(par->net, info->add_set.index);
 		if (info->del_set.index != IPSET_INVALID_ID)
@@ -370,6 +366,140 @@
 #define set_target_v2_checkentry	set_target_v1_checkentry
 #define set_target_v2_destroy		set_target_v1_destroy
 
+/* Revision 3 target */
+
+static unsigned int
+set_target_v3(struct sk_buff *skb, const struct xt_action_param *par)
+{
+	const struct xt_set_info_target_v3 *info = par->targinfo;
+	ADT_OPT(add_opt, par->family, info->add_set.dim,
+		info->add_set.flags, info->flags, info->timeout);
+	ADT_OPT(del_opt, par->family, info->del_set.dim,
+		info->del_set.flags, 0, UINT_MAX);
+	ADT_OPT(map_opt, par->family, info->map_set.dim,
+		info->map_set.flags, 0, UINT_MAX);
+
+	int ret;
+
+	/* Normalize to fit into jiffies */
+	if (add_opt.ext.timeout != IPSET_NO_TIMEOUT &&
+	    add_opt.ext.timeout > UINT_MAX/MSEC_PER_SEC)
+		add_opt.ext.timeout = UINT_MAX/MSEC_PER_SEC;
+	if (info->add_set.index != IPSET_INVALID_ID)
+		ip_set_add(info->add_set.index, skb, par, &add_opt);
+	if (info->del_set.index != IPSET_INVALID_ID)
+		ip_set_del(info->del_set.index, skb, par, &del_opt);
+	if (info->map_set.index != IPSET_INVALID_ID) {
+		map_opt.cmdflags |= info->flags & (IPSET_FLAG_MAP_SKBMARK |
+						   IPSET_FLAG_MAP_SKBPRIO |
+						   IPSET_FLAG_MAP_SKBQUEUE);
+		ret = match_set(info->map_set.index, skb, par, &map_opt,
+				info->map_set.flags & IPSET_INV_MATCH);
+		if (!ret)
+			return XT_CONTINUE;
+		if (map_opt.cmdflags & IPSET_FLAG_MAP_SKBMARK)
+			skb->mark = (skb->mark & ~(map_opt.ext.skbmarkmask))
+				    ^ (map_opt.ext.skbmark);
+		if (map_opt.cmdflags & IPSET_FLAG_MAP_SKBPRIO)
+			skb->priority = map_opt.ext.skbprio;
+		if ((map_opt.cmdflags & IPSET_FLAG_MAP_SKBQUEUE) &&
+		    skb->dev &&
+		    skb->dev->real_num_tx_queues > map_opt.ext.skbqueue)
+			skb_set_queue_mapping(skb, map_opt.ext.skbqueue);
+	}
+	return XT_CONTINUE;
+}
+
+
+static int
+set_target_v3_checkentry(const struct xt_tgchk_param *par)
+{
+	const struct xt_set_info_target_v3 *info = par->targinfo;
+	ip_set_id_t index;
+
+	if (info->add_set.index != IPSET_INVALID_ID) {
+		index = ip_set_nfnl_get_byindex(par->net,
+						info->add_set.index);
+		if (index == IPSET_INVALID_ID) {
+			pr_warn("Cannot find add_set index %u as target\n",
+				info->add_set.index);
+			return -ENOENT;
+		}
+	}
+
+	if (info->del_set.index != IPSET_INVALID_ID) {
+		index = ip_set_nfnl_get_byindex(par->net,
+						info->del_set.index);
+		if (index == IPSET_INVALID_ID) {
+			pr_warn("Cannot find del_set index %u as target\n",
+				info->del_set.index);
+			if (info->add_set.index != IPSET_INVALID_ID)
+				ip_set_nfnl_put(par->net,
+						info->add_set.index);
+			return -ENOENT;
+		}
+	}
+
+	if (info->map_set.index != IPSET_INVALID_ID) {
+		if (strncmp(par->table, "mangle", 7)) {
+			pr_warn("--map-set only usable from mangle table\n");
+			return -EINVAL;
+		}
+		if (((info->flags & IPSET_FLAG_MAP_SKBPRIO) |
+		     (info->flags & IPSET_FLAG_MAP_SKBQUEUE)) &&
+		     !(par->hook_mask & (1 << NF_INET_FORWARD |
+					 1 << NF_INET_LOCAL_OUT |
+					 1 << NF_INET_POST_ROUTING))) {
+			pr_warn("mapping of prio or/and queue is allowed only"
+				"from OUTPUT/FORWARD/POSTROUTING chains\n");
+			return -EINVAL;
+		}
+		index = ip_set_nfnl_get_byindex(par->net,
+						info->map_set.index);
+		if (index == IPSET_INVALID_ID) {
+			pr_warn("Cannot find map_set index %u as target\n",
+				info->map_set.index);
+			if (info->add_set.index != IPSET_INVALID_ID)
+				ip_set_nfnl_put(par->net,
+						info->add_set.index);
+			if (info->del_set.index != IPSET_INVALID_ID)
+				ip_set_nfnl_put(par->net,
+						info->del_set.index);
+			return -ENOENT;
+		}
+	}
+
+	if (info->add_set.dim > IPSET_DIM_MAX ||
+	    info->del_set.dim > IPSET_DIM_MAX ||
+	    info->map_set.dim > IPSET_DIM_MAX) {
+		pr_warn("Protocol error: SET target dimension "
+			"is over the limit!\n");
+		if (info->add_set.index != IPSET_INVALID_ID)
+			ip_set_nfnl_put(par->net, info->add_set.index);
+		if (info->del_set.index != IPSET_INVALID_ID)
+			ip_set_nfnl_put(par->net, info->del_set.index);
+		if (info->map_set.index != IPSET_INVALID_ID)
+			ip_set_nfnl_put(par->net, info->map_set.index);
+		return -ERANGE;
+	}
+
+	return 0;
+}
+
+static void
+set_target_v3_destroy(const struct xt_tgdtor_param *par)
+{
+	const struct xt_set_info_target_v3 *info = par->targinfo;
+
+	if (info->add_set.index != IPSET_INVALID_ID)
+		ip_set_nfnl_put(par->net, info->add_set.index);
+	if (info->del_set.index != IPSET_INVALID_ID)
+		ip_set_nfnl_put(par->net, info->del_set.index);
+	if (info->map_set.index != IPSET_INVALID_ID)
+		ip_set_nfnl_put(par->net, info->map_set.index);
+}
+
+
 static struct xt_match set_matches[] __read_mostly = {
 	{
 		.name		= "set",
@@ -497,6 +627,27 @@
 		.destroy	= set_target_v2_destroy,
 		.me		= THIS_MODULE
 	},
+	/* --map-set support */
+	{
+		.name		= "SET",
+		.revision	= 3,
+		.family		= NFPROTO_IPV4,
+		.target		= set_target_v3,
+		.targetsize	= sizeof(struct xt_set_info_target_v3),
+		.checkentry	= set_target_v3_checkentry,
+		.destroy	= set_target_v3_destroy,
+		.me		= THIS_MODULE
+	},
+	{
+		.name		= "SET",
+		.revision	= 3,
+		.family		= NFPROTO_IPV6,
+		.target		= set_target_v3,
+		.targetsize	= sizeof(struct xt_set_info_target_v3),
+		.checkentry	= set_target_v3_checkentry,
+		.destroy	= set_target_v3_destroy,
+		.me		= THIS_MODULE
+	},
 };
 
 static int __init xt_set_init(void)
diff -urN linux/net/netfilter/xt_string.c net-next-2.6/net/netfilter/xt_string.c
--- linux/net/netfilter/xt_string.c	2011-07-22 09:59:45.593382318 +0200
+++ net-next-2.6/net/netfilter/xt_string.c	2014-10-06 10:49:04.176940666 +0200
@@ -29,7 +29,6 @@
 	struct ts_state state;
 	bool invert;
 
-	memset(&state, 0, sizeof(struct ts_state));
 	invert = conf->u.v1.flags & XT_STRING_FLAG_INVERT;
 
 	return (skb_find_text((struct sk_buff *)skb, conf->from_offset,
