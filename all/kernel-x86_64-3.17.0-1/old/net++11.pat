diff -urN linux/net/openvswitch/actions.c net-next-2.6/net/openvswitch/actions.c
--- linux/net/openvswitch/actions.c	2014-09-24 09:52:43.864651554 +0200
+++ net-next-2.6/net/openvswitch/actions.c	2014-10-06 10:49:04.204940952 +0200
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2007-2013 Nicira, Inc.
+ * Copyright (c) 2007-2014 Nicira, Inc.
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -35,11 +35,78 @@
 #include <net/sctp/checksum.h>
 
 #include "datapath.h"
+#include "flow.h"
 #include "vport.h"
 
 static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
+			      struct sw_flow_key *key,
 			      const struct nlattr *attr, int len);
 
+struct deferred_action {
+	struct sk_buff *skb;
+	const struct nlattr *actions;
+
+	/* Store pkt_key clone when creating deferred action. */
+	struct sw_flow_key pkt_key;
+};
+
+#define DEFERRED_ACTION_FIFO_SIZE 10
+struct action_fifo {
+	int head;
+	int tail;
+	/* Deferred action fifo queue storage. */
+	struct deferred_action fifo[DEFERRED_ACTION_FIFO_SIZE];
+};
+
+static struct action_fifo __percpu *action_fifos;
+static DEFINE_PER_CPU(int, exec_actions_level);
+
+static void action_fifo_init(struct action_fifo *fifo)
+{
+	fifo->head = 0;
+	fifo->tail = 0;
+}
+
+static bool action_fifo_is_empty(struct action_fifo *fifo)
+{
+	return (fifo->head == fifo->tail);
+}
+
+static struct deferred_action *action_fifo_get(struct action_fifo *fifo)
+{
+	if (action_fifo_is_empty(fifo))
+		return NULL;
+
+	return &fifo->fifo[fifo->tail++];
+}
+
+static struct deferred_action *action_fifo_put(struct action_fifo *fifo)
+{
+	if (fifo->head >= DEFERRED_ACTION_FIFO_SIZE - 1)
+		return NULL;
+
+	return &fifo->fifo[fifo->head++];
+}
+
+/* Return true if fifo is not full */
+static struct deferred_action *add_deferred_actions(struct sk_buff *skb,
+						    struct sw_flow_key *key,
+						    const struct nlattr *attr)
+{
+	struct action_fifo *fifo;
+	struct deferred_action *da;
+
+	fifo = this_cpu_ptr(action_fifos);
+	da = action_fifo_put(fifo);
+	if (da) {
+		da->skb = skb;
+		da->actions = attr;
+		da->pkt_key = *key;
+	}
+
+	return da;
+}
+
 static int make_writable(struct sk_buff *skb, int write_len)
 {
 	if (!pskb_may_pull(skb, write_len))
@@ -410,16 +477,14 @@
 }
 
 static int output_userspace(struct datapath *dp, struct sk_buff *skb,
-			    const struct nlattr *attr)
+			    struct sw_flow_key *key, const struct nlattr *attr)
 {
 	struct dp_upcall_info upcall;
 	const struct nlattr *a;
 	int rem;
 
-	BUG_ON(!OVS_CB(skb)->pkt_key);
-
 	upcall.cmd = OVS_PACKET_CMD_ACTION;
-	upcall.key = OVS_CB(skb)->pkt_key;
+	upcall.key = key;
 	upcall.userdata = NULL;
 	upcall.portid = 0;
 
@@ -445,11 +510,10 @@
 }
 
 static int sample(struct datapath *dp, struct sk_buff *skb,
-		  const struct nlattr *attr)
+		  struct sw_flow_key *key, const struct nlattr *attr)
 {
 	const struct nlattr *acts_list = NULL;
 	const struct nlattr *a;
-	struct sk_buff *sample_skb;
 	int rem;
 
 	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
@@ -469,31 +533,47 @@
 	rem = nla_len(acts_list);
 	a = nla_data(acts_list);
 
-	/* Actions list is either empty or only contains a single user-space
-	 * action, the latter being a special case as it is the only known
-	 * usage of the sample action.
-	 * In these special cases don't clone the skb as there are no
-	 * side-effects in the nested actions.
-	 * Otherwise, clone in case the nested actions have side effects.
+	/* Actions list is empty, do nothing */
+	if (unlikely(!rem))
+		return 0;
+
+	/* The only known usage of sample action is having a single user-space
+	 * action. Treat this usage as a special case.
+	 * The output_userspace() should clone the skb to be sent to the
+	 * user space. This skb will be consumed by its caller.
 	 */
-	if (likely(rem == 0 || (nla_type(a) == OVS_ACTION_ATTR_USERSPACE &&
-				last_action(a, rem)))) {
-		sample_skb = skb;
-		skb_get(skb);
-	} else {
-		sample_skb = skb_clone(skb, GFP_ATOMIC);
-		if (!sample_skb) /* Skip sample action when out of memory. */
-			return 0;
+	if (likely(nla_type(a) == OVS_ACTION_ATTR_USERSPACE &&
+		   last_action(a, rem)))
+		return output_userspace(dp, skb, key, a);
+
+	skb = skb_clone(skb, GFP_ATOMIC);
+	if (!skb)
+		/* Skip the sample action when out of memory. */
+		return 0;
+
+	if (!add_deferred_actions(skb, key, a)) {
+		if (net_ratelimit())
+			pr_warn("%s: deferred actions limit reached, dropping sample action\n",
+				ovs_dp_name(dp));
+
+		kfree_skb(skb);
 	}
+	return 0;
+}
 
-	/* Note that do_execute_actions() never consumes skb.
-	 * In the case where skb has been cloned above it is the clone that
-	 * is consumed.  Otherwise the skb_get(skb) call prevents
-	 * consumption by do_execute_actions(). Thus, it is safe to simply
-	 * return the error code and let the caller (also
-	 * do_execute_actions()) free skb on error.
-	 */
-	return do_execute_actions(dp, sample_skb, a, rem);
+static void execute_hash(struct sk_buff *skb, struct sw_flow_key *key,
+			 const struct nlattr *attr)
+{
+	struct ovs_action_hash *hash_act = nla_data(attr);
+	u32 hash = 0;
+
+	/* OVS_HASH_ALG_L4 is the only possible hash algorithm.  */
+	hash = skb_get_hash(skb);
+	hash = jhash_1word(hash, hash_act->hash_basis);
+	if (!hash)
+		hash = 0x1;
+
+	key->ovs_flow_hash = hash;
 }
 
 static int execute_set_action(struct sk_buff *skb,
@@ -510,8 +590,8 @@
 		skb->mark = nla_get_u32(nested_attr);
 		break;
 
-	case OVS_KEY_ATTR_IPV4_TUNNEL:
-		OVS_CB(skb)->tun_key = nla_data(nested_attr);
+	case OVS_KEY_ATTR_TUNNEL_INFO:
+		OVS_CB(skb)->egress_tun_info = nla_data(nested_attr);
 		break;
 
 	case OVS_KEY_ATTR_ETHERNET:
@@ -542,8 +622,47 @@
 	return err;
 }
 
+static int execute_recirc(struct datapath *dp, struct sk_buff *skb,
+			  struct sw_flow_key *key,
+			  const struct nlattr *a, int rem)
+{
+	struct deferred_action *da;
+	int err;
+
+	err = ovs_flow_key_update(skb, key);
+	if (err)
+		return err;
+
+	if (!last_action(a, rem)) {
+		/* Recirc action is the not the last action
+		 * of the action list, need to clone the skb.
+		 */
+		skb = skb_clone(skb, GFP_ATOMIC);
+
+		/* Skip the recirc action when out of memory, but
+		 * continue on with the rest of the action list.
+		 */
+		if (!skb)
+			return 0;
+	}
+
+	da = add_deferred_actions(skb, key, NULL);
+	if (da) {
+		da->pkt_key.recirc_id = nla_get_u32(a);
+	} else {
+		kfree_skb(skb);
+
+		if (net_ratelimit())
+			pr_warn("%s: deferred action limit reached, drop recirc action\n",
+				ovs_dp_name(dp));
+	}
+
+	return 0;
+}
+
 /* Execute a list of actions against 'skb'. */
 static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
+			      struct sw_flow_key *key,
 			      const struct nlattr *attr, int len)
 {
 	/* Every output action needs a separate clone of 'skb', but the common
@@ -569,7 +688,11 @@
 			break;
 
 		case OVS_ACTION_ATTR_USERSPACE:
-			output_userspace(dp, skb, a);
+			output_userspace(dp, skb, key, a);
+			break;
+
+		case OVS_ACTION_ATTR_HASH:
+			execute_hash(skb, key, a);
 			break;
 
 		case OVS_ACTION_ATTR_PUSH_VLAN:
@@ -582,12 +705,23 @@
 			err = pop_vlan(skb);
 			break;
 
+		case OVS_ACTION_ATTR_RECIRC:
+			err = execute_recirc(dp, skb, key, a, rem);
+			if (last_action(a, rem)) {
+				/* If this is the last action, the skb has
+				 * been consumed or freed.
+				 * Return immediately.
+				 */
+				return err;
+			}
+			break;
+
 		case OVS_ACTION_ATTR_SET:
 			err = execute_set_action(skb, nla_data(a));
 			break;
 
 		case OVS_ACTION_ATTR_SAMPLE:
-			err = sample(dp, skb, a);
+			err = sample(dp, skb, key, a);
 			if (unlikely(err)) /* skb already freed. */
 				return err;
 			break;
@@ -607,11 +741,64 @@
 	return 0;
 }
 
+static void process_deferred_actions(struct datapath *dp)
+{
+	struct action_fifo *fifo = this_cpu_ptr(action_fifos);
+
+	/* Do not touch the FIFO in case there is no deferred actions. */
+	if (action_fifo_is_empty(fifo))
+		return;
+
+	/* Finishing executing all deferred actions. */
+	do {
+		struct deferred_action *da = action_fifo_get(fifo);
+		struct sk_buff *skb = da->skb;
+		struct sw_flow_key *key = &da->pkt_key;
+		const struct nlattr *actions = da->actions;
+
+		if (actions)
+			do_execute_actions(dp, skb, key, actions,
+					   nla_len(actions));
+		else
+			ovs_dp_process_packet(skb, key);
+	} while (!action_fifo_is_empty(fifo));
+
+	/* Reset FIFO for the next packet.  */
+	action_fifo_init(fifo);
+}
+
 /* Execute a list of actions against 'skb'. */
-int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb)
+int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb,
+			struct sw_flow_key *key)
+{
+	int level = this_cpu_read(exec_actions_level);
+	struct sw_flow_actions *acts;
+	int err;
+
+	acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);
+
+	this_cpu_inc(exec_actions_level);
+	OVS_CB(skb)->egress_tun_info = NULL;
+	err = do_execute_actions(dp, skb, key,
+				 acts->actions, acts->actions_len);
+
+	if (!level)
+		process_deferred_actions(dp);
+
+	this_cpu_dec(exec_actions_level);
+	return err;
+}
+
+int action_fifos_init(void)
 {
-	struct sw_flow_actions *acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);
+	action_fifos = alloc_percpu(struct action_fifo);
+	if (!action_fifos)
+		return -ENOMEM;
 
-	OVS_CB(skb)->tun_key = NULL;
-	return do_execute_actions(dp, skb, acts->actions, acts->actions_len);
+	return 0;
+}
+
+void action_fifos_exit(void)
+{
+	free_percpu(action_fifos);
 }
diff -urN linux/net/openvswitch/datapath.c net-next-2.6/net/openvswitch/datapath.c
--- linux/net/openvswitch/datapath.c	2014-09-24 09:52:43.864651554 +0200
+++ net-next-2.6/net/openvswitch/datapath.c	2014-10-06 10:49:04.204940952 +0200
@@ -157,7 +157,7 @@
 }
 
 /* Must be called with rcu_read_lock or ovs_mutex. */
-static const char *ovs_dp_name(const struct datapath *dp)
+const char *ovs_dp_name(const struct datapath *dp)
 {
 	struct vport *vport = ovs_vport_ovsl_rcu(dp, OVSP_LOCAL);
 	return vport->ops->get_name(vport);
@@ -238,32 +238,25 @@
 }
 
 /* Must be called with rcu_read_lock. */
-void ovs_dp_process_received_packet(struct vport *p, struct sk_buff *skb)
+void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key)
 {
+	const struct vport *p = OVS_CB(skb)->input_vport;
 	struct datapath *dp = p->dp;
 	struct sw_flow *flow;
 	struct dp_stats_percpu *stats;
-	struct sw_flow_key key;
 	u64 *stats_counter;
 	u32 n_mask_hit;
-	int error;
 
 	stats = this_cpu_ptr(dp->stats_percpu);
 
-	/* Extract flow from 'skb' into 'key'. */
-	error = ovs_flow_extract(skb, p->port_no, &key);
-	if (unlikely(error)) {
-		kfree_skb(skb);
-		return;
-	}
-
 	/* Look up flow. */
-	flow = ovs_flow_tbl_lookup_stats(&dp->table, &key, &n_mask_hit);
+	flow = ovs_flow_tbl_lookup_stats(&dp->table, key, &n_mask_hit);
 	if (unlikely(!flow)) {
 		struct dp_upcall_info upcall;
+		int error;
 
 		upcall.cmd = OVS_PACKET_CMD_MISS;
-		upcall.key = &key;
+		upcall.key = key;
 		upcall.userdata = NULL;
 		upcall.portid = ovs_vport_find_upcall_portid(p, skb);
 		error = ovs_dp_upcall(dp, skb, &upcall);
@@ -276,10 +269,9 @@
 	}
 
 	OVS_CB(skb)->flow = flow;
-	OVS_CB(skb)->pkt_key = &key;
 
-	ovs_flow_stats_update(OVS_CB(skb)->flow, key.tp.flags, skb);
-	ovs_execute_actions(dp, skb);
+	ovs_flow_stats_update(OVS_CB(skb)->flow, key->tp.flags, skb);
+	ovs_execute_actions(dp, skb, key);
 	stats_counter = &stats->n_hit;
 
 out:
@@ -377,6 +369,8 @@
 		  + nla_total_size(1)   /* OVS_TUNNEL_KEY_ATTR_TTL */
 		  + nla_total_size(0)   /* OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT */
 		  + nla_total_size(0)   /* OVS_TUNNEL_KEY_ATTR_CSUM */
+		  + nla_total_size(0)   /* OVS_TUNNEL_KEY_ATTR_OAM */
+		  + nla_total_size(256)   /* OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS */
 		+ nla_total_size(4)   /* OVS_KEY_ATTR_IN_PORT */
 		+ nla_total_size(4)   /* OVS_KEY_ATTR_SKB_MARK */
 		+ nla_total_size(12)  /* OVS_KEY_ATTR_ETHERNET */
@@ -516,6 +510,7 @@
 	struct sw_flow *flow;
 	struct datapath *dp;
 	struct ethhdr *eth;
+	struct vport *input_vport;
 	int len;
 	int err;
 
@@ -550,13 +545,11 @@
 	if (IS_ERR(flow))
 		goto err_kfree_skb;
 
-	err = ovs_flow_extract(packet, -1, &flow->key);
+	err = ovs_flow_key_extract_userspace(a[OVS_PACKET_ATTR_KEY], packet,
+					     &flow->key);
 	if (err)
 		goto err_flow_free;
 
-	err = ovs_nla_get_flow_metadata(flow, a[OVS_PACKET_ATTR_KEY]);
-	if (err)
-		goto err_flow_free;
 	acts = ovs_nla_alloc_flow_actions(nla_len(a[OVS_PACKET_ATTR_ACTIONS]));
 	err = PTR_ERR(acts);
 	if (IS_ERR(acts))
@@ -564,12 +557,13 @@
 
 	err = ovs_nla_copy_actions(a[OVS_PACKET_ATTR_ACTIONS],
 				   &flow->key, 0, &acts);
-	rcu_assign_pointer(flow->sf_acts, acts);
 	if (err)
 		goto err_flow_free;
 
+	rcu_assign_pointer(flow->sf_acts, acts);
+
+	OVS_CB(packet)->egress_tun_info = NULL;
 	OVS_CB(packet)->flow = flow;
-	OVS_CB(packet)->pkt_key = &flow->key;
 	packet->priority = flow->key.phy.priority;
 	packet->mark = flow->key.phy.skb_mark;
 
@@ -579,8 +573,17 @@
 	if (!dp)
 		goto err_unlock;
 
+	input_vport = ovs_vport_rcu(dp, flow->key.phy.in_port);
+	if (!input_vport)
+		input_vport = ovs_vport_rcu(dp, OVSP_LOCAL);
+
+	if (!input_vport)
+		goto err_unlock;
+
+	OVS_CB(packet)->input_vport = input_vport;
+
 	local_bh_disable();
-	err = ovs_execute_actions(dp, packet);
+	err = ovs_execute_actions(dp, packet, &flow->key);
 	local_bh_enable();
 	rcu_read_unlock();
 
@@ -933,11 +936,34 @@
 	return error;
 }
 
+static struct sw_flow_actions *get_flow_actions(const struct nlattr *a,
+						const struct sw_flow_key *key,
+						const struct sw_flow_mask *mask)
+{
+	struct sw_flow_actions *acts;
+	struct sw_flow_key masked_key;
+	int error;
+
+	acts = ovs_nla_alloc_flow_actions(nla_len(a));
+	if (IS_ERR(acts))
+		return acts;
+
+	ovs_flow_mask_key(&masked_key, key, mask);
+	error = ovs_nla_copy_actions(a, &masked_key, 0, &acts);
+	if (error) {
+		OVS_NLERR("Flow actions may not be safe on all matching packets.\n");
+		kfree(acts);
+		return ERR_PTR(error);
+	}
+
+	return acts;
+}
+
 static int ovs_flow_cmd_set(struct sk_buff *skb, struct genl_info *info)
 {
 	struct nlattr **a = info->attrs;
 	struct ovs_header *ovs_header = info->userhdr;
-	struct sw_flow_key key, masked_key;
+	struct sw_flow_key key;
 	struct sw_flow *flow;
 	struct sw_flow_mask mask;
 	struct sk_buff *reply = NULL;
@@ -959,17 +985,10 @@
 
 	/* Validate actions. */
 	if (a[OVS_FLOW_ATTR_ACTIONS]) {
-		acts = ovs_nla_alloc_flow_actions(nla_len(a[OVS_FLOW_ATTR_ACTIONS]));
-		error = PTR_ERR(acts);
-		if (IS_ERR(acts))
+		acts = get_flow_actions(a[OVS_FLOW_ATTR_ACTIONS], &key, &mask);
+		if (IS_ERR(acts)) {
+			error = PTR_ERR(acts);
 			goto error;
-
-		ovs_flow_mask_key(&masked_key, &key, &mask);
-		error = ovs_nla_copy_actions(a[OVS_FLOW_ATTR_ACTIONS],
-					     &masked_key, 0, &acts);
-		if (error) {
-			OVS_NLERR("Flow actions may not be safe on all matching packets.\n");
-			goto err_kfree_acts;
 		}
 	}
 
@@ -2067,10 +2086,14 @@
 
 	pr_info("Open vSwitch switching datapath\n");
 
-	err = ovs_internal_dev_rtnl_link_register();
+	err = action_fifos_init();
 	if (err)
 		goto error;
 
+	err = ovs_internal_dev_rtnl_link_register();
+	if (err)
+		goto error_action_fifos_exit;
+
 	err = ovs_flow_init();
 	if (err)
 		goto error_unreg_rtnl_link;
@@ -2103,6 +2126,8 @@
 	ovs_flow_exit();
 error_unreg_rtnl_link:
 	ovs_internal_dev_rtnl_link_unregister();
+error_action_fifos_exit:
+	action_fifos_exit();
 error:
 	return err;
 }
@@ -2116,6 +2141,7 @@
 	ovs_vport_exit();
 	ovs_flow_exit();
 	ovs_internal_dev_rtnl_link_unregister();
+	action_fifos_exit();
 }
 
 module_init(dp_init);
diff -urN linux/net/openvswitch/datapath.h net-next-2.6/net/openvswitch/datapath.h
--- linux/net/openvswitch/datapath.h	2014-09-24 09:52:43.864651554 +0200
+++ net-next-2.6/net/openvswitch/datapath.h	2014-10-06 10:49:04.208940992 +0200
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2007-2012 Nicira, Inc.
+ * Copyright (c) 2007-2014 Nicira, Inc.
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -95,14 +95,15 @@
 /**
  * struct ovs_skb_cb - OVS data in skb CB
  * @flow: The flow associated with this packet.  May be %NULL if no flow.
- * @pkt_key: The flow information extracted from the packet.  Must be nonnull.
- * @tun_key: Key for the tunnel that encapsulated this packet. NULL if the
- * packet is not being tunneled.
+ * @egress_tun_key: Tunnel information about this packet on egress path.
+ * NULL if the packet is not being tunneled.
+ * @input_vport: The original vport packet came in on. This value is cached
+ * when a packet is received by OVS.
  */
 struct ovs_skb_cb {
 	struct sw_flow		*flow;
-	struct sw_flow_key	*pkt_key;
-	struct ovs_key_ipv4_tunnel  *tun_key;
+	struct ovs_tunnel_info  *egress_tun_info;
+	struct vport		*input_vport;
 };
 #define OVS_CB(skb) ((struct ovs_skb_cb *)(skb)->cb)
 
@@ -183,17 +184,23 @@
 extern struct notifier_block ovs_dp_device_notifier;
 extern struct genl_family dp_vport_genl_family;
 
-void ovs_dp_process_received_packet(struct vport *, struct sk_buff *);
+void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key);
 void ovs_dp_detach_port(struct vport *);
 int ovs_dp_upcall(struct datapath *, struct sk_buff *,
 		  const struct dp_upcall_info *);
 
+const char *ovs_dp_name(const struct datapath *dp);
 struct sk_buff *ovs_vport_cmd_build_info(struct vport *, u32 pid, u32 seq,
 					 u8 cmd);
 
-int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb);
+int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb,
+			struct sw_flow_key *);
+
 void ovs_dp_notify_wq(struct work_struct *work);
 
+int action_fifos_init(void);
+void action_fifos_exit(void);
+
 #define OVS_NLERR(fmt, ...)					\
 do {								\
 	if (net_ratelimit())					\
diff -urN linux/net/openvswitch/flow.c net-next-2.6/net/openvswitch/flow.c
--- linux/net/openvswitch/flow.c	2014-09-24 09:52:43.864651554 +0200
+++ net-next-2.6/net/openvswitch/flow.c	2014-10-06 10:49:04.208940992 +0200
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2007-2013 Nicira, Inc.
+ * Copyright (c) 2007-2014 Nicira, Inc.
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -16,8 +16,6 @@
  * 02110-1301, USA
  */
 
-#include "flow.h"
-#include "datapath.h"
 #include <linux/uaccess.h>
 #include <linux/netdevice.h>
 #include <linux/etherdevice.h>
@@ -46,6 +44,10 @@
 #include <net/ipv6.h>
 #include <net/ndisc.h>
 
+#include "datapath.h"
+#include "flow.h"
+#include "flow_netlink.h"
+
 u64 ovs_flow_used_time(unsigned long flow_jiffies)
 {
 	struct timespec cur_ts;
@@ -89,7 +91,7 @@
 			 * allocated stats as we have already locked them.
 			 */
 			if (likely(flow->stats_last_writer != NUMA_NO_NODE)
-			    && likely(!rcu_dereference(flow->stats[node]))) {
+			    && likely(!rcu_access_pointer(flow->stats[node]))) {
 				/* Try to allocate node-specific stats. */
 				struct flow_stats *new_stats;
 
@@ -420,10 +422,9 @@
 }
 
 /**
- * ovs_flow_extract - extracts a flow key from an Ethernet frame.
+ * key_extract - extracts a flow key from an Ethernet frame.
  * @skb: sk_buff that contains the frame, with skb->data pointing to the
  * Ethernet header
- * @in_port: port number on which @skb was received.
  * @key: output flow key
  *
  * The caller must ensure that skb->len >= ETH_HLEN.
@@ -442,18 +443,13 @@
  *      of a correct length, otherwise the same as skb->network_header.
  *      For other key->eth.type values it is left untouched.
  */
-int ovs_flow_extract(struct sk_buff *skb, u16 in_port, struct sw_flow_key *key)
+static int key_extract(struct sk_buff *skb, struct sw_flow_key *key)
 {
 	int error;
 	struct ethhdr *eth;
 
-	memset(key, 0, sizeof(*key));
-
-	key->phy.priority = skb->priority;
-	if (OVS_CB(skb)->tun_key)
-		memcpy(&key->tun_key, OVS_CB(skb)->tun_key, sizeof(key->tun_key));
-	key->phy.in_port = in_port;
-	key->phy.skb_mark = skb->mark;
+	/* Flags are always used as part of stats */
+	key->tp.flags = 0;
 
 	skb_reset_mac_header(skb);
 
@@ -469,6 +465,7 @@
 	 * update skb->csum here.
 	 */
 
+	key->eth.tci = 0;
 	if (vlan_tx_tag_present(skb))
 		key->eth.tci = htons(skb->vlan_tci);
 	else if (eth->h_proto == htons(ETH_P_8021Q))
@@ -489,6 +486,8 @@
 
 		error = check_iphdr(skb);
 		if (unlikely(error)) {
+			memset(&key->ip, 0, sizeof(key->ip));
+			memset(&key->ipv4, 0, sizeof(key->ipv4));
 			if (error == -EINVAL) {
 				skb->transport_header = skb->network_header;
 				error = 0;
@@ -510,8 +509,10 @@
 			return 0;
 		}
 		if (nh->frag_off & htons(IP_MF) ||
-			 skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
+			skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
 			key->ip.frag = OVS_FRAG_TYPE_FIRST;
+		else
+			key->ip.frag = OVS_FRAG_TYPE_NONE;
 
 		/* Transport layer. */
 		if (key->ip.proto == IPPROTO_TCP) {
@@ -520,18 +521,25 @@
 				key->tp.src = tcp->source;
 				key->tp.dst = tcp->dest;
 				key->tp.flags = TCP_FLAGS_BE16(tcp);
+			} else {
+				memset(&key->tp, 0, sizeof(key->tp));
 			}
+
 		} else if (key->ip.proto == IPPROTO_UDP) {
 			if (udphdr_ok(skb)) {
 				struct udphdr *udp = udp_hdr(skb);
 				key->tp.src = udp->source;
 				key->tp.dst = udp->dest;
+			} else {
+				memset(&key->tp, 0, sizeof(key->tp));
 			}
 		} else if (key->ip.proto == IPPROTO_SCTP) {
 			if (sctphdr_ok(skb)) {
 				struct sctphdr *sctp = sctp_hdr(skb);
 				key->tp.src = sctp->source;
 				key->tp.dst = sctp->dest;
+			} else {
+				memset(&key->tp, 0, sizeof(key->tp));
 			}
 		} else if (key->ip.proto == IPPROTO_ICMP) {
 			if (icmphdr_ok(skb)) {
@@ -541,33 +549,44 @@
 				 * them in 16-bit network byte order. */
 				key->tp.src = htons(icmp->type);
 				key->tp.dst = htons(icmp->code);
+			} else {
+				memset(&key->tp, 0, sizeof(key->tp));
 			}
 		}
 
-	} else if ((key->eth.type == htons(ETH_P_ARP) ||
-		   key->eth.type == htons(ETH_P_RARP)) && arphdr_ok(skb)) {
+	} else if (key->eth.type == htons(ETH_P_ARP) ||
+		   key->eth.type == htons(ETH_P_RARP)) {
 		struct arp_eth_header *arp;
 
 		arp = (struct arp_eth_header *)skb_network_header(skb);
 
-		if (arp->ar_hrd == htons(ARPHRD_ETHER)
-				&& arp->ar_pro == htons(ETH_P_IP)
-				&& arp->ar_hln == ETH_ALEN
-				&& arp->ar_pln == 4) {
+		if (arphdr_ok(skb) &&
+		    arp->ar_hrd == htons(ARPHRD_ETHER) &&
+		    arp->ar_pro == htons(ETH_P_IP) &&
+		    arp->ar_hln == ETH_ALEN &&
+		    arp->ar_pln == 4) {
 
 			/* We only match on the lower 8 bits of the opcode. */
 			if (ntohs(arp->ar_op) <= 0xff)
 				key->ip.proto = ntohs(arp->ar_op);
+			else
+				key->ip.proto = 0;
+
 			memcpy(&key->ipv4.addr.src, arp->ar_sip, sizeof(key->ipv4.addr.src));
 			memcpy(&key->ipv4.addr.dst, arp->ar_tip, sizeof(key->ipv4.addr.dst));
 			ether_addr_copy(key->ipv4.arp.sha, arp->ar_sha);
 			ether_addr_copy(key->ipv4.arp.tha, arp->ar_tha);
+		} else {
+			memset(&key->ip, 0, sizeof(key->ip));
+			memset(&key->ipv4, 0, sizeof(key->ipv4));
 		}
 	} else if (key->eth.type == htons(ETH_P_IPV6)) {
 		int nh_len;             /* IPv6 Header + Extensions */
 
 		nh_len = parse_ipv6hdr(skb, key);
 		if (unlikely(nh_len < 0)) {
+			memset(&key->ip, 0, sizeof(key->ip));
+			memset(&key->ipv6.addr, 0, sizeof(key->ipv6.addr));
 			if (nh_len == -EINVAL) {
 				skb->transport_header = skb->network_header;
 				error = 0;
@@ -589,27 +608,87 @@
 				key->tp.src = tcp->source;
 				key->tp.dst = tcp->dest;
 				key->tp.flags = TCP_FLAGS_BE16(tcp);
+			} else {
+				memset(&key->tp, 0, sizeof(key->tp));
 			}
 		} else if (key->ip.proto == NEXTHDR_UDP) {
 			if (udphdr_ok(skb)) {
 				struct udphdr *udp = udp_hdr(skb);
 				key->tp.src = udp->source;
 				key->tp.dst = udp->dest;
+			} else {
+				memset(&key->tp, 0, sizeof(key->tp));
 			}
 		} else if (key->ip.proto == NEXTHDR_SCTP) {
 			if (sctphdr_ok(skb)) {
 				struct sctphdr *sctp = sctp_hdr(skb);
 				key->tp.src = sctp->source;
 				key->tp.dst = sctp->dest;
+			} else {
+				memset(&key->tp, 0, sizeof(key->tp));
 			}
 		} else if (key->ip.proto == NEXTHDR_ICMP) {
 			if (icmp6hdr_ok(skb)) {
 				error = parse_icmpv6(skb, key, nh_len);
 				if (error)
 					return error;
+			} else {
+				memset(&key->tp, 0, sizeof(key->tp));
 			}
 		}
 	}
-
 	return 0;
 }
+
+int ovs_flow_key_update(struct sk_buff *skb, struct sw_flow_key *key)
+{
+	return key_extract(skb, key);
+}
+
+int ovs_flow_key_extract(struct ovs_tunnel_info *tun_info,
+			 struct sk_buff *skb, struct sw_flow_key *key)
+{
+	/* Extract metadata from packet. */
+	if (tun_info) {
+		memcpy(&key->tun_key, &tun_info->tunnel, sizeof(key->tun_key));
+
+		if (tun_info->options) {
+			BUILD_BUG_ON((1 << (sizeof(tun_info->options_len) *
+						   8)) - 1
+					> sizeof(key->tun_opts));
+			memcpy(GENEVE_OPTS(key, tun_info->options_len),
+			       tun_info->options, tun_info->options_len);
+			key->tun_opts_len = tun_info->options_len;
+		} else {
+			key->tun_opts_len = 0;
+		}
+	} else  {
+		key->tun_opts_len = 0;
+		memset(&key->tun_key, 0, sizeof(key->tun_key));
+	}
+
+	key->phy.priority = skb->priority;
+	key->phy.in_port = OVS_CB(skb)->input_vport->port_no;
+	key->phy.skb_mark = skb->mark;
+	key->ovs_flow_hash = 0;
+	key->recirc_id = 0;
+
+	/* Flags are always used as part of stats */
+	key->tp.flags = 0;
+
+	return key_extract(skb, key);
+}
+
+int ovs_flow_key_extract_userspace(const struct nlattr *attr,
+				   struct sk_buff *skb,
+				   struct sw_flow_key *key)
+{
+	int err;
+
+	/* Extract metadata from netlink attributes. */
+	err = ovs_nla_get_flow_metadata(attr, key);
+	if (err)
+		return err;
+
+	return key_extract(skb, key);
+}
diff -urN linux/net/openvswitch/flow.h net-next-2.6/net/openvswitch/flow.h
--- linux/net/openvswitch/flow.h	2014-09-24 09:52:43.864651554 +0200
+++ net-next-2.6/net/openvswitch/flow.h	2014-10-06 10:49:04.208940992 +0200
@@ -49,29 +49,53 @@
 	u8   ipv4_ttl;
 } __packed __aligned(4); /* Minimize padding. */
 
-static inline void ovs_flow_tun_key_init(struct ovs_key_ipv4_tunnel *tun_key,
-					 const struct iphdr *iph, __be64 tun_id,
-					 __be16 tun_flags)
+struct ovs_tunnel_info {
+	struct ovs_key_ipv4_tunnel tunnel;
+	struct geneve_opt *options;
+	u8 options_len;
+};
+
+/* Store options at the end of the array if they are less than the
+ * maximum size. This allows us to get the benefits of variable length
+ * matching for small options.
+ */
+#define GENEVE_OPTS(flow_key, opt_len)	\
+	((struct geneve_opt *)((flow_key)->tun_opts + \
+			       FIELD_SIZEOF(struct sw_flow_key, tun_opts) - \
+			       opt_len))
+
+static inline void ovs_flow_tun_info_init(struct ovs_tunnel_info *tun_info,
+					  const struct iphdr *iph,
+					  __be64 tun_id, __be16 tun_flags,
+					  struct geneve_opt *opts,
+					  u8 opts_len)
 {
-	tun_key->tun_id = tun_id;
-	tun_key->ipv4_src = iph->saddr;
-	tun_key->ipv4_dst = iph->daddr;
-	tun_key->ipv4_tos = iph->tos;
-	tun_key->ipv4_ttl = iph->ttl;
-	tun_key->tun_flags = tun_flags;
+	tun_info->tunnel.tun_id = tun_id;
+	tun_info->tunnel.ipv4_src = iph->saddr;
+	tun_info->tunnel.ipv4_dst = iph->daddr;
+	tun_info->tunnel.ipv4_tos = iph->tos;
+	tun_info->tunnel.ipv4_ttl = iph->ttl;
+	tun_info->tunnel.tun_flags = tun_flags;
 
 	/* clear struct padding. */
-	memset((unsigned char *) tun_key + OVS_TUNNEL_KEY_SIZE, 0,
-	       sizeof(*tun_key) - OVS_TUNNEL_KEY_SIZE);
+	memset((unsigned char *)&tun_info->tunnel + OVS_TUNNEL_KEY_SIZE, 0,
+	       sizeof(tun_info->tunnel) - OVS_TUNNEL_KEY_SIZE);
+
+	tun_info->options = opts;
+	tun_info->options_len = opts_len;
 }
 
 struct sw_flow_key {
+	u8 tun_opts[255];
+	u8 tun_opts_len;
 	struct ovs_key_ipv4_tunnel tun_key;  /* Encapsulating tunnel key. */
 	struct {
 		u32	priority;	/* Packet QoS priority. */
 		u32	skb_mark;	/* SKB mark. */
 		u16	in_port;	/* Input switch port (or DP_MAX_PORTS). */
 	} __packed phy; /* Safe when right after 'tun_key'. */
+	u32 ovs_flow_hash;		/* Datapath computed hash value.  */
+	u32 recirc_id;			/* Recirculation ID.  */
 	struct {
 		u8     src[ETH_ALEN];	/* Ethernet source address. */
 		u8     dst[ETH_ALEN];	/* Ethernet destination address. */
@@ -187,6 +211,12 @@
 void ovs_flow_stats_clear(struct sw_flow *);
 u64 ovs_flow_used_time(unsigned long flow_jiffies);
 
-int ovs_flow_extract(struct sk_buff *, u16 in_port, struct sw_flow_key *);
+int ovs_flow_key_update(struct sk_buff *skb, struct sw_flow_key *key);
+int ovs_flow_key_extract(struct ovs_tunnel_info *tun_info, struct sk_buff *skb,
+			 struct sw_flow_key *key);
+/* Extract key from packet coming from userspace. */
+int ovs_flow_key_extract_userspace(const struct nlattr *attr,
+				   struct sk_buff *skb,
+				   struct sw_flow_key *key);
 
 #endif /* flow.h */
diff -urN linux/net/openvswitch/flow_netlink.c net-next-2.6/net/openvswitch/flow_netlink.c
--- linux/net/openvswitch/flow_netlink.c	2014-09-24 09:52:43.864651554 +0200
+++ net-next-2.6/net/openvswitch/flow_netlink.c	2014-10-06 10:49:04.208940992 +0200
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2007-2013 Nicira, Inc.
+ * Copyright (c) 2007-2014 Nicira, Inc.
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -42,6 +42,7 @@
 #include <linux/icmp.h>
 #include <linux/icmpv6.h>
 #include <linux/rculist.h>
+#include <net/geneve.h>
 #include <net/ip.h>
 #include <net/ipv6.h>
 #include <net/ndisc.h>
@@ -88,18 +89,20 @@
 		}                                                           \
 	} while (0)
 
-#define SW_FLOW_KEY_MEMCPY(match, field, value_p, len, is_mask) \
-	do { \
-		update_range__(match, offsetof(struct sw_flow_key, field),  \
-				len, is_mask);                              \
-		if (is_mask) {						    \
-			if ((match)->mask)				    \
-				memcpy(&(match)->mask->key.field, value_p, len);\
-		} else {                                                    \
-			memcpy(&(match)->key->field, value_p, len);         \
-		}                                                           \
+#define SW_FLOW_KEY_MEMCPY_OFFSET(match, offset, value_p, len, is_mask)	    \
+	do {								    \
+		update_range__(match, offset, len, is_mask);		    \
+		if (is_mask)						    \
+			memcpy((u8 *)&(match)->mask->key + offset, value_p, \
+			       len);					    \
+		else							    \
+			memcpy((u8 *)(match)->key + offset, value_p, len);  \
 	} while (0)
 
+#define SW_FLOW_KEY_MEMCPY(match, field, value_p, len, is_mask)		      \
+	SW_FLOW_KEY_MEMCPY_OFFSET(match, offsetof(struct sw_flow_key, field), \
+				  value_p, len, is_mask)
+
 static u16 range_n_bytes(const struct sw_flow_key_range *range)
 {
 	return range->end - range->start;
@@ -251,6 +254,8 @@
 	[OVS_KEY_ATTR_ICMPV6] = sizeof(struct ovs_key_icmpv6),
 	[OVS_KEY_ATTR_ARP] = sizeof(struct ovs_key_arp),
 	[OVS_KEY_ATTR_ND] = sizeof(struct ovs_key_nd),
+	[OVS_KEY_ATTR_RECIRC_ID] = sizeof(u32),
+	[OVS_KEY_ATTR_DP_HASH] = sizeof(u32),
 	[OVS_KEY_ATTR_TUNNEL] = -1,
 };
 
@@ -333,6 +338,7 @@
 	int rem;
 	bool ttl = false;
 	__be16 tun_flags = 0;
+	unsigned long opt_key_offset;
 
 	nla_for_each_nested(a, attr, rem) {
 		int type = nla_type(a);
@@ -344,6 +350,8 @@
 			[OVS_TUNNEL_KEY_ATTR_TTL] = 1,
 			[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = 0,
 			[OVS_TUNNEL_KEY_ATTR_CSUM] = 0,
+			[OVS_TUNNEL_KEY_ATTR_OAM] = 0,
+			[OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS] = -1,
 		};
 
 		if (type > OVS_TUNNEL_KEY_ATTR_MAX) {
@@ -352,7 +360,8 @@
 			return -EINVAL;
 		}
 
-		if (ovs_tunnel_key_lens[type] != nla_len(a)) {
+		if (ovs_tunnel_key_lens[type] != nla_len(a) &&
+		    ovs_tunnel_key_lens[type] != -1) {
 			OVS_NLERR("IPv4 tunnel attribute type has unexpected "
 				  " length (type=%d, length=%d, expected=%d).\n",
 				  type, nla_len(a), ovs_tunnel_key_lens[type]);
@@ -388,7 +397,63 @@
 		case OVS_TUNNEL_KEY_ATTR_CSUM:
 			tun_flags |= TUNNEL_CSUM;
 			break;
+		case OVS_TUNNEL_KEY_ATTR_OAM:
+			tun_flags |= TUNNEL_OAM;
+			break;
+		case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
+			tun_flags |= TUNNEL_OPTIONS_PRESENT;
+			if (nla_len(a) > sizeof(match->key->tun_opts)) {
+				OVS_NLERR("Geneve option length exceeds maximum size (len %d, max %zu).\n",
+					  nla_len(a),
+					  sizeof(match->key->tun_opts));
+				return -EINVAL;
+			}
+
+			if (nla_len(a) % 4 != 0) {
+				OVS_NLERR("Geneve option length is not a multiple of 4 (len %d).\n",
+					  nla_len(a));
+				return -EINVAL;
+			}
+
+			/* We need to record the length of the options passed
+			 * down, otherwise packets with the same format but
+			 * additional options will be silently matched.
+			 */
+			if (!is_mask) {
+				SW_FLOW_KEY_PUT(match, tun_opts_len, nla_len(a),
+						false);
+			} else {
+				/* This is somewhat unusual because it looks at
+				 * both the key and mask while parsing the
+				 * attributes (and by extension assumes the key
+				 * is parsed first). Normally, we would verify
+				 * that each is the correct length and that the
+				 * attributes line up in the validate function.
+				 * However, that is difficult because this is
+				 * variable length and we won't have the
+				 * information later.
+				 */
+				if (match->key->tun_opts_len != nla_len(a)) {
+					OVS_NLERR("Geneve option key length (%d) is different from mask length (%d).",
+						  match->key->tun_opts_len,
+						  nla_len(a));
+					return -EINVAL;
+				}
+
+				SW_FLOW_KEY_PUT(match, tun_opts_len, 0xff,
+						true);
+			}
+
+			opt_key_offset = (unsigned long)GENEVE_OPTS(
+					  (struct sw_flow_key *)0,
+					  nla_len(a));
+			SW_FLOW_KEY_MEMCPY_OFFSET(match, opt_key_offset,
+						  nla_data(a), nla_len(a),
+						  is_mask);
+			break;
 		default:
+			OVS_NLERR("Unknown IPv4 tunnel attribute (%d).\n",
+				  type);
 			return -EINVAL;
 		}
 	}
@@ -415,45 +480,80 @@
 	return 0;
 }
 
-static int ipv4_tun_to_nlattr(struct sk_buff *skb,
-			      const struct ovs_key_ipv4_tunnel *tun_key,
-			      const struct ovs_key_ipv4_tunnel *output)
+static int __ipv4_tun_to_nlattr(struct sk_buff *skb,
+				const struct ovs_key_ipv4_tunnel *output,
+				const struct geneve_opt *tun_opts,
+				int swkey_tun_opts_len)
 {
-	struct nlattr *nla;
-
-	nla = nla_nest_start(skb, OVS_KEY_ATTR_TUNNEL);
-	if (!nla)
-		return -EMSGSIZE;
-
 	if (output->tun_flags & TUNNEL_KEY &&
 	    nla_put_be64(skb, OVS_TUNNEL_KEY_ATTR_ID, output->tun_id))
 		return -EMSGSIZE;
 	if (output->ipv4_src &&
-		nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, output->ipv4_src))
+	    nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, output->ipv4_src))
 		return -EMSGSIZE;
 	if (output->ipv4_dst &&
-		nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_DST, output->ipv4_dst))
+	    nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_DST, output->ipv4_dst))
 		return -EMSGSIZE;
 	if (output->ipv4_tos &&
-		nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TOS, output->ipv4_tos))
+	    nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TOS, output->ipv4_tos))
 		return -EMSGSIZE;
 	if (nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TTL, output->ipv4_ttl))
 		return -EMSGSIZE;
 	if ((output->tun_flags & TUNNEL_DONT_FRAGMENT) &&
-		nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT))
+	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT))
 		return -EMSGSIZE;
 	if ((output->tun_flags & TUNNEL_CSUM) &&
-		nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_CSUM))
+	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_CSUM))
+		return -EMSGSIZE;
+	if ((output->tun_flags & TUNNEL_OAM) &&
+	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_OAM))
+		return -EMSGSIZE;
+	if (tun_opts &&
+	    nla_put(skb, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,
+		    swkey_tun_opts_len, tun_opts))
 		return -EMSGSIZE;
 
-	nla_nest_end(skb, nla);
 	return 0;
 }
 
 
+static int ipv4_tun_to_nlattr(struct sk_buff *skb,
+			      const struct ovs_key_ipv4_tunnel *output,
+			      const struct geneve_opt *tun_opts,
+			      int swkey_tun_opts_len)
+{
+	struct nlattr *nla;
+	int err;
+
+	nla = nla_nest_start(skb, OVS_KEY_ATTR_TUNNEL);
+	if (!nla)
+		return -EMSGSIZE;
+
+	err = __ipv4_tun_to_nlattr(skb, output, tun_opts, swkey_tun_opts_len);
+	if (err)
+		return err;
+
+	nla_nest_end(skb, nla);
+	return 0;
+}
+
 static int metadata_from_nlattrs(struct sw_flow_match *match,  u64 *attrs,
 				 const struct nlattr **a, bool is_mask)
 {
+	if (*attrs & (1 << OVS_KEY_ATTR_DP_HASH)) {
+		u32 hash_val = nla_get_u32(a[OVS_KEY_ATTR_DP_HASH]);
+
+		SW_FLOW_KEY_PUT(match, ovs_flow_hash, hash_val, is_mask);
+		*attrs &= ~(1 << OVS_KEY_ATTR_DP_HASH);
+	}
+
+	if (*attrs & (1 << OVS_KEY_ATTR_RECIRC_ID)) {
+		u32 recirc_id = nla_get_u32(a[OVS_KEY_ATTR_RECIRC_ID]);
+
+		SW_FLOW_KEY_PUT(match, recirc_id, recirc_id, is_mask);
+		*attrs &= ~(1 << OVS_KEY_ATTR_RECIRC_ID);
+	}
+
 	if (*attrs & (1 << OVS_KEY_ATTR_PRIORITY)) {
 		SW_FLOW_KEY_PUT(match, phy.priority,
 			  nla_get_u32(a[OVS_KEY_ATTR_PRIORITY]), is_mask);
@@ -836,7 +936,7 @@
 
 /**
  * ovs_nla_get_flow_metadata - parses Netlink attributes into a flow key.
- * @flow: Receives extracted in_port, priority, tun_key and skb_mark.
+ * @key: Receives extracted in_port, priority, tun_key and skb_mark.
  * @attr: Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink attribute
  * sequence.
  *
@@ -846,32 +946,24 @@
  * extracted from the packet itself.
  */
 
-int ovs_nla_get_flow_metadata(struct sw_flow *flow,
-			      const struct nlattr *attr)
+int ovs_nla_get_flow_metadata(const struct nlattr *attr,
+			      struct sw_flow_key *key)
 {
-	struct ovs_key_ipv4_tunnel *tun_key = &flow->key.tun_key;
 	const struct nlattr *a[OVS_KEY_ATTR_MAX + 1];
+	struct sw_flow_match match;
 	u64 attrs = 0;
 	int err;
-	struct sw_flow_match match;
-
-	flow->key.phy.in_port = DP_MAX_PORTS;
-	flow->key.phy.priority = 0;
-	flow->key.phy.skb_mark = 0;
-	memset(tun_key, 0, sizeof(flow->key.tun_key));
 
 	err = parse_flow_nlattrs(attr, a, &attrs);
 	if (err)
 		return -EINVAL;
 
 	memset(&match, 0, sizeof(match));
-	match.key = &flow->key;
+	match.key = key;
 
-	err = metadata_from_nlattrs(&match, &attrs, a, false);
-	if (err)
-		return err;
+	key->phy.in_port = DP_MAX_PORTS;
 
-	return 0;
+	return metadata_from_nlattrs(&match, &attrs, a, false);
 }
 
 int ovs_nla_put_flow(const struct sw_flow_key *swkey,
@@ -881,13 +973,26 @@
 	struct nlattr *nla, *encap;
 	bool is_mask = (swkey != output);
 
-	if (nla_put_u32(skb, OVS_KEY_ATTR_PRIORITY, output->phy.priority))
+	if (nla_put_u32(skb, OVS_KEY_ATTR_RECIRC_ID, output->recirc_id))
 		goto nla_put_failure;
 
-	if ((swkey->tun_key.ipv4_dst || is_mask) &&
-	    ipv4_tun_to_nlattr(skb, &swkey->tun_key, &output->tun_key))
+	if (nla_put_u32(skb, OVS_KEY_ATTR_DP_HASH, output->ovs_flow_hash))
 		goto nla_put_failure;
 
+	if (nla_put_u32(skb, OVS_KEY_ATTR_PRIORITY, output->phy.priority))
+		goto nla_put_failure;
+
+	if ((swkey->tun_key.ipv4_dst || is_mask)) {
+		const struct geneve_opt *opts = NULL;
+
+		if (output->tun_key.tun_flags & TUNNEL_OPTIONS_PRESENT)
+			opts = GENEVE_OPTS(output, swkey->tun_opts_len);
+
+		if (ipv4_tun_to_nlattr(skb, &output->tun_key, opts,
+				       swkey->tun_opts_len))
+			goto nla_put_failure;
+	}
+
 	if (swkey->phy.in_port == DP_MAX_PORTS) {
 		if (is_mask && (output->phy.in_port == 0xffff))
 			if (nla_put_u32(skb, OVS_KEY_ATTR_IN_PORT, 0xffffffff))
@@ -1127,13 +1232,14 @@
 	return  (struct nlattr *) ((unsigned char *)(*sfa) + next_offset);
 }
 
-static int add_action(struct sw_flow_actions **sfa, int attrtype, void *data, int len)
+static struct nlattr *__add_action(struct sw_flow_actions **sfa,
+				   int attrtype, void *data, int len)
 {
 	struct nlattr *a;
 
 	a = reserve_sfa_size(sfa, nla_attr_size(len));
 	if (IS_ERR(a))
-		return PTR_ERR(a);
+		return a;
 
 	a->nla_type = attrtype;
 	a->nla_len = nla_attr_size(len);
@@ -1142,6 +1248,18 @@
 		memcpy(nla_data(a), data, len);
 	memset((unsigned char *) a + a->nla_len, 0, nla_padlen(len));
 
+	return a;
+}
+
+static int add_action(struct sw_flow_actions **sfa, int attrtype,
+		      void *data, int len)
+{
+	struct nlattr *a;
+
+	a = __add_action(sfa, attrtype, data, len);
+	if (IS_ERR(a))
+		return PTR_ERR(a);
+
 	return 0;
 }
 
@@ -1247,6 +1365,8 @@
 {
 	struct sw_flow_match match;
 	struct sw_flow_key key;
+	struct ovs_tunnel_info *tun_info;
+	struct nlattr *a;
 	int err, start;
 
 	ovs_match_init(&match, &key, NULL);
@@ -1254,12 +1374,56 @@
 	if (err)
 		return err;
 
+	if (key.tun_opts_len) {
+		struct geneve_opt *option = GENEVE_OPTS(&key,
+							key.tun_opts_len);
+		int opts_len = key.tun_opts_len;
+		bool crit_opt = false;
+
+		while (opts_len > 0) {
+			int len;
+
+			if (opts_len < sizeof(*option))
+				return -EINVAL;
+
+			len = sizeof(*option) + option->length * 4;
+			if (len > opts_len)
+				return -EINVAL;
+
+			crit_opt |= !!(option->type & GENEVE_CRIT_OPT_TYPE);
+
+			option = (struct geneve_opt *)((u8 *)option + len);
+			opts_len -= len;
+		};
+
+		key.tun_key.tun_flags |= crit_opt ? TUNNEL_CRIT_OPT : 0;
+	};
+
 	start = add_nested_action_start(sfa, OVS_ACTION_ATTR_SET);
 	if (start < 0)
 		return start;
 
-	err = add_action(sfa, OVS_KEY_ATTR_IPV4_TUNNEL, &match.key->tun_key,
-			sizeof(match.key->tun_key));
+	a = __add_action(sfa, OVS_KEY_ATTR_TUNNEL_INFO, NULL,
+			 sizeof(*tun_info) + key.tun_opts_len);
+	if (IS_ERR(a))
+		return PTR_ERR(a);
+
+	tun_info = nla_data(a);
+	tun_info->tunnel = key.tun_key;
+	tun_info->options_len = key.tun_opts_len;
+
+	if (tun_info->options_len) {
+		/* We need to store the options in the action itself since
+		 * everything else will go away after flow setup. We can append
+		 * it to tun_info and then point there.
+		 */
+		memcpy((tun_info + 1), GENEVE_OPTS(&key, key.tun_opts_len),
+		       key.tun_opts_len);
+		tun_info->options = (struct geneve_opt *)(tun_info + 1);
+	} else {
+		tun_info->options = NULL;
+	}
+
 	add_nested_action_end(*sfa, start);
 
 	return err;
@@ -1409,11 +1573,13 @@
 		/* Expected argument lengths, (u32)-1 for variable length. */
 		static const u32 action_lens[OVS_ACTION_ATTR_MAX + 1] = {
 			[OVS_ACTION_ATTR_OUTPUT] = sizeof(u32),
+			[OVS_ACTION_ATTR_RECIRC] = sizeof(u32),
 			[OVS_ACTION_ATTR_USERSPACE] = (u32)-1,
 			[OVS_ACTION_ATTR_PUSH_VLAN] = sizeof(struct ovs_action_push_vlan),
 			[OVS_ACTION_ATTR_POP_VLAN] = 0,
 			[OVS_ACTION_ATTR_SET] = (u32)-1,
-			[OVS_ACTION_ATTR_SAMPLE] = (u32)-1
+			[OVS_ACTION_ATTR_SAMPLE] = (u32)-1,
+			[OVS_ACTION_ATTR_HASH] = sizeof(struct ovs_action_hash)
 		};
 		const struct ovs_action_push_vlan *vlan;
 		int type = nla_type(a);
@@ -1440,6 +1606,18 @@
 				return -EINVAL;
 			break;
 
+		case OVS_ACTION_ATTR_HASH: {
+			const struct ovs_action_hash *act_hash = nla_data(a);
+
+			switch (act_hash->hash_alg) {
+			case OVS_HASH_ALG_L4:
+				break;
+			default:
+				return  -EINVAL;
+			}
+
+			break;
+		}
 
 		case OVS_ACTION_ATTR_POP_VLAN:
 			break;
@@ -1452,6 +1630,9 @@
 				return -EINVAL;
 			break;
 
+		case OVS_ACTION_ATTR_RECIRC:
+			break;
+
 		case OVS_ACTION_ATTR_SET:
 			err = validate_set(a, key, sfa, &skip_copy);
 			if (err)
@@ -1525,17 +1706,22 @@
 	int err;
 
 	switch (key_type) {
-	case OVS_KEY_ATTR_IPV4_TUNNEL:
+	case OVS_KEY_ATTR_TUNNEL_INFO: {
+		struct ovs_tunnel_info *tun_info = nla_data(ovs_key);
+
 		start = nla_nest_start(skb, OVS_ACTION_ATTR_SET);
 		if (!start)
 			return -EMSGSIZE;
 
-		err = ipv4_tun_to_nlattr(skb, nla_data(ovs_key),
-					     nla_data(ovs_key));
+		err = ipv4_tun_to_nlattr(skb, &tun_info->tunnel,
+					 tun_info->options_len ?
+						tun_info->options : NULL,
+					 tun_info->options_len);
 		if (err)
 			return err;
 		nla_nest_end(skb, start);
 		break;
+	}
 	default:
 		if (nla_put(skb, OVS_ACTION_ATTR_SET, nla_len(a), ovs_key))
 			return -EMSGSIZE;
diff -urN linux/net/openvswitch/flow_netlink.h net-next-2.6/net/openvswitch/flow_netlink.h
--- linux/net/openvswitch/flow_netlink.h	2013-11-29 12:59:37.991382663 +0100
+++ net-next-2.6/net/openvswitch/flow_netlink.h	2014-10-06 10:49:04.208940992 +0200
@@ -42,8 +42,8 @@
 
 int ovs_nla_put_flow(const struct sw_flow_key *,
 		     const struct sw_flow_key *, struct sk_buff *);
-int ovs_nla_get_flow_metadata(struct sw_flow *flow,
-			      const struct nlattr *attr);
+int ovs_nla_get_flow_metadata(const struct nlattr *, struct sw_flow_key *);
+
 int ovs_nla_get_match(struct sw_flow_match *match,
 		      const struct nlattr *,
 		      const struct nlattr *);
diff -urN linux/net/openvswitch/Kconfig net-next-2.6/net/openvswitch/Kconfig
--- linux/net/openvswitch/Kconfig	2013-11-29 12:59:37.991382663 +0100
+++ net-next-2.6/net/openvswitch/Kconfig	2014-10-06 10:49:04.204940952 +0200
@@ -54,3 +54,14 @@
 	  Say N to exclude this support and reduce the binary size.
 
 	  If unsure, say Y.
+
+config OPENVSWITCH_GENEVE
+	bool "Open vSwitch Geneve tunneling support"
+	depends on INET
+	depends on OPENVSWITCH
+	depends on GENEVE && !(OPENVSWITCH=y && GENEVE=m)
+	default y
+	---help---
+	  If you say Y here, then the Open vSwitch will be able create geneve vport.
+
+	  Say N to exclude this support and reduce the binary size.
diff -urN linux/net/openvswitch/Makefile net-next-2.6/net/openvswitch/Makefile
--- linux/net/openvswitch/Makefile	2013-11-29 12:59:37.991382663 +0100
+++ net-next-2.6/net/openvswitch/Makefile	2014-10-06 10:49:04.204940952 +0200
@@ -15,6 +15,10 @@
 	vport-internal_dev.o \
 	vport-netdev.o
 
+ifneq ($(CONFIG_OPENVSWITCH_GENEVE),)
+openvswitch-y += vport-geneve.o
+endif
+
 ifneq ($(CONFIG_OPENVSWITCH_VXLAN),)
 openvswitch-y += vport-vxlan.o
 endif
diff -urN linux/net/openvswitch/vport.c net-next-2.6/net/openvswitch/vport.c
--- linux/net/openvswitch/vport.c	2014-09-24 09:52:43.868651596 +0200
+++ net-next-2.6/net/openvswitch/vport.c	2014-10-06 10:49:04.208940992 +0200
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2007-2012 Nicira, Inc.
+ * Copyright (c) 2007-2014 Nicira, Inc.
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -48,6 +48,9 @@
 #ifdef CONFIG_OPENVSWITCH_VXLAN
 	&ovs_vxlan_vport_ops,
 #endif
+#ifdef CONFIG_OPENVSWITCH_GENEVE
+	&ovs_geneve_vport_ops,
+#endif
 };
 
 /* Protected by RCU read lock for reading, ovs_mutex for writing. */
@@ -148,8 +151,6 @@
 		return ERR_PTR(-ENOMEM);
 	}
 
-	spin_lock_init(&vport->stats_lock);
-
 	return vport;
 }
 
@@ -268,14 +269,10 @@
 	 * netdev-stats can be directly read over netlink-ioctl.
 	 */
 
-	spin_lock_bh(&vport->stats_lock);
-
-	stats->rx_errors	= vport->err_stats.rx_errors;
-	stats->tx_errors	= vport->err_stats.tx_errors;
-	stats->tx_dropped	= vport->err_stats.tx_dropped;
-	stats->rx_dropped	= vport->err_stats.rx_dropped;
-
-	spin_unlock_bh(&vport->stats_lock);
+	stats->rx_errors  = atomic_long_read(&vport->err_stats.rx_errors);
+	stats->tx_errors  = atomic_long_read(&vport->err_stats.tx_errors);
+	stats->tx_dropped = atomic_long_read(&vport->err_stats.tx_dropped);
+	stats->rx_dropped = atomic_long_read(&vport->err_stats.rx_dropped);
 
 	for_each_possible_cpu(i) {
 		const struct pcpu_sw_netstats *percpu_stats;
@@ -438,9 +435,11 @@
  * skb->data should point to the Ethernet header.
  */
 void ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
-		       struct ovs_key_ipv4_tunnel *tun_key)
+		       struct ovs_tunnel_info *tun_info)
 {
 	struct pcpu_sw_netstats *stats;
+	struct sw_flow_key key;
+	int error;
 
 	stats = this_cpu_ptr(vport->percpu_stats);
 	u64_stats_update_begin(&stats->syncp);
@@ -448,8 +447,15 @@
 	stats->rx_bytes += skb->len;
 	u64_stats_update_end(&stats->syncp);
 
-	OVS_CB(skb)->tun_key = tun_key;
-	ovs_dp_process_received_packet(vport, skb);
+	OVS_CB(skb)->input_vport = vport;
+	OVS_CB(skb)->egress_tun_info = NULL;
+	/* Extract flow from 'skb' into 'key'. */
+	error = ovs_flow_key_extract(tun_info, skb, &key);
+	if (unlikely(error)) {
+		kfree_skb(skb);
+		return;
+	}
+	ovs_dp_process_packet(skb, &key);
 }
 
 /**
@@ -495,27 +501,24 @@
 static void ovs_vport_record_error(struct vport *vport,
 				   enum vport_err_type err_type)
 {
-	spin_lock(&vport->stats_lock);
-
 	switch (err_type) {
 	case VPORT_E_RX_DROPPED:
-		vport->err_stats.rx_dropped++;
+		atomic_long_inc(&vport->err_stats.rx_dropped);
 		break;
 
 	case VPORT_E_RX_ERROR:
-		vport->err_stats.rx_errors++;
+		atomic_long_inc(&vport->err_stats.rx_errors);
 		break;
 
 	case VPORT_E_TX_DROPPED:
-		vport->err_stats.tx_dropped++;
+		atomic_long_inc(&vport->err_stats.tx_dropped);
 		break;
 
 	case VPORT_E_TX_ERROR:
-		vport->err_stats.tx_errors++;
+		atomic_long_inc(&vport->err_stats.tx_errors);
 		break;
 	}
 
-	spin_unlock(&vport->stats_lock);
 }
 
 static void free_vport_rcu(struct rcu_head *rcu)
diff -urN linux/net/openvswitch/vport-geneve.c net-next-2.6/net/openvswitch/vport-geneve.c
--- linux/net/openvswitch/vport-geneve.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/openvswitch/vport-geneve.c	2014-10-06 10:49:04.208940992 +0200
@@ -0,0 +1,236 @@
+/*
+ * Copyright (c) 2014 Nicira, Inc.
+ *
+ * This program is free software; you can redistribute it and/or
+ * modify it under the terms of the GNU General Public License
+ * as published by the Free Software Foundation; either version
+ * 2 of the License, or (at your option) any later version.
+ */
+
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/version.h>
+
+#include <linux/in.h>
+#include <linux/ip.h>
+#include <linux/net.h>
+#include <linux/rculist.h>
+#include <linux/udp.h>
+#include <linux/if_vlan.h>
+
+#include <net/geneve.h>
+#include <net/icmp.h>
+#include <net/ip.h>
+#include <net/route.h>
+#include <net/udp.h>
+#include <net/xfrm.h>
+
+#include "datapath.h"
+#include "vport.h"
+
+/**
+ * struct geneve_port - Keeps track of open UDP ports
+ * @sock: The socket created for this port number.
+ * @name: vport name.
+ */
+struct geneve_port {
+	struct geneve_sock *gs;
+	char name[IFNAMSIZ];
+};
+
+static LIST_HEAD(geneve_ports);
+
+static inline struct geneve_port *geneve_vport(const struct vport *vport)
+{
+	return vport_priv(vport);
+}
+
+static inline struct genevehdr *geneve_hdr(const struct sk_buff *skb)
+{
+	return (struct genevehdr *)(udp_hdr(skb) + 1);
+}
+
+/* Convert 64 bit tunnel ID to 24 bit VNI. */
+static void tunnel_id_to_vni(__be64 tun_id, __u8 *vni)
+{
+#ifdef __BIG_ENDIAN
+	vni[0] = (__force __u8)(tun_id >> 16);
+	vni[1] = (__force __u8)(tun_id >> 8);
+	vni[2] = (__force __u8)tun_id;
+#else
+	vni[0] = (__force __u8)((__force u64)tun_id >> 40);
+	vni[1] = (__force __u8)((__force u64)tun_id >> 48);
+	vni[2] = (__force __u8)((__force u64)tun_id >> 56);
+#endif
+}
+
+/* Convert 24 bit VNI to 64 bit tunnel ID. */
+static __be64 vni_to_tunnel_id(__u8 *vni)
+{
+#ifdef __BIG_ENDIAN
+	return (vni[0] << 16) | (vni[1] << 8) | vni[2];
+#else
+	return (__force __be64)(((__force u64)vni[0] << 40) |
+				((__force u64)vni[1] << 48) |
+				((__force u64)vni[2] << 56));
+#endif
+}
+
+static void geneve_rcv(struct geneve_sock *gs, struct sk_buff *skb)
+{
+	struct vport *vport = gs->rcv_data;
+	struct genevehdr *geneveh = geneve_hdr(skb);
+	int opts_len;
+	struct ovs_tunnel_info tun_info;
+	__be64 key;
+	__be16 flags;
+
+	opts_len = geneveh->opt_len * 4;
+
+	flags = TUNNEL_KEY | TUNNEL_OPTIONS_PRESENT |
+		(udp_hdr(skb)->check != 0 ? TUNNEL_CSUM : 0) |
+		(geneveh->oam ? TUNNEL_OAM : 0) |
+		(geneveh->critical ? TUNNEL_CRIT_OPT : 0);
+
+	key = vni_to_tunnel_id(geneveh->vni);
+
+	ovs_flow_tun_info_init(&tun_info, ip_hdr(skb), key, flags,
+			       geneveh->options, opts_len);
+
+	ovs_vport_receive(vport, skb, &tun_info);
+}
+
+static int geneve_get_options(const struct vport *vport,
+			      struct sk_buff *skb)
+{
+	struct geneve_port *geneve_port = geneve_vport(vport);
+	__be16 sport;
+
+	sport = ntohs(inet_sk(geneve_port->gs->sock->sk)->inet_sport);
+	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, sport))
+		return -EMSGSIZE;
+	return 0;
+}
+
+static void geneve_tnl_destroy(struct vport *vport)
+{
+	struct geneve_port *geneve_port = geneve_vport(vport);
+
+	geneve_sock_release(geneve_port->gs);
+
+	ovs_vport_deferred_free(vport);
+}
+
+static struct vport *geneve_tnl_create(const struct vport_parms *parms)
+{
+	struct net *net = ovs_dp_get_net(parms->dp);
+	struct nlattr *options = parms->options;
+	struct geneve_port *geneve_port;
+	struct geneve_sock *gs;
+	struct vport *vport;
+	struct nlattr *a;
+	int err;
+	u16 dst_port;
+
+	if (!options) {
+		err = -EINVAL;
+		goto error;
+	}
+
+	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
+	if (a && nla_len(a) == sizeof(u16)) {
+		dst_port = nla_get_u16(a);
+	} else {
+		/* Require destination port from userspace. */
+		err = -EINVAL;
+		goto error;
+	}
+
+	vport = ovs_vport_alloc(sizeof(struct geneve_port),
+				&ovs_geneve_vport_ops, parms);
+	if (IS_ERR(vport))
+		return vport;
+
+	geneve_port = geneve_vport(vport);
+	strncpy(geneve_port->name, parms->name, IFNAMSIZ);
+
+	gs = geneve_sock_add(net, htons(dst_port), geneve_rcv, vport, true, 0);
+	if (IS_ERR(gs)) {
+		ovs_vport_free(vport);
+		return (void *)gs;
+	}
+	geneve_port->gs = gs;
+
+	return vport;
+error:
+	return ERR_PTR(err);
+}
+
+static int geneve_tnl_send(struct vport *vport, struct sk_buff *skb)
+{
+	struct ovs_key_ipv4_tunnel *tun_key;
+	struct ovs_tunnel_info *tun_info;
+	struct net *net = ovs_dp_get_net(vport->dp);
+	struct geneve_port *geneve_port = geneve_vport(vport);
+	__be16 dport = inet_sk(geneve_port->gs->sock->sk)->inet_sport;
+	__be16 sport;
+	struct rtable *rt;
+	struct flowi4 fl;
+	u8 vni[3];
+	__be16 df;
+	int err;
+
+	tun_info = OVS_CB(skb)->egress_tun_info;
+	if (unlikely(!tun_info)) {
+		err = -EINVAL;
+		goto error;
+	}
+
+	tun_key = &tun_info->tunnel;
+
+	/* Route lookup */
+	memset(&fl, 0, sizeof(fl));
+	fl.daddr = tun_key->ipv4_dst;
+	fl.saddr = tun_key->ipv4_src;
+	fl.flowi4_tos = RT_TOS(tun_key->ipv4_tos);
+	fl.flowi4_mark = skb->mark;
+	fl.flowi4_proto = IPPROTO_UDP;
+
+	rt = ip_route_output_key(net, &fl);
+	if (IS_ERR(rt)) {
+		err = PTR_ERR(rt);
+		goto error;
+	}
+
+	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
+	sport = udp_flow_src_port(net, skb, 1, USHRT_MAX, true);
+	tunnel_id_to_vni(tun_key->tun_id, vni);
+	skb->ignore_df = 1;
+
+	err = geneve_xmit_skb(geneve_port->gs, rt, skb, fl.saddr,
+			      tun_key->ipv4_dst, tun_key->ipv4_tos,
+			      tun_key->ipv4_ttl, df, sport, dport,
+			      tun_key->tun_flags, vni,
+			      tun_info->options_len, (u8 *)tun_info->options,
+			      false);
+	if (err < 0)
+		ip_rt_put(rt);
+error:
+	return err;
+}
+
+static const char *geneve_get_name(const struct vport *vport)
+{
+	struct geneve_port *geneve_port = geneve_vport(vport);
+
+	return geneve_port->name;
+}
+
+const struct vport_ops ovs_geneve_vport_ops = {
+	.type		= OVS_VPORT_TYPE_GENEVE,
+	.create		= geneve_tnl_create,
+	.destroy	= geneve_tnl_destroy,
+	.get_name	= geneve_get_name,
+	.get_options	= geneve_get_options,
+	.send		= geneve_tnl_send,
+};
diff -urN linux/net/openvswitch/vport-gre.c net-next-2.6/net/openvswitch/vport-gre.c
--- linux/net/openvswitch/vport-gre.c	2014-09-24 09:52:43.864651554 +0200
+++ net-next-2.6/net/openvswitch/vport-gre.c	2014-10-06 10:49:04.208940992 +0200
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2007-2013 Nicira, Inc.
+ * Copyright (c) 2007-2014 Nicira, Inc.
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -63,8 +63,10 @@
 static struct sk_buff *__build_header(struct sk_buff *skb,
 				      int tunnel_hlen)
 {
-	const struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;
 	struct tnl_ptk_info tpi;
+	const struct ovs_key_ipv4_tunnel *tun_key;
+
+	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;
 
 	skb = gre_handle_offloads(skb, !!(tun_key->tun_flags & TUNNEL_CSUM));
 	if (IS_ERR(skb))
@@ -92,7 +94,7 @@
 static int gre_rcv(struct sk_buff *skb,
 		   const struct tnl_ptk_info *tpi)
 {
-	struct ovs_key_ipv4_tunnel tun_key;
+	struct ovs_tunnel_info tun_info;
 	struct ovs_net *ovs_net;
 	struct vport *vport;
 	__be64 key;
@@ -103,10 +105,10 @@
 		return PACKET_REJECT;
 
 	key = key_to_tunnel_id(tpi->key, tpi->seq);
-	ovs_flow_tun_key_init(&tun_key, ip_hdr(skb), key,
-			      filter_tnl_flags(tpi->flags));
+	ovs_flow_tun_info_init(&tun_info, ip_hdr(skb), key,
+			       filter_tnl_flags(tpi->flags), NULL, 0);
 
-	ovs_vport_receive(vport, skb, &tun_key);
+	ovs_vport_receive(vport, skb, &tun_info);
 	return PACKET_RCVD;
 }
 
@@ -129,6 +131,7 @@
 static int gre_tnl_send(struct vport *vport, struct sk_buff *skb)
 {
 	struct net *net = ovs_dp_get_net(vport->dp);
+	struct ovs_key_ipv4_tunnel *tun_key;
 	struct flowi4 fl;
 	struct rtable *rt;
 	int min_headroom;
@@ -136,16 +139,17 @@
 	__be16 df;
 	int err;
 
-	if (unlikely(!OVS_CB(skb)->tun_key)) {
+	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
 		err = -EINVAL;
 		goto error;
 	}
 
+	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;
 	/* Route lookup */
 	memset(&fl, 0, sizeof(fl));
-	fl.daddr = OVS_CB(skb)->tun_key->ipv4_dst;
-	fl.saddr = OVS_CB(skb)->tun_key->ipv4_src;
-	fl.flowi4_tos = RT_TOS(OVS_CB(skb)->tun_key->ipv4_tos);
+	fl.daddr = tun_key->ipv4_dst;
+	fl.saddr = tun_key->ipv4_src;
+	fl.flowi4_tos = RT_TOS(tun_key->ipv4_tos);
 	fl.flowi4_mark = skb->mark;
 	fl.flowi4_proto = IPPROTO_GRE;
 
@@ -153,7 +157,7 @@
 	if (IS_ERR(rt))
 		return PTR_ERR(rt);
 
-	tunnel_hlen = ip_gre_calc_hlen(OVS_CB(skb)->tun_key->tun_flags);
+	tunnel_hlen = ip_gre_calc_hlen(tun_key->tun_flags);
 
 	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
 			+ tunnel_hlen + sizeof(struct iphdr)
@@ -185,15 +189,14 @@
 		goto err_free_rt;
 	}
 
-	df = OVS_CB(skb)->tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ?
+	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ?
 		htons(IP_DF) : 0;
 
 	skb->ignore_df = 1;
 
 	return iptunnel_xmit(skb->sk, rt, skb, fl.saddr,
-			     OVS_CB(skb)->tun_key->ipv4_dst, IPPROTO_GRE,
-			     OVS_CB(skb)->tun_key->ipv4_tos,
-			     OVS_CB(skb)->tun_key->ipv4_ttl, df, false);
+			     tun_key->ipv4_dst, IPPROTO_GRE,
+			     tun_key->ipv4_tos, tun_key->ipv4_ttl, df, false);
 err_free_rt:
 	ip_rt_put(rt);
 error:
diff -urN linux/net/openvswitch/vport.h net-next-2.6/net/openvswitch/vport.h
--- linux/net/openvswitch/vport.h	2014-09-24 09:52:43.868651596 +0200
+++ net-next-2.6/net/openvswitch/vport.h	2014-10-06 10:49:04.208940992 +0200
@@ -35,7 +35,6 @@
 
 /* The following definitions are for users of the vport subsytem: */
 
-/* The following definitions are for users of the vport subsytem: */
 struct vport_net {
 	struct vport __rcu *gre_vport;
 };
@@ -62,10 +61,10 @@
 /* The following definitions are for implementers of vport devices: */
 
 struct vport_err_stats {
-	u64 rx_dropped;
-	u64 rx_errors;
-	u64 tx_dropped;
-	u64 tx_errors;
+	atomic_long_t rx_dropped;
+	atomic_long_t rx_errors;
+	atomic_long_t tx_dropped;
+	atomic_long_t tx_errors;
 };
 /**
  * struct vport_portids - array of netlink portids of a vport.
@@ -93,7 +92,6 @@
  * @dp_hash_node: Element in @datapath->ports hash table in datapath.c.
  * @ops: Class structure.
  * @percpu_stats: Points to per-CPU statistics used and maintained by vport
- * @stats_lock: Protects @err_stats;
  * @err_stats: Points to error statistics used and maintained by vport
  */
 struct vport {
@@ -108,7 +106,6 @@
 
 	struct pcpu_sw_netstats __percpu *percpu_stats;
 
-	spinlock_t stats_lock;
 	struct vport_err_stats err_stats;
 };
 
@@ -210,7 +207,7 @@
 }
 
 void ovs_vport_receive(struct vport *, struct sk_buff *,
-		       struct ovs_key_ipv4_tunnel *);
+		       struct ovs_tunnel_info *);
 
 /* List of statically compiled vport implementations.  Don't forget to also
  * add yours to the list at the top of vport.c. */
@@ -218,6 +215,7 @@
 extern const struct vport_ops ovs_internal_vport_ops;
 extern const struct vport_ops ovs_gre_vport_ops;
 extern const struct vport_ops ovs_vxlan_vport_ops;
+extern const struct vport_ops ovs_geneve_vport_ops;
 
 static inline void ovs_skb_postpush_rcsum(struct sk_buff *skb,
 				      const void *start, unsigned int len)
diff -urN linux/net/openvswitch/vport-vxlan.c net-next-2.6/net/openvswitch/vport-vxlan.c
--- linux/net/openvswitch/vport-vxlan.c	2014-09-24 09:52:43.864651554 +0200
+++ net-next-2.6/net/openvswitch/vport-vxlan.c	2014-10-06 10:49:04.208940992 +0200
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2013 Nicira, Inc.
+ * Copyright (c) 2014 Nicira, Inc.
  * Copyright (c) 2013 Cisco Systems, Inc.
  *
  * This program is free software; you can redistribute it and/or
@@ -58,7 +58,7 @@
 /* Called with rcu_read_lock and BH disabled. */
 static void vxlan_rcv(struct vxlan_sock *vs, struct sk_buff *skb, __be32 vx_vni)
 {
-	struct ovs_key_ipv4_tunnel tun_key;
+	struct ovs_tunnel_info tun_info;
 	struct vport *vport = vs->data;
 	struct iphdr *iph;
 	__be64 key;
@@ -66,9 +66,9 @@
 	/* Save outer tunnel values */
 	iph = ip_hdr(skb);
 	key = cpu_to_be64(ntohl(vx_vni) >> 8);
-	ovs_flow_tun_key_init(&tun_key, iph, key, TUNNEL_KEY);
+	ovs_flow_tun_info_init(&tun_info, iph, key, TUNNEL_KEY, NULL, 0);
 
-	ovs_vport_receive(vport, skb, &tun_key);
+	ovs_vport_receive(vport, skb, &tun_info);
 }
 
 static int vxlan_get_options(const struct vport *vport, struct sk_buff *skb)
@@ -140,22 +140,24 @@
 	struct net *net = ovs_dp_get_net(vport->dp);
 	struct vxlan_port *vxlan_port = vxlan_vport(vport);
 	__be16 dst_port = inet_sk(vxlan_port->vs->sock->sk)->inet_sport;
+	struct ovs_key_ipv4_tunnel *tun_key;
 	struct rtable *rt;
 	struct flowi4 fl;
 	__be16 src_port;
 	__be16 df;
 	int err;
 
-	if (unlikely(!OVS_CB(skb)->tun_key)) {
+	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
 		err = -EINVAL;
 		goto error;
 	}
 
+	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;
 	/* Route lookup */
 	memset(&fl, 0, sizeof(fl));
-	fl.daddr = OVS_CB(skb)->tun_key->ipv4_dst;
-	fl.saddr = OVS_CB(skb)->tun_key->ipv4_src;
-	fl.flowi4_tos = RT_TOS(OVS_CB(skb)->tun_key->ipv4_tos);
+	fl.daddr = tun_key->ipv4_dst;
+	fl.saddr = tun_key->ipv4_src;
+	fl.flowi4_tos = RT_TOS(tun_key->ipv4_tos);
 	fl.flowi4_mark = skb->mark;
 	fl.flowi4_proto = IPPROTO_UDP;
 
@@ -165,7 +167,7 @@
 		goto error;
 	}
 
-	df = OVS_CB(skb)->tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ?
+	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ?
 		htons(IP_DF) : 0;
 
 	skb->ignore_df = 1;
@@ -173,11 +175,10 @@
 	src_port = udp_flow_src_port(net, skb, 0, 0, true);
 
 	err = vxlan_xmit_skb(vxlan_port->vs, rt, skb,
-			     fl.saddr, OVS_CB(skb)->tun_key->ipv4_dst,
-			     OVS_CB(skb)->tun_key->ipv4_tos,
-			     OVS_CB(skb)->tun_key->ipv4_ttl, df,
+			     fl.saddr, tun_key->ipv4_dst,
+			     tun_key->ipv4_tos, tun_key->ipv4_ttl, df,
 			     src_port, dst_port,
-			     htonl(be64_to_cpu(OVS_CB(skb)->tun_key->tun_id) << 8),
+			     htonl(be64_to_cpu(tun_key->tun_id) << 8),
 			     false);
 	if (err < 0)
 		ip_rt_put(rt);
