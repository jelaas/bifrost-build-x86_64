diff -urN linux/net/ipv4/af_inet.c net-next-2.6/net/ipv4/af_inet.c
--- linux/net/ipv4/af_inet.c	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/af_inet.c	2014-10-06 10:49:00.272900881 +0200
@@ -418,10 +418,6 @@
 }
 EXPORT_SYMBOL(inet_release);
 
-/* It is off by default, see below. */
-int sysctl_ip_nonlocal_bind __read_mostly;
-EXPORT_SYMBOL(sysctl_ip_nonlocal_bind);
-
 int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
 {
 	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
@@ -461,7 +457,7 @@
 	 *  is temporarily down)
 	 */
 	err = -EADDRNOTAVAIL;
-	if (!sysctl_ip_nonlocal_bind &&
+	if (!net->ipv4.sysctl_ip_nonlocal_bind &&
 	    !(inet->freebind || inet->transparent) &&
 	    addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
 	    chk_addr_ret != RTN_LOCAL &&
@@ -1201,40 +1197,6 @@
 }
 EXPORT_SYMBOL(inet_sk_rebuild_header);
 
-static int inet_gso_send_check(struct sk_buff *skb)
-{
-	const struct net_offload *ops;
-	const struct iphdr *iph;
-	int proto;
-	int ihl;
-	int err = -EINVAL;
-
-	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
-		goto out;
-
-	iph = ip_hdr(skb);
-	ihl = iph->ihl * 4;
-	if (ihl < sizeof(*iph))
-		goto out;
-
-	proto = iph->protocol;
-
-	/* Warning: after this point, iph might be no longer valid */
-	if (unlikely(!pskb_may_pull(skb, ihl)))
-		goto out;
-	__skb_pull(skb, ihl);
-
-	skb_reset_transport_header(skb);
-	err = -EPROTONOSUPPORT;
-
-	ops = rcu_dereference(inet_offloads[proto]);
-	if (likely(ops && ops->callbacks.gso_send_check))
-		err = ops->callbacks.gso_send_check(skb);
-
-out:
-	return err;
-}
-
 static struct sk_buff *inet_gso_segment(struct sk_buff *skb,
 					netdev_features_t features)
 {
@@ -1407,6 +1369,9 @@
 	 * immediately following this IP hdr.
 	 */
 
+	/* Note : No need to call skb_gro_postpull_rcsum() here,
+	 * as we already checked checksum over ipv4 header was 0
+	 */
 	skb_gro_pull(skb, sizeof(*iph));
 	skb_set_transport_header(skb, skb_gro_offset(skb));
 
@@ -1659,7 +1624,6 @@
 static struct packet_offload ip_packet_offload __read_mostly = {
 	.type = cpu_to_be16(ETH_P_IP),
 	.callbacks = {
-		.gso_send_check = inet_gso_send_check,
 		.gso_segment = inet_gso_segment,
 		.gro_receive = inet_gro_receive,
 		.gro_complete = inet_gro_complete,
@@ -1668,8 +1632,9 @@
 
 static const struct net_offload ipip_offload = {
 	.callbacks = {
-		.gso_send_check = inet_gso_send_check,
 		.gso_segment	= inet_gso_segment,
+		.gro_receive	= inet_gro_receive,
+		.gro_complete	= inet_gro_complete,
 	},
 };
 
diff -urN linux/net/ipv4/ah4.c net-next-2.6/net/ipv4/ah4.c
--- linux/net/ipv4/ah4.c	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/ah4.c	2014-10-06 10:49:00.276900921 +0200
@@ -505,8 +505,6 @@
 	ahp->icv_full_len = aalg_desc->uinfo.auth.icv_fullbits/8;
 	ahp->icv_trunc_len = x->aalg->alg_trunc_len/8;
 
-	BUG_ON(ahp->icv_trunc_len > MAX_AH_AUTH_LEN);
-
 	if (x->props.flags & XFRM_STATE_ALIGN4)
 		x->props.header_len = XFRM_ALIGN4(sizeof(struct ip_auth_hdr) +
 						  ahp->icv_trunc_len);
diff -urN linux/net/ipv4/arp.c net-next-2.6/net/ipv4/arp.c
--- linux/net/ipv4/arp.c	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/arp.c	2014-10-06 10:49:00.276900921 +0200
@@ -953,10 +953,11 @@
 {
 	const struct arphdr *arp;
 
+	/* do not tweak dropwatch on an ARP we will ignore */
 	if (dev->flags & IFF_NOARP ||
 	    skb->pkt_type == PACKET_OTHERHOST ||
 	    skb->pkt_type == PACKET_LOOPBACK)
-		goto freeskb;
+		goto consumeskb;
 
 	skb = skb_share_check(skb, GFP_ATOMIC);
 	if (!skb)
@@ -974,6 +975,9 @@
 
 	return NF_HOOK(NFPROTO_ARP, NF_ARP_IN, skb, dev, NULL, arp_process);
 
+consumeskb:
+	consume_skb(skb);
+	return 0;
 freeskb:
 	kfree_skb(skb);
 out_of_mem:
diff -urN linux/net/ipv4/cipso_ipv4.c net-next-2.6/net/ipv4/cipso_ipv4.c
--- linux/net/ipv4/cipso_ipv4.c	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/cipso_ipv4.c	2014-10-06 10:49:00.276900921 +0200
@@ -246,7 +246,7 @@
  * success, negative values on error.
  *
  */
-static int cipso_v4_cache_init(void)
+static int __init cipso_v4_cache_init(void)
 {
 	u32 iter;
 
diff -urN linux/net/ipv4/fib_frontend.c net-next-2.6/net/ipv4/fib_frontend.c
--- linux/net/ipv4/fib_frontend.c	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/fib_frontend.c	2014-10-06 10:49:00.276900921 +0200
@@ -243,7 +243,7 @@
 				 u8 tos, int oif, struct net_device *dev,
 				 int rpf, struct in_device *idev, u32 *itag)
 {
-	int ret, no_addr, accept_local;
+	int ret, no_addr;
 	struct fib_result res;
 	struct flowi4 fl4;
 	struct net *net;
@@ -258,16 +258,17 @@
 
 	no_addr = idev->ifa_list == NULL;
 
-	accept_local = IN_DEV_ACCEPT_LOCAL(idev);
 	fl4.flowi4_mark = IN_DEV_SRC_VMARK(idev) ? skb->mark : 0;
 
 	net = dev_net(dev);
 	if (fib_lookup(net, &fl4, &res))
 		goto last_resort;
-	if (res.type != RTN_UNICAST) {
-		if (res.type != RTN_LOCAL || !accept_local)
-			goto e_inval;
-	}
+	if (res.type != RTN_UNICAST &&
+	    (res.type != RTN_LOCAL || !IN_DEV_ACCEPT_LOCAL(idev)))
+		goto e_inval;
+	if (!rpf && !fib_num_tclassid_users(dev_net(dev)) &&
+	    (dev->ifindex != oif || !IN_DEV_TX_REDIRECTS(idev)))
+		goto last_resort;
 	fib_combine_itag(itag, &res);
 	dev_match = false;
 
@@ -321,6 +322,7 @@
 	int r = secpath_exists(skb) ? 0 : IN_DEV_RPFILTER(idev);
 
 	if (!r && !fib_num_tclassid_users(dev_net(dev)) &&
+	    IN_DEV_ACCEPT_LOCAL(idev) &&
 	    (dev->ifindex != oif || !IN_DEV_TX_REDIRECTS(idev))) {
 		*itag = 0;
 		return 0;
diff -urN linux/net/ipv4/fib_semantics.c net-next-2.6/net/ipv4/fib_semantics.c
--- linux/net/ipv4/fib_semantics.c	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/fib_semantics.c	2014-10-06 10:49:00.300901165 +0200
@@ -157,9 +157,12 @@
 
 static void free_nh_exceptions(struct fib_nh *nh)
 {
-	struct fnhe_hash_bucket *hash = nh->nh_exceptions;
+	struct fnhe_hash_bucket *hash;
 	int i;
 
+	hash = rcu_dereference_protected(nh->nh_exceptions, 1);
+	if (!hash)
+		return;
 	for (i = 0; i < FNHE_HASH_SIZE; i++) {
 		struct fib_nh_exception *fnhe;
 
@@ -205,8 +208,7 @@
 	change_nexthops(fi) {
 		if (nexthop_nh->nh_dev)
 			dev_put(nexthop_nh->nh_dev);
-		if (nexthop_nh->nh_exceptions)
-			free_nh_exceptions(nexthop_nh);
+		free_nh_exceptions(nexthop_nh);
 		rt_fibinfo_free_cpus(nexthop_nh->nh_pcpu_rth_output);
 		rt_fibinfo_free(&nexthop_nh->nh_rth_input);
 	} endfor_nexthops(fi);
diff -urN linux/net/ipv4/fou.c net-next-2.6/net/ipv4/fou.c
--- linux/net/ipv4/fou.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv4/fou.c	2014-10-06 10:49:00.300901165 +0200
@@ -0,0 +1,514 @@
+#include <linux/module.h>
+#include <linux/errno.h>
+#include <linux/socket.h>
+#include <linux/skbuff.h>
+#include <linux/ip.h>
+#include <linux/udp.h>
+#include <linux/types.h>
+#include <linux/kernel.h>
+#include <net/genetlink.h>
+#include <net/gue.h>
+#include <net/ip.h>
+#include <net/protocol.h>
+#include <net/udp.h>
+#include <net/udp_tunnel.h>
+#include <net/xfrm.h>
+#include <uapi/linux/fou.h>
+#include <uapi/linux/genetlink.h>
+
+static DEFINE_SPINLOCK(fou_lock);
+static LIST_HEAD(fou_list);
+
+struct fou {
+	struct socket *sock;
+	u8 protocol;
+	u16 port;
+	struct udp_offload udp_offloads;
+	struct list_head list;
+};
+
+struct fou_cfg {
+	u16 type;
+	u8 protocol;
+	struct udp_port_cfg udp_config;
+};
+
+static inline struct fou *fou_from_sock(struct sock *sk)
+{
+	return sk->sk_user_data;
+}
+
+static int fou_udp_encap_recv_deliver(struct sk_buff *skb,
+				      u8 protocol, size_t len)
+{
+	struct iphdr *iph = ip_hdr(skb);
+
+	/* Remove 'len' bytes from the packet (UDP header and
+	 * FOU header if present), modify the protocol to the one
+	 * we found, and then call rcv_encap.
+	 */
+	iph->tot_len = htons(ntohs(iph->tot_len) - len);
+	__skb_pull(skb, len);
+	skb_postpull_rcsum(skb, udp_hdr(skb), len);
+	skb_reset_transport_header(skb);
+
+	return -protocol;
+}
+
+static int fou_udp_recv(struct sock *sk, struct sk_buff *skb)
+{
+	struct fou *fou = fou_from_sock(sk);
+
+	if (!fou)
+		return 1;
+
+	return fou_udp_encap_recv_deliver(skb, fou->protocol,
+					  sizeof(struct udphdr));
+}
+
+static int gue_udp_recv(struct sock *sk, struct sk_buff *skb)
+{
+	struct fou *fou = fou_from_sock(sk);
+	size_t len;
+	struct guehdr *guehdr;
+	struct udphdr *uh;
+
+	if (!fou)
+		return 1;
+
+	len = sizeof(struct udphdr) + sizeof(struct guehdr);
+	if (!pskb_may_pull(skb, len))
+		goto drop;
+
+	uh = udp_hdr(skb);
+	guehdr = (struct guehdr *)&uh[1];
+
+	len += guehdr->hlen << 2;
+	if (!pskb_may_pull(skb, len))
+		goto drop;
+
+	if (guehdr->version != 0)
+		goto drop;
+
+	if (guehdr->flags) {
+		/* No support yet */
+		goto drop;
+	}
+
+	return fou_udp_encap_recv_deliver(skb, guehdr->next_hdr, len);
+drop:
+	kfree_skb(skb);
+	return 0;
+}
+
+static struct sk_buff **fou_gro_receive(struct sk_buff **head,
+					struct sk_buff *skb)
+{
+	const struct net_offload *ops;
+	struct sk_buff **pp = NULL;
+	u8 proto = NAPI_GRO_CB(skb)->proto;
+	const struct net_offload **offloads;
+
+	rcu_read_lock();
+	offloads = NAPI_GRO_CB(skb)->is_ipv6 ? inet6_offloads : inet_offloads;
+	ops = rcu_dereference(offloads[proto]);
+	if (!ops || !ops->callbacks.gro_receive)
+		goto out_unlock;
+
+	pp = ops->callbacks.gro_receive(head, skb);
+
+out_unlock:
+	rcu_read_unlock();
+
+	return pp;
+}
+
+static int fou_gro_complete(struct sk_buff *skb, int nhoff)
+{
+	const struct net_offload *ops;
+	u8 proto = NAPI_GRO_CB(skb)->proto;
+	int err = -ENOSYS;
+	const struct net_offload **offloads;
+
+	rcu_read_lock();
+	offloads = NAPI_GRO_CB(skb)->is_ipv6 ? inet6_offloads : inet_offloads;
+	ops = rcu_dereference(offloads[proto]);
+	if (WARN_ON(!ops || !ops->callbacks.gro_complete))
+		goto out_unlock;
+
+	err = ops->callbacks.gro_complete(skb, nhoff);
+
+out_unlock:
+	rcu_read_unlock();
+
+	return err;
+}
+
+static struct sk_buff **gue_gro_receive(struct sk_buff **head,
+					struct sk_buff *skb)
+{
+	const struct net_offload **offloads;
+	const struct net_offload *ops;
+	struct sk_buff **pp = NULL;
+	struct sk_buff *p;
+	u8 proto;
+	struct guehdr *guehdr;
+	unsigned int hlen, guehlen;
+	unsigned int off;
+	int flush = 1;
+
+	off = skb_gro_offset(skb);
+	hlen = off + sizeof(*guehdr);
+	guehdr = skb_gro_header_fast(skb, off);
+	if (skb_gro_header_hard(skb, hlen)) {
+		guehdr = skb_gro_header_slow(skb, hlen, off);
+		if (unlikely(!guehdr))
+			goto out;
+	}
+
+	proto = guehdr->next_hdr;
+
+	rcu_read_lock();
+	offloads = NAPI_GRO_CB(skb)->is_ipv6 ? inet6_offloads : inet_offloads;
+	ops = rcu_dereference(offloads[proto]);
+	if (WARN_ON(!ops || !ops->callbacks.gro_receive))
+		goto out_unlock;
+
+	guehlen = sizeof(*guehdr) + (guehdr->hlen << 2);
+
+	hlen = off + guehlen;
+	if (skb_gro_header_hard(skb, hlen)) {
+		guehdr = skb_gro_header_slow(skb, hlen, off);
+		if (unlikely(!guehdr))
+			goto out_unlock;
+	}
+
+	flush = 0;
+
+	for (p = *head; p; p = p->next) {
+		const struct guehdr *guehdr2;
+
+		if (!NAPI_GRO_CB(p)->same_flow)
+			continue;
+
+		guehdr2 = (struct guehdr *)(p->data + off);
+
+		/* Compare base GUE header to be equal (covers
+		 * hlen, version, next_hdr, and flags.
+		 */
+		if (guehdr->word != guehdr2->word) {
+			NAPI_GRO_CB(p)->same_flow = 0;
+			continue;
+		}
+
+		/* Compare optional fields are the same. */
+		if (guehdr->hlen && memcmp(&guehdr[1], &guehdr2[1],
+					   guehdr->hlen << 2)) {
+			NAPI_GRO_CB(p)->same_flow = 0;
+			continue;
+		}
+	}
+
+	skb_gro_pull(skb, guehlen);
+
+	/* Adjusted NAPI_GRO_CB(skb)->csum after skb_gro_pull()*/
+	skb_gro_postpull_rcsum(skb, guehdr, guehlen);
+
+	pp = ops->callbacks.gro_receive(head, skb);
+
+out_unlock:
+	rcu_read_unlock();
+out:
+	NAPI_GRO_CB(skb)->flush |= flush;
+
+	return pp;
+}
+
+static int gue_gro_complete(struct sk_buff *skb, int nhoff)
+{
+	const struct net_offload **offloads;
+	struct guehdr *guehdr = (struct guehdr *)(skb->data + nhoff);
+	const struct net_offload *ops;
+	unsigned int guehlen;
+	u8 proto;
+	int err = -ENOENT;
+
+	proto = guehdr->next_hdr;
+
+	guehlen = sizeof(*guehdr) + (guehdr->hlen << 2);
+
+	rcu_read_lock();
+	offloads = NAPI_GRO_CB(skb)->is_ipv6 ? inet6_offloads : inet_offloads;
+	ops = rcu_dereference(offloads[proto]);
+	if (WARN_ON(!ops || !ops->callbacks.gro_complete))
+		goto out_unlock;
+
+	err = ops->callbacks.gro_complete(skb, nhoff + guehlen);
+
+out_unlock:
+	rcu_read_unlock();
+	return err;
+}
+
+static int fou_add_to_port_list(struct fou *fou)
+{
+	struct fou *fout;
+
+	spin_lock(&fou_lock);
+	list_for_each_entry(fout, &fou_list, list) {
+		if (fou->port == fout->port) {
+			spin_unlock(&fou_lock);
+			return -EALREADY;
+		}
+	}
+
+	list_add(&fou->list, &fou_list);
+	spin_unlock(&fou_lock);
+
+	return 0;
+}
+
+static void fou_release(struct fou *fou)
+{
+	struct socket *sock = fou->sock;
+	struct sock *sk = sock->sk;
+
+	udp_del_offload(&fou->udp_offloads);
+
+	list_del(&fou->list);
+
+	/* Remove hooks into tunnel socket */
+	sk->sk_user_data = NULL;
+
+	sock_release(sock);
+
+	kfree(fou);
+}
+
+static int fou_encap_init(struct sock *sk, struct fou *fou, struct fou_cfg *cfg)
+{
+	udp_sk(sk)->encap_rcv = fou_udp_recv;
+	fou->protocol = cfg->protocol;
+	fou->udp_offloads.callbacks.gro_receive = fou_gro_receive;
+	fou->udp_offloads.callbacks.gro_complete = fou_gro_complete;
+	fou->udp_offloads.port = cfg->udp_config.local_udp_port;
+	fou->udp_offloads.ipproto = cfg->protocol;
+
+	return 0;
+}
+
+static int gue_encap_init(struct sock *sk, struct fou *fou, struct fou_cfg *cfg)
+{
+	udp_sk(sk)->encap_rcv = gue_udp_recv;
+	fou->udp_offloads.callbacks.gro_receive = gue_gro_receive;
+	fou->udp_offloads.callbacks.gro_complete = gue_gro_complete;
+	fou->udp_offloads.port = cfg->udp_config.local_udp_port;
+
+	return 0;
+}
+
+static int fou_create(struct net *net, struct fou_cfg *cfg,
+		      struct socket **sockp)
+{
+	struct fou *fou = NULL;
+	int err;
+	struct socket *sock = NULL;
+	struct sock *sk;
+
+	/* Open UDP socket */
+	err = udp_sock_create(net, &cfg->udp_config, &sock);
+	if (err < 0)
+		goto error;
+
+	/* Allocate FOU port structure */
+	fou = kzalloc(sizeof(*fou), GFP_KERNEL);
+	if (!fou) {
+		err = -ENOMEM;
+		goto error;
+	}
+
+	sk = sock->sk;
+
+	fou->port = cfg->udp_config.local_udp_port;
+
+	/* Initial for fou type */
+	switch (cfg->type) {
+	case FOU_ENCAP_DIRECT:
+		err = fou_encap_init(sk, fou, cfg);
+		if (err)
+			goto error;
+		break;
+	case FOU_ENCAP_GUE:
+		err = gue_encap_init(sk, fou, cfg);
+		if (err)
+			goto error;
+		break;
+	default:
+		err = -EINVAL;
+		goto error;
+	}
+
+	udp_sk(sk)->encap_type = 1;
+	udp_encap_enable();
+
+	sk->sk_user_data = fou;
+	fou->sock = sock;
+
+	udp_set_convert_csum(sk, true);
+
+	sk->sk_allocation = GFP_ATOMIC;
+
+	if (cfg->udp_config.family == AF_INET) {
+		err = udp_add_offload(&fou->udp_offloads);
+		if (err)
+			goto error;
+	}
+
+	err = fou_add_to_port_list(fou);
+	if (err)
+		goto error;
+
+	if (sockp)
+		*sockp = sock;
+
+	return 0;
+
+error:
+	kfree(fou);
+	if (sock)
+		sock_release(sock);
+
+	return err;
+}
+
+static int fou_destroy(struct net *net, struct fou_cfg *cfg)
+{
+	struct fou *fou;
+	u16 port = cfg->udp_config.local_udp_port;
+	int err = -EINVAL;
+
+	spin_lock(&fou_lock);
+	list_for_each_entry(fou, &fou_list, list) {
+		if (fou->port == port) {
+			udp_del_offload(&fou->udp_offloads);
+			fou_release(fou);
+			err = 0;
+			break;
+		}
+	}
+	spin_unlock(&fou_lock);
+
+	return err;
+}
+
+static struct genl_family fou_nl_family = {
+	.id		= GENL_ID_GENERATE,
+	.hdrsize	= 0,
+	.name		= FOU_GENL_NAME,
+	.version	= FOU_GENL_VERSION,
+	.maxattr	= FOU_ATTR_MAX,
+	.netnsok	= true,
+};
+
+static struct nla_policy fou_nl_policy[FOU_ATTR_MAX + 1] = {
+	[FOU_ATTR_PORT] = { .type = NLA_U16, },
+	[FOU_ATTR_AF] = { .type = NLA_U8, },
+	[FOU_ATTR_IPPROTO] = { .type = NLA_U8, },
+	[FOU_ATTR_TYPE] = { .type = NLA_U8, },
+};
+
+static int parse_nl_config(struct genl_info *info,
+			   struct fou_cfg *cfg)
+{
+	memset(cfg, 0, sizeof(*cfg));
+
+	cfg->udp_config.family = AF_INET;
+
+	if (info->attrs[FOU_ATTR_AF]) {
+		u8 family = nla_get_u8(info->attrs[FOU_ATTR_AF]);
+
+		if (family != AF_INET && family != AF_INET6)
+			return -EINVAL;
+
+		cfg->udp_config.family = family;
+	}
+
+	if (info->attrs[FOU_ATTR_PORT]) {
+		u16 port = nla_get_u16(info->attrs[FOU_ATTR_PORT]);
+
+		cfg->udp_config.local_udp_port = port;
+	}
+
+	if (info->attrs[FOU_ATTR_IPPROTO])
+		cfg->protocol = nla_get_u8(info->attrs[FOU_ATTR_IPPROTO]);
+
+	if (info->attrs[FOU_ATTR_TYPE])
+		cfg->type = nla_get_u8(info->attrs[FOU_ATTR_TYPE]);
+
+	return 0;
+}
+
+static int fou_nl_cmd_add_port(struct sk_buff *skb, struct genl_info *info)
+{
+	struct fou_cfg cfg;
+	int err;
+
+	err = parse_nl_config(info, &cfg);
+	if (err)
+		return err;
+
+	return fou_create(&init_net, &cfg, NULL);
+}
+
+static int fou_nl_cmd_rm_port(struct sk_buff *skb, struct genl_info *info)
+{
+	struct fou_cfg cfg;
+
+	parse_nl_config(info, &cfg);
+
+	return fou_destroy(&init_net, &cfg);
+}
+
+static const struct genl_ops fou_nl_ops[] = {
+	{
+		.cmd = FOU_CMD_ADD,
+		.doit = fou_nl_cmd_add_port,
+		.policy = fou_nl_policy,
+		.flags = GENL_ADMIN_PERM,
+	},
+	{
+		.cmd = FOU_CMD_DEL,
+		.doit = fou_nl_cmd_rm_port,
+		.policy = fou_nl_policy,
+		.flags = GENL_ADMIN_PERM,
+	},
+};
+
+static int __init fou_init(void)
+{
+	int ret;
+
+	ret = genl_register_family_with_ops(&fou_nl_family,
+					    fou_nl_ops);
+
+	return ret;
+}
+
+static void __exit fou_fini(void)
+{
+	struct fou *fou, *next;
+
+	genl_unregister_family(&fou_nl_family);
+
+	/* Close all the FOU sockets */
+
+	spin_lock(&fou_lock);
+	list_for_each_entry_safe(fou, next, &fou_list, list)
+		fou_release(fou);
+	spin_unlock(&fou_lock);
+}
+
+module_init(fou_init);
+module_exit(fou_fini);
+MODULE_AUTHOR("Tom Herbert <therbert@google.com>");
+MODULE_LICENSE("GPL");
diff -urN linux/net/ipv4/geneve.c net-next-2.6/net/ipv4/geneve.c
--- linux/net/ipv4/geneve.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv4/geneve.c	2014-10-06 10:49:00.300901165 +0200
@@ -0,0 +1,373 @@
+/*
+ * Geneve: Generic Network Virtualization Encapsulation
+ *
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
+#include <linux/kernel.h>
+#include <linux/types.h>
+#include <linux/module.h>
+#include <linux/errno.h>
+#include <linux/slab.h>
+#include <linux/skbuff.h>
+#include <linux/rculist.h>
+#include <linux/netdevice.h>
+#include <linux/in.h>
+#include <linux/ip.h>
+#include <linux/udp.h>
+#include <linux/igmp.h>
+#include <linux/etherdevice.h>
+#include <linux/if_ether.h>
+#include <linux/if_vlan.h>
+#include <linux/hash.h>
+#include <linux/ethtool.h>
+#include <net/arp.h>
+#include <net/ndisc.h>
+#include <net/ip.h>
+#include <net/ip_tunnels.h>
+#include <net/icmp.h>
+#include <net/udp.h>
+#include <net/rtnetlink.h>
+#include <net/route.h>
+#include <net/dsfield.h>
+#include <net/inet_ecn.h>
+#include <net/net_namespace.h>
+#include <net/netns/generic.h>
+#include <net/geneve.h>
+#include <net/protocol.h>
+#include <net/udp_tunnel.h>
+#if IS_ENABLED(CONFIG_IPV6)
+#include <net/ipv6.h>
+#include <net/addrconf.h>
+#include <net/ip6_tunnel.h>
+#include <net/ip6_checksum.h>
+#endif
+
+#define PORT_HASH_BITS 8
+#define PORT_HASH_SIZE (1<<PORT_HASH_BITS)
+
+/* per-network namespace private data for this module */
+struct geneve_net {
+	struct hlist_head	sock_list[PORT_HASH_SIZE];
+	spinlock_t		sock_lock;   /* Protects sock_list */
+};
+
+static int geneve_net_id;
+
+static struct workqueue_struct *geneve_wq;
+
+static inline struct genevehdr *geneve_hdr(const struct sk_buff *skb)
+{
+	return (struct genevehdr *)(udp_hdr(skb) + 1);
+}
+
+static struct hlist_head *gs_head(struct net *net, __be16 port)
+{
+	struct geneve_net *gn = net_generic(net, geneve_net_id);
+
+	return &gn->sock_list[hash_32(ntohs(port), PORT_HASH_BITS)];
+}
+
+/* Find geneve socket based on network namespace and UDP port */
+static struct geneve_sock *geneve_find_sock(struct net *net, __be16 port)
+{
+	struct geneve_sock *gs;
+
+	hlist_for_each_entry_rcu(gs, gs_head(net, port), hlist) {
+		if (inet_sk(gs->sock->sk)->inet_sport == port)
+			return gs;
+	}
+
+	return NULL;
+}
+
+static void geneve_build_header(struct genevehdr *geneveh,
+				__be16 tun_flags, u8 vni[3],
+				u8 options_len, u8 *options)
+{
+	geneveh->ver = GENEVE_VER;
+	geneveh->opt_len = options_len / 4;
+	geneveh->oam = !!(tun_flags & TUNNEL_OAM);
+	geneveh->critical = !!(tun_flags & TUNNEL_CRIT_OPT);
+	geneveh->rsvd1 = 0;
+	memcpy(geneveh->vni, vni, 3);
+	geneveh->proto_type = htons(ETH_P_TEB);
+	geneveh->rsvd2 = 0;
+
+	memcpy(geneveh->options, options, options_len);
+}
+
+/* Transmit a fully formated Geneve frame.
+ *
+ * When calling this function. The skb->data should point
+ * to the geneve header which is fully formed.
+ *
+ * This function will add other UDP tunnel headers.
+ */
+int geneve_xmit_skb(struct geneve_sock *gs, struct rtable *rt,
+		    struct sk_buff *skb, __be32 src, __be32 dst, __u8 tos,
+		    __u8 ttl, __be16 df, __be16 src_port, __be16 dst_port,
+		    __be16 tun_flags, u8 vni[3], u8 opt_len, u8 *opt,
+		    bool xnet)
+{
+	struct genevehdr *gnvh;
+	int min_headroom;
+	int err;
+
+	skb = udp_tunnel_handle_offloads(skb, !gs->sock->sk->sk_no_check_tx);
+
+	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
+			+ GENEVE_BASE_HLEN + opt_len + sizeof(struct iphdr)
+			+ (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);
+
+	err = skb_cow_head(skb, min_headroom);
+	if (unlikely(err))
+		return err;
+
+	if (vlan_tx_tag_present(skb)) {
+		if (unlikely(!__vlan_put_tag(skb,
+					     skb->vlan_proto,
+					     vlan_tx_tag_get(skb)))) {
+			err = -ENOMEM;
+			return err;
+		}
+		skb->vlan_tci = 0;
+	}
+
+	gnvh = (struct genevehdr *)__skb_push(skb, sizeof(*gnvh) + opt_len);
+	geneve_build_header(gnvh, tun_flags, vni, opt_len, opt);
+
+	return udp_tunnel_xmit_skb(gs->sock, rt, skb, src, dst,
+				   tos, ttl, df, src_port, dst_port, xnet);
+}
+EXPORT_SYMBOL_GPL(geneve_xmit_skb);
+
+static void geneve_notify_add_rx_port(struct geneve_sock *gs)
+{
+	struct sock *sk = gs->sock->sk;
+	sa_family_t sa_family = sk->sk_family;
+	int err;
+
+	if (sa_family == AF_INET) {
+		err = udp_add_offload(&gs->udp_offloads);
+		if (err)
+			pr_warn("geneve: udp_add_offload failed with status %d\n",
+				err);
+	}
+}
+
+/* Callback from net/ipv4/udp.c to receive packets */
+static int geneve_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
+{
+	struct genevehdr *geneveh;
+	struct geneve_sock *gs;
+	int opts_len;
+
+	/* Need Geneve and inner Ethernet header to be present */
+	if (unlikely(!pskb_may_pull(skb, GENEVE_BASE_HLEN)))
+		goto error;
+
+	/* Return packets with reserved bits set */
+	geneveh = geneve_hdr(skb);
+
+	if (unlikely(geneveh->ver != GENEVE_VER))
+		goto error;
+
+	if (unlikely(geneveh->proto_type != htons(ETH_P_TEB)))
+		goto error;
+
+	opts_len = geneveh->opt_len * 4;
+	if (iptunnel_pull_header(skb, GENEVE_BASE_HLEN + opts_len,
+				 htons(ETH_P_TEB)))
+		goto drop;
+
+	gs = rcu_dereference_sk_user_data(sk);
+	if (!gs)
+		goto drop;
+
+	gs->rcv(gs, skb);
+	return 0;
+
+drop:
+	/* Consume bad packet */
+	kfree_skb(skb);
+	return 0;
+
+error:
+	/* Let the UDP layer deal with the skb */
+	return 1;
+}
+
+static void geneve_del_work(struct work_struct *work)
+{
+	struct geneve_sock *gs = container_of(work, struct geneve_sock,
+					      del_work);
+
+	udp_tunnel_sock_release(gs->sock);
+	kfree_rcu(gs, rcu);
+}
+
+static struct socket *geneve_create_sock(struct net *net, bool ipv6,
+					 __be16 port)
+{
+	struct socket *sock;
+	struct udp_port_cfg udp_conf;
+	int err;
+
+	memset(&udp_conf, 0, sizeof(udp_conf));
+
+	if (ipv6) {
+		udp_conf.family = AF_INET6;
+	} else {
+		udp_conf.family = AF_INET;
+		udp_conf.local_ip.s_addr = INADDR_ANY;
+	}
+
+	udp_conf.local_udp_port = port;
+
+	/* Open UDP socket */
+	err = udp_sock_create(net, &udp_conf, &sock);
+	if (err < 0)
+		return ERR_PTR(err);
+
+	return sock;
+}
+
+/* Create new listen socket if needed */
+static struct geneve_sock *geneve_socket_create(struct net *net, __be16 port,
+						geneve_rcv_t *rcv, void *data,
+						bool ipv6)
+{
+	struct geneve_net *gn = net_generic(net, geneve_net_id);
+	struct geneve_sock *gs;
+	struct socket *sock;
+	struct udp_tunnel_sock_cfg tunnel_cfg;
+
+	gs = kzalloc(sizeof(*gs), GFP_KERNEL);
+	if (!gs)
+		return ERR_PTR(-ENOMEM);
+
+	INIT_WORK(&gs->del_work, geneve_del_work);
+
+	sock = geneve_create_sock(net, ipv6, port);
+	if (IS_ERR(sock)) {
+		kfree(gs);
+		return ERR_CAST(sock);
+	}
+
+	gs->sock = sock;
+	atomic_set(&gs->refcnt, 1);
+	gs->rcv = rcv;
+	gs->rcv_data = data;
+
+	/* Initialize the geneve udp offloads structure */
+	gs->udp_offloads.port = port;
+	gs->udp_offloads.callbacks.gro_receive = NULL;
+	gs->udp_offloads.callbacks.gro_complete = NULL;
+
+	spin_lock(&gn->sock_lock);
+	hlist_add_head_rcu(&gs->hlist, gs_head(net, port));
+	geneve_notify_add_rx_port(gs);
+	spin_unlock(&gn->sock_lock);
+
+	/* Mark socket as an encapsulation socket */
+	tunnel_cfg.sk_user_data = gs;
+	tunnel_cfg.encap_type = 1;
+	tunnel_cfg.encap_rcv = geneve_udp_encap_recv;
+	tunnel_cfg.encap_destroy = NULL;
+	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);
+
+	return gs;
+}
+
+struct geneve_sock *geneve_sock_add(struct net *net, __be16 port,
+				    geneve_rcv_t *rcv, void *data,
+				    bool no_share, bool ipv6)
+{
+	struct geneve_sock *gs;
+
+	gs = geneve_socket_create(net, port, rcv, data, ipv6);
+	if (!IS_ERR(gs))
+		return gs;
+
+	if (no_share)	/* Return error if sharing is not allowed. */
+		return ERR_PTR(-EINVAL);
+
+	gs = geneve_find_sock(net, port);
+	if (gs) {
+		if (gs->rcv == rcv)
+			atomic_inc(&gs->refcnt);
+		else
+			gs = ERR_PTR(-EBUSY);
+	} else {
+		gs = ERR_PTR(-EINVAL);
+	}
+
+	return gs;
+}
+EXPORT_SYMBOL_GPL(geneve_sock_add);
+
+void geneve_sock_release(struct geneve_sock *gs)
+{
+	if (!atomic_dec_and_test(&gs->refcnt))
+		return;
+
+	queue_work(geneve_wq, &gs->del_work);
+}
+EXPORT_SYMBOL_GPL(geneve_sock_release);
+
+static __net_init int geneve_init_net(struct net *net)
+{
+	struct geneve_net *gn = net_generic(net, geneve_net_id);
+	unsigned int h;
+
+	spin_lock_init(&gn->sock_lock);
+
+	for (h = 0; h < PORT_HASH_SIZE; ++h)
+		INIT_HLIST_HEAD(&gn->sock_list[h]);
+
+	return 0;
+}
+
+static struct pernet_operations geneve_net_ops = {
+	.init = geneve_init_net,
+	.exit = NULL,
+	.id   = &geneve_net_id,
+	.size = sizeof(struct geneve_net),
+};
+
+static int __init geneve_init_module(void)
+{
+	int rc;
+
+	geneve_wq = alloc_workqueue("geneve", 0, 0);
+	if (!geneve_wq)
+		return -ENOMEM;
+
+	rc = register_pernet_subsys(&geneve_net_ops);
+	if (rc)
+		return rc;
+
+	pr_info("Geneve driver\n");
+
+	return 0;
+}
+late_initcall(geneve_init_module);
+
+static void __exit geneve_cleanup_module(void)
+{
+	destroy_workqueue(geneve_wq);
+}
+module_exit(geneve_cleanup_module);
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Jesse Gross <jesse@nicira.com>");
+MODULE_DESCRIPTION("Driver for GENEVE encapsulated traffic");
+MODULE_ALIAS_RTNL_LINK("geneve");
diff -urN linux/net/ipv4/gre_demux.c net-next-2.6/net/ipv4/gre_demux.c
--- linux/net/ipv4/gre_demux.c	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/gre_demux.c	2014-10-06 10:49:00.300901165 +0200
@@ -98,7 +98,6 @@
 static int parse_gre_header(struct sk_buff *skb, struct tnl_ptk_info *tpi,
 			    bool *csum_err)
 {
-	unsigned int ip_hlen = ip_hdrlen(skb);
 	const struct gre_base_hdr *greh;
 	__be32 *options;
 	int hdr_len;
@@ -106,7 +105,7 @@
 	if (unlikely(!pskb_may_pull(skb, sizeof(struct gre_base_hdr))))
 		return -EINVAL;
 
-	greh = (struct gre_base_hdr *)(skb_network_header(skb) + ip_hlen);
+	greh = (struct gre_base_hdr *)skb_transport_header(skb);
 	if (unlikely(greh->flags & (GRE_VERSION | GRE_ROUTING)))
 		return -EINVAL;
 
@@ -116,7 +115,7 @@
 	if (!pskb_may_pull(skb, hdr_len))
 		return -EINVAL;
 
-	greh = (struct gre_base_hdr *)(skb_network_header(skb) + ip_hlen);
+	greh = (struct gre_base_hdr *)skb_transport_header(skb);
 	tpi->proto = greh->protocol;
 
 	options = (__be32 *)(greh + 1);
@@ -125,6 +124,10 @@
 			*csum_err = true;
 			return -EINVAL;
 		}
+
+		skb_checksum_try_convert(skb, IPPROTO_GRE, 0,
+					 null_compute_pseudo);
+
 		options++;
 	}
 
diff -urN linux/net/ipv4/gre_offload.c net-next-2.6/net/ipv4/gre_offload.c
--- linux/net/ipv4/gre_offload.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/gre_offload.c	2014-10-06 10:49:00.300901165 +0200
@@ -15,13 +15,6 @@
 #include <net/protocol.h>
 #include <net/gre.h>
 
-static int gre_gso_send_check(struct sk_buff *skb)
-{
-	if (!skb->encapsulation)
-		return -EINVAL;
-	return 0;
-}
-
 static struct sk_buff *gre_gso_segment(struct sk_buff *skb,
 				       netdev_features_t features)
 {
@@ -46,6 +39,9 @@
 				  SKB_GSO_IPIP)))
 		goto out;
 
+	if (!skb->encapsulation)
+		goto out;
+
 	if (unlikely(!pskb_may_pull(skb, sizeof(*greh))))
 		goto out;
 
@@ -119,28 +115,6 @@
 	return segs;
 }
 
-/* Compute the whole skb csum in s/w and store it, then verify GRO csum
- * starting from gro_offset.
- */
-static __sum16 gro_skb_checksum(struct sk_buff *skb)
-{
-	__sum16 sum;
-
-	skb->csum = skb_checksum(skb, 0, skb->len, 0);
-	NAPI_GRO_CB(skb)->csum = csum_sub(skb->csum,
-		csum_partial(skb->data, skb_gro_offset(skb), 0));
-	sum = csum_fold(NAPI_GRO_CB(skb)->csum);
-	if (unlikely(skb->ip_summed == CHECKSUM_COMPLETE)) {
-		if (unlikely(!sum) && !skb->csum_complete_sw)
-			netdev_rx_csum_fault(skb->dev);
-	} else {
-		skb->ip_summed = CHECKSUM_COMPLETE;
-		skb->csum_complete_sw = 1;
-	}
-
-	return sum;
-}
-
 static struct sk_buff **gre_gro_receive(struct sk_buff **head,
 					struct sk_buff *skb)
 {
@@ -192,22 +166,16 @@
 		if (unlikely(!greh))
 			goto out_unlock;
 	}
-	if (greh->flags & GRE_CSUM) { /* Need to verify GRE csum first */
-		__sum16 csum = 0;
 
-		if (skb->ip_summed == CHECKSUM_COMPLETE)
-			csum = csum_fold(NAPI_GRO_CB(skb)->csum);
-		/* Don't trust csum error calculated/reported by h/w */
-		if (skb->ip_summed == CHECKSUM_NONE || csum != 0)
-			csum = gro_skb_checksum(skb);
-
-		/* GRE CSUM is the 1's complement of the 1's complement sum
-		 * of the GRE hdr plus payload so it should add up to 0xffff
-		 * (and 0 after csum_fold()) just like the IPv4 hdr csum.
-		 */
-		if (csum)
+	/* Don't bother verifying checksum if we're going to flush anyway. */
+	if ((greh->flags & GRE_CSUM) && !NAPI_GRO_CB(skb)->flush) {
+		if (skb_gro_checksum_simple_validate(skb))
 			goto out_unlock;
+
+		skb_gro_checksum_try_convert(skb, IPPROTO_GRE, 0,
+					     null_compute_pseudo);
 	}
+
 	flush = 0;
 
 	for (p = *head; p; p = p->next) {
@@ -284,7 +252,6 @@
 
 static const struct net_offload gre_offload = {
 	.callbacks = {
-		.gso_send_check = gre_gso_send_check,
 		.gso_segment = gre_gso_segment,
 		.gro_receive = gre_gro_receive,
 		.gro_complete = gre_gro_complete,
diff -urN linux/net/ipv4/icmp.c net-next-2.6/net/ipv4/icmp.c
--- linux/net/ipv4/icmp.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/icmp.c	2014-10-06 10:49:00.300901165 +0200
@@ -231,12 +231,62 @@
 	spin_unlock_bh(&sk->sk_lock.slock);
 }
 
+int sysctl_icmp_msgs_per_sec __read_mostly = 1000;
+int sysctl_icmp_msgs_burst __read_mostly = 50;
+
+static struct {
+	spinlock_t	lock;
+	u32		credit;
+	u32		stamp;
+} icmp_global = {
+	.lock		= __SPIN_LOCK_UNLOCKED(icmp_global.lock),
+};
+
+/**
+ * icmp_global_allow - Are we allowed to send one more ICMP message ?
+ *
+ * Uses a token bucket to limit our ICMP messages to sysctl_icmp_msgs_per_sec.
+ * Returns false if we reached the limit and can not send another packet.
+ * Note: called with BH disabled
+ */
+bool icmp_global_allow(void)
+{
+	u32 credit, delta, incr = 0, now = (u32)jiffies;
+	bool rc = false;
+
+	/* Check if token bucket is empty and cannot be refilled
+	 * without taking the spinlock.
+	 */
+	if (!icmp_global.credit) {
+		delta = min_t(u32, now - icmp_global.stamp, HZ);
+		if (delta < HZ / 50)
+			return false;
+	}
+
+	spin_lock(&icmp_global.lock);
+	delta = min_t(u32, now - icmp_global.stamp, HZ);
+	if (delta >= HZ / 50) {
+		incr = sysctl_icmp_msgs_per_sec * delta / HZ ;
+		if (incr)
+			icmp_global.stamp = now;
+	}
+	credit = min_t(u32, icmp_global.credit + incr, sysctl_icmp_msgs_burst);
+	if (credit) {
+		credit--;
+		rc = true;
+	}
+	icmp_global.credit = credit;
+	spin_unlock(&icmp_global.lock);
+	return rc;
+}
+EXPORT_SYMBOL(icmp_global_allow);
+
 /*
  *	Send an ICMP frame.
  */
 
-static inline bool icmpv4_xrlim_allow(struct net *net, struct rtable *rt,
-				      struct flowi4 *fl4, int type, int code)
+static bool icmpv4_xrlim_allow(struct net *net, struct rtable *rt,
+			       struct flowi4 *fl4, int type, int code)
 {
 	struct dst_entry *dst = &rt->dst;
 	bool rc = true;
@@ -253,8 +303,14 @@
 		goto out;
 
 	/* Limit if icmp type is enabled in ratemask. */
-	if ((1 << type) & net->ipv4.sysctl_icmp_ratemask) {
-		struct inet_peer *peer = inet_getpeer_v4(net->ipv4.peers, fl4->daddr, 1);
+	if (!((1 << type) & net->ipv4.sysctl_icmp_ratemask))
+		goto out;
+
+	rc = false;
+	if (icmp_global_allow()) {
+		struct inet_peer *peer;
+
+		peer = inet_getpeer_v4(net->ipv4.peers, fl4->daddr, 1);
 		rc = inet_peer_xrlim_allow(peer,
 					   net->ipv4.sysctl_icmp_ratelimit);
 		if (peer)
diff -urN linux/net/ipv4/igmp.c net-next-2.6/net/ipv4/igmp.c
--- linux/net/ipv4/igmp.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/igmp.c	2014-10-06 10:49:00.300901165 +0200
@@ -117,7 +117,7 @@
 #define IGMP_V2_Unsolicited_Report_Interval	(10*HZ)
 #define IGMP_V3_Unsolicited_Report_Interval	(1*HZ)
 #define IGMP_Query_Response_Interval		(10*HZ)
-#define IGMP_Unsolicited_Report_Count		2
+#define IGMP_Query_Robustness_Variable		2
 
 
 #define IGMP_Initial_Report_Delay		(1)
@@ -756,8 +756,7 @@
 {
 	if (IGMP_V1_SEEN(in_dev) || IGMP_V2_SEEN(in_dev))
 		return;
-	in_dev->mr_ifc_count = in_dev->mr_qrv ? in_dev->mr_qrv :
-		IGMP_Unsolicited_Report_Count;
+	in_dev->mr_ifc_count = in_dev->mr_qrv ?: sysctl_igmp_qrv;
 	igmp_ifc_start_timer(in_dev, 1);
 }
 
@@ -1086,8 +1085,7 @@
 	pmc->interface = im->interface;
 	in_dev_hold(in_dev);
 	pmc->multiaddr = im->multiaddr;
-	pmc->crcount = in_dev->mr_qrv ? in_dev->mr_qrv :
-		IGMP_Unsolicited_Report_Count;
+	pmc->crcount = in_dev->mr_qrv ?: sysctl_igmp_qrv;
 	pmc->sfmode = im->sfmode;
 	if (pmc->sfmode == MCAST_INCLUDE) {
 		struct ip_sf_list *psf;
@@ -1226,8 +1224,7 @@
 	}
 	/* else, v3 */
 
-	im->crcount = in_dev->mr_qrv ? in_dev->mr_qrv :
-		IGMP_Unsolicited_Report_Count;
+	im->crcount = in_dev->mr_qrv ?: sysctl_igmp_qrv;
 	igmp_ifc_event(in_dev);
 #endif
 }
@@ -1322,7 +1319,7 @@
 	spin_lock_init(&im->lock);
 #ifdef CONFIG_IP_MULTICAST
 	setup_timer(&im->timer, igmp_timer_expire, (unsigned long)im);
-	im->unsolicit_count = IGMP_Unsolicited_Report_Count;
+	im->unsolicit_count = sysctl_igmp_qrv;
 #endif
 
 	im->next_rcu = in_dev->mc_list;
@@ -1460,7 +1457,7 @@
 			(unsigned long)in_dev);
 	setup_timer(&in_dev->mr_ifc_timer, igmp_ifc_timer_expire,
 			(unsigned long)in_dev);
-	in_dev->mr_qrv = IGMP_Unsolicited_Report_Count;
+	in_dev->mr_qrv = sysctl_igmp_qrv;
 #endif
 
 	spin_lock_init(&in_dev->mc_tomb_lock);
@@ -1474,6 +1471,9 @@
 
 	ASSERT_RTNL();
 
+#ifdef CONFIG_IP_MULTICAST
+	in_dev->mr_qrv = sysctl_igmp_qrv;
+#endif
 	ip_mc_inc_group(in_dev, IGMP_ALL_HOSTS);
 
 	for_each_pmc_rtnl(in_dev, pmc)
@@ -1540,7 +1540,9 @@
  */
 int sysctl_igmp_max_memberships __read_mostly = IP_MAX_MEMBERSHIPS;
 int sysctl_igmp_max_msf __read_mostly = IP_MAX_MSF;
-
+#ifdef CONFIG_IP_MULTICAST
+int sysctl_igmp_qrv __read_mostly = IGMP_Query_Robustness_Variable;
+#endif
 
 static int ip_mc_del1_src(struct ip_mc_list *pmc, int sfmode,
 	__be32 *psfsrc)
@@ -1575,8 +1577,7 @@
 #ifdef CONFIG_IP_MULTICAST
 		if (psf->sf_oldin &&
 		    !IGMP_V1_SEEN(in_dev) && !IGMP_V2_SEEN(in_dev)) {
-			psf->sf_crcount = in_dev->mr_qrv ? in_dev->mr_qrv :
-				IGMP_Unsolicited_Report_Count;
+			psf->sf_crcount = in_dev->mr_qrv ?: sysctl_igmp_qrv;
 			psf->sf_next = pmc->tomb;
 			pmc->tomb = psf;
 			rv = 1;
@@ -1639,8 +1640,7 @@
 		/* filter mode change */
 		pmc->sfmode = MCAST_INCLUDE;
 #ifdef CONFIG_IP_MULTICAST
-		pmc->crcount = in_dev->mr_qrv ? in_dev->mr_qrv :
-			IGMP_Unsolicited_Report_Count;
+		pmc->crcount = in_dev->mr_qrv ?: sysctl_igmp_qrv;
 		in_dev->mr_ifc_count = pmc->crcount;
 		for (psf = pmc->sources; psf; psf = psf->sf_next)
 			psf->sf_crcount = 0;
@@ -1818,8 +1818,7 @@
 #ifdef CONFIG_IP_MULTICAST
 		/* else no filters; keep old mode for reports */
 
-		pmc->crcount = in_dev->mr_qrv ? in_dev->mr_qrv :
-			IGMP_Unsolicited_Report_Count;
+		pmc->crcount = in_dev->mr_qrv ?: sysctl_igmp_qrv;
 		in_dev->mr_ifc_count = pmc->crcount;
 		for (psf = pmc->sources; psf; psf = psf->sf_next)
 			psf->sf_crcount = 0;
@@ -2539,7 +2538,7 @@
 		querier = "NONE";
 #endif
 
-		if (rcu_dereference(state->in_dev->mc_list) == im) {
+		if (rcu_access_pointer(state->in_dev->mc_list) == im) {
 			seq_printf(seq, "%d\t%-10s: %5d %7s\n",
 				   state->dev->ifindex, state->dev->name, state->in_dev->mc_count, querier);
 		}
diff -urN linux/net/ipv4/inet_hashtables.c net-next-2.6/net/ipv4/inet_hashtables.c
--- linux/net/ipv4/inet_hashtables.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/inet_hashtables.c	2014-10-06 10:49:00.304901207 +0200
@@ -229,7 +229,7 @@
 			}
 		} else if (score == hiscore && reuseport) {
 			matches++;
-			if (((u64)phash * matches) >> 32 == 0)
+			if (reciprocal_scale(phash, matches) == 0)
 				result = sk;
 			phash = next_pseudo_random32(phash);
 		}
diff -urN linux/net/ipv4/inetpeer.c net-next-2.6/net/ipv4/inetpeer.c
--- linux/net/ipv4/inetpeer.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/inetpeer.c	2014-10-06 10:49:00.304901207 +0200
@@ -72,29 +72,10 @@
 {
 	bp->root = peer_avl_empty_rcu;
 	seqlock_init(&bp->lock);
-	bp->flush_seq = ~0U;
 	bp->total = 0;
 }
 EXPORT_SYMBOL_GPL(inet_peer_base_init);
 
-static atomic_t v4_seq = ATOMIC_INIT(0);
-static atomic_t v6_seq = ATOMIC_INIT(0);
-
-static atomic_t *inetpeer_seq_ptr(int family)
-{
-	return (family == AF_INET ? &v4_seq : &v6_seq);
-}
-
-static inline void flush_check(struct inet_peer_base *base, int family)
-{
-	atomic_t *fp = inetpeer_seq_ptr(family);
-
-	if (unlikely(base->flush_seq != atomic_read(fp))) {
-		inetpeer_invalidate_tree(base);
-		base->flush_seq = atomic_read(fp);
-	}
-}
-
 #define PEER_MAXDEPTH 40 /* sufficient for about 2^27 nodes */
 
 /* Exported for sysctl_net_ipv4.  */
@@ -444,8 +425,6 @@
 	unsigned int sequence;
 	int invalidated, gccnt = 0;
 
-	flush_check(base, daddr->family);
-
 	/* Attempt a lockless lookup first.
 	 * Because of a concurrent writer, we might not find an existing entry.
 	 */
diff -urN linux/net/ipv4/ipconfig.c net-next-2.6/net/ipv4/ipconfig.c
--- linux/net/ipv4/ipconfig.c	2014-09-24 09:52:43.152644082 +0200
+++ net-next-2.6/net/ipv4/ipconfig.c	2014-10-06 10:49:00.308901247 +0200
@@ -262,7 +262,8 @@
 	/* wait for a carrier on at least one device */
 	start = jiffies;
 	next_msg = start + msecs_to_jiffies(CONF_CARRIER_TIMEOUT/12);
-	while (jiffies - start < msecs_to_jiffies(CONF_CARRIER_TIMEOUT)) {
+	while (time_before(jiffies, start +
+			   msecs_to_jiffies(CONF_CARRIER_TIMEOUT))) {
 		int wait, elapsed;
 
 		for_each_netdev(&init_net, dev)
diff -urN linux/net/ipv4/ip_fragment.c net-next-2.6/net/ipv4/ip_fragment.c
--- linux/net/ipv4/ip_fragment.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/ip_fragment.c	2014-10-06 10:49:00.304901207 +0200
@@ -790,7 +790,7 @@
 	kfree(table);
 }
 
-static void ip4_frags_ctl_register(void)
+static void __init ip4_frags_ctl_register(void)
 {
 	register_net_sysctl(&init_net, "net/ipv4", ip4_frags_ctl_table);
 }
@@ -804,7 +804,7 @@
 {
 }
 
-static inline void ip4_frags_ctl_register(void)
+static inline void __init ip4_frags_ctl_register(void)
 {
 }
 #endif
diff -urN linux/net/ipv4/ip_gre.c net-next-2.6/net/ipv4/ip_gre.c
--- linux/net/ipv4/ip_gre.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/ip_gre.c	2014-10-06 10:49:00.304901207 +0200
@@ -239,7 +239,9 @@
 	tpi.seq = htonl(tunnel->o_seqno);
 
 	/* Push GRE header. */
-	gre_build_header(skb, &tpi, tunnel->hlen);
+	gre_build_header(skb, &tpi, tunnel->tun_hlen);
+
+	skb_set_inner_protocol(skb, tpi.proto);
 
 	ip_tunnel_xmit(skb, dev, tnl_params, tnl_params->protocol);
 }
@@ -310,7 +312,7 @@
 static int ipgre_tunnel_ioctl(struct net_device *dev,
 			      struct ifreq *ifr, int cmd)
 {
-	int err = 0;
+	int err;
 	struct ip_tunnel_parm p;
 
 	if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
@@ -470,13 +472,18 @@
 static void __gre_tunnel_init(struct net_device *dev)
 {
 	struct ip_tunnel *tunnel;
+	int t_hlen;
 
 	tunnel = netdev_priv(dev);
-	tunnel->hlen = ip_gre_calc_hlen(tunnel->parms.o_flags);
+	tunnel->tun_hlen = ip_gre_calc_hlen(tunnel->parms.o_flags);
 	tunnel->parms.iph.protocol = IPPROTO_GRE;
 
-	dev->needed_headroom	= LL_MAX_HEADER + sizeof(struct iphdr) + 4;
-	dev->mtu		= ETH_DATA_LEN - sizeof(struct iphdr) - 4;
+	tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen;
+
+	t_hlen = tunnel->hlen + sizeof(struct iphdr);
+
+	dev->needed_headroom	= LL_MAX_HEADER + t_hlen + 4;
+	dev->mtu		= ETH_DATA_LEN - t_hlen - 4;
 
 	dev->features		|= GRE_FEATURES;
 	dev->hw_features	|= GRE_FEATURES;
@@ -628,6 +635,40 @@
 		parms->iph.frag_off = htons(IP_DF);
 }
 
+/* This function returns true when ENCAP attributes are present in the nl msg */
+static bool ipgre_netlink_encap_parms(struct nlattr *data[],
+				      struct ip_tunnel_encap *ipencap)
+{
+	bool ret = false;
+
+	memset(ipencap, 0, sizeof(*ipencap));
+
+	if (!data)
+		return ret;
+
+	if (data[IFLA_GRE_ENCAP_TYPE]) {
+		ret = true;
+		ipencap->type = nla_get_u16(data[IFLA_GRE_ENCAP_TYPE]);
+	}
+
+	if (data[IFLA_GRE_ENCAP_FLAGS]) {
+		ret = true;
+		ipencap->flags = nla_get_u16(data[IFLA_GRE_ENCAP_FLAGS]);
+	}
+
+	if (data[IFLA_GRE_ENCAP_SPORT]) {
+		ret = true;
+		ipencap->sport = nla_get_u16(data[IFLA_GRE_ENCAP_SPORT]);
+	}
+
+	if (data[IFLA_GRE_ENCAP_DPORT]) {
+		ret = true;
+		ipencap->dport = nla_get_u16(data[IFLA_GRE_ENCAP_DPORT]);
+	}
+
+	return ret;
+}
+
 static int gre_tap_init(struct net_device *dev)
 {
 	__gre_tunnel_init(dev);
@@ -657,6 +698,15 @@
 			 struct nlattr *tb[], struct nlattr *data[])
 {
 	struct ip_tunnel_parm p;
+	struct ip_tunnel_encap ipencap;
+
+	if (ipgre_netlink_encap_parms(data, &ipencap)) {
+		struct ip_tunnel *t = netdev_priv(dev);
+		int err = ip_tunnel_encap_setup(t, &ipencap);
+
+		if (err < 0)
+			return err;
+	}
 
 	ipgre_netlink_parms(data, tb, &p);
 	return ip_tunnel_newlink(dev, tb, &p);
@@ -666,6 +716,15 @@
 			    struct nlattr *data[])
 {
 	struct ip_tunnel_parm p;
+	struct ip_tunnel_encap ipencap;
+
+	if (ipgre_netlink_encap_parms(data, &ipencap)) {
+		struct ip_tunnel *t = netdev_priv(dev);
+		int err = ip_tunnel_encap_setup(t, &ipencap);
+
+		if (err < 0)
+			return err;
+	}
 
 	ipgre_netlink_parms(data, tb, &p);
 	return ip_tunnel_changelink(dev, tb, &p);
@@ -694,6 +753,14 @@
 		nla_total_size(1) +
 		/* IFLA_GRE_PMTUDISC */
 		nla_total_size(1) +
+		/* IFLA_GRE_ENCAP_TYPE */
+		nla_total_size(2) +
+		/* IFLA_GRE_ENCAP_FLAGS */
+		nla_total_size(2) +
+		/* IFLA_GRE_ENCAP_SPORT */
+		nla_total_size(2) +
+		/* IFLA_GRE_ENCAP_DPORT */
+		nla_total_size(2) +
 		0;
 }
 
@@ -714,6 +781,17 @@
 	    nla_put_u8(skb, IFLA_GRE_PMTUDISC,
 		       !!(p->iph.frag_off & htons(IP_DF))))
 		goto nla_put_failure;
+
+	if (nla_put_u16(skb, IFLA_GRE_ENCAP_TYPE,
+			t->encap.type) ||
+	    nla_put_u16(skb, IFLA_GRE_ENCAP_SPORT,
+			t->encap.sport) ||
+	    nla_put_u16(skb, IFLA_GRE_ENCAP_DPORT,
+			t->encap.dport) ||
+	    nla_put_u16(skb, IFLA_GRE_ENCAP_FLAGS,
+			t->encap.dport))
+		goto nla_put_failure;
+
 	return 0;
 
 nla_put_failure:
@@ -731,6 +809,10 @@
 	[IFLA_GRE_TTL]		= { .type = NLA_U8 },
 	[IFLA_GRE_TOS]		= { .type = NLA_U8 },
 	[IFLA_GRE_PMTUDISC]	= { .type = NLA_U8 },
+	[IFLA_GRE_ENCAP_TYPE]	= { .type = NLA_U16 },
+	[IFLA_GRE_ENCAP_FLAGS]	= { .type = NLA_U16 },
+	[IFLA_GRE_ENCAP_SPORT]	= { .type = NLA_U16 },
+	[IFLA_GRE_ENCAP_DPORT]	= { .type = NLA_U16 },
 };
 
 static struct rtnl_link_ops ipgre_link_ops __read_mostly = {
diff -urN linux/net/ipv4/ipip.c net-next-2.6/net/ipv4/ipip.c
--- linux/net/ipv4/ipip.c	2014-09-24 09:52:43.152644082 +0200
+++ net-next-2.6/net/ipv4/ipip.c	2014-10-06 10:49:00.308901247 +0200
@@ -224,6 +224,8 @@
 	if (IS_ERR(skb))
 		goto out;
 
+	skb_set_inner_ipproto(skb, IPPROTO_IPIP);
+
 	ip_tunnel_xmit(skb, dev, tiph, tiph->protocol);
 	return NETDEV_TX_OK;
 
@@ -301,7 +303,8 @@
 	memcpy(dev->dev_addr, &tunnel->parms.iph.saddr, 4);
 	memcpy(dev->broadcast, &tunnel->parms.iph.daddr, 4);
 
-	tunnel->hlen = 0;
+	tunnel->tun_hlen = 0;
+	tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen;
 	tunnel->parms.iph.protocol = IPPROTO_IPIP;
 	return ip_tunnel_init(dev);
 }
@@ -340,10 +343,53 @@
 		parms->iph.frag_off = htons(IP_DF);
 }
 
+/* This function returns true when ENCAP attributes are present in the nl msg */
+static bool ipip_netlink_encap_parms(struct nlattr *data[],
+				     struct ip_tunnel_encap *ipencap)
+{
+	bool ret = false;
+
+	memset(ipencap, 0, sizeof(*ipencap));
+
+	if (!data)
+		return ret;
+
+	if (data[IFLA_IPTUN_ENCAP_TYPE]) {
+		ret = true;
+		ipencap->type = nla_get_u16(data[IFLA_IPTUN_ENCAP_TYPE]);
+	}
+
+	if (data[IFLA_IPTUN_ENCAP_FLAGS]) {
+		ret = true;
+		ipencap->flags = nla_get_u16(data[IFLA_IPTUN_ENCAP_FLAGS]);
+	}
+
+	if (data[IFLA_IPTUN_ENCAP_SPORT]) {
+		ret = true;
+		ipencap->sport = nla_get_u16(data[IFLA_IPTUN_ENCAP_SPORT]);
+	}
+
+	if (data[IFLA_IPTUN_ENCAP_DPORT]) {
+		ret = true;
+		ipencap->dport = nla_get_u16(data[IFLA_IPTUN_ENCAP_DPORT]);
+	}
+
+	return ret;
+}
+
 static int ipip_newlink(struct net *src_net, struct net_device *dev,
 			struct nlattr *tb[], struct nlattr *data[])
 {
 	struct ip_tunnel_parm p;
+	struct ip_tunnel_encap ipencap;
+
+	if (ipip_netlink_encap_parms(data, &ipencap)) {
+		struct ip_tunnel *t = netdev_priv(dev);
+		int err = ip_tunnel_encap_setup(t, &ipencap);
+
+		if (err < 0)
+			return err;
+	}
 
 	ipip_netlink_parms(data, &p);
 	return ip_tunnel_newlink(dev, tb, &p);
@@ -353,6 +399,15 @@
 			   struct nlattr *data[])
 {
 	struct ip_tunnel_parm p;
+	struct ip_tunnel_encap ipencap;
+
+	if (ipip_netlink_encap_parms(data, &ipencap)) {
+		struct ip_tunnel *t = netdev_priv(dev);
+		int err = ip_tunnel_encap_setup(t, &ipencap);
+
+		if (err < 0)
+			return err;
+	}
 
 	ipip_netlink_parms(data, &p);
 
@@ -378,6 +433,14 @@
 		nla_total_size(1) +
 		/* IFLA_IPTUN_PMTUDISC */
 		nla_total_size(1) +
+		/* IFLA_IPTUN_ENCAP_TYPE */
+		nla_total_size(2) +
+		/* IFLA_IPTUN_ENCAP_FLAGS */
+		nla_total_size(2) +
+		/* IFLA_IPTUN_ENCAP_SPORT */
+		nla_total_size(2) +
+		/* IFLA_IPTUN_ENCAP_DPORT */
+		nla_total_size(2) +
 		0;
 }
 
@@ -394,6 +457,17 @@
 	    nla_put_u8(skb, IFLA_IPTUN_PMTUDISC,
 		       !!(parm->iph.frag_off & htons(IP_DF))))
 		goto nla_put_failure;
+
+	if (nla_put_u16(skb, IFLA_IPTUN_ENCAP_TYPE,
+			tunnel->encap.type) ||
+	    nla_put_u16(skb, IFLA_IPTUN_ENCAP_SPORT,
+			tunnel->encap.sport) ||
+	    nla_put_u16(skb, IFLA_IPTUN_ENCAP_DPORT,
+			tunnel->encap.dport) ||
+	    nla_put_u16(skb, IFLA_IPTUN_ENCAP_FLAGS,
+			tunnel->encap.dport))
+		goto nla_put_failure;
+
 	return 0;
 
 nla_put_failure:
@@ -407,6 +481,10 @@
 	[IFLA_IPTUN_TTL]		= { .type = NLA_U8 },
 	[IFLA_IPTUN_TOS]		= { .type = NLA_U8 },
 	[IFLA_IPTUN_PMTUDISC]		= { .type = NLA_U8 },
+	[IFLA_IPTUN_ENCAP_TYPE]		= { .type = NLA_U16 },
+	[IFLA_IPTUN_ENCAP_FLAGS]	= { .type = NLA_U16 },
+	[IFLA_IPTUN_ENCAP_SPORT]	= { .type = NLA_U16 },
+	[IFLA_IPTUN_ENCAP_DPORT]	= { .type = NLA_U16 },
 };
 
 static struct rtnl_link_ops ipip_link_ops __read_mostly = {
diff -urN linux/net/ipv4/ip_options.c net-next-2.6/net/ipv4/ip_options.c
--- linux/net/ipv4/ip_options.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/ip_options.c	2014-10-06 10:49:00.304901207 +0200
@@ -87,17 +87,15 @@
  * NOTE: dopt cannot point to skb.
  */
 
-int ip_options_echo(struct ip_options *dopt, struct sk_buff *skb)
+int __ip_options_echo(struct ip_options *dopt, struct sk_buff *skb,
+		      const struct ip_options *sopt)
 {
-	const struct ip_options *sopt;
 	unsigned char *sptr, *dptr;
 	int soffset, doffset;
 	int	optlen;
 
 	memset(dopt, 0, sizeof(struct ip_options));
 
-	sopt = &(IPCB(skb)->opt);
-
 	if (sopt->optlen == 0)
 		return 0;
 
diff -urN linux/net/ipv4/ip_output.c net-next-2.6/net/ipv4/ip_output.c
--- linux/net/ipv4/ip_output.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/ip_output.c	2014-10-06 10:49:00.308901247 +0200
@@ -516,7 +516,7 @@
 
 	hlen = iph->ihl * 4;
 	mtu = mtu - hlen;	/* Size of data space */
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	if (skb->nf_bridge)
 		mtu -= nf_bridge_mtu_reduction(skb);
 #endif
@@ -1522,8 +1522,10 @@
 	.uc_ttl		= -1,
 };
 
-void ip_send_unicast_reply(struct net *net, struct sk_buff *skb, __be32 daddr,
-			   __be32 saddr, const struct ip_reply_arg *arg,
+void ip_send_unicast_reply(struct net *net, struct sk_buff *skb,
+			   const struct ip_options *sopt,
+			   __be32 daddr, __be32 saddr,
+			   const struct ip_reply_arg *arg,
 			   unsigned int len)
 {
 	struct ip_options_data replyopts;
@@ -1534,7 +1536,7 @@
 	struct sock *sk;
 	struct inet_sock *inet;
 
-	if (ip_options_echo(&replyopts.opt.opt, skb))
+	if (__ip_options_echo(&replyopts.opt.opt, skb, sopt))
 		return;
 
 	ipc.addr = daddr;
diff -urN linux/net/ipv4/ip_sockglue.c net-next-2.6/net/ipv4/ip_sockglue.c
--- linux/net/ipv4/ip_sockglue.c	2014-09-24 09:52:43.148644039 +0200
+++ net-next-2.6/net/ipv4/ip_sockglue.c	2014-10-06 10:49:00.308901247 +0200
@@ -303,7 +303,7 @@
 			}
 			/* dont let ip_call_ra_chain() use sk again */
 			ra->sk = NULL;
-			rcu_assign_pointer(*rap, ra->next);
+			RCU_INIT_POINTER(*rap, ra->next);
 			spin_unlock_bh(&ip_ra_lock);
 
 			if (ra->destructor)
@@ -325,7 +325,7 @@
 	new_ra->sk = sk;
 	new_ra->destructor = destructor;
 
-	new_ra->next = ra;
+	RCU_INIT_POINTER(new_ra->next, ra);
 	rcu_assign_pointer(*rap, new_ra);
 	sock_hold(sk);
 	spin_unlock_bh(&ip_ra_lock);
@@ -405,7 +405,7 @@
 int ip_recv_error(struct sock *sk, struct msghdr *msg, int len, int *addr_len)
 {
 	struct sock_exterr_skb *serr;
-	struct sk_buff *skb, *skb2;
+	struct sk_buff *skb;
 	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
 	struct {
 		struct sock_extended_err ee;
@@ -415,7 +415,7 @@
 	int copied;
 
 	err = -EAGAIN;
-	skb = skb_dequeue(&sk->sk_error_queue);
+	skb = sock_dequeue_err_skb(sk);
 	if (skb == NULL)
 		goto out;
 
@@ -462,17 +462,6 @@
 	msg->msg_flags |= MSG_ERRQUEUE;
 	err = copied;
 
-	/* Reset and regenerate socket error */
-	spin_lock_bh(&sk->sk_error_queue.lock);
-	sk->sk_err = 0;
-	skb2 = skb_peek(&sk->sk_error_queue);
-	if (skb2 != NULL) {
-		sk->sk_err = SKB_EXT_ERR(skb2)->ee.ee_errno;
-		spin_unlock_bh(&sk->sk_error_queue.lock);
-		sk->sk_error_report(sk);
-	} else
-		spin_unlock_bh(&sk->sk_error_queue.lock);
-
 out_free_skb:
 	kfree_skb(skb);
 out:
diff -urN linux/net/ipv4/ip_tunnel.c net-next-2.6/net/ipv4/ip_tunnel.c
--- linux/net/ipv4/ip_tunnel.c	2014-10-06 10:59:24.267259086 +0200
+++ net-next-2.6/net/ipv4/ip_tunnel.c	2014-10-06 10:49:00.308901247 +0200
@@ -55,6 +55,8 @@
 #include <net/net_namespace.h>
 #include <net/netns/generic.h>
 #include <net/rtnetlink.h>
+#include <net/udp.h>
+#include <net/gue.h>
 
 #if IS_ENABLED(CONFIG_IPV6)
 #include <net/ipv6.h>
@@ -487,6 +489,103 @@
 }
 EXPORT_SYMBOL_GPL(ip_tunnel_rcv);
 
+static int ip_encap_hlen(struct ip_tunnel_encap *e)
+{
+	switch (e->type) {
+	case TUNNEL_ENCAP_NONE:
+		return 0;
+	case TUNNEL_ENCAP_FOU:
+		return sizeof(struct udphdr);
+	case TUNNEL_ENCAP_GUE:
+		return sizeof(struct udphdr) + sizeof(struct guehdr);
+	default:
+		return -EINVAL;
+	}
+}
+
+int ip_tunnel_encap_setup(struct ip_tunnel *t,
+			  struct ip_tunnel_encap *ipencap)
+{
+	int hlen;
+
+	memset(&t->encap, 0, sizeof(t->encap));
+
+	hlen = ip_encap_hlen(ipencap);
+	if (hlen < 0)
+		return hlen;
+
+	t->encap.type = ipencap->type;
+	t->encap.sport = ipencap->sport;
+	t->encap.dport = ipencap->dport;
+	t->encap.flags = ipencap->flags;
+
+	t->encap_hlen = hlen;
+	t->hlen = t->encap_hlen + t->tun_hlen;
+
+	return 0;
+}
+EXPORT_SYMBOL_GPL(ip_tunnel_encap_setup);
+
+static int fou_build_header(struct sk_buff *skb, struct ip_tunnel_encap *e,
+			    size_t hdr_len, u8 *protocol, struct flowi4 *fl4)
+{
+	struct udphdr *uh;
+	__be16 sport;
+	bool csum = !!(e->flags & TUNNEL_ENCAP_FLAG_CSUM);
+	int type = csum ? SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
+
+	skb = iptunnel_handle_offloads(skb, csum, type);
+
+	if (IS_ERR(skb))
+		return PTR_ERR(skb);
+
+	/* Get length and hash before making space in skb */
+
+	sport = e->sport ? : udp_flow_src_port(dev_net(skb->dev),
+					       skb, 0, 0, false);
+
+	skb_push(skb, hdr_len);
+
+	skb_reset_transport_header(skb);
+	uh = udp_hdr(skb);
+
+	if (e->type == TUNNEL_ENCAP_GUE) {
+		struct guehdr *guehdr = (struct guehdr *)&uh[1];
+
+		guehdr->version = 0;
+		guehdr->hlen = 0;
+		guehdr->flags = 0;
+		guehdr->next_hdr = *protocol;
+	}
+
+	uh->dest = e->dport;
+	uh->source = sport;
+	uh->len = htons(skb->len);
+	uh->check = 0;
+	udp_set_csum(!(e->flags & TUNNEL_ENCAP_FLAG_CSUM), skb,
+		     fl4->saddr, fl4->daddr, skb->len);
+
+	*protocol = IPPROTO_UDP;
+
+	return 0;
+}
+
+int ip_tunnel_encap(struct sk_buff *skb, struct ip_tunnel *t,
+		    u8 *protocol, struct flowi4 *fl4)
+{
+	switch (t->encap.type) {
+	case TUNNEL_ENCAP_NONE:
+		return 0;
+	case TUNNEL_ENCAP_FOU:
+	case TUNNEL_ENCAP_GUE:
+		return fou_build_header(skb, &t->encap, t->encap_hlen,
+					protocol, fl4);
+	default:
+		return -EINVAL;
+	}
+}
+EXPORT_SYMBOL(ip_tunnel_encap);
+
 static int tnl_update_pmtu(struct net_device *dev, struct sk_buff *skb,
 			    struct rtable *rt, __be16 df)
 {
@@ -536,7 +635,7 @@
 }
 
 void ip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
-		    const struct iphdr *tnl_params, const u8 protocol)
+		    const struct iphdr *tnl_params, u8 protocol)
 {
 	struct ip_tunnel *tunnel = netdev_priv(dev);
 	const struct iphdr *inner_iph;
@@ -617,6 +716,9 @@
 	init_tunnel_flow(&fl4, protocol, dst, tnl_params->saddr,
 			 tunnel->parms.o_key, RT_TOS(tos), tunnel->parms.link);
 
+	if (ip_tunnel_encap(skb, tunnel, &protocol, &fl4) < 0)
+		goto tx_error;
+
 	rt = connected ? tunnel_rtable_get(tunnel, 0, &fl4.saddr) : NULL;
 
 	if (!rt) {
@@ -670,7 +772,7 @@
 		df |= (inner_iph->frag_off&htons(IP_DF));
 
 	max_headroom = LL_RESERVED_SPACE(rt->dst.dev) + sizeof(struct iphdr)
-			+ rt->dst.header_len;
+			+ rt->dst.header_len + ip_encap_hlen(&tunnel->encap);
 	if (max_headroom > dev->needed_headroom)
 		dev->needed_headroom = max_headroom;
 
diff -urN linux/net/ipv4/Kconfig net-next-2.6/net/ipv4/Kconfig
--- linux/net/ipv4/Kconfig	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/Kconfig	2014-10-06 10:49:00.272900881 +0200
@@ -311,6 +311,16 @@
 	tristate
 	default n
 
+config NET_FOU
+	tristate "IP: Foo (IP protocols) over UDP"
+	select XFRM
+	select NET_UDP_TUNNEL
+	---help---
+	  Foo over UDP allows any IP protocol to be directly encapsulated
+	  over UDP include tunnels (IPIP, GRE, SIT). By encapsulating in UDP
+	  network mechanisms and optimizations for UDP (such as ECMP
+	  and RSS) can be leveraged to provide better service.
+
 config INET_AH
 	tristate "IP: AH transformation"
 	select XFRM_ALGO
@@ -443,6 +453,20 @@
 	increase provides TCP friendliness.
 	See http://www.csc.ncsu.edu/faculty/rhee/export/bitcp/
 
+config GENEVE
+	tristate "Generic Network Virtualization Encapsulation (Geneve)"
+	depends on INET
+	select NET_IP_TUNNEL
+	select NET_UDP_TUNNEL
+	---help---
+	This allows one to create Geneve virtual interfaces that provide
+	Layer 2 Networks over Layer 3 Networks. Geneve is often used
+	to tunnel virtual network infrastructure in virtualized environments.
+	For more information see:
+	  http://tools.ietf.org/html/draft-gross-geneve-01
+
+	  To compile this driver as a module, choose M here: the module
+
 config TCP_CONG_CUBIC
 	tristate "CUBIC TCP"
 	default y
@@ -560,6 +584,27 @@
 	For further details see:
 	  http://www.ews.uiuc.edu/~shaoliu/tcpillinois/index.html
 
+config TCP_CONG_DCTCP
+	tristate "DataCenter TCP (DCTCP)"
+	default n
+	---help---
+	DCTCP leverages Explicit Congestion Notification (ECN) in the network to
+	provide multi-bit feedback to the end hosts. It is designed to provide:
+
+	- High burst tolerance (incast due to partition/aggregate),
+	- Low latency (short flows, queries),
+	- High throughput (continuous data updates, large file transfers) with
+	  commodity, shallow-buffered switches.
+
+	All switches in the data center network running DCTCP must support
+	ECN marking and be configured for marking when reaching defined switch
+	buffer thresholds. The default ECN marking threshold heuristic for
+	DCTCP on switches is 20 packets (30KB) at 1Gbps, and 65 packets
+	(~100KB) at 10Gbps, but might need further careful tweaking.
+
+	For further details see:
+	  http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp-final.pdf
+
 choice
 	prompt "Default TCP congestion control"
 	default DEFAULT_CUBIC
@@ -588,9 +633,11 @@
 	config DEFAULT_WESTWOOD
 		bool "Westwood" if TCP_CONG_WESTWOOD=y
 
+	config DEFAULT_DCTCP
+		bool "DCTCP" if TCP_CONG_DCTCP=y
+
 	config DEFAULT_RENO
 		bool "Reno"
-
 endchoice
 
 endif
@@ -610,6 +657,7 @@
 	default "westwood" if DEFAULT_WESTWOOD
 	default "veno" if DEFAULT_VENO
 	default "reno" if DEFAULT_RENO
+	default "dctcp" if DEFAULT_DCTCP
 	default "cubic"
 
 config TCP_MD5SIG
diff -urN linux/net/ipv4/Makefile net-next-2.6/net/ipv4/Makefile
--- linux/net/ipv4/Makefile	2014-09-24 09:52:43.144643997 +0200
+++ net-next-2.6/net/ipv4/Makefile	2014-10-06 10:49:00.272900881 +0200
@@ -20,6 +20,7 @@
 obj-$(CONFIG_IP_MROUTE) += ipmr.o
 obj-$(CONFIG_NET_IPIP) += ipip.o
 gre-y := gre_demux.o
+obj-$(CONFIG_NET_FOU) += fou.o
 obj-$(CONFIG_NET_IPGRE_DEMUX) += gre.o
 obj-$(CONFIG_NET_IPGRE) += ip_gre.o
 obj-$(CONFIG_NET_UDP_TUNNEL) += udp_tunnel.o
@@ -42,6 +43,7 @@
 obj-$(CONFIG_NET_TCPPROBE) += tcp_probe.o
 obj-$(CONFIG_TCP_CONG_BIC) += tcp_bic.o
 obj-$(CONFIG_TCP_CONG_CUBIC) += tcp_cubic.o
+obj-$(CONFIG_TCP_CONG_DCTCP) += tcp_dctcp.o
 obj-$(CONFIG_TCP_CONG_WESTWOOD) += tcp_westwood.o
 obj-$(CONFIG_TCP_CONG_HSTCP) += tcp_highspeed.o
 obj-$(CONFIG_TCP_CONG_HYBLA) += tcp_hybla.o
@@ -54,6 +56,7 @@
 obj-$(CONFIG_TCP_CONG_ILLINOIS) += tcp_illinois.o
 obj-$(CONFIG_MEMCG_KMEM) += tcp_memcontrol.o
 obj-$(CONFIG_NETLABEL) += cipso_ipv4.o
+obj-$(CONFIG_GENEVE) += geneve.o
 
 obj-$(CONFIG_XFRM) += xfrm4_policy.o xfrm4_state.o xfrm4_input.o \
 		      xfrm4_output.o xfrm4_protocol.o
diff -urN linux/net/ipv4/netfilter/iptable_nat.c net-next-2.6/net/ipv4/netfilter/iptable_nat.c
--- linux/net/ipv4/netfilter/iptable_nat.c	2014-09-24 09:52:43.168644248 +0200
+++ net-next-2.6/net/ipv4/netfilter/iptable_nat.c	2014-10-06 10:49:00.340901572 +0200
@@ -28,222 +28,57 @@
 	.af		= NFPROTO_IPV4,
 };
 
-static unsigned int alloc_null_binding(struct nf_conn *ct, unsigned int hooknum)
-{
-	/* Force range to this IP; let proto decide mapping for
-	 * per-proto parts (hence not IP_NAT_RANGE_PROTO_SPECIFIED).
-	 */
-	struct nf_nat_range range;
-
-	range.flags = 0;
-	pr_debug("Allocating NULL binding for %p (%pI4)\n", ct,
-		 HOOK2MANIP(hooknum) == NF_NAT_MANIP_SRC ?
-		 &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip :
-		 &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip);
-
-	return nf_nat_setup_info(ct, &range, HOOK2MANIP(hooknum));
-}
-
-static unsigned int nf_nat_rule_find(struct sk_buff *skb, unsigned int hooknum,
-				     const struct net_device *in,
-				     const struct net_device *out,
-				     struct nf_conn *ct)
+static unsigned int iptable_nat_do_chain(const struct nf_hook_ops *ops,
+					 struct sk_buff *skb,
+					 const struct net_device *in,
+					 const struct net_device *out,
+					 struct nf_conn *ct)
 {
 	struct net *net = nf_ct_net(ct);
-	unsigned int ret;
 
-	ret = ipt_do_table(skb, hooknum, in, out, net->ipv4.nat_table);
-	if (ret == NF_ACCEPT) {
-		if (!nf_nat_initialized(ct, HOOK2MANIP(hooknum)))
-			ret = alloc_null_binding(ct, hooknum);
-	}
-	return ret;
+	return ipt_do_table(skb, ops->hooknum, in, out, net->ipv4.nat_table);
 }
 
-static unsigned int
-nf_nat_ipv4_fn(const struct nf_hook_ops *ops,
-	       struct sk_buff *skb,
-	       const struct net_device *in,
-	       const struct net_device *out,
-	       int (*okfn)(struct sk_buff *))
+static unsigned int iptable_nat_ipv4_fn(const struct nf_hook_ops *ops,
+					struct sk_buff *skb,
+					const struct net_device *in,
+					const struct net_device *out,
+					int (*okfn)(struct sk_buff *))
 {
-	struct nf_conn *ct;
-	enum ip_conntrack_info ctinfo;
-	struct nf_conn_nat *nat;
-	/* maniptype == SRC for postrouting. */
-	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);
-
-	/* We never see fragments: conntrack defrags on pre-routing
-	 * and local-out, and nf_nat_out protects post-routing.
-	 */
-	NF_CT_ASSERT(!ip_is_fragment(ip_hdr(skb)));
-
-	ct = nf_ct_get(skb, &ctinfo);
-	/* Can't track?  It's not due to stress, or conntrack would
-	 * have dropped it.  Hence it's the user's responsibilty to
-	 * packet filter it out, or implement conntrack/NAT for that
-	 * protocol. 8) --RR
-	 */
-	if (!ct)
-		return NF_ACCEPT;
-
-	/* Don't try to NAT if this packet is not conntracked */
-	if (nf_ct_is_untracked(ct))
-		return NF_ACCEPT;
-
-	nat = nf_ct_nat_ext_add(ct);
-	if (nat == NULL)
-		return NF_ACCEPT;
-
-	switch (ctinfo) {
-	case IP_CT_RELATED:
-	case IP_CT_RELATED_REPLY:
-		if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
-			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
-							   ops->hooknum))
-				return NF_DROP;
-			else
-				return NF_ACCEPT;
-		}
-		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
-	case IP_CT_NEW:
-		/* Seen it before?  This can happen for loopback, retrans,
-		 * or local packets.
-		 */
-		if (!nf_nat_initialized(ct, maniptype)) {
-			unsigned int ret;
-
-			ret = nf_nat_rule_find(skb, ops->hooknum, in, out, ct);
-			if (ret != NF_ACCEPT)
-				return ret;
-		} else {
-			pr_debug("Already setup manip %s for ct %p\n",
-				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
-				 ct);
-			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
-				goto oif_changed;
-		}
-		break;
-
-	default:
-		/* ESTABLISHED */
-		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||
-			     ctinfo == IP_CT_ESTABLISHED_REPLY);
-		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
-			goto oif_changed;
-	}
-
-	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);
-
-oif_changed:
-	nf_ct_kill_acct(ct, ctinfo, skb);
-	return NF_DROP;
+	return nf_nat_ipv4_fn(ops, skb, in, out, iptable_nat_do_chain);
 }
 
-static unsigned int
-nf_nat_ipv4_in(const struct nf_hook_ops *ops,
-	       struct sk_buff *skb,
-	       const struct net_device *in,
-	       const struct net_device *out,
-	       int (*okfn)(struct sk_buff *))
+static unsigned int iptable_nat_ipv4_in(const struct nf_hook_ops *ops,
+					struct sk_buff *skb,
+					const struct net_device *in,
+					const struct net_device *out,
+					int (*okfn)(struct sk_buff *))
 {
-	unsigned int ret;
-	__be32 daddr = ip_hdr(skb)->daddr;
-
-	ret = nf_nat_ipv4_fn(ops, skb, in, out, okfn);
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    daddr != ip_hdr(skb)->daddr)
-		skb_dst_drop(skb);
-
-	return ret;
+	return nf_nat_ipv4_in(ops, skb, in, out, iptable_nat_do_chain);
 }
 
-static unsigned int
-nf_nat_ipv4_out(const struct nf_hook_ops *ops,
-		struct sk_buff *skb,
-		const struct net_device *in,
-		const struct net_device *out,
-		int (*okfn)(struct sk_buff *))
+static unsigned int iptable_nat_ipv4_out(const struct nf_hook_ops *ops,
+					 struct sk_buff *skb,
+					 const struct net_device *in,
+					 const struct net_device *out,
+					 int (*okfn)(struct sk_buff *))
 {
-#ifdef CONFIG_XFRM
-	const struct nf_conn *ct;
-	enum ip_conntrack_info ctinfo;
-	int err;
-#endif
-	unsigned int ret;
-
-	/* root is playing with raw sockets. */
-	if (skb->len < sizeof(struct iphdr) ||
-	    ip_hdrlen(skb) < sizeof(struct iphdr))
-		return NF_ACCEPT;
-
-	ret = nf_nat_ipv4_fn(ops, skb, in, out, okfn);
-#ifdef CONFIG_XFRM
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    !(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
-	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
-		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
-
-		if ((ct->tuplehash[dir].tuple.src.u3.ip !=
-		     ct->tuplehash[!dir].tuple.dst.u3.ip) ||
-		    (ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMP &&
-		     ct->tuplehash[dir].tuple.src.u.all !=
-		     ct->tuplehash[!dir].tuple.dst.u.all)) {
-			err = nf_xfrm_me_harder(skb, AF_INET);
-			if (err < 0)
-				ret = NF_DROP_ERR(err);
-		}
-	}
-#endif
-	return ret;
+	return nf_nat_ipv4_out(ops, skb, in, out, iptable_nat_do_chain);
 }
 
-static unsigned int
-nf_nat_ipv4_local_fn(const struct nf_hook_ops *ops,
-		     struct sk_buff *skb,
-		     const struct net_device *in,
-		     const struct net_device *out,
-		     int (*okfn)(struct sk_buff *))
+static unsigned int iptable_nat_ipv4_local_fn(const struct nf_hook_ops *ops,
+					      struct sk_buff *skb,
+					      const struct net_device *in,
+					      const struct net_device *out,
+					      int (*okfn)(struct sk_buff *))
 {
-	const struct nf_conn *ct;
-	enum ip_conntrack_info ctinfo;
-	unsigned int ret;
-	int err;
-
-	/* root is playing with raw sockets. */
-	if (skb->len < sizeof(struct iphdr) ||
-	    ip_hdrlen(skb) < sizeof(struct iphdr))
-		return NF_ACCEPT;
-
-	ret = nf_nat_ipv4_fn(ops, skb, in, out, okfn);
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
-		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
-
-		if (ct->tuplehash[dir].tuple.dst.u3.ip !=
-		    ct->tuplehash[!dir].tuple.src.u3.ip) {
-			err = ip_route_me_harder(skb, RTN_UNSPEC);
-			if (err < 0)
-				ret = NF_DROP_ERR(err);
-		}
-#ifdef CONFIG_XFRM
-		else if (!(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
-			 ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMP &&
-			 ct->tuplehash[dir].tuple.dst.u.all !=
-			 ct->tuplehash[!dir].tuple.src.u.all) {
-			err = nf_xfrm_me_harder(skb, AF_INET);
-			if (err < 0)
-				ret = NF_DROP_ERR(err);
-		}
-#endif
-	}
-	return ret;
+	return nf_nat_ipv4_local_fn(ops, skb, in, out, iptable_nat_do_chain);
 }
 
 static struct nf_hook_ops nf_nat_ipv4_ops[] __read_mostly = {
 	/* Before packet filtering, change destination */
 	{
-		.hook		= nf_nat_ipv4_in,
+		.hook		= iptable_nat_ipv4_in,
 		.owner		= THIS_MODULE,
 		.pf		= NFPROTO_IPV4,
 		.hooknum	= NF_INET_PRE_ROUTING,
@@ -251,7 +86,7 @@
 	},
 	/* After packet filtering, change source */
 	{
-		.hook		= nf_nat_ipv4_out,
+		.hook		= iptable_nat_ipv4_out,
 		.owner		= THIS_MODULE,
 		.pf		= NFPROTO_IPV4,
 		.hooknum	= NF_INET_POST_ROUTING,
@@ -259,7 +94,7 @@
 	},
 	/* Before packet filtering, change destination */
 	{
-		.hook		= nf_nat_ipv4_local_fn,
+		.hook		= iptable_nat_ipv4_local_fn,
 		.owner		= THIS_MODULE,
 		.pf		= NFPROTO_IPV4,
 		.hooknum	= NF_INET_LOCAL_OUT,
@@ -267,7 +102,7 @@
 	},
 	/* After packet filtering, change source */
 	{
-		.hook		= nf_nat_ipv4_fn,
+		.hook		= iptable_nat_ipv4_fn,
 		.owner		= THIS_MODULE,
 		.pf		= NFPROTO_IPV4,
 		.hooknum	= NF_INET_LOCAL_IN,
diff -urN linux/net/ipv4/netfilter/ipt_CLUSTERIP.c net-next-2.6/net/ipv4/netfilter/ipt_CLUSTERIP.c
--- linux/net/ipv4/netfilter/ipt_CLUSTERIP.c	2013-11-29 12:59:37.443377017 +0100
+++ net-next-2.6/net/ipv4/netfilter/ipt_CLUSTERIP.c	2014-10-06 10:49:00.340901572 +0200
@@ -285,7 +285,7 @@
 	}
 
 	/* node numbers are 1..n, not 0..n */
-	return (((u64)hashval * config->num_total_nodes) >> 32) + 1;
+	return reciprocal_scale(hashval, config->num_total_nodes) + 1;
 }
 
 static inline int
diff -urN linux/net/ipv4/netfilter/ipt_MASQUERADE.c net-next-2.6/net/ipv4/netfilter/ipt_MASQUERADE.c
--- linux/net/ipv4/netfilter/ipt_MASQUERADE.c	2013-11-29 12:59:37.443377017 +0100
+++ net-next-2.6/net/ipv4/netfilter/ipt_MASQUERADE.c	2014-10-06 10:49:00.340901572 +0200
@@ -22,6 +22,7 @@
 #include <linux/netfilter_ipv4.h>
 #include <linux/netfilter/x_tables.h>
 #include <net/netfilter/nf_nat.h>
+#include <net/netfilter/ipv4/nf_nat_masquerade.h>
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
@@ -46,103 +47,17 @@
 static unsigned int
 masquerade_tg(struct sk_buff *skb, const struct xt_action_param *par)
 {
-	struct nf_conn *ct;
-	struct nf_conn_nat *nat;
-	enum ip_conntrack_info ctinfo;
-	struct nf_nat_range newrange;
+	struct nf_nat_range range;
 	const struct nf_nat_ipv4_multi_range_compat *mr;
-	const struct rtable *rt;
-	__be32 newsrc, nh;
-
-	NF_CT_ASSERT(par->hooknum == NF_INET_POST_ROUTING);
-
-	ct = nf_ct_get(skb, &ctinfo);
-	nat = nfct_nat(ct);
-
-	NF_CT_ASSERT(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
-			    ctinfo == IP_CT_RELATED_REPLY));
-
-	/* Source address is 0.0.0.0 - locally generated packet that is
-	 * probably not supposed to be masqueraded.
-	 */
-	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip == 0)
-		return NF_ACCEPT;
 
 	mr = par->targinfo;
-	rt = skb_rtable(skb);
-	nh = rt_nexthop(rt, ip_hdr(skb)->daddr);
-	newsrc = inet_select_addr(par->out, nh, RT_SCOPE_UNIVERSE);
-	if (!newsrc) {
-		pr_info("%s ate my IP address\n", par->out->name);
-		return NF_DROP;
-	}
-
-	nat->masq_index = par->out->ifindex;
-
-	/* Transfer from original range. */
-	memset(&newrange.min_addr, 0, sizeof(newrange.min_addr));
-	memset(&newrange.max_addr, 0, sizeof(newrange.max_addr));
-	newrange.flags       = mr->range[0].flags | NF_NAT_RANGE_MAP_IPS;
-	newrange.min_addr.ip = newsrc;
-	newrange.max_addr.ip = newsrc;
-	newrange.min_proto   = mr->range[0].min;
-	newrange.max_proto   = mr->range[0].max;
-
-	/* Hand modified range to generic setup. */
-	return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_SRC);
-}
-
-static int
-device_cmp(struct nf_conn *i, void *ifindex)
-{
-	const struct nf_conn_nat *nat = nfct_nat(i);
-
-	if (!nat)
-		return 0;
-	if (nf_ct_l3num(i) != NFPROTO_IPV4)
-		return 0;
-	return nat->masq_index == (int)(long)ifindex;
-}
-
-static int masq_device_event(struct notifier_block *this,
-			     unsigned long event,
-			     void *ptr)
-{
-	const struct net_device *dev = netdev_notifier_info_to_dev(ptr);
-	struct net *net = dev_net(dev);
-
-	if (event == NETDEV_DOWN) {
-		/* Device was downed.  Search entire table for
-		   conntracks which were associated with that device,
-		   and forget them. */
-		NF_CT_ASSERT(dev->ifindex != 0);
-
-		nf_ct_iterate_cleanup(net, device_cmp,
-				      (void *)(long)dev->ifindex, 0, 0);
-	}
+	range.flags = mr->range[0].flags;
+	range.min_proto = mr->range[0].min;
+	range.max_proto = mr->range[0].max;
 
-	return NOTIFY_DONE;
+	return nf_nat_masquerade_ipv4(skb, par->hooknum, &range, par->out);
 }
 
-static int masq_inet_event(struct notifier_block *this,
-			   unsigned long event,
-			   void *ptr)
-{
-	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;
-	struct netdev_notifier_info info;
-
-	netdev_notifier_info_init(&info, dev);
-	return masq_device_event(this, event, &info);
-}
-
-static struct notifier_block masq_dev_notifier = {
-	.notifier_call	= masq_device_event,
-};
-
-static struct notifier_block masq_inet_notifier = {
-	.notifier_call	= masq_inet_event,
-};
-
 static struct xt_target masquerade_tg_reg __read_mostly = {
 	.name		= "MASQUERADE",
 	.family		= NFPROTO_IPV4,
@@ -160,12 +75,8 @@
 
 	ret = xt_register_target(&masquerade_tg_reg);
 
-	if (ret == 0) {
-		/* Register for device down reports */
-		register_netdevice_notifier(&masq_dev_notifier);
-		/* Register IP address change reports */
-		register_inetaddr_notifier(&masq_inet_notifier);
-	}
+	if (ret == 0)
+		nf_nat_masquerade_ipv4_register_notifier();
 
 	return ret;
 }
@@ -173,8 +84,7 @@
 static void __exit masquerade_tg_exit(void)
 {
 	xt_unregister_target(&masquerade_tg_reg);
-	unregister_netdevice_notifier(&masq_dev_notifier);
-	unregister_inetaddr_notifier(&masq_inet_notifier);
+	nf_nat_masquerade_ipv4_unregister_notifier();
 }
 
 module_init(masquerade_tg_init);
diff -urN linux/net/ipv4/netfilter/ipt_REJECT.c net-next-2.6/net/ipv4/netfilter/ipt_REJECT.c
--- linux/net/ipv4/netfilter/ipt_REJECT.c	2014-09-24 09:52:43.168644248 +0200
+++ net-next-2.6/net/ipv4/netfilter/ipt_REJECT.c	2014-10-06 10:49:00.340901572 +0200
@@ -20,7 +20,7 @@
 #include <linux/netfilter/x_tables.h>
 #include <linux/netfilter_ipv4/ip_tables.h>
 #include <linux/netfilter_ipv4/ipt_REJECT.h>
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 #include <linux/netfilter_bridge.h>
 #endif
 
diff -urN linux/net/ipv4/netfilter/Kconfig net-next-2.6/net/ipv4/netfilter/Kconfig
--- linux/net/ipv4/netfilter/Kconfig	2014-09-24 09:52:43.152644082 +0200
+++ net-next-2.6/net/ipv4/netfilter/Kconfig	2014-10-06 10:49:00.308901247 +0200
@@ -61,18 +61,13 @@
 	  fields such as the source, destination, type of service and
 	  the packet mark.
 
-config NFT_CHAIN_NAT_IPV4
-	depends on NF_TABLES_IPV4
-	depends on NF_NAT_IPV4 && NFT_NAT
-	tristate "IPv4 nf_tables nat chain support"
-	help
-	  This option enables the "nat" chain for IPv4 in nf_tables. This
-	  chain type is used to perform Network Address Translation (NAT)
-	  packet transformations such as the source, destination address and
-	  source and destination ports.
+config NF_REJECT_IPV4
+	tristate "IPv4 packet rejection"
+	default m if NETFILTER_ADVANCED=n
 
 config NFT_REJECT_IPV4
 	depends on NF_TABLES_IPV4
+	select NF_REJECT_IPV4
 	default NFT_REJECT
 	tristate
 
@@ -94,6 +89,30 @@
 
 if NF_NAT_IPV4
 
+config NFT_CHAIN_NAT_IPV4
+	depends on NF_TABLES_IPV4
+	tristate "IPv4 nf_tables nat chain support"
+	help
+	  This option enables the "nat" chain for IPv4 in nf_tables. This
+	  chain type is used to perform Network Address Translation (NAT)
+	  packet transformations such as the source, destination address and
+	  source and destination ports.
+
+config NF_NAT_MASQUERADE_IPV4
+	tristate "IPv4 masquerade support"
+	help
+	  This is the kernel functionality to provide NAT in the masquerade
+	  flavour (automatic source address selection).
+
+config NFT_MASQ_IPV4
+	tristate "IPv4 masquerading support for nf_tables"
+	depends on NF_TABLES_IPV4
+	depends on NFT_MASQ
+	select NF_NAT_MASQUERADE_IPV4
+	help
+	  This is the expression that provides IPv4 masquerading support for
+	  nf_tables.
+
 config NF_NAT_SNMP_BASIC
 	tristate "Basic SNMP-ALG support"
 	depends on NF_CONNTRACK_SNMP
@@ -194,6 +213,7 @@
 config IP_NF_TARGET_REJECT
 	tristate "REJECT target support"
 	depends on IP_NF_FILTER
+	select NF_REJECT_IPV4
 	default m if NETFILTER_ADVANCED=n
 	help
 	  The REJECT target allows a filtering rule to specify that an ICMP
@@ -234,6 +254,7 @@
 
 config IP_NF_TARGET_MASQUERADE
 	tristate "MASQUERADE target support"
+	select NF_NAT_MASQUERADE_IPV4
 	default m if NETFILTER_ADVANCED=n
 	help
 	  Masquerading is a special case of NAT: all outgoing connections are
diff -urN linux/net/ipv4/netfilter/Makefile net-next-2.6/net/ipv4/netfilter/Makefile
--- linux/net/ipv4/netfilter/Makefile	2014-09-24 09:52:43.152644082 +0200
+++ net-next-2.6/net/ipv4/netfilter/Makefile	2014-10-06 10:49:00.308901247 +0200
@@ -23,10 +23,14 @@
 obj-$(CONFIG_NF_LOG_ARP) += nf_log_arp.o
 obj-$(CONFIG_NF_LOG_IPV4) += nf_log_ipv4.o
 
+# reject
+obj-$(CONFIG_NF_REJECT_IPV4) += nf_reject_ipv4.o
+
 # NAT helpers (nf_conntrack)
 obj-$(CONFIG_NF_NAT_H323) += nf_nat_h323.o
 obj-$(CONFIG_NF_NAT_PPTP) += nf_nat_pptp.o
 obj-$(CONFIG_NF_NAT_SNMP_BASIC) += nf_nat_snmp_basic.o
+obj-$(CONFIG_NF_NAT_MASQUERADE_IPV4) += nf_nat_masquerade_ipv4.o
 
 # NAT protocols (nf_nat)
 obj-$(CONFIG_NF_NAT_PROTO_GRE) += nf_nat_proto_gre.o
@@ -35,6 +39,7 @@
 obj-$(CONFIG_NFT_CHAIN_ROUTE_IPV4) += nft_chain_route_ipv4.o
 obj-$(CONFIG_NFT_CHAIN_NAT_IPV4) += nft_chain_nat_ipv4.o
 obj-$(CONFIG_NFT_REJECT_IPV4) += nft_reject_ipv4.o
+obj-$(CONFIG_NFT_MASQ_IPV4) += nft_masq_ipv4.o
 obj-$(CONFIG_NF_TABLES_ARP) += nf_tables_arp.o
 
 # generic IP tables 
diff -urN linux/net/ipv4/netfilter/nf_defrag_ipv4.c net-next-2.6/net/ipv4/netfilter/nf_defrag_ipv4.c
--- linux/net/ipv4/netfilter/nf_defrag_ipv4.c	2014-09-24 09:52:43.168644248 +0200
+++ net-next-2.6/net/ipv4/netfilter/nf_defrag_ipv4.c	2014-10-06 10:49:00.344901613 +0200
@@ -50,7 +50,7 @@
 		zone = nf_ct_zone((struct nf_conn *)skb->nfct);
 #endif
 
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	if (skb->nf_bridge &&
 	    skb->nf_bridge->mask & BRNF_NF_BRIDGE_PREROUTING)
 		return IP_DEFRAG_CONNTRACK_BRIDGE_IN + zone;
diff -urN linux/net/ipv4/netfilter/nf_nat_l3proto_ipv4.c net-next-2.6/net/ipv4/netfilter/nf_nat_l3proto_ipv4.c
--- linux/net/ipv4/netfilter/nf_nat_l3proto_ipv4.c	2014-09-24 09:52:43.168644248 +0200
+++ net-next-2.6/net/ipv4/netfilter/nf_nat_l3proto_ipv4.c	2014-10-06 10:49:00.344901613 +0200
@@ -254,6 +254,205 @@
 }
 EXPORT_SYMBOL_GPL(nf_nat_icmp_reply_translation);
 
+unsigned int
+nf_nat_ipv4_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
+	       const struct net_device *in, const struct net_device *out,
+	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
+					struct sk_buff *skb,
+					const struct net_device *in,
+					const struct net_device *out,
+					struct nf_conn *ct))
+{
+	struct nf_conn *ct;
+	enum ip_conntrack_info ctinfo;
+	struct nf_conn_nat *nat;
+	/* maniptype == SRC for postrouting. */
+	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);
+
+	/* We never see fragments: conntrack defrags on pre-routing
+	 * and local-out, and nf_nat_out protects post-routing.
+	 */
+	NF_CT_ASSERT(!ip_is_fragment(ip_hdr(skb)));
+
+	ct = nf_ct_get(skb, &ctinfo);
+	/* Can't track?  It's not due to stress, or conntrack would
+	 * have dropped it.  Hence it's the user's responsibilty to
+	 * packet filter it out, or implement conntrack/NAT for that
+	 * protocol. 8) --RR
+	 */
+	if (!ct)
+		return NF_ACCEPT;
+
+	/* Don't try to NAT if this packet is not conntracked */
+	if (nf_ct_is_untracked(ct))
+		return NF_ACCEPT;
+
+	nat = nf_ct_nat_ext_add(ct);
+	if (nat == NULL)
+		return NF_ACCEPT;
+
+	switch (ctinfo) {
+	case IP_CT_RELATED:
+	case IP_CT_RELATED_REPLY:
+		if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
+			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
+							   ops->hooknum))
+				return NF_DROP;
+			else
+				return NF_ACCEPT;
+		}
+		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
+	case IP_CT_NEW:
+		/* Seen it before?  This can happen for loopback, retrans,
+		 * or local packets.
+		 */
+		if (!nf_nat_initialized(ct, maniptype)) {
+			unsigned int ret;
+
+			ret = do_chain(ops, skb, in, out, ct);
+			if (ret != NF_ACCEPT)
+				return ret;
+
+			if (nf_nat_initialized(ct, HOOK2MANIP(ops->hooknum)))
+				break;
+
+			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);
+			if (ret != NF_ACCEPT)
+				return ret;
+		} else {
+			pr_debug("Already setup manip %s for ct %p\n",
+				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
+				 ct);
+			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
+				goto oif_changed;
+		}
+		break;
+
+	default:
+		/* ESTABLISHED */
+		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||
+			     ctinfo == IP_CT_ESTABLISHED_REPLY);
+		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
+			goto oif_changed;
+	}
+
+	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);
+
+oif_changed:
+	nf_ct_kill_acct(ct, ctinfo, skb);
+	return NF_DROP;
+}
+EXPORT_SYMBOL_GPL(nf_nat_ipv4_fn);
+
+unsigned int
+nf_nat_ipv4_in(const struct nf_hook_ops *ops, struct sk_buff *skb,
+	       const struct net_device *in, const struct net_device *out,
+	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
+					 struct sk_buff *skb,
+					 const struct net_device *in,
+					 const struct net_device *out,
+					 struct nf_conn *ct))
+{
+	unsigned int ret;
+	__be32 daddr = ip_hdr(skb)->daddr;
+
+	ret = nf_nat_ipv4_fn(ops, skb, in, out, do_chain);
+	if (ret != NF_DROP && ret != NF_STOLEN &&
+	    daddr != ip_hdr(skb)->daddr)
+		skb_dst_drop(skb);
+
+	return ret;
+}
+EXPORT_SYMBOL_GPL(nf_nat_ipv4_in);
+
+unsigned int
+nf_nat_ipv4_out(const struct nf_hook_ops *ops, struct sk_buff *skb,
+		const struct net_device *in, const struct net_device *out,
+		unsigned int (*do_chain)(const struct nf_hook_ops *ops,
+					  struct sk_buff *skb,
+					  const struct net_device *in,
+					  const struct net_device *out,
+					  struct nf_conn *ct))
+{
+#ifdef CONFIG_XFRM
+	const struct nf_conn *ct;
+	enum ip_conntrack_info ctinfo;
+	int err;
+#endif
+	unsigned int ret;
+
+	/* root is playing with raw sockets. */
+	if (skb->len < sizeof(struct iphdr) ||
+	    ip_hdrlen(skb) < sizeof(struct iphdr))
+		return NF_ACCEPT;
+
+	ret = nf_nat_ipv4_fn(ops, skb, in, out, do_chain);
+#ifdef CONFIG_XFRM
+	if (ret != NF_DROP && ret != NF_STOLEN &&
+	    !(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
+	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
+		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
+
+		if ((ct->tuplehash[dir].tuple.src.u3.ip !=
+		     ct->tuplehash[!dir].tuple.dst.u3.ip) ||
+		    (ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMP &&
+		     ct->tuplehash[dir].tuple.src.u.all !=
+		     ct->tuplehash[!dir].tuple.dst.u.all)) {
+			err = nf_xfrm_me_harder(skb, AF_INET);
+			if (err < 0)
+				ret = NF_DROP_ERR(err);
+		}
+	}
+#endif
+	return ret;
+}
+EXPORT_SYMBOL_GPL(nf_nat_ipv4_out);
+
+unsigned int
+nf_nat_ipv4_local_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
+		     const struct net_device *in, const struct net_device *out,
+		     unsigned int (*do_chain)(const struct nf_hook_ops *ops,
+					       struct sk_buff *skb,
+					       const struct net_device *in,
+					       const struct net_device *out,
+					       struct nf_conn *ct))
+{
+	const struct nf_conn *ct;
+	enum ip_conntrack_info ctinfo;
+	unsigned int ret;
+	int err;
+
+	/* root is playing with raw sockets. */
+	if (skb->len < sizeof(struct iphdr) ||
+	    ip_hdrlen(skb) < sizeof(struct iphdr))
+		return NF_ACCEPT;
+
+	ret = nf_nat_ipv4_fn(ops, skb, in, out, do_chain);
+	if (ret != NF_DROP && ret != NF_STOLEN &&
+	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
+		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
+
+		if (ct->tuplehash[dir].tuple.dst.u3.ip !=
+		    ct->tuplehash[!dir].tuple.src.u3.ip) {
+			err = ip_route_me_harder(skb, RTN_UNSPEC);
+			if (err < 0)
+				ret = NF_DROP_ERR(err);
+		}
+#ifdef CONFIG_XFRM
+		else if (!(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
+			 ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMP &&
+			 ct->tuplehash[dir].tuple.dst.u.all !=
+			 ct->tuplehash[!dir].tuple.src.u.all) {
+			err = nf_xfrm_me_harder(skb, AF_INET);
+			if (err < 0)
+				ret = NF_DROP_ERR(err);
+		}
+#endif
+	}
+	return ret;
+}
+EXPORT_SYMBOL_GPL(nf_nat_ipv4_local_fn);
+
 static int __init nf_nat_l3proto_ipv4_init(void)
 {
 	int err;
diff -urN linux/net/ipv4/netfilter/nf_nat_masquerade_ipv4.c net-next-2.6/net/ipv4/netfilter/nf_nat_masquerade_ipv4.c
--- linux/net/ipv4/netfilter/nf_nat_masquerade_ipv4.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv4/netfilter/nf_nat_masquerade_ipv4.c	2014-10-06 10:49:00.344901613 +0200
@@ -0,0 +1,153 @@
+/* (C) 1999-2001 Paul `Rusty' Russell
+ * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ */
+
+#include <linux/types.h>
+#include <linux/module.h>
+#include <linux/atomic.h>
+#include <linux/inetdevice.h>
+#include <linux/ip.h>
+#include <linux/timer.h>
+#include <linux/netfilter.h>
+#include <net/protocol.h>
+#include <net/ip.h>
+#include <net/checksum.h>
+#include <net/route.h>
+#include <linux/netfilter_ipv4.h>
+#include <linux/netfilter/x_tables.h>
+#include <net/netfilter/nf_nat.h>
+#include <net/netfilter/ipv4/nf_nat_masquerade.h>
+
+unsigned int
+nf_nat_masquerade_ipv4(struct sk_buff *skb, unsigned int hooknum,
+		       const struct nf_nat_range *range,
+		       const struct net_device *out)
+{
+	struct nf_conn *ct;
+	struct nf_conn_nat *nat;
+	enum ip_conntrack_info ctinfo;
+	struct nf_nat_range newrange;
+	const struct rtable *rt;
+	__be32 newsrc, nh;
+
+	NF_CT_ASSERT(hooknum == NF_INET_POST_ROUTING);
+
+	ct = nf_ct_get(skb, &ctinfo);
+	nat = nfct_nat(ct);
+
+	NF_CT_ASSERT(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
+			    ctinfo == IP_CT_RELATED_REPLY));
+
+	/* Source address is 0.0.0.0 - locally generated packet that is
+	 * probably not supposed to be masqueraded.
+	 */
+	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip == 0)
+		return NF_ACCEPT;
+
+	rt = skb_rtable(skb);
+	nh = rt_nexthop(rt, ip_hdr(skb)->daddr);
+	newsrc = inet_select_addr(out, nh, RT_SCOPE_UNIVERSE);
+	if (!newsrc) {
+		pr_info("%s ate my IP address\n", out->name);
+		return NF_DROP;
+	}
+
+	nat->masq_index = out->ifindex;
+
+	/* Transfer from original range. */
+	memset(&newrange.min_addr, 0, sizeof(newrange.min_addr));
+	memset(&newrange.max_addr, 0, sizeof(newrange.max_addr));
+	newrange.flags       = range->flags | NF_NAT_RANGE_MAP_IPS;
+	newrange.min_addr.ip = newsrc;
+	newrange.max_addr.ip = newsrc;
+	newrange.min_proto   = range->min_proto;
+	newrange.max_proto   = range->max_proto;
+
+	/* Hand modified range to generic setup. */
+	return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_SRC);
+}
+EXPORT_SYMBOL_GPL(nf_nat_masquerade_ipv4);
+
+static int device_cmp(struct nf_conn *i, void *ifindex)
+{
+	const struct nf_conn_nat *nat = nfct_nat(i);
+
+	if (!nat)
+		return 0;
+	if (nf_ct_l3num(i) != NFPROTO_IPV4)
+		return 0;
+	return nat->masq_index == (int)(long)ifindex;
+}
+
+static int masq_device_event(struct notifier_block *this,
+			     unsigned long event,
+			     void *ptr)
+{
+	const struct net_device *dev = netdev_notifier_info_to_dev(ptr);
+	struct net *net = dev_net(dev);
+
+	if (event == NETDEV_DOWN) {
+		/* Device was downed.  Search entire table for
+		 * conntracks which were associated with that device,
+		 * and forget them.
+		 */
+		NF_CT_ASSERT(dev->ifindex != 0);
+
+		nf_ct_iterate_cleanup(net, device_cmp,
+				      (void *)(long)dev->ifindex, 0, 0);
+	}
+
+	return NOTIFY_DONE;
+}
+
+static int masq_inet_event(struct notifier_block *this,
+			   unsigned long event,
+			   void *ptr)
+{
+	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;
+	struct netdev_notifier_info info;
+
+	netdev_notifier_info_init(&info, dev);
+	return masq_device_event(this, event, &info);
+}
+
+static struct notifier_block masq_dev_notifier = {
+	.notifier_call	= masq_device_event,
+};
+
+static struct notifier_block masq_inet_notifier = {
+	.notifier_call	= masq_inet_event,
+};
+
+static atomic_t masquerade_notifier_refcount = ATOMIC_INIT(0);
+
+void nf_nat_masquerade_ipv4_register_notifier(void)
+{
+	/* check if the notifier was already set */
+	if (atomic_inc_return(&masquerade_notifier_refcount) > 1)
+		return;
+
+	/* Register for device down reports */
+	register_netdevice_notifier(&masq_dev_notifier);
+	/* Register IP address change reports */
+	register_inetaddr_notifier(&masq_inet_notifier);
+}
+EXPORT_SYMBOL_GPL(nf_nat_masquerade_ipv4_register_notifier);
+
+void nf_nat_masquerade_ipv4_unregister_notifier(void)
+{
+	/* check if the notifier still has clients */
+	if (atomic_dec_return(&masquerade_notifier_refcount) > 0)
+		return;
+
+	unregister_netdevice_notifier(&masq_dev_notifier);
+	unregister_inetaddr_notifier(&masq_inet_notifier);
+}
+EXPORT_SYMBOL_GPL(nf_nat_masquerade_ipv4_unregister_notifier);
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Rusty Russell <rusty@rustcorp.com.au>");
diff -urN linux/net/ipv4/netfilter/nf_reject_ipv4.c net-next-2.6/net/ipv4/netfilter/nf_reject_ipv4.c
--- linux/net/ipv4/netfilter/nf_reject_ipv4.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv4/netfilter/nf_reject_ipv4.c	2014-10-06 10:49:00.344901613 +0200
@@ -0,0 +1,127 @@
+/* (C) 1999-2001 Paul `Rusty' Russell
+ * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ */
+
+#include <net/ip.h>
+#include <net/tcp.h>
+#include <net/route.h>
+#include <net/dst.h>
+#include <linux/netfilter_ipv4.h>
+
+/* Send RST reply */
+void nf_send_reset(struct sk_buff *oldskb, int hook)
+{
+	struct sk_buff *nskb;
+	const struct iphdr *oiph;
+	struct iphdr *niph;
+	const struct tcphdr *oth;
+	struct tcphdr _otcph, *tcph;
+
+	/* IP header checks: fragment. */
+	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
+		return;
+
+	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
+				 sizeof(_otcph), &_otcph);
+	if (oth == NULL)
+		return;
+
+	/* No RST for RST. */
+	if (oth->rst)
+		return;
+
+	if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
+		return;
+
+	/* Check checksum */
+	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
+		return;
+	oiph = ip_hdr(oldskb);
+
+	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
+			 LL_MAX_HEADER, GFP_ATOMIC);
+	if (!nskb)
+		return;
+
+	skb_reserve(nskb, LL_MAX_HEADER);
+
+	skb_reset_network_header(nskb);
+	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
+	niph->version	= 4;
+	niph->ihl	= sizeof(struct iphdr) / 4;
+	niph->tos	= 0;
+	niph->id	= 0;
+	niph->frag_off	= htons(IP_DF);
+	niph->protocol	= IPPROTO_TCP;
+	niph->check	= 0;
+	niph->saddr	= oiph->daddr;
+	niph->daddr	= oiph->saddr;
+
+	skb_reset_transport_header(nskb);
+	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
+	memset(tcph, 0, sizeof(*tcph));
+	tcph->source	= oth->dest;
+	tcph->dest	= oth->source;
+	tcph->doff	= sizeof(struct tcphdr) / 4;
+
+	if (oth->ack)
+		tcph->seq = oth->ack_seq;
+	else {
+		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
+				      oldskb->len - ip_hdrlen(oldskb) -
+				      (oth->doff << 2));
+		tcph->ack = 1;
+	}
+
+	tcph->rst	= 1;
+	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
+				    niph->daddr, 0);
+	nskb->ip_summed = CHECKSUM_PARTIAL;
+	nskb->csum_start = (unsigned char *)tcph - nskb->head;
+	nskb->csum_offset = offsetof(struct tcphdr, check);
+
+	/* ip_route_me_harder expects skb->dst to be set */
+	skb_dst_set_noref(nskb, skb_dst(oldskb));
+
+	nskb->protocol = htons(ETH_P_IP);
+	if (ip_route_me_harder(nskb, RTN_UNSPEC))
+		goto free_nskb;
+
+	niph->ttl	= ip4_dst_hoplimit(skb_dst(nskb));
+
+	/* "Never happens" */
+	if (nskb->len > dst_mtu(skb_dst(nskb)))
+		goto free_nskb;
+
+	nf_ct_attach(nskb, oldskb);
+
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
+	/* If we use ip_local_out for bridged traffic, the MAC source on
+	 * the RST will be ours, instead of the destination's.  This confuses
+	 * some routers/firewalls, and they drop the packet.  So we need to
+	 * build the eth header using the original destination's MAC as the
+	 * source, and send the RST packet directly.
+	 */
+	if (oldskb->nf_bridge) {
+		struct ethhdr *oeth = eth_hdr(oldskb);
+		nskb->dev = oldskb->nf_bridge->physindev;
+		niph->tot_len = htons(nskb->len);
+		ip_send_check(niph);
+		if (dev_hard_header(nskb, nskb->dev, ntohs(nskb->protocol),
+				    oeth->h_source, oeth->h_dest, nskb->len) < 0)
+			goto free_nskb;
+		dev_queue_xmit(nskb);
+	} else
+#endif
+		ip_local_out(nskb);
+
+	return;
+
+ free_nskb:
+	kfree_skb(nskb);
+}
+EXPORT_SYMBOL_GPL(nf_send_reset);
diff -urN linux/net/ipv4/netfilter/nft_chain_nat_ipv4.c net-next-2.6/net/ipv4/netfilter/nft_chain_nat_ipv4.c
--- linux/net/ipv4/netfilter/nft_chain_nat_ipv4.c	2014-09-24 09:52:43.168644248 +0200
+++ net-next-2.6/net/ipv4/netfilter/nft_chain_nat_ipv4.c	2014-10-06 10:49:00.344901613 +0200
@@ -26,136 +26,53 @@
 #include <net/netfilter/nf_nat_l3proto.h>
 #include <net/ip.h>
 
-/*
- * NAT chains
- */
-
-static unsigned int nf_nat_fn(const struct nf_hook_ops *ops,
-			      struct sk_buff *skb,
-			      const struct net_device *in,
-			      const struct net_device *out,
-			      int (*okfn)(struct sk_buff *))
+static unsigned int nft_nat_do_chain(const struct nf_hook_ops *ops,
+				      struct sk_buff *skb,
+				      const struct net_device *in,
+				      const struct net_device *out,
+				      struct nf_conn *ct)
 {
-	enum ip_conntrack_info ctinfo;
-	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
-	struct nf_conn_nat *nat;
-	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);
 	struct nft_pktinfo pkt;
-	unsigned int ret;
-
-	if (ct == NULL || nf_ct_is_untracked(ct))
-		return NF_ACCEPT;
-
-	NF_CT_ASSERT(!(ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)));
 
-	nat = nf_ct_nat_ext_add(ct);
-	if (nat == NULL)
-		return NF_ACCEPT;
-
-	switch (ctinfo) {
-	case IP_CT_RELATED:
-	case IP_CT_RELATED + IP_CT_IS_REPLY:
-		if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
-			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
-							   ops->hooknum))
-				return NF_DROP;
-			else
-				return NF_ACCEPT;
-		}
-		/* Fall through */
-	case IP_CT_NEW:
-		if (nf_nat_initialized(ct, maniptype))
-			break;
-
-		nft_set_pktinfo_ipv4(&pkt, ops, skb, in, out);
-
-		ret = nft_do_chain(&pkt, ops);
-		if (ret != NF_ACCEPT)
-			return ret;
-		if (!nf_nat_initialized(ct, maniptype)) {
-			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);
-			if (ret != NF_ACCEPT)
-				return ret;
-		}
-	default:
-		break;
-	}
+	nft_set_pktinfo_ipv4(&pkt, ops, skb, in, out);
 
-	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);
+	return nft_do_chain(&pkt, ops);
 }
 
-static unsigned int nf_nat_prerouting(const struct nf_hook_ops *ops,
-				      struct sk_buff *skb,
-				      const struct net_device *in,
-				      const struct net_device *out,
-				      int (*okfn)(struct sk_buff *))
+static unsigned int nft_nat_ipv4_fn(const struct nf_hook_ops *ops,
+				    struct sk_buff *skb,
+				    const struct net_device *in,
+				    const struct net_device *out,
+				    int (*okfn)(struct sk_buff *))
 {
-	__be32 daddr = ip_hdr(skb)->daddr;
-	unsigned int ret;
+	return nf_nat_ipv4_fn(ops, skb, in, out, nft_nat_do_chain);
+}
 
-	ret = nf_nat_fn(ops, skb, in, out, okfn);
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    ip_hdr(skb)->daddr != daddr) {
-		skb_dst_drop(skb);
-	}
-	return ret;
+static unsigned int nft_nat_ipv4_in(const struct nf_hook_ops *ops,
+				    struct sk_buff *skb,
+				    const struct net_device *in,
+				    const struct net_device *out,
+				    int (*okfn)(struct sk_buff *))
+{
+	return nf_nat_ipv4_in(ops, skb, in, out, nft_nat_do_chain);
 }
 
-static unsigned int nf_nat_postrouting(const struct nf_hook_ops *ops,
-				       struct sk_buff *skb,
-				       const struct net_device *in,
-				       const struct net_device *out,
-				       int (*okfn)(struct sk_buff *))
+static unsigned int nft_nat_ipv4_out(const struct nf_hook_ops *ops,
+				     struct sk_buff *skb,
+				     const struct net_device *in,
+				     const struct net_device *out,
+				     int (*okfn)(struct sk_buff *))
 {
-	enum ip_conntrack_info ctinfo __maybe_unused;
-	const struct nf_conn *ct __maybe_unused;
-	unsigned int ret;
-
-	ret = nf_nat_fn(ops, skb, in, out, okfn);
-#ifdef CONFIG_XFRM
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
-		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
-
-		if (ct->tuplehash[dir].tuple.src.u3.ip !=
-		    ct->tuplehash[!dir].tuple.dst.u3.ip ||
-		    ct->tuplehash[dir].tuple.src.u.all !=
-		    ct->tuplehash[!dir].tuple.dst.u.all)
-			return nf_xfrm_me_harder(skb, AF_INET) == 0 ?
-								ret : NF_DROP;
-	}
-#endif
-	return ret;
+	return nf_nat_ipv4_out(ops, skb, in, out, nft_nat_do_chain);
 }
 
-static unsigned int nf_nat_output(const struct nf_hook_ops *ops,
-				  struct sk_buff *skb,
-				  const struct net_device *in,
-				  const struct net_device *out,
-				  int (*okfn)(struct sk_buff *))
+static unsigned int nft_nat_ipv4_local_fn(const struct nf_hook_ops *ops,
+					  struct sk_buff *skb,
+					  const struct net_device *in,
+					  const struct net_device *out,
+					  int (*okfn)(struct sk_buff *))
 {
-	enum ip_conntrack_info ctinfo;
-	const struct nf_conn *ct;
-	unsigned int ret;
-
-	ret = nf_nat_fn(ops, skb, in, out, okfn);
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
-		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
-
-		if (ct->tuplehash[dir].tuple.dst.u3.ip !=
-		    ct->tuplehash[!dir].tuple.src.u3.ip) {
-			if (ip_route_me_harder(skb, RTN_UNSPEC))
-				ret = NF_DROP;
-		}
-#ifdef CONFIG_XFRM
-		else if (ct->tuplehash[dir].tuple.dst.u.all !=
-			 ct->tuplehash[!dir].tuple.src.u.all)
-			if (nf_xfrm_me_harder(skb, AF_INET))
-				ret = NF_DROP;
-#endif
-	}
-	return ret;
+	return nf_nat_ipv4_local_fn(ops, skb, in, out, nft_nat_do_chain);
 }
 
 static const struct nf_chain_type nft_chain_nat_ipv4 = {
@@ -168,10 +85,10 @@
 			  (1 << NF_INET_LOCAL_OUT) |
 			  (1 << NF_INET_LOCAL_IN),
 	.hooks		= {
-		[NF_INET_PRE_ROUTING]	= nf_nat_prerouting,
-		[NF_INET_POST_ROUTING]	= nf_nat_postrouting,
-		[NF_INET_LOCAL_OUT]	= nf_nat_output,
-		[NF_INET_LOCAL_IN]	= nf_nat_fn,
+		[NF_INET_PRE_ROUTING]	= nft_nat_ipv4_in,
+		[NF_INET_POST_ROUTING]	= nft_nat_ipv4_out,
+		[NF_INET_LOCAL_OUT]	= nft_nat_ipv4_local_fn,
+		[NF_INET_LOCAL_IN]	= nft_nat_ipv4_fn,
 	},
 };
 
diff -urN linux/net/ipv4/netfilter/nft_masq_ipv4.c net-next-2.6/net/ipv4/netfilter/nft_masq_ipv4.c
--- linux/net/ipv4/netfilter/nft_masq_ipv4.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv4/netfilter/nft_masq_ipv4.c	2014-10-06 10:49:00.344901613 +0200
@@ -0,0 +1,77 @@
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
+#include <net/netfilter/nft_masq.h>
+#include <net/netfilter/ipv4/nf_nat_masquerade.h>
+
+static void nft_masq_ipv4_eval(const struct nft_expr *expr,
+			       struct nft_data data[NFT_REG_MAX + 1],
+			       const struct nft_pktinfo *pkt)
+{
+	struct nft_masq *priv = nft_expr_priv(expr);
+	struct nf_nat_range range;
+	unsigned int verdict;
+
+	range.flags = priv->flags;
+
+	verdict = nf_nat_masquerade_ipv4(pkt->skb, pkt->ops->hooknum,
+					 &range, pkt->out);
+
+	data[NFT_REG_VERDICT].verdict = verdict;
+}
+
+static struct nft_expr_type nft_masq_ipv4_type;
+static const struct nft_expr_ops nft_masq_ipv4_ops = {
+	.type		= &nft_masq_ipv4_type,
+	.size		= NFT_EXPR_SIZE(sizeof(struct nft_masq)),
+	.eval		= nft_masq_ipv4_eval,
+	.init		= nft_masq_init,
+	.dump		= nft_masq_dump,
+};
+
+static struct nft_expr_type nft_masq_ipv4_type __read_mostly = {
+	.family		= NFPROTO_IPV4,
+	.name		= "masq",
+	.ops		= &nft_masq_ipv4_ops,
+	.policy		= nft_masq_policy,
+	.maxattr	= NFTA_MASQ_MAX,
+	.owner		= THIS_MODULE,
+};
+
+static int __init nft_masq_ipv4_module_init(void)
+{
+	int ret;
+
+	ret = nft_register_expr(&nft_masq_ipv4_type);
+	if (ret < 0)
+		return ret;
+
+	nf_nat_masquerade_ipv4_register_notifier();
+
+	return ret;
+}
+
+static void __exit nft_masq_ipv4_module_exit(void)
+{
+	nft_unregister_expr(&nft_masq_ipv4_type);
+	nf_nat_masquerade_ipv4_unregister_notifier();
+}
+
+module_init(nft_masq_ipv4_module_init);
+module_exit(nft_masq_ipv4_module_exit);
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>");
+MODULE_ALIAS_NFT_AF_EXPR(AF_INET, "masq");
diff -urN linux/net/ipv4/netfilter/nft_reject_ipv4.c net-next-2.6/net/ipv4/netfilter/nft_reject_ipv4.c
--- linux/net/ipv4/netfilter/nft_reject_ipv4.c	2014-09-24 09:52:43.168644248 +0200
+++ net-next-2.6/net/ipv4/netfilter/nft_reject_ipv4.c	2014-10-06 10:49:00.344901613 +0200
@@ -16,7 +16,6 @@
 #include <linux/netfilter.h>
 #include <linux/netfilter/nf_tables.h>
 #include <net/netfilter/nf_tables.h>
-#include <net/icmp.h>
 #include <net/netfilter/ipv4/nf_reject.h>
 #include <net/netfilter/nft_reject.h>
 
diff -urN linux/net/ipv4/ping.c net-next-2.6/net/ipv4/ping.c
--- linux/net/ipv4/ping.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/ping.c	2014-10-06 10:49:00.348901654 +0200
@@ -311,7 +311,7 @@
 		if (addr->sin_addr.s_addr == htonl(INADDR_ANY))
 			chk_addr_ret = RTN_LOCAL;
 
-		if ((sysctl_ip_nonlocal_bind == 0 &&
+		if ((net->ipv4.sysctl_ip_nonlocal_bind == 0 &&
 		    isk->freebind == 0 && isk->transparent == 0 &&
 		     chk_addr_ret != RTN_LOCAL) ||
 		    chk_addr_ret == RTN_MULTICAST ||
diff -urN linux/net/ipv4/protocol.c net-next-2.6/net/ipv4/protocol.c
--- linux/net/ipv4/protocol.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/protocol.c	2014-10-06 10:49:00.348901654 +0200
@@ -30,6 +30,7 @@
 
 const struct net_protocol __rcu *inet_protos[MAX_INET_PROTOS] __read_mostly;
 const struct net_offload __rcu *inet_offloads[MAX_INET_PROTOS] __read_mostly;
+EXPORT_SYMBOL(inet_offloads);
 
 int inet_add_protocol(const struct net_protocol *prot, unsigned char protocol)
 {
diff -urN linux/net/ipv4/route.c net-next-2.6/net/ipv4/route.c
--- linux/net/ipv4/route.c	2014-10-06 10:59:24.267259086 +0200
+++ net-next-2.6/net/ipv4/route.c	2014-10-06 10:49:00.348901654 +0200
@@ -596,12 +596,12 @@
 
 static inline u32 fnhe_hashfun(__be32 daddr)
 {
+	static u32 fnhe_hashrnd __read_mostly;
 	u32 hval;
 
-	hval = (__force u32) daddr;
-	hval ^= (hval >> 11) ^ (hval >> 22);
-
-	return hval & (FNHE_HASH_SIZE - 1);
+	net_get_random_once(&fnhe_hashrnd, sizeof(fnhe_hashrnd));
+	hval = jhash_1word((__force u32) daddr, fnhe_hashrnd);
+	return hash_32(hval, FNHE_HASH_SHIFT);
 }
 
 static void fill_route_from_fnhe(struct rtable *rt, struct fib_nh_exception *fnhe)
@@ -628,12 +628,12 @@
 
 	spin_lock_bh(&fnhe_lock);
 
-	hash = nh->nh_exceptions;
+	hash = rcu_dereference(nh->nh_exceptions);
 	if (!hash) {
 		hash = kzalloc(FNHE_HASH_SIZE * sizeof(*hash), GFP_ATOMIC);
 		if (!hash)
 			goto out_unlock;
-		nh->nh_exceptions = hash;
+		rcu_assign_pointer(nh->nh_exceptions, hash);
 	}
 
 	hash += hval;
@@ -1242,7 +1242,7 @@
 
 static struct fib_nh_exception *find_exception(struct fib_nh *nh, __be32 daddr)
 {
-	struct fnhe_hash_bucket *hash = nh->nh_exceptions;
+	struct fnhe_hash_bucket *hash = rcu_dereference(nh->nh_exceptions);
 	struct fib_nh_exception *fnhe;
 	u32 hval;
 
diff -urN linux/net/ipv4/syncookies.c net-next-2.6/net/ipv4/syncookies.c
--- linux/net/ipv4/syncookies.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/syncookies.c	2014-10-06 10:49:00.348901654 +0200
@@ -25,7 +25,7 @@
 
 extern int sysctl_tcp_syncookies;
 
-static u32 syncookie_secret[2][16-4+SHA_DIGEST_WORDS];
+static u32 syncookie_secret[2][16-4+SHA_DIGEST_WORDS] __read_mostly;
 
 #define COOKIEBITS 24	/* Upper bits store count */
 #define COOKIEMASK (((__u32)1 << COOKIEBITS) - 1)
diff -urN linux/net/ipv4/sysctl_net_ipv4.c net-next-2.6/net/ipv4/sysctl_net_ipv4.c
--- linux/net/ipv4/sysctl_net_ipv4.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/sysctl_net_ipv4.c	2014-10-06 10:49:00.348901654 +0200
@@ -286,13 +286,6 @@
 		.extra2		= &ip_ttl_max,
 	},
 	{
-		.procname	= "ip_nonlocal_bind",
-		.data		= &sysctl_ip_nonlocal_bind,
-		.maxlen		= sizeof(int),
-		.mode		= 0644,
-		.proc_handler	= proc_dointvec
-	},
-	{
 		.procname	= "tcp_syn_retries",
 		.data		= &sysctl_tcp_syn_retries,
 		.maxlen		= sizeof(int),
@@ -450,6 +443,16 @@
 		.mode		= 0644,
 		.proc_handler	= proc_dointvec
 	},
+#ifdef CONFIG_IP_MULTICAST
+	{
+		.procname	= "igmp_qrv",
+		.data		= &sysctl_igmp_qrv,
+		.maxlen		= sizeof(int),
+		.mode		= 0644,
+		.proc_handler	= proc_dointvec_minmax,
+		.extra1		= &one
+	},
+#endif
 	{
 		.procname	= "inet_peer_threshold",
 		.data		= &inet_peer_threshold,
@@ -728,6 +731,22 @@
 		.extra2		= &one,
 	},
 	{
+		.procname	= "icmp_msgs_per_sec",
+		.data		= &sysctl_icmp_msgs_per_sec,
+		.maxlen		= sizeof(int),
+		.mode		= 0644,
+		.proc_handler	= proc_dointvec_minmax,
+		.extra1		= &zero,
+	},
+	{
+		.procname	= "icmp_msgs_burst",
+		.data		= &sysctl_icmp_msgs_burst,
+		.maxlen		= sizeof(int),
+		.mode		= 0644,
+		.proc_handler	= proc_dointvec_minmax,
+		.extra1		= &zero,
+	},
+	{
 		.procname	= "udp_mem",
 		.data		= &sysctl_udp_mem,
 		.maxlen		= sizeof(sysctl_udp_mem),
@@ -839,6 +858,13 @@
 		.proc_handler	= proc_dointvec,
 	},
 	{
+		.procname	= "ip_nonlocal_bind",
+		.data		= &init_net.ipv4.sysctl_ip_nonlocal_bind,
+		.maxlen		= sizeof(int),
+		.mode		= 0644,
+		.proc_handler	= proc_dointvec
+	},
+	{
 		.procname	= "fwmark_reflect",
 		.data		= &init_net.ipv4.sysctl_fwmark_reflect,
 		.maxlen		= sizeof(int),
diff -urN linux/net/ipv4/tcp_bic.c net-next-2.6/net/ipv4/tcp_bic.c
--- linux/net/ipv4/tcp_bic.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp_bic.c	2014-10-06 10:49:00.352901696 +0200
@@ -17,7 +17,6 @@
 #include <linux/module.h>
 #include <net/tcp.h>
 
-
 #define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
 					 * max_cwnd = snd_cwnd * beta
 					 */
@@ -46,11 +45,10 @@
 module_param(smooth_part, int, 0644);
 MODULE_PARM_DESC(smooth_part, "log(B/(B*Smin))/log(B/(B-1))+B, # of RTT from Wmax-B to Wmax");
 
-
 /* BIC TCP Parameters */
 struct bictcp {
 	u32	cnt;		/* increase cwnd by 1 after ACKs */
-	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
+	u32	last_max_cwnd;	/* last maximum snd_cwnd */
 	u32	loss_cwnd;	/* congestion window at last loss */
 	u32	last_cwnd;	/* the last snd_cwnd */
 	u32	last_time;	/* time when updated last_cwnd */
@@ -103,7 +101,7 @@
 
 	/* binary increase */
 	if (cwnd < ca->last_max_cwnd) {
-		__u32 	dist = (ca->last_max_cwnd - cwnd)
+		__u32	dist = (ca->last_max_cwnd - cwnd)
 			/ BICTCP_B;
 
 		if (dist > max_increment)
@@ -154,7 +152,6 @@
 		bictcp_update(ca, tp->snd_cwnd);
 		tcp_cong_avoid_ai(tp, ca->cnt);
 	}
-
 }
 
 /*
@@ -177,7 +174,6 @@
 
 	ca->loss_cwnd = tp->snd_cwnd;
 
-
 	if (tp->snd_cwnd <= low_window)
 		return max(tp->snd_cwnd >> 1U, 2U);
 	else
@@ -188,6 +184,7 @@
 {
 	const struct tcp_sock *tp = tcp_sk(sk);
 	const struct bictcp *ca = inet_csk_ca(sk);
+
 	return max(tp->snd_cwnd, ca->loss_cwnd);
 }
 
@@ -206,12 +203,12 @@
 
 	if (icsk->icsk_ca_state == TCP_CA_Open) {
 		struct bictcp *ca = inet_csk_ca(sk);
+
 		cnt -= ca->delayed_ack >> ACK_RATIO_SHIFT;
 		ca->delayed_ack += cnt;
 	}
 }
 
-
 static struct tcp_congestion_ops bictcp __read_mostly = {
 	.init		= bictcp_init,
 	.ssthresh	= bictcp_recalc_ssthresh,
diff -urN linux/net/ipv4/tcp.c net-next-2.6/net/ipv4/tcp.c
--- linux/net/ipv4/tcp.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp.c	2014-10-06 10:49:00.352901696 +0200
@@ -405,7 +405,7 @@
 
 	tp->reordering = sysctl_tcp_reordering;
 	tcp_enable_early_retrans(tp);
-	icsk->icsk_ca_ops = &tcp_init_congestion_ops;
+	tcp_assign_congestion_control(sk);
 
 	tp->tsoffset = 0;
 
@@ -609,7 +609,7 @@
 	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
 }
 
-static inline void skb_entail(struct sock *sk, struct sk_buff *skb)
+static void skb_entail(struct sock *sk, struct sk_buff *skb)
 {
 	struct tcp_sock *tp = tcp_sk(sk);
 	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
@@ -618,7 +618,7 @@
 	tcb->seq     = tcb->end_seq = tp->write_seq;
 	tcb->tcp_flags = TCPHDR_ACK;
 	tcb->sacked  = 0;
-	skb_header_release(skb);
+	__skb_header_release(skb);
 	tcp_add_write_queue_tail(sk, skb);
 	sk->sk_wmem_queued += skb->truesize;
 	sk_mem_charge(sk, skb->truesize);
@@ -963,7 +963,7 @@
 		skb->ip_summed = CHECKSUM_PARTIAL;
 		tp->write_seq += copy;
 		TCP_SKB_CB(skb)->end_seq += copy;
-		skb_shinfo(skb)->gso_segs = 0;
+		tcp_skb_pcount_set(skb, 0);
 
 		if (!copied)
 			TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;
@@ -1261,7 +1261,7 @@
 
 			tp->write_seq += copy;
 			TCP_SKB_CB(skb)->end_seq += copy;
-			skb_shinfo(skb)->gso_segs = 0;
+			tcp_skb_pcount_set(skb, 0);
 
 			from += copy;
 			copied += copy;
@@ -1510,9 +1510,9 @@
 
 	while ((skb = skb_peek(&sk->sk_receive_queue)) != NULL) {
 		offset = seq - TCP_SKB_CB(skb)->seq;
-		if (tcp_hdr(skb)->syn)
+		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
 			offset--;
-		if (offset < skb->len || tcp_hdr(skb)->fin) {
+		if (offset < skb->len || (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)) {
 			*off = offset;
 			return skb;
 		}
@@ -1585,7 +1585,7 @@
 			if (offset + 1 != skb->len)
 				continue;
 		}
-		if (tcp_hdr(skb)->fin) {
+		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) {
 			sk_eat_skb(sk, skb, false);
 			++seq;
 			break;
@@ -1722,11 +1722,11 @@
 				break;
 
 			offset = *seq - TCP_SKB_CB(skb)->seq;
-			if (tcp_hdr(skb)->syn)
+			if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
 				offset--;
 			if (offset < skb->len)
 				goto found_ok_skb;
-			if (tcp_hdr(skb)->fin)
+			if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
 				goto found_fin_ok;
 			WARN(!(flags & MSG_PEEK),
 			     "recvmsg bug 2: copied %X seq %X rcvnxt %X fl %X\n",
@@ -1959,7 +1959,7 @@
 		if (used + offset < skb->len)
 			continue;
 
-		if (tcp_hdr(skb)->fin)
+		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
 			goto found_fin_ok;
 		if (!(flags & MSG_PEEK)) {
 			sk_eat_skb(sk, skb, copied_early);
@@ -2160,8 +2160,10 @@
 	 *  reader process may not have drained the data yet!
 	 */
 	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
-		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
-			  tcp_hdr(skb)->fin;
+		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;
+
+		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
+			len--;
 		data_was_unread += len;
 		__kfree_skb(skb);
 	}
@@ -2691,7 +2693,7 @@
 		break;
 #endif
 	case TCP_USER_TIMEOUT:
-		/* Cap the max timeout in ms TCP will retry/retrans
+		/* Cap the max time in ms TCP will retry or probe the window
 		 * before giving up and aborting (ETIMEDOUT) a connection.
 		 */
 		if (val < 0)
@@ -3170,7 +3172,7 @@
 }
 __setup("thash_entries=", set_thash_entries);
 
-static void tcp_init_mem(void)
+static void __init tcp_init_mem(void)
 {
 	unsigned long limit = nr_free_buffer_pages() / 8;
 	limit = max(limit, 128UL);
@@ -3256,8 +3258,6 @@
 		tcp_hashinfo.ehash_mask + 1, tcp_hashinfo.bhash_size);
 
 	tcp_metrics_init();
-
-	tcp_register_congestion_control(&tcp_reno);
-
+	BUG_ON(tcp_register_congestion_control(&tcp_reno) != 0);
 	tcp_tasklet_init();
 }
diff -urN linux/net/ipv4/tcp_cong.c net-next-2.6/net/ipv4/tcp_cong.c
--- linux/net/ipv4/tcp_cong.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp_cong.c	2014-10-06 10:49:00.352901696 +0200
@@ -74,24 +74,34 @@
 EXPORT_SYMBOL_GPL(tcp_unregister_congestion_control);
 
 /* Assign choice of congestion control. */
-void tcp_init_congestion_control(struct sock *sk)
+void tcp_assign_congestion_control(struct sock *sk)
 {
 	struct inet_connection_sock *icsk = inet_csk(sk);
 	struct tcp_congestion_ops *ca;
 
-	/* if no choice made yet assign the current value set as default */
-	if (icsk->icsk_ca_ops == &tcp_init_congestion_ops) {
-		rcu_read_lock();
-		list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
-			if (try_module_get(ca->owner)) {
-				icsk->icsk_ca_ops = ca;
-				break;
-			}
-
-			/* fallback to next available */
+	rcu_read_lock();
+	list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
+		if (likely(try_module_get(ca->owner))) {
+			icsk->icsk_ca_ops = ca;
+			goto out;
 		}
-		rcu_read_unlock();
+		/* Fallback to next available. The last really
+		 * guaranteed fallback is Reno from this list.
+		 */
 	}
+out:
+	rcu_read_unlock();
+
+	/* Clear out private data before diag gets it and
+	 * the ca has not been initialized.
+	 */
+	if (ca->get_info)
+		memset(icsk->icsk_ca_priv, 0, sizeof(icsk->icsk_ca_priv));
+}
+
+void tcp_init_congestion_control(struct sock *sk)
+{
+	const struct inet_connection_sock *icsk = inet_csk(sk);
 
 	if (icsk->icsk_ca_ops->init)
 		icsk->icsk_ca_ops->init(sk);
@@ -142,7 +152,6 @@
 }
 late_initcall(tcp_congestion_default);
 
-
 /* Build string with list of available congestion control values */
 void tcp_get_available_congestion_control(char *buf, size_t maxlen)
 {
@@ -154,7 +163,6 @@
 		offs += snprintf(buf + offs, maxlen - offs,
 				 "%s%s",
 				 offs == 0 ? "" : " ", ca->name);
-
 	}
 	rcu_read_unlock();
 }
@@ -186,7 +194,6 @@
 		offs += snprintf(buf + offs, maxlen - offs,
 				 "%s%s",
 				 offs == 0 ? "" : " ", ca->name);
-
 	}
 	rcu_read_unlock();
 }
@@ -230,7 +237,6 @@
 	return ret;
 }
 
-
 /* Change congestion control for socket */
 int tcp_set_congestion_control(struct sock *sk, const char *name)
 {
@@ -285,15 +291,13 @@
  * ABC caps N to 2. Slow start exits when cwnd grows over ssthresh and
  * returns the leftover acks to adjust cwnd in congestion avoidance mode.
  */
-int tcp_slow_start(struct tcp_sock *tp, u32 acked)
+void tcp_slow_start(struct tcp_sock *tp, u32 acked)
 {
 	u32 cwnd = tp->snd_cwnd + acked;
 
 	if (cwnd > tp->snd_ssthresh)
 		cwnd = tp->snd_ssthresh + 1;
-	acked -= cwnd - tp->snd_cwnd;
 	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
-	return acked;
 }
 EXPORT_SYMBOL_GPL(tcp_slow_start);
 
@@ -337,6 +341,7 @@
 u32 tcp_reno_ssthresh(struct sock *sk)
 {
 	const struct tcp_sock *tp = tcp_sk(sk);
+
 	return max(tp->snd_cwnd >> 1U, 2U);
 }
 EXPORT_SYMBOL_GPL(tcp_reno_ssthresh);
@@ -348,15 +353,3 @@
 	.ssthresh	= tcp_reno_ssthresh,
 	.cong_avoid	= tcp_reno_cong_avoid,
 };
-
-/* Initial congestion control used (until SYN)
- * really reno under another name so we can tell difference
- * during tcp_set_default_congestion_control
- */
-struct tcp_congestion_ops tcp_init_congestion_ops  = {
-	.name		= "",
-	.owner		= THIS_MODULE,
-	.ssthresh	= tcp_reno_ssthresh,
-	.cong_avoid	= tcp_reno_cong_avoid,
-};
-EXPORT_SYMBOL_GPL(tcp_init_congestion_ops);
diff -urN linux/net/ipv4/tcp_cubic.c net-next-2.6/net/ipv4/tcp_cubic.c
--- linux/net/ipv4/tcp_cubic.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp_cubic.c	2014-10-06 10:49:00.352901696 +0200
@@ -82,12 +82,13 @@
 /* BIC TCP Parameters */
 struct bictcp {
 	u32	cnt;		/* increase cwnd by 1 after ACKs */
-	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
+	u32	last_max_cwnd;	/* last maximum snd_cwnd */
 	u32	loss_cwnd;	/* congestion window at last loss */
 	u32	last_cwnd;	/* the last snd_cwnd */
 	u32	last_time;	/* time when updated last_cwnd */
 	u32	bic_origin_point;/* origin point of bic function */
-	u32	bic_K;		/* time to origin point from the beginning of the current epoch */
+	u32	bic_K;		/* time to origin point
+				   from the beginning of the current epoch */
 	u32	delay_min;	/* min delay (msec << 3) */
 	u32	epoch_start;	/* beginning of an epoch */
 	u32	ack_cnt;	/* number of acks */
@@ -219,7 +220,7 @@
 	ca->last_time = tcp_time_stamp;
 
 	if (ca->epoch_start == 0) {
-		ca->epoch_start = tcp_time_stamp;	/* record the beginning of an epoch */
+		ca->epoch_start = tcp_time_stamp;	/* record beginning */
 		ca->ack_cnt = 1;			/* start counting */
 		ca->tcp_cwnd = cwnd;			/* syn with cubic */
 
@@ -263,9 +264,9 @@
 
 	/* c/rtt * (t-K)^3 */
 	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
-	if (t < ca->bic_K)                                	/* below origin*/
+	if (t < ca->bic_K)                            /* below origin*/
 		bic_target = ca->bic_origin_point - delta;
-	else                                                	/* above origin*/
+	else                                          /* above origin*/
 		bic_target = ca->bic_origin_point + delta;
 
 	/* cubic function - calc bictcp_cnt*/
@@ -285,13 +286,14 @@
 	/* TCP Friendly */
 	if (tcp_friendliness) {
 		u32 scale = beta_scale;
+
 		delta = (cwnd * scale) >> 3;
 		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
 			ca->ack_cnt -= delta;
 			ca->tcp_cwnd++;
 		}
 
-		if (ca->tcp_cwnd > cwnd){	/* if bic is slower than tcp */
+		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
 			delta = ca->tcp_cwnd - cwnd;
 			max_cnt = cwnd / delta;
 			if (ca->cnt > max_cnt)
@@ -320,7 +322,6 @@
 		bictcp_update(ca, tp->snd_cwnd);
 		tcp_cong_avoid_ai(tp, ca->cnt);
 	}
-
 }
 
 static u32 bictcp_recalc_ssthresh(struct sock *sk)
@@ -452,7 +453,8 @@
 	 * based on SRTT of 100ms
 	 */
 
-	beta_scale = 8*(BICTCP_BETA_SCALE+beta)/ 3 / (BICTCP_BETA_SCALE - beta);
+	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3
+		/ (BICTCP_BETA_SCALE - beta);
 
 	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */
 
diff -urN linux/net/ipv4/tcp_dctcp.c net-next-2.6/net/ipv4/tcp_dctcp.c
--- linux/net/ipv4/tcp_dctcp.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv4/tcp_dctcp.c	2014-10-06 10:49:00.352901696 +0200
@@ -0,0 +1,344 @@
+/* DataCenter TCP (DCTCP) congestion control.
+ *
+ * http://simula.stanford.edu/~alizade/Site/DCTCP.html
+ *
+ * This is an implementation of DCTCP over Reno, an enhancement to the
+ * TCP congestion control algorithm designed for data centers. DCTCP
+ * leverages Explicit Congestion Notification (ECN) in the network to
+ * provide multi-bit feedback to the end hosts. DCTCP's goal is to meet
+ * the following three data center transport requirements:
+ *
+ *  - High burst tolerance (incast due to partition/aggregate)
+ *  - Low latency (short flows, queries)
+ *  - High throughput (continuous data updates, large file transfers)
+ *    with commodity shallow buffered switches
+ *
+ * The algorithm is described in detail in the following two papers:
+ *
+ * 1) Mohammad Alizadeh, Albert Greenberg, David A. Maltz, Jitendra Padhye,
+ *    Parveen Patel, Balaji Prabhakar, Sudipta Sengupta, and Murari Sridharan:
+ *      "Data Center TCP (DCTCP)", Data Center Networks session
+ *      Proc. ACM SIGCOMM, New Delhi, 2010.
+ *   http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp-final.pdf
+ *
+ * 2) Mohammad Alizadeh, Adel Javanmard, and Balaji Prabhakar:
+ *      "Analysis of DCTCP: Stability, Convergence, and Fairness"
+ *      Proc. ACM SIGMETRICS, San Jose, 2011.
+ *   http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp_analysis-full.pdf
+ *
+ * Initial prototype from Abdul Kabbani, Masato Yasuda and Mohammad Alizadeh.
+ *
+ * Authors:
+ *
+ *	Daniel Borkmann <dborkman@redhat.com>
+ *	Florian Westphal <fw@strlen.de>
+ *	Glenn Judd <glenn.judd@morganstanley.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published by
+ * the Free Software Foundation; either version 2 of the License, or (at
+ * your option) any later version.
+ */
+
+#include <linux/module.h>
+#include <linux/mm.h>
+#include <net/tcp.h>
+#include <linux/inet_diag.h>
+
+#define DCTCP_MAX_ALPHA	1024U
+
+struct dctcp {
+	u32 acked_bytes_ecn;
+	u32 acked_bytes_total;
+	u32 prior_snd_una;
+	u32 prior_rcv_nxt;
+	u32 dctcp_alpha;
+	u32 next_seq;
+	u32 ce_state;
+	u32 delayed_ack_reserved;
+};
+
+static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
+module_param(dctcp_shift_g, uint, 0644);
+MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");
+
+static unsigned int dctcp_alpha_on_init __read_mostly = DCTCP_MAX_ALPHA;
+module_param(dctcp_alpha_on_init, uint, 0644);
+MODULE_PARM_DESC(dctcp_alpha_on_init, "parameter for initial alpha value");
+
+static unsigned int dctcp_clamp_alpha_on_loss __read_mostly;
+module_param(dctcp_clamp_alpha_on_loss, uint, 0644);
+MODULE_PARM_DESC(dctcp_clamp_alpha_on_loss,
+		 "parameter for clamping alpha on loss");
+
+static struct tcp_congestion_ops dctcp_reno;
+
+static void dctcp_reset(const struct tcp_sock *tp, struct dctcp *ca)
+{
+	ca->next_seq = tp->snd_nxt;
+
+	ca->acked_bytes_ecn = 0;
+	ca->acked_bytes_total = 0;
+}
+
+static void dctcp_init(struct sock *sk)
+{
+	const struct tcp_sock *tp = tcp_sk(sk);
+
+	if ((tp->ecn_flags & TCP_ECN_OK) ||
+	    (sk->sk_state == TCP_LISTEN ||
+	     sk->sk_state == TCP_CLOSE)) {
+		struct dctcp *ca = inet_csk_ca(sk);
+
+		ca->prior_snd_una = tp->snd_una;
+		ca->prior_rcv_nxt = tp->rcv_nxt;
+
+		ca->dctcp_alpha = min(dctcp_alpha_on_init, DCTCP_MAX_ALPHA);
+
+		ca->delayed_ack_reserved = 0;
+		ca->ce_state = 0;
+
+		dctcp_reset(tp, ca);
+		return;
+	}
+
+	/* No ECN support? Fall back to Reno. Also need to clear
+	 * ECT from sk since it is set during 3WHS for DCTCP.
+	 */
+	inet_csk(sk)->icsk_ca_ops = &dctcp_reno;
+	INET_ECN_dontxmit(sk);
+}
+
+static u32 dctcp_ssthresh(struct sock *sk)
+{
+	const struct dctcp *ca = inet_csk_ca(sk);
+	struct tcp_sock *tp = tcp_sk(sk);
+
+	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
+}
+
+/* Minimal DCTP CE state machine:
+ *
+ * S:	0 <- last pkt was non-CE
+ *	1 <- last pkt was CE
+ */
+
+static void dctcp_ce_state_0_to_1(struct sock *sk)
+{
+	struct dctcp *ca = inet_csk_ca(sk);
+	struct tcp_sock *tp = tcp_sk(sk);
+
+	/* State has changed from CE=0 to CE=1 and delayed
+	 * ACK has not sent yet.
+	 */
+	if (!ca->ce_state && ca->delayed_ack_reserved) {
+		u32 tmp_rcv_nxt;
+
+		/* Save current rcv_nxt. */
+		tmp_rcv_nxt = tp->rcv_nxt;
+
+		/* Generate previous ack with CE=0. */
+		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
+		tp->rcv_nxt = ca->prior_rcv_nxt;
+
+		tcp_send_ack(sk);
+
+		/* Recover current rcv_nxt. */
+		tp->rcv_nxt = tmp_rcv_nxt;
+	}
+
+	ca->prior_rcv_nxt = tp->rcv_nxt;
+	ca->ce_state = 1;
+
+	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
+}
+
+static void dctcp_ce_state_1_to_0(struct sock *sk)
+{
+	struct dctcp *ca = inet_csk_ca(sk);
+	struct tcp_sock *tp = tcp_sk(sk);
+
+	/* State has changed from CE=1 to CE=0 and delayed
+	 * ACK has not sent yet.
+	 */
+	if (ca->ce_state && ca->delayed_ack_reserved) {
+		u32 tmp_rcv_nxt;
+
+		/* Save current rcv_nxt. */
+		tmp_rcv_nxt = tp->rcv_nxt;
+
+		/* Generate previous ack with CE=1. */
+		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
+		tp->rcv_nxt = ca->prior_rcv_nxt;
+
+		tcp_send_ack(sk);
+
+		/* Recover current rcv_nxt. */
+		tp->rcv_nxt = tmp_rcv_nxt;
+	}
+
+	ca->prior_rcv_nxt = tp->rcv_nxt;
+	ca->ce_state = 0;
+
+	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
+}
+
+static void dctcp_update_alpha(struct sock *sk, u32 flags)
+{
+	const struct tcp_sock *tp = tcp_sk(sk);
+	struct dctcp *ca = inet_csk_ca(sk);
+	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;
+
+	/* If ack did not advance snd_una, count dupack as MSS size.
+	 * If ack did update window, do not count it at all.
+	 */
+	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
+		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
+	if (acked_bytes) {
+		ca->acked_bytes_total += acked_bytes;
+		ca->prior_snd_una = tp->snd_una;
+
+		if (flags & CA_ACK_ECE)
+			ca->acked_bytes_ecn += acked_bytes;
+	}
+
+	/* Expired RTT */
+	if (!before(tp->snd_una, ca->next_seq)) {
+		/* For avoiding denominator == 1. */
+		if (ca->acked_bytes_total == 0)
+			ca->acked_bytes_total = 1;
+
+		/* alpha = (1 - g) * alpha + g * F */
+		ca->dctcp_alpha = ca->dctcp_alpha -
+				  (ca->dctcp_alpha >> dctcp_shift_g) +
+				  (ca->acked_bytes_ecn << (10U - dctcp_shift_g)) /
+				  ca->acked_bytes_total;
+
+		if (ca->dctcp_alpha > DCTCP_MAX_ALPHA)
+			/* Clamp dctcp_alpha to max. */
+			ca->dctcp_alpha = DCTCP_MAX_ALPHA;
+
+		dctcp_reset(tp, ca);
+	}
+}
+
+static void dctcp_state(struct sock *sk, u8 new_state)
+{
+	if (dctcp_clamp_alpha_on_loss && new_state == TCP_CA_Loss) {
+		struct dctcp *ca = inet_csk_ca(sk);
+
+		/* If this extension is enabled, we clamp dctcp_alpha to
+		 * max on packet loss; the motivation is that dctcp_alpha
+		 * is an indicator to the extend of congestion and packet
+		 * loss is an indicator of extreme congestion; setting
+		 * this in practice turned out to be beneficial, and
+		 * effectively assumes total congestion which reduces the
+		 * window by half.
+		 */
+		ca->dctcp_alpha = DCTCP_MAX_ALPHA;
+	}
+}
+
+static void dctcp_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
+{
+	struct dctcp *ca = inet_csk_ca(sk);
+
+	switch (ev) {
+	case CA_EVENT_DELAYED_ACK:
+		if (!ca->delayed_ack_reserved)
+			ca->delayed_ack_reserved = 1;
+		break;
+	case CA_EVENT_NON_DELAYED_ACK:
+		if (ca->delayed_ack_reserved)
+			ca->delayed_ack_reserved = 0;
+		break;
+	default:
+		/* Don't care for the rest. */
+		break;
+	}
+}
+
+static void dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
+{
+	switch (ev) {
+	case CA_EVENT_ECN_IS_CE:
+		dctcp_ce_state_0_to_1(sk);
+		break;
+	case CA_EVENT_ECN_NO_CE:
+		dctcp_ce_state_1_to_0(sk);
+		break;
+	case CA_EVENT_DELAYED_ACK:
+	case CA_EVENT_NON_DELAYED_ACK:
+		dctcp_update_ack_reserved(sk, ev);
+		break;
+	default:
+		/* Don't care for the rest. */
+		break;
+	}
+}
+
+static void dctcp_get_info(struct sock *sk, u32 ext, struct sk_buff *skb)
+{
+	const struct dctcp *ca = inet_csk_ca(sk);
+
+	/* Fill it also in case of VEGASINFO due to req struct limits.
+	 * We can still correctly retrieve it later.
+	 */
+	if (ext & (1 << (INET_DIAG_DCTCPINFO - 1)) ||
+	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
+		struct tcp_dctcp_info info;
+
+		memset(&info, 0, sizeof(info));
+		if (inet_csk(sk)->icsk_ca_ops != &dctcp_reno) {
+			info.dctcp_enabled = 1;
+			info.dctcp_ce_state = (u16) ca->ce_state;
+			info.dctcp_alpha = ca->dctcp_alpha;
+			info.dctcp_ab_ecn = ca->acked_bytes_ecn;
+			info.dctcp_ab_tot = ca->acked_bytes_total;
+		}
+
+		nla_put(skb, INET_DIAG_DCTCPINFO, sizeof(info), &info);
+	}
+}
+
+static struct tcp_congestion_ops dctcp __read_mostly = {
+	.init		= dctcp_init,
+	.in_ack_event   = dctcp_update_alpha,
+	.cwnd_event	= dctcp_cwnd_event,
+	.ssthresh	= dctcp_ssthresh,
+	.cong_avoid	= tcp_reno_cong_avoid,
+	.set_state	= dctcp_state,
+	.get_info	= dctcp_get_info,
+	.flags		= TCP_CONG_NEEDS_ECN,
+	.owner		= THIS_MODULE,
+	.name		= "dctcp",
+};
+
+static struct tcp_congestion_ops dctcp_reno __read_mostly = {
+	.ssthresh	= tcp_reno_ssthresh,
+	.cong_avoid	= tcp_reno_cong_avoid,
+	.get_info	= dctcp_get_info,
+	.owner		= THIS_MODULE,
+	.name		= "dctcp-reno",
+};
+
+static int __init dctcp_register(void)
+{
+	BUILD_BUG_ON(sizeof(struct dctcp) > ICSK_CA_PRIV_SIZE);
+	return tcp_register_congestion_control(&dctcp);
+}
+
+static void __exit dctcp_unregister(void)
+{
+	tcp_unregister_congestion_control(&dctcp);
+}
+
+module_init(dctcp_register);
+module_exit(dctcp_unregister);
+
+MODULE_AUTHOR("Daniel Borkmann <dborkman@redhat.com>");
+MODULE_AUTHOR("Florian Westphal <fw@strlen.de>");
+MODULE_AUTHOR("Glenn Judd <glenn.judd@morganstanley.com>");
+
+MODULE_LICENSE("GPL v2");
+MODULE_DESCRIPTION("DataCenter TCP (DCTCP)");
diff -urN linux/net/ipv4/tcp_diag.c net-next-2.6/net/ipv4/tcp_diag.c
--- linux/net/ipv4/tcp_diag.c	2013-05-02 09:43:20.649515168 +0200
+++ net-next-2.6/net/ipv4/tcp_diag.c	2014-10-06 10:49:00.352901696 +0200
@@ -9,7 +9,6 @@
  *      2 of the License, or (at your option) any later version.
  */
 
-
 #include <linux/module.h>
 #include <linux/inet_diag.h>
 
@@ -35,13 +34,13 @@
 }
 
 static void tcp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
-		struct inet_diag_req_v2 *r, struct nlattr *bc)
+			  struct inet_diag_req_v2 *r, struct nlattr *bc)
 {
 	inet_diag_dump_icsk(&tcp_hashinfo, skb, cb, r, bc);
 }
 
 static int tcp_diag_dump_one(struct sk_buff *in_skb, const struct nlmsghdr *nlh,
-		struct inet_diag_req_v2 *req)
+			     struct inet_diag_req_v2 *req)
 {
 	return inet_diag_dump_one_icsk(&tcp_hashinfo, in_skb, nlh, req);
 }
diff -urN linux/net/ipv4/tcp_fastopen.c net-next-2.6/net/ipv4/tcp_fastopen.c
--- linux/net/ipv4/tcp_fastopen.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp_fastopen.c	2014-10-06 10:49:00.352901696 +0200
@@ -115,7 +115,7 @@
 
 		if (__tcp_fastopen_cookie_gen(&ip6h->saddr, &tmp)) {
 			struct in6_addr *buf = (struct in6_addr *) tmp.val;
-			int i = 4;
+			int i;
 
 			for (i = 0; i < 4; i++)
 				buf->s6_addr32[i] ^= ip6h->daddr.s6_addr32[i];
diff -urN linux/net/ipv4/tcp_highspeed.c net-next-2.6/net/ipv4/tcp_highspeed.c
--- linux/net/ipv4/tcp_highspeed.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp_highspeed.c	2014-10-06 10:49:00.376901940 +0200
@@ -9,7 +9,6 @@
 #include <linux/module.h>
 #include <net/tcp.h>
 
-
 /* From AIMD tables from RFC 3649 appendix B,
  * with fixed-point MD scaled <<8.
  */
@@ -17,78 +16,78 @@
 	unsigned int cwnd;
 	unsigned int md;
 } hstcp_aimd_vals[] = {
- {     38,  128, /*  0.50 */ },
- {    118,  112, /*  0.44 */ },
- {    221,  104, /*  0.41 */ },
- {    347,   98, /*  0.38 */ },
- {    495,   93, /*  0.37 */ },
- {    663,   89, /*  0.35 */ },
- {    851,   86, /*  0.34 */ },
- {   1058,   83, /*  0.33 */ },
- {   1284,   81, /*  0.32 */ },
- {   1529,   78, /*  0.31 */ },
- {   1793,   76, /*  0.30 */ },
- {   2076,   74, /*  0.29 */ },
- {   2378,   72, /*  0.28 */ },
- {   2699,   71, /*  0.28 */ },
- {   3039,   69, /*  0.27 */ },
- {   3399,   68, /*  0.27 */ },
- {   3778,   66, /*  0.26 */ },
- {   4177,   65, /*  0.26 */ },
- {   4596,   64, /*  0.25 */ },
- {   5036,   62, /*  0.25 */ },
- {   5497,   61, /*  0.24 */ },
- {   5979,   60, /*  0.24 */ },
- {   6483,   59, /*  0.23 */ },
- {   7009,   58, /*  0.23 */ },
- {   7558,   57, /*  0.22 */ },
- {   8130,   56, /*  0.22 */ },
- {   8726,   55, /*  0.22 */ },
- {   9346,   54, /*  0.21 */ },
- {   9991,   53, /*  0.21 */ },
- {  10661,   52, /*  0.21 */ },
- {  11358,   52, /*  0.20 */ },
- {  12082,   51, /*  0.20 */ },
- {  12834,   50, /*  0.20 */ },
- {  13614,   49, /*  0.19 */ },
- {  14424,   48, /*  0.19 */ },
- {  15265,   48, /*  0.19 */ },
- {  16137,   47, /*  0.19 */ },
- {  17042,   46, /*  0.18 */ },
- {  17981,   45, /*  0.18 */ },
- {  18955,   45, /*  0.18 */ },
- {  19965,   44, /*  0.17 */ },
- {  21013,   43, /*  0.17 */ },
- {  22101,   43, /*  0.17 */ },
- {  23230,   42, /*  0.17 */ },
- {  24402,   41, /*  0.16 */ },
- {  25618,   41, /*  0.16 */ },
- {  26881,   40, /*  0.16 */ },
- {  28193,   39, /*  0.16 */ },
- {  29557,   39, /*  0.15 */ },
- {  30975,   38, /*  0.15 */ },
- {  32450,   38, /*  0.15 */ },
- {  33986,   37, /*  0.15 */ },
- {  35586,   36, /*  0.14 */ },
- {  37253,   36, /*  0.14 */ },
- {  38992,   35, /*  0.14 */ },
- {  40808,   35, /*  0.14 */ },
- {  42707,   34, /*  0.13 */ },
- {  44694,   33, /*  0.13 */ },
- {  46776,   33, /*  0.13 */ },
- {  48961,   32, /*  0.13 */ },
- {  51258,   32, /*  0.13 */ },
- {  53677,   31, /*  0.12 */ },
- {  56230,   30, /*  0.12 */ },
- {  58932,   30, /*  0.12 */ },
- {  61799,   29, /*  0.12 */ },
- {  64851,   28, /*  0.11 */ },
- {  68113,   28, /*  0.11 */ },
- {  71617,   27, /*  0.11 */ },
- {  75401,   26, /*  0.10 */ },
- {  79517,   26, /*  0.10 */ },
- {  84035,   25, /*  0.10 */ },
- {  89053,   24, /*  0.10 */ },
+	{     38,  128, /*  0.50 */ },
+	{    118,  112, /*  0.44 */ },
+	{    221,  104, /*  0.41 */ },
+	{    347,   98, /*  0.38 */ },
+	{    495,   93, /*  0.37 */ },
+	{    663,   89, /*  0.35 */ },
+	{    851,   86, /*  0.34 */ },
+	{   1058,   83, /*  0.33 */ },
+	{   1284,   81, /*  0.32 */ },
+	{   1529,   78, /*  0.31 */ },
+	{   1793,   76, /*  0.30 */ },
+	{   2076,   74, /*  0.29 */ },
+	{   2378,   72, /*  0.28 */ },
+	{   2699,   71, /*  0.28 */ },
+	{   3039,   69, /*  0.27 */ },
+	{   3399,   68, /*  0.27 */ },
+	{   3778,   66, /*  0.26 */ },
+	{   4177,   65, /*  0.26 */ },
+	{   4596,   64, /*  0.25 */ },
+	{   5036,   62, /*  0.25 */ },
+	{   5497,   61, /*  0.24 */ },
+	{   5979,   60, /*  0.24 */ },
+	{   6483,   59, /*  0.23 */ },
+	{   7009,   58, /*  0.23 */ },
+	{   7558,   57, /*  0.22 */ },
+	{   8130,   56, /*  0.22 */ },
+	{   8726,   55, /*  0.22 */ },
+	{   9346,   54, /*  0.21 */ },
+	{   9991,   53, /*  0.21 */ },
+	{  10661,   52, /*  0.21 */ },
+	{  11358,   52, /*  0.20 */ },
+	{  12082,   51, /*  0.20 */ },
+	{  12834,   50, /*  0.20 */ },
+	{  13614,   49, /*  0.19 */ },
+	{  14424,   48, /*  0.19 */ },
+	{  15265,   48, /*  0.19 */ },
+	{  16137,   47, /*  0.19 */ },
+	{  17042,   46, /*  0.18 */ },
+	{  17981,   45, /*  0.18 */ },
+	{  18955,   45, /*  0.18 */ },
+	{  19965,   44, /*  0.17 */ },
+	{  21013,   43, /*  0.17 */ },
+	{  22101,   43, /*  0.17 */ },
+	{  23230,   42, /*  0.17 */ },
+	{  24402,   41, /*  0.16 */ },
+	{  25618,   41, /*  0.16 */ },
+	{  26881,   40, /*  0.16 */ },
+	{  28193,   39, /*  0.16 */ },
+	{  29557,   39, /*  0.15 */ },
+	{  30975,   38, /*  0.15 */ },
+	{  32450,   38, /*  0.15 */ },
+	{  33986,   37, /*  0.15 */ },
+	{  35586,   36, /*  0.14 */ },
+	{  37253,   36, /*  0.14 */ },
+	{  38992,   35, /*  0.14 */ },
+	{  40808,   35, /*  0.14 */ },
+	{  42707,   34, /*  0.13 */ },
+	{  44694,   33, /*  0.13 */ },
+	{  46776,   33, /*  0.13 */ },
+	{  48961,   32, /*  0.13 */ },
+	{  51258,   32, /*  0.13 */ },
+	{  53677,   31, /*  0.12 */ },
+	{  56230,   30, /*  0.12 */ },
+	{  58932,   30, /*  0.12 */ },
+	{  61799,   29, /*  0.12 */ },
+	{  64851,   28, /*  0.11 */ },
+	{  68113,   28, /*  0.11 */ },
+	{  71617,   27, /*  0.11 */ },
+	{  75401,   26, /*  0.10 */ },
+	{  79517,   26, /*  0.10 */ },
+	{  84035,   25, /*  0.10 */ },
+	{  89053,   24, /*  0.10 */ },
 };
 
 #define HSTCP_AIMD_MAX	ARRAY_SIZE(hstcp_aimd_vals)
diff -urN linux/net/ipv4/tcp_htcp.c net-next-2.6/net/ipv4/tcp_htcp.c
--- linux/net/ipv4/tcp_htcp.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp_htcp.c	2014-10-06 10:49:00.376901940 +0200
@@ -98,7 +98,8 @@
 	}
 }
 
-static void measure_achieved_throughput(struct sock *sk, u32 pkts_acked, s32 rtt)
+static void measure_achieved_throughput(struct sock *sk,
+					u32 pkts_acked, s32 rtt)
 {
 	const struct inet_connection_sock *icsk = inet_csk(sk);
 	const struct tcp_sock *tp = tcp_sk(sk);
@@ -148,8 +149,8 @@
 	if (use_bandwidth_switch) {
 		u32 maxB = ca->maxB;
 		u32 old_maxB = ca->old_maxB;
-		ca->old_maxB = ca->maxB;
 
+		ca->old_maxB = ca->maxB;
 		if (!between(5 * maxB, 4 * old_maxB, 6 * old_maxB)) {
 			ca->beta = BETA_MIN;
 			ca->modeswitch = 0;
@@ -270,6 +271,7 @@
 	case TCP_CA_Open:
 		{
 			struct htcp *ca = inet_csk_ca(sk);
+
 			if (ca->undo_last_cong) {
 				ca->last_cong = jiffies;
 				ca->undo_last_cong = 0;
diff -urN linux/net/ipv4/tcp_hybla.c net-next-2.6/net/ipv4/tcp_hybla.c
--- linux/net/ipv4/tcp_hybla.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp_hybla.c	2014-10-06 10:49:00.376901940 +0200
@@ -29,7 +29,6 @@
 module_param(rtt0, int, 0644);
 MODULE_PARM_DESC(rtt0, "reference rout trip time (ms)");
 
-
 /* This is called to refresh values for hybla parameters */
 static inline void hybla_recalc_param (struct sock *sk)
 {
diff -urN linux/net/ipv4/tcp_illinois.c net-next-2.6/net/ipv4/tcp_illinois.c
--- linux/net/ipv4/tcp_illinois.c	2014-09-24 09:52:43.172644291 +0200
+++ net-next-2.6/net/ipv4/tcp_illinois.c	2014-10-06 10:49:00.376901940 +0200
@@ -284,7 +284,7 @@
 		delta = (tp->snd_cwnd_cnt * ca->alpha) >> ALPHA_SHIFT;
 		if (delta >= tp->snd_cwnd) {
 			tp->snd_cwnd = min(tp->snd_cwnd + delta / tp->snd_cwnd,
-					   (u32) tp->snd_cwnd_clamp);
+					   (u32)tp->snd_cwnd_clamp);
 			tp->snd_cwnd_cnt = 0;
 		}
 	}
@@ -299,7 +299,6 @@
 	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->beta) >> BETA_SHIFT), 2U);
 }
 
-
 /* Extract info for Tcp socket info provided via netlink. */
 static void tcp_illinois_info(struct sock *sk, u32 ext,
 			      struct sk_buff *skb)
diff -urN linux/net/ipv4/tcp_input.c net-next-2.6/net/ipv4/tcp_input.c
--- linux/net/ipv4/tcp_input.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_input.c	2014-10-06 10:49:00.376901940 +0200
@@ -201,28 +201,25 @@
 	return icsk->icsk_ack.quick && !icsk->icsk_ack.pingpong;
 }
 
-static inline void TCP_ECN_queue_cwr(struct tcp_sock *tp)
+static void tcp_ecn_queue_cwr(struct tcp_sock *tp)
 {
 	if (tp->ecn_flags & TCP_ECN_OK)
 		tp->ecn_flags |= TCP_ECN_QUEUE_CWR;
 }
 
-static inline void TCP_ECN_accept_cwr(struct tcp_sock *tp, const struct sk_buff *skb)
+static void tcp_ecn_accept_cwr(struct tcp_sock *tp, const struct sk_buff *skb)
 {
 	if (tcp_hdr(skb)->cwr)
 		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
 }
 
-static inline void TCP_ECN_withdraw_cwr(struct tcp_sock *tp)
+static void tcp_ecn_withdraw_cwr(struct tcp_sock *tp)
 {
 	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
 }
 
-static inline void TCP_ECN_check_ce(struct tcp_sock *tp, const struct sk_buff *skb)
+static void __tcp_ecn_check_ce(struct tcp_sock *tp, const struct sk_buff *skb)
 {
-	if (!(tp->ecn_flags & TCP_ECN_OK))
-		return;
-
 	switch (TCP_SKB_CB(skb)->ip_dsfield & INET_ECN_MASK) {
 	case INET_ECN_NOT_ECT:
 		/* Funny extension: if ECT is not set on a segment,
@@ -233,30 +230,43 @@
 			tcp_enter_quickack_mode((struct sock *)tp);
 		break;
 	case INET_ECN_CE:
+		if (tcp_ca_needs_ecn((struct sock *)tp))
+			tcp_ca_event((struct sock *)tp, CA_EVENT_ECN_IS_CE);
+
 		if (!(tp->ecn_flags & TCP_ECN_DEMAND_CWR)) {
 			/* Better not delay acks, sender can have a very low cwnd */
 			tcp_enter_quickack_mode((struct sock *)tp);
 			tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
 		}
-		/* fallinto */
+		tp->ecn_flags |= TCP_ECN_SEEN;
+		break;
 	default:
+		if (tcp_ca_needs_ecn((struct sock *)tp))
+			tcp_ca_event((struct sock *)tp, CA_EVENT_ECN_NO_CE);
 		tp->ecn_flags |= TCP_ECN_SEEN;
+		break;
 	}
 }
 
-static inline void TCP_ECN_rcv_synack(struct tcp_sock *tp, const struct tcphdr *th)
+static void tcp_ecn_check_ce(struct tcp_sock *tp, const struct sk_buff *skb)
+{
+	if (tp->ecn_flags & TCP_ECN_OK)
+		__tcp_ecn_check_ce(tp, skb);
+}
+
+static void tcp_ecn_rcv_synack(struct tcp_sock *tp, const struct tcphdr *th)
 {
 	if ((tp->ecn_flags & TCP_ECN_OK) && (!th->ece || th->cwr))
 		tp->ecn_flags &= ~TCP_ECN_OK;
 }
 
-static inline void TCP_ECN_rcv_syn(struct tcp_sock *tp, const struct tcphdr *th)
+static void tcp_ecn_rcv_syn(struct tcp_sock *tp, const struct tcphdr *th)
 {
 	if ((tp->ecn_flags & TCP_ECN_OK) && (!th->ece || !th->cwr))
 		tp->ecn_flags &= ~TCP_ECN_OK;
 }
 
-static bool TCP_ECN_rcv_ecn_echo(const struct tcp_sock *tp, const struct tcphdr *th)
+static bool tcp_ecn_rcv_ecn_echo(const struct tcp_sock *tp, const struct tcphdr *th)
 {
 	if (th->ece && !th->syn && (tp->ecn_flags & TCP_ECN_OK))
 		return true;
@@ -653,7 +663,7 @@
 	}
 	icsk->icsk_ack.lrcvtime = now;
 
-	TCP_ECN_check_ce(tp, skb);
+	tcp_ecn_check_ce(tp, skb);
 
 	if (skb->len >= 128)
 		tcp_grow_window(sk, skb);
@@ -1295,9 +1305,9 @@
 	TCP_SKB_CB(prev)->end_seq += shifted;
 	TCP_SKB_CB(skb)->seq += shifted;
 
-	skb_shinfo(prev)->gso_segs += pcount;
-	BUG_ON(skb_shinfo(skb)->gso_segs < pcount);
-	skb_shinfo(skb)->gso_segs -= pcount;
+	tcp_skb_pcount_add(prev, pcount);
+	BUG_ON(tcp_skb_pcount(skb) < pcount);
+	tcp_skb_pcount_add(skb, -pcount);
 
 	/* When we're adding to gso_segs == 1, gso_size will be zero,
 	 * in theory this shouldn't be necessary but as long as DSACK
@@ -1310,7 +1320,7 @@
 	}
 
 	/* CHECKME: To clear or not to clear? Mimics normal skb currently */
-	if (skb_shinfo(skb)->gso_segs <= 1) {
+	if (tcp_skb_pcount(skb) <= 1) {
 		skb_shinfo(skb)->gso_size = 0;
 		skb_shinfo(skb)->gso_type = 0;
 	}
@@ -1888,21 +1898,21 @@
 	tp->sacked_out = 0;
 }
 
-static void tcp_clear_retrans_partial(struct tcp_sock *tp)
+void tcp_clear_retrans(struct tcp_sock *tp)
 {
 	tp->retrans_out = 0;
 	tp->lost_out = 0;
-
 	tp->undo_marker = 0;
 	tp->undo_retrans = -1;
+	tp->fackets_out = 0;
+	tp->sacked_out = 0;
 }
 
-void tcp_clear_retrans(struct tcp_sock *tp)
+static inline void tcp_init_undo(struct tcp_sock *tp)
 {
-	tcp_clear_retrans_partial(tp);
-
-	tp->fackets_out = 0;
-	tp->sacked_out = 0;
+	tp->undo_marker = tp->snd_una;
+	/* Retransmission still in flight may cause DSACKs later. */
+	tp->undo_retrans = tp->retrans_out ? : -1;
 }
 
 /* Enter Loss state. If we detect SACK reneging, forget all SACK information
@@ -1925,18 +1935,18 @@
 		tp->prior_ssthresh = tcp_current_ssthresh(sk);
 		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
 		tcp_ca_event(sk, CA_EVENT_LOSS);
+		tcp_init_undo(tp);
 	}
 	tp->snd_cwnd	   = 1;
 	tp->snd_cwnd_cnt   = 0;
 	tp->snd_cwnd_stamp = tcp_time_stamp;
 
-	tcp_clear_retrans_partial(tp);
+	tp->retrans_out = 0;
+	tp->lost_out = 0;
 
 	if (tcp_is_reno(tp))
 		tcp_reset_reno_sack(tp);
 
-	tp->undo_marker = tp->snd_una;
-
 	skb = tcp_write_queue_head(sk);
 	is_reneg = skb && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED);
 	if (is_reneg) {
@@ -1950,9 +1960,6 @@
 		if (skb == tcp_send_head(sk))
 			break;
 
-		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
-			tp->undo_marker = 0;
-
 		TCP_SKB_CB(skb)->sacked &= (~TCPCB_TAGBITS)|TCPCB_SACKED_ACKED;
 		if (!(TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_ACKED) || is_reneg) {
 			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_ACKED;
@@ -1972,7 +1979,7 @@
 				       sysctl_tcp_reordering);
 	tcp_set_ca_state(sk, TCP_CA_Loss);
 	tp->high_seq = tp->snd_nxt;
-	TCP_ECN_queue_cwr(tp);
+	tcp_ecn_queue_cwr(tp);
 
 	/* F-RTO RFC5682 sec 3.1 step 1: retransmit SND.UNA if no previous
 	 * loss recovery is underway except recurring timeout(s) on
@@ -2364,7 +2371,7 @@
 
 		if (tp->prior_ssthresh > tp->snd_ssthresh) {
 			tp->snd_ssthresh = tp->prior_ssthresh;
-			TCP_ECN_withdraw_cwr(tp);
+			tcp_ecn_withdraw_cwr(tp);
 		}
 	} else {
 		tp->snd_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh);
@@ -2494,7 +2501,7 @@
 	tp->prr_delivered = 0;
 	tp->prr_out = 0;
 	tp->snd_ssthresh = inet_csk(sk)->icsk_ca_ops->ssthresh(sk);
-	TCP_ECN_queue_cwr(tp);
+	tcp_ecn_queue_cwr(tp);
 }
 
 static void tcp_cwnd_reduction(struct sock *sk, const int prior_unsacked,
@@ -2671,8 +2678,7 @@
 	NET_INC_STATS_BH(sock_net(sk), mib_idx);
 
 	tp->prior_ssthresh = 0;
-	tp->undo_marker = tp->snd_una;
-	tp->undo_retrans = tp->retrans_out ? : -1;
+	tcp_init_undo(tp);
 
 	if (inet_csk(sk)->icsk_ca_state < TCP_CA_CWR) {
 		if (!ece_ack)
@@ -2971,7 +2977,8 @@
 		if (icsk->icsk_pending == ICSK_TIME_EARLY_RETRANS ||
 		    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE) {
 			struct sk_buff *skb = tcp_write_queue_head(sk);
-			const u32 rto_time_stamp = TCP_SKB_CB(skb)->when + rto;
+			const u32 rto_time_stamp =
+				tcp_skb_timestamp(skb) + rto;
 			s32 delta = (s32)(rto_time_stamp - tcp_time_stamp);
 			/* delta may not be positive if the socket is locked
 			 * when the retrans timer fires and is rescheduled.
@@ -3211,9 +3218,10 @@
 		 * This function is not for random using!
 		 */
 	} else {
+		unsigned long when = inet_csk_rto_backoff(icsk, TCP_RTO_MAX);
+
 		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
-					  min(icsk->icsk_rto << icsk->icsk_backoff, TCP_RTO_MAX),
-					  TCP_RTO_MAX);
+					  when, TCP_RTO_MAX);
 	}
 }
 
@@ -3364,6 +3372,14 @@
 	}
 }
 
+static inline void tcp_in_ack_event(struct sock *sk, u32 flags)
+{
+	const struct inet_connection_sock *icsk = inet_csk(sk);
+
+	if (icsk->icsk_ca_ops->in_ack_event)
+		icsk->icsk_ca_ops->in_ack_event(sk, flags);
+}
+
 /* This routine deals with incoming acks, but not outgoing ones. */
 static int tcp_ack(struct sock *sk, const struct sk_buff *skb, int flag)
 {
@@ -3423,10 +3439,12 @@
 		tp->snd_una = ack;
 		flag |= FLAG_WIN_UPDATE;
 
-		tcp_ca_event(sk, CA_EVENT_FAST_ACK);
+		tcp_in_ack_event(sk, CA_ACK_WIN_UPDATE);
 
 		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPHPACKS);
 	} else {
+		u32 ack_ev_flags = CA_ACK_SLOWPATH;
+
 		if (ack_seq != TCP_SKB_CB(skb)->end_seq)
 			flag |= FLAG_DATA;
 		else
@@ -3438,10 +3456,15 @@
 			flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una,
 							&sack_rtt_us);
 
-		if (TCP_ECN_rcv_ecn_echo(tp, tcp_hdr(skb)))
+		if (tcp_ecn_rcv_ecn_echo(tp, tcp_hdr(skb))) {
 			flag |= FLAG_ECE;
+			ack_ev_flags |= CA_ACK_ECE;
+		}
 
-		tcp_ca_event(sk, CA_EVENT_SLOW_ACK);
+		if (flag & FLAG_WIN_UPDATE)
+			ack_ev_flags |= CA_ACK_WIN_UPDATE;
+
+		tcp_in_ack_event(sk, ack_ev_flags);
 	}
 
 	/* We passed data and got it acked, remove any soft error
@@ -4063,6 +4086,44 @@
 	tp->rx_opt.num_sacks = num_sacks;
 }
 
+/**
+ * tcp_try_coalesce - try to merge skb to prior one
+ * @sk: socket
+ * @to: prior buffer
+ * @from: buffer to add in queue
+ * @fragstolen: pointer to boolean
+ *
+ * Before queueing skb @from after @to, try to merge them
+ * to reduce overall memory use and queue lengths, if cost is small.
+ * Packets in ofo or receive queues can stay a long time.
+ * Better try to coalesce them right now to avoid future collapses.
+ * Returns true if caller should free @from instead of queueing it
+ */
+static bool tcp_try_coalesce(struct sock *sk,
+			     struct sk_buff *to,
+			     struct sk_buff *from,
+			     bool *fragstolen)
+{
+	int delta;
+
+	*fragstolen = false;
+
+	/* Its possible this segment overlaps with prior segment in queue */
+	if (TCP_SKB_CB(from)->seq != TCP_SKB_CB(to)->end_seq)
+		return false;
+
+	if (!skb_try_coalesce(to, from, fragstolen, &delta))
+		return false;
+
+	atomic_add(delta, &sk->sk_rmem_alloc);
+	sk_mem_charge(sk, delta);
+	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
+	TCP_SKB_CB(to)->end_seq = TCP_SKB_CB(from)->end_seq;
+	TCP_SKB_CB(to)->ack_seq = TCP_SKB_CB(from)->ack_seq;
+	TCP_SKB_CB(to)->tcp_flags |= TCP_SKB_CB(from)->tcp_flags;
+	return true;
+}
+
 /* This one checks to see if we can put data from the
  * out_of_order queue into the receive_queue.
  */
@@ -4070,7 +4131,8 @@
 {
 	struct tcp_sock *tp = tcp_sk(sk);
 	__u32 dsack_high = tp->rcv_nxt;
-	struct sk_buff *skb;
+	struct sk_buff *skb, *tail;
+	bool fragstolen, eaten;
 
 	while ((skb = skb_peek(&tp->out_of_order_queue)) != NULL) {
 		if (after(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
@@ -4083,9 +4145,9 @@
 			tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
 		}
 
+		__skb_unlink(skb, &tp->out_of_order_queue);
 		if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {
 			SOCK_DEBUG(sk, "ofo packet was already received\n");
-			__skb_unlink(skb, &tp->out_of_order_queue);
 			__kfree_skb(skb);
 			continue;
 		}
@@ -4093,11 +4155,15 @@
 			   tp->rcv_nxt, TCP_SKB_CB(skb)->seq,
 			   TCP_SKB_CB(skb)->end_seq);
 
-		__skb_unlink(skb, &tp->out_of_order_queue);
-		__skb_queue_tail(&sk->sk_receive_queue, skb);
+		tail = skb_peek_tail(&sk->sk_receive_queue);
+		eaten = tail && tcp_try_coalesce(sk, tail, skb, &fragstolen);
 		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
-		if (tcp_hdr(skb)->fin)
+		if (!eaten)
+			__skb_queue_tail(&sk->sk_receive_queue, skb);
+		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
 			tcp_fin(sk);
+		if (eaten)
+			kfree_skb_partial(skb, fragstolen);
 	}
 }
 
@@ -4124,53 +4190,13 @@
 	return 0;
 }
 
-/**
- * tcp_try_coalesce - try to merge skb to prior one
- * @sk: socket
- * @to: prior buffer
- * @from: buffer to add in queue
- * @fragstolen: pointer to boolean
- *
- * Before queueing skb @from after @to, try to merge them
- * to reduce overall memory use and queue lengths, if cost is small.
- * Packets in ofo or receive queues can stay a long time.
- * Better try to coalesce them right now to avoid future collapses.
- * Returns true if caller should free @from instead of queueing it
- */
-static bool tcp_try_coalesce(struct sock *sk,
-			     struct sk_buff *to,
-			     struct sk_buff *from,
-			     bool *fragstolen)
-{
-	int delta;
-
-	*fragstolen = false;
-
-	if (tcp_hdr(from)->fin)
-		return false;
-
-	/* Its possible this segment overlaps with prior segment in queue */
-	if (TCP_SKB_CB(from)->seq != TCP_SKB_CB(to)->end_seq)
-		return false;
-
-	if (!skb_try_coalesce(to, from, fragstolen, &delta))
-		return false;
-
-	atomic_add(delta, &sk->sk_rmem_alloc);
-	sk_mem_charge(sk, delta);
-	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
-	TCP_SKB_CB(to)->end_seq = TCP_SKB_CB(from)->end_seq;
-	TCP_SKB_CB(to)->ack_seq = TCP_SKB_CB(from)->ack_seq;
-	return true;
-}
-
 static void tcp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
 {
 	struct tcp_sock *tp = tcp_sk(sk);
 	struct sk_buff *skb1;
 	u32 seq, end_seq;
 
-	TCP_ECN_check_ce(tp, skb);
+	tcp_ecn_check_ce(tp, skb);
 
 	if (unlikely(tcp_try_rmem_schedule(sk, skb, skb->truesize))) {
 		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFODROP);
@@ -4309,24 +4335,19 @@
 
 int tcp_send_rcvq(struct sock *sk, struct msghdr *msg, size_t size)
 {
-	struct sk_buff *skb = NULL;
-	struct tcphdr *th;
+	struct sk_buff *skb;
 	bool fragstolen;
 
 	if (size == 0)
 		return 0;
 
-	skb = alloc_skb(size + sizeof(*th), sk->sk_allocation);
+	skb = alloc_skb(size, sk->sk_allocation);
 	if (!skb)
 		goto err;
 
-	if (tcp_try_rmem_schedule(sk, skb, size + sizeof(*th)))
+	if (tcp_try_rmem_schedule(sk, skb, skb->truesize))
 		goto err_free;
 
-	th = (struct tcphdr *)skb_put(skb, sizeof(*th));
-	skb_reset_transport_header(skb);
-	memset(th, 0, sizeof(*th));
-
 	if (memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size))
 		goto err_free;
 
@@ -4334,7 +4355,7 @@
 	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + size;
 	TCP_SKB_CB(skb)->ack_seq = tcp_sk(sk)->snd_una - 1;
 
-	if (tcp_queue_rcv(sk, skb, sizeof(*th), &fragstolen)) {
+	if (tcp_queue_rcv(sk, skb, 0, &fragstolen)) {
 		WARN_ON_ONCE(fragstolen); /* should not happen */
 		__kfree_skb(skb);
 	}
@@ -4348,7 +4369,6 @@
 
 static void tcp_data_queue(struct sock *sk, struct sk_buff *skb)
 {
-	const struct tcphdr *th = tcp_hdr(skb);
 	struct tcp_sock *tp = tcp_sk(sk);
 	int eaten = -1;
 	bool fragstolen = false;
@@ -4357,9 +4377,9 @@
 		goto drop;
 
 	skb_dst_drop(skb);
-	__skb_pull(skb, th->doff * 4);
+	__skb_pull(skb, tcp_hdr(skb)->doff * 4);
 
-	TCP_ECN_accept_cwr(tp, skb);
+	tcp_ecn_accept_cwr(tp, skb);
 
 	tp->rx_opt.dsack = 0;
 
@@ -4401,7 +4421,7 @@
 		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
 		if (skb->len)
 			tcp_event_data_recv(sk, skb);
-		if (th->fin)
+		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
 			tcp_fin(sk);
 
 		if (!skb_queue_empty(&tp->out_of_order_queue)) {
@@ -4516,7 +4536,7 @@
 		 * - bloated or contains data before "start" or
 		 *   overlaps to the next one.
 		 */
-		if (!tcp_hdr(skb)->syn && !tcp_hdr(skb)->fin &&
+		if (!(TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN)) &&
 		    (tcp_win_from_space(skb->truesize) > skb->len ||
 		     before(TCP_SKB_CB(skb)->seq, start))) {
 			end_of_skbs = false;
@@ -4535,30 +4555,18 @@
 		/* Decided to skip this, advance start seq. */
 		start = TCP_SKB_CB(skb)->end_seq;
 	}
-	if (end_of_skbs || tcp_hdr(skb)->syn || tcp_hdr(skb)->fin)
+	if (end_of_skbs ||
+	    (TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN)))
 		return;
 
 	while (before(start, end)) {
+		int copy = min_t(int, SKB_MAX_ORDER(0, 0), end - start);
 		struct sk_buff *nskb;
-		unsigned int header = skb_headroom(skb);
-		int copy = SKB_MAX_ORDER(header, 0);
 
-		/* Too big header? This can happen with IPv6. */
-		if (copy < 0)
-			return;
-		if (end - start < copy)
-			copy = end - start;
-		nskb = alloc_skb(copy + header, GFP_ATOMIC);
+		nskb = alloc_skb(copy, GFP_ATOMIC);
 		if (!nskb)
 			return;
 
-		skb_set_mac_header(nskb, skb_mac_header(skb) - skb->head);
-		skb_set_network_header(nskb, (skb_network_header(skb) -
-					      skb->head));
-		skb_set_transport_header(nskb, (skb_transport_header(skb) -
-						skb->head));
-		skb_reserve(nskb, header);
-		memcpy(nskb->head, skb->head, header);
 		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
 		TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(nskb)->end_seq = start;
 		__skb_queue_before(list, skb, nskb);
@@ -4582,8 +4590,7 @@
 				skb = tcp_collapse_one(sk, skb, list);
 				if (!skb ||
 				    skb == tail ||
-				    tcp_hdr(skb)->syn ||
-				    tcp_hdr(skb)->fin)
+				    (TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN)))
 					return;
 			}
 		}
@@ -5453,7 +5460,7 @@
 		 *    state to ESTABLISHED..."
 		 */
 
-		TCP_ECN_rcv_synack(tp, th);
+		tcp_ecn_rcv_synack(tp, th);
 
 		tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
 		tcp_ack(sk, skb, FLAG_SLOWPATH);
@@ -5572,7 +5579,7 @@
 		tp->snd_wl1    = TCP_SKB_CB(skb)->seq;
 		tp->max_window = tp->snd_wnd;
 
-		TCP_ECN_rcv_syn(tp, th);
+		tcp_ecn_rcv_syn(tp, th);
 
 		tcp_mtup_init(sk);
 		tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
@@ -5902,6 +5909,40 @@
 #endif
 }
 
+/* RFC3168 : 6.1.1 SYN packets must not have ECT/ECN bits set
+ *
+ * If we receive a SYN packet with these bits set, it means a
+ * network is playing bad games with TOS bits. In order to
+ * avoid possible false congestion notifications, we disable
+ * TCP ECN negociation.
+ *
+ * Exception: tcp_ca wants ECN. This is required for DCTCP
+ * congestion control; it requires setting ECT on all packets,
+ * including SYN. We inverse the test in this case: If our
+ * local socket wants ECN, but peer only set ece/cwr (but not
+ * ECT in IP header) its probably a non-DCTCP aware sender.
+ */
+static void tcp_ecn_create_request(struct request_sock *req,
+				   const struct sk_buff *skb,
+				   const struct sock *listen_sk)
+{
+	const struct tcphdr *th = tcp_hdr(skb);
+	const struct net *net = sock_net(listen_sk);
+	bool th_ecn = th->ece && th->cwr;
+	bool ect, need_ecn;
+
+	if (!th_ecn)
+		return;
+
+	ect = !INET_ECN_is_not_ect(TCP_SKB_CB(skb)->ip_dsfield);
+	need_ecn = tcp_ca_needs_ecn(listen_sk);
+
+	if (!ect && !need_ecn && net->ipv4.sysctl_tcp_ecn)
+		inet_rsk(req)->ecn_ok = 1;
+	else if (ect && need_ecn)
+		inet_rsk(req)->ecn_ok = 1;
+}
+
 int tcp_conn_request(struct request_sock_ops *rsk_ops,
 		     const struct tcp_request_sock_ops *af_ops,
 		     struct sock *sk, struct sk_buff *skb)
@@ -5910,7 +5951,7 @@
 	struct request_sock *req;
 	struct tcp_sock *tp = tcp_sk(sk);
 	struct dst_entry *dst = NULL;
-	__u32 isn = TCP_SKB_CB(skb)->when;
+	__u32 isn = TCP_SKB_CB(skb)->tcp_tw_isn;
 	bool want_cookie = false, fastopen;
 	struct flowi fl;
 	struct tcp_fastopen_cookie foc = { .len = -1 };
@@ -5962,7 +6003,7 @@
 		goto drop_and_free;
 
 	if (!want_cookie || tmp_opt.tstamp_ok)
-		TCP_ECN_create_request(req, skb, sock_net(sk));
+		tcp_ecn_create_request(req, skb, sk);
 
 	if (want_cookie) {
 		isn = cookie_init_sequence(af_ops, sk, skb, &req->mss);
diff -urN linux/net/ipv4/tcp_ipv4.c net-next-2.6/net/ipv4/tcp_ipv4.c
--- linux/net/ipv4/tcp_ipv4.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_ipv4.c	2014-10-06 10:49:00.376901940 +0200
@@ -90,7 +90,6 @@
 int sysctl_tcp_low_latency __read_mostly;
 EXPORT_SYMBOL(sysctl_tcp_low_latency);
 
-
 #ifdef CONFIG_TCP_MD5SIG
 static int tcp_v4_md5_hash_hdr(char *md5_hash, const struct tcp_md5sig_key *key,
 			       __be32 daddr, __be32 saddr, const struct tcphdr *th);
@@ -431,15 +430,16 @@
 			break;
 
 		icsk->icsk_backoff--;
-		inet_csk(sk)->icsk_rto = (tp->srtt_us ? __tcp_set_rto(tp) :
-			TCP_TIMEOUT_INIT) << icsk->icsk_backoff;
-		tcp_bound_rto(sk);
+		icsk->icsk_rto = tp->srtt_us ? __tcp_set_rto(tp) :
+					       TCP_TIMEOUT_INIT;
+		icsk->icsk_rto = inet_csk_rto_backoff(icsk, TCP_RTO_MAX);
 
 		skb = tcp_write_queue_head(sk);
 		BUG_ON(!skb);
 
-		remaining = icsk->icsk_rto - min(icsk->icsk_rto,
-				tcp_time_stamp - TCP_SKB_CB(skb)->when);
+		remaining = icsk->icsk_rto -
+			    min(icsk->icsk_rto,
+				tcp_time_stamp - tcp_skb_timestamp(skb));
 
 		if (remaining) {
 			inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
@@ -681,8 +681,9 @@
 
 	net = dev_net(skb_dst(skb)->dev);
 	arg.tos = ip_hdr(skb)->tos;
-	ip_send_unicast_reply(net, skb, ip_hdr(skb)->saddr,
-			      ip_hdr(skb)->daddr, &arg, arg.iov[0].iov_len);
+	ip_send_unicast_reply(net, skb, &TCP_SKB_CB(skb)->header.h4.opt,
+			      ip_hdr(skb)->saddr, ip_hdr(skb)->daddr,
+			      &arg, arg.iov[0].iov_len);
 
 	TCP_INC_STATS_BH(net, TCP_MIB_OUTSEGS);
 	TCP_INC_STATS_BH(net, TCP_MIB_OUTRSTS);
@@ -764,8 +765,9 @@
 	if (oif)
 		arg.bound_dev_if = oif;
 	arg.tos = tos;
-	ip_send_unicast_reply(net, skb, ip_hdr(skb)->saddr,
-			      ip_hdr(skb)->daddr, &arg, arg.iov[0].iov_len);
+	ip_send_unicast_reply(net, skb, &TCP_SKB_CB(skb)->header.h4.opt,
+			      ip_hdr(skb)->saddr, ip_hdr(skb)->daddr,
+			      &arg, arg.iov[0].iov_len);
 
 	TCP_INC_STATS_BH(net, TCP_MIB_OUTSEGS);
 }
@@ -884,18 +886,16 @@
  */
 static struct ip_options_rcu *tcp_v4_save_options(struct sk_buff *skb)
 {
-	const struct ip_options *opt = &(IPCB(skb)->opt);
+	const struct ip_options *opt = &TCP_SKB_CB(skb)->header.h4.opt;
 	struct ip_options_rcu *dopt = NULL;
 
 	if (opt && opt->optlen) {
 		int opt_size = sizeof(*dopt) + opt->optlen;
 
 		dopt = kmalloc(opt_size, GFP_ATOMIC);
-		if (dopt) {
-			if (ip_options_echo(&dopt->opt, skb)) {
-				kfree(dopt);
-				dopt = NULL;
-			}
+		if (dopt && __ip_options_echo(&dopt->opt, skb, opt)) {
+			kfree(dopt);
+			dopt = NULL;
 		}
 	}
 	return dopt;
@@ -1269,7 +1269,7 @@
 	.send_ack	=	tcp_v4_reqsk_send_ack,
 	.destructor	=	tcp_v4_reqsk_destructor,
 	.send_reset	=	tcp_v4_send_reset,
-	.syn_ack_timeout = 	tcp_syn_ack_timeout,
+	.syn_ack_timeout =	tcp_syn_ack_timeout,
 };
 
 static const struct tcp_request_sock_ops tcp_request_sock_ipv4_ops = {
@@ -1429,7 +1429,7 @@
 
 #ifdef CONFIG_SYN_COOKIES
 	if (!th->syn)
-		sk = cookie_v4_check(sk, skb, &(IPCB(skb)->opt));
+		sk = cookie_v4_check(sk, skb, &TCP_SKB_CB(skb)->header.h4.opt);
 #endif
 	return sk;
 }
@@ -1559,7 +1559,17 @@
 	    skb_queue_len(&tp->ucopy.prequeue) == 0)
 		return false;
 
-	skb_dst_force(skb);
+	/* Before escaping RCU protected region, we need to take care of skb
+	 * dst. Prequeue is only enabled for established sockets.
+	 * For such sockets, we might need the skb dst only to set sk->sk_rx_dst
+	 * Instead of doing full sk_rx_dst validity here, let's perform
+	 * an optimistic check.
+	 */
+	if (likely(sk->sk_rx_dst))
+		skb_dst_drop(skb);
+	else
+		skb_dst_force(skb);
+
 	__skb_queue_tail(&tp->ucopy.prequeue, skb);
 	tp->ucopy.memory += skb->truesize;
 	if (tp->ucopy.memory > sk->sk_rcvbuf) {
@@ -1624,11 +1634,19 @@
 
 	th = tcp_hdr(skb);
 	iph = ip_hdr(skb);
+	/* This is tricky : We move IPCB at its correct location into TCP_SKB_CB()
+	 * barrier() makes sure compiler wont play fool^Waliasing games.
+	 */
+	memmove(&TCP_SKB_CB(skb)->header.h4, IPCB(skb),
+		sizeof(struct inet_skb_parm));
+	barrier();
+
 	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
 	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
 				    skb->len - th->doff * 4);
 	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
-	TCP_SKB_CB(skb)->when	 = 0;
+	TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
+	TCP_SKB_CB(skb)->tcp_tw_isn = 0;
 	TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
 	TCP_SKB_CB(skb)->sacked	 = 0;
 
@@ -1765,9 +1783,11 @@
 {
 	struct dst_entry *dst = skb_dst(skb);
 
-	dst_hold(dst);
-	sk->sk_rx_dst = dst;
-	inet_sk(sk)->rx_dst_ifindex = skb->skb_iif;
+	if (dst) {
+		dst_hold(dst);
+		sk->sk_rx_dst = dst;
+		inet_sk(sk)->rx_dst_ifindex = skb->skb_iif;
+	}
 }
 EXPORT_SYMBOL(inet_sk_rx_dst_set);
 
@@ -2183,7 +2203,7 @@
 
 	s = ((struct seq_file *)file->private_data)->private;
 	s->family		= afinfo->family;
-	s->last_pos 		= 0;
+	s->last_pos		= 0;
 	return 0;
 }
 EXPORT_SYMBOL(tcp_seq_open);
diff -urN linux/net/ipv4/tcp_minisocks.c net-next-2.6/net/ipv4/tcp_minisocks.c
--- linux/net/ipv4/tcp_minisocks.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_minisocks.c	2014-10-06 10:49:00.392902103 +0200
@@ -232,7 +232,7 @@
 		u32 isn = tcptw->tw_snd_nxt + 65535 + 2;
 		if (isn == 0)
 			isn++;
-		TCP_SKB_CB(skb)->when = isn;
+		TCP_SKB_CB(skb)->tcp_tw_isn = isn;
 		return TCP_TW_SYN;
 	}
 
@@ -393,8 +393,8 @@
 }
 EXPORT_SYMBOL(tcp_openreq_init_rwin);
 
-static inline void TCP_ECN_openreq_child(struct tcp_sock *tp,
-					 struct request_sock *req)
+static void tcp_ecn_openreq_child(struct tcp_sock *tp,
+				  const struct request_sock *req)
 {
 	tp->ecn_flags = inet_rsk(req)->ecn_ok ? TCP_ECN_OK : 0;
 }
@@ -451,9 +451,8 @@
 		newtp->snd_cwnd = TCP_INIT_CWND;
 		newtp->snd_cwnd_cnt = 0;
 
-		if (newicsk->icsk_ca_ops != &tcp_init_congestion_ops &&
-		    !try_module_get(newicsk->icsk_ca_ops->owner))
-			newicsk->icsk_ca_ops = &tcp_init_congestion_ops;
+		if (!try_module_get(newicsk->icsk_ca_ops->owner))
+			tcp_assign_congestion_control(newsk);
 
 		tcp_set_ca_state(newsk, TCP_CA_Open);
 		tcp_init_xmit_timers(newsk);
@@ -508,7 +507,7 @@
 		if (skb->len >= TCP_MSS_DEFAULT + newtp->tcp_header_len)
 			newicsk->icsk_ack.last_seg_size = skb->len - newtp->tcp_header_len;
 		newtp->rx_opt.mss_clamp = req->mss;
-		TCP_ECN_openreq_child(newtp, req);
+		tcp_ecn_openreq_child(newtp, req);
 		newtp->fastopen_rsk = NULL;
 		newtp->syn_data_acked = 0;
 
diff -urN linux/net/ipv4/tcp_offload.c net-next-2.6/net/ipv4/tcp_offload.c
--- linux/net/ipv4/tcp_offload.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_offload.c	2014-10-06 10:49:00.392902103 +0200
@@ -29,6 +29,28 @@
 	}
 }
 
+struct sk_buff *tcp4_gso_segment(struct sk_buff *skb,
+				 netdev_features_t features)
+{
+	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
+		return ERR_PTR(-EINVAL);
+
+	if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL)) {
+		const struct iphdr *iph = ip_hdr(skb);
+		struct tcphdr *th = tcp_hdr(skb);
+
+		/* Set up checksum pseudo header, usually expect stack to
+		 * have done this already.
+		 */
+
+		th->check = 0;
+		skb->ip_summed = CHECKSUM_PARTIAL;
+		__tcp_v4_send_check(skb, iph->saddr, iph->daddr);
+	}
+
+	return tcp_gso_segment(skb, features);
+}
+
 struct sk_buff *tcp_gso_segment(struct sk_buff *skb,
 				netdev_features_t features)
 {
@@ -44,9 +66,6 @@
 	__sum16 newcheck;
 	bool ooo_okay, copy_destructor;
 
-	if (!pskb_may_pull(skb, sizeof(*th)))
-		goto out;
-
 	th = tcp_hdr(skb);
 	thlen = th->doff * 4;
 	if (thlen < sizeof(*th))
@@ -269,54 +288,16 @@
 }
 EXPORT_SYMBOL(tcp_gro_complete);
 
-static int tcp_v4_gso_send_check(struct sk_buff *skb)
-{
-	const struct iphdr *iph;
-	struct tcphdr *th;
-
-	if (!pskb_may_pull(skb, sizeof(*th)))
-		return -EINVAL;
-
-	iph = ip_hdr(skb);
-	th = tcp_hdr(skb);
-
-	th->check = 0;
-	skb->ip_summed = CHECKSUM_PARTIAL;
-	__tcp_v4_send_check(skb, iph->saddr, iph->daddr);
-	return 0;
-}
-
 static struct sk_buff **tcp4_gro_receive(struct sk_buff **head, struct sk_buff *skb)
 {
-	/* Use the IP hdr immediately proceeding for this transport */
-	const struct iphdr *iph = skb_gro_network_header(skb);
-	__wsum wsum;
-
 	/* Don't bother verifying checksum if we're going to flush anyway. */
-	if (NAPI_GRO_CB(skb)->flush)
-		goto skip_csum;
-
-	wsum = NAPI_GRO_CB(skb)->csum;
-
-	switch (skb->ip_summed) {
-	case CHECKSUM_NONE:
-		wsum = skb_checksum(skb, skb_gro_offset(skb), skb_gro_len(skb),
-				    0);
-
-		/* fall through */
-
-	case CHECKSUM_COMPLETE:
-		if (!tcp_v4_check(skb_gro_len(skb), iph->saddr, iph->daddr,
-				  wsum)) {
-			skb->ip_summed = CHECKSUM_UNNECESSARY;
-			break;
-		}
-
+	if (!NAPI_GRO_CB(skb)->flush &&
+	    skb_gro_checksum_validate(skb, IPPROTO_TCP,
+				      inet_gro_compute_pseudo)) {
 		NAPI_GRO_CB(skb)->flush = 1;
 		return NULL;
 	}
 
-skip_csum:
 	return tcp_gro_receive(head, skb);
 }
 
@@ -334,8 +315,7 @@
 
 static const struct net_offload tcpv4_offload = {
 	.callbacks = {
-		.gso_send_check	=	tcp_v4_gso_send_check,
-		.gso_segment	=	tcp_gso_segment,
+		.gso_segment	=	tcp4_gso_segment,
 		.gro_receive	=	tcp4_gro_receive,
 		.gro_complete	=	tcp4_gro_complete,
 	},
diff -urN linux/net/ipv4/tcp_output.c net-next-2.6/net/ipv4/tcp_output.c
--- linux/net/ipv4/tcp_output.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_output.c	2014-10-06 10:49:00.392902103 +0200
@@ -318,36 +318,47 @@
 }
 
 /* Packet ECN state for a SYN-ACK */
-static inline void TCP_ECN_send_synack(const struct tcp_sock *tp, struct sk_buff *skb)
+static void tcp_ecn_send_synack(struct sock *sk, struct sk_buff *skb)
 {
+	const struct tcp_sock *tp = tcp_sk(sk);
+
 	TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_CWR;
 	if (!(tp->ecn_flags & TCP_ECN_OK))
 		TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_ECE;
+	else if (tcp_ca_needs_ecn(sk))
+		INET_ECN_xmit(sk);
 }
 
 /* Packet ECN state for a SYN.  */
-static inline void TCP_ECN_send_syn(struct sock *sk, struct sk_buff *skb)
+static void tcp_ecn_send_syn(struct sock *sk, struct sk_buff *skb)
 {
 	struct tcp_sock *tp = tcp_sk(sk);
 
 	tp->ecn_flags = 0;
-	if (sock_net(sk)->ipv4.sysctl_tcp_ecn == 1) {
+	if (sock_net(sk)->ipv4.sysctl_tcp_ecn == 1 ||
+	    tcp_ca_needs_ecn(sk)) {
 		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ECE | TCPHDR_CWR;
 		tp->ecn_flags = TCP_ECN_OK;
+		if (tcp_ca_needs_ecn(sk))
+			INET_ECN_xmit(sk);
 	}
 }
 
-static __inline__ void
-TCP_ECN_make_synack(const struct request_sock *req, struct tcphdr *th)
+static void
+tcp_ecn_make_synack(const struct request_sock *req, struct tcphdr *th,
+		    struct sock *sk)
 {
-	if (inet_rsk(req)->ecn_ok)
+	if (inet_rsk(req)->ecn_ok) {
 		th->ece = 1;
+		if (tcp_ca_needs_ecn(sk))
+			INET_ECN_xmit(sk);
+	}
 }
 
 /* Set up ECN state for a packet on a ESTABLISHED socket that is about to
  * be sent.
  */
-static inline void TCP_ECN_send(struct sock *sk, struct sk_buff *skb,
+static void tcp_ecn_send(struct sock *sk, struct sk_buff *skb,
 				int tcp_header_len)
 {
 	struct tcp_sock *tp = tcp_sk(sk);
@@ -362,7 +373,7 @@
 				tcp_hdr(skb)->cwr = 1;
 				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
 			}
-		} else {
+		} else if (!tcp_ca_needs_ecn(sk)) {
 			/* ACK or retransmitted segment: clear ECT|CE */
 			INET_ECN_dontxmit(sk);
 		}
@@ -384,7 +395,7 @@
 	TCP_SKB_CB(skb)->tcp_flags = flags;
 	TCP_SKB_CB(skb)->sacked = 0;
 
-	shinfo->gso_segs = 1;
+	tcp_skb_pcount_set(skb, 1);
 	shinfo->gso_size = 0;
 	shinfo->gso_type = 0;
 
@@ -550,7 +561,7 @@
 
 	if (likely(sysctl_tcp_timestamps && *md5 == NULL)) {
 		opts->options |= OPTION_TS;
-		opts->tsval = TCP_SKB_CB(skb)->when + tp->tsoffset;
+		opts->tsval = tcp_skb_timestamp(skb) + tp->tsoffset;
 		opts->tsecr = tp->rx_opt.ts_recent;
 		remaining -= TCPOLEN_TSTAMP_ALIGNED;
 	}
@@ -618,7 +629,7 @@
 	}
 	if (likely(ireq->tstamp_ok)) {
 		opts->options |= OPTION_TS;
-		opts->tsval = TCP_SKB_CB(skb)->when;
+		opts->tsval = tcp_skb_timestamp(skb);
 		opts->tsecr = req->ts_recent;
 		remaining -= TCPOLEN_TSTAMP_ALIGNED;
 	}
@@ -647,7 +658,6 @@
 					struct tcp_out_options *opts,
 					struct tcp_md5sig_key **md5)
 {
-	struct tcp_skb_cb *tcb = skb ? TCP_SKB_CB(skb) : NULL;
 	struct tcp_sock *tp = tcp_sk(sk);
 	unsigned int size = 0;
 	unsigned int eff_sacks;
@@ -666,7 +676,7 @@
 
 	if (likely(tp->rx_opt.tstamp_ok)) {
 		opts->options |= OPTION_TS;
-		opts->tsval = tcb ? tcb->when + tp->tsoffset : 0;
+		opts->tsval = skb ? tcp_skb_timestamp(skb) + tp->tsoffset : 0;
 		opts->tsecr = tp->rx_opt.ts_recent;
 		size += TCPOLEN_TSTAMP_ALIGNED;
 	}
@@ -886,8 +896,6 @@
 			skb = skb_clone(skb, gfp_mask);
 		if (unlikely(!skb))
 			return -ENOBUFS;
-		/* Our usage of tstamp should remain private */
-		skb->tstamp.tv64 = 0;
 	}
 
 	inet = inet_sk(sk);
@@ -952,7 +960,7 @@
 
 	tcp_options_write((__be32 *)(th + 1), tp, &opts);
 	if (likely((tcb->tcp_flags & TCPHDR_SYN) == 0))
-		TCP_ECN_send(sk, skb, tcp_header_size);
+		tcp_ecn_send(sk, skb, tcp_header_size);
 
 #ifdef CONFIG_TCP_MD5SIG
 	/* Calculate the MD5 hash, as we have all we need now */
@@ -975,7 +983,18 @@
 		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
 			      tcp_skb_pcount(skb));
 
+	/* OK, its time to fill skb_shinfo(skb)->gso_segs */
+	skb_shinfo(skb)->gso_segs = tcp_skb_pcount(skb);
+
+	/* Our usage of tstamp should remain private */
+	skb->tstamp.tv64 = 0;
+
+	/* Cleanup our debris for IP stacks */
+	memset(skb->cb, 0, max(sizeof(struct inet_skb_parm),
+			       sizeof(struct inet6_skb_parm)));
+
 	err = icsk->icsk_af_ops->queue_xmit(sk, skb, &inet->cork.fl);
+
 	if (likely(err <= 0))
 		return err;
 
@@ -995,7 +1014,7 @@
 
 	/* Advance write_seq and place onto the write_queue. */
 	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
-	skb_header_release(skb);
+	__skb_header_release(skb);
 	tcp_add_write_queue_tail(sk, skb);
 	sk->sk_wmem_queued += skb->truesize;
 	sk_mem_charge(sk, skb->truesize);
@@ -1014,11 +1033,11 @@
 		/* Avoid the costly divide in the normal
 		 * non-TSO case.
 		 */
-		shinfo->gso_segs = 1;
+		tcp_skb_pcount_set(skb, 1);
 		shinfo->gso_size = 0;
 		shinfo->gso_type = 0;
 	} else {
-		shinfo->gso_segs = DIV_ROUND_UP(skb->len, mss_now);
+		tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
 		shinfo->gso_size = mss_now;
 		shinfo->gso_type = sk->sk_gso_type;
 	}
@@ -1146,10 +1165,6 @@
 
 	buff->ip_summed = skb->ip_summed;
 
-	/* Looks stupid, but our code really uses when of
-	 * skbs, which it never sent before. --ANK
-	 */
-	TCP_SKB_CB(buff)->when = TCP_SKB_CB(skb)->when;
 	buff->tstamp = skb->tstamp;
 	tcp_fragment_tstamp(skb, buff);
 
@@ -1171,7 +1186,7 @@
 	}
 
 	/* Link BUFF into the send queue. */
-	skb_header_release(buff);
+	__skb_header_release(buff);
 	tcp_insert_write_queue_after(skb, buff, sk);
 
 	return 0;
@@ -1675,7 +1690,7 @@
 	tcp_set_skb_tso_segs(sk, buff, mss_now);
 
 	/* Link BUFF into the send queue. */
-	skb_header_release(buff);
+	__skb_header_release(buff);
 	tcp_insert_write_queue_after(skb, buff, sk);
 
 	return 0;
@@ -1874,8 +1889,8 @@
 	tcp_init_tso_segs(sk, nskb, nskb->len);
 
 	/* We're ready to send.  If this fails, the probe will
-	 * be resegmented into mss-sized pieces by tcp_write_xmit(). */
-	TCP_SKB_CB(nskb)->when = tcp_time_stamp;
+	 * be resegmented into mss-sized pieces by tcp_write_xmit().
+	 */
 	if (!tcp_transmit_skb(sk, nskb, 1, GFP_ATOMIC)) {
 		/* Decrement cwnd here because we are sending
 		 * effectively two packets. */
@@ -1935,8 +1950,8 @@
 		BUG_ON(!tso_segs);
 
 		if (unlikely(tp->repair) && tp->repair_queue == TCP_SEND_QUEUE) {
-			/* "when" is used as a start point for the retransmit timer */
-			TCP_SKB_CB(skb)->when = tcp_time_stamp;
+			/* "skb_mstamp" is used as a start point for the retransmit timer */
+			skb_mstamp_get(&skb->skb_mstamp);
 			goto repair; /* Skip network transmission */
 		}
 
@@ -2000,8 +2015,6 @@
 		    unlikely(tso_fragment(sk, skb, limit, mss_now, gfp)))
 			break;
 
-		TCP_SKB_CB(skb)->when = tcp_time_stamp;
-
 		if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))
 			break;
 
@@ -2097,10 +2110,7 @@
 static bool skb_still_in_host_queue(const struct sock *sk,
 				    const struct sk_buff *skb)
 {
-	const struct sk_buff *fclone = skb + 1;
-
-	if (unlikely(skb->fclone == SKB_FCLONE_ORIG &&
-		     fclone->fclone == SKB_FCLONE_CLONE)) {
+	if (unlikely(skb_fclone_busy(skb))) {
 		NET_INC_STATS_BH(sock_net(sk),
 				 LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES);
 		return true;
@@ -2499,7 +2509,6 @@
 	/* Make a copy, if the first transmission SKB clone we made
 	 * is still in somebody's hands, else make a clone.
 	 */
-	TCP_SKB_CB(skb)->when = tcp_time_stamp;
 
 	/* make sure skb->data is aligned on arches that require it
 	 * and check if ack-trimming & collapsing extended the headroom
@@ -2544,7 +2553,7 @@
 
 		/* Save stamp of the first retransmit. */
 		if (!tp->retrans_stamp)
-			tp->retrans_stamp = TCP_SKB_CB(skb)->when;
+			tp->retrans_stamp = tcp_skb_timestamp(skb);
 
 		/* snd_nxt is stored to detect loss of retransmitted segment,
 		 * see tcp_input.c tcp_sacktag_write_queue().
@@ -2752,7 +2761,6 @@
 	tcp_init_nondata_skb(skb, tcp_acceptable_seq(sk),
 			     TCPHDR_ACK | TCPHDR_RST);
 	/* Send it off. */
-	TCP_SKB_CB(skb)->when = tcp_time_stamp;
 	if (tcp_transmit_skb(sk, skb, 0, priority))
 		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);
 
@@ -2780,7 +2788,7 @@
 			if (nskb == NULL)
 				return -ENOMEM;
 			tcp_unlink_write_queue(skb, sk);
-			skb_header_release(nskb);
+			__skb_header_release(nskb);
 			__tcp_add_write_queue_head(sk, nskb);
 			sk_wmem_free_skb(sk, skb);
 			sk->sk_wmem_queued += nskb->truesize;
@@ -2789,9 +2797,8 @@
 		}
 
 		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ACK;
-		TCP_ECN_send_synack(tcp_sk(sk), skb);
+		tcp_ecn_send_synack(sk, skb);
 	}
-	TCP_SKB_CB(skb)->when = tcp_time_stamp;
 	return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
 }
 
@@ -2835,10 +2842,10 @@
 	memset(&opts, 0, sizeof(opts));
 #ifdef CONFIG_SYN_COOKIES
 	if (unlikely(req->cookie_ts))
-		TCP_SKB_CB(skb)->when = cookie_init_timestamp(req);
+		skb->skb_mstamp.stamp_jiffies = cookie_init_timestamp(req);
 	else
 #endif
-	TCP_SKB_CB(skb)->when = tcp_time_stamp;
+	skb_mstamp_get(&skb->skb_mstamp);
 	tcp_header_size = tcp_synack_options(sk, req, mss, skb, &opts, &md5,
 					     foc) + sizeof(*th);
 
@@ -2849,7 +2856,7 @@
 	memset(th, 0, sizeof(struct tcphdr));
 	th->syn = 1;
 	th->ack = 1;
-	TCP_ECN_make_synack(req, th);
+	tcp_ecn_make_synack(req, th, sk);
 	th->source = htons(ireq->ir_num);
 	th->dest = ireq->ir_rmt_port;
 	/* Setting of flags are superfluous here for callers (and ECE is
@@ -2956,7 +2963,7 @@
 	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
 
 	tcb->end_seq += skb->len;
-	skb_header_release(skb);
+	__skb_header_release(skb);
 	__tcp_add_write_queue_tail(sk, skb);
 	sk->sk_wmem_queued += skb->truesize;
 	sk_mem_charge(sk, skb->truesize);
@@ -3086,9 +3093,9 @@
 	skb_reserve(buff, MAX_TCP_HEADER);
 
 	tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
-	tp->retrans_stamp = TCP_SKB_CB(buff)->when = tcp_time_stamp;
+	tp->retrans_stamp = tcp_time_stamp;
 	tcp_connect_queue_skb(sk, buff);
-	TCP_ECN_send_syn(sk, buff);
+	tcp_ecn_send_syn(sk, buff);
 
 	/* Send off SYN; include data in Fast Open. */
 	err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
@@ -3120,6 +3127,8 @@
 	int ato = icsk->icsk_ack.ato;
 	unsigned long timeout;
 
+	tcp_ca_event(sk, CA_EVENT_DELAYED_ACK);
+
 	if (ato > TCP_DELACK_MIN) {
 		const struct tcp_sock *tp = tcp_sk(sk);
 		int max_ato = HZ / 2;
@@ -3176,6 +3185,8 @@
 	if (sk->sk_state == TCP_CLOSE)
 		return;
 
+	tcp_ca_event(sk, CA_EVENT_NON_DELAYED_ACK);
+
 	/* We are not putting this on the write queue, so
 	 * tcp_transmit_skb() will set the ownership to this
 	 * sock.
@@ -3194,9 +3205,10 @@
 	tcp_init_nondata_skb(buff, tcp_acceptable_seq(sk), TCPHDR_ACK);
 
 	/* Send it off, this clears delayed acks for us. */
-	TCP_SKB_CB(buff)->when = tcp_time_stamp;
+	skb_mstamp_get(&buff->skb_mstamp);
 	tcp_transmit_skb(sk, buff, 0, sk_gfp_atomic(sk, GFP_ATOMIC));
 }
+EXPORT_SYMBOL_GPL(tcp_send_ack);
 
 /* This routine sends a packet with an out of date sequence
  * number. It assumes the other end will try to ack it.
@@ -3226,7 +3238,7 @@
 	 * send it.
 	 */
 	tcp_init_nondata_skb(skb, tp->snd_una - !urgent, TCPHDR_ACK);
-	TCP_SKB_CB(skb)->when = tcp_time_stamp;
+	skb_mstamp_get(&skb->skb_mstamp);
 	return tcp_transmit_skb(sk, skb, 0, GFP_ATOMIC);
 }
 
@@ -3270,7 +3282,6 @@
 			tcp_set_skb_tso_segs(sk, skb, mss);
 
 		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
-		TCP_SKB_CB(skb)->when = tcp_time_stamp;
 		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
 		if (!err)
 			tcp_event_new_data_sent(sk, skb);
@@ -3289,6 +3300,7 @@
 {
 	struct inet_connection_sock *icsk = inet_csk(sk);
 	struct tcp_sock *tp = tcp_sk(sk);
+	unsigned long probe_max;
 	int err;
 
 	err = tcp_write_wakeup(sk);
@@ -3304,9 +3316,7 @@
 		if (icsk->icsk_backoff < sysctl_tcp_retries2)
 			icsk->icsk_backoff++;
 		icsk->icsk_probes_out++;
-		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
-					  min(icsk->icsk_rto << icsk->icsk_backoff, TCP_RTO_MAX),
-					  TCP_RTO_MAX);
+		probe_max = TCP_RTO_MAX;
 	} else {
 		/* If packet was not sent due to local congestion,
 		 * do not backoff and do not remember icsk_probes_out.
@@ -3316,11 +3326,11 @@
 		 */
 		if (!icsk->icsk_probes_out)
 			icsk->icsk_probes_out = 1;
-		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
-					  min(icsk->icsk_rto << icsk->icsk_backoff,
-					      TCP_RESOURCE_PROBE_INTERVAL),
-					  TCP_RTO_MAX);
+		probe_max = TCP_RESOURCE_PROBE_INTERVAL;
 	}
+	inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
+				  inet_csk_rto_backoff(icsk, probe_max),
+				  TCP_RTO_MAX);
 }
 
 int tcp_rtx_synack(struct sock *sk, struct request_sock *req)
diff -urN linux/net/ipv4/tcp_probe.c net-next-2.6/net/ipv4/tcp_probe.c
--- linux/net/ipv4/tcp_probe.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_probe.c	2014-10-06 10:49:00.392902103 +0200
@@ -83,7 +83,6 @@
 	struct tcp_log	*log;
 } tcp_probe;
 
-
 static inline int tcp_probe_used(void)
 {
 	return (tcp_probe.head - tcp_probe.tail) & (bufsize - 1);
@@ -101,7 +100,6 @@
 		si4.sin_addr.s_addr = inet->inet_##mem##addr;	\
 	} while (0)						\
 
-
 /*
  * Hook inserted to be called before each receive packet.
  * Note: arguments must match tcp_rcv_established()!
@@ -194,8 +192,8 @@
 
 	return scnprintf(tbuf, n,
 			"%lu.%09lu %pISpc %pISpc %d %#x %#x %u %u %u %u %u\n",
-			(unsigned long) tv.tv_sec,
-			(unsigned long) tv.tv_nsec,
+			(unsigned long)tv.tv_sec,
+			(unsigned long)tv.tv_nsec,
 			&p->src, &p->dst, p->length, p->snd_nxt, p->snd_una,
 			p->snd_cwnd, p->ssthresh, p->snd_wnd, p->srtt, p->rcv_wnd);
 }
diff -urN linux/net/ipv4/tcp_scalable.c net-next-2.6/net/ipv4/tcp_scalable.c
--- linux/net/ipv4/tcp_scalable.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_scalable.c	2014-10-06 10:49:00.392902103 +0200
@@ -31,10 +31,10 @@
 static u32 tcp_scalable_ssthresh(struct sock *sk)
 {
 	const struct tcp_sock *tp = tcp_sk(sk);
+
 	return max(tp->snd_cwnd - (tp->snd_cwnd>>TCP_SCALABLE_MD_SCALE), 2U);
 }
 
-
 static struct tcp_congestion_ops tcp_scalable __read_mostly = {
 	.ssthresh	= tcp_scalable_ssthresh,
 	.cong_avoid	= tcp_scalable_cong_avoid,
diff -urN linux/net/ipv4/tcp_timer.c net-next-2.6/net/ipv4/tcp_timer.c
--- linux/net/ipv4/tcp_timer.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_timer.c	2014-10-06 10:49:00.392902103 +0200
@@ -52,7 +52,7 @@
  *    limit.
  * 2. If we have strong memory pressure.
  */
-static int tcp_out_of_resources(struct sock *sk, int do_reset)
+static int tcp_out_of_resources(struct sock *sk, bool do_reset)
 {
 	struct tcp_sock *tp = tcp_sk(sk);
 	int shift = 0;
@@ -72,7 +72,7 @@
 		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
 		    /*  2. Window is closed. */
 		    (!tp->snd_wnd && !tp->packets_out))
-			do_reset = 1;
+			do_reset = true;
 		if (do_reset)
 			tcp_send_active_reset(sk, GFP_ATOMIC);
 		tcp_done(sk);
@@ -135,10 +135,9 @@
 	if (!inet_csk(sk)->icsk_retransmits)
 		return false;
 
-	if (unlikely(!tcp_sk(sk)->retrans_stamp))
-		start_ts = TCP_SKB_CB(tcp_write_queue_head(sk))->when;
-	else
-		start_ts = tcp_sk(sk)->retrans_stamp;
+	start_ts = tcp_sk(sk)->retrans_stamp;
+	if (unlikely(!start_ts))
+		start_ts = tcp_skb_timestamp(tcp_write_queue_head(sk));
 
 	if (likely(timeout == 0)) {
 		linear_backoff_thresh = ilog2(TCP_RTO_MAX/rto_base);
@@ -181,7 +180,7 @@
 
 		retry_until = sysctl_tcp_retries2;
 		if (sock_flag(sk, SOCK_DEAD)) {
-			const int alive = (icsk->icsk_rto < TCP_RTO_MAX);
+			const int alive = icsk->icsk_rto < TCP_RTO_MAX;
 
 			retry_until = tcp_orphan_retries(sk, alive);
 			do_reset = alive ||
@@ -271,40 +270,41 @@
 	struct inet_connection_sock *icsk = inet_csk(sk);
 	struct tcp_sock *tp = tcp_sk(sk);
 	int max_probes;
+	u32 start_ts;
 
 	if (tp->packets_out || !tcp_send_head(sk)) {
 		icsk->icsk_probes_out = 0;
 		return;
 	}
 
-	/* *WARNING* RFC 1122 forbids this
-	 *
-	 * It doesn't AFAIK, because we kill the retransmit timer -AK
-	 *
-	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
-	 * this behaviour in Solaris down as a bug fix. [AC]
-	 *
-	 * Let me to explain. icsk_probes_out is zeroed by incoming ACKs
-	 * even if they advertise zero window. Hence, connection is killed only
-	 * if we received no ACKs for normal connection timeout. It is not killed
-	 * only because window stays zero for some time, window may be zero
-	 * until armageddon and even later. We are in full accordance
-	 * with RFCs, only probe timer combines both retransmission timeout
-	 * and probe timeout in one bottle.				--ANK
+	/* RFC 1122 4.2.2.17 requires the sender to stay open indefinitely as
+	 * long as the receiver continues to respond probes. We support this by
+	 * default and reset icsk_probes_out with incoming ACKs. But if the
+	 * socket is orphaned or the user specifies TCP_USER_TIMEOUT, we
+	 * kill the socket when the retry count and the time exceeds the
+	 * corresponding system limit. We also implement similar policy when
+	 * we use RTO to probe window in tcp_retransmit_timer().
 	 */
-	max_probes = sysctl_tcp_retries2;
+	start_ts = tcp_skb_timestamp(tcp_send_head(sk));
+	if (!start_ts)
+		skb_mstamp_get(&tcp_send_head(sk)->skb_mstamp);
+	else if (icsk->icsk_user_timeout &&
+		 (s32)(tcp_time_stamp - start_ts) > icsk->icsk_user_timeout)
+		goto abort;
 
+	max_probes = sysctl_tcp_retries2;
 	if (sock_flag(sk, SOCK_DEAD)) {
-		const int alive = ((icsk->icsk_rto << icsk->icsk_backoff) < TCP_RTO_MAX);
+		const int alive = inet_csk_rto_backoff(icsk, TCP_RTO_MAX) < TCP_RTO_MAX;
 
 		max_probes = tcp_orphan_retries(sk, alive);
-
-		if (tcp_out_of_resources(sk, alive || icsk->icsk_probes_out <= max_probes))
+		if (!alive && icsk->icsk_backoff >= max_probes)
+			goto abort;
+		if (tcp_out_of_resources(sk, true))
 			return;
 	}
 
 	if (icsk->icsk_probes_out > max_probes) {
-		tcp_write_err(sk);
+abort:		tcp_write_err(sk);
 	} else {
 		/* Only send another probe if we didn't close things up. */
 		tcp_send_probe0(sk);
diff -urN linux/net/ipv4/tcp_vegas.c net-next-2.6/net/ipv4/tcp_vegas.c
--- linux/net/ipv4/tcp_vegas.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_vegas.c	2014-10-06 10:49:00.392902103 +0200
@@ -51,7 +51,6 @@
 module_param(gamma, int, 0644);
 MODULE_PARM_DESC(gamma, "limit on increase (scale by 2)");
 
-
 /* There are several situations when we must "re-start" Vegas:
  *
  *  o when a connection is established
@@ -133,7 +132,6 @@
 
 void tcp_vegas_state(struct sock *sk, u8 ca_state)
 {
-
 	if (ca_state == TCP_CA_Open)
 		vegas_enable(sk);
 	else
@@ -285,7 +283,6 @@
 	/* Use normal slow start */
 	else if (tp->snd_cwnd <= tp->snd_ssthresh)
 		tcp_slow_start(tp, acked);
-
 }
 
 /* Extract info for Tcp socket info provided via netlink. */
diff -urN linux/net/ipv4/tcp_veno.c net-next-2.6/net/ipv4/tcp_veno.c
--- linux/net/ipv4/tcp_veno.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_veno.c	2014-10-06 10:49:00.432902511 +0200
@@ -175,7 +175,6 @@
 				} else
 					tp->snd_cwnd_cnt++;
 			}
-
 		}
 		if (tp->snd_cwnd < 2)
 			tp->snd_cwnd = 2;
diff -urN linux/net/ipv4/tcp_westwood.c net-next-2.6/net/ipv4/tcp_westwood.c
--- linux/net/ipv4/tcp_westwood.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_westwood.c	2014-10-06 10:49:00.432902511 +0200
@@ -42,7 +42,6 @@
 	u8     reset_rtt_min;    /* Reset RTT min to next RTT sample*/
 };
 
-
 /* TCP Westwood functions and constants */
 #define TCP_WESTWOOD_RTT_MIN   (HZ/20)	/* 50ms */
 #define TCP_WESTWOOD_INIT_RTT  (20*HZ)	/* maybe too conservative?! */
@@ -153,7 +152,6 @@
 		w->rtt_min = min(w->rtt, w->rtt_min);
 }
 
-
 /*
  * @westwood_fast_bw
  * It is called when we are in fast path. In particular it is called when
@@ -208,7 +206,6 @@
 	return w->cumul_ack;
 }
 
-
 /*
  * TCP Westwood
  * Here limit is evaluated as Bw estimation*RTTmin (for obtaining it
@@ -219,47 +216,51 @@
 {
 	const struct tcp_sock *tp = tcp_sk(sk);
 	const struct westwood *w = inet_csk_ca(sk);
+
 	return max_t(u32, (w->bw_est * w->rtt_min) / tp->mss_cache, 2);
 }
 
+static void tcp_westwood_ack(struct sock *sk, u32 ack_flags)
+{
+	if (ack_flags & CA_ACK_SLOWPATH) {
+		struct westwood *w = inet_csk_ca(sk);
+
+		westwood_update_window(sk);
+		w->bk += westwood_acked_count(sk);
+
+		update_rtt_min(w);
+		return;
+	}
+
+	westwood_fast_bw(sk);
+}
+
 static void tcp_westwood_event(struct sock *sk, enum tcp_ca_event event)
 {
 	struct tcp_sock *tp = tcp_sk(sk);
 	struct westwood *w = inet_csk_ca(sk);
 
 	switch (event) {
-	case CA_EVENT_FAST_ACK:
-		westwood_fast_bw(sk);
-		break;
-
 	case CA_EVENT_COMPLETE_CWR:
 		tp->snd_cwnd = tp->snd_ssthresh = tcp_westwood_bw_rttmin(sk);
 		break;
-
 	case CA_EVENT_LOSS:
 		tp->snd_ssthresh = tcp_westwood_bw_rttmin(sk);
 		/* Update RTT_min when next ack arrives */
 		w->reset_rtt_min = 1;
 		break;
-
-	case CA_EVENT_SLOW_ACK:
-		westwood_update_window(sk);
-		w->bk += westwood_acked_count(sk);
-		update_rtt_min(w);
-		break;
-
 	default:
 		/* don't care */
 		break;
 	}
 }
 
-
 /* Extract info for Tcp socket info provided via netlink. */
 static void tcp_westwood_info(struct sock *sk, u32 ext,
 			      struct sk_buff *skb)
 {
 	const struct westwood *ca = inet_csk_ca(sk);
+
 	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
 		struct tcpvegas_info info = {
 			.tcpv_enabled = 1,
@@ -271,12 +272,12 @@
 	}
 }
 
-
 static struct tcp_congestion_ops tcp_westwood __read_mostly = {
 	.init		= tcp_westwood_init,
 	.ssthresh	= tcp_reno_ssthresh,
 	.cong_avoid	= tcp_reno_cong_avoid,
 	.cwnd_event	= tcp_westwood_event,
+	.in_ack_event	= tcp_westwood_ack,
 	.get_info	= tcp_westwood_info,
 	.pkts_acked	= tcp_westwood_pkts_acked,
 
diff -urN linux/net/ipv4/tcp_yeah.c net-next-2.6/net/ipv4/tcp_yeah.c
--- linux/net/ipv4/tcp_yeah.c	2014-09-24 09:52:43.176644334 +0200
+++ net-next-2.6/net/ipv4/tcp_yeah.c	2014-10-06 10:49:00.432902511 +0200
@@ -54,10 +54,8 @@
 	/* Ensure the MD arithmetic works.  This is somewhat pedantic,
 	 * since I don't think we will see a cwnd this large. :) */
 	tp->snd_cwnd_clamp = min_t(u32, tp->snd_cwnd_clamp, 0xffffffff/128);
-
 }
 
-
 static void tcp_yeah_pkts_acked(struct sock *sk, u32 pkts_acked, s32 rtt_us)
 {
 	const struct inet_connection_sock *icsk = inet_csk(sk);
@@ -84,7 +82,7 @@
 		/* Scalable */
 
 		tp->snd_cwnd_cnt += yeah->pkts_acked;
-		if (tp->snd_cwnd_cnt > min(tp->snd_cwnd, TCP_SCALABLE_AI_CNT)){
+		if (tp->snd_cwnd_cnt > min(tp->snd_cwnd, TCP_SCALABLE_AI_CNT)) {
 			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
 				tp->snd_cwnd++;
 			tp->snd_cwnd_cnt = 0;
@@ -120,7 +118,6 @@
 	 */
 
 	if (after(ack, yeah->vegas.beg_snd_nxt)) {
-
 		/* We do the Vegas calculations only if we got enough RTT
 		 * samples that we can be reasonably sure that we got
 		 * at least one RTT sample that wasn't from a delayed ACK.
@@ -189,7 +186,6 @@
 			}
 
 			yeah->lastQ = queue;
-
 		}
 
 		/* Save the extent of the current window so we can use this
@@ -205,7 +201,8 @@
 	}
 }
 
-static u32 tcp_yeah_ssthresh(struct sock *sk) {
+static u32 tcp_yeah_ssthresh(struct sock *sk)
+{
 	const struct tcp_sock *tp = tcp_sk(sk);
 	struct yeah *yeah = inet_csk_ca(sk);
 	u32 reduction;
diff -urN linux/net/ipv4/udp.c net-next-2.6/net/ipv4/udp.c
--- linux/net/ipv4/udp.c	2014-09-24 09:52:43.180644375 +0200
+++ net-next-2.6/net/ipv4/udp.c	2014-10-06 10:49:00.432902511 +0200
@@ -99,6 +99,7 @@
 #include <linux/slab.h>
 #include <net/tcp_states.h>
 #include <linux/skbuff.h>
+#include <linux/netdevice.h>
 #include <linux/proc_fs.h>
 #include <linux/seq_file.h>
 #include <net/net_namespace.h>
@@ -224,7 +225,7 @@
 		remaining = (high - low) + 1;
 
 		rand = prandom_u32();
-		first = (((u64)rand * remaining) >> 32) + low;
+		first = reciprocal_scale(rand, remaining) + low;
 		/*
 		 * force rand to be an odd multiple of UDP_HTABLE_SIZE
 		 */
@@ -448,7 +449,7 @@
 			}
 		} else if (score == badness && reuseport) {
 			matches++;
-			if (((u64)hash * matches) >> 32 == 0)
+			if (reciprocal_scale(hash, matches) == 0)
 				result = sk;
 			hash = next_pseudo_random32(hash);
 		}
@@ -529,7 +530,7 @@
 			}
 		} else if (score == badness && reuseport) {
 			matches++;
-			if (((u64)hash * matches) >> 32 == 0)
+			if (reciprocal_scale(hash, matches) == 0)
 				result = sk;
 			hash = next_pseudo_random32(hash);
 		}
@@ -1787,6 +1788,10 @@
 	if (sk != NULL) {
 		int ret;
 
+		if (udp_sk(sk)->convert_csum && uh->check && !IS_UDPLITE(sk))
+			skb_checksum_try_convert(skb, IPPROTO_UDP, uh->check,
+						 inet_compute_pseudo);
+
 		ret = udp_queue_rcv_skb(sk, skb);
 		sock_put(sk);
 
@@ -1967,7 +1972,7 @@
 		return;
 
 	skb->sk = sk;
-	skb->destructor = sock_edemux;
+	skb->destructor = sock_efree;
 	dst = sk->sk_rx_dst;
 
 	if (dst)
diff -urN linux/net/ipv4/udp_offload.c net-next-2.6/net/ipv4/udp_offload.c
--- linux/net/ipv4/udp_offload.c	2014-09-24 09:52:43.180644375 +0200
+++ net-next-2.6/net/ipv4/udp_offload.c	2014-10-06 10:49:00.432902511 +0200
@@ -25,30 +25,11 @@
 	struct udp_offload_priv __rcu *next;
 };
 
-static int udp4_ufo_send_check(struct sk_buff *skb)
-{
-	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
-		return -EINVAL;
-
-	if (likely(!skb->encapsulation)) {
-		const struct iphdr *iph;
-		struct udphdr *uh;
-
-		iph = ip_hdr(skb);
-		uh = udp_hdr(skb);
-
-		uh->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len,
-				IPPROTO_UDP, 0);
-		skb->csum_start = skb_transport_header(skb) - skb->head;
-		skb->csum_offset = offsetof(struct udphdr, check);
-		skb->ip_summed = CHECKSUM_PARTIAL;
-	}
-
-	return 0;
-}
-
-struct sk_buff *skb_udp_tunnel_segment(struct sk_buff *skb,
-				       netdev_features_t features)
+static struct sk_buff *__skb_udp_tunnel_segment(struct sk_buff *skb,
+	netdev_features_t features,
+	struct sk_buff *(*gso_inner_segment)(struct sk_buff *skb,
+					     netdev_features_t features),
+	__be16 new_protocol)
 {
 	struct sk_buff *segs = ERR_PTR(-EINVAL);
 	u16 mac_offset = skb->mac_header;
@@ -70,7 +51,7 @@
 	skb_reset_mac_header(skb);
 	skb_set_network_header(skb, skb_inner_network_offset(skb));
 	skb->mac_len = skb_inner_network_offset(skb);
-	skb->protocol = htons(ETH_P_TEB);
+	skb->protocol = new_protocol;
 
 	need_csum = !!(skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM);
 	if (need_csum)
@@ -78,7 +59,7 @@
 
 	/* segment inner packet. */
 	enc_features = skb->dev->hw_enc_features & netif_skb_features(skb);
-	segs = skb_mac_gso_segment(skb, enc_features);
+	segs = gso_inner_segment(skb, enc_features);
 	if (IS_ERR_OR_NULL(segs)) {
 		skb_gso_error_unwind(skb, protocol, tnl_hlen, mac_offset,
 				     mac_len);
@@ -123,21 +104,63 @@
 	return segs;
 }
 
+struct sk_buff *skb_udp_tunnel_segment(struct sk_buff *skb,
+				       netdev_features_t features,
+				       bool is_ipv6)
+{
+	__be16 protocol = skb->protocol;
+	const struct net_offload **offloads;
+	const struct net_offload *ops;
+	struct sk_buff *segs = ERR_PTR(-EINVAL);
+	struct sk_buff *(*gso_inner_segment)(struct sk_buff *skb,
+					     netdev_features_t features);
+
+	rcu_read_lock();
+
+	switch (skb->inner_protocol_type) {
+	case ENCAP_TYPE_ETHER:
+		protocol = skb->inner_protocol;
+		gso_inner_segment = skb_mac_gso_segment;
+		break;
+	case ENCAP_TYPE_IPPROTO:
+		offloads = is_ipv6 ? inet6_offloads : inet_offloads;
+		ops = rcu_dereference(offloads[skb->inner_ipproto]);
+		if (!ops || !ops->callbacks.gso_segment)
+			goto out_unlock;
+		gso_inner_segment = ops->callbacks.gso_segment;
+		break;
+	default:
+		goto out_unlock;
+	}
+
+	segs = __skb_udp_tunnel_segment(skb, features, gso_inner_segment,
+					protocol);
+
+out_unlock:
+	rcu_read_unlock();
+
+	return segs;
+}
+
 static struct sk_buff *udp4_ufo_fragment(struct sk_buff *skb,
 					 netdev_features_t features)
 {
 	struct sk_buff *segs = ERR_PTR(-EINVAL);
 	unsigned int mss;
-	int offset;
 	__wsum csum;
+	struct udphdr *uh;
+	struct iphdr *iph;
 
 	if (skb->encapsulation &&
 	    (skb_shinfo(skb)->gso_type &
 	     (SKB_GSO_UDP_TUNNEL|SKB_GSO_UDP_TUNNEL_CSUM))) {
-		segs = skb_udp_tunnel_segment(skb, features);
+		segs = skb_udp_tunnel_segment(skb, features, false);
 		goto out;
 	}
 
+	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
+		goto out;
+
 	mss = skb_shinfo(skb)->gso_size;
 	if (unlikely(skb->len <= mss))
 		goto out;
@@ -165,10 +188,16 @@
 	 * HW cannot do checksum of UDP packets sent as multiple
 	 * IP fragments.
 	 */
-	offset = skb_checksum_start_offset(skb);
-	csum = skb_checksum(skb, offset, skb->len - offset, 0);
-	offset += skb->csum_offset;
-	*(__sum16 *)(skb->data + offset) = csum_fold(csum);
+
+	uh = udp_hdr(skb);
+	iph = ip_hdr(skb);
+
+	uh->check = 0;
+	csum = skb_checksum(skb, 0, skb->len, 0);
+	uh->check = udp_v4_check(skb->len, iph->saddr, iph->daddr, csum);
+	if (uh->check == 0)
+		uh->check = CSUM_MANGLED_0;
+
 	skb->ip_summed = CHECKSUM_NONE;
 
 	/* Fragment the skb. IP headers of the fragments are updated in
@@ -228,30 +257,24 @@
 }
 EXPORT_SYMBOL(udp_del_offload);
 
-static struct sk_buff **udp_gro_receive(struct sk_buff **head, struct sk_buff *skb)
+struct sk_buff **udp_gro_receive(struct sk_buff **head, struct sk_buff *skb,
+				 struct udphdr *uh)
 {
 	struct udp_offload_priv *uo_priv;
 	struct sk_buff *p, **pp = NULL;
-	struct udphdr *uh, *uh2;
-	unsigned int hlen, off;
+	struct udphdr *uh2;
+	unsigned int off = skb_gro_offset(skb);
 	int flush = 1;
 
 	if (NAPI_GRO_CB(skb)->udp_mark ||
-	    (!skb->encapsulation && skb->ip_summed != CHECKSUM_COMPLETE))
+	    (skb->ip_summed != CHECKSUM_PARTIAL &&
+	     NAPI_GRO_CB(skb)->csum_cnt == 0 &&
+	     !NAPI_GRO_CB(skb)->csum_valid))
 		goto out;
 
 	/* mark that this skb passed once through the udp gro layer */
 	NAPI_GRO_CB(skb)->udp_mark = 1;
 
-	off  = skb_gro_offset(skb);
-	hlen = off + sizeof(*uh);
-	uh   = skb_gro_header_fast(skb, off);
-	if (skb_gro_header_hard(skb, hlen)) {
-		uh = skb_gro_header_slow(skb, hlen, off);
-		if (unlikely(!uh))
-			goto out;
-	}
-
 	rcu_read_lock();
 	uo_priv = rcu_dereference(udp_offload_base);
 	for (; uo_priv != NULL; uo_priv = rcu_dereference(uo_priv->next)) {
@@ -269,7 +292,12 @@
 			continue;
 
 		uh2 = (struct udphdr   *)(p->data + off);
-		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source)) {
+
+		/* Match ports and either checksums are either both zero
+		 * or nonzero.
+		 */
+		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source) ||
+		    (!uh->check ^ !uh2->check)) {
 			NAPI_GRO_CB(p)->same_flow = 0;
 			continue;
 		}
@@ -277,6 +305,7 @@
 
 	skb_gro_pull(skb, sizeof(struct udphdr)); /* pull encapsulating udp header */
 	skb_gro_postpull_rcsum(skb, uh, sizeof(struct udphdr));
+	NAPI_GRO_CB(skb)->proto = uo_priv->offload->ipproto;
 	pp = uo_priv->offload->callbacks.gro_receive(head, skb);
 
 out_unlock:
@@ -286,7 +315,34 @@
 	return pp;
 }
 
-static int udp_gro_complete(struct sk_buff *skb, int nhoff)
+static struct sk_buff **udp4_gro_receive(struct sk_buff **head,
+					 struct sk_buff *skb)
+{
+	struct udphdr *uh = udp_gro_udphdr(skb);
+
+	if (unlikely(!uh))
+		goto flush;
+
+	/* Don't bother verifying checksum if we're going to flush anyway. */
+	if (NAPI_GRO_CB(skb)->flush)
+		goto skip;
+
+	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_UDP, uh->check,
+						 inet_gro_compute_pseudo))
+		goto flush;
+	else if (uh->check)
+		skb_gro_checksum_try_convert(skb, IPPROTO_UDP, uh->check,
+					     inet_gro_compute_pseudo);
+skip:
+	NAPI_GRO_CB(skb)->is_ipv6 = 0;
+	return udp_gro_receive(head, skb, uh);
+
+flush:
+	NAPI_GRO_CB(skb)->flush = 1;
+	return NULL;
+}
+
+int udp_gro_complete(struct sk_buff *skb, int nhoff)
 {
 	struct udp_offload_priv *uo_priv;
 	__be16 newlen = htons(skb->len - nhoff);
@@ -304,19 +360,32 @@
 			break;
 	}
 
-	if (uo_priv != NULL)
+	if (uo_priv != NULL) {
+		NAPI_GRO_CB(skb)->proto = uo_priv->offload->ipproto;
 		err = uo_priv->offload->callbacks.gro_complete(skb, nhoff + sizeof(struct udphdr));
+	}
 
 	rcu_read_unlock();
 	return err;
 }
 
+static int udp4_gro_complete(struct sk_buff *skb, int nhoff)
+{
+	const struct iphdr *iph = ip_hdr(skb);
+	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);
+
+	if (uh->check)
+		uh->check = ~udp_v4_check(skb->len - nhoff, iph->saddr,
+					  iph->daddr, 0);
+
+	return udp_gro_complete(skb, nhoff);
+}
+
 static const struct net_offload udpv4_offload = {
 	.callbacks = {
-		.gso_send_check = udp4_ufo_send_check,
 		.gso_segment = udp4_ufo_fragment,
-		.gro_receive  =	udp_gro_receive,
-		.gro_complete =	udp_gro_complete,
+		.gro_receive  =	udp4_gro_receive,
+		.gro_complete =	udp4_gro_complete,
 	},
 };
 
diff -urN linux/net/ipv4/udp_tunnel.c net-next-2.6/net/ipv4/udp_tunnel.c
--- linux/net/ipv4/udp_tunnel.c	2014-09-24 09:52:43.180644375 +0200
+++ net-next-2.6/net/ipv4/udp_tunnel.c	2014-10-06 10:49:00.432902511 +0200
@@ -8,83 +8,40 @@
 #include <net/udp_tunnel.h>
 #include <net/net_namespace.h>
 
-int udp_sock_create(struct net *net, struct udp_port_cfg *cfg,
-		    struct socket **sockp)
+int udp_sock_create4(struct net *net, struct udp_port_cfg *cfg,
+		     struct socket **sockp)
 {
-	int err = -EINVAL;
+	int err;
 	struct socket *sock = NULL;
+	struct sockaddr_in udp_addr;
 
-#if IS_ENABLED(CONFIG_IPV6)
-	if (cfg->family == AF_INET6) {
-		struct sockaddr_in6 udp6_addr;
-
-		err = sock_create_kern(AF_INET6, SOCK_DGRAM, 0, &sock);
-		if (err < 0)
-			goto error;
-
-		sk_change_net(sock->sk, net);
-
-		udp6_addr.sin6_family = AF_INET6;
-		memcpy(&udp6_addr.sin6_addr, &cfg->local_ip6,
-		       sizeof(udp6_addr.sin6_addr));
-		udp6_addr.sin6_port = cfg->local_udp_port;
-		err = kernel_bind(sock, (struct sockaddr *)&udp6_addr,
-				  sizeof(udp6_addr));
-		if (err < 0)
-			goto error;
-
-		if (cfg->peer_udp_port) {
-			udp6_addr.sin6_family = AF_INET6;
-			memcpy(&udp6_addr.sin6_addr, &cfg->peer_ip6,
-			       sizeof(udp6_addr.sin6_addr));
-			udp6_addr.sin6_port = cfg->peer_udp_port;
-			err = kernel_connect(sock,
-					     (struct sockaddr *)&udp6_addr,
-					     sizeof(udp6_addr), 0);
-		}
-		if (err < 0)
-			goto error;
-
-		udp_set_no_check6_tx(sock->sk, !cfg->use_udp6_tx_checksums);
-		udp_set_no_check6_rx(sock->sk, !cfg->use_udp6_rx_checksums);
-	} else
-#endif
-	if (cfg->family == AF_INET) {
-		struct sockaddr_in udp_addr;
-
-		err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &sock);
-		if (err < 0)
-			goto error;
-
-		sk_change_net(sock->sk, net);
+	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &sock);
+	if (err < 0)
+		goto error;
+
+	sk_change_net(sock->sk, net);
+
+	udp_addr.sin_family = AF_INET;
+	udp_addr.sin_addr = cfg->local_ip;
+	udp_addr.sin_port = cfg->local_udp_port;
+	err = kernel_bind(sock, (struct sockaddr *)&udp_addr,
+			  sizeof(udp_addr));
+	if (err < 0)
+		goto error;
 
+	if (cfg->peer_udp_port) {
 		udp_addr.sin_family = AF_INET;
-		udp_addr.sin_addr = cfg->local_ip;
-		udp_addr.sin_port = cfg->local_udp_port;
-		err = kernel_bind(sock, (struct sockaddr *)&udp_addr,
-				  sizeof(udp_addr));
+		udp_addr.sin_addr = cfg->peer_ip;
+		udp_addr.sin_port = cfg->peer_udp_port;
+		err = kernel_connect(sock, (struct sockaddr *)&udp_addr,
+				     sizeof(udp_addr), 0);
 		if (err < 0)
 			goto error;
-
-		if (cfg->peer_udp_port) {
-			udp_addr.sin_family = AF_INET;
-			udp_addr.sin_addr = cfg->peer_ip;
-			udp_addr.sin_port = cfg->peer_udp_port;
-			err = kernel_connect(sock,
-					     (struct sockaddr *)&udp_addr,
-					     sizeof(udp_addr), 0);
-			if (err < 0)
-				goto error;
-		}
-
-		sock->sk->sk_no_check_tx = !cfg->use_udp_checksums;
-	} else {
-		return -EPFNOSUPPORT;
 	}
 
+	sock->sk->sk_no_check_tx = !cfg->use_udp_checksums;
 
 	*sockp = sock;
-
 	return 0;
 
 error:
@@ -95,6 +52,57 @@
 	*sockp = NULL;
 	return err;
 }
-EXPORT_SYMBOL(udp_sock_create);
+EXPORT_SYMBOL(udp_sock_create4);
+
+void setup_udp_tunnel_sock(struct net *net, struct socket *sock,
+			   struct udp_tunnel_sock_cfg *cfg)
+{
+	struct sock *sk = sock->sk;
+
+	/* Disable multicast loopback */
+	inet_sk(sk)->mc_loop = 0;
+
+	/* Enable CHECKSUM_UNNECESSARY to CHECKSUM_COMPLETE conversion */
+	udp_set_convert_csum(sk, true);
+
+	rcu_assign_sk_user_data(sk, cfg->sk_user_data);
+
+	udp_sk(sk)->encap_type = cfg->encap_type;
+	udp_sk(sk)->encap_rcv = cfg->encap_rcv;
+	udp_sk(sk)->encap_destroy = cfg->encap_destroy;
+
+	udp_tunnel_encap_enable(sock);
+}
+EXPORT_SYMBOL_GPL(setup_udp_tunnel_sock);
+
+int udp_tunnel_xmit_skb(struct socket *sock, struct rtable *rt,
+			struct sk_buff *skb, __be32 src, __be32 dst,
+			__u8 tos, __u8 ttl, __be16 df, __be16 src_port,
+			__be16 dst_port, bool xnet)
+{
+	struct udphdr *uh;
+
+	__skb_push(skb, sizeof(*uh));
+	skb_reset_transport_header(skb);
+	uh = udp_hdr(skb);
+
+	uh->dest = dst_port;
+	uh->source = src_port;
+	uh->len = htons(skb->len);
+
+	udp_set_csum(sock->sk->sk_no_check_tx, skb, src, dst, skb->len);
+
+	return iptunnel_xmit(sock->sk, rt, skb, src, dst, IPPROTO_UDP,
+			     tos, ttl, df, xnet);
+}
+EXPORT_SYMBOL_GPL(udp_tunnel_xmit_skb);
+
+void udp_tunnel_sock_release(struct socket *sock)
+{
+	rcu_assign_sk_user_data(sock->sk, NULL);
+	kernel_sock_shutdown(sock, SHUT_RDWR);
+	sk_release_kernel(sock->sk);
+}
+EXPORT_SYMBOL_GPL(udp_tunnel_sock_release);
 
 MODULE_LICENSE("GPL");
diff -urN linux/net/ipv6/addrconf.c net-next-2.6/net/ipv6/addrconf.c
--- linux/net/ipv6/addrconf.c	2014-10-06 10:59:24.271259126 +0200
+++ net-next-2.6/net/ipv6/addrconf.c	2014-10-06 10:49:00.716905405 +0200
@@ -180,7 +180,7 @@
 	.rtr_solicits		= MAX_RTR_SOLICITATIONS,
 	.rtr_solicit_interval	= RTR_SOLICITATION_INTERVAL,
 	.rtr_solicit_delay	= MAX_RTR_SOLICITATION_DELAY,
-	.use_tempaddr 		= 0,
+	.use_tempaddr		= 0,
 	.temp_valid_lft		= TEMP_VALID_LIFETIME,
 	.temp_prefered_lft	= TEMP_PREFERRED_LIFETIME,
 	.regen_max_retry	= REGEN_MAX_RETRY,
@@ -1105,8 +1105,8 @@
 	spin_unlock_bh(&ifp->lock);
 
 	regen_advance = idev->cnf.regen_max_retry *
-	                idev->cnf.dad_transmits *
-	                NEIGH_VAR(idev->nd_parms, RETRANS_TIME) / HZ;
+			idev->cnf.dad_transmits *
+			NEIGH_VAR(idev->nd_parms, RETRANS_TIME) / HZ;
 	write_unlock_bh(&idev->lock);
 
 	/* A temporary address is created only if this calculated Preferred
@@ -1725,7 +1725,7 @@
 	ipv6_addr_prefix(&addr, &ifp->addr, ifp->prefix_len);
 	if (ipv6_addr_any(&addr))
 		return;
-	ipv6_dev_ac_inc(ifp->idev->dev, &addr);
+	__ipv6_dev_ac_inc(ifp->idev, &addr);
 }
 
 /* caller must hold RTNL */
@@ -2844,6 +2844,9 @@
 		if (dev->flags & IFF_SLAVE)
 			break;
 
+		if (idev && idev->cnf.disable_ipv6)
+			break;
+
 		if (event == NETDEV_UP) {
 			if (!addrconf_qdisc_ok(dev)) {
 				/* device is not ready yet. */
@@ -3030,7 +3033,7 @@
 		struct hlist_head *h = &inet6_addr_lst[i];
 
 		spin_lock_bh(&addrconf_hash_lock);
-	restart:
+restart:
 		hlist_for_each_entry_rcu(ifa, h, addr_lst) {
 			if (ifa->idev == idev) {
 				hlist_del_init_rcu(&ifa->addr_lst);
@@ -3544,8 +3547,8 @@
 }
 
 static struct pernet_operations if6_proc_net_ops = {
-       .init = if6_proc_net_init,
-       .exit = if6_proc_net_exit,
+	.init = if6_proc_net_init,
+	.exit = if6_proc_net_exit,
 };
 
 int __init if6_proc_init(void)
diff -urN linux/net/ipv6/af_inet6.c net-next-2.6/net/ipv6/af_inet6.c
--- linux/net/ipv6/af_inet6.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/af_inet6.c	2014-10-06 10:49:00.716905405 +0200
@@ -7,15 +7,15 @@
  *
  *	Adapted from linux/net/ipv4/af_inet.c
  *
- * 	Fixes:
+ *	Fixes:
  *	piggy, Karl Knutson	:	Socket protocol table
- * 	Hideaki YOSHIFUJI	:	sin6_scope_id support
- * 	Arnaldo Melo		: 	check proc_net_create return, cleanups
+ *	Hideaki YOSHIFUJI	:	sin6_scope_id support
+ *	Arnaldo Melo		:	check proc_net_create return, cleanups
  *
  *	This program is free software; you can redistribute it and/or
- *      modify it under the terms of the GNU General Public License
- *      as published by the Free Software Foundation; either version
- *      2 of the License, or (at your option) any later version.
+ *	modify it under the terms of the GNU General Public License
+ *	as published by the Free Software Foundation; either version
+ *	2 of the License, or (at your option) any later version.
  */
 
 #define pr_fmt(fmt) "IPv6: " fmt
@@ -302,7 +302,7 @@
 		/* Reproduce AF_INET checks to make the bindings consistent */
 		v4addr = addr->sin6_addr.s6_addr32[3];
 		chk_addr_ret = inet_addr_type(net, v4addr);
-		if (!sysctl_ip_nonlocal_bind &&
+		if (!net->ipv4.sysctl_ip_nonlocal_bind &&
 		    !(inet->freebind || inet->transparent) &&
 		    v4addr != htonl(INADDR_ANY) &&
 		    chk_addr_ret != RTN_LOCAL &&
@@ -672,10 +672,10 @@
 }
 EXPORT_SYMBOL_GPL(inet6_sk_rebuild_header);
 
-bool ipv6_opt_accepted(const struct sock *sk, const struct sk_buff *skb)
+bool ipv6_opt_accepted(const struct sock *sk, const struct sk_buff *skb,
+		       const struct inet6_skb_parm *opt)
 {
 	const struct ipv6_pinfo *np = inet6_sk(sk);
-	const struct inet6_skb_parm *opt = IP6CB(skb);
 
 	if (np->rxopt.all) {
 		if ((opt->hop && (np->rxopt.bits.hopopts ||
diff -urN linux/net/ipv6/ah6.c net-next-2.6/net/ipv6/ah6.c
--- linux/net/ipv6/ah6.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/ah6.c	2014-10-06 10:49:00.716905405 +0200
@@ -17,10 +17,10 @@
  * Authors
  *
  *	Mitsuru KANDA @USAGI       : IPv6 Support
- * 	Kazunori MIYAZAWA @USAGI   :
- * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
+ *	Kazunori MIYAZAWA @USAGI   :
+ *	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
  *
- * 	This file is derived from net/ipv4/ah.c.
+ *	This file is derived from net/ipv4/ah.c.
  */
 
 #define pr_fmt(fmt) "IPv6: " fmt
@@ -284,7 +284,7 @@
 			ipv6_rearrange_rthdr(iph, exthdr.rth);
 			break;
 
-		default :
+		default:
 			return 0;
 		}
 
@@ -478,7 +478,7 @@
 	auth_data = ah_tmp_auth(work_iph, hdr_len);
 	icv = ah_tmp_icv(ahp->ahash, auth_data, ahp->icv_trunc_len);
 
-	err = memcmp(icv, auth_data, ahp->icv_trunc_len) ? -EBADMSG: 0;
+	err = memcmp(icv, auth_data, ahp->icv_trunc_len) ? -EBADMSG : 0;
 	if (err)
 		goto out;
 
@@ -622,7 +622,7 @@
 		goto out_free;
 	}
 
-	err = memcmp(icv, auth_data, ahp->icv_trunc_len) ? -EBADMSG: 0;
+	err = memcmp(icv, auth_data, ahp->icv_trunc_len) ? -EBADMSG : 0;
 	if (err)
 		goto out_free;
 
@@ -647,8 +647,8 @@
 		   u8 type, u8 code, int offset, __be32 info)
 {
 	struct net *net = dev_net(skb->dev);
-	struct ipv6hdr *iph = (struct ipv6hdr*)skb->data;
-	struct ip_auth_hdr *ah = (struct ip_auth_hdr*)(skb->data+offset);
+	struct ipv6hdr *iph = (struct ipv6hdr *)skb->data;
+	struct ip_auth_hdr *ah = (struct ip_auth_hdr *)(skb->data+offset);
 	struct xfrm_state *x;
 
 	if (type != ICMPV6_PKT_TOOBIG &&
@@ -713,8 +713,6 @@
 	ahp->icv_full_len = aalg_desc->uinfo.auth.icv_fullbits/8;
 	ahp->icv_trunc_len = x->aalg->alg_trunc_len/8;
 
-	BUG_ON(ahp->icv_trunc_len > MAX_AH_AUTH_LEN);
-
 	x->props.header_len = XFRM_ALIGN8(sizeof(struct ip_auth_hdr) +
 					  ahp->icv_trunc_len);
 	switch (x->props.mode) {
@@ -755,11 +753,10 @@
 	return 0;
 }
 
-static const struct xfrm_type ah6_type =
-{
+static const struct xfrm_type ah6_type = {
 	.description	= "AH6",
 	.owner		= THIS_MODULE,
-	.proto	     	= IPPROTO_AH,
+	.proto		= IPPROTO_AH,
 	.flags		= XFRM_TYPE_REPLAY_PROT,
 	.init_state	= ah6_init_state,
 	.destructor	= ah6_destroy,
diff -urN linux/net/ipv6/anycast.c net-next-2.6/net/ipv6/anycast.c
--- linux/net/ipv6/anycast.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/anycast.c	2014-10-06 10:49:00.716905405 +0200
@@ -46,10 +46,6 @@
 
 static int ipv6_dev_ac_dec(struct net_device *dev, const struct in6_addr *addr);
 
-/* Big ac list lock for all the sockets */
-static DEFINE_SPINLOCK(ipv6_sk_ac_lock);
-
-
 /*
  *	socket join an anycast group
  */
@@ -78,7 +74,6 @@
 	pac->acl_addr = *addr;
 
 	rtnl_lock();
-	rcu_read_lock();
 	if (ifindex == 0) {
 		struct rt6_info *rt;
 
@@ -91,11 +86,11 @@
 			goto error;
 		} else {
 			/* router, no matching interface: just pick one */
-			dev = dev_get_by_flags_rcu(net, IFF_UP,
-						   IFF_UP | IFF_LOOPBACK);
+			dev = __dev_get_by_flags(net, IFF_UP,
+						 IFF_UP | IFF_LOOPBACK);
 		}
 	} else
-		dev = dev_get_by_index_rcu(net, ifindex);
+		dev = __dev_get_by_index(net, ifindex);
 
 	if (dev == NULL) {
 		err = -ENODEV;
@@ -127,17 +122,14 @@
 			goto error;
 	}
 
-	err = ipv6_dev_ac_inc(dev, addr);
+	err = __ipv6_dev_ac_inc(idev, addr);
 	if (!err) {
-		spin_lock_bh(&ipv6_sk_ac_lock);
 		pac->acl_next = np->ipv6_ac_list;
 		np->ipv6_ac_list = pac;
-		spin_unlock_bh(&ipv6_sk_ac_lock);
 		pac = NULL;
 	}
 
 error:
-	rcu_read_unlock();
 	rtnl_unlock();
 	if (pac)
 		sock_kfree_s(sk, pac, sizeof(*pac));
@@ -154,7 +146,7 @@
 	struct ipv6_ac_socklist *pac, *prev_pac;
 	struct net *net = sock_net(sk);
 
-	spin_lock_bh(&ipv6_sk_ac_lock);
+	rtnl_lock();
 	prev_pac = NULL;
 	for (pac = np->ipv6_ac_list; pac; pac = pac->acl_next) {
 		if ((ifindex == 0 || pac->acl_ifindex == ifindex) &&
@@ -163,7 +155,7 @@
 		prev_pac = pac;
 	}
 	if (!pac) {
-		spin_unlock_bh(&ipv6_sk_ac_lock);
+		rtnl_unlock();
 		return -ENOENT;
 	}
 	if (prev_pac)
@@ -171,14 +163,9 @@
 	else
 		np->ipv6_ac_list = pac->acl_next;
 
-	spin_unlock_bh(&ipv6_sk_ac_lock);
-
-	rtnl_lock();
-	rcu_read_lock();
-	dev = dev_get_by_index_rcu(net, pac->acl_ifindex);
+	dev = __dev_get_by_index(net, pac->acl_ifindex);
 	if (dev)
 		ipv6_dev_ac_dec(dev, &pac->acl_addr);
-	rcu_read_unlock();
 	rtnl_unlock();
 
 	sock_kfree_s(sk, pac, sizeof(*pac));
@@ -196,19 +183,16 @@
 	if (!np->ipv6_ac_list)
 		return;
 
-	spin_lock_bh(&ipv6_sk_ac_lock);
+	rtnl_lock();
 	pac = np->ipv6_ac_list;
 	np->ipv6_ac_list = NULL;
-	spin_unlock_bh(&ipv6_sk_ac_lock);
 
 	prev_index = 0;
-	rtnl_lock();
-	rcu_read_lock();
 	while (pac) {
 		struct ipv6_ac_socklist *next = pac->acl_next;
 
 		if (pac->acl_ifindex != prev_index) {
-			dev = dev_get_by_index_rcu(net, pac->acl_ifindex);
+			dev = __dev_get_by_index(net, pac->acl_ifindex);
 			prev_index = pac->acl_ifindex;
 		}
 		if (dev)
@@ -216,10 +200,14 @@
 		sock_kfree_s(sk, pac, sizeof(*pac));
 		pac = next;
 	}
-	rcu_read_unlock();
 	rtnl_unlock();
 }
 
+static void aca_get(struct ifacaddr6 *aca)
+{
+	atomic_inc(&aca->aca_refcnt);
+}
+
 static void aca_put(struct ifacaddr6 *ac)
 {
 	if (atomic_dec_and_test(&ac->aca_refcnt)) {
@@ -229,23 +217,40 @@
 	}
 }
 
+static struct ifacaddr6 *aca_alloc(struct rt6_info *rt,
+				   const struct in6_addr *addr)
+{
+	struct inet6_dev *idev = rt->rt6i_idev;
+	struct ifacaddr6 *aca;
+
+	aca = kzalloc(sizeof(*aca), GFP_ATOMIC);
+	if (aca == NULL)
+		return NULL;
+
+	aca->aca_addr = *addr;
+	in6_dev_hold(idev);
+	aca->aca_idev = idev;
+	aca->aca_rt = rt;
+	aca->aca_users = 1;
+	/* aca_tstamp should be updated upon changes */
+	aca->aca_cstamp = aca->aca_tstamp = jiffies;
+	atomic_set(&aca->aca_refcnt, 1);
+	spin_lock_init(&aca->aca_lock);
+
+	return aca;
+}
+
 /*
  *	device anycast group inc (add if not found)
  */
-int ipv6_dev_ac_inc(struct net_device *dev, const struct in6_addr *addr)
+int __ipv6_dev_ac_inc(struct inet6_dev *idev, const struct in6_addr *addr)
 {
 	struct ifacaddr6 *aca;
-	struct inet6_dev *idev;
 	struct rt6_info *rt;
 	int err;
 
 	ASSERT_RTNL();
 
-	idev = in6_dev_get(dev);
-
-	if (idev == NULL)
-		return -EINVAL;
-
 	write_lock_bh(&idev->lock);
 	if (idev->dead) {
 		err = -ENODEV;
@@ -260,46 +265,35 @@
 		}
 	}
 
-	/*
-	 *	not found: create a new one.
-	 */
-
-	aca = kzalloc(sizeof(struct ifacaddr6), GFP_ATOMIC);
-
-	if (aca == NULL) {
-		err = -ENOMEM;
-		goto out;
-	}
-
 	rt = addrconf_dst_alloc(idev, addr, true);
 	if (IS_ERR(rt)) {
-		kfree(aca);
 		err = PTR_ERR(rt);
 		goto out;
 	}
-
-	aca->aca_addr = *addr;
-	aca->aca_idev = idev;
-	aca->aca_rt = rt;
-	aca->aca_users = 1;
-	/* aca_tstamp should be updated upon changes */
-	aca->aca_cstamp = aca->aca_tstamp = jiffies;
-	atomic_set(&aca->aca_refcnt, 2);
-	spin_lock_init(&aca->aca_lock);
+	aca = aca_alloc(rt, addr);
+	if (aca == NULL) {
+		ip6_rt_put(rt);
+		err = -ENOMEM;
+		goto out;
+	}
 
 	aca->aca_next = idev->ac_list;
 	idev->ac_list = aca;
+
+	/* Hold this for addrconf_join_solict() below before we unlock,
+	 * it is already exposed via idev->ac_list.
+	 */
+	aca_get(aca);
 	write_unlock_bh(&idev->lock);
 
 	ip6_ins_rt(rt);
 
-	addrconf_join_solict(dev, &aca->aca_addr);
+	addrconf_join_solict(idev->dev, &aca->aca_addr);
 
 	aca_put(aca);
 	return 0;
 out:
 	write_unlock_bh(&idev->lock);
-	in6_dev_put(idev);
 	return err;
 }
 
@@ -341,7 +335,7 @@
 	return 0;
 }
 
-/* called with rcu_read_lock() */
+/* called with rtnl_lock() */
 static int ipv6_dev_ac_dec(struct net_device *dev, const struct in6_addr *addr)
 {
 	struct inet6_dev *idev = __in6_dev_get(dev);
diff -urN linux/net/ipv6/datagram.c net-next-2.6/net/ipv6/datagram.c
--- linux/net/ipv6/datagram.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/datagram.c	2014-10-06 10:49:00.716905405 +0200
@@ -43,13 +43,13 @@
 int ip6_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 {
 	struct sockaddr_in6	*usin = (struct sockaddr_in6 *) uaddr;
-	struct inet_sock      	*inet = inet_sk(sk);
-	struct ipv6_pinfo      	*np = inet6_sk(sk);
-	struct in6_addr		*daddr, *final_p, final;
+	struct inet_sock	*inet = inet_sk(sk);
+	struct ipv6_pinfo	*np = inet6_sk(sk);
+	struct in6_addr	*daddr, *final_p, final;
 	struct dst_entry	*dst;
 	struct flowi6		fl6;
 	struct ip6_flowlabel	*flowlabel = NULL;
-	struct ipv6_txoptions   *opt;
+	struct ipv6_txoptions	*opt;
 	int			addr_type;
 	int			err;
 
@@ -332,7 +332,7 @@
 {
 	struct ipv6_pinfo *np = inet6_sk(sk);
 	struct sock_exterr_skb *serr;
-	struct sk_buff *skb, *skb2;
+	struct sk_buff *skb;
 	DECLARE_SOCKADDR(struct sockaddr_in6 *, sin, msg->msg_name);
 	struct {
 		struct sock_extended_err ee;
@@ -342,7 +342,7 @@
 	int copied;
 
 	err = -EAGAIN;
-	skb = skb_dequeue(&sk->sk_error_queue);
+	skb = sock_dequeue_err_skb(sk);
 	if (skb == NULL)
 		goto out;
 
@@ -415,17 +415,6 @@
 	msg->msg_flags |= MSG_ERRQUEUE;
 	err = copied;
 
-	/* Reset and regenerate socket error */
-	spin_lock_bh(&sk->sk_error_queue.lock);
-	sk->sk_err = 0;
-	if ((skb2 = skb_peek(&sk->sk_error_queue)) != NULL) {
-		sk->sk_err = SKB_EXT_ERR(skb2)->ee.ee_errno;
-		spin_unlock_bh(&sk->sk_error_queue.lock);
-		sk->sk_error_report(sk);
-	} else {
-		spin_unlock_bh(&sk->sk_error_queue.lock);
-	}
-
 out_free_skb:
 	kfree_skb(skb);
 out:
diff -urN linux/net/ipv6/esp6.c net-next-2.6/net/ipv6/esp6.c
--- linux/net/ipv6/esp6.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/esp6.c	2014-10-06 10:49:00.716905405 +0200
@@ -17,10 +17,10 @@
  * Authors
  *
  *	Mitsuru KANDA @USAGI       : IPv6 Support
- * 	Kazunori MIYAZAWA @USAGI   :
- * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
+ *	Kazunori MIYAZAWA @USAGI   :
+ *	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
  *
- * 	This file is derived from net/ipv4/esp.c
+ *	This file is derived from net/ipv4/esp.c
  */
 
 #define pr_fmt(fmt) "IPv6: " fmt
@@ -598,7 +598,7 @@
 	case XFRM_MODE_BEET:
 		if (x->sel.family != AF_INET6)
 			x->props.header_len += IPV4_BEET_PHMAXLEN +
-				               (sizeof(struct ipv6hdr) - sizeof(struct iphdr));
+					       (sizeof(struct ipv6hdr) - sizeof(struct iphdr));
 		break;
 	case XFRM_MODE_TRANSPORT:
 		break;
@@ -621,11 +621,10 @@
 	return 0;
 }
 
-static const struct xfrm_type esp6_type =
-{
+static const struct xfrm_type esp6_type = {
 	.description	= "ESP6",
-	.owner	     	= THIS_MODULE,
-	.proto	     	= IPPROTO_ESP,
+	.owner		= THIS_MODULE,
+	.proto		= IPPROTO_ESP,
 	.flags		= XFRM_TYPE_REPLAY_PROT,
 	.init_state	= esp6_init_state,
 	.destructor	= esp6_destroy,
diff -urN linux/net/ipv6/exthdrs.c net-next-2.6/net/ipv6/exthdrs.c
--- linux/net/ipv6/exthdrs.c	2013-11-29 12:59:37.859381302 +0100
+++ net-next-2.6/net/ipv6/exthdrs.c	2014-10-06 10:49:00.716905405 +0200
@@ -142,7 +142,7 @@
 		default: /* Other TLV code so scan list */
 			if (optlen > len)
 				goto bad;
-			for (curr=procs; curr->type >= 0; curr++) {
+			for (curr = procs; curr->type >= 0; curr++) {
 				if (curr->type == nh[off]) {
 					/* type specific length/alignment
 					   checks will be performed in the
diff -urN linux/net/ipv6/icmp.c net-next-2.6/net/ipv6/icmp.c
--- linux/net/ipv6/icmp.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/icmp.c	2014-10-06 10:49:00.716905405 +0200
@@ -170,11 +170,11 @@
 /*
  * Check the ICMP output rate limit
  */
-static inline bool icmpv6_xrlim_allow(struct sock *sk, u8 type,
-				      struct flowi6 *fl6)
+static bool icmpv6_xrlim_allow(struct sock *sk, u8 type,
+			       struct flowi6 *fl6)
 {
-	struct dst_entry *dst;
 	struct net *net = sock_net(sk);
+	struct dst_entry *dst;
 	bool res = false;
 
 	/* Informational messages are not limited. */
@@ -199,16 +199,20 @@
 	} else {
 		struct rt6_info *rt = (struct rt6_info *)dst;
 		int tmo = net->ipv6.sysctl.icmpv6_time;
-		struct inet_peer *peer;
 
 		/* Give more bandwidth to wider prefixes. */
 		if (rt->rt6i_dst.plen < 128)
 			tmo >>= ((128 - rt->rt6i_dst.plen)>>5);
 
-		peer = inet_getpeer_v6(net->ipv6.peers, &rt->rt6i_dst.addr, 1);
-		res = inet_peer_xrlim_allow(peer, tmo);
-		if (peer)
-			inet_putpeer(peer);
+		if (icmp_global_allow()) {
+			struct inet_peer *peer;
+
+			peer = inet_getpeer_v6(net->ipv6.peers,
+					       &rt->rt6i_dst.addr, 1);
+			res = inet_peer_xrlim_allow(peer, tmo);
+			if (peer)
+				inet_putpeer(peer);
+		}
 	}
 	dst_release(dst);
 	return res;
@@ -503,7 +507,7 @@
 	msg.type = type;
 
 	len = skb->len - msg.offset;
-	len = min_t(unsigned int, len, IPV6_MIN_MTU - sizeof(struct ipv6hdr) -sizeof(struct icmp6hdr));
+	len = min_t(unsigned int, len, IPV6_MIN_MTU - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr));
 	if (len < 0) {
 		LIMIT_NETDEBUG(KERN_DEBUG "icmp: len problem\n");
 		goto out_dst_release;
@@ -636,7 +640,7 @@
 		/* now skip over extension headers */
 		inner_offset = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr),
 						&nexthdr, &frag_off);
-		if (inner_offset<0)
+		if (inner_offset < 0)
 			goto out;
 	} else {
 		inner_offset = sizeof(struct ipv6hdr);
@@ -808,7 +812,7 @@
 	memset(fl6, 0, sizeof(*fl6));
 	fl6->saddr = *saddr;
 	fl6->daddr = *daddr;
-	fl6->flowi6_proto 	= IPPROTO_ICMPV6;
+	fl6->flowi6_proto	= IPPROTO_ICMPV6;
 	fl6->fl6_icmp_type	= type;
 	fl6->fl6_icmp_code	= 0;
 	fl6->flowi6_oif		= oif;
@@ -875,8 +879,8 @@
 }
 
 static struct pernet_operations icmpv6_sk_ops = {
-       .init = icmpv6_sk_init,
-       .exit = icmpv6_sk_exit,
+	.init = icmpv6_sk_init,
+	.exit = icmpv6_sk_exit,
 };
 
 int __init icmpv6_init(void)
diff -urN linux/net/ipv6/inet6_connection_sock.c net-next-2.6/net/ipv6/inet6_connection_sock.c
--- linux/net/ipv6/inet6_connection_sock.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/inet6_connection_sock.c	2014-10-06 10:49:00.716905405 +0200
@@ -63,7 +63,6 @@
 
 	return sk2 != NULL;
 }
-
 EXPORT_SYMBOL_GPL(inet6_csk_bind_conflict);
 
 struct dst_entry *inet6_csk_route_req(struct sock *sk,
@@ -144,7 +143,6 @@
 
 	return NULL;
 }
-
 EXPORT_SYMBOL_GPL(inet6_csk_search_req);
 
 void inet6_csk_reqsk_queue_hash_add(struct sock *sk,
@@ -160,10 +158,9 @@
 	reqsk_queue_hash_req(&icsk->icsk_accept_queue, h, req, timeout);
 	inet_csk_reqsk_queue_added(sk, timeout);
 }
-
 EXPORT_SYMBOL_GPL(inet6_csk_reqsk_queue_hash_add);
 
-void inet6_csk_addr2sockaddr(struct sock *sk, struct sockaddr * uaddr)
+void inet6_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr)
 {
 	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) uaddr;
 
@@ -175,7 +172,6 @@
 	sin6->sin6_scope_id = ipv6_iface_scope_id(&sin6->sin6_addr,
 						  sk->sk_bound_dev_if);
 }
-
 EXPORT_SYMBOL_GPL(inet6_csk_addr2sockaddr);
 
 static inline
diff -urN linux/net/ipv6/inet6_hashtables.c net-next-2.6/net/ipv6/inet6_hashtables.c
--- linux/net/ipv6/inet6_hashtables.c	2013-11-29 12:59:37.859381302 +0100
+++ net-next-2.6/net/ipv6/inet6_hashtables.c	2014-10-06 10:49:00.716905405 +0200
@@ -6,7 +6,7 @@
  *		Generic INET6 transport hashtables
  *
  * Authors:	Lotsa people, from code originally in tcp, generalised here
- * 		by Arnaldo Carvalho de Melo <acme@mandriva.com>
+ *		by Arnaldo Carvalho de Melo <acme@mandriva.com>
  *
  *	This program is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU General Public License
@@ -198,7 +198,7 @@
 			}
 		} else if (score == hiscore && reuseport) {
 			matches++;
-			if (((u64)phash * matches) >> 32 == 0)
+			if (reciprocal_scale(phash, matches) == 0)
 				result = sk;
 			phash = next_pseudo_random32(phash);
 		}
@@ -222,7 +222,6 @@
 	rcu_read_unlock();
 	return result;
 }
-
 EXPORT_SYMBOL_GPL(inet6_lookup_listener);
 
 struct sock *inet6_lookup(struct net *net, struct inet_hashinfo *hashinfo,
@@ -238,7 +237,6 @@
 
 	return sk;
 }
-
 EXPORT_SYMBOL_GPL(inet6_lookup);
 
 static int __inet6_check_established(struct inet_timewait_death_row *death_row,
@@ -324,5 +322,4 @@
 	return __inet_hash_connect(death_row, sk, inet6_sk_port_offset(sk),
 			__inet6_check_established, __inet6_hash);
 }
-
 EXPORT_SYMBOL_GPL(inet6_hash_connect);
diff -urN linux/net/ipv6/ip6_flowlabel.c net-next-2.6/net/ipv6/ip6_flowlabel.c
--- linux/net/ipv6/ip6_flowlabel.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/ip6_flowlabel.c	2014-10-06 10:49:00.732905568 +0200
@@ -136,7 +136,7 @@
 
 	spin_lock(&ip6_fl_lock);
 
-	for (i=0; i<=FL_HASH_MASK; i++) {
+	for (i = 0; i <= FL_HASH_MASK; i++) {
 		struct ip6_flowlabel *fl;
 		struct ip6_flowlabel __rcu **flp;
 
@@ -239,7 +239,7 @@
 
 /* Socket flowlabel lists */
 
-struct ip6_flowlabel * fl6_sock_lookup(struct sock *sk, __be32 label)
+struct ip6_flowlabel *fl6_sock_lookup(struct sock *sk, __be32 label)
 {
 	struct ipv6_fl_socklist *sfl;
 	struct ipv6_pinfo *np = inet6_sk(sk);
@@ -259,7 +259,6 @@
 	rcu_read_unlock_bh();
 	return NULL;
 }
-
 EXPORT_SYMBOL_GPL(fl6_sock_lookup);
 
 void fl6_free_socklist(struct sock *sk)
@@ -293,11 +292,11 @@
    following rthdr.
  */
 
-struct ipv6_txoptions *fl6_merge_options(struct ipv6_txoptions * opt_space,
-					 struct ip6_flowlabel * fl,
-					 struct ipv6_txoptions * fopt)
+struct ipv6_txoptions *fl6_merge_options(struct ipv6_txoptions *opt_space,
+					 struct ip6_flowlabel *fl,
+					 struct ipv6_txoptions *fopt)
 {
-	struct ipv6_txoptions * fl_opt = fl->opt;
+	struct ipv6_txoptions *fl_opt = fl->opt;
 
 	if (fopt == NULL || fopt->opt_flen == 0)
 		return fl_opt;
@@ -388,7 +387,7 @@
 			goto done;
 
 		msg.msg_controllen = olen;
-		msg.msg_control = (void*)(fl->opt+1);
+		msg.msg_control = (void *)(fl->opt+1);
 		memset(&flowi6, 0, sizeof(flowi6));
 
 		err = ip6_datagram_send_ctl(net, sk, &msg, &flowi6, fl->opt,
@@ -517,7 +516,7 @@
 	struct net *net = sock_net(sk);
 	struct ipv6_pinfo *np = inet6_sk(sk);
 	struct in6_flowlabel_req freq;
-	struct ipv6_fl_socklist *sfl1=NULL;
+	struct ipv6_fl_socklist *sfl1 = NULL;
 	struct ipv6_fl_socklist *sfl;
 	struct ipv6_fl_socklist __rcu **sflp;
 	struct ip6_flowlabel *fl, *fl1 = NULL;
@@ -542,7 +541,7 @@
 		}
 		spin_lock_bh(&ip6_sk_fl_lock);
 		for (sflp = &np->ipv6_fl_list;
-		     (sfl = rcu_dereference(*sflp))!=NULL;
+		     (sfl = rcu_dereference(*sflp)) != NULL;
 		     sflp = &sfl->next) {
 			if (sfl->fl->label == freq.flr_label) {
 				if (freq.flr_label == (np->flow_label&IPV6_FLOWLABEL_MASK))
diff -urN linux/net/ipv6/ip6_gre.c net-next-2.6/net/ipv6/ip6_gre.c
--- linux/net/ipv6/ip6_gre.c	2014-10-06 10:59:24.271259126 +0200
+++ net-next-2.6/net/ipv6/ip6_gre.c	2014-10-06 10:49:00.732905568 +0200
@@ -618,6 +618,7 @@
 	int err = -1;
 	u8 proto;
 	struct sk_buff *new_skb;
+	__be16 protocol;
 
 	if (dev->type == ARPHRD_ETHER)
 		IPCB(skb)->flags = 0;
@@ -734,8 +735,9 @@
 	ipv6h->daddr = fl6->daddr;
 
 	((__be16 *)(ipv6h + 1))[0] = tunnel->parms.o_flags;
-	((__be16 *)(ipv6h + 1))[1] = (dev->type == ARPHRD_ETHER) ?
-				   htons(ETH_P_TEB) : skb->protocol;
+	protocol = (dev->type == ARPHRD_ETHER) ?
+		    htons(ETH_P_TEB) : skb->protocol;
+	((__be16 *)(ipv6h + 1))[1] = protocol;
 
 	if (tunnel->parms.o_flags&(GRE_KEY|GRE_CSUM|GRE_SEQ)) {
 		__be32 *ptr = (__be32 *)(((u8 *)ipv6h) + tunnel->hlen - 4);
@@ -756,6 +758,8 @@
 		}
 	}
 
+	skb_set_inner_protocol(skb, protocol);
+
 	ip6tunnel_xmit(skb, dev);
 	if (ndst)
 		ip6_tnl_dst_store(tunnel, ndst);
diff -urN linux/net/ipv6/ip6_icmp.c net-next-2.6/net/ipv6/ip6_icmp.c
--- linux/net/ipv6/ip6_icmp.c	2013-05-02 09:43:20.669515168 +0200
+++ net-next-2.6/net/ipv6/ip6_icmp.c	2014-10-06 10:49:00.732905568 +0200
@@ -13,7 +13,7 @@
 int inet6_register_icmp_sender(ip6_icmp_send_t *fn)
 {
 	return (cmpxchg((ip6_icmp_send_t **)&ip6_icmp_send, NULL, fn) == NULL) ?
-	        0 : -EBUSY;
+		0 : -EBUSY;
 }
 EXPORT_SYMBOL(inet6_register_icmp_sender);
 
diff -urN linux/net/ipv6/ip6_input.c net-next-2.6/net/ipv6/ip6_input.c
--- linux/net/ipv6/ip6_input.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/ip6_input.c	2014-10-06 10:49:00.732905568 +0200
@@ -15,8 +15,8 @@
  */
 /* Changes
  *
- * 	Mitsuru KANDA @USAGI and
- * 	YOSHIFUJI Hideaki @USAGI: Remove ipv6_parse_exthdrs().
+ *	Mitsuru KANDA @USAGI and
+ *	YOSHIFUJI Hideaki @USAGI: Remove ipv6_parse_exthdrs().
  */
 
 #include <linux/errno.h>
@@ -65,7 +65,7 @@
 int ipv6_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
 {
 	const struct ipv6hdr *hdr;
-	u32 		pkt_len;
+	u32 pkt_len;
 	struct inet6_dev *idev;
 	struct net *net = dev_net(skb->dev);
 
diff -urN linux/net/ipv6/ip6mr.c net-next-2.6/net/ipv6/ip6mr.c
--- linux/net/ipv6/ip6mr.c	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/ip6mr.c	2014-10-06 10:49:00.756905813 +0200
@@ -845,7 +845,7 @@
 
 	atomic_dec(&mrt->cache_resolve_queue_len);
 
-	while((skb = skb_dequeue(&c->mfc_un.unres.unresolved)) != NULL) {
+	while ((skb = skb_dequeue(&c->mfc_un.unres.unresolved)) != NULL) {
 		if (ipv6_hdr(skb)->version == 0) {
 			struct nlmsghdr *nlh = (struct nlmsghdr *)skb_pull(skb, sizeof(struct ipv6hdr));
 			nlh->nlmsg_type = NLMSG_ERROR;
@@ -1103,7 +1103,7 @@
 	 *	Play the pending entries through our router
 	 */
 
-	while((skb = __skb_dequeue(&uc->mfc_un.unres.unresolved))) {
+	while ((skb = __skb_dequeue(&uc->mfc_un.unres.unresolved))) {
 		if (ipv6_hdr(skb)->version == 0) {
 			struct nlmsghdr *nlh = (struct nlmsghdr *)skb_pull(skb, sizeof(struct ipv6hdr));
 
diff -urN linux/net/ipv6/ip6_offload.c net-next-2.6/net/ipv6/ip6_offload.c
--- linux/net/ipv6/ip6_offload.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/ip6_offload.c	2014-10-06 10:49:00.732905568 +0200
@@ -53,31 +53,6 @@
 	return proto;
 }
 
-static int ipv6_gso_send_check(struct sk_buff *skb)
-{
-	const struct ipv6hdr *ipv6h;
-	const struct net_offload *ops;
-	int err = -EINVAL;
-
-	if (unlikely(!pskb_may_pull(skb, sizeof(*ipv6h))))
-		goto out;
-
-	ipv6h = ipv6_hdr(skb);
-	__skb_pull(skb, sizeof(*ipv6h));
-	err = -EPROTONOSUPPORT;
-
-	ops = rcu_dereference(inet6_offloads[
-		ipv6_gso_pull_exthdrs(skb, ipv6h->nexthdr)]);
-
-	if (likely(ops && ops->callbacks.gso_send_check)) {
-		skb_reset_transport_header(skb);
-		err = ops->callbacks.gso_send_check(skb);
-	}
-
-out:
-	return err;
-}
-
 static struct sk_buff *ipv6_gso_segment(struct sk_buff *skb,
 	netdev_features_t features)
 {
@@ -244,7 +219,7 @@
 			continue;
 
 		iph2 = (struct ipv6hdr *)(p->data + off);
-		first_word = *(__be32 *)iph ^ *(__be32 *)iph2 ;
+		first_word = *(__be32 *)iph ^ *(__be32 *)iph2;
 
 		/* All fields must match except length and Traffic Class.
 		 * XXX skbs on the gro_list have all been parsed and pulled
@@ -261,6 +236,9 @@
 		/* flush if Traffic Class fields are different */
 		NAPI_GRO_CB(p)->flush |= !!(first_word & htonl(0x0FF00000));
 		NAPI_GRO_CB(p)->flush |= flush;
+
+		/* Clear flush_id, there's really no concept of ID in IPv6. */
+		NAPI_GRO_CB(p)->flush_id = 0;
 	}
 
 	NAPI_GRO_CB(skb)->flush |= flush;
@@ -303,7 +281,6 @@
 static struct packet_offload ipv6_packet_offload __read_mostly = {
 	.type = cpu_to_be16(ETH_P_IPV6),
 	.callbacks = {
-		.gso_send_check = ipv6_gso_send_check,
 		.gso_segment = ipv6_gso_segment,
 		.gro_receive = ipv6_gro_receive,
 		.gro_complete = ipv6_gro_complete,
@@ -312,8 +289,9 @@
 
 static const struct net_offload sit_offload = {
 	.callbacks = {
-		.gso_send_check = ipv6_gso_send_check,
 		.gso_segment	= ipv6_gso_segment,
+		.gro_receive	= ipv6_gro_receive,
+		.gro_complete	= ipv6_gro_complete,
 	},
 };
 
diff -urN linux/net/ipv6/ip6_output.c net-next-2.6/net/ipv6/ip6_output.c
--- linux/net/ipv6/ip6_output.c	2014-09-24 09:52:43.184644417 +0200
+++ net-next-2.6/net/ipv6/ip6_output.c	2014-10-06 10:49:00.732905568 +0200
@@ -20,7 +20,7 @@
  *				etc.
  *
  *      H. von Brand    :       Added missing #include <linux/string.h>
- *	Imran Patel	: 	frag id should be in NBO
+ *	Imran Patel	:	frag id should be in NBO
  *      Kazunori MIYAZAWA @USAGI
  *			:       add ip6_append_data and related functions
  *				for datagram xmit
@@ -233,7 +233,6 @@
 	kfree_skb(skb);
 	return -EMSGSIZE;
 }
-
 EXPORT_SYMBOL(ip6_xmit);
 
 static int ip6_call_ra_chain(struct sk_buff *skb, int sel)
@@ -555,14 +554,14 @@
 int ip6_fragment(struct sk_buff *skb, int (*output)(struct sk_buff *))
 {
 	struct sk_buff *frag;
-	struct rt6_info *rt = (struct rt6_info*)skb_dst(skb);
+	struct rt6_info *rt = (struct rt6_info *)skb_dst(skb);
 	struct ipv6_pinfo *np = skb->sk ? inet6_sk(skb->sk) : NULL;
 	struct ipv6hdr *tmp_hdr;
 	struct frag_hdr *fh;
 	unsigned int mtu, hlen, left, len;
 	int hroom, troom;
 	__be32 frag_id = 0;
-	int ptr, offset = 0, err=0;
+	int ptr, offset = 0, err = 0;
 	u8 *prevhdr, nexthdr = 0;
 	struct net *net = dev_net(skb_dst(skb)->dev);
 
@@ -637,7 +636,7 @@
 		}
 
 		__skb_pull(skb, hlen);
-		fh = (struct frag_hdr*)__skb_push(skb, sizeof(struct frag_hdr));
+		fh = (struct frag_hdr *)__skb_push(skb, sizeof(struct frag_hdr));
 		__skb_push(skb, hlen);
 		skb_reset_network_header(skb);
 		memcpy(skb_network_header(skb), tmp_hdr, hlen);
@@ -662,7 +661,7 @@
 			if (frag) {
 				frag->ip_summed = CHECKSUM_NONE;
 				skb_reset_transport_header(frag);
-				fh = (struct frag_hdr*)__skb_push(frag, sizeof(struct frag_hdr));
+				fh = (struct frag_hdr *)__skb_push(frag, sizeof(struct frag_hdr));
 				__skb_push(frag, hlen);
 				skb_reset_network_header(frag);
 				memcpy(skb_network_header(frag), tmp_hdr,
@@ -681,7 +680,7 @@
 			}
 
 			err = output(skb);
-			if(!err)
+			if (!err)
 				IP6_INC_STATS(net, ip6_dst_idev(&rt->dst),
 					      IPSTATS_MIB_FRAGCREATES);
 
@@ -702,11 +701,7 @@
 			return 0;
 		}
 
-		while (frag) {
-			skb = frag->next;
-			kfree_skb(frag);
-			frag = skb;
-		}
+		kfree_skb_list(frag);
 
 		IP6_INC_STATS(net, ip6_dst_idev(&rt->dst),
 			      IPSTATS_MIB_FRAGFAILS);
@@ -742,7 +737,7 @@
 	/*
 	 *	Keep copying data until we run out.
 	 */
-	while(left > 0)	{
+	while (left > 0)	{
 		len = left;
 		/* IF: it doesn't fit, use 'mtu' - the data space left */
 		if (len > mtu)
@@ -865,7 +860,7 @@
 	/* Yes, checking route validity in not connected
 	 * case is not very simple. Take into account,
 	 * that we do not support routing by source, TOS,
-	 * and MSG_DONTROUTE 		--ANK (980726)
+	 * and MSG_DONTROUTE		--ANK (980726)
 	 *
 	 * 1. ip6_rt_check(): If route was host route,
 	 *    check that cached destination is current.
@@ -1049,7 +1044,7 @@
 			int getfrag(void *from, char *to, int offset, int len,
 			int odd, struct sk_buff *skb),
 			void *from, int length, int hh_len, int fragheaderlen,
-			int transhdrlen, int mtu,unsigned int flags,
+			int transhdrlen, int mtu, unsigned int flags,
 			struct rt6_info *rt)
 
 {
@@ -1072,7 +1067,7 @@
 		skb_reserve(skb, hh_len);
 
 		/* create space for UDP/IP header */
-		skb_put(skb,fragheaderlen + transhdrlen);
+		skb_put(skb, fragheaderlen + transhdrlen);
 
 		/* initialize network header pointer */
 		skb_reset_network_header(skb);
diff -urN linux/net/ipv6/ip6_tunnel.c net-next-2.6/net/ipv6/ip6_tunnel.c
--- linux/net/ipv6/ip6_tunnel.c	2014-10-06 10:59:24.271259126 +0200
+++ net-next-2.6/net/ipv6/ip6_tunnel.c	2014-10-06 10:49:00.756905813 +0200
@@ -412,12 +412,12 @@
 {
 	const struct ipv6hdr *ipv6h = (const struct ipv6hdr *) raw;
 	__u8 nexthdr = ipv6h->nexthdr;
-	__u16 off = sizeof (*ipv6h);
+	__u16 off = sizeof(*ipv6h);
 
 	while (ipv6_ext_hdr(nexthdr) && nexthdr != NEXTHDR_NONE) {
 		__u16 optlen = 0;
 		struct ipv6_opt_hdr *hdr;
-		if (raw + off + sizeof (*hdr) > skb->data &&
+		if (raw + off + sizeof(*hdr) > skb->data &&
 		    !pskb_may_pull(skb, raw - skb->data + off + sizeof (*hdr)))
 			break;
 
@@ -534,7 +534,7 @@
 			mtu = IPV6_MIN_MTU;
 		t->dev->mtu = mtu;
 
-		if ((len = sizeof (*ipv6h) + ntohs(ipv6h->payload_len)) > mtu) {
+		if ((len = sizeof(*ipv6h) + ntohs(ipv6h->payload_len)) > mtu) {
 			rel_type = ICMPV6_PKT_TOOBIG;
 			rel_code = 0;
 			rel_info = mtu;
@@ -995,7 +995,7 @@
 				     t->parms.name);
 		goto tx_err_dst_release;
 	}
-	mtu = dst_mtu(dst) - sizeof (*ipv6h);
+	mtu = dst_mtu(dst) - sizeof(*ipv6h);
 	if (encap_limit >= 0) {
 		max_headroom += 8;
 		mtu -= 8;
@@ -1087,7 +1087,7 @@
 	if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
 		encap_limit = t->parms.encap_limit;
 
-	memcpy(&fl6, &t->fl.u.ip6, sizeof (fl6));
+	memcpy(&fl6, &t->fl.u.ip6, sizeof(fl6));
 	fl6.flowi6_proto = IPPROTO_IPIP;
 
 	dsfield = ipv4_get_dsfield(iph);
@@ -1139,7 +1139,7 @@
 	} else if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
 		encap_limit = t->parms.encap_limit;
 
-	memcpy(&fl6, &t->fl.u.ip6, sizeof (fl6));
+	memcpy(&fl6, &t->fl.u.ip6, sizeof(fl6));
 	fl6.flowi6_proto = IPPROTO_IPV6;
 
 	dsfield = ipv6_get_dsfield(ipv6h);
@@ -1233,11 +1233,11 @@
 
 		if (rt->dst.dev) {
 			dev->hard_header_len = rt->dst.dev->hard_header_len +
-				sizeof (struct ipv6hdr);
+				sizeof(struct ipv6hdr);
 
-			dev->mtu = rt->dst.dev->mtu - sizeof (struct ipv6hdr);
+			dev->mtu = rt->dst.dev->mtu - sizeof(struct ipv6hdr);
 			if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
-				dev->mtu-=8;
+				dev->mtu -= 8;
 
 			if (dev->mtu < IPV6_MIN_MTU)
 				dev->mtu = IPV6_MIN_MTU;
@@ -1354,7 +1354,7 @@
 	switch (cmd) {
 	case SIOCGETTUNNEL:
 		if (dev == ip6n->fb_tnl_dev) {
-			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p))) {
+			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p))) {
 				err = -EFAULT;
 				break;
 			}
@@ -1366,7 +1366,7 @@
 			memset(&p, 0, sizeof(p));
 		}
 		ip6_tnl_parm_to_user(&p, &t->parms);
-		if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof (p))) {
+		if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof(p))) {
 			err = -EFAULT;
 		}
 		break;
@@ -1376,7 +1376,7 @@
 		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
 			break;
 		err = -EFAULT;
-		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p)))
+		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
 			break;
 		err = -EINVAL;
 		if (p.proto != IPPROTO_IPV6 && p.proto != IPPROTO_IPIP &&
@@ -1411,7 +1411,7 @@
 
 		if (dev == ip6n->fb_tnl_dev) {
 			err = -EFAULT;
-			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p)))
+			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
 				break;
 			err = -ENOENT;
 			ip6_tnl_parm_from_user(&p1, &p);
@@ -1486,11 +1486,11 @@
 	dev->destructor = ip6_dev_free;
 
 	dev->type = ARPHRD_TUNNEL6;
-	dev->hard_header_len = LL_MAX_HEADER + sizeof (struct ipv6hdr);
-	dev->mtu = ETH_DATA_LEN - sizeof (struct ipv6hdr);
+	dev->hard_header_len = LL_MAX_HEADER + sizeof(struct ipv6hdr);
+	dev->mtu = ETH_DATA_LEN - sizeof(struct ipv6hdr);
 	t = netdev_priv(dev);
 	if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
-		dev->mtu-=8;
+		dev->mtu -= 8;
 	dev->flags |= IFF_NOARP;
 	dev->addr_len = sizeof(struct in6_addr);
 	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
diff -urN linux/net/ipv6/ip6_udp_tunnel.c net-next-2.6/net/ipv6/ip6_udp_tunnel.c
--- linux/net/ipv6/ip6_udp_tunnel.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv6/ip6_udp_tunnel.c	2014-10-06 10:49:00.756905813 +0200
@@ -0,0 +1,107 @@
+#include <linux/module.h>
+#include <linux/errno.h>
+#include <linux/socket.h>
+#include <linux/udp.h>
+#include <linux/types.h>
+#include <linux/kernel.h>
+#include <linux/in6.h>
+#include <net/udp.h>
+#include <net/udp_tunnel.h>
+#include <net/net_namespace.h>
+#include <net/netns/generic.h>
+#include <net/ip6_tunnel.h>
+#include <net/ip6_checksum.h>
+
+int udp_sock_create6(struct net *net, struct udp_port_cfg *cfg,
+		     struct socket **sockp)
+{
+	struct sockaddr_in6 udp6_addr;
+	int err;
+	struct socket *sock = NULL;
+
+	err = sock_create_kern(AF_INET6, SOCK_DGRAM, 0, &sock);
+	if (err < 0)
+		goto error;
+
+	sk_change_net(sock->sk, net);
+
+	udp6_addr.sin6_family = AF_INET6;
+	memcpy(&udp6_addr.sin6_addr, &cfg->local_ip6,
+	       sizeof(udp6_addr.sin6_addr));
+	udp6_addr.sin6_port = cfg->local_udp_port;
+	err = kernel_bind(sock, (struct sockaddr *)&udp6_addr,
+			  sizeof(udp6_addr));
+	if (err < 0)
+		goto error;
+
+	if (cfg->peer_udp_port) {
+		udp6_addr.sin6_family = AF_INET6;
+		memcpy(&udp6_addr.sin6_addr, &cfg->peer_ip6,
+		       sizeof(udp6_addr.sin6_addr));
+		udp6_addr.sin6_port = cfg->peer_udp_port;
+		err = kernel_connect(sock,
+				     (struct sockaddr *)&udp6_addr,
+				     sizeof(udp6_addr), 0);
+	}
+	if (err < 0)
+		goto error;
+
+	udp_set_no_check6_tx(sock->sk, !cfg->use_udp6_tx_checksums);
+	udp_set_no_check6_rx(sock->sk, !cfg->use_udp6_rx_checksums);
+
+	*sockp = sock;
+	return 0;
+
+error:
+	if (sock) {
+		kernel_sock_shutdown(sock, SHUT_RDWR);
+		sk_release_kernel(sock->sk);
+	}
+	*sockp = NULL;
+	return err;
+}
+EXPORT_SYMBOL_GPL(udp_sock_create6);
+
+int udp_tunnel6_xmit_skb(struct socket *sock, struct dst_entry *dst,
+			 struct sk_buff *skb, struct net_device *dev,
+			 struct in6_addr *saddr, struct in6_addr *daddr,
+			 __u8 prio, __u8 ttl, __be16 src_port, __be16 dst_port)
+{
+	struct udphdr *uh;
+	struct ipv6hdr *ip6h;
+	struct sock *sk = sock->sk;
+
+	__skb_push(skb, sizeof(*uh));
+	skb_reset_transport_header(skb);
+	uh = udp_hdr(skb);
+
+	uh->dest = dst_port;
+	uh->source = src_port;
+
+	uh->len = htons(skb->len);
+	uh->check = 0;
+
+	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
+	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED
+			    | IPSKB_REROUTED);
+	skb_dst_set(skb, dst);
+
+	udp6_set_csum(udp_get_no_check6_tx(sk), skb, &inet6_sk(sk)->saddr,
+		      &sk->sk_v6_daddr, skb->len);
+
+	__skb_push(skb, sizeof(*ip6h));
+	skb_reset_network_header(skb);
+	ip6h		  = ipv6_hdr(skb);
+	ip6_flow_hdr(ip6h, prio, htonl(0));
+	ip6h->payload_len = htons(skb->len);
+	ip6h->nexthdr     = IPPROTO_UDP;
+	ip6h->hop_limit   = ttl;
+	ip6h->daddr	  = *daddr;
+	ip6h->saddr	  = *saddr;
+
+	ip6tunnel_xmit(skb, dev);
+	return 0;
+}
+EXPORT_SYMBOL_GPL(udp_tunnel6_xmit_skb);
+
+MODULE_LICENSE("GPL");
diff -urN linux/net/ipv6/ipcomp6.c net-next-2.6/net/ipv6/ipcomp6.c
--- linux/net/ipv6/ipcomp6.c	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/ipcomp6.c	2014-10-06 10:49:00.756905813 +0200
@@ -181,8 +181,7 @@
 	return 0;
 }
 
-static const struct xfrm_type ipcomp6_type =
-{
+static const struct xfrm_type ipcomp6_type = {
 	.description	= "IPCOMP6",
 	.owner		= THIS_MODULE,
 	.proto		= IPPROTO_COMP,
@@ -193,8 +192,7 @@
 	.hdr_offset	= xfrm6_find_1stfragopt,
 };
 
-static struct xfrm6_protocol ipcomp6_protocol =
-{
+static struct xfrm6_protocol ipcomp6_protocol = {
 	.handler	= xfrm6_rcv,
 	.cb_handler	= ipcomp6_rcv_cb,
 	.err_handler	= ipcomp6_err,
diff -urN linux/net/ipv6/ipv6_sockglue.c net-next-2.6/net/ipv6/ipv6_sockglue.c
--- linux/net/ipv6/ipv6_sockglue.c	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/ipv6_sockglue.c	2014-10-06 10:49:00.760905853 +0200
@@ -66,12 +66,12 @@
 	if (sk->sk_type != SOCK_RAW || inet_sk(sk)->inet_num != IPPROTO_RAW)
 		return -ENOPROTOOPT;
 
-	new_ra = (sel>=0) ? kmalloc(sizeof(*new_ra), GFP_KERNEL) : NULL;
+	new_ra = (sel >= 0) ? kmalloc(sizeof(*new_ra), GFP_KERNEL) : NULL;
 
 	write_lock_bh(&ip6_ra_lock);
-	for (rap = &ip6_ra_chain; (ra=*rap) != NULL; rap = &ra->next) {
+	for (rap = &ip6_ra_chain; (ra = *rap) != NULL; rap = &ra->next) {
 		if (ra->sk == sk) {
-			if (sel>=0) {
+			if (sel >= 0) {
 				write_unlock_bh(&ip6_ra_lock);
 				kfree(new_ra);
 				return -EADDRINUSE;
@@ -130,7 +130,7 @@
 	int retv = -ENOPROTOOPT;
 
 	if (optval == NULL)
-		val=0;
+		val = 0;
 	else {
 		if (optlen >= sizeof(int)) {
 			if (get_user(val, (int __user *) optval))
@@ -139,7 +139,7 @@
 			val = 0;
 	}
 
-	valbool = (val!=0);
+	valbool = (val != 0);
 
 	if (ip6_mroute_opt(optname))
 		return ip6_mroute_setsockopt(sk, optname, optval, optlen);
@@ -474,7 +474,7 @@
 			goto done;
 
 		msg.msg_controllen = optlen;
-		msg.msg_control = (void*)(opt+1);
+		msg.msg_control = (void *)(opt+1);
 
 		retv = ip6_datagram_send_ctl(net, sk, &msg, &fl6, opt, &junk,
 					     &junk, &junk);
@@ -687,7 +687,7 @@
 			retv = -ENOBUFS;
 			break;
 		}
-		gsf = kmalloc(optlen,GFP_KERNEL);
+		gsf = kmalloc(optlen, GFP_KERNEL);
 		if (!gsf) {
 			retv = -ENOBUFS;
 			break;
@@ -873,7 +873,6 @@
 #endif
 	return err;
 }
-
 EXPORT_SYMBOL(ipv6_setsockopt);
 
 #ifdef CONFIG_COMPAT
@@ -909,7 +908,6 @@
 #endif
 	return err;
 }
-
 EXPORT_SYMBOL(compat_ipv6_setsockopt);
 #endif
 
@@ -921,7 +919,7 @@
 	if (!opt)
 		return 0;
 
-	switch(optname) {
+	switch (optname) {
 	case IPV6_HOPOPTS:
 		hdr = opt->hopopt;
 		break;
@@ -1284,9 +1282,9 @@
 		return -ENOPROTOOPT;
 	}
 	len = min_t(unsigned int, sizeof(int), len);
-	if(put_user(len, optlen))
+	if (put_user(len, optlen))
 		return -EFAULT;
-	if(copy_to_user(optval,&val,len))
+	if (copy_to_user(optval, &val, len))
 		return -EFAULT;
 	return 0;
 }
@@ -1299,7 +1297,7 @@
 	if (level == SOL_IP && sk->sk_type != SOCK_RAW)
 		return udp_prot.getsockopt(sk, level, optname, optval, optlen);
 
-	if(level != SOL_IPV6)
+	if (level != SOL_IPV6)
 		return -ENOPROTOOPT;
 
 	err = do_ipv6_getsockopt(sk, level, optname, optval, optlen, 0);
@@ -1321,7 +1319,6 @@
 #endif
 	return err;
 }
-
 EXPORT_SYMBOL(ipv6_getsockopt);
 
 #ifdef CONFIG_COMPAT
@@ -1364,7 +1361,6 @@
 #endif
 	return err;
 }
-
 EXPORT_SYMBOL(compat_ipv6_getsockopt);
 #endif
 
diff -urN linux/net/ipv6/Makefile net-next-2.6/net/ipv6/Makefile
--- linux/net/ipv6/Makefile	2014-09-24 09:52:43.180644375 +0200
+++ net-next-2.6/net/ipv6/Makefile	2014-10-06 10:49:00.712905364 +0200
@@ -45,3 +45,7 @@
 obj-$(CONFIG_INET) += output_core.o protocol.o $(ipv6-offload)
 
 obj-$(subst m,y,$(CONFIG_IPV6)) += inet6_hashtables.o
+
+ifneq ($(CONFIG_IPV6),)
+obj-$(CONFIG_NET_UDP_TUNNEL) += ip6_udp_tunnel.o
+endif
diff -urN linux/net/ipv6/mcast.c net-next-2.6/net/ipv6/mcast.c
--- linux/net/ipv6/mcast.c	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/mcast.c	2014-10-06 10:49:00.760905853 +0200
@@ -64,15 +64,6 @@
 
 #include <net/ip6_checksum.h>
 
-/* Set to 3 to get tracing... */
-#define MCAST_DEBUG 2
-
-#if MCAST_DEBUG >= 3
-#define MDBG(x) printk x
-#else
-#define MDBG(x)
-#endif
-
 /* Ensure that we have struct in6_addr aligned on 32bit word. */
 static void *__mld2_query_bugs[] __attribute__((__unused__)) = {
 	BUILD_BUG_ON_NULL(offsetof(struct mld2_query, mld2q_srcs) % 4),
@@ -82,9 +73,6 @@
 
 static struct in6_addr mld2_all_mcr = MLD2_ALL_MCR_INIT;
 
-/* Big mc list lock for all the sockets */
-static DEFINE_SPINLOCK(ipv6_sk_mc_lock);
-
 static void igmp6_join_group(struct ifmcaddr6 *ma);
 static void igmp6_leave_group(struct ifmcaddr6 *ma);
 static void igmp6_timer_handler(unsigned long data);
@@ -121,6 +109,7 @@
 #define IPV6_MLD_MAX_MSF	64
 
 int sysctl_mld_max_msf __read_mostly = IPV6_MLD_MAX_MSF;
+int sysctl_mld_qrv __read_mostly = MLD_QRV_DEFAULT;
 
 /*
  *	socket join on multicast group
@@ -173,7 +162,6 @@
 	mc_lst->addr = *addr;
 
 	rtnl_lock();
-	rcu_read_lock();
 	if (ifindex == 0) {
 		struct rt6_info *rt;
 		rt = rt6_lookup(net, addr, NULL, 0, 0);
@@ -182,10 +170,9 @@
 			ip6_rt_put(rt);
 		}
 	} else
-		dev = dev_get_by_index_rcu(net, ifindex);
+		dev = __dev_get_by_index(net, ifindex);
 
 	if (dev == NULL) {
-		rcu_read_unlock();
 		rtnl_unlock();
 		sock_kfree_s(sk, mc_lst, sizeof(*mc_lst));
 		return -ENODEV;
@@ -203,18 +190,14 @@
 	err = ipv6_dev_mc_inc(dev, addr);
 
 	if (err) {
-		rcu_read_unlock();
 		rtnl_unlock();
 		sock_kfree_s(sk, mc_lst, sizeof(*mc_lst));
 		return err;
 	}
 
-	spin_lock(&ipv6_sk_mc_lock);
 	mc_lst->next = np->ipv6_mc_list;
 	rcu_assign_pointer(np->ipv6_mc_list, mc_lst);
-	spin_unlock(&ipv6_sk_mc_lock);
 
-	rcu_read_unlock();
 	rtnl_unlock();
 
 	return 0;
@@ -234,20 +217,16 @@
 		return -EINVAL;
 
 	rtnl_lock();
-	spin_lock(&ipv6_sk_mc_lock);
 	for (lnk = &np->ipv6_mc_list;
-	     (mc_lst = rcu_dereference_protected(*lnk,
-			lockdep_is_held(&ipv6_sk_mc_lock))) !=NULL ;
+	     (mc_lst = rtnl_dereference(*lnk)) != NULL;
 	      lnk = &mc_lst->next) {
 		if ((ifindex == 0 || mc_lst->ifindex == ifindex) &&
 		    ipv6_addr_equal(&mc_lst->addr, addr)) {
 			struct net_device *dev;
 
 			*lnk = mc_lst->next;
-			spin_unlock(&ipv6_sk_mc_lock);
 
-			rcu_read_lock();
-			dev = dev_get_by_index_rcu(net, mc_lst->ifindex);
+			dev = __dev_get_by_index(net, mc_lst->ifindex);
 			if (dev != NULL) {
 				struct inet6_dev *idev = __in6_dev_get(dev);
 
@@ -256,7 +235,6 @@
 					__ipv6_dev_mc_dec(idev, &mc_lst->addr);
 			} else
 				(void) ip6_mc_leave_src(sk, mc_lst, NULL);
-			rcu_read_unlock();
 			rtnl_unlock();
 
 			atomic_sub(sizeof(*mc_lst), &sk->sk_omem_alloc);
@@ -264,7 +242,6 @@
 			return 0;
 		}
 	}
-	spin_unlock(&ipv6_sk_mc_lock);
 	rtnl_unlock();
 
 	return -EADDRNOTAVAIL;
@@ -311,16 +288,12 @@
 		return;
 
 	rtnl_lock();
-	spin_lock(&ipv6_sk_mc_lock);
-	while ((mc_lst = rcu_dereference_protected(np->ipv6_mc_list,
-				lockdep_is_held(&ipv6_sk_mc_lock))) != NULL) {
+	while ((mc_lst = rtnl_dereference(np->ipv6_mc_list)) != NULL) {
 		struct net_device *dev;
 
 		np->ipv6_mc_list = mc_lst->next;
-		spin_unlock(&ipv6_sk_mc_lock);
 
-		rcu_read_lock();
-		dev = dev_get_by_index_rcu(net, mc_lst->ifindex);
+		dev = __dev_get_by_index(net, mc_lst->ifindex);
 		if (dev) {
 			struct inet6_dev *idev = __in6_dev_get(dev);
 
@@ -329,14 +302,11 @@
 				__ipv6_dev_mc_dec(idev, &mc_lst->addr);
 		} else
 			(void) ip6_mc_leave_src(sk, mc_lst, NULL);
-		rcu_read_unlock();
 
 		atomic_sub(sizeof(*mc_lst), &sk->sk_omem_alloc);
 		kfree_rcu(mc_lst, rcu);
 
-		spin_lock(&ipv6_sk_mc_lock);
 	}
-	spin_unlock(&ipv6_sk_mc_lock);
 	rtnl_unlock();
 }
 
@@ -400,7 +370,7 @@
 		if (!psl)
 			goto done;	/* err = -EADDRNOTAVAIL */
 		rv = !0;
-		for (i=0; i<psl->sl_count; i++) {
+		for (i = 0; i < psl->sl_count; i++) {
 			rv = !ipv6_addr_equal(&psl->sl_addr[i], source);
 			if (rv == 0)
 				break;
@@ -417,7 +387,7 @@
 		/* update the interface filter */
 		ip6_mc_del_src(idev, group, omode, 1, source, 1);
 
-		for (j=i+1; j<psl->sl_count; j++)
+		for (j = i+1; j < psl->sl_count; j++)
 			psl->sl_addr[j-1] = psl->sl_addr[j];
 		psl->sl_count--;
 		err = 0;
@@ -443,19 +413,19 @@
 		newpsl->sl_max = count;
 		newpsl->sl_count = count - IP6_SFBLOCK;
 		if (psl) {
-			for (i=0; i<psl->sl_count; i++)
+			for (i = 0; i < psl->sl_count; i++)
 				newpsl->sl_addr[i] = psl->sl_addr[i];
 			sock_kfree_s(sk, psl, IP6_SFLSIZE(psl->sl_max));
 		}
 		pmc->sflist = psl = newpsl;
 	}
 	rv = 1;	/* > 0 for insert logic below if sl_count is 0 */
-	for (i=0; i<psl->sl_count; i++) {
+	for (i = 0; i < psl->sl_count; i++) {
 		rv = !ipv6_addr_equal(&psl->sl_addr[i], source);
 		if (rv == 0) /* There is an error in the address. */
 			goto done;
 	}
-	for (j=psl->sl_count-1; j>=i; j--)
+	for (j = psl->sl_count-1; j >= i; j--)
 		psl->sl_addr[j+1] = psl->sl_addr[j];
 	psl->sl_addr[i] = *source;
 	psl->sl_count++;
@@ -524,7 +494,7 @@
 			goto done;
 		}
 		newpsl->sl_max = newpsl->sl_count = gsf->gf_numsrc;
-		for (i=0; i<newpsl->sl_count; ++i) {
+		for (i = 0; i < newpsl->sl_count; ++i) {
 			struct sockaddr_in6 *psin6;
 
 			psin6 = (struct sockaddr_in6 *)&gsf->gf_slist[i];
@@ -586,9 +556,8 @@
 	}
 
 	err = -EADDRNOTAVAIL;
-	/*
-	 * changes to the ipv6_mc_list require the socket lock and
-	 * a read lock on ip6_sk_mc_lock. We have the socket lock,
+	/* changes to the ipv6_mc_list require the socket lock and
+	 * rtnl lock. We have the socket lock and rcu read lock,
 	 * so reading the list is safe.
 	 */
 
@@ -612,11 +581,10 @@
 	    copy_to_user(optval, gsf, GROUP_FILTER_SIZE(0))) {
 		return -EFAULT;
 	}
-	/* changes to psl require the socket lock, a read lock on
-	 * on ipv6_sk_mc_lock and a write lock on pmc->sflock. We
-	 * have the socket lock, so reading here is safe.
+	/* changes to psl require the socket lock, and a write lock
+	 * on pmc->sflock. We have the socket lock so reading here is safe.
 	 */
-	for (i=0; i<copycount; i++) {
+	for (i = 0; i < copycount; i++) {
 		struct sockaddr_in6 *psin6;
 		struct sockaddr_storage ss;
 
@@ -658,7 +626,7 @@
 	} else {
 		int i;
 
-		for (i=0; i<psl->sl_count; i++) {
+		for (i = 0; i < psl->sl_count; i++) {
 			if (ipv6_addr_equal(&psl->sl_addr[i], src_addr))
 				break;
 		}
@@ -673,14 +641,6 @@
 	return rv;
 }
 
-static void ma_put(struct ifmcaddr6 *mc)
-{
-	if (atomic_dec_and_test(&mc->mca_refcnt)) {
-		in6_dev_put(mc->idev);
-		kfree(mc);
-	}
-}
-
 static void igmp6_group_added(struct ifmcaddr6 *mc)
 {
 	struct net_device *dev = mc->idev->dev;
@@ -772,7 +732,7 @@
 		pmc->mca_tomb = im->mca_tomb;
 		pmc->mca_sources = im->mca_sources;
 		im->mca_tomb = im->mca_sources = NULL;
-		for (psf=pmc->mca_sources; psf; psf=psf->sf_next)
+		for (psf = pmc->mca_sources; psf; psf = psf->sf_next)
 			psf->sf_crcount = pmc->mca_crcount;
 	}
 	spin_unlock_bh(&im->mca_lock);
@@ -790,7 +750,7 @@
 
 	spin_lock_bh(&idev->mc_lock);
 	pmc_prev = NULL;
-	for (pmc=idev->mc_tomb; pmc; pmc=pmc->next) {
+	for (pmc = idev->mc_tomb; pmc; pmc = pmc->next) {
 		if (ipv6_addr_equal(&pmc->mca_addr, pmca))
 			break;
 		pmc_prev = pmc;
@@ -804,7 +764,7 @@
 	spin_unlock_bh(&idev->mc_lock);
 
 	if (pmc) {
-		for (psf=pmc->mca_tomb; psf; psf=psf_next) {
+		for (psf = pmc->mca_tomb; psf; psf = psf_next) {
 			psf_next = psf->sf_next;
 			kfree(psf);
 		}
@@ -831,14 +791,14 @@
 
 	/* clear dead sources, too */
 	read_lock_bh(&idev->lock);
-	for (pmc=idev->mc_list; pmc; pmc=pmc->next) {
+	for (pmc = idev->mc_list; pmc; pmc = pmc->next) {
 		struct ip6_sf_list *psf, *psf_next;
 
 		spin_lock_bh(&pmc->mca_lock);
 		psf = pmc->mca_tomb;
 		pmc->mca_tomb = NULL;
 		spin_unlock_bh(&pmc->mca_lock);
-		for (; psf; psf=psf_next) {
+		for (; psf; psf = psf_next) {
 			psf_next = psf->sf_next;
 			kfree(psf);
 		}
@@ -846,6 +806,48 @@
 	read_unlock_bh(&idev->lock);
 }
 
+static void mca_get(struct ifmcaddr6 *mc)
+{
+	atomic_inc(&mc->mca_refcnt);
+}
+
+static void ma_put(struct ifmcaddr6 *mc)
+{
+	if (atomic_dec_and_test(&mc->mca_refcnt)) {
+		in6_dev_put(mc->idev);
+		kfree(mc);
+	}
+}
+
+static struct ifmcaddr6 *mca_alloc(struct inet6_dev *idev,
+				   const struct in6_addr *addr)
+{
+	struct ifmcaddr6 *mc;
+
+	mc = kzalloc(sizeof(*mc), GFP_ATOMIC);
+	if (mc == NULL)
+		return NULL;
+
+	setup_timer(&mc->mca_timer, igmp6_timer_handler, (unsigned long)mc);
+
+	mc->mca_addr = *addr;
+	mc->idev = idev; /* reference taken by caller */
+	mc->mca_users = 1;
+	/* mca_stamp should be updated upon changes */
+	mc->mca_cstamp = mc->mca_tstamp = jiffies;
+	atomic_set(&mc->mca_refcnt, 1);
+	spin_lock_init(&mc->mca_lock);
+
+	/* initial mode is (EX, empty) */
+	mc->mca_sfmode = MCAST_EXCLUDE;
+	mc->mca_sfcount[MCAST_EXCLUDE] = 1;
+
+	if (ipv6_addr_is_ll_all_nodes(&mc->mca_addr) ||
+	    IPV6_ADDR_MC_SCOPE(&mc->mca_addr) < IPV6_ADDR_SCOPE_LINKLOCAL)
+		mc->mca_flags |= MAF_NOREPORT;
+
+	return mc;
+}
 
 /*
  *	device multicast group inc (add if not found)
@@ -881,38 +883,20 @@
 		}
 	}
 
-	/*
-	 *	not found: create a new one.
-	 */
-
-	mc = kzalloc(sizeof(struct ifmcaddr6), GFP_ATOMIC);
-
-	if (mc == NULL) {
+	mc = mca_alloc(idev, addr);
+	if (!mc) {
 		write_unlock_bh(&idev->lock);
 		in6_dev_put(idev);
 		return -ENOMEM;
 	}
 
-	setup_timer(&mc->mca_timer, igmp6_timer_handler, (unsigned long)mc);
-
-	mc->mca_addr = *addr;
-	mc->idev = idev; /* (reference taken) */
-	mc->mca_users = 1;
-	/* mca_stamp should be updated upon changes */
-	mc->mca_cstamp = mc->mca_tstamp = jiffies;
-	atomic_set(&mc->mca_refcnt, 2);
-	spin_lock_init(&mc->mca_lock);
-
-	/* initial mode is (EX, empty) */
-	mc->mca_sfmode = MCAST_EXCLUDE;
-	mc->mca_sfcount[MCAST_EXCLUDE] = 1;
-
-	if (ipv6_addr_is_ll_all_nodes(&mc->mca_addr) ||
-	    IPV6_ADDR_MC_SCOPE(&mc->mca_addr) < IPV6_ADDR_SCOPE_LINKLOCAL)
-		mc->mca_flags |= MAF_NOREPORT;
-
 	mc->next = idev->mc_list;
 	idev->mc_list = mc;
+
+	/* Hold this for the code below before we unlock,
+	 * it is already exposed via idev->mc_list.
+	 */
+	mca_get(mc);
 	write_unlock_bh(&idev->lock);
 
 	mld_del_delrec(idev, &mc->mca_addr);
@@ -931,7 +915,7 @@
 	ASSERT_RTNL();
 
 	write_lock_bh(&idev->lock);
-	for (map = &idev->mc_list; (ma=*map) != NULL; map = &ma->next) {
+	for (map = &idev->mc_list; (ma = *map) != NULL; map = &ma->next) {
 		if (ipv6_addr_equal(&ma->mca_addr, addr)) {
 			if (--ma->mca_users == 0) {
 				*map = ma->next;
@@ -956,7 +940,7 @@
 	struct inet6_dev *idev;
 	int err;
 
-	rcu_read_lock();
+	ASSERT_RTNL();
 
 	idev = __in6_dev_get(dev);
 	if (!idev)
@@ -964,7 +948,6 @@
 	else
 		err = __ipv6_dev_mc_dec(idev, addr);
 
-	rcu_read_unlock();
 	return err;
 }
 
@@ -982,7 +965,7 @@
 	idev = __in6_dev_get(dev);
 	if (idev) {
 		read_lock_bh(&idev->lock);
-		for (mc = idev->mc_list; mc; mc=mc->next) {
+		for (mc = idev->mc_list; mc; mc = mc->next) {
 			if (ipv6_addr_equal(&mc->mca_addr, group))
 				break;
 		}
@@ -991,7 +974,7 @@
 				struct ip6_sf_list *psf;
 
 				spin_lock_bh(&mc->mca_lock);
-				for (psf=mc->mca_sources;psf;psf=psf->sf_next) {
+				for (psf = mc->mca_sources; psf; psf = psf->sf_next) {
 					if (ipv6_addr_equal(&psf->sf_addr, src_addr))
 						break;
 				}
@@ -1000,7 +983,7 @@
 						psf->sf_count[MCAST_EXCLUDE] !=
 						mc->mca_sfcount[MCAST_EXCLUDE];
 				else
-					rv = mc->mca_sfcount[MCAST_EXCLUDE] !=0;
+					rv = mc->mca_sfcount[MCAST_EXCLUDE] != 0;
 				spin_unlock_bh(&mc->mca_lock);
 			} else
 				rv = true; /* don't filter unspecified source */
@@ -1091,10 +1074,10 @@
 	int i, scount;
 
 	scount = 0;
-	for (psf=pmc->mca_sources; psf; psf=psf->sf_next) {
+	for (psf = pmc->mca_sources; psf; psf = psf->sf_next) {
 		if (scount == nsrcs)
 			break;
-		for (i=0; i<nsrcs; i++) {
+		for (i = 0; i < nsrcs; i++) {
 			/* skip inactive filters */
 			if (psf->sf_count[MCAST_INCLUDE] ||
 			    pmc->mca_sfcount[MCAST_EXCLUDE] !=
@@ -1124,10 +1107,10 @@
 	/* mark INCLUDE-mode sources */
 
 	scount = 0;
-	for (psf=pmc->mca_sources; psf; psf=psf->sf_next) {
+	for (psf = pmc->mca_sources; psf; psf = psf->sf_next) {
 		if (scount == nsrcs)
 			break;
-		for (i=0; i<nsrcs; i++) {
+		for (i = 0; i < nsrcs; i++) {
 			if (ipv6_addr_equal(&srcs[i], &psf->sf_addr)) {
 				psf->sf_gsresp = 1;
 				scount++;
@@ -1205,15 +1188,16 @@
 	 * and SHOULD NOT be one. Catch this here if we ever run
 	 * into such a case in future.
 	 */
+	const int min_qrv = min(MLD_QRV_DEFAULT, sysctl_mld_qrv);
 	WARN_ON(idev->mc_qrv == 0);
 
 	if (mlh2->mld2q_qrv > 0)
 		idev->mc_qrv = mlh2->mld2q_qrv;
 
-	if (unlikely(idev->mc_qrv < 2)) {
+	if (unlikely(idev->mc_qrv < min_qrv)) {
 		net_warn_ratelimited("IPv6: MLD: clamping QRV from %u to %u!\n",
-				     idev->mc_qrv, MLD_QRV_DEFAULT);
-		idev->mc_qrv = MLD_QRV_DEFAULT;
+				     idev->mc_qrv, min_qrv);
+		idev->mc_qrv = min_qrv;
 	}
 }
 
@@ -1253,7 +1237,7 @@
 }
 
 static int mld_process_v1(struct inet6_dev *idev, struct mld_msg *mld,
-			  unsigned long *max_delay)
+			  unsigned long *max_delay, bool v1_query)
 {
 	unsigned long mldv1_md;
 
@@ -1261,11 +1245,32 @@
 	if (mld_in_v2_mode_only(idev))
 		return -EINVAL;
 
-	/* MLDv1 router present */
 	mldv1_md = ntohs(mld->mld_maxdelay);
+
+	/* When in MLDv1 fallback and a MLDv2 router start-up being
+	 * unaware of current MLDv1 operation, the MRC == MRD mapping
+	 * only works when the exponential algorithm is not being
+	 * used (as MLDv1 is unaware of such things).
+	 *
+	 * According to the RFC author, the MLDv2 implementations
+	 * he's aware of all use a MRC < 32768 on start up queries.
+	 *
+	 * Thus, should we *ever* encounter something else larger
+	 * than that, just assume the maximum possible within our
+	 * reach.
+	 */
+	if (!v1_query)
+		mldv1_md = min(mldv1_md, MLDV1_MRD_MAX_COMPAT);
+
 	*max_delay = max(msecs_to_jiffies(mldv1_md), 1UL);
 
-	mld_set_v1_mode(idev);
+	/* MLDv1 router present: we need to go into v1 mode *only*
+	 * when an MLDv1 query is received as per section 9.12. of
+	 * RFC3810! And we know from RFC2710 section 3.7 that MLDv1
+	 * queries MUST be of exactly 24 octets.
+	 */
+	if (v1_query)
+		mld_set_v1_mode(idev);
 
 	/* cancel MLDv2 report timer */
 	mld_gq_stop_timer(idev);
@@ -1280,10 +1285,6 @@
 static int mld_process_v2(struct inet6_dev *idev, struct mld2_query *mld,
 			  unsigned long *max_delay)
 {
-	/* hosts need to stay in MLDv1 mode, discard MLDv2 queries */
-	if (mld_in_v1_mode(idev))
-		return -EINVAL;
-
 	*max_delay = max(msecs_to_jiffies(mldv2_mrc(mld)), 1UL);
 
 	mld_update_qrv(idev, mld);
@@ -1340,8 +1341,11 @@
 	    !(group_type&IPV6_ADDR_MULTICAST))
 		return -EINVAL;
 
-	if (len == MLD_V1_QUERY_LEN) {
-		err = mld_process_v1(idev, mld, &max_delay);
+	if (len < MLD_V1_QUERY_LEN) {
+		return -EINVAL;
+	} else if (len == MLD_V1_QUERY_LEN || mld_in_v1_mode(idev)) {
+		err = mld_process_v1(idev, mld, &max_delay,
+				     len == MLD_V1_QUERY_LEN);
 		if (err < 0)
 			return err;
 	} else if (len >= MLD_V2_QUERY_LEN_MIN) {
@@ -1373,18 +1377,19 @@
 			mlh2 = (struct mld2_query *)skb_transport_header(skb);
 			mark = 1;
 		}
-	} else
+	} else {
 		return -EINVAL;
+	}
 
 	read_lock_bh(&idev->lock);
 	if (group_type == IPV6_ADDR_ANY) {
-		for (ma = idev->mc_list; ma; ma=ma->next) {
+		for (ma = idev->mc_list; ma; ma = ma->next) {
 			spin_lock_bh(&ma->mca_lock);
 			igmp6_group_queried(ma, max_delay);
 			spin_unlock_bh(&ma->mca_lock);
 		}
 	} else {
-		for (ma = idev->mc_list; ma; ma=ma->next) {
+		for (ma = idev->mc_list; ma; ma = ma->next) {
 			if (!ipv6_addr_equal(group, &ma->mca_addr))
 				continue;
 			spin_lock_bh(&ma->mca_lock);
@@ -1448,7 +1453,7 @@
 	 */
 
 	read_lock_bh(&idev->lock);
-	for (ma = idev->mc_list; ma; ma=ma->next) {
+	for (ma = idev->mc_list; ma; ma = ma->next) {
 		if (ipv6_addr_equal(&ma->mca_addr, &mld->mld_mca)) {
 			spin_lock(&ma->mca_lock);
 			if (del_timer(&ma->mca_timer))
@@ -1512,7 +1517,7 @@
 	struct ip6_sf_list *psf;
 	int scount = 0;
 
-	for (psf=pmc->mca_sources; psf; psf=psf->sf_next) {
+	for (psf = pmc->mca_sources; psf; psf = psf->sf_next) {
 		if (!is_in(pmc, psf, type, gdeleted, sdeleted))
 			continue;
 		scount++;
@@ -1726,7 +1731,7 @@
 	}
 	first = 1;
 	psf_prev = NULL;
-	for (psf=*psf_list; psf; psf=psf_next) {
+	for (psf = *psf_list; psf; psf = psf_next) {
 		struct in6_addr *psrc;
 
 		psf_next = psf->sf_next;
@@ -1805,7 +1810,7 @@
 
 	read_lock_bh(&idev->lock);
 	if (!pmc) {
-		for (pmc=idev->mc_list; pmc; pmc=pmc->next) {
+		for (pmc = idev->mc_list; pmc; pmc = pmc->next) {
 			if (pmc->mca_flags & MAF_NOREPORT)
 				continue;
 			spin_lock_bh(&pmc->mca_lock);
@@ -1838,7 +1843,7 @@
 	struct ip6_sf_list *psf_prev, *psf_next, *psf;
 
 	psf_prev = NULL;
-	for (psf=*ppsf; psf; psf = psf_next) {
+	for (psf = *ppsf; psf; psf = psf_next) {
 		psf_next = psf->sf_next;
 		if (psf->sf_crcount == 0) {
 			if (psf_prev)
@@ -1862,7 +1867,7 @@
 
 	/* deleted MCA's */
 	pmc_prev = NULL;
-	for (pmc=idev->mc_tomb; pmc; pmc=pmc_next) {
+	for (pmc = idev->mc_tomb; pmc; pmc = pmc_next) {
 		pmc_next = pmc->next;
 		if (pmc->mca_sfmode == MCAST_INCLUDE) {
 			type = MLD2_BLOCK_OLD_SOURCES;
@@ -1895,7 +1900,7 @@
 	spin_unlock(&idev->mc_lock);
 
 	/* change recs */
-	for (pmc=idev->mc_list; pmc; pmc=pmc->next) {
+	for (pmc = idev->mc_list; pmc; pmc = pmc->next) {
 		spin_lock_bh(&pmc->mca_lock);
 		if (pmc->mca_sfcount[MCAST_EXCLUDE]) {
 			type = MLD2_BLOCK_OLD_SOURCES;
@@ -2032,7 +2037,7 @@
 
 	skb = NULL;
 	read_lock_bh(&idev->lock);
-	for (pmc=idev->mc_list; pmc; pmc=pmc->next) {
+	for (pmc = idev->mc_list; pmc; pmc = pmc->next) {
 		spin_lock_bh(&pmc->mca_lock);
 		if (pmc->mca_sfcount[MCAST_EXCLUDE])
 			type = MLD2_CHANGE_TO_EXCLUDE;
@@ -2077,7 +2082,7 @@
 	int rv = 0;
 
 	psf_prev = NULL;
-	for (psf=pmc->mca_sources; psf; psf=psf->sf_next) {
+	for (psf = pmc->mca_sources; psf; psf = psf->sf_next) {
 		if (ipv6_addr_equal(&psf->sf_addr, psfsrc))
 			break;
 		psf_prev = psf;
@@ -2118,7 +2123,7 @@
 	if (!idev)
 		return -ENODEV;
 	read_lock_bh(&idev->lock);
-	for (pmc=idev->mc_list; pmc; pmc=pmc->next) {
+	for (pmc = idev->mc_list; pmc; pmc = pmc->next) {
 		if (ipv6_addr_equal(pmca, &pmc->mca_addr))
 			break;
 	}
@@ -2138,7 +2143,7 @@
 		pmc->mca_sfcount[sfmode]--;
 	}
 	err = 0;
-	for (i=0; i<sfcount; i++) {
+	for (i = 0; i < sfcount; i++) {
 		int rv = ip6_mc_del1_src(pmc, sfmode, &psfsrc[i]);
 
 		changerec |= rv > 0;
@@ -2154,7 +2159,7 @@
 		pmc->mca_sfmode = MCAST_INCLUDE;
 		pmc->mca_crcount = idev->mc_qrv;
 		idev->mc_ifc_count = pmc->mca_crcount;
-		for (psf=pmc->mca_sources; psf; psf = psf->sf_next)
+		for (psf = pmc->mca_sources; psf; psf = psf->sf_next)
 			psf->sf_crcount = 0;
 		mld_ifc_event(pmc->idev);
 	} else if (sf_setstate(pmc) || changerec)
@@ -2173,7 +2178,7 @@
 	struct ip6_sf_list *psf, *psf_prev;
 
 	psf_prev = NULL;
-	for (psf=pmc->mca_sources; psf; psf=psf->sf_next) {
+	for (psf = pmc->mca_sources; psf; psf = psf->sf_next) {
 		if (ipv6_addr_equal(&psf->sf_addr, psfsrc))
 			break;
 		psf_prev = psf;
@@ -2198,7 +2203,7 @@
 	struct ip6_sf_list *psf;
 	int mca_xcount = pmc->mca_sfcount[MCAST_EXCLUDE];
 
-	for (psf=pmc->mca_sources; psf; psf=psf->sf_next)
+	for (psf = pmc->mca_sources; psf; psf = psf->sf_next)
 		if (pmc->mca_sfcount[MCAST_EXCLUDE]) {
 			psf->sf_oldin = mca_xcount ==
 				psf->sf_count[MCAST_EXCLUDE] &&
@@ -2215,7 +2220,7 @@
 	int new_in, rv;
 
 	rv = 0;
-	for (psf=pmc->mca_sources; psf; psf=psf->sf_next) {
+	for (psf = pmc->mca_sources; psf; psf = psf->sf_next) {
 		if (pmc->mca_sfcount[MCAST_EXCLUDE]) {
 			new_in = mca_xcount == psf->sf_count[MCAST_EXCLUDE] &&
 				!psf->sf_count[MCAST_INCLUDE];
@@ -2225,8 +2230,8 @@
 			if (!psf->sf_oldin) {
 				struct ip6_sf_list *prev = NULL;
 
-				for (dpsf=pmc->mca_tomb; dpsf;
-				     dpsf=dpsf->sf_next) {
+				for (dpsf = pmc->mca_tomb; dpsf;
+				     dpsf = dpsf->sf_next) {
 					if (ipv6_addr_equal(&dpsf->sf_addr,
 					    &psf->sf_addr))
 						break;
@@ -2248,7 +2253,7 @@
 			 * add or update "delete" records if an active filter
 			 * is now inactive
 			 */
-			for (dpsf=pmc->mca_tomb; dpsf; dpsf=dpsf->sf_next)
+			for (dpsf = pmc->mca_tomb; dpsf; dpsf = dpsf->sf_next)
 				if (ipv6_addr_equal(&dpsf->sf_addr,
 				    &psf->sf_addr))
 					break;
@@ -2282,7 +2287,7 @@
 	if (!idev)
 		return -ENODEV;
 	read_lock_bh(&idev->lock);
-	for (pmc=idev->mc_list; pmc; pmc=pmc->next) {
+	for (pmc = idev->mc_list; pmc; pmc = pmc->next) {
 		if (ipv6_addr_equal(pmca, &pmc->mca_addr))
 			break;
 	}
@@ -2298,7 +2303,7 @@
 	if (!delta)
 		pmc->mca_sfcount[sfmode]++;
 	err = 0;
-	for (i=0; i<sfcount; i++) {
+	for (i = 0; i < sfcount; i++) {
 		err = ip6_mc_add1_src(pmc, sfmode, &psfsrc[i]);
 		if (err)
 			break;
@@ -2308,7 +2313,7 @@
 
 		if (!delta)
 			pmc->mca_sfcount[sfmode]--;
-		for (j=0; j<i; j++)
+		for (j = 0; j < i; j++)
 			ip6_mc_del1_src(pmc, sfmode, &psfsrc[j]);
 	} else if (isexclude != (pmc->mca_sfcount[MCAST_EXCLUDE] != 0)) {
 		struct ip6_sf_list *psf;
@@ -2322,7 +2327,7 @@
 
 		pmc->mca_crcount = idev->mc_qrv;
 		idev->mc_ifc_count = pmc->mca_crcount;
-		for (psf=pmc->mca_sources; psf; psf = psf->sf_next)
+		for (psf = pmc->mca_sources; psf; psf = psf->sf_next)
 			psf->sf_crcount = 0;
 		mld_ifc_event(idev);
 	} else if (sf_setstate(pmc))
@@ -2336,12 +2341,12 @@
 {
 	struct ip6_sf_list *psf, *nextpsf;
 
-	for (psf=pmc->mca_tomb; psf; psf=nextpsf) {
+	for (psf = pmc->mca_tomb; psf; psf = nextpsf) {
 		nextpsf = psf->sf_next;
 		kfree(psf);
 	}
 	pmc->mca_tomb = NULL;
-	for (psf=pmc->mca_sources; psf; psf=nextpsf) {
+	for (psf = pmc->mca_sources; psf; psf = nextpsf) {
 		nextpsf = psf->sf_next;
 		kfree(psf);
 	}
@@ -2380,7 +2385,7 @@
 {
 	int err;
 
-	/* callers have the socket lock and a write lock on ipv6_sk_mc_lock,
+	/* callers have the socket lock and rtnl lock
 	 * so no other readers or writers of iml or its sflist
 	 */
 	if (!iml->sflist) {
@@ -2485,13 +2490,21 @@
 	mld_gq_stop_timer(idev);
 	mld_dad_stop_timer(idev);
 
-	for (i = idev->mc_list; i; i=i->next)
+	for (i = idev->mc_list; i; i = i->next)
 		igmp6_group_dropped(i);
 	read_unlock_bh(&idev->lock);
 
 	mld_clear_delrec(idev);
 }
 
+static void ipv6_mc_reset(struct inet6_dev *idev)
+{
+	idev->mc_qrv = sysctl_mld_qrv;
+	idev->mc_qi = MLD_QI_DEFAULT;
+	idev->mc_qri = MLD_QRI_DEFAULT;
+	idev->mc_v1_seen = 0;
+	idev->mc_maxdelay = unsolicited_report_interval(idev);
+}
 
 /* Device going up */
 
@@ -2502,7 +2515,8 @@
 	/* Install multicast list, except for all-nodes (already installed) */
 
 	read_lock_bh(&idev->lock);
-	for (i = idev->mc_list; i; i=i->next)
+	ipv6_mc_reset(idev);
+	for (i = idev->mc_list; i; i = i->next)
 		igmp6_group_added(i);
 	read_unlock_bh(&idev->lock);
 }
@@ -2522,13 +2536,7 @@
 			(unsigned long)idev);
 	setup_timer(&idev->mc_dad_timer, mld_dad_timer_expire,
 		    (unsigned long)idev);
-
-	idev->mc_qrv = MLD_QRV_DEFAULT;
-	idev->mc_qi = MLD_QI_DEFAULT;
-	idev->mc_qri = MLD_QRI_DEFAULT;
-
-	idev->mc_maxdelay = unsolicited_report_interval(idev);
-	idev->mc_v1_seen = 0;
+	ipv6_mc_reset(idev);
 	write_unlock_bh(&idev->lock);
 }
 
diff -urN linux/net/ipv6/mip6.c net-next-2.6/net/ipv6/mip6.c
--- linux/net/ipv6/mip6.c	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/mip6.c	2014-10-06 10:49:00.760905853 +0200
@@ -336,11 +336,10 @@
 {
 }
 
-static const struct xfrm_type mip6_destopt_type =
-{
+static const struct xfrm_type mip6_destopt_type = {
 	.description	= "MIP6DESTOPT",
 	.owner		= THIS_MODULE,
-	.proto	     	= IPPROTO_DSTOPTS,
+	.proto		= IPPROTO_DSTOPTS,
 	.flags		= XFRM_TYPE_NON_FRAGMENT | XFRM_TYPE_LOCAL_COADDR,
 	.init_state	= mip6_destopt_init_state,
 	.destructor	= mip6_destopt_destroy,
@@ -469,11 +468,10 @@
 {
 }
 
-static const struct xfrm_type mip6_rthdr_type =
-{
+static const struct xfrm_type mip6_rthdr_type = {
 	.description	= "MIP6RT",
 	.owner		= THIS_MODULE,
-	.proto	     	= IPPROTO_ROUTING,
+	.proto		= IPPROTO_ROUTING,
 	.flags		= XFRM_TYPE_NON_FRAGMENT | XFRM_TYPE_REMOTE_COADDR,
 	.init_state	= mip6_rthdr_init_state,
 	.destructor	= mip6_rthdr_destroy,
diff -urN linux/net/ipv6/ndisc.c net-next-2.6/net/ipv6/ndisc.c
--- linux/net/ipv6/ndisc.c	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/ndisc.c	2014-10-06 10:49:01.020908504 +0200
@@ -175,7 +175,7 @@
 	type = cur->nd_opt_type;
 	do {
 		cur = ((void *)cur) + (cur->nd_opt_len << 3);
-	} while(cur < end && cur->nd_opt_type != type);
+	} while (cur < end && cur->nd_opt_type != type);
 	return cur <= end && cur->nd_opt_type == type ? cur : NULL;
 }
 
@@ -192,7 +192,7 @@
 		return NULL;
 	do {
 		cur = ((void *)cur) + (cur->nd_opt_len << 3);
-	} while(cur < end && !ndisc_is_useropt(cur));
+	} while (cur < end && !ndisc_is_useropt(cur));
 	return cur <= end && ndisc_is_useropt(cur) ? cur : NULL;
 }
 
@@ -284,7 +284,6 @@
 	}
 	return -EINVAL;
 }
-
 EXPORT_SYMBOL(ndisc_mc_map);
 
 static u32 ndisc_hash(const void *pkey,
@@ -296,7 +295,7 @@
 
 static int ndisc_constructor(struct neighbour *neigh)
 {
-	struct in6_addr *addr = (struct in6_addr*)&neigh->primary_key;
+	struct in6_addr *addr = (struct in6_addr *)&neigh->primary_key;
 	struct net_device *dev = neigh->dev;
 	struct inet6_dev *in6_dev;
 	struct neigh_parms *parms;
@@ -344,7 +343,7 @@
 
 static int pndisc_constructor(struct pneigh_entry *n)
 {
-	struct in6_addr *addr = (struct in6_addr*)&n->key;
+	struct in6_addr *addr = (struct in6_addr *)&n->key;
 	struct in6_addr maddr;
 	struct net_device *dev = n->dev;
 
@@ -357,7 +356,7 @@
 
 static void pndisc_destructor(struct pneigh_entry *n)
 {
-	struct in6_addr *addr = (struct in6_addr*)&n->key;
+	struct in6_addr *addr = (struct in6_addr *)&n->key;
 	struct in6_addr maddr;
 	struct net_device *dev = n->dev;
 
@@ -1065,7 +1064,7 @@
 	int optlen;
 	unsigned int pref = 0;
 
-	__u8 * opt = (__u8 *)(ra_msg + 1);
+	__u8 *opt = (__u8 *)(ra_msg + 1);
 
 	optlen = (skb_tail_pointer(skb) - skb_transport_header(skb)) -
 		sizeof(struct ra_msg);
@@ -1319,7 +1318,7 @@
 				continue;
 			if (ri->prefix_len > in6_dev->cnf.accept_ra_rt_info_max_plen)
 				continue;
-			rt6_route_rcv(skb->dev, (u8*)p, (p->nd_opt_len) << 3,
+			rt6_route_rcv(skb->dev, (u8 *)p, (p->nd_opt_len) << 3,
 				      &ipv6_hdr(skb)->saddr);
 		}
 	}
@@ -1352,7 +1351,7 @@
 		__be32 n;
 		u32 mtu;
 
-		memcpy(&n, ((u8*)(ndopts.nd_opts_mtu+1))+2, sizeof(mtu));
+		memcpy(&n, ((u8 *)(ndopts.nd_opts_mtu+1))+2, sizeof(mtu));
 		mtu = ntohl(n);
 
 		if (mtu < IPV6_MIN_MTU || mtu > skb->dev->mtu) {
diff -urN linux/net/ipv6/netfilter/ip6table_nat.c net-next-2.6/net/ipv6/netfilter/ip6table_nat.c
--- linux/net/ipv6/netfilter/ip6table_nat.c	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/netfilter/ip6table_nat.c	2014-10-06 10:49:01.368912051 +0200
@@ -30,222 +30,57 @@
 	.af		= NFPROTO_IPV6,
 };
 
-static unsigned int alloc_null_binding(struct nf_conn *ct, unsigned int hooknum)
-{
-	/* Force range to this IP; let proto decide mapping for
-	 * per-proto parts (hence not IP_NAT_RANGE_PROTO_SPECIFIED).
-	 */
-	struct nf_nat_range range;
-
-	range.flags = 0;
-	pr_debug("Allocating NULL binding for %p (%pI6)\n", ct,
-		 HOOK2MANIP(hooknum) == NF_NAT_MANIP_SRC ?
-		 &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip6 :
-		 &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip6);
-
-	return nf_nat_setup_info(ct, &range, HOOK2MANIP(hooknum));
-}
-
-static unsigned int nf_nat_rule_find(struct sk_buff *skb, unsigned int hooknum,
-				     const struct net_device *in,
-				     const struct net_device *out,
-				     struct nf_conn *ct)
+static unsigned int ip6table_nat_do_chain(const struct nf_hook_ops *ops,
+					  struct sk_buff *skb,
+					  const struct net_device *in,
+					  const struct net_device *out,
+					  struct nf_conn *ct)
 {
 	struct net *net = nf_ct_net(ct);
-	unsigned int ret;
 
-	ret = ip6t_do_table(skb, hooknum, in, out, net->ipv6.ip6table_nat);
-	if (ret == NF_ACCEPT) {
-		if (!nf_nat_initialized(ct, HOOK2MANIP(hooknum)))
-			ret = alloc_null_binding(ct, hooknum);
-	}
-	return ret;
+	return ip6t_do_table(skb, ops->hooknum, in, out, net->ipv6.ip6table_nat);
 }
 
-static unsigned int
-nf_nat_ipv6_fn(const struct nf_hook_ops *ops,
-	       struct sk_buff *skb,
-	       const struct net_device *in,
-	       const struct net_device *out,
-	       int (*okfn)(struct sk_buff *))
+static unsigned int ip6table_nat_fn(const struct nf_hook_ops *ops,
+				    struct sk_buff *skb,
+				    const struct net_device *in,
+				    const struct net_device *out,
+				    int (*okfn)(struct sk_buff *))
 {
-	struct nf_conn *ct;
-	enum ip_conntrack_info ctinfo;
-	struct nf_conn_nat *nat;
-	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);
-	__be16 frag_off;
-	int hdrlen;
-	u8 nexthdr;
-
-	ct = nf_ct_get(skb, &ctinfo);
-	/* Can't track?  It's not due to stress, or conntrack would
-	 * have dropped it.  Hence it's the user's responsibilty to
-	 * packet filter it out, or implement conntrack/NAT for that
-	 * protocol. 8) --RR
-	 */
-	if (!ct)
-		return NF_ACCEPT;
-
-	/* Don't try to NAT if this packet is not conntracked */
-	if (nf_ct_is_untracked(ct))
-		return NF_ACCEPT;
-
-	nat = nf_ct_nat_ext_add(ct);
-	if (nat == NULL)
-		return NF_ACCEPT;
-
-	switch (ctinfo) {
-	case IP_CT_RELATED:
-	case IP_CT_RELATED_REPLY:
-		nexthdr = ipv6_hdr(skb)->nexthdr;
-		hdrlen = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr),
-					  &nexthdr, &frag_off);
-
-		if (hdrlen >= 0 && nexthdr == IPPROTO_ICMPV6) {
-			if (!nf_nat_icmpv6_reply_translation(skb, ct, ctinfo,
-							     ops->hooknum,
-							     hdrlen))
-				return NF_DROP;
-			else
-				return NF_ACCEPT;
-		}
-		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
-	case IP_CT_NEW:
-		/* Seen it before?  This can happen for loopback, retrans,
-		 * or local packets.
-		 */
-		if (!nf_nat_initialized(ct, maniptype)) {
-			unsigned int ret;
-
-			ret = nf_nat_rule_find(skb, ops->hooknum, in, out, ct);
-			if (ret != NF_ACCEPT)
-				return ret;
-		} else {
-			pr_debug("Already setup manip %s for ct %p\n",
-				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
-				 ct);
-			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
-				goto oif_changed;
-		}
-		break;
-
-	default:
-		/* ESTABLISHED */
-		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||
-			     ctinfo == IP_CT_ESTABLISHED_REPLY);
-		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
-			goto oif_changed;
-	}
-
-	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);
-
-oif_changed:
-	nf_ct_kill_acct(ct, ctinfo, skb);
-	return NF_DROP;
+	return nf_nat_ipv6_fn(ops, skb, in, out, ip6table_nat_do_chain);
 }
 
-static unsigned int
-nf_nat_ipv6_in(const struct nf_hook_ops *ops,
-	       struct sk_buff *skb,
-	       const struct net_device *in,
-	       const struct net_device *out,
-	       int (*okfn)(struct sk_buff *))
+static unsigned int ip6table_nat_in(const struct nf_hook_ops *ops,
+				    struct sk_buff *skb,
+				    const struct net_device *in,
+				    const struct net_device *out,
+				    int (*okfn)(struct sk_buff *))
 {
-	unsigned int ret;
-	struct in6_addr daddr = ipv6_hdr(skb)->daddr;
-
-	ret = nf_nat_ipv6_fn(ops, skb, in, out, okfn);
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    ipv6_addr_cmp(&daddr, &ipv6_hdr(skb)->daddr))
-		skb_dst_drop(skb);
-
-	return ret;
+	return nf_nat_ipv6_in(ops, skb, in, out, ip6table_nat_do_chain);
 }
 
-static unsigned int
-nf_nat_ipv6_out(const struct nf_hook_ops *ops,
-		struct sk_buff *skb,
-		const struct net_device *in,
-		const struct net_device *out,
-		int (*okfn)(struct sk_buff *))
+static unsigned int ip6table_nat_out(const struct nf_hook_ops *ops,
+				     struct sk_buff *skb,
+				     const struct net_device *in,
+				     const struct net_device *out,
+				     int (*okfn)(struct sk_buff *))
 {
-#ifdef CONFIG_XFRM
-	const struct nf_conn *ct;
-	enum ip_conntrack_info ctinfo;
-	int err;
-#endif
-	unsigned int ret;
-
-	/* root is playing with raw sockets. */
-	if (skb->len < sizeof(struct ipv6hdr))
-		return NF_ACCEPT;
-
-	ret = nf_nat_ipv6_fn(ops, skb, in, out, okfn);
-#ifdef CONFIG_XFRM
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    !(IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) &&
-	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
-		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
-
-		if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.src.u3,
-				      &ct->tuplehash[!dir].tuple.dst.u3) ||
-		    (ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMPV6 &&
-		     ct->tuplehash[dir].tuple.src.u.all !=
-		     ct->tuplehash[!dir].tuple.dst.u.all)) {
-			err = nf_xfrm_me_harder(skb, AF_INET6);
-			if (err < 0)
-				ret = NF_DROP_ERR(err);
-		}
-	}
-#endif
-	return ret;
+	return nf_nat_ipv6_out(ops, skb, in, out, ip6table_nat_do_chain);
 }
 
-static unsigned int
-nf_nat_ipv6_local_fn(const struct nf_hook_ops *ops,
-		     struct sk_buff *skb,
-		     const struct net_device *in,
-		     const struct net_device *out,
-		     int (*okfn)(struct sk_buff *))
+static unsigned int ip6table_nat_local_fn(const struct nf_hook_ops *ops,
+					  struct sk_buff *skb,
+					  const struct net_device *in,
+					  const struct net_device *out,
+					  int (*okfn)(struct sk_buff *))
 {
-	const struct nf_conn *ct;
-	enum ip_conntrack_info ctinfo;
-	unsigned int ret;
-	int err;
-
-	/* root is playing with raw sockets. */
-	if (skb->len < sizeof(struct ipv6hdr))
-		return NF_ACCEPT;
-
-	ret = nf_nat_ipv6_fn(ops, skb, in, out, okfn);
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
-		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
-
-		if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.dst.u3,
-				      &ct->tuplehash[!dir].tuple.src.u3)) {
-			err = ip6_route_me_harder(skb);
-			if (err < 0)
-				ret = NF_DROP_ERR(err);
-		}
-#ifdef CONFIG_XFRM
-		else if (!(IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) &&
-			 ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMPV6 &&
-			 ct->tuplehash[dir].tuple.dst.u.all !=
-			 ct->tuplehash[!dir].tuple.src.u.all) {
-			err = nf_xfrm_me_harder(skb, AF_INET6);
-			if (err < 0)
-				ret = NF_DROP_ERR(err);
-		}
-#endif
-	}
-	return ret;
+	return nf_nat_ipv6_local_fn(ops, skb, in, out, ip6table_nat_do_chain);
 }
 
 static struct nf_hook_ops nf_nat_ipv6_ops[] __read_mostly = {
 	/* Before packet filtering, change destination */
 	{
-		.hook		= nf_nat_ipv6_in,
+		.hook		= ip6table_nat_in,
 		.owner		= THIS_MODULE,
 		.pf		= NFPROTO_IPV6,
 		.hooknum	= NF_INET_PRE_ROUTING,
@@ -253,7 +88,7 @@
 	},
 	/* After packet filtering, change source */
 	{
-		.hook		= nf_nat_ipv6_out,
+		.hook		= ip6table_nat_out,
 		.owner		= THIS_MODULE,
 		.pf		= NFPROTO_IPV6,
 		.hooknum	= NF_INET_POST_ROUTING,
@@ -261,7 +96,7 @@
 	},
 	/* Before packet filtering, change destination */
 	{
-		.hook		= nf_nat_ipv6_local_fn,
+		.hook		= ip6table_nat_local_fn,
 		.owner		= THIS_MODULE,
 		.pf		= NFPROTO_IPV6,
 		.hooknum	= NF_INET_LOCAL_OUT,
@@ -269,7 +104,7 @@
 	},
 	/* After packet filtering, change source */
 	{
-		.hook		= nf_nat_ipv6_fn,
+		.hook		= ip6table_nat_fn,
 		.owner		= THIS_MODULE,
 		.pf		= NFPROTO_IPV6,
 		.hooknum	= NF_INET_LOCAL_IN,
diff -urN linux/net/ipv6/netfilter/ip6t_MASQUERADE.c net-next-2.6/net/ipv6/netfilter/ip6t_MASQUERADE.c
--- linux/net/ipv6/netfilter/ip6t_MASQUERADE.c	2013-11-29 12:59:37.871381427 +0100
+++ net-next-2.6/net/ipv6/netfilter/ip6t_MASQUERADE.c	2014-10-06 10:49:01.020908504 +0200
@@ -19,33 +19,12 @@
 #include <net/netfilter/nf_nat.h>
 #include <net/addrconf.h>
 #include <net/ipv6.h>
+#include <net/netfilter/ipv6/nf_nat_masquerade.h>
 
 static unsigned int
 masquerade_tg6(struct sk_buff *skb, const struct xt_action_param *par)
 {
-	const struct nf_nat_range *range = par->targinfo;
-	enum ip_conntrack_info ctinfo;
-	struct in6_addr src;
-	struct nf_conn *ct;
-	struct nf_nat_range newrange;
-
-	ct = nf_ct_get(skb, &ctinfo);
-	NF_CT_ASSERT(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
-			    ctinfo == IP_CT_RELATED_REPLY));
-
-	if (ipv6_dev_get_saddr(dev_net(par->out), par->out,
-			       &ipv6_hdr(skb)->daddr, 0, &src) < 0)
-		return NF_DROP;
-
-	nfct_nat(ct)->masq_index = par->out->ifindex;
-
-	newrange.flags		= range->flags | NF_NAT_RANGE_MAP_IPS;
-	newrange.min_addr.in6	= src;
-	newrange.max_addr.in6	= src;
-	newrange.min_proto	= range->min_proto;
-	newrange.max_proto	= range->max_proto;
-
-	return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_SRC);
+	return nf_nat_masquerade_ipv6(skb, par->targinfo, par->out);
 }
 
 static int masquerade_tg6_checkentry(const struct xt_tgchk_param *par)
@@ -57,48 +36,6 @@
 	return 0;
 }
 
-static int device_cmp(struct nf_conn *ct, void *ifindex)
-{
-	const struct nf_conn_nat *nat = nfct_nat(ct);
-
-	if (!nat)
-		return 0;
-	if (nf_ct_l3num(ct) != NFPROTO_IPV6)
-		return 0;
-	return nat->masq_index == (int)(long)ifindex;
-}
-
-static int masq_device_event(struct notifier_block *this,
-			     unsigned long event, void *ptr)
-{
-	const struct net_device *dev = netdev_notifier_info_to_dev(ptr);
-	struct net *net = dev_net(dev);
-
-	if (event == NETDEV_DOWN)
-		nf_ct_iterate_cleanup(net, device_cmp,
-				      (void *)(long)dev->ifindex, 0, 0);
-
-	return NOTIFY_DONE;
-}
-
-static struct notifier_block masq_dev_notifier = {
-	.notifier_call	= masq_device_event,
-};
-
-static int masq_inet_event(struct notifier_block *this,
-			   unsigned long event, void *ptr)
-{
-	struct inet6_ifaddr *ifa = ptr;
-	struct netdev_notifier_info info;
-
-	netdev_notifier_info_init(&info, ifa->idev->dev);
-	return masq_device_event(this, event, &info);
-}
-
-static struct notifier_block masq_inet_notifier = {
-	.notifier_call	= masq_inet_event,
-};
-
 static struct xt_target masquerade_tg6_reg __read_mostly = {
 	.name		= "MASQUERADE",
 	.family		= NFPROTO_IPV6,
@@ -115,17 +52,14 @@
 	int err;
 
 	err = xt_register_target(&masquerade_tg6_reg);
-	if (err == 0) {
-		register_netdevice_notifier(&masq_dev_notifier);
-		register_inet6addr_notifier(&masq_inet_notifier);
-	}
+	if (err == 0)
+		nf_nat_masquerade_ipv6_register_notifier();
 
 	return err;
 }
 static void __exit masquerade_tg6_exit(void)
 {
-	unregister_inet6addr_notifier(&masq_inet_notifier);
-	unregister_netdevice_notifier(&masq_dev_notifier);
+	nf_nat_masquerade_ipv6_unregister_notifier();
 	xt_unregister_target(&masquerade_tg6_reg);
 }
 
diff -urN linux/net/ipv6/netfilter/Kconfig net-next-2.6/net/ipv6/netfilter/Kconfig
--- linux/net/ipv6/netfilter/Kconfig	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/netfilter/Kconfig	2014-10-06 10:49:01.020908504 +0200
@@ -40,18 +40,13 @@
 	  fields such as the source, destination, flowlabel, hop-limit and
 	  the packet mark.
 
-config NFT_CHAIN_NAT_IPV6
-	depends on NF_TABLES_IPV6
-	depends on NF_NAT_IPV6 && NFT_NAT
-	tristate "IPv6 nf_tables nat chain support"
-	help
-	  This option enables the "nat" chain for IPv6 in nf_tables. This
-	  chain type is used to perform Network Address Translation (NAT)
-	  packet transformations such as the source, destination address and
-	  source and destination ports.
+config NF_REJECT_IPV6
+	tristate "IPv6 packet rejection"
+	default m if NETFILTER_ADVANCED=n
 
 config NFT_REJECT_IPV6
 	depends on NF_TABLES_IPV6
+	select NF_REJECT_IPV6
 	default NFT_REJECT
 	tristate
 
@@ -70,6 +65,34 @@
 	  forms of full Network Address Port Translation. This can be
 	  controlled by iptables or nft.
 
+if NF_NAT_IPV6
+
+config NFT_CHAIN_NAT_IPV6
+	depends on NF_TABLES_IPV6
+	tristate "IPv6 nf_tables nat chain support"
+	help
+	  This option enables the "nat" chain for IPv6 in nf_tables. This
+	  chain type is used to perform Network Address Translation (NAT)
+	  packet transformations such as the source, destination address and
+	  source and destination ports.
+
+config NF_NAT_MASQUERADE_IPV6
+	tristate "IPv6 masquerade support"
+	help
+	  This is the kernel functionality to provide NAT in the masquerade
+	  flavour (automatic source address selection) for IPv6.
+
+config NFT_MASQ_IPV6
+	tristate "IPv6 masquerade support for nf_tables"
+	depends on NF_TABLES_IPV6
+	depends on NFT_MASQ
+	select NF_NAT_MASQUERADE_IPV6
+	help
+	  This is the expression that provides IPv4 masquerading support for
+	  nf_tables.
+
+endif # NF_NAT_IPV6
+
 config IP6_NF_IPTABLES
 	tristate "IP6 tables support (required for filtering)"
 	depends on INET && IPV6
@@ -190,6 +213,7 @@
 config IP6_NF_TARGET_REJECT
 	tristate "REJECT target support"
 	depends on IP6_NF_FILTER
+	select NF_REJECT_IPV6
 	default m if NETFILTER_ADVANCED=n
 	help
 	  The REJECT target allows a filtering rule to specify that an ICMPv6
@@ -260,6 +284,7 @@
 
 config IP6_NF_TARGET_MASQUERADE
 	tristate "MASQUERADE target support"
+	select NF_NAT_MASQUERADE_IPV6
 	help
 	  Masquerading is a special case of NAT: all outgoing connections are
 	  changed to seem to come from a particular interface's address, and
diff -urN linux/net/ipv6/netfilter/Makefile net-next-2.6/net/ipv6/netfilter/Makefile
--- linux/net/ipv6/netfilter/Makefile	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/netfilter/Makefile	2014-10-06 10:49:01.020908504 +0200
@@ -18,6 +18,7 @@
 
 nf_nat_ipv6-y		:= nf_nat_l3proto_ipv6.o nf_nat_proto_icmpv6.o
 obj-$(CONFIG_NF_NAT_IPV6) += nf_nat_ipv6.o
+obj-$(CONFIG_NF_NAT_MASQUERADE_IPV6) += nf_nat_masquerade_ipv6.o
 
 # defrag
 nf_defrag_ipv6-y := nf_defrag_ipv6_hooks.o nf_conntrack_reasm.o
@@ -26,11 +27,15 @@
 # logging
 obj-$(CONFIG_NF_LOG_IPV6) += nf_log_ipv6.o
 
+# reject
+obj-$(CONFIG_NF_REJECT_IPV6) += nf_reject_ipv6.o
+
 # nf_tables
 obj-$(CONFIG_NF_TABLES_IPV6) += nf_tables_ipv6.o
 obj-$(CONFIG_NFT_CHAIN_ROUTE_IPV6) += nft_chain_route_ipv6.o
 obj-$(CONFIG_NFT_CHAIN_NAT_IPV6) += nft_chain_nat_ipv6.o
 obj-$(CONFIG_NFT_REJECT_IPV6) += nft_reject_ipv6.o
+obj-$(CONFIG_NFT_MASQ_IPV6) += nft_masq_ipv6.o
 
 # matches
 obj-$(CONFIG_IP6_NF_MATCH_AH) += ip6t_ah.o
diff -urN linux/net/ipv6/netfilter/nf_defrag_ipv6_hooks.c net-next-2.6/net/ipv6/netfilter/nf_defrag_ipv6_hooks.c
--- linux/net/ipv6/netfilter/nf_defrag_ipv6_hooks.c	2013-11-29 12:59:37.871381427 +0100
+++ net-next-2.6/net/ipv6/netfilter/nf_defrag_ipv6_hooks.c	2014-10-06 10:49:01.408912456 +0200
@@ -40,7 +40,7 @@
 		zone = nf_ct_zone((struct nf_conn *)skb->nfct);
 #endif
 
-#ifdef CONFIG_BRIDGE_NETFILTER
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 	if (skb->nf_bridge &&
 	    skb->nf_bridge->mask & BRNF_NF_BRIDGE_PREROUTING)
 		return IP6_DEFRAG_CONNTRACK_BRIDGE_IN + zone;
diff -urN linux/net/ipv6/netfilter/nf_nat_l3proto_ipv6.c net-next-2.6/net/ipv6/netfilter/nf_nat_l3proto_ipv6.c
--- linux/net/ipv6/netfilter/nf_nat_l3proto_ipv6.c	2014-09-24 09:52:43.188644458 +0200
+++ net-next-2.6/net/ipv6/netfilter/nf_nat_l3proto_ipv6.c	2014-10-06 10:49:01.408912456 +0200
@@ -261,6 +261,205 @@
 }
 EXPORT_SYMBOL_GPL(nf_nat_icmpv6_reply_translation);
 
+unsigned int
+nf_nat_ipv6_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
+	       const struct net_device *in, const struct net_device *out,
+	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
+					struct sk_buff *skb,
+					const struct net_device *in,
+					const struct net_device *out,
+					struct nf_conn *ct))
+{
+	struct nf_conn *ct;
+	enum ip_conntrack_info ctinfo;
+	struct nf_conn_nat *nat;
+	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);
+	__be16 frag_off;
+	int hdrlen;
+	u8 nexthdr;
+
+	ct = nf_ct_get(skb, &ctinfo);
+	/* Can't track?  It's not due to stress, or conntrack would
+	 * have dropped it.  Hence it's the user's responsibilty to
+	 * packet filter it out, or implement conntrack/NAT for that
+	 * protocol. 8) --RR
+	 */
+	if (!ct)
+		return NF_ACCEPT;
+
+	/* Don't try to NAT if this packet is not conntracked */
+	if (nf_ct_is_untracked(ct))
+		return NF_ACCEPT;
+
+	nat = nf_ct_nat_ext_add(ct);
+	if (nat == NULL)
+		return NF_ACCEPT;
+
+	switch (ctinfo) {
+	case IP_CT_RELATED:
+	case IP_CT_RELATED_REPLY:
+		nexthdr = ipv6_hdr(skb)->nexthdr;
+		hdrlen = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr),
+					  &nexthdr, &frag_off);
+
+		if (hdrlen >= 0 && nexthdr == IPPROTO_ICMPV6) {
+			if (!nf_nat_icmpv6_reply_translation(skb, ct, ctinfo,
+							     ops->hooknum,
+							     hdrlen))
+				return NF_DROP;
+			else
+				return NF_ACCEPT;
+		}
+		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
+	case IP_CT_NEW:
+		/* Seen it before?  This can happen for loopback, retrans,
+		 * or local packets.
+		 */
+		if (!nf_nat_initialized(ct, maniptype)) {
+			unsigned int ret;
+
+			ret = do_chain(ops, skb, in, out, ct);
+			if (ret != NF_ACCEPT)
+				return ret;
+
+			if (nf_nat_initialized(ct, HOOK2MANIP(ops->hooknum)))
+				break;
+
+			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);
+			if (ret != NF_ACCEPT)
+				return ret;
+		} else {
+			pr_debug("Already setup manip %s for ct %p\n",
+				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
+				 ct);
+			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
+				goto oif_changed;
+		}
+		break;
+
+	default:
+		/* ESTABLISHED */
+		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||
+			     ctinfo == IP_CT_ESTABLISHED_REPLY);
+		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
+			goto oif_changed;
+	}
+
+	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);
+
+oif_changed:
+	nf_ct_kill_acct(ct, ctinfo, skb);
+	return NF_DROP;
+}
+EXPORT_SYMBOL_GPL(nf_nat_ipv6_fn);
+
+unsigned int
+nf_nat_ipv6_in(const struct nf_hook_ops *ops, struct sk_buff *skb,
+	       const struct net_device *in, const struct net_device *out,
+	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
+					struct sk_buff *skb,
+					const struct net_device *in,
+					const struct net_device *out,
+					struct nf_conn *ct))
+{
+	unsigned int ret;
+	struct in6_addr daddr = ipv6_hdr(skb)->daddr;
+
+	ret = nf_nat_ipv6_fn(ops, skb, in, out, do_chain);
+	if (ret != NF_DROP && ret != NF_STOLEN &&
+	    ipv6_addr_cmp(&daddr, &ipv6_hdr(skb)->daddr))
+		skb_dst_drop(skb);
+
+	return ret;
+}
+EXPORT_SYMBOL_GPL(nf_nat_ipv6_in);
+
+unsigned int
+nf_nat_ipv6_out(const struct nf_hook_ops *ops, struct sk_buff *skb,
+		const struct net_device *in, const struct net_device *out,
+		unsigned int (*do_chain)(const struct nf_hook_ops *ops,
+					 struct sk_buff *skb,
+					 const struct net_device *in,
+					 const struct net_device *out,
+					 struct nf_conn *ct))
+{
+#ifdef CONFIG_XFRM
+	const struct nf_conn *ct;
+	enum ip_conntrack_info ctinfo;
+	int err;
+#endif
+	unsigned int ret;
+
+	/* root is playing with raw sockets. */
+	if (skb->len < sizeof(struct ipv6hdr))
+		return NF_ACCEPT;
+
+	ret = nf_nat_ipv6_fn(ops, skb, in, out, do_chain);
+#ifdef CONFIG_XFRM
+	if (ret != NF_DROP && ret != NF_STOLEN &&
+	    !(IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) &&
+	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
+		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
+
+		if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.src.u3,
+				      &ct->tuplehash[!dir].tuple.dst.u3) ||
+		    (ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMPV6 &&
+		     ct->tuplehash[dir].tuple.src.u.all !=
+		     ct->tuplehash[!dir].tuple.dst.u.all)) {
+			err = nf_xfrm_me_harder(skb, AF_INET6);
+			if (err < 0)
+				ret = NF_DROP_ERR(err);
+		}
+	}
+#endif
+	return ret;
+}
+EXPORT_SYMBOL_GPL(nf_nat_ipv6_out);
+
+unsigned int
+nf_nat_ipv6_local_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
+		     const struct net_device *in, const struct net_device *out,
+		     unsigned int (*do_chain)(const struct nf_hook_ops *ops,
+					      struct sk_buff *skb,
+					      const struct net_device *in,
+					      const struct net_device *out,
+					      struct nf_conn *ct))
+{
+	const struct nf_conn *ct;
+	enum ip_conntrack_info ctinfo;
+	unsigned int ret;
+	int err;
+
+	/* root is playing with raw sockets. */
+	if (skb->len < sizeof(struct ipv6hdr))
+		return NF_ACCEPT;
+
+	ret = nf_nat_ipv6_fn(ops, skb, in, out, do_chain);
+	if (ret != NF_DROP && ret != NF_STOLEN &&
+	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
+		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
+
+		if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.dst.u3,
+				      &ct->tuplehash[!dir].tuple.src.u3)) {
+			err = ip6_route_me_harder(skb);
+			if (err < 0)
+				ret = NF_DROP_ERR(err);
+		}
+#ifdef CONFIG_XFRM
+		else if (!(IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) &&
+			 ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMPV6 &&
+			 ct->tuplehash[dir].tuple.dst.u.all !=
+			 ct->tuplehash[!dir].tuple.src.u.all) {
+			err = nf_xfrm_me_harder(skb, AF_INET6);
+			if (err < 0)
+				ret = NF_DROP_ERR(err);
+		}
+#endif
+	}
+	return ret;
+}
+EXPORT_SYMBOL_GPL(nf_nat_ipv6_local_fn);
+
 static int __init nf_nat_l3proto_ipv6_init(void)
 {
 	int err;
diff -urN linux/net/ipv6/netfilter/nf_nat_masquerade_ipv6.c net-next-2.6/net/ipv6/netfilter/nf_nat_masquerade_ipv6.c
--- linux/net/ipv6/netfilter/nf_nat_masquerade_ipv6.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv6/netfilter/nf_nat_masquerade_ipv6.c	2014-10-06 10:49:01.408912456 +0200
@@ -0,0 +1,120 @@
+/*
+ * Copyright (c) 2011 Patrick McHardy <kaber@trash.net>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ *
+ * Based on Rusty Russell's IPv6 MASQUERADE target. Development of IPv6
+ * NAT funded by Astaro.
+ */
+
+#include <linux/kernel.h>
+#include <linux/module.h>
+#include <linux/atomic.h>
+#include <linux/netdevice.h>
+#include <linux/ipv6.h>
+#include <linux/netfilter.h>
+#include <linux/netfilter_ipv6.h>
+#include <net/netfilter/nf_nat.h>
+#include <net/addrconf.h>
+#include <net/ipv6.h>
+#include <net/netfilter/ipv6/nf_nat_masquerade.h>
+
+unsigned int
+nf_nat_masquerade_ipv6(struct sk_buff *skb, const struct nf_nat_range *range,
+		       const struct net_device *out)
+{
+	enum ip_conntrack_info ctinfo;
+	struct in6_addr src;
+	struct nf_conn *ct;
+	struct nf_nat_range newrange;
+
+	ct = nf_ct_get(skb, &ctinfo);
+	NF_CT_ASSERT(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
+			    ctinfo == IP_CT_RELATED_REPLY));
+
+	if (ipv6_dev_get_saddr(dev_net(out), out,
+			       &ipv6_hdr(skb)->daddr, 0, &src) < 0)
+		return NF_DROP;
+
+	nfct_nat(ct)->masq_index = out->ifindex;
+
+	newrange.flags		= range->flags | NF_NAT_RANGE_MAP_IPS;
+	newrange.min_addr.in6	= src;
+	newrange.max_addr.in6	= src;
+	newrange.min_proto	= range->min_proto;
+	newrange.max_proto	= range->max_proto;
+
+	return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_SRC);
+}
+EXPORT_SYMBOL_GPL(nf_nat_masquerade_ipv6);
+
+static int device_cmp(struct nf_conn *ct, void *ifindex)
+{
+	const struct nf_conn_nat *nat = nfct_nat(ct);
+
+	if (!nat)
+		return 0;
+	if (nf_ct_l3num(ct) != NFPROTO_IPV6)
+		return 0;
+	return nat->masq_index == (int)(long)ifindex;
+}
+
+static int masq_device_event(struct notifier_block *this,
+			     unsigned long event, void *ptr)
+{
+	const struct net_device *dev = netdev_notifier_info_to_dev(ptr);
+	struct net *net = dev_net(dev);
+
+	if (event == NETDEV_DOWN)
+		nf_ct_iterate_cleanup(net, device_cmp,
+				      (void *)(long)dev->ifindex, 0, 0);
+
+	return NOTIFY_DONE;
+}
+
+static struct notifier_block masq_dev_notifier = {
+	.notifier_call	= masq_device_event,
+};
+
+static int masq_inet_event(struct notifier_block *this,
+			   unsigned long event, void *ptr)
+{
+	struct inet6_ifaddr *ifa = ptr;
+	struct netdev_notifier_info info;
+
+	netdev_notifier_info_init(&info, ifa->idev->dev);
+	return masq_device_event(this, event, &info);
+}
+
+static struct notifier_block masq_inet_notifier = {
+	.notifier_call	= masq_inet_event,
+};
+
+static atomic_t masquerade_notifier_refcount = ATOMIC_INIT(0);
+
+void nf_nat_masquerade_ipv6_register_notifier(void)
+{
+	/* check if the notifier is already set */
+	if (atomic_inc_return(&masquerade_notifier_refcount) > 1)
+		return;
+
+	register_netdevice_notifier(&masq_dev_notifier);
+	register_inet6addr_notifier(&masq_inet_notifier);
+}
+EXPORT_SYMBOL_GPL(nf_nat_masquerade_ipv6_register_notifier);
+
+void nf_nat_masquerade_ipv6_unregister_notifier(void)
+{
+	/* check if the notifier still has clients */
+	if (atomic_dec_return(&masquerade_notifier_refcount) > 0)
+		return;
+
+	unregister_inet6addr_notifier(&masq_inet_notifier);
+	unregister_netdevice_notifier(&masq_dev_notifier);
+}
+EXPORT_SYMBOL_GPL(nf_nat_masquerade_ipv6_unregister_notifier);
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
diff -urN linux/net/ipv6/netfilter/nf_reject_ipv6.c net-next-2.6/net/ipv6/netfilter/nf_reject_ipv6.c
--- linux/net/ipv6/netfilter/nf_reject_ipv6.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv6/netfilter/nf_reject_ipv6.c	2014-10-06 10:49:01.408912456 +0200
@@ -0,0 +1,163 @@
+/* (C) 1999-2001 Paul `Rusty' Russell
+ * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ */
+#include <net/ipv6.h>
+#include <net/ip6_route.h>
+#include <net/ip6_fib.h>
+#include <net/ip6_checksum.h>
+#include <linux/netfilter_ipv6.h>
+
+void nf_send_reset6(struct net *net, struct sk_buff *oldskb, int hook)
+{
+	struct sk_buff *nskb;
+	struct tcphdr otcph, *tcph;
+	unsigned int otcplen, hh_len;
+	int tcphoff, needs_ack;
+	const struct ipv6hdr *oip6h = ipv6_hdr(oldskb);
+	struct ipv6hdr *ip6h;
+#define DEFAULT_TOS_VALUE	0x0U
+	const __u8 tclass = DEFAULT_TOS_VALUE;
+	struct dst_entry *dst = NULL;
+	u8 proto;
+	__be16 frag_off;
+	struct flowi6 fl6;
+
+	if ((!(ipv6_addr_type(&oip6h->saddr) & IPV6_ADDR_UNICAST)) ||
+	    (!(ipv6_addr_type(&oip6h->daddr) & IPV6_ADDR_UNICAST))) {
+		pr_debug("addr is not unicast.\n");
+		return;
+	}
+
+	proto = oip6h->nexthdr;
+	tcphoff = ipv6_skip_exthdr(oldskb, ((u8*)(oip6h+1) - oldskb->data), &proto, &frag_off);
+
+	if ((tcphoff < 0) || (tcphoff > oldskb->len)) {
+		pr_debug("Cannot get TCP header.\n");
+		return;
+	}
+
+	otcplen = oldskb->len - tcphoff;
+
+	/* IP header checks: fragment, too short. */
+	if (proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr)) {
+		pr_debug("proto(%d) != IPPROTO_TCP, "
+			 "or too short. otcplen = %d\n",
+			 proto, otcplen);
+		return;
+	}
+
+	if (skb_copy_bits(oldskb, tcphoff, &otcph, sizeof(struct tcphdr)))
+		BUG();
+
+	/* No RST for RST. */
+	if (otcph.rst) {
+		pr_debug("RST is set\n");
+		return;
+	}
+
+	/* Check checksum. */
+	if (nf_ip6_checksum(oldskb, hook, tcphoff, IPPROTO_TCP)) {
+		pr_debug("TCP checksum is invalid\n");
+		return;
+	}
+
+	memset(&fl6, 0, sizeof(fl6));
+	fl6.flowi6_proto = IPPROTO_TCP;
+	fl6.saddr = oip6h->daddr;
+	fl6.daddr = oip6h->saddr;
+	fl6.fl6_sport = otcph.dest;
+	fl6.fl6_dport = otcph.source;
+	security_skb_classify_flow(oldskb, flowi6_to_flowi(&fl6));
+	dst = ip6_route_output(net, NULL, &fl6);
+	if (dst == NULL || dst->error) {
+		dst_release(dst);
+		return;
+	}
+	dst = xfrm_lookup(net, dst, flowi6_to_flowi(&fl6), NULL, 0);
+	if (IS_ERR(dst))
+		return;
+
+	hh_len = (dst->dev->hard_header_len + 15)&~15;
+	nskb = alloc_skb(hh_len + 15 + dst->header_len + sizeof(struct ipv6hdr)
+			 + sizeof(struct tcphdr) + dst->trailer_len,
+			 GFP_ATOMIC);
+
+	if (!nskb) {
+		net_dbg_ratelimited("cannot alloc skb\n");
+		dst_release(dst);
+		return;
+	}
+
+	skb_dst_set(nskb, dst);
+
+	skb_reserve(nskb, hh_len + dst->header_len);
+
+	skb_put(nskb, sizeof(struct ipv6hdr));
+	skb_reset_network_header(nskb);
+	ip6h = ipv6_hdr(nskb);
+	ip6_flow_hdr(ip6h, tclass, 0);
+	ip6h->hop_limit = ip6_dst_hoplimit(dst);
+	ip6h->nexthdr = IPPROTO_TCP;
+	ip6h->saddr = oip6h->daddr;
+	ip6h->daddr = oip6h->saddr;
+
+	skb_reset_transport_header(nskb);
+	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
+	/* Truncate to length (no data) */
+	tcph->doff = sizeof(struct tcphdr)/4;
+	tcph->source = otcph.dest;
+	tcph->dest = otcph.source;
+
+	if (otcph.ack) {
+		needs_ack = 0;
+		tcph->seq = otcph.ack_seq;
+		tcph->ack_seq = 0;
+	} else {
+		needs_ack = 1;
+		tcph->ack_seq = htonl(ntohl(otcph.seq) + otcph.syn + otcph.fin
+				      + otcplen - (otcph.doff<<2));
+		tcph->seq = 0;
+	}
+
+	/* Reset flags */
+	((u_int8_t *)tcph)[13] = 0;
+	tcph->rst = 1;
+	tcph->ack = needs_ack;
+	tcph->window = 0;
+	tcph->urg_ptr = 0;
+	tcph->check = 0;
+
+	/* Adjust TCP checksum */
+	tcph->check = csum_ipv6_magic(&ipv6_hdr(nskb)->saddr,
+				      &ipv6_hdr(nskb)->daddr,
+				      sizeof(struct tcphdr), IPPROTO_TCP,
+				      csum_partial(tcph,
+						   sizeof(struct tcphdr), 0));
+
+	nf_ct_attach(nskb, oldskb);
+
+#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
+	/* If we use ip6_local_out for bridged traffic, the MAC source on
+	 * the RST will be ours, instead of the destination's.  This confuses
+	 * some routers/firewalls, and they drop the packet.  So we need to
+	 * build the eth header using the original destination's MAC as the
+	 * source, and send the RST packet directly.
+	 */
+	if (oldskb->nf_bridge) {
+		struct ethhdr *oeth = eth_hdr(oldskb);
+		nskb->dev = oldskb->nf_bridge->physindev;
+		nskb->protocol = htons(ETH_P_IPV6);
+		ip6h->payload_len = htons(sizeof(struct tcphdr));
+		if (dev_hard_header(nskb, nskb->dev, ntohs(nskb->protocol),
+				    oeth->h_source, oeth->h_dest, nskb->len) < 0)
+			return;
+		dev_queue_xmit(nskb);
+	} else
+#endif
+		ip6_local_out(nskb);
+}
+EXPORT_SYMBOL_GPL(nf_send_reset6);
diff -urN linux/net/ipv6/netfilter/nft_chain_nat_ipv6.c net-next-2.6/net/ipv6/netfilter/nft_chain_nat_ipv6.c
--- linux/net/ipv6/netfilter/nft_chain_nat_ipv6.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/netfilter/nft_chain_nat_ipv6.c	2014-10-06 10:49:01.408912456 +0200
@@ -24,144 +24,53 @@
 #include <net/netfilter/nf_nat_l3proto.h>
 #include <net/ipv6.h>
 
-/*
- * IPv6 NAT chains
- */
-
-static unsigned int nf_nat_ipv6_fn(const struct nf_hook_ops *ops,
-			      struct sk_buff *skb,
-			      const struct net_device *in,
-			      const struct net_device *out,
-			      int (*okfn)(struct sk_buff *))
+static unsigned int nft_nat_do_chain(const struct nf_hook_ops *ops,
+				     struct sk_buff *skb,
+				     const struct net_device *in,
+				     const struct net_device *out,
+				     struct nf_conn *ct)
 {
-	enum ip_conntrack_info ctinfo;
-	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
-	struct nf_conn_nat *nat;
-	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);
-	__be16 frag_off;
-	int hdrlen;
-	u8 nexthdr;
 	struct nft_pktinfo pkt;
-	unsigned int ret;
 
-	if (ct == NULL || nf_ct_is_untracked(ct))
-		return NF_ACCEPT;
+	nft_set_pktinfo_ipv6(&pkt, ops, skb, in, out);
 
-	nat = nf_ct_nat_ext_add(ct);
-	if (nat == NULL)
-		return NF_ACCEPT;
-
-	switch (ctinfo) {
-	case IP_CT_RELATED:
-	case IP_CT_RELATED + IP_CT_IS_REPLY:
-		nexthdr = ipv6_hdr(skb)->nexthdr;
-		hdrlen = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr),
-					  &nexthdr, &frag_off);
-
-		if (hdrlen >= 0 && nexthdr == IPPROTO_ICMPV6) {
-			if (!nf_nat_icmpv6_reply_translation(skb, ct, ctinfo,
-							   ops->hooknum,
-							   hdrlen))
-				return NF_DROP;
-			else
-				return NF_ACCEPT;
-		}
-		/* Fall through */
-	case IP_CT_NEW:
-		if (nf_nat_initialized(ct, maniptype))
-			break;
-
-		nft_set_pktinfo_ipv6(&pkt, ops, skb, in, out);
-
-		ret = nft_do_chain(&pkt, ops);
-		if (ret != NF_ACCEPT)
-			return ret;
-		if (!nf_nat_initialized(ct, maniptype)) {
-			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);
-			if (ret != NF_ACCEPT)
-				return ret;
-		}
-	default:
-		break;
-	}
-
-	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);
+	return nft_do_chain(&pkt, ops);
 }
 
-static unsigned int nf_nat_ipv6_prerouting(const struct nf_hook_ops *ops,
-				      struct sk_buff *skb,
-				      const struct net_device *in,
-				      const struct net_device *out,
-				      int (*okfn)(struct sk_buff *))
+static unsigned int nft_nat_ipv6_fn(const struct nf_hook_ops *ops,
+				    struct sk_buff *skb,
+				    const struct net_device *in,
+				    const struct net_device *out,
+				    int (*okfn)(struct sk_buff *))
 {
-	struct in6_addr daddr = ipv6_hdr(skb)->daddr;
-	unsigned int ret;
-
-	ret = nf_nat_ipv6_fn(ops, skb, in, out, okfn);
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    ipv6_addr_cmp(&daddr, &ipv6_hdr(skb)->daddr))
-		skb_dst_drop(skb);
+	return nf_nat_ipv6_fn(ops, skb, in, out, nft_nat_do_chain);
+}
 
-	return ret;
+static unsigned int nft_nat_ipv6_in(const struct nf_hook_ops *ops,
+				    struct sk_buff *skb,
+				    const struct net_device *in,
+				    const struct net_device *out,
+				    int (*okfn)(struct sk_buff *))
+{
+	return nf_nat_ipv6_in(ops, skb, in, out, nft_nat_do_chain);
 }
 
-static unsigned int nf_nat_ipv6_postrouting(const struct nf_hook_ops *ops,
-				       struct sk_buff *skb,
-				       const struct net_device *in,
-				       const struct net_device *out,
-				       int (*okfn)(struct sk_buff *))
+static unsigned int nft_nat_ipv6_out(const struct nf_hook_ops *ops,
+				     struct sk_buff *skb,
+				     const struct net_device *in,
+				     const struct net_device *out,
+				     int (*okfn)(struct sk_buff *))
 {
-	enum ip_conntrack_info ctinfo __maybe_unused;
-	const struct nf_conn *ct __maybe_unused;
-	unsigned int ret;
-
-	ret = nf_nat_ipv6_fn(ops, skb, in, out, okfn);
-#ifdef CONFIG_XFRM
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    !(IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) &&
-	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
-		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
-
-		if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.src.u3,
-				      &ct->tuplehash[!dir].tuple.dst.u3) ||
-		    (ct->tuplehash[dir].tuple.src.u.all !=
-		     ct->tuplehash[!dir].tuple.dst.u.all))
-			if (nf_xfrm_me_harder(skb, AF_INET6) < 0)
-				ret = NF_DROP;
-	}
-#endif
-	return ret;
+	return nf_nat_ipv6_out(ops, skb, in, out, nft_nat_do_chain);
 }
 
-static unsigned int nf_nat_ipv6_output(const struct nf_hook_ops *ops,
-				  struct sk_buff *skb,
-				  const struct net_device *in,
-				  const struct net_device *out,
-				  int (*okfn)(struct sk_buff *))
+static unsigned int nft_nat_ipv6_local_fn(const struct nf_hook_ops *ops,
+					  struct sk_buff *skb,
+					  const struct net_device *in,
+					  const struct net_device *out,
+					  int (*okfn)(struct sk_buff *))
 {
-	enum ip_conntrack_info ctinfo;
-	const struct nf_conn *ct;
-	unsigned int ret;
-
-	ret = nf_nat_ipv6_fn(ops, skb, in, out, okfn);
-	if (ret != NF_DROP && ret != NF_STOLEN &&
-	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
-		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
-
-		if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.dst.u3,
-				      &ct->tuplehash[!dir].tuple.src.u3)) {
-			if (ip6_route_me_harder(skb))
-				ret = NF_DROP;
-		}
-#ifdef CONFIG_XFRM
-		else if (!(IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) &&
-			 ct->tuplehash[dir].tuple.dst.u.all !=
-			 ct->tuplehash[!dir].tuple.src.u.all)
-			if (nf_xfrm_me_harder(skb, AF_INET6))
-				ret = NF_DROP;
-#endif
-	}
-	return ret;
+	return nf_nat_ipv6_local_fn(ops, skb, in, out, nft_nat_do_chain);
 }
 
 static const struct nf_chain_type nft_chain_nat_ipv6 = {
@@ -174,10 +83,10 @@
 			  (1 << NF_INET_LOCAL_OUT) |
 			  (1 << NF_INET_LOCAL_IN),
 	.hooks		= {
-		[NF_INET_PRE_ROUTING]	= nf_nat_ipv6_prerouting,
-		[NF_INET_POST_ROUTING]	= nf_nat_ipv6_postrouting,
-		[NF_INET_LOCAL_OUT]	= nf_nat_ipv6_output,
-		[NF_INET_LOCAL_IN]	= nf_nat_ipv6_fn,
+		[NF_INET_PRE_ROUTING]	= nft_nat_ipv6_in,
+		[NF_INET_POST_ROUTING]	= nft_nat_ipv6_out,
+		[NF_INET_LOCAL_OUT]	= nft_nat_ipv6_local_fn,
+		[NF_INET_LOCAL_IN]	= nft_nat_ipv6_fn,
 	},
 };
 
diff -urN linux/net/ipv6/netfilter/nft_masq_ipv6.c net-next-2.6/net/ipv6/netfilter/nft_masq_ipv6.c
--- linux/net/ipv6/netfilter/nft_masq_ipv6.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/ipv6/netfilter/nft_masq_ipv6.c	2014-10-06 10:49:01.408912456 +0200
@@ -0,0 +1,77 @@
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
+#include <net/netfilter/ipv6/nf_nat_masquerade.h>
+
+static void nft_masq_ipv6_eval(const struct nft_expr *expr,
+			       struct nft_data data[NFT_REG_MAX + 1],
+			       const struct nft_pktinfo *pkt)
+{
+	struct nft_masq *priv = nft_expr_priv(expr);
+	struct nf_nat_range range;
+	unsigned int verdict;
+
+	range.flags = priv->flags;
+
+	verdict = nf_nat_masquerade_ipv6(pkt->skb, &range, pkt->out);
+
+	data[NFT_REG_VERDICT].verdict = verdict;
+}
+
+static struct nft_expr_type nft_masq_ipv6_type;
+static const struct nft_expr_ops nft_masq_ipv6_ops = {
+	.type		= &nft_masq_ipv6_type,
+	.size		= NFT_EXPR_SIZE(sizeof(struct nft_masq)),
+	.eval		= nft_masq_ipv6_eval,
+	.init		= nft_masq_init,
+	.dump		= nft_masq_dump,
+};
+
+static struct nft_expr_type nft_masq_ipv6_type __read_mostly = {
+	.family		= NFPROTO_IPV6,
+	.name		= "masq",
+	.ops		= &nft_masq_ipv6_ops,
+	.policy		= nft_masq_policy,
+	.maxattr	= NFTA_MASQ_MAX,
+	.owner		= THIS_MODULE,
+};
+
+static int __init nft_masq_ipv6_module_init(void)
+{
+	int ret;
+
+	ret = nft_register_expr(&nft_masq_ipv6_type);
+	if (ret < 0)
+		return ret;
+
+	nf_nat_masquerade_ipv6_register_notifier();
+
+	return ret;
+}
+
+static void __exit nft_masq_ipv6_module_exit(void)
+{
+	nft_unregister_expr(&nft_masq_ipv6_type);
+	nf_nat_masquerade_ipv6_unregister_notifier();
+}
+
+module_init(nft_masq_ipv6_module_init);
+module_exit(nft_masq_ipv6_module_exit);
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>");
+MODULE_ALIAS_NFT_AF_EXPR(AF_INET6, "masq");
diff -urN linux/net/ipv6/output_core.c net-next-2.6/net/ipv6/output_core.c
--- linux/net/ipv6/output_core.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/output_core.c	2014-10-06 10:49:01.408912456 +0200
@@ -35,7 +35,7 @@
 			if (found_rhdr)
 				return offset;
 			break;
-		default :
+		default:
 			return offset;
 		}
 
diff -urN linux/net/ipv6/proc.c net-next-2.6/net/ipv6/proc.c
--- linux/net/ipv6/proc.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/proc.c	2014-10-06 10:49:01.412912498 +0200
@@ -8,7 +8,7 @@
  *		except it reports the sockets in the INET6 address family.
  *
  * Authors:	David S. Miller (davem@caip.rutgers.edu)
- * 		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
+ *		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
  *
  *		This program is free software; you can redistribute it and/or
  *		modify it under the terms of the GNU General Public License
diff -urN linux/net/ipv6/protocol.c net-next-2.6/net/ipv6/protocol.c
--- linux/net/ipv6/protocol.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/protocol.c	2014-10-06 10:49:01.412912498 +0200
@@ -51,6 +51,7 @@
 #endif
 
 const struct net_offload __rcu *inet6_offloads[MAX_INET_PROTOS] __read_mostly;
+EXPORT_SYMBOL(inet6_offloads);
 
 int inet6_add_offload(const struct net_offload *prot, unsigned char protocol)
 {
diff -urN linux/net/ipv6/raw.c net-next-2.6/net/ipv6/raw.c
--- linux/net/ipv6/raw.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/raw.c	2014-10-06 10:49:01.412912498 +0200
@@ -889,7 +889,7 @@
 	else {
 		lock_sock(sk);
 		err = ip6_append_data(sk, ip_generic_getfrag, msg->msg_iov,
-			len, 0, hlimit, tclass, opt, &fl6, (struct rt6_info*)dst,
+			len, 0, hlimit, tclass, opt, &fl6, (struct rt6_info *)dst,
 			msg->msg_flags, dontfrag);
 
 		if (err)
@@ -902,7 +902,7 @@
 	dst_release(dst);
 out:
 	fl6_sock_release(flowlabel);
-	return err<0?err:len;
+	return err < 0 ? err : len;
 do_confirm:
 	dst_confirm(dst);
 	if (!(msg->msg_flags & MSG_PROBE) || len)
@@ -1045,7 +1045,7 @@
 	struct raw6_sock *rp = raw6_sk(sk);
 	int val, len;
 
-	if (get_user(len,optlen))
+	if (get_user(len, optlen))
 		return -EFAULT;
 
 	switch (optname) {
@@ -1069,7 +1069,7 @@
 
 	if (put_user(len, optlen))
 		return -EFAULT;
-	if (copy_to_user(optval,&val,len))
+	if (copy_to_user(optval, &val, len))
 		return -EFAULT;
 	return 0;
 }
diff -urN linux/net/ipv6/reassembly.c net-next-2.6/net/ipv6/reassembly.c
--- linux/net/ipv6/reassembly.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/reassembly.c	2014-10-06 10:49:01.412912498 +0200
@@ -62,13 +62,12 @@
 
 static const char ip6_frag_cache_name[] = "ip6-frags";
 
-struct ip6frag_skb_cb
-{
+struct ip6frag_skb_cb {
 	struct inet6_skb_parm	h;
 	int			offset;
 };
 
-#define FRAG6_CB(skb)	((struct ip6frag_skb_cb*)((skb)->cb))
+#define FRAG6_CB(skb)	((struct ip6frag_skb_cb *)((skb)->cb))
 
 static inline u8 ip6_frag_ecn(const struct ipv6hdr *ipv6h)
 {
@@ -289,7 +288,7 @@
 		goto found;
 	}
 	prev = NULL;
-	for(next = fq->q.fragments; next != NULL; next = next->next) {
+	for (next = fq->q.fragments; next != NULL; next = next->next) {
 		if (FRAG6_CB(next)->offset >= offset)
 			break;	/* bingo! */
 		prev = next;
@@ -529,7 +528,7 @@
 	IP6_INC_STATS_BH(net, ip6_dst_idev(skb_dst(skb)), IPSTATS_MIB_REASMREQDS);
 
 	/* Jumbo payload inhibits frag. header */
-	if (hdr->payload_len==0)
+	if (hdr->payload_len == 0)
 		goto fail_hdr;
 
 	if (!pskb_may_pull(skb, (skb_transport_offset(skb) +
@@ -575,8 +574,7 @@
 	return -1;
 }
 
-static const struct inet6_protocol frag_protocol =
-{
+static const struct inet6_protocol frag_protocol = {
 	.handler	=	ipv6_frag_rcv,
 	.flags		=	INET6_PROTO_NOPOLICY,
 };
diff -urN linux/net/ipv6/route.c net-next-2.6/net/ipv6/route.c
--- linux/net/ipv6/route.c	2014-10-06 10:59:24.275259167 +0200
+++ net-next-2.6/net/ipv6/route.c	2014-10-06 10:49:01.412912498 +0200
@@ -812,7 +812,7 @@
 
 }
 
-struct dst_entry * ip6_route_lookup(struct net *net, struct flowi6 *fl6,
+struct dst_entry *ip6_route_lookup(struct net *net, struct flowi6 *fl6,
 				    int flags)
 {
 	return fib6_rule_lookup(net, fl6, flags, ip6_pol_route_lookup);
@@ -842,7 +842,6 @@
 
 	return NULL;
 }
-
 EXPORT_SYMBOL(rt6_lookup);
 
 /* ip6_ins_rt is called with FREE table->tb6_lock.
@@ -1023,7 +1022,7 @@
 	return ip6_pol_route(net, table, fl6->flowi6_oif, fl6, flags);
 }
 
-struct dst_entry * ip6_route_output(struct net *net, const struct sock *sk,
+struct dst_entry *ip6_route_output(struct net *net, const struct sock *sk,
 				    struct flowi6 *fl6)
 {
 	int flags = 0;
@@ -1040,7 +1039,6 @@
 
 	return fib6_rule_lookup(net, fl6, flags, ip6_pol_route_output);
 }
-
 EXPORT_SYMBOL(ip6_route_output);
 
 struct dst_entry *ip6_blackhole_route(struct net *net, struct dst_entry *dst_orig)
@@ -1145,7 +1143,7 @@
 static void ip6_rt_update_pmtu(struct dst_entry *dst, struct sock *sk,
 			       struct sk_buff *skb, u32 mtu)
 {
-	struct rt6_info *rt6 = (struct rt6_info*)dst;
+	struct rt6_info *rt6 = (struct rt6_info *)dst;
 
 	dst_confirm(dst);
 	if (mtu < dst_mtu(dst) && rt6->rt6i_dst.plen == 128) {
@@ -1920,7 +1918,7 @@
 		return NULL;
 
 	read_lock_bh(&table->tb6_lock);
-	fn = fib6_locate(&table->tb6_root, prefix ,prefixlen, NULL, 0);
+	fn = fib6_locate(&table->tb6_root, prefix, prefixlen, NULL, 0);
 	if (!fn)
 		goto out;
 
@@ -1979,7 +1977,7 @@
 		return NULL;
 
 	read_lock_bh(&table->tb6_lock);
-	for (rt = table->tb6_root.leaf; rt; rt=rt->dst.rt6_next) {
+	for (rt = table->tb6_root.leaf; rt; rt = rt->dst.rt6_next) {
 		if (dev == rt->dst.dev &&
 		    ((rt->rt6i_flags & (RTF_ADDRCONF | RTF_DEFAULT)) == (RTF_ADDRCONF | RTF_DEFAULT)) &&
 		    ipv6_addr_equal(&rt->rt6i_gateway, addr))
@@ -2064,7 +2062,7 @@
 	struct in6_rtmsg rtmsg;
 	int err;
 
-	switch(cmd) {
+	switch (cmd) {
 	case SIOCADDRT:		/* Add a route */
 	case SIOCDELRT:		/* Delete a route */
 		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
@@ -2187,7 +2185,7 @@
 			unsigned int prefs,
 			struct in6_addr *saddr)
 {
-	struct inet6_dev *idev = ip6_dst_idev((struct dst_entry*)rt);
+	struct inet6_dev *idev = ip6_dst_idev((struct dst_entry *)rt);
 	int err = 0;
 	if (rt->rt6i_prefsrc.plen)
 		*saddr = rt->rt6i_prefsrc.addr;
@@ -2482,7 +2480,7 @@
 	return last_err;
 }
 
-static int inet6_rtm_delroute(struct sk_buff *skb, struct nlmsghdr* nlh)
+static int inet6_rtm_delroute(struct sk_buff *skb, struct nlmsghdr *nlh)
 {
 	struct fib6_config cfg;
 	int err;
@@ -2497,7 +2495,7 @@
 		return ip6_route_del(&cfg);
 }
 
-static int inet6_rtm_newroute(struct sk_buff *skb, struct nlmsghdr* nlh)
+static int inet6_rtm_newroute(struct sk_buff *skb, struct nlmsghdr *nlh)
 {
 	struct fib6_config cfg;
 	int err;
@@ -2689,7 +2687,7 @@
 		     prefix, 0, NLM_F_MULTI);
 }
 
-static int inet6_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr* nlh)
+static int inet6_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr *nlh)
 {
 	struct net *net = sock_net(in_skb->sk);
 	struct nlattr *tb[RTA_MAX+1];
diff -urN linux/net/ipv6/sit.c net-next-2.6/net/ipv6/sit.c
--- linux/net/ipv6/sit.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/sit.c	2014-10-06 10:49:01.412912498 +0200
@@ -812,9 +812,9 @@
 	const struct ipv6hdr *iph6 = ipv6_hdr(skb);
 	u8     tos = tunnel->parms.iph.tos;
 	__be16 df = tiph->frag_off;
-	struct rtable *rt;     			/* Route to the other host */
-	struct net_device *tdev;		/* Device to other host */
-	unsigned int max_headroom;		/* The extra header space needed */
+	struct rtable *rt;		/* Route to the other host */
+	struct net_device *tdev;	/* Device to other host */
+	unsigned int max_headroom;	/* The extra header space needed */
 	__be32 dst = tiph->daddr;
 	struct flowi4 fl4;
 	int    mtu;
@@ -822,6 +822,8 @@
 	int addr_type;
 	u8 ttl;
 	int err;
+	u8 protocol = IPPROTO_IPV6;
+	int t_hlen = tunnel->hlen + sizeof(struct iphdr);
 
 	if (skb->protocol != htons(ETH_P_IPV6))
 		goto tx_error;
@@ -911,8 +913,14 @@
 		goto tx_error;
 	}
 
+	skb = iptunnel_handle_offloads(skb, false, SKB_GSO_SIT);
+	if (IS_ERR(skb)) {
+		ip_rt_put(rt);
+		goto out;
+	}
+
 	if (df) {
-		mtu = dst_mtu(&rt->dst) - sizeof(struct iphdr);
+		mtu = dst_mtu(&rt->dst) - t_hlen;
 
 		if (mtu < 68) {
 			dev->stats.collisions++;
@@ -947,7 +955,7 @@
 	/*
 	 * Okay, now see if we can stuff it in the buffer as-is.
 	 */
-	max_headroom = LL_RESERVED_SPACE(tdev)+sizeof(struct iphdr);
+	max_headroom = LL_RESERVED_SPACE(tdev) + t_hlen;
 
 	if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
 	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
@@ -969,14 +977,15 @@
 		ttl = iph6->hop_limit;
 	tos = INET_ECN_encapsulate(tos, ipv6_get_dsfield(iph6));
 
-	skb = iptunnel_handle_offloads(skb, false, SKB_GSO_SIT);
-	if (IS_ERR(skb)) {
+	if (ip_tunnel_encap(skb, tunnel, &protocol, &fl4) < 0) {
 		ip_rt_put(rt);
-		goto out;
+		goto tx_error;
 	}
 
+	skb_set_inner_ipproto(skb, IPPROTO_IPV6);
+
 	err = iptunnel_xmit(skb->sk, rt, skb, fl4.saddr, fl4.daddr,
-			    IPPROTO_IPV6, tos, ttl, df,
+			    protocol, tos, ttl, df,
 			    !net_eq(tunnel->net, dev_net(dev)));
 	iptunnel_xmit_stats(err, &dev->stats, dev->tstats);
 	return NETDEV_TX_OK;
@@ -999,6 +1008,8 @@
 	if (IS_ERR(skb))
 		goto out;
 
+	skb_set_inner_ipproto(skb, IPPROTO_IPIP);
+
 	ip_tunnel_xmit(skb, dev, tiph, IPPROTO_IPIP);
 	return NETDEV_TX_OK;
 out:
@@ -1059,8 +1070,10 @@
 		tdev = __dev_get_by_index(tunnel->net, tunnel->parms.link);
 
 	if (tdev) {
+		int t_hlen = tunnel->hlen + sizeof(struct iphdr);
+
 		dev->hard_header_len = tdev->hard_header_len + sizeof(struct iphdr);
-		dev->mtu = tdev->mtu - sizeof(struct iphdr);
+		dev->mtu = tdev->mtu - t_hlen;
 		if (dev->mtu < IPV6_MIN_MTU)
 			dev->mtu = IPV6_MIN_MTU;
 	}
@@ -1123,7 +1136,7 @@
 #endif
 
 static int
-ipip6_tunnel_ioctl (struct net_device *dev, struct ifreq *ifr, int cmd)
+ipip6_tunnel_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
 {
 	int err = 0;
 	struct ip_tunnel_parm p;
@@ -1307,7 +1320,10 @@
 
 static int ipip6_tunnel_change_mtu(struct net_device *dev, int new_mtu)
 {
-	if (new_mtu < IPV6_MIN_MTU || new_mtu > 0xFFF8 - sizeof(struct iphdr))
+	struct ip_tunnel *tunnel = netdev_priv(dev);
+	int t_hlen = tunnel->hlen + sizeof(struct iphdr);
+
+	if (new_mtu < IPV6_MIN_MTU || new_mtu > 0xFFF8 - t_hlen)
 		return -EINVAL;
 	dev->mtu = new_mtu;
 	return 0;
@@ -1338,12 +1354,15 @@
 
 static void ipip6_tunnel_setup(struct net_device *dev)
 {
+	struct ip_tunnel *tunnel = netdev_priv(dev);
+	int t_hlen = tunnel->hlen + sizeof(struct iphdr);
+
 	dev->netdev_ops		= &ipip6_netdev_ops;
-	dev->destructor 	= ipip6_dev_free;
+	dev->destructor		= ipip6_dev_free;
 
 	dev->type		= ARPHRD_SIT;
-	dev->hard_header_len 	= LL_MAX_HEADER + sizeof(struct iphdr);
-	dev->mtu		= ETH_DATA_LEN - sizeof(struct iphdr);
+	dev->hard_header_len	= LL_MAX_HEADER + t_hlen;
+	dev->mtu		= ETH_DATA_LEN - t_hlen;
 	dev->flags		= IFF_NOARP;
 	dev->priv_flags	       &= ~IFF_XMIT_DST_RELEASE;
 	dev->iflink		= 0;
@@ -1466,6 +1485,40 @@
 
 }
 
+/* This function returns true when ENCAP attributes are present in the nl msg */
+static bool ipip6_netlink_encap_parms(struct nlattr *data[],
+				      struct ip_tunnel_encap *ipencap)
+{
+	bool ret = false;
+
+	memset(ipencap, 0, sizeof(*ipencap));
+
+	if (!data)
+		return ret;
+
+	if (data[IFLA_IPTUN_ENCAP_TYPE]) {
+		ret = true;
+		ipencap->type = nla_get_u16(data[IFLA_IPTUN_ENCAP_TYPE]);
+	}
+
+	if (data[IFLA_IPTUN_ENCAP_FLAGS]) {
+		ret = true;
+		ipencap->flags = nla_get_u16(data[IFLA_IPTUN_ENCAP_FLAGS]);
+	}
+
+	if (data[IFLA_IPTUN_ENCAP_SPORT]) {
+		ret = true;
+		ipencap->sport = nla_get_u16(data[IFLA_IPTUN_ENCAP_SPORT]);
+	}
+
+	if (data[IFLA_IPTUN_ENCAP_DPORT]) {
+		ret = true;
+		ipencap->dport = nla_get_u16(data[IFLA_IPTUN_ENCAP_DPORT]);
+	}
+
+	return ret;
+}
+
 #ifdef CONFIG_IPV6_SIT_6RD
 /* This function returns true when 6RD attributes are present in the nl msg */
 static bool ipip6_netlink_6rd_parms(struct nlattr *data[],
@@ -1509,12 +1562,20 @@
 {
 	struct net *net = dev_net(dev);
 	struct ip_tunnel *nt;
+	struct ip_tunnel_encap ipencap;
 #ifdef CONFIG_IPV6_SIT_6RD
 	struct ip_tunnel_6rd ip6rd;
 #endif
 	int err;
 
 	nt = netdev_priv(dev);
+
+	if (ipip6_netlink_encap_parms(data, &ipencap)) {
+		err = ip_tunnel_encap_setup(nt, &ipencap);
+		if (err < 0)
+			return err;
+	}
+
 	ipip6_netlink_parms(data, &nt->parms);
 
 	if (ipip6_tunnel_locate(net, &nt->parms, 0))
@@ -1537,15 +1598,23 @@
 {
 	struct ip_tunnel *t = netdev_priv(dev);
 	struct ip_tunnel_parm p;
+	struct ip_tunnel_encap ipencap;
 	struct net *net = t->net;
 	struct sit_net *sitn = net_generic(net, sit_net_id);
 #ifdef CONFIG_IPV6_SIT_6RD
 	struct ip_tunnel_6rd ip6rd;
 #endif
+	int err;
 
 	if (dev == sitn->fb_tunnel_dev)
 		return -EINVAL;
 
+	if (ipip6_netlink_encap_parms(data, &ipencap)) {
+		err = ip_tunnel_encap_setup(t, &ipencap);
+		if (err < 0)
+			return err;
+	}
+
 	ipip6_netlink_parms(data, &p);
 
 	if (((dev->flags & IFF_POINTOPOINT) && !p.iph.daddr) ||
@@ -1599,6 +1668,14 @@
 		/* IFLA_IPTUN_6RD_RELAY_PREFIXLEN */
 		nla_total_size(2) +
 #endif
+		/* IFLA_IPTUN_ENCAP_TYPE */
+		nla_total_size(2) +
+		/* IFLA_IPTUN_ENCAP_FLAGS */
+		nla_total_size(2) +
+		/* IFLA_IPTUN_ENCAP_SPORT */
+		nla_total_size(2) +
+		/* IFLA_IPTUN_ENCAP_DPORT */
+		nla_total_size(2) +
 		0;
 }
 
@@ -1630,6 +1707,16 @@
 		goto nla_put_failure;
 #endif
 
+	if (nla_put_u16(skb, IFLA_IPTUN_ENCAP_TYPE,
+			tunnel->encap.type) ||
+	    nla_put_u16(skb, IFLA_IPTUN_ENCAP_SPORT,
+			tunnel->encap.sport) ||
+	    nla_put_u16(skb, IFLA_IPTUN_ENCAP_DPORT,
+			tunnel->encap.dport) ||
+	    nla_put_u16(skb, IFLA_IPTUN_ENCAP_FLAGS,
+			tunnel->encap.dport))
+		goto nla_put_failure;
+
 	return 0;
 
 nla_put_failure:
@@ -1651,6 +1738,10 @@
 	[IFLA_IPTUN_6RD_PREFIXLEN]	= { .type = NLA_U16 },
 	[IFLA_IPTUN_6RD_RELAY_PREFIXLEN] = { .type = NLA_U16 },
 #endif
+	[IFLA_IPTUN_ENCAP_TYPE]		= { .type = NLA_U16 },
+	[IFLA_IPTUN_ENCAP_FLAGS]	= { .type = NLA_U16 },
+	[IFLA_IPTUN_ENCAP_SPORT]	= { .type = NLA_U16 },
+	[IFLA_IPTUN_ENCAP_DPORT]	= { .type = NLA_U16 },
 };
 
 static void ipip6_dellink(struct net_device *dev, struct list_head *head)
diff -urN linux/net/ipv6/syncookies.c net-next-2.6/net/ipv6/syncookies.c
--- linux/net/ipv6/syncookies.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/syncookies.c	2014-10-06 10:49:01.412912498 +0200
@@ -24,7 +24,7 @@
 #define COOKIEBITS 24	/* Upper bits store count */
 #define COOKIEMASK (((__u32)1 << COOKIEBITS) - 1)
 
-static u32 syncookie6_secret[2][16-4+SHA_DIGEST_WORDS];
+static u32 syncookie6_secret[2][16-4+SHA_DIGEST_WORDS] __read_mostly;
 
 /* RFC 2460, Section 8.3:
  * [ipv6 tcp] MSS must be computed as the maximum packet size minus 60 [..]
@@ -203,7 +203,7 @@
 	ireq->ir_num = ntohs(th->dest);
 	ireq->ir_v6_rmt_addr = ipv6_hdr(skb)->saddr;
 	ireq->ir_v6_loc_addr = ipv6_hdr(skb)->daddr;
-	if (ipv6_opt_accepted(sk, skb) ||
+	if (ipv6_opt_accepted(sk, skb, &TCP_SKB_CB(skb)->header.h6) ||
 	    np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo ||
 	    np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim) {
 		atomic_inc(&skb->users);
diff -urN linux/net/ipv6/sysctl_net_ipv6.c net-next-2.6/net/ipv6/sysctl_net_ipv6.c
--- linux/net/ipv6/sysctl_net_ipv6.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/sysctl_net_ipv6.c	2014-10-06 10:49:01.412912498 +0200
@@ -16,6 +16,8 @@
 #include <net/addrconf.h>
 #include <net/inet_frag.h>
 
+static int one = 1;
+
 static struct ctl_table ipv6_table_template[] = {
 	{
 		.procname	= "bindv6only",
@@ -63,6 +65,14 @@
 		.mode		= 0644,
 		.proc_handler	= proc_dointvec
 	},
+	{
+		.procname	= "mld_qrv",
+		.data		= &sysctl_mld_qrv,
+		.maxlen		= sizeof(int),
+		.mode		= 0644,
+		.proc_handler	= proc_dointvec_minmax,
+		.extra1		= &one
+	},
 	{ }
 };
 
diff -urN linux/net/ipv6/tcp_ipv6.c net-next-2.6/net/ipv6/tcp_ipv6.c
--- linux/net/ipv6/tcp_ipv6.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/tcp_ipv6.c	2014-10-06 10:49:01.412912498 +0200
@@ -93,13 +93,16 @@
 static void inet6_sk_rx_dst_set(struct sock *sk, const struct sk_buff *skb)
 {
 	struct dst_entry *dst = skb_dst(skb);
-	const struct rt6_info *rt = (const struct rt6_info *)dst;
 
-	dst_hold(dst);
-	sk->sk_rx_dst = dst;
-	inet_sk(sk)->rx_dst_ifindex = skb->skb_iif;
-	if (rt->rt6i_node)
-		inet6_sk(sk)->rx_dst_cookie = rt->rt6i_node->fn_sernum;
+	if (dst) {
+		const struct rt6_info *rt = (const struct rt6_info *)dst;
+
+		dst_hold(dst);
+		sk->sk_rx_dst = dst;
+		inet_sk(sk)->rx_dst_ifindex = skb->skb_iif;
+		if (rt->rt6i_node)
+			inet6_sk(sk)->rx_dst_cookie = rt->rt6i_node->fn_sernum;
+	}
 }
 
 static void tcp_v6_hash(struct sock *sk)
@@ -738,8 +741,9 @@
 	    ipv6_addr_type(&ireq->ir_v6_rmt_addr) & IPV6_ADDR_LINKLOCAL)
 		ireq->ir_iif = inet6_iif(skb);
 
-	if (!TCP_SKB_CB(skb)->when &&
-	    (ipv6_opt_accepted(sk, skb) || np->rxopt.bits.rxinfo ||
+	if (!TCP_SKB_CB(skb)->tcp_tw_isn &&
+	    (ipv6_opt_accepted(sk, skb, &TCP_SKB_CB(skb)->header.h6) ||
+	     np->rxopt.bits.rxinfo ||
 	     np->rxopt.bits.rxoinfo || np->rxopt.bits.rxhlim ||
 	     np->rxopt.bits.rxohlim || np->repflow)) {
 		atomic_inc(&skb->users);
@@ -1364,7 +1368,7 @@
 			np->rcv_flowinfo = ip6_flowinfo(ipv6_hdr(opt_skb));
 		if (np->repflow)
 			np->flow_label = ip6_flowlabel(ipv6_hdr(opt_skb));
-		if (ipv6_opt_accepted(sk, opt_skb)) {
+		if (ipv6_opt_accepted(sk, opt_skb, &TCP_SKB_CB(opt_skb)->header.h6)) {
 			skb_set_owner_r(opt_skb, sk);
 			opt_skb = xchg(&np->pktoptions, opt_skb);
 		} else {
@@ -1408,11 +1412,19 @@
 
 	th = tcp_hdr(skb);
 	hdr = ipv6_hdr(skb);
+	/* This is tricky : We move IPCB at its correct location into TCP_SKB_CB()
+	 * barrier() makes sure compiler wont play fool^Waliasing games.
+	 */
+	memmove(&TCP_SKB_CB(skb)->header.h6, IP6CB(skb),
+		sizeof(struct inet6_skb_parm));
+	barrier();
+
 	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
 	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
 				    skb->len - th->doff*4);
 	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
-	TCP_SKB_CB(skb)->when = 0;
+	TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
+	TCP_SKB_CB(skb)->tcp_tw_isn = 0;
 	TCP_SKB_CB(skb)->ip_dsfield = ipv6_get_dsfield(hdr);
 	TCP_SKB_CB(skb)->sacked = 0;
 
diff -urN linux/net/ipv6/tcpv6_offload.c net-next-2.6/net/ipv6/tcpv6_offload.c
--- linux/net/ipv6/tcpv6_offload.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/tcpv6_offload.c	2014-10-06 10:49:01.412912498 +0200
@@ -15,54 +15,17 @@
 #include <net/ip6_checksum.h>
 #include "ip6_offload.h"
 
-static int tcp_v6_gso_send_check(struct sk_buff *skb)
-{
-	const struct ipv6hdr *ipv6h;
-	struct tcphdr *th;
-
-	if (!pskb_may_pull(skb, sizeof(*th)))
-		return -EINVAL;
-
-	ipv6h = ipv6_hdr(skb);
-	th = tcp_hdr(skb);
-
-	th->check = 0;
-	skb->ip_summed = CHECKSUM_PARTIAL;
-	__tcp_v6_send_check(skb, &ipv6h->saddr, &ipv6h->daddr);
-	return 0;
-}
-
 static struct sk_buff **tcp6_gro_receive(struct sk_buff **head,
 					 struct sk_buff *skb)
 {
-	const struct ipv6hdr *iph = skb_gro_network_header(skb);
-	__wsum wsum;
-
 	/* Don't bother verifying checksum if we're going to flush anyway. */
-	if (NAPI_GRO_CB(skb)->flush)
-		goto skip_csum;
-
-	wsum = NAPI_GRO_CB(skb)->csum;
-
-	switch (skb->ip_summed) {
-	case CHECKSUM_NONE:
-		wsum = skb_checksum(skb, skb_gro_offset(skb), skb_gro_len(skb),
-				    wsum);
-
-		/* fall through */
-
-	case CHECKSUM_COMPLETE:
-		if (!tcp_v6_check(skb_gro_len(skb), &iph->saddr, &iph->daddr,
-				  wsum)) {
-			skb->ip_summed = CHECKSUM_UNNECESSARY;
-			break;
-		}
-
+	if (!NAPI_GRO_CB(skb)->flush &&
+	    skb_gro_checksum_validate(skb, IPPROTO_TCP,
+				      ip6_gro_compute_pseudo)) {
 		NAPI_GRO_CB(skb)->flush = 1;
 		return NULL;
 	}
 
-skip_csum:
 	return tcp_gro_receive(head, skb);
 }
 
@@ -78,10 +41,32 @@
 	return tcp_gro_complete(skb);
 }
 
+struct sk_buff *tcp6_gso_segment(struct sk_buff *skb,
+				 netdev_features_t features)
+{
+	struct tcphdr *th;
+
+	if (!pskb_may_pull(skb, sizeof(*th)))
+		return ERR_PTR(-EINVAL);
+
+	if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL)) {
+		const struct ipv6hdr *ipv6h = ipv6_hdr(skb);
+		struct tcphdr *th = tcp_hdr(skb);
+
+		/* Set up pseudo header, usually expect stack to have done
+		 * this.
+		 */
+
+		th->check = 0;
+		skb->ip_summed = CHECKSUM_PARTIAL;
+		__tcp_v6_send_check(skb, &ipv6h->saddr, &ipv6h->daddr);
+	}
+
+	return tcp_gso_segment(skb, features);
+}
 static const struct net_offload tcpv6_offload = {
 	.callbacks = {
-		.gso_send_check	=	tcp_v6_gso_send_check,
-		.gso_segment	=	tcp_gso_segment,
+		.gso_segment	=	tcp6_gso_segment,
 		.gro_receive	=	tcp6_gro_receive,
 		.gro_complete	=	tcp6_gro_complete,
 	},
diff -urN linux/net/ipv6/tunnel6.c net-next-2.6/net/ipv6/tunnel6.c
--- linux/net/ipv6/tunnel6.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/tunnel6.c	2014-10-06 10:49:01.412912498 +0200
@@ -15,7 +15,7 @@
  * along with this program; if not, see <http://www.gnu.org/licenses/>.
  *
  * Authors	Mitsuru KANDA  <mk@linux-ipv6.org>
- * 		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
+ *		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
  */
 
 #define pr_fmt(fmt) "IPv6: " fmt
@@ -64,7 +64,6 @@
 
 	return ret;
 }
-
 EXPORT_SYMBOL(xfrm6_tunnel_register);
 
 int xfrm6_tunnel_deregister(struct xfrm6_tunnel *handler, unsigned short family)
@@ -92,7 +91,6 @@
 
 	return ret;
 }
-
 EXPORT_SYMBOL(xfrm6_tunnel_deregister);
 
 #define for_each_tunnel_rcu(head, handler)		\
diff -urN linux/net/ipv6/udp.c net-next-2.6/net/ipv6/udp.c
--- linux/net/ipv6/udp.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/udp.c	2014-10-06 10:49:01.412912498 +0200
@@ -243,7 +243,7 @@
 				goto exact_match;
 		} else if (score == badness && reuseport) {
 			matches++;
-			if (((u64)hash * matches) >> 32 == 0)
+			if (reciprocal_scale(hash, matches) == 0)
 				result = sk;
 			hash = next_pseudo_random32(hash);
 		}
@@ -323,7 +323,7 @@
 			}
 		} else if (score == badness && reuseport) {
 			matches++;
-			if (((u64)hash * matches) >> 32 == 0)
+			if (reciprocal_scale(hash, matches) == 0)
 				result = sk;
 			hash = next_pseudo_random32(hash);
 		}
@@ -373,8 +373,8 @@
 
 
 /*
- * 	This should be easy, if there is something there we
- * 	return it, otherwise we block.
+ *	This should be easy, if there is something there we
+ *	return it, otherwise we block.
  */
 
 int udpv6_recvmsg(struct kiocb *iocb, struct sock *sk,
@@ -530,7 +530,7 @@
 	const struct ipv6hdr *hdr = (const struct ipv6hdr *)skb->data;
 	const struct in6_addr *saddr = &hdr->saddr;
 	const struct in6_addr *daddr = &hdr->daddr;
-	struct udphdr *uh = (struct udphdr*)(skb->data+offset);
+	struct udphdr *uh = (struct udphdr *)(skb->data+offset);
 	struct sock *sk;
 	int err;
 	struct net *net = dev_net(skb->dev);
@@ -596,7 +596,7 @@
 
 static __inline__ void udpv6_err(struct sk_buff *skb,
 				 struct inet6_skb_parm *opt, u8 type,
-				 u8 code, int offset, __be32 info     )
+				 u8 code, int offset, __be32 info)
 {
 	__udp6_lib_err(skb, opt, type, code, offset, info, &udp_table);
 }
@@ -891,6 +891,10 @@
 			goto csum_error;
 		}
 
+		if (udp_sk(sk)->convert_csum && uh->check && !IS_UDPLITE(sk))
+			skb_checksum_try_convert(skb, IPPROTO_UDP, uh->check,
+						 ip6_compute_pseudo);
+
 		ret = udpv6_queue_rcv_skb(sk, skb);
 		sock_put(sk);
 
@@ -960,10 +964,10 @@
 }
 
 /**
- * 	udp6_hwcsum_outgoing  -  handle outgoing HW checksumming
- * 	@sk: 	socket we are sending on
- * 	@skb: 	sk_buff containing the filled-in UDP header
- * 	        (checksum field must be zeroed out)
+ *	udp6_hwcsum_outgoing  -  handle outgoing HW checksumming
+ *	@sk:	socket we are sending on
+ *	@skb:	sk_buff containing the filled-in UDP header
+ *		(checksum field must be zeroed out)
  */
 static void udp6_hwcsum_outgoing(struct sock *sk, struct sk_buff *skb,
 				 const struct in6_addr *saddr,
@@ -1294,7 +1298,7 @@
 	getfrag  =  is_udplite ?  udplite_getfrag : ip_generic_getfrag;
 	err = ip6_append_data(sk, getfrag, msg->msg_iov, ulen,
 		sizeof(struct udphdr), hlimit, tclass, opt, &fl6,
-		(struct rt6_info*)dst,
+		(struct rt6_info *)dst,
 		corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags, dontfrag);
 	if (err)
 		udp_v6_flush_pending_frames(sk);
diff -urN linux/net/ipv6/udp_offload.c net-next-2.6/net/ipv6/udp_offload.c
--- linux/net/ipv6/udp_offload.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/udp_offload.c	2014-10-06 10:49:01.412912498 +0200
@@ -10,34 +10,13 @@
  *      UDPv6 GSO support
  */
 #include <linux/skbuff.h>
+#include <linux/netdevice.h>
 #include <net/protocol.h>
 #include <net/ipv6.h>
 #include <net/udp.h>
 #include <net/ip6_checksum.h>
 #include "ip6_offload.h"
 
-static int udp6_ufo_send_check(struct sk_buff *skb)
-{
-	const struct ipv6hdr *ipv6h;
-	struct udphdr *uh;
-
-	if (!pskb_may_pull(skb, sizeof(*uh)))
-		return -EINVAL;
-
-	if (likely(!skb->encapsulation)) {
-		ipv6h = ipv6_hdr(skb);
-		uh = udp_hdr(skb);
-
-		uh->check = ~csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr, skb->len,
-					     IPPROTO_UDP, 0);
-		skb->csum_start = skb_transport_header(skb) - skb->head;
-		skb->csum_offset = offsetof(struct udphdr, check);
-		skb->ip_summed = CHECKSUM_PARTIAL;
-	}
-
-	return 0;
-}
-
 static struct sk_buff *udp6_ufo_fragment(struct sk_buff *skb,
 					 netdev_features_t features)
 {
@@ -48,7 +27,6 @@
 	u8 *packet_start, *prevhdr;
 	u8 nexthdr;
 	u8 frag_hdr_sz = sizeof(struct frag_hdr);
-	int offset;
 	__wsum csum;
 	int tnl_hlen;
 
@@ -80,15 +58,29 @@
 
 	if (skb->encapsulation && skb_shinfo(skb)->gso_type &
 	    (SKB_GSO_UDP_TUNNEL|SKB_GSO_UDP_TUNNEL_CSUM))
-		segs = skb_udp_tunnel_segment(skb, features);
+		segs = skb_udp_tunnel_segment(skb, features, true);
 	else {
+		const struct ipv6hdr *ipv6h;
+		struct udphdr *uh;
+
+		if (!pskb_may_pull(skb, sizeof(struct udphdr)))
+			goto out;
+
 		/* Do software UFO. Complete and fill in the UDP checksum as HW cannot
 		 * do checksum of UDP packets sent as multiple IP fragments.
 		 */
-		offset = skb_checksum_start_offset(skb);
-		csum = skb_checksum(skb, offset, skb->len - offset, 0);
-		offset += skb->csum_offset;
-		*(__sum16 *)(skb->data + offset) = csum_fold(csum);
+
+		uh = udp_hdr(skb);
+		ipv6h = ipv6_hdr(skb);
+
+		uh->check = 0;
+		csum = skb_checksum(skb, 0, skb->len, 0);
+		uh->check = udp_v6_check(skb->len, &ipv6h->saddr,
+					  &ipv6h->daddr, csum);
+
+		if (uh->check == 0)
+			uh->check = CSUM_MANGLED_0;
+
 		skb->ip_summed = CHECKSUM_NONE;
 
 		/* Check if there is enough headroom to insert fragment header. */
@@ -127,10 +119,52 @@
 out:
 	return segs;
 }
+
+static struct sk_buff **udp6_gro_receive(struct sk_buff **head,
+					 struct sk_buff *skb)
+{
+	struct udphdr *uh = udp_gro_udphdr(skb);
+
+	if (unlikely(!uh))
+		goto flush;
+
+	/* Don't bother verifying checksum if we're going to flush anyway. */
+	if (NAPI_GRO_CB(skb)->flush)
+		goto skip;
+
+	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_UDP, uh->check,
+						 ip6_gro_compute_pseudo))
+		goto flush;
+	else if (uh->check)
+		skb_gro_checksum_try_convert(skb, IPPROTO_UDP, uh->check,
+					     ip6_gro_compute_pseudo);
+
+skip:
+	NAPI_GRO_CB(skb)->is_ipv6 = 1;
+	return udp_gro_receive(head, skb, uh);
+
+flush:
+	NAPI_GRO_CB(skb)->flush = 1;
+	return NULL;
+}
+
+static int udp6_gro_complete(struct sk_buff *skb, int nhoff)
+{
+	const struct ipv6hdr *ipv6h = ipv6_hdr(skb);
+	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);
+
+	if (uh->check)
+		uh->check = ~udp_v6_check(skb->len - nhoff, &ipv6h->saddr,
+					  &ipv6h->daddr, 0);
+
+	return udp_gro_complete(skb, nhoff);
+}
+
 static const struct net_offload udpv6_offload = {
 	.callbacks = {
-		.gso_send_check =	udp6_ufo_send_check,
 		.gso_segment	=	udp6_ufo_fragment,
+		.gro_receive	=	udp6_gro_receive,
+		.gro_complete	=	udp6_gro_complete,
 	},
 };
 
diff -urN linux/net/ipv6/xfrm6_input.c net-next-2.6/net/ipv6/xfrm6_input.c
--- linux/net/ipv6/xfrm6_input.c	2011-07-22 09:59:45.412264645 +0200
+++ net-next-2.6/net/ipv6/xfrm6_input.c	2014-10-06 10:49:01.692915354 +0200
@@ -3,8 +3,8 @@
  *
  * Authors:
  *	Mitsuru KANDA @USAGI
- * 	Kazunori MIYAZAWA @USAGI
- * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
+ *	Kazunori MIYAZAWA @USAGI
+ *	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
  *	YOSHIFUJI Hideaki @USAGI
  *		IPv6 support
  */
@@ -52,7 +52,6 @@
 	return xfrm6_rcv_spi(skb, skb_network_header(skb)[IP6CB(skb)->nhoff],
 			     0);
 }
-
 EXPORT_SYMBOL(xfrm6_rcv);
 
 int xfrm6_input_addr(struct sk_buff *skb, xfrm_address_t *daddr,
@@ -142,5 +141,4 @@
 drop:
 	return -1;
 }
-
 EXPORT_SYMBOL(xfrm6_input_addr);
diff -urN linux/net/ipv6/xfrm6_output.c net-next-2.6/net/ipv6/xfrm6_output.c
--- linux/net/ipv6/xfrm6_output.c	2014-09-24 09:52:43.192644501 +0200
+++ net-next-2.6/net/ipv6/xfrm6_output.c	2014-10-06 10:49:01.692915354 +0200
@@ -25,7 +25,6 @@
 {
 	return ip6_find_1stfragopt(skb, prevhdr);
 }
-
 EXPORT_SYMBOL(xfrm6_find_1stfragopt);
 
 static int xfrm6_local_dontfrag(struct sk_buff *skb)
diff -urN linux/net/ipv6/xfrm6_policy.c net-next-2.6/net/ipv6/xfrm6_policy.c
--- linux/net/ipv6/xfrm6_policy.c	2014-09-24 09:52:43.196644544 +0200
+++ net-next-2.6/net/ipv6/xfrm6_policy.c	2014-10-06 10:49:01.692915354 +0200
@@ -3,11 +3,11 @@
  *
  * Authors:
  *	Mitsuru KANDA @USAGI
- * 	Kazunori MIYAZAWA @USAGI
- * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
- * 		IPv6 support
- * 	YOSHIFUJI Hideaki
- * 		Split up af-specific portion
+ *	Kazunori MIYAZAWA @USAGI
+ *	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
+ *		IPv6 support
+ *	YOSHIFUJI Hideaki
+ *		Split up af-specific portion
  *
  */
 
@@ -84,7 +84,7 @@
 			   int nfheader_len)
 {
 	if (dst->ops->family == AF_INET6) {
-		struct rt6_info *rt = (struct rt6_info*)dst;
+		struct rt6_info *rt = (struct rt6_info *)dst;
 		if (rt->rt6i_node)
 			path->path_cookie = rt->rt6i_node->fn_sernum;
 	}
@@ -97,7 +97,7 @@
 static int xfrm6_fill_dst(struct xfrm_dst *xdst, struct net_device *dev,
 			  const struct flowi *fl)
 {
-	struct rt6_info *rt = (struct rt6_info*)xdst->route;
+	struct rt6_info *rt = (struct rt6_info *)xdst->route;
 
 	xdst->u.dst.dev = dev;
 	dev_hold(dev);
@@ -296,7 +296,7 @@
 	.family =		AF_INET6,
 	.dst_ops =		&xfrm6_dst_ops,
 	.dst_lookup =		xfrm6_dst_lookup,
-	.get_saddr = 		xfrm6_get_saddr,
+	.get_saddr =		xfrm6_get_saddr,
 	.decode_session =	_decode_session6,
 	.get_tos =		xfrm6_get_tos,
 	.init_dst =		xfrm6_init_dst,
@@ -319,9 +319,9 @@
 static struct ctl_table xfrm6_policy_table[] = {
 	{
 		.procname       = "xfrm6_gc_thresh",
-		.data	   	= &init_net.xfrm.xfrm6_dst_ops.gc_thresh,
-		.maxlen	 	= sizeof(int),
-		.mode	   	= 0644,
+		.data		= &init_net.xfrm.xfrm6_dst_ops.gc_thresh,
+		.maxlen		= sizeof(int),
+		.mode		= 0644,
 		.proc_handler   = proc_dointvec,
 	},
 	{ }
diff -urN linux/net/ipv6/xfrm6_state.c net-next-2.6/net/ipv6/xfrm6_state.c
--- linux/net/ipv6/xfrm6_state.c	2013-11-29 12:59:37.875381468 +0100
+++ net-next-2.6/net/ipv6/xfrm6_state.c	2014-10-06 10:49:01.692915354 +0200
@@ -3,11 +3,11 @@
  *
  * Authors:
  *	Mitsuru KANDA @USAGI
- * 	Kazunori MIYAZAWA @USAGI
- * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
- * 		IPv6 support
- * 	YOSHIFUJI Hideaki @USAGI
- * 		Split up af-specific portion
+ *	Kazunori MIYAZAWA @USAGI
+ *	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
+ *		IPv6 support
+ *	YOSHIFUJI Hideaki @USAGI
+ *		Split up af-specific portion
  *
  */
 
@@ -45,10 +45,10 @@
 		   const xfrm_address_t *daddr, const xfrm_address_t *saddr)
 {
 	x->id = tmpl->id;
-	if (ipv6_addr_any((struct in6_addr*)&x->id.daddr))
+	if (ipv6_addr_any((struct in6_addr *)&x->id.daddr))
 		memcpy(&x->id.daddr, daddr, sizeof(x->sel.daddr));
 	memcpy(&x->props.saddr, &tmpl->saddr, sizeof(x->props.saddr));
-	if (ipv6_addr_any((struct in6_addr*)&x->props.saddr))
+	if (ipv6_addr_any((struct in6_addr *)&x->props.saddr))
 		memcpy(&x->props.saddr, saddr, sizeof(x->props.saddr));
 	x->props.mode = tmpl->mode;
 	x->props.reqid = tmpl->reqid;
diff -urN linux/net/ipv6/xfrm6_tunnel.c net-next-2.6/net/ipv6/xfrm6_tunnel.c
--- linux/net/ipv6/xfrm6_tunnel.c	2014-09-24 09:52:43.196644544 +0200
+++ net-next-2.6/net/ipv6/xfrm6_tunnel.c	2014-10-06 10:49:01.692915354 +0200
@@ -15,7 +15,7 @@
  * along with this program; if not, see <http://www.gnu.org/licenses/>.
  *
  * Authors	Mitsuru KANDA  <mk@linux-ipv6.org>
- * 		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
+ *		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
  *
  * Based on net/ipv4/xfrm4_tunnel.c
  *
@@ -110,7 +110,6 @@
 	rcu_read_unlock_bh();
 	return htonl(spi);
 }
-
 EXPORT_SYMBOL(xfrm6_tunnel_spi_lookup);
 
 static int __xfrm6_tunnel_spi_check(struct net *net, u32 spi)
@@ -187,7 +186,6 @@
 
 	return htonl(spi);
 }
-
 EXPORT_SYMBOL(xfrm6_tunnel_alloc_spi);
 
 static void x6spi_destroy_rcu(struct rcu_head *head)
