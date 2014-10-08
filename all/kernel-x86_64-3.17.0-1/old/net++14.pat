diff -urN linux/net/xfrm/xfrm_hash.h net-next-2.6/net/xfrm/xfrm_hash.h
--- linux/net/xfrm/xfrm_hash.h	2013-11-29 12:59:38.751390492 +0100
+++ net-next-2.6/net/xfrm/xfrm_hash.h	2014-10-06 10:49:04.368942622 +0200
@@ -3,6 +3,7 @@
 
 #include <linux/xfrm.h>
 #include <linux/socket.h>
+#include <linux/jhash.h>
 
 static inline unsigned int __xfrm4_addr_hash(const xfrm_address_t *addr)
 {
@@ -28,6 +29,58 @@
 		     saddr->a6[2] ^ saddr->a6[3]);
 }
 
+static inline u32 __bits2mask32(__u8 bits)
+{
+	u32 mask32 = 0xffffffff;
+
+	if (bits == 0)
+		mask32 = 0;
+	else if (bits < 32)
+		mask32 <<= (32 - bits);
+
+	return mask32;
+}
+
+static inline unsigned int __xfrm4_dpref_spref_hash(const xfrm_address_t *daddr,
+						    const xfrm_address_t *saddr,
+						    __u8 dbits,
+						    __u8 sbits)
+{
+	return jhash_2words(ntohl(daddr->a4) & __bits2mask32(dbits),
+			    ntohl(saddr->a4) & __bits2mask32(sbits),
+			    0);
+}
+
+static inline unsigned int __xfrm6_pref_hash(const xfrm_address_t *addr,
+					     __u8 prefixlen)
+{
+	int pdw;
+	int pbi;
+	u32 initval = 0;
+
+	pdw = prefixlen >> 5;     /* num of whole u32 in prefix */
+	pbi = prefixlen &  0x1f;  /* num of bits in incomplete u32 in prefix */
+
+	if (pbi) {
+		__be32 mask;
+
+		mask = htonl((0xffffffff) << (32 - pbi));
+
+		initval = (__force u32)(addr->a6[pdw] & mask);
+	}
+
+	return jhash2((__force u32 *)addr->a6, pdw, initval);
+}
+
+static inline unsigned int __xfrm6_dpref_spref_hash(const xfrm_address_t *daddr,
+						    const xfrm_address_t *saddr,
+						    __u8 dbits,
+						    __u8 sbits)
+{
+	return __xfrm6_pref_hash(daddr, dbits) ^
+	       __xfrm6_pref_hash(saddr, sbits);
+}
+
 static inline unsigned int __xfrm_dst_hash(const xfrm_address_t *daddr,
 					   const xfrm_address_t *saddr,
 					   u32 reqid, unsigned short family,
@@ -84,7 +137,8 @@
 }
 
 static inline unsigned int __sel_hash(const struct xfrm_selector *sel,
-				      unsigned short family, unsigned int hmask)
+				      unsigned short family, unsigned int hmask,
+				      u8 dbits, u8 sbits)
 {
 	const xfrm_address_t *daddr = &sel->daddr;
 	const xfrm_address_t *saddr = &sel->saddr;
@@ -92,19 +146,19 @@
 
 	switch (family) {
 	case AF_INET:
-		if (sel->prefixlen_d != 32 ||
-		    sel->prefixlen_s != 32)
+		if (sel->prefixlen_d < dbits ||
+		    sel->prefixlen_s < sbits)
 			return hmask + 1;
 
-		h = __xfrm4_daddr_saddr_hash(daddr, saddr);
+		h = __xfrm4_dpref_spref_hash(daddr, saddr, dbits, sbits);
 		break;
 
 	case AF_INET6:
-		if (sel->prefixlen_d != 128 ||
-		    sel->prefixlen_s != 128)
+		if (sel->prefixlen_d < dbits ||
+		    sel->prefixlen_s < sbits)
 			return hmask + 1;
 
-		h = __xfrm6_daddr_saddr_hash(daddr, saddr);
+		h = __xfrm6_dpref_spref_hash(daddr, saddr, dbits, sbits);
 		break;
 	}
 	h ^= (h >> 16);
@@ -113,17 +167,19 @@
 
 static inline unsigned int __addr_hash(const xfrm_address_t *daddr,
 				       const xfrm_address_t *saddr,
-				       unsigned short family, unsigned int hmask)
+				       unsigned short family,
+				       unsigned int hmask,
+				       u8 dbits, u8 sbits)
 {
 	unsigned int h = 0;
 
 	switch (family) {
 	case AF_INET:
-		h = __xfrm4_daddr_saddr_hash(daddr, saddr);
+		h = __xfrm4_dpref_spref_hash(daddr, saddr, dbits, sbits);
 		break;
 
 	case AF_INET6:
-		h = __xfrm6_daddr_saddr_hash(daddr, saddr);
+		h = __xfrm6_dpref_spref_hash(daddr, saddr, dbits, sbits);
 		break;
 	}
 	h ^= (h >> 16);
diff -urN linux/net/xfrm/xfrm_output.c net-next-2.6/net/xfrm/xfrm_output.c
--- linux/net/xfrm/xfrm_output.c	2014-09-24 09:52:44.372656886 +0200
+++ net-next-2.6/net/xfrm/xfrm_output.c	2014-10-06 10:49:04.368942622 +0200
@@ -166,11 +166,7 @@
 		err = xfrm_output2(segs);
 
 		if (unlikely(err)) {
-			while ((segs = nskb)) {
-				nskb = segs->next;
-				segs->next = NULL;
-				kfree_skb(segs);
-			}
+			kfree_skb_list(nskb);
 			return err;
 		}
 
diff -urN linux/net/xfrm/xfrm_policy.c net-next-2.6/net/xfrm/xfrm_policy.c
--- linux/net/xfrm/xfrm_policy.c	2014-09-24 09:52:44.372656886 +0200
+++ net-next-2.6/net/xfrm/xfrm_policy.c	2014-10-06 10:49:04.372942663 +0200
@@ -349,12 +349,39 @@
 	return __idx_hash(index, net->xfrm.policy_idx_hmask);
 }
 
+/* calculate policy hash thresholds */
+static void __get_hash_thresh(struct net *net,
+			      unsigned short family, int dir,
+			      u8 *dbits, u8 *sbits)
+{
+	switch (family) {
+	case AF_INET:
+		*dbits = net->xfrm.policy_bydst[dir].dbits4;
+		*sbits = net->xfrm.policy_bydst[dir].sbits4;
+		break;
+
+	case AF_INET6:
+		*dbits = net->xfrm.policy_bydst[dir].dbits6;
+		*sbits = net->xfrm.policy_bydst[dir].sbits6;
+		break;
+
+	default:
+		*dbits = 0;
+		*sbits = 0;
+	}
+}
+
 static struct hlist_head *policy_hash_bysel(struct net *net,
 					    const struct xfrm_selector *sel,
 					    unsigned short family, int dir)
 {
 	unsigned int hmask = net->xfrm.policy_bydst[dir].hmask;
-	unsigned int hash = __sel_hash(sel, family, hmask);
+	unsigned int hash;
+	u8 dbits;
+	u8 sbits;
+
+	__get_hash_thresh(net, family, dir, &dbits, &sbits);
+	hash = __sel_hash(sel, family, hmask, dbits, sbits);
 
 	return (hash == hmask + 1 ?
 		&net->xfrm.policy_inexact[dir] :
@@ -367,25 +394,35 @@
 					     unsigned short family, int dir)
 {
 	unsigned int hmask = net->xfrm.policy_bydst[dir].hmask;
-	unsigned int hash = __addr_hash(daddr, saddr, family, hmask);
+	unsigned int hash;
+	u8 dbits;
+	u8 sbits;
+
+	__get_hash_thresh(net, family, dir, &dbits, &sbits);
+	hash = __addr_hash(daddr, saddr, family, hmask, dbits, sbits);
 
 	return net->xfrm.policy_bydst[dir].table + hash;
 }
 
-static void xfrm_dst_hash_transfer(struct hlist_head *list,
+static void xfrm_dst_hash_transfer(struct net *net,
+				   struct hlist_head *list,
 				   struct hlist_head *ndsttable,
-				   unsigned int nhashmask)
+				   unsigned int nhashmask,
+				   int dir)
 {
 	struct hlist_node *tmp, *entry0 = NULL;
 	struct xfrm_policy *pol;
 	unsigned int h0 = 0;
+	u8 dbits;
+	u8 sbits;
 
 redo:
 	hlist_for_each_entry_safe(pol, tmp, list, bydst) {
 		unsigned int h;
 
+		__get_hash_thresh(net, pol->family, dir, &dbits, &sbits);
 		h = __addr_hash(&pol->selector.daddr, &pol->selector.saddr,
-				pol->family, nhashmask);
+				pol->family, nhashmask, dbits, sbits);
 		if (!entry0) {
 			hlist_del(&pol->bydst);
 			hlist_add_head(&pol->bydst, ndsttable+h);
@@ -439,7 +476,7 @@
 	write_lock_bh(&net->xfrm.xfrm_policy_lock);
 
 	for (i = hmask; i >= 0; i--)
-		xfrm_dst_hash_transfer(odst + i, ndst, nhashmask);
+		xfrm_dst_hash_transfer(net, odst + i, ndst, nhashmask, dir);
 
 	net->xfrm.policy_bydst[dir].table = ndst;
 	net->xfrm.policy_bydst[dir].hmask = nhashmask;
@@ -534,6 +571,86 @@
 	mutex_unlock(&hash_resize_mutex);
 }
 
+static void xfrm_hash_rebuild(struct work_struct *work)
+{
+	struct net *net = container_of(work, struct net,
+				       xfrm.policy_hthresh.work);
+	unsigned int hmask;
+	struct xfrm_policy *pol;
+	struct xfrm_policy *policy;
+	struct hlist_head *chain;
+	struct hlist_head *odst;
+	struct hlist_node *newpos;
+	int i;
+	int dir;
+	unsigned seq;
+	u8 lbits4, rbits4, lbits6, rbits6;
+
+	mutex_lock(&hash_resize_mutex);
+
+	/* read selector prefixlen thresholds */
+	do {
+		seq = read_seqbegin(&net->xfrm.policy_hthresh.lock);
+
+		lbits4 = net->xfrm.policy_hthresh.lbits4;
+		rbits4 = net->xfrm.policy_hthresh.rbits4;
+		lbits6 = net->xfrm.policy_hthresh.lbits6;
+		rbits6 = net->xfrm.policy_hthresh.rbits6;
+	} while (read_seqretry(&net->xfrm.policy_hthresh.lock, seq));
+
+	write_lock_bh(&net->xfrm.xfrm_policy_lock);
+
+	/* reset the bydst and inexact table in all directions */
+	for (dir = 0; dir < XFRM_POLICY_MAX * 2; dir++) {
+		INIT_HLIST_HEAD(&net->xfrm.policy_inexact[dir]);
+		hmask = net->xfrm.policy_bydst[dir].hmask;
+		odst = net->xfrm.policy_bydst[dir].table;
+		for (i = hmask; i >= 0; i--)
+			INIT_HLIST_HEAD(odst + i);
+		if ((dir & XFRM_POLICY_MASK) == XFRM_POLICY_OUT) {
+			/* dir out => dst = remote, src = local */
+			net->xfrm.policy_bydst[dir].dbits4 = rbits4;
+			net->xfrm.policy_bydst[dir].sbits4 = lbits4;
+			net->xfrm.policy_bydst[dir].dbits6 = rbits6;
+			net->xfrm.policy_bydst[dir].sbits6 = lbits6;
+		} else {
+			/* dir in/fwd => dst = local, src = remote */
+			net->xfrm.policy_bydst[dir].dbits4 = lbits4;
+			net->xfrm.policy_bydst[dir].sbits4 = rbits4;
+			net->xfrm.policy_bydst[dir].dbits6 = lbits6;
+			net->xfrm.policy_bydst[dir].sbits6 = rbits6;
+		}
+	}
+
+	/* re-insert all policies by order of creation */
+	list_for_each_entry_reverse(policy, &net->xfrm.policy_all, walk.all) {
+		newpos = NULL;
+		chain = policy_hash_bysel(net, &policy->selector,
+					  policy->family,
+					  xfrm_policy_id2dir(policy->index));
+		hlist_for_each_entry(pol, chain, bydst) {
+			if (policy->priority >= pol->priority)
+				newpos = &pol->bydst;
+			else
+				break;
+		}
+		if (newpos)
+			hlist_add_behind(&policy->bydst, newpos);
+		else
+			hlist_add_head(&policy->bydst, chain);
+	}
+
+	write_unlock_bh(&net->xfrm.xfrm_policy_lock);
+
+	mutex_unlock(&hash_resize_mutex);
+}
+
+void xfrm_policy_hash_rebuild(struct net *net)
+{
+	schedule_work(&net->xfrm.policy_hthresh.work);
+}
+EXPORT_SYMBOL(xfrm_policy_hash_rebuild);
+
 /* Generate new index... KAME seems to generate them ordered by cost
  * of an absolute inpredictability of ordering of rules. This will not pass. */
 static u32 xfrm_gen_index(struct net *net, int dir, u32 index)
@@ -1844,10 +1961,8 @@
 	struct xfrm_dst *xdst = (struct xfrm_dst *) dst;
 	struct xfrm_policy *pol = xdst->pols[0];
 	struct xfrm_policy_queue *pq = &pol->polq;
-	const struct sk_buff *fclone = skb + 1;
 
-	if (unlikely(skb->fclone == SKB_FCLONE_ORIG &&
-		     fclone->fclone == SKB_FCLONE_CLONE)) {
+	if (unlikely(skb_fclone_busy(skb))) {
 		kfree_skb(skb);
 		return 0;
 	}
@@ -2862,10 +2977,21 @@
 		if (!htab->table)
 			goto out_bydst;
 		htab->hmask = hmask;
-	}
+		htab->dbits4 = 32;
+		htab->sbits4 = 32;
+		htab->dbits6 = 128;
+		htab->sbits6 = 128;
+	}
+	net->xfrm.policy_hthresh.lbits4 = 32;
+	net->xfrm.policy_hthresh.rbits4 = 32;
+	net->xfrm.policy_hthresh.lbits6 = 128;
+	net->xfrm.policy_hthresh.rbits6 = 128;
+
+	seqlock_init(&net->xfrm.policy_hthresh.lock);
 
 	INIT_LIST_HEAD(&net->xfrm.policy_all);
 	INIT_WORK(&net->xfrm.policy_hash_work, xfrm_hash_resize);
+	INIT_WORK(&net->xfrm.policy_hthresh.work, xfrm_hash_rebuild);
 	if (net_eq(net, &init_net))
 		register_netdevice_notifier(&xfrm_dev_notifier);
 	return 0;
diff -urN linux/net/xfrm/xfrm_state.c net-next-2.6/net/xfrm/xfrm_state.c
--- linux/net/xfrm/xfrm_state.c	2014-09-24 09:52:44.372656886 +0200
+++ net-next-2.6/net/xfrm/xfrm_state.c	2014-10-06 10:49:04.372942663 +0200
@@ -97,8 +97,6 @@
 	return ((state_hmask + 1) << 1) * sizeof(struct hlist_head);
 }
 
-static DEFINE_MUTEX(hash_resize_mutex);
-
 static void xfrm_hash_resize(struct work_struct *work)
 {
 	struct net *net = container_of(work, struct net, xfrm.state_hash_work);
@@ -107,22 +105,20 @@
 	unsigned int nhashmask, ohashmask;
 	int i;
 
-	mutex_lock(&hash_resize_mutex);
-
 	nsize = xfrm_hash_new_size(net->xfrm.state_hmask);
 	ndst = xfrm_hash_alloc(nsize);
 	if (!ndst)
-		goto out_unlock;
+		return;
 	nsrc = xfrm_hash_alloc(nsize);
 	if (!nsrc) {
 		xfrm_hash_free(ndst, nsize);
-		goto out_unlock;
+		return;
 	}
 	nspi = xfrm_hash_alloc(nsize);
 	if (!nspi) {
 		xfrm_hash_free(ndst, nsize);
 		xfrm_hash_free(nsrc, nsize);
-		goto out_unlock;
+		return;
 	}
 
 	spin_lock_bh(&net->xfrm.xfrm_state_lock);
@@ -148,9 +144,6 @@
 	xfrm_hash_free(odst, osize);
 	xfrm_hash_free(osrc, osize);
 	xfrm_hash_free(ospi, osize);
-
-out_unlock:
-	mutex_unlock(&hash_resize_mutex);
 }
 
 static DEFINE_SPINLOCK(xfrm_state_afinfo_lock);
diff -urN linux/net/xfrm/xfrm_user.c net-next-2.6/net/xfrm/xfrm_user.c
--- linux/net/xfrm/xfrm_user.c	2014-09-24 09:52:44.372656886 +0200
+++ net-next-2.6/net/xfrm/xfrm_user.c	2014-10-06 10:49:04.372942663 +0200
@@ -333,8 +333,7 @@
 	algo = xfrm_aalg_get_byname(ualg->alg_name, 1);
 	if (!algo)
 		return -ENOSYS;
-	if ((ualg->alg_trunc_len / 8) > MAX_AH_AUTH_LEN ||
-	    ualg->alg_trunc_len > algo->uinfo.auth.icv_fullbits)
+	if (ualg->alg_trunc_len > algo->uinfo.auth.icv_fullbits)
 		return -EINVAL;
 	*props = algo->desc.sadb_alg_id;
 
@@ -964,7 +963,9 @@
 {
 	return NLMSG_ALIGN(4)
 	       + nla_total_size(sizeof(struct xfrmu_spdinfo))
-	       + nla_total_size(sizeof(struct xfrmu_spdhinfo));
+	       + nla_total_size(sizeof(struct xfrmu_spdhinfo))
+	       + nla_total_size(sizeof(struct xfrmu_spdhthresh))
+	       + nla_total_size(sizeof(struct xfrmu_spdhthresh));
 }
 
 static int build_spdinfo(struct sk_buff *skb, struct net *net,
@@ -973,9 +974,11 @@
 	struct xfrmk_spdinfo si;
 	struct xfrmu_spdinfo spc;
 	struct xfrmu_spdhinfo sph;
+	struct xfrmu_spdhthresh spt4, spt6;
 	struct nlmsghdr *nlh;
 	int err;
 	u32 *f;
+	unsigned lseq;
 
 	nlh = nlmsg_put(skb, portid, seq, XFRM_MSG_NEWSPDINFO, sizeof(u32), 0);
 	if (nlh == NULL) /* shouldn't really happen ... */
@@ -993,9 +996,22 @@
 	sph.spdhcnt = si.spdhcnt;
 	sph.spdhmcnt = si.spdhmcnt;
 
+	do {
+		lseq = read_seqbegin(&net->xfrm.policy_hthresh.lock);
+
+		spt4.lbits = net->xfrm.policy_hthresh.lbits4;
+		spt4.rbits = net->xfrm.policy_hthresh.rbits4;
+		spt6.lbits = net->xfrm.policy_hthresh.lbits6;
+		spt6.rbits = net->xfrm.policy_hthresh.rbits6;
+	} while (read_seqretry(&net->xfrm.policy_hthresh.lock, lseq));
+
 	err = nla_put(skb, XFRMA_SPD_INFO, sizeof(spc), &spc);
 	if (!err)
 		err = nla_put(skb, XFRMA_SPD_HINFO, sizeof(sph), &sph);
+	if (!err)
+		err = nla_put(skb, XFRMA_SPD_IPV4_HTHRESH, sizeof(spt4), &spt4);
+	if (!err)
+		err = nla_put(skb, XFRMA_SPD_IPV6_HTHRESH, sizeof(spt6), &spt6);
 	if (err) {
 		nlmsg_cancel(skb, nlh);
 		return err;
@@ -1004,6 +1020,51 @@
 	return nlmsg_end(skb, nlh);
 }
 
+static int xfrm_set_spdinfo(struct sk_buff *skb, struct nlmsghdr *nlh,
+			    struct nlattr **attrs)
+{
+	struct net *net = sock_net(skb->sk);
+	struct xfrmu_spdhthresh *thresh4 = NULL;
+	struct xfrmu_spdhthresh *thresh6 = NULL;
+
+	/* selector prefixlen thresholds to hash policies */
+	if (attrs[XFRMA_SPD_IPV4_HTHRESH]) {
+		struct nlattr *rta = attrs[XFRMA_SPD_IPV4_HTHRESH];
+
+		if (nla_len(rta) < sizeof(*thresh4))
+			return -EINVAL;
+		thresh4 = nla_data(rta);
+		if (thresh4->lbits > 32 || thresh4->rbits > 32)
+			return -EINVAL;
+	}
+	if (attrs[XFRMA_SPD_IPV6_HTHRESH]) {
+		struct nlattr *rta = attrs[XFRMA_SPD_IPV6_HTHRESH];
+
+		if (nla_len(rta) < sizeof(*thresh6))
+			return -EINVAL;
+		thresh6 = nla_data(rta);
+		if (thresh6->lbits > 128 || thresh6->rbits > 128)
+			return -EINVAL;
+	}
+
+	if (thresh4 || thresh6) {
+		write_seqlock(&net->xfrm.policy_hthresh.lock);
+		if (thresh4) {
+			net->xfrm.policy_hthresh.lbits4 = thresh4->lbits;
+			net->xfrm.policy_hthresh.rbits4 = thresh4->rbits;
+		}
+		if (thresh6) {
+			net->xfrm.policy_hthresh.lbits6 = thresh6->lbits;
+			net->xfrm.policy_hthresh.rbits6 = thresh6->rbits;
+		}
+		write_sequnlock(&net->xfrm.policy_hthresh.lock);
+
+		xfrm_policy_hash_rebuild(net);
+	}
+
+	return 0;
+}
+
 static int xfrm_get_spdinfo(struct sk_buff *skb, struct nlmsghdr *nlh,
 		struct nlattr **attrs)
 {
@@ -2274,6 +2335,7 @@
 	[XFRM_MSG_REPORT      - XFRM_MSG_BASE] = XMSGSIZE(xfrm_user_report),
 	[XFRM_MSG_MIGRATE     - XFRM_MSG_BASE] = XMSGSIZE(xfrm_userpolicy_id),
 	[XFRM_MSG_GETSADINFO  - XFRM_MSG_BASE] = sizeof(u32),
+	[XFRM_MSG_NEWSPDINFO  - XFRM_MSG_BASE] = sizeof(u32),
 	[XFRM_MSG_GETSPDINFO  - XFRM_MSG_BASE] = sizeof(u32),
 };
 
@@ -2308,10 +2370,17 @@
 	[XFRMA_ADDRESS_FILTER]	= { .len = sizeof(struct xfrm_address_filter) },
 };
 
+static const struct nla_policy xfrma_spd_policy[XFRMA_SPD_MAX+1] = {
+	[XFRMA_SPD_IPV4_HTHRESH] = { .len = sizeof(struct xfrmu_spdhthresh) },
+	[XFRMA_SPD_IPV6_HTHRESH] = { .len = sizeof(struct xfrmu_spdhthresh) },
+};
+
 static const struct xfrm_link {
 	int (*doit)(struct sk_buff *, struct nlmsghdr *, struct nlattr **);
 	int (*dump)(struct sk_buff *, struct netlink_callback *);
 	int (*done)(struct netlink_callback *);
+	const struct nla_policy *nla_pol;
+	int nla_max;
 } xfrm_dispatch[XFRM_NR_MSGTYPES] = {
 	[XFRM_MSG_NEWSA       - XFRM_MSG_BASE] = { .doit = xfrm_add_sa        },
 	[XFRM_MSG_DELSA       - XFRM_MSG_BASE] = { .doit = xfrm_del_sa        },
@@ -2335,6 +2404,9 @@
 	[XFRM_MSG_GETAE       - XFRM_MSG_BASE] = { .doit = xfrm_get_ae  },
 	[XFRM_MSG_MIGRATE     - XFRM_MSG_BASE] = { .doit = xfrm_do_migrate    },
 	[XFRM_MSG_GETSADINFO  - XFRM_MSG_BASE] = { .doit = xfrm_get_sadinfo   },
+	[XFRM_MSG_NEWSPDINFO  - XFRM_MSG_BASE] = { .doit = xfrm_set_spdinfo,
+						   .nla_pol = xfrma_spd_policy,
+						   .nla_max = XFRMA_SPD_MAX },
 	[XFRM_MSG_GETSPDINFO  - XFRM_MSG_BASE] = { .doit = xfrm_get_spdinfo   },
 };
 
@@ -2371,8 +2443,9 @@
 		}
 	}
 
-	err = nlmsg_parse(nlh, xfrm_msg_min[type], attrs, XFRMA_MAX,
-			  xfrma_policy);
+	err = nlmsg_parse(nlh, xfrm_msg_min[type], attrs,
+			  link->nla_max ? : XFRMA_MAX,
+			  link->nla_pol ? : xfrma_policy);
 	if (err < 0)
 		return err;
 
