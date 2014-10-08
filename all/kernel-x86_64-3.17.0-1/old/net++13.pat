diff -urN linux/net/wireless/chan.c net-next-2.6/net/wireless/chan.c
--- linux/net/wireless/chan.c	2014-09-24 09:52:44.364656803 +0200
+++ net-next-2.6/net/wireless/chan.c	2014-10-06 10:49:04.352942459 +0200
@@ -4,6 +4,7 @@
  * any point in time.
  *
  * Copyright 2009	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  */
 
 #include <linux/export.h>
diff -urN linux/net/wireless/core.c net-next-2.6/net/wireless/core.c
--- linux/net/wireless/core.c	2014-09-24 09:52:44.364656803 +0200
+++ net-next-2.6/net/wireless/core.c	2014-10-06 10:49:04.352942459 +0200
@@ -2,6 +2,7 @@
  * This is the linux wireless configuration interface.
  *
  * Copyright 2006-2010		Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
@@ -492,12 +493,6 @@
 	int i;
 	u16 ifmodes = wiphy->interface_modes;
 
-	/*
-	 * There are major locking problems in nl80211/mac80211 for CSA,
-	 * disable for all drivers until this has been reworked.
-	 */
-	wiphy->flags &= ~WIPHY_FLAG_HAS_CHANNEL_SWITCH;
-
 #ifdef CONFIG_PM
 	if (WARN_ON(wiphy->wowlan &&
 		    (wiphy->wowlan->flags & WIPHY_WOWLAN_GTK_REKEY_FAILURE) &&
@@ -635,6 +630,9 @@
 	if (IS_ERR(rdev->wiphy.debugfsdir))
 		rdev->wiphy.debugfsdir = NULL;
 
+	cfg80211_debugfs_rdev_add(rdev);
+	nl80211_notify_wiphy(rdev, NL80211_CMD_NEW_WIPHY);
+
 	if (wiphy->regulatory_flags & REGULATORY_CUSTOM_REG) {
 		struct regulatory_request request;
 
@@ -646,8 +644,6 @@
 		nl80211_send_reg_change_event(&request);
 	}
 
-	cfg80211_debugfs_rdev_add(rdev);
-
 	rdev->wiphy.registered = true;
 	rtnl_unlock();
 
@@ -659,8 +655,6 @@
 		return res;
 	}
 
-	nl80211_notify_wiphy(rdev, NL80211_CMD_NEW_WIPHY);
-
 	return 0;
 }
 EXPORT_SYMBOL(wiphy_register);
@@ -1012,7 +1006,7 @@
 			rdev->devlist_generation++;
 			cfg80211_mlme_purge_registrations(wdev);
 #ifdef CONFIG_CFG80211_WEXT
-			kfree(wdev->wext.keys);
+			kzfree(wdev->wext.keys);
 #endif
 		}
 		/*
diff -urN linux/net/wireless/ibss.c net-next-2.6/net/wireless/ibss.c
--- linux/net/wireless/ibss.c	2014-09-24 09:52:44.364656803 +0200
+++ net-next-2.6/net/wireless/ibss.c	2014-10-06 10:49:04.356942501 +0200
@@ -115,7 +115,7 @@
 	}
 
 	if (WARN_ON(wdev->connect_keys))
-		kfree(wdev->connect_keys);
+		kzfree(wdev->connect_keys);
 	wdev->connect_keys = connkeys;
 
 	wdev->ibss_fixed = params->channel_fixed;
@@ -161,7 +161,7 @@
 
 	ASSERT_WDEV_LOCK(wdev);
 
-	kfree(wdev->connect_keys);
+	kzfree(wdev->connect_keys);
 	wdev->connect_keys = NULL;
 
 	rdev_set_qos_map(rdev, dev, NULL);
diff -urN linux/net/wireless/mlme.c net-next-2.6/net/wireless/mlme.c
--- linux/net/wireless/mlme.c	2014-09-24 09:52:44.364656803 +0200
+++ net-next-2.6/net/wireless/mlme.c	2014-10-06 10:49:04.356942501 +0200
@@ -19,7 +19,7 @@
 
 
 void cfg80211_rx_assoc_resp(struct net_device *dev, struct cfg80211_bss *bss,
-			    const u8 *buf, size_t len)
+			    const u8 *buf, size_t len, int uapsd_queues)
 {
 	struct wireless_dev *wdev = dev->ieee80211_ptr;
 	struct wiphy *wiphy = wdev->wiphy;
@@ -43,7 +43,7 @@
 		return;
 	}
 
-	nl80211_send_rx_assoc(rdev, dev, buf, len, GFP_KERNEL);
+	nl80211_send_rx_assoc(rdev, dev, buf, len, GFP_KERNEL, uapsd_queues);
 	/* update current_bss etc., consumes the bss reference */
 	__cfg80211_connect_result(dev, mgmt->bssid, NULL, 0, ie, len - ieoffs,
 				  status_code,
@@ -605,7 +605,7 @@
 }
 
 bool cfg80211_rx_mgmt(struct wireless_dev *wdev, int freq, int sig_mbm,
-		      const u8 *buf, size_t len, u32 flags, gfp_t gfp)
+		      const u8 *buf, size_t len, u32 flags)
 {
 	struct wiphy *wiphy = wdev->wiphy;
 	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
@@ -648,7 +648,7 @@
 		/* Indicate the received Action frame to user space */
 		if (nl80211_send_mgmt(rdev, wdev, reg->nlportid,
 				      freq, sig_mbm,
-				      buf, len, flags, gfp))
+				      buf, len, flags, GFP_ATOMIC))
 			continue;
 
 		result = true;
diff -urN linux/net/wireless/nl80211.c net-next-2.6/net/wireless/nl80211.c
--- linux/net/wireless/nl80211.c	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/nl80211.c	2014-10-06 10:49:04.360942541 +0200
@@ -2,6 +2,7 @@
  * This is the new netlink-based wireless configuration interface.
  *
  * Copyright 2006-2010	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  */
 
 #include <linux/if.h>
@@ -225,6 +226,7 @@
 	[NL80211_ATTR_WIPHY_FRAG_THRESHOLD] = { .type = NLA_U32 },
 	[NL80211_ATTR_WIPHY_RTS_THRESHOLD] = { .type = NLA_U32 },
 	[NL80211_ATTR_WIPHY_COVERAGE_CLASS] = { .type = NLA_U8 },
+	[NL80211_ATTR_WIPHY_DYN_ACK] = { .type = NLA_FLAG },
 
 	[NL80211_ATTR_IFTYPE] = { .type = NLA_U32 },
 	[NL80211_ATTR_IFINDEX] = { .type = NLA_U32 },
@@ -388,6 +390,11 @@
 	[NL80211_ATTR_TDLS_PEER_CAPABILITY] = { .type = NLA_U32 },
 	[NL80211_ATTR_IFACE_SOCKET_OWNER] = { .type = NLA_FLAG },
 	[NL80211_ATTR_CSA_C_OFFSETS_TX] = { .type = NLA_BINARY },
+	[NL80211_ATTR_USE_RRM] = { .type = NLA_FLAG },
+	[NL80211_ATTR_TSID] = { .type = NLA_U8 },
+	[NL80211_ATTR_USER_PRIO] = { .type = NLA_U8 },
+	[NL80211_ATTR_ADMITTED_TIME] = { .type = NLA_U16 },
+	[NL80211_ATTR_SMPS_MODE] = { .type = NLA_U8 },
 };
 
 /* policy for the key attributes */
@@ -1507,6 +1514,9 @@
 			if (rdev->wiphy.flags & WIPHY_FLAG_HAS_CHANNEL_SWITCH)
 				CMD(channel_switch, CHANNEL_SWITCH);
 			CMD(set_qos_map, SET_QOS_MAP);
+			if (rdev->wiphy.flags &
+					WIPHY_FLAG_SUPPORTS_WMM_ADMISSION)
+				CMD(add_tx_ts, ADD_TX_TS);
 		}
 		/* add into the if now */
 #undef CMD
@@ -2237,11 +2247,21 @@
 	}
 
 	if (info->attrs[NL80211_ATTR_WIPHY_COVERAGE_CLASS]) {
+		if (info->attrs[NL80211_ATTR_WIPHY_DYN_ACK])
+			return -EINVAL;
+
 		coverage_class = nla_get_u8(
 			info->attrs[NL80211_ATTR_WIPHY_COVERAGE_CLASS]);
 		changed |= WIPHY_PARAM_COVERAGE_CLASS;
 	}
 
+	if (info->attrs[NL80211_ATTR_WIPHY_DYN_ACK]) {
+		if (!(rdev->wiphy.features & NL80211_FEATURE_ACKTO_ESTIMATION))
+			return -EOPNOTSUPP;
+
+		changed |= WIPHY_PARAM_DYN_ACK;
+	}
+
 	if (changed) {
 		u8 old_retry_short, old_retry_long;
 		u32 old_frag_threshold, old_rts_threshold;
@@ -3326,6 +3346,29 @@
 			return PTR_ERR(params.acl);
 	}
 
+	if (info->attrs[NL80211_ATTR_SMPS_MODE]) {
+		params.smps_mode =
+			nla_get_u8(info->attrs[NL80211_ATTR_SMPS_MODE]);
+		switch (params.smps_mode) {
+		case NL80211_SMPS_OFF:
+			break;
+		case NL80211_SMPS_STATIC:
+			if (!(rdev->wiphy.features &
+			      NL80211_FEATURE_STATIC_SMPS))
+				return -EINVAL;
+			break;
+		case NL80211_SMPS_DYNAMIC:
+			if (!(rdev->wiphy.features &
+			      NL80211_FEATURE_DYNAMIC_SMPS))
+				return -EINVAL;
+			break;
+		default:
+			return -EINVAL;
+		}
+	} else {
+		params.smps_mode = NL80211_SMPS_OFF;
+	}
+
 	wdev_lock(wdev);
 	err = rdev_start_ap(rdev, dev, &params);
 	if (!err) {
@@ -6033,7 +6076,6 @@
 	const struct cfg80211_bss_ies *ies;
 	void *hdr;
 	struct nlattr *bss;
-	bool tsf = false;
 
 	ASSERT_WDEV_LOCK(wdev);
 
@@ -6060,18 +6102,27 @@
 		goto nla_put_failure;
 
 	rcu_read_lock();
+	/* indicate whether we have probe response data or not */
+	if (rcu_access_pointer(res->proberesp_ies) &&
+	    nla_put_flag(msg, NL80211_BSS_PRESP_DATA))
+		goto fail_unlock_rcu;
+
+	/* this pointer prefers to be pointed to probe response data
+	 * but is always valid
+	 */
 	ies = rcu_dereference(res->ies);
 	if (ies) {
 		if (nla_put_u64(msg, NL80211_BSS_TSF, ies->tsf))
 			goto fail_unlock_rcu;
-		tsf = true;
 		if (ies->len && nla_put(msg, NL80211_BSS_INFORMATION_ELEMENTS,
 					ies->len, ies->data))
 			goto fail_unlock_rcu;
 	}
+
+	/* and this pointer is always (unless driver didn't know) beacon data */
 	ies = rcu_dereference(res->beacon_ies);
-	if (ies) {
-		if (!tsf && nla_put_u64(msg, NL80211_BSS_TSF, ies->tsf))
+	if (ies && ies->from_beacon) {
+		if (nla_put_u64(msg, NL80211_BSS_BEACON_TSF, ies->tsf))
 			goto fail_unlock_rcu;
 		if (ies->len && nla_put(msg, NL80211_BSS_BEACON_IES,
 					ies->len, ies->data))
@@ -6575,6 +6626,14 @@
 		       sizeof(req.vht_capa));
 	}
 
+	if (nla_get_flag(info->attrs[NL80211_ATTR_USE_RRM])) {
+		if (!(rdev->wiphy.features &
+		      NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES) ||
+		    !(rdev->wiphy.features & NL80211_FEATURE_QUIET))
+			return -EINVAL;
+		req.flags |= ASSOC_REQ_USE_RRM;
+	}
+
 	err = nl80211_crypto_settings(rdev, info, &req.crypto, 1);
 	if (!err) {
 		wdev_lock(dev->ieee80211_ptr);
@@ -6837,7 +6896,7 @@
 
 	err = cfg80211_join_ibss(rdev, dev, &ibss, connkeys);
 	if (err)
-		kfree(connkeys);
+		kzfree(connkeys);
 	return err;
 }
 
@@ -7209,7 +7268,7 @@
 
 	if (info->attrs[NL80211_ATTR_HT_CAPABILITY]) {
 		if (!info->attrs[NL80211_ATTR_HT_CAPABILITY_MASK]) {
-			kfree(connkeys);
+			kzfree(connkeys);
 			return -EINVAL;
 		}
 		memcpy(&connect.ht_capa,
@@ -7227,7 +7286,7 @@
 
 	if (info->attrs[NL80211_ATTR_VHT_CAPABILITY]) {
 		if (!info->attrs[NL80211_ATTR_VHT_CAPABILITY_MASK]) {
-			kfree(connkeys);
+			kzfree(connkeys);
 			return -EINVAL;
 		}
 		memcpy(&connect.vht_capa,
@@ -7235,11 +7294,19 @@
 		       sizeof(connect.vht_capa));
 	}
 
+	if (nla_get_flag(info->attrs[NL80211_ATTR_USE_RRM])) {
+		if (!(rdev->wiphy.features &
+		      NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES) ||
+		    !(rdev->wiphy.features & NL80211_FEATURE_QUIET))
+			return -EINVAL;
+		connect.flags |= ASSOC_REQ_USE_RRM;
+	}
+
 	wdev_lock(dev->ieee80211_ptr);
 	err = cfg80211_connect(rdev, dev, &connect, connkeys, NULL);
 	wdev_unlock(dev->ieee80211_ptr);
 	if (err)
-		kfree(connkeys);
+		kzfree(connkeys);
 	return err;
 }
 
@@ -8925,13 +8992,9 @@
 	if (nla_len(tb[NL80211_REKEY_DATA_KCK]) != NL80211_KCK_LEN)
 		return -ERANGE;
 
-	memcpy(rekey_data.kek, nla_data(tb[NL80211_REKEY_DATA_KEK]),
-	       NL80211_KEK_LEN);
-	memcpy(rekey_data.kck, nla_data(tb[NL80211_REKEY_DATA_KCK]),
-	       NL80211_KCK_LEN);
-	memcpy(rekey_data.replay_ctr,
-	       nla_data(tb[NL80211_REKEY_DATA_REPLAY_CTR]),
-	       NL80211_REPLAY_CTR_LEN);
+	rekey_data.kek = nla_data(tb[NL80211_REKEY_DATA_KEK]);
+	rekey_data.kck = nla_data(tb[NL80211_REKEY_DATA_KCK]);
+	rekey_data.replay_ctr = nla_data(tb[NL80211_REKEY_DATA_REPLAY_CTR]);
 
 	wdev_lock(wdev);
 	if (!wdev->current_bss) {
@@ -9363,6 +9426,93 @@
 	return ret;
 }
 
+static int nl80211_add_tx_ts(struct sk_buff *skb, struct genl_info *info)
+{
+	struct cfg80211_registered_device *rdev = info->user_ptr[0];
+	struct net_device *dev = info->user_ptr[1];
+	struct wireless_dev *wdev = dev->ieee80211_ptr;
+	const u8 *peer;
+	u8 tsid, up;
+	u16 admitted_time = 0;
+	int err;
+
+	if (!(rdev->wiphy.flags & WIPHY_FLAG_SUPPORTS_WMM_ADMISSION))
+		return -EOPNOTSUPP;
+
+	if (!info->attrs[NL80211_ATTR_TSID] || !info->attrs[NL80211_ATTR_MAC] ||
+	    !info->attrs[NL80211_ATTR_USER_PRIO])
+		return -EINVAL;
+
+	tsid = nla_get_u8(info->attrs[NL80211_ATTR_TSID]);
+	if (tsid >= IEEE80211_NUM_TIDS)
+		return -EINVAL;
+
+	up = nla_get_u8(info->attrs[NL80211_ATTR_USER_PRIO]);
+	if (up >= IEEE80211_NUM_UPS)
+		return -EINVAL;
+
+	/* WMM uses TIDs 0-7 even for TSPEC */
+	if (tsid < IEEE80211_FIRST_TSPEC_TSID) {
+		if (!(rdev->wiphy.flags & WIPHY_FLAG_SUPPORTS_WMM_ADMISSION))
+			return -EINVAL;
+	} else {
+		/* TODO: handle 802.11 TSPEC/admission control
+		 * need more attributes for that (e.g. BA session requirement)
+		 */
+		return -EINVAL;
+	}
+
+	peer = nla_data(info->attrs[NL80211_ATTR_MAC]);
+
+	if (info->attrs[NL80211_ATTR_ADMITTED_TIME]) {
+		admitted_time =
+			nla_get_u16(info->attrs[NL80211_ATTR_ADMITTED_TIME]);
+		if (!admitted_time)
+			return -EINVAL;
+	}
+
+	wdev_lock(wdev);
+	switch (wdev->iftype) {
+	case NL80211_IFTYPE_STATION:
+	case NL80211_IFTYPE_P2P_CLIENT:
+		if (wdev->current_bss)
+			break;
+		err = -ENOTCONN;
+		goto out;
+	default:
+		err = -EOPNOTSUPP;
+		goto out;
+	}
+
+	err = rdev_add_tx_ts(rdev, dev, tsid, peer, up, admitted_time);
+
+ out:
+	wdev_unlock(wdev);
+	return err;
+}
+
+static int nl80211_del_tx_ts(struct sk_buff *skb, struct genl_info *info)
+{
+	struct cfg80211_registered_device *rdev = info->user_ptr[0];
+	struct net_device *dev = info->user_ptr[1];
+	struct wireless_dev *wdev = dev->ieee80211_ptr;
+	const u8 *peer;
+	u8 tsid;
+	int err;
+
+	if (!info->attrs[NL80211_ATTR_TSID] || !info->attrs[NL80211_ATTR_MAC])
+		return -EINVAL;
+
+	tsid = nla_get_u8(info->attrs[NL80211_ATTR_TSID]);
+	peer = nla_data(info->attrs[NL80211_ATTR_MAC]);
+
+	wdev_lock(wdev);
+	err = rdev_del_tx_ts(rdev, dev, tsid, peer);
+	wdev_unlock(wdev);
+
+	return err;
+}
+
 #define NL80211_FLAG_NEED_WIPHY		0x01
 #define NL80211_FLAG_NEED_NETDEV	0x02
 #define NL80211_FLAG_NEED_RTNL		0x04
@@ -9373,6 +9523,7 @@
 /* If a netdev is associated, it must be UP, P2P must be started */
 #define NL80211_FLAG_NEED_WDEV_UP	(NL80211_FLAG_NEED_WDEV |\
 					 NL80211_FLAG_CHECK_NETDEV_UP)
+#define NL80211_FLAG_CLEAR_SKB		0x20
 
 static int nl80211_pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
 			    struct genl_info *info)
@@ -9456,8 +9607,20 @@
 			dev_put(info->user_ptr[1]);
 		}
 	}
+
 	if (ops->internal_flags & NL80211_FLAG_NEED_RTNL)
 		rtnl_unlock();
+
+	/* If needed, clear the netlink message payload from the SKB
+	 * as it might contain key data that shouldn't stick around on
+	 * the heap after the SKB is freed. The netlink message header
+	 * is still needed for further processing, so leave it intact.
+	 */
+	if (ops->internal_flags & NL80211_FLAG_CLEAR_SKB) {
+		struct nlmsghdr *nlh = nlmsg_hdr(skb);
+
+		memset(nlmsg_data(nlh), 0, nlmsg_len(nlh));
+	}
 }
 
 static const struct genl_ops nl80211_ops[] = {
@@ -9525,7 +9688,8 @@
 		.policy = nl80211_policy,
 		.flags = GENL_ADMIN_PERM,
 		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
-				  NL80211_FLAG_NEED_RTNL,
+				  NL80211_FLAG_NEED_RTNL |
+				  NL80211_FLAG_CLEAR_SKB,
 	},
 	{
 		.cmd = NL80211_CMD_NEW_KEY,
@@ -9533,7 +9697,8 @@
 		.policy = nl80211_policy,
 		.flags = GENL_ADMIN_PERM,
 		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
-				  NL80211_FLAG_NEED_RTNL,
+				  NL80211_FLAG_NEED_RTNL |
+				  NL80211_FLAG_CLEAR_SKB,
 	},
 	{
 		.cmd = NL80211_CMD_DEL_KEY,
@@ -9711,7 +9876,8 @@
 		.policy = nl80211_policy,
 		.flags = GENL_ADMIN_PERM,
 		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
-				  NL80211_FLAG_NEED_RTNL,
+				  NL80211_FLAG_NEED_RTNL |
+				  NL80211_FLAG_CLEAR_SKB,
 	},
 	{
 		.cmd = NL80211_CMD_ASSOCIATE,
@@ -9945,7 +10111,8 @@
 		.policy = nl80211_policy,
 		.flags = GENL_ADMIN_PERM,
 		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
-				  NL80211_FLAG_NEED_RTNL,
+				  NL80211_FLAG_NEED_RTNL |
+				  NL80211_FLAG_CLEAR_SKB,
 	},
 	{
 		.cmd = NL80211_CMD_TDLS_MGMT,
@@ -10103,6 +10270,22 @@
 		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
 				  NL80211_FLAG_NEED_RTNL,
 	},
+	{
+		.cmd = NL80211_CMD_ADD_TX_TS,
+		.doit = nl80211_add_tx_ts,
+		.policy = nl80211_policy,
+		.flags = GENL_ADMIN_PERM,
+		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
+				  NL80211_FLAG_NEED_RTNL,
+	},
+	{
+		.cmd = NL80211_CMD_DEL_TX_TS,
+		.doit = nl80211_del_tx_ts,
+		.policy = nl80211_policy,
+		.flags = GENL_ADMIN_PERM,
+		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
+				  NL80211_FLAG_NEED_RTNL,
+	},
 };
 
 /* notification functions */
@@ -10371,7 +10554,8 @@
 static void nl80211_send_mlme_event(struct cfg80211_registered_device *rdev,
 				    struct net_device *netdev,
 				    const u8 *buf, size_t len,
-				    enum nl80211_commands cmd, gfp_t gfp)
+				    enum nl80211_commands cmd, gfp_t gfp,
+				    int uapsd_queues)
 {
 	struct sk_buff *msg;
 	void *hdr;
@@ -10391,6 +10575,19 @@
 	    nla_put(msg, NL80211_ATTR_FRAME, len, buf))
 		goto nla_put_failure;
 
+	if (uapsd_queues >= 0) {
+		struct nlattr *nla_wmm =
+			nla_nest_start(msg, NL80211_ATTR_STA_WME);
+		if (!nla_wmm)
+			goto nla_put_failure;
+
+		if (nla_put_u8(msg, NL80211_STA_WME_UAPSD_QUEUES,
+			       uapsd_queues))
+			goto nla_put_failure;
+
+		nla_nest_end(msg, nla_wmm);
+	}
+
 	genlmsg_end(msg, hdr);
 
 	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
@@ -10407,15 +10604,15 @@
 			  size_t len, gfp_t gfp)
 {
 	nl80211_send_mlme_event(rdev, netdev, buf, len,
-				NL80211_CMD_AUTHENTICATE, gfp);
+				NL80211_CMD_AUTHENTICATE, gfp, -1);
 }
 
 void nl80211_send_rx_assoc(struct cfg80211_registered_device *rdev,
 			   struct net_device *netdev, const u8 *buf,
-			   size_t len, gfp_t gfp)
+			   size_t len, gfp_t gfp, int uapsd_queues)
 {
 	nl80211_send_mlme_event(rdev, netdev, buf, len,
-				NL80211_CMD_ASSOCIATE, gfp);
+				NL80211_CMD_ASSOCIATE, gfp, uapsd_queues);
 }
 
 void nl80211_send_deauth(struct cfg80211_registered_device *rdev,
@@ -10423,7 +10620,7 @@
 			 size_t len, gfp_t gfp)
 {
 	nl80211_send_mlme_event(rdev, netdev, buf, len,
-				NL80211_CMD_DEAUTHENTICATE, gfp);
+				NL80211_CMD_DEAUTHENTICATE, gfp, -1);
 }
 
 void nl80211_send_disassoc(struct cfg80211_registered_device *rdev,
@@ -10431,7 +10628,7 @@
 			   size_t len, gfp_t gfp)
 {
 	nl80211_send_mlme_event(rdev, netdev, buf, len,
-				NL80211_CMD_DISASSOCIATE, gfp);
+				NL80211_CMD_DISASSOCIATE, gfp, -1);
 }
 
 void cfg80211_rx_unprot_mlme_mgmt(struct net_device *dev, const u8 *buf,
@@ -10452,7 +10649,7 @@
 		cmd = NL80211_CMD_UNPROT_DISASSOCIATE;
 
 	trace_cfg80211_rx_unprot_mlme_mgmt(dev, buf, len);
-	nl80211_send_mlme_event(rdev, dev, buf, len, cmd, GFP_ATOMIC);
+	nl80211_send_mlme_event(rdev, dev, buf, len, cmd, GFP_ATOMIC, -1);
 }
 EXPORT_SYMBOL(cfg80211_rx_unprot_mlme_mgmt);
 
diff -urN linux/net/wireless/nl80211.h net-next-2.6/net/wireless/nl80211.h
--- linux/net/wireless/nl80211.h	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/nl80211.h	2014-10-06 10:49:04.360942541 +0200
@@ -23,7 +23,8 @@
 			  const u8 *buf, size_t len, gfp_t gfp);
 void nl80211_send_rx_assoc(struct cfg80211_registered_device *rdev,
 			   struct net_device *netdev,
-			   const u8 *buf, size_t len, gfp_t gfp);
+			   const u8 *buf, size_t len, gfp_t gfp,
+			   int uapsd_queues);
 void nl80211_send_deauth(struct cfg80211_registered_device *rdev,
 			 struct net_device *netdev,
 			 const u8 *buf, size_t len, gfp_t gfp);
diff -urN linux/net/wireless/rdev-ops.h net-next-2.6/net/wireless/rdev-ops.h
--- linux/net/wireless/rdev-ops.h	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/rdev-ops.h	2014-10-06 10:49:04.360942541 +0200
@@ -915,4 +915,35 @@
 	return ret;
 }
 
+static inline int
+rdev_add_tx_ts(struct cfg80211_registered_device *rdev,
+	       struct net_device *dev, u8 tsid, const u8 *peer,
+	       u8 user_prio, u16 admitted_time)
+{
+	int ret = -EOPNOTSUPP;
+
+	trace_rdev_add_tx_ts(&rdev->wiphy, dev, tsid, peer,
+			     user_prio, admitted_time);
+	if (rdev->ops->add_tx_ts)
+		ret = rdev->ops->add_tx_ts(&rdev->wiphy, dev, tsid, peer,
+					   user_prio, admitted_time);
+	trace_rdev_return_int(&rdev->wiphy, ret);
+
+	return ret;
+}
+
+static inline int
+rdev_del_tx_ts(struct cfg80211_registered_device *rdev,
+	       struct net_device *dev, u8 tsid, const u8 *peer)
+{
+	int ret = -EOPNOTSUPP;
+
+	trace_rdev_del_tx_ts(&rdev->wiphy, dev, tsid, peer);
+	if (rdev->ops->del_tx_ts)
+		ret = rdev->ops->del_tx_ts(&rdev->wiphy, dev, tsid, peer);
+	trace_rdev_return_int(&rdev->wiphy, ret);
+
+	return ret;
+}
+
 #endif /* __CFG80211_RDEV_OPS */
diff -urN linux/net/wireless/reg.c net-next-2.6/net/wireless/reg.c
--- linux/net/wireless/reg.c	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/reg.c	2014-10-06 10:49:04.360942541 +0200
@@ -3,6 +3,7 @@
  * Copyright 2005-2006, Devicescape Software, Inc.
  * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
  * Copyright 2008-2011	Luis R. Rodriguez <mcgrof@qca.qualcomm.com>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * Permission to use, copy, modify, and/or distribute this software for any
  * purpose with or without fee is hereby granted, provided that the above
@@ -798,6 +799,57 @@
 	return 0;
 }
 
+/* check whether old rule contains new rule */
+static bool rule_contains(struct ieee80211_reg_rule *r1,
+			  struct ieee80211_reg_rule *r2)
+{
+	/* for simplicity, currently consider only same flags */
+	if (r1->flags != r2->flags)
+		return false;
+
+	/* verify r1 is more restrictive */
+	if ((r1->power_rule.max_antenna_gain >
+	     r2->power_rule.max_antenna_gain) ||
+	    r1->power_rule.max_eirp > r2->power_rule.max_eirp)
+		return false;
+
+	/* make sure r2's range is contained within r1 */
+	if (r1->freq_range.start_freq_khz > r2->freq_range.start_freq_khz ||
+	    r1->freq_range.end_freq_khz < r2->freq_range.end_freq_khz)
+		return false;
+
+	/* and finally verify that r1.max_bw >= r2.max_bw */
+	if (r1->freq_range.max_bandwidth_khz <
+	    r2->freq_range.max_bandwidth_khz)
+		return false;
+
+	return true;
+}
+
+/* add or extend current rules. do nothing if rule is already contained */
+static void add_rule(struct ieee80211_reg_rule *rule,
+		     struct ieee80211_reg_rule *reg_rules, u32 *n_rules)
+{
+	struct ieee80211_reg_rule *tmp_rule;
+	int i;
+
+	for (i = 0; i < *n_rules; i++) {
+		tmp_rule = &reg_rules[i];
+		/* rule is already contained - do nothing */
+		if (rule_contains(tmp_rule, rule))
+			return;
+
+		/* extend rule if possible */
+		if (rule_contains(rule, tmp_rule)) {
+			memcpy(tmp_rule, rule, sizeof(*rule));
+			return;
+		}
+	}
+
+	memcpy(&reg_rules[*n_rules], rule, sizeof(*rule));
+	(*n_rules)++;
+}
+
 /**
  * regdom_intersect - do the intersection between two regulatory domains
  * @rd1: first regulatory domain
@@ -817,12 +869,10 @@
 {
 	int r, size_of_regd;
 	unsigned int x, y;
-	unsigned int num_rules = 0, rule_idx = 0;
+	unsigned int num_rules = 0;
 	const struct ieee80211_reg_rule *rule1, *rule2;
-	struct ieee80211_reg_rule *intersected_rule;
+	struct ieee80211_reg_rule intersected_rule;
 	struct ieee80211_regdomain *rd;
-	/* This is just a dummy holder to help us count */
-	struct ieee80211_reg_rule dummy_rule;
 
 	if (!rd1 || !rd2)
 		return NULL;
@@ -840,7 +890,7 @@
 		for (y = 0; y < rd2->n_reg_rules; y++) {
 			rule2 = &rd2->reg_rules[y];
 			if (!reg_rules_intersect(rd1, rd2, rule1, rule2,
-						 &dummy_rule))
+						 &intersected_rule))
 				num_rules++;
 		}
 	}
@@ -855,34 +905,24 @@
 	if (!rd)
 		return NULL;
 
-	for (x = 0; x < rd1->n_reg_rules && rule_idx < num_rules; x++) {
+	for (x = 0; x < rd1->n_reg_rules; x++) {
 		rule1 = &rd1->reg_rules[x];
-		for (y = 0; y < rd2->n_reg_rules && rule_idx < num_rules; y++) {
+		for (y = 0; y < rd2->n_reg_rules; y++) {
 			rule2 = &rd2->reg_rules[y];
-			/*
-			 * This time around instead of using the stack lets
-			 * write to the target rule directly saving ourselves
-			 * a memcpy()
-			 */
-			intersected_rule = &rd->reg_rules[rule_idx];
 			r = reg_rules_intersect(rd1, rd2, rule1, rule2,
-						intersected_rule);
+						&intersected_rule);
 			/*
 			 * No need to memset here the intersected rule here as
 			 * we're not using the stack anymore
 			 */
 			if (r)
 				continue;
-			rule_idx++;
-		}
-	}
 
-	if (rule_idx != num_rules) {
-		kfree(rd);
-		return NULL;
+			add_rule(&intersected_rule, rd->reg_rules,
+				 &rd->n_reg_rules);
+		}
 	}
 
-	rd->n_reg_rules = num_rules;
 	rd->alpha2[0] = '9';
 	rd->alpha2[1] = '8';
 	rd->dfs_region = reg_intersect_dfs_region(rd1->dfs_region,
diff -urN linux/net/wireless/scan.c net-next-2.6/net/wireless/scan.c
--- linux/net/wireless/scan.c	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/scan.c	2014-10-06 10:49:04.364942582 +0200
@@ -2,6 +2,7 @@
  * cfg80211 scan result handling
  *
  * Copyright 2008 Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  */
 #include <linux/kernel.h>
 #include <linux/slab.h>
@@ -884,6 +885,7 @@
 cfg80211_inform_bss_width(struct wiphy *wiphy,
 			  struct ieee80211_channel *rx_channel,
 			  enum nl80211_bss_scan_width scan_width,
+			  enum cfg80211_bss_frame_type ftype,
 			  const u8 *bssid, u64 tsf, u16 capability,
 			  u16 beacon_interval, const u8 *ie, size_t ielen,
 			  s32 signal, gfp_t gfp)
@@ -911,21 +913,32 @@
 	tmp.pub.beacon_interval = beacon_interval;
 	tmp.pub.capability = capability;
 	/*
-	 * Since we do not know here whether the IEs are from a Beacon or Probe
+	 * If we do not know here whether the IEs are from a Beacon or Probe
 	 * Response frame, we need to pick one of the options and only use it
 	 * with the driver that does not provide the full Beacon/Probe Response
 	 * frame. Use Beacon frame pointer to avoid indicating that this should
 	 * override the IEs pointer should we have received an earlier
 	 * indication of Probe Response data.
 	 */
-	ies = kmalloc(sizeof(*ies) + ielen, gfp);
+	ies = kzalloc(sizeof(*ies) + ielen, gfp);
 	if (!ies)
 		return NULL;
 	ies->len = ielen;
 	ies->tsf = tsf;
+	ies->from_beacon = false;
 	memcpy(ies->data, ie, ielen);
 
-	rcu_assign_pointer(tmp.pub.beacon_ies, ies);
+	switch (ftype) {
+	case CFG80211_BSS_FTYPE_BEACON:
+		ies->from_beacon = true;
+		/* fall through to assign */
+	case CFG80211_BSS_FTYPE_UNKNOWN:
+		rcu_assign_pointer(tmp.pub.beacon_ies, ies);
+		break;
+	case CFG80211_BSS_FTYPE_PRESP:
+		rcu_assign_pointer(tmp.pub.proberesp_ies, ies);
+		break;
+	}
 	rcu_assign_pointer(tmp.pub.ies, ies);
 
 	signal_valid = abs(rx_channel->center_freq - channel->center_freq) <=
@@ -982,11 +995,12 @@
 	if (!channel)
 		return NULL;
 
-	ies = kmalloc(sizeof(*ies) + ielen, gfp);
+	ies = kzalloc(sizeof(*ies) + ielen, gfp);
 	if (!ies)
 		return NULL;
 	ies->len = ielen;
 	ies->tsf = le64_to_cpu(mgmt->u.probe_resp.timestamp);
+	ies->from_beacon = ieee80211_is_beacon(mgmt->frame_control);
 	memcpy(ies->data, mgmt->u.probe_resp.variable, ielen);
 
 	if (ieee80211_is_probe_resp(mgmt->frame_control))
diff -urN linux/net/wireless/sme.c net-next-2.6/net/wireless/sme.c
--- linux/net/wireless/sme.c	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/sme.c	2014-10-06 10:49:04.364942582 +0200
@@ -641,7 +641,7 @@
 	}
 
 	if (status != WLAN_STATUS_SUCCESS) {
-		kfree(wdev->connect_keys);
+		kzfree(wdev->connect_keys);
 		wdev->connect_keys = NULL;
 		wdev->ssid_len = 0;
 		if (bss) {
@@ -918,7 +918,7 @@
 	ASSERT_WDEV_LOCK(wdev);
 
 	if (WARN_ON(wdev->connect_keys)) {
-		kfree(wdev->connect_keys);
+		kzfree(wdev->connect_keys);
 		wdev->connect_keys = NULL;
 	}
 
@@ -978,7 +978,7 @@
 
 	ASSERT_WDEV_LOCK(wdev);
 
-	kfree(wdev->connect_keys);
+	kzfree(wdev->connect_keys);
 	wdev->connect_keys = NULL;
 
 	if (wdev->conn)
diff -urN linux/net/wireless/trace.h net-next-2.6/net/wireless/trace.h
--- linux/net/wireless/trace.h	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/trace.h	2014-10-06 10:49:04.364942582 +0200
@@ -1896,6 +1896,51 @@
 		  WIPHY_PR_ARG, NETDEV_PR_ARG, CHAN_DEF_PR_ARG)
 );
 
+TRACE_EVENT(rdev_add_tx_ts,
+	TP_PROTO(struct wiphy *wiphy, struct net_device *netdev,
+		 u8 tsid, const u8 *peer, u8 user_prio, u16 admitted_time),
+	TP_ARGS(wiphy, netdev, tsid, peer, user_prio, admitted_time),
+	TP_STRUCT__entry(
+		WIPHY_ENTRY
+		NETDEV_ENTRY
+		MAC_ENTRY(peer)
+		__field(u8, tsid)
+		__field(u8, user_prio)
+		__field(u16, admitted_time)
+	),
+	TP_fast_assign(
+		WIPHY_ASSIGN;
+		NETDEV_ASSIGN;
+		MAC_ASSIGN(peer, peer);
+		__entry->tsid = tsid;
+		__entry->user_prio = user_prio;
+		__entry->admitted_time = admitted_time;
+	),
+	TP_printk(WIPHY_PR_FMT ", " NETDEV_PR_FMT ", " MAC_PR_FMT ", TSID %d, UP %d, time %d",
+		  WIPHY_PR_ARG, NETDEV_PR_ARG, MAC_PR_ARG(peer),
+		  __entry->tsid, __entry->user_prio, __entry->admitted_time)
+);
+
+TRACE_EVENT(rdev_del_tx_ts,
+	TP_PROTO(struct wiphy *wiphy, struct net_device *netdev,
+		 u8 tsid, const u8 *peer),
+	TP_ARGS(wiphy, netdev, tsid, peer),
+	TP_STRUCT__entry(
+		WIPHY_ENTRY
+		NETDEV_ENTRY
+		MAC_ENTRY(peer)
+		__field(u8, tsid)
+	),
+	TP_fast_assign(
+		WIPHY_ASSIGN;
+		NETDEV_ASSIGN;
+		MAC_ASSIGN(peer, peer);
+		__entry->tsid = tsid;
+	),
+	TP_printk(WIPHY_PR_FMT ", " NETDEV_PR_FMT ", " MAC_PR_FMT ", TSID %d",
+		  WIPHY_PR_ARG, NETDEV_PR_ARG, MAC_PR_ARG(peer), __entry->tsid)
+);
+
 /*************************************************************
  *	     cfg80211 exported functions traces		     *
  *************************************************************/
diff -urN linux/net/wireless/util.c net-next-2.6/net/wireless/util.c
--- linux/net/wireless/util.c	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/util.c	2014-10-06 10:49:04.364942582 +0200
@@ -2,6 +2,7 @@
  * Wireless utility functions
  *
  * Copyright 2007-2009	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  */
 #include <linux/export.h>
 #include <linux/bitops.h>
@@ -796,7 +797,7 @@
 				netdev_err(dev, "failed to set mgtdef %d\n", i);
 	}
 
-	kfree(wdev->connect_keys);
+	kzfree(wdev->connect_keys);
 	wdev->connect_keys = NULL;
 }
 
diff -urN linux/net/wireless/wext-compat.c net-next-2.6/net/wireless/wext-compat.c
--- linux/net/wireless/wext-compat.c	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/wext-compat.c	2014-10-06 10:49:04.364942582 +0200
@@ -496,6 +496,8 @@
 			err = 0;
 		if (!err) {
 			if (!addr) {
+				memset(wdev->wext.keys->data[idx], 0,
+				       sizeof(wdev->wext.keys->data[idx]));
 				wdev->wext.keys->params[idx].key_len = 0;
 				wdev->wext.keys->params[idx].cipher = 0;
 			}
diff -urN linux/net/wireless/wext-sme.c net-next-2.6/net/wireless/wext-sme.c
--- linux/net/wireless/wext-sme.c	2014-09-24 09:52:44.368656845 +0200
+++ net-next-2.6/net/wireless/wext-sme.c	2014-10-06 10:49:04.364942582 +0200
@@ -57,7 +57,7 @@
 	err = cfg80211_connect(rdev, wdev->netdev,
 			       &wdev->wext.connect, ck, prev_bssid);
 	if (err)
-		kfree(ck);
+		kzfree(ck);
 
 	return err;
 }
