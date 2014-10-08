diff -urN linux/net/mac80211/agg-rx.c net-next-2.6/net/mac80211/agg-rx.c
--- linux/net/mac80211/agg-rx.c	2014-09-24 09:52:43.220644795 +0200
+++ net-next-2.6/net/mac80211/agg-rx.c	2014-10-06 10:49:03.000928682 +0200
@@ -227,7 +227,7 @@
 void __ieee80211_start_rx_ba_session(struct sta_info *sta,
 				     u8 dialog_token, u16 timeout,
 				     u16 start_seq_num, u16 ba_policy, u16 tid,
-				     u16 buf_size, bool tx)
+				     u16 buf_size, bool tx, bool auto_seq)
 {
 	struct ieee80211_local *local = sta->sdata->local;
 	struct tid_ampdu_rx *tid_agg_rx;
@@ -326,6 +326,7 @@
 	tid_agg_rx->buf_size = buf_size;
 	tid_agg_rx->timeout = timeout;
 	tid_agg_rx->stored_mpdu_num = 0;
+	tid_agg_rx->auto_seq = auto_seq;
 	status = WLAN_STATUS_SUCCESS;
 
 	/* activate it for RX */
@@ -367,7 +368,7 @@
 
 	__ieee80211_start_rx_ba_session(sta, dialog_token, timeout,
 					start_seq_num, ba_policy, tid,
-					buf_size, true);
+					buf_size, true, false);
 }
 
 void ieee80211_start_rx_ba_session_offl(struct ieee80211_vif *vif,
diff -urN linux/net/mac80211/cfg.c net-next-2.6/net/mac80211/cfg.c
--- linux/net/mac80211/cfg.c	2014-09-24 09:52:43.220644795 +0200
+++ net-next-2.6/net/mac80211/cfg.c	2014-10-06 10:49:03.000928682 +0200
@@ -2,6 +2,7 @@
  * mac80211 configuration hooks for cfg80211
  *
  * Copyright 2006-2010	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This file is GPLv2 as found in COPYING.
  */
@@ -682,8 +683,19 @@
 	if (old)
 		return -EALREADY;
 
-	/* TODO: make hostapd tell us what it wants */
-	sdata->smps_mode = IEEE80211_SMPS_OFF;
+	switch (params->smps_mode) {
+	case NL80211_SMPS_OFF:
+		sdata->smps_mode = IEEE80211_SMPS_OFF;
+		break;
+	case NL80211_SMPS_STATIC:
+		sdata->smps_mode = IEEE80211_SMPS_STATIC;
+		break;
+	case NL80211_SMPS_DYNAMIC:
+		sdata->smps_mode = IEEE80211_SMPS_DYNAMIC;
+		break;
+	default:
+		return -EINVAL;
+	}
 	sdata->needed_rx_chains = sdata->local->rx_chains;
 
 	mutex_lock(&local->mtx);
@@ -1011,15 +1023,8 @@
 			clear_sta_flag(sta, WLAN_STA_SHORT_PREAMBLE);
 	}
 
-	if (mask & BIT(NL80211_STA_FLAG_WME)) {
-		if (set & BIT(NL80211_STA_FLAG_WME)) {
-			set_sta_flag(sta, WLAN_STA_WME);
-			sta->sta.wme = true;
-		} else {
-			clear_sta_flag(sta, WLAN_STA_WME);
-			sta->sta.wme = false;
-		}
-	}
+	if (mask & BIT(NL80211_STA_FLAG_WME))
+		sta->sta.wme = set & BIT(NL80211_STA_FLAG_WME);
 
 	if (mask & BIT(NL80211_STA_FLAG_MFP)) {
 		if (set & BIT(NL80211_STA_FLAG_MFP))
@@ -1984,8 +1989,13 @@
 			return err;
 	}
 
-	if (changed & WIPHY_PARAM_COVERAGE_CLASS) {
-		err = drv_set_coverage_class(local, wiphy->coverage_class);
+	if ((changed & WIPHY_PARAM_COVERAGE_CLASS) ||
+	    (changed & WIPHY_PARAM_DYN_ACK)) {
+		s16 coverage_class;
+
+		coverage_class = changed & WIPHY_PARAM_COVERAGE_CLASS ?
+					wiphy->coverage_class : -1;
+		err = drv_set_coverage_class(local, coverage_class);
 
 		if (err)
 			return err;
@@ -2358,6 +2368,58 @@
 	return 0;
 }
 
+static bool ieee80211_coalesce_started_roc(struct ieee80211_local *local,
+					   struct ieee80211_roc_work *new_roc,
+					   struct ieee80211_roc_work *cur_roc)
+{
+	unsigned long j = jiffies;
+	unsigned long cur_roc_end = cur_roc->hw_start_time +
+				    msecs_to_jiffies(cur_roc->duration);
+	struct ieee80211_roc_work *next_roc;
+	int new_dur;
+
+	if (WARN_ON(!cur_roc->started || !cur_roc->hw_begun))
+		return false;
+
+	if (time_after(j + IEEE80211_ROC_MIN_LEFT, cur_roc_end))
+		return false;
+
+	ieee80211_handle_roc_started(new_roc);
+
+	new_dur = new_roc->duration - jiffies_to_msecs(cur_roc_end - j);
+
+	/* cur_roc is long enough - add new_roc to the dependents list. */
+	if (new_dur <= 0) {
+		list_add_tail(&new_roc->list, &cur_roc->dependents);
+		return true;
+	}
+
+	new_roc->duration = new_dur;
+
+	/*
+	 * if cur_roc was already coalesced before, we might
+	 * want to extend the next roc instead of adding
+	 * a new one.
+	 */
+	next_roc = list_entry(cur_roc->list.next,
+			      struct ieee80211_roc_work, list);
+	if (&next_roc->list != &local->roc_list &&
+	    next_roc->chan == new_roc->chan &&
+	    next_roc->sdata == new_roc->sdata &&
+	    !WARN_ON(next_roc->started)) {
+		list_add_tail(&new_roc->list, &next_roc->dependents);
+		next_roc->duration = max(next_roc->duration,
+					 new_roc->duration);
+		next_roc->type = max(next_roc->type, new_roc->type);
+		return true;
+	}
+
+	/* add right after cur_roc */
+	list_add(&new_roc->list, &cur_roc->list);
+
+	return true;
+}
+
 static int ieee80211_start_roc_work(struct ieee80211_local *local,
 				    struct ieee80211_sub_if_data *sdata,
 				    struct ieee80211_channel *channel,
@@ -2463,8 +2525,6 @@
 
 		/* If it has already started, it's more difficult ... */
 		if (local->ops->remain_on_channel) {
-			unsigned long j = jiffies;
-
 			/*
 			 * In the offloaded ROC case, if it hasn't begun, add
 			 * this new one to the dependent list to be handled
@@ -2487,28 +2547,8 @@
 				break;
 			}
 
-			if (time_before(j + IEEE80211_ROC_MIN_LEFT,
-					tmp->hw_start_time +
-					msecs_to_jiffies(tmp->duration))) {
-				int new_dur;
-
-				ieee80211_handle_roc_started(roc);
-
-				new_dur = roc->duration -
-					  jiffies_to_msecs(tmp->hw_start_time +
-							   msecs_to_jiffies(
-								tmp->duration) -
-							   j);
-
-				if (new_dur > 0) {
-					/* add right after tmp */
-					list_add(&roc->list, &tmp->list);
-				} else {
-					list_add_tail(&roc->list,
-						      &tmp->dependents);
-				}
+			if (ieee80211_coalesce_started_roc(local, roc, tmp))
 				queued = true;
-			}
 		} else if (del_timer_sync(&tmp->work.timer)) {
 			unsigned long new_end;
 
@@ -3352,7 +3392,7 @@
 	band = chanctx_conf->def.chan->band;
 	sta = sta_info_get_bss(sdata, peer);
 	if (sta) {
-		qos = test_sta_flag(sta, WLAN_STA_WME);
+		qos = sta->sta.wme;
 	} else {
 		rcu_read_unlock();
 		return -ENOLINK;
diff -urN linux/net/mac80211/chan.c net-next-2.6/net/mac80211/chan.c
--- linux/net/mac80211/chan.c	2014-09-24 09:52:43.220644795 +0200
+++ net-next-2.6/net/mac80211/chan.c	2014-10-06 10:49:03.000928682 +0200
@@ -549,12 +549,12 @@
 
 		compat = cfg80211_chandef_compatible(
 				&sdata->vif.bss_conf.chandef, compat);
-		if (!compat)
+		if (WARN_ON_ONCE(!compat))
 			break;
 	}
 	rcu_read_unlock();
 
-	if (WARN_ON_ONCE(!compat))
+	if (!compat)
 		return;
 
 	ieee80211_change_chanctx(local, ctx, compat);
@@ -639,41 +639,6 @@
 	return ret;
 }
 
-static void __ieee80211_vif_release_channel(struct ieee80211_sub_if_data *sdata)
-{
-	struct ieee80211_local *local = sdata->local;
-	struct ieee80211_chanctx_conf *conf;
-	struct ieee80211_chanctx *ctx;
-	bool use_reserved_switch = false;
-
-	lockdep_assert_held(&local->chanctx_mtx);
-
-	conf = rcu_dereference_protected(sdata->vif.chanctx_conf,
-					 lockdep_is_held(&local->chanctx_mtx));
-	if (!conf)
-		return;
-
-	ctx = container_of(conf, struct ieee80211_chanctx, conf);
-
-	if (sdata->reserved_chanctx) {
-		if (sdata->reserved_chanctx->replace_state ==
-		    IEEE80211_CHANCTX_REPLACES_OTHER &&
-		    ieee80211_chanctx_num_reserved(local,
-						   sdata->reserved_chanctx) > 1)
-			use_reserved_switch = true;
-
-		ieee80211_vif_unreserve_chanctx(sdata);
-	}
-
-	ieee80211_assign_vif_chanctx(sdata, NULL);
-	if (ieee80211_chanctx_refcount(local, ctx) == 0)
-		ieee80211_free_chanctx(local, ctx);
-
-	/* Unreserving may ready an in-place reservation. */
-	if (use_reserved_switch)
-		ieee80211_vif_use_reserved_switch(local);
-}
-
 void ieee80211_recalc_smps_chanctx(struct ieee80211_local *local,
 				   struct ieee80211_chanctx *chanctx)
 {
@@ -764,63 +729,6 @@
 	drv_change_chanctx(local, chanctx, IEEE80211_CHANCTX_CHANGE_RX_CHAINS);
 }
 
-int ieee80211_vif_use_channel(struct ieee80211_sub_if_data *sdata,
-			      const struct cfg80211_chan_def *chandef,
-			      enum ieee80211_chanctx_mode mode)
-{
-	struct ieee80211_local *local = sdata->local;
-	struct ieee80211_chanctx *ctx;
-	u8 radar_detect_width = 0;
-	int ret;
-
-	lockdep_assert_held(&local->mtx);
-
-	WARN_ON(sdata->dev && netif_carrier_ok(sdata->dev));
-
-	mutex_lock(&local->chanctx_mtx);
-
-	ret = cfg80211_chandef_dfs_required(local->hw.wiphy,
-					    chandef,
-					    sdata->wdev.iftype);
-	if (ret < 0)
-		goto out;
-	if (ret > 0)
-		radar_detect_width = BIT(chandef->width);
-
-	sdata->radar_required = ret;
-
-	ret = ieee80211_check_combinations(sdata, chandef, mode,
-					   radar_detect_width);
-	if (ret < 0)
-		goto out;
-
-	__ieee80211_vif_release_channel(sdata);
-
-	ctx = ieee80211_find_chanctx(local, chandef, mode);
-	if (!ctx)
-		ctx = ieee80211_new_chanctx(local, chandef, mode);
-	if (IS_ERR(ctx)) {
-		ret = PTR_ERR(ctx);
-		goto out;
-	}
-
-	sdata->vif.bss_conf.chandef = *chandef;
-
-	ret = ieee80211_assign_vif_chanctx(sdata, ctx);
-	if (ret) {
-		/* if assign fails refcount stays the same */
-		if (ieee80211_chanctx_refcount(local, ctx) == 0)
-			ieee80211_free_chanctx(local, ctx);
-		goto out;
-	}
-
-	ieee80211_recalc_smps_chanctx(local, ctx);
-	ieee80211_recalc_radar_chanctx(local, ctx);
- out:
-	mutex_unlock(&local->chanctx_mtx);
-	return ret;
-}
-
 static void
 __ieee80211_vif_copy_chanctx_to_vlans(struct ieee80211_sub_if_data *sdata,
 				      bool clear)
@@ -1269,8 +1177,7 @@
 	return err;
 }
 
-int
-ieee80211_vif_use_reserved_switch(struct ieee80211_local *local)
+static int ieee80211_vif_use_reserved_switch(struct ieee80211_local *local)
 {
 	struct ieee80211_sub_if_data *sdata, *sdata_tmp;
 	struct ieee80211_chanctx *ctx, *ctx_tmp, *old_ctx;
@@ -1522,6 +1429,98 @@
 	return err;
 }
 
+static void __ieee80211_vif_release_channel(struct ieee80211_sub_if_data *sdata)
+{
+	struct ieee80211_local *local = sdata->local;
+	struct ieee80211_chanctx_conf *conf;
+	struct ieee80211_chanctx *ctx;
+	bool use_reserved_switch = false;
+
+	lockdep_assert_held(&local->chanctx_mtx);
+
+	conf = rcu_dereference_protected(sdata->vif.chanctx_conf,
+					 lockdep_is_held(&local->chanctx_mtx));
+	if (!conf)
+		return;
+
+	ctx = container_of(conf, struct ieee80211_chanctx, conf);
+
+	if (sdata->reserved_chanctx) {
+		if (sdata->reserved_chanctx->replace_state ==
+		    IEEE80211_CHANCTX_REPLACES_OTHER &&
+		    ieee80211_chanctx_num_reserved(local,
+						   sdata->reserved_chanctx) > 1)
+			use_reserved_switch = true;
+
+		ieee80211_vif_unreserve_chanctx(sdata);
+	}
+
+	ieee80211_assign_vif_chanctx(sdata, NULL);
+	if (ieee80211_chanctx_refcount(local, ctx) == 0)
+		ieee80211_free_chanctx(local, ctx);
+
+	/* Unreserving may ready an in-place reservation. */
+	if (use_reserved_switch)
+		ieee80211_vif_use_reserved_switch(local);
+}
+
+int ieee80211_vif_use_channel(struct ieee80211_sub_if_data *sdata,
+			      const struct cfg80211_chan_def *chandef,
+			      enum ieee80211_chanctx_mode mode)
+{
+	struct ieee80211_local *local = sdata->local;
+	struct ieee80211_chanctx *ctx;
+	u8 radar_detect_width = 0;
+	int ret;
+
+	lockdep_assert_held(&local->mtx);
+
+	WARN_ON(sdata->dev && netif_carrier_ok(sdata->dev));
+
+	mutex_lock(&local->chanctx_mtx);
+
+	ret = cfg80211_chandef_dfs_required(local->hw.wiphy,
+					    chandef,
+					    sdata->wdev.iftype);
+	if (ret < 0)
+		goto out;
+	if (ret > 0)
+		radar_detect_width = BIT(chandef->width);
+
+	sdata->radar_required = ret;
+
+	ret = ieee80211_check_combinations(sdata, chandef, mode,
+					   radar_detect_width);
+	if (ret < 0)
+		goto out;
+
+	__ieee80211_vif_release_channel(sdata);
+
+	ctx = ieee80211_find_chanctx(local, chandef, mode);
+	if (!ctx)
+		ctx = ieee80211_new_chanctx(local, chandef, mode);
+	if (IS_ERR(ctx)) {
+		ret = PTR_ERR(ctx);
+		goto out;
+	}
+
+	sdata->vif.bss_conf.chandef = *chandef;
+
+	ret = ieee80211_assign_vif_chanctx(sdata, ctx);
+	if (ret) {
+		/* if assign fails refcount stays the same */
+		if (ieee80211_chanctx_refcount(local, ctx) == 0)
+			ieee80211_free_chanctx(local, ctx);
+		goto out;
+	}
+
+	ieee80211_recalc_smps_chanctx(local, ctx);
+	ieee80211_recalc_radar_chanctx(local, ctx);
+ out:
+	mutex_unlock(&local->chanctx_mtx);
+	return ret;
+}
+
 int ieee80211_vif_use_reserved_context(struct ieee80211_sub_if_data *sdata)
 {
 	struct ieee80211_local *local = sdata->local;
diff -urN linux/net/mac80211/debugfs.c net-next-2.6/net/mac80211/debugfs.c
--- linux/net/mac80211/debugfs.c	2014-09-24 09:52:43.220644795 +0200
+++ net-next-2.6/net/mac80211/debugfs.c	2014-10-06 10:49:03.036929049 +0200
@@ -3,6 +3,7 @@
  * mac80211 debugfs for wireless PHYs
  *
  * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * GPLv2
  *
@@ -302,11 +303,6 @@
 		sf += scnprintf(buf + sf, mxln - sf, "SUPPORTS_DYNAMIC_PS\n");
 	if (local->hw.flags & IEEE80211_HW_MFP_CAPABLE)
 		sf += scnprintf(buf + sf, mxln - sf, "MFP_CAPABLE\n");
-	if (local->hw.flags & IEEE80211_HW_SUPPORTS_STATIC_SMPS)
-		sf += scnprintf(buf + sf, mxln - sf, "SUPPORTS_STATIC_SMPS\n");
-	if (local->hw.flags & IEEE80211_HW_SUPPORTS_DYNAMIC_SMPS)
-		sf += scnprintf(buf + sf, mxln - sf,
-				"SUPPORTS_DYNAMIC_SMPS\n");
 	if (local->hw.flags & IEEE80211_HW_SUPPORTS_UAPSD)
 		sf += scnprintf(buf + sf, mxln - sf, "SUPPORTS_UAPSD\n");
 	if (local->hw.flags & IEEE80211_HW_REPORTS_TX_ACK_STATUS)
diff -urN linux/net/mac80211/debugfs_netdev.c net-next-2.6/net/mac80211/debugfs_netdev.c
--- linux/net/mac80211/debugfs_netdev.c	2014-09-24 09:52:43.220644795 +0200
+++ net-next-2.6/net/mac80211/debugfs_netdev.c	2014-10-06 10:49:03.036929049 +0200
@@ -226,12 +226,12 @@
 	struct ieee80211_local *local = sdata->local;
 	int err;
 
-	if (!(local->hw.flags & IEEE80211_HW_SUPPORTS_STATIC_SMPS) &&
+	if (!(local->hw.wiphy->features & NL80211_FEATURE_STATIC_SMPS) &&
 	    smps_mode == IEEE80211_SMPS_STATIC)
 		return -EINVAL;
 
 	/* auto should be dynamic if in PS mode */
-	if (!(local->hw.flags & IEEE80211_HW_SUPPORTS_DYNAMIC_SMPS) &&
+	if (!(local->hw.wiphy->features & NL80211_FEATURE_DYNAMIC_SMPS) &&
 	    (smps_mode == IEEE80211_SMPS_DYNAMIC ||
 	     smps_mode == IEEE80211_SMPS_AUTOMATIC))
 		return -EINVAL;
diff -urN linux/net/mac80211/debugfs_sta.c net-next-2.6/net/mac80211/debugfs_sta.c
--- linux/net/mac80211/debugfs_sta.c	2014-09-24 09:52:43.220644795 +0200
+++ net-next-2.6/net/mac80211/debugfs_sta.c	2014-10-06 10:49:03.036929049 +0200
@@ -2,6 +2,7 @@
  * Copyright 2003-2005	Devicescape Software, Inc.
  * Copyright (c) 2006	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -77,7 +78,8 @@
 			    TEST(AUTH), TEST(ASSOC), TEST(PS_STA),
 			    TEST(PS_DRIVER), TEST(AUTHORIZED),
 			    TEST(SHORT_PREAMBLE),
-			    TEST(WME), TEST(WDS), TEST(CLEAR_PS_FILT),
+			    sta->sta.wme ? "WME\n" : "",
+			    TEST(WDS), TEST(CLEAR_PS_FILT),
 			    TEST(MFP), TEST(BLOCK_BA), TEST(PSPOLL),
 			    TEST(UAPSD), TEST(SP), TEST(TDLS_PEER),
 			    TEST(TDLS_PEER_AUTH), TEST(4ADDR_EVENT),
diff -urN linux/net/mac80211/driver-ops.h net-next-2.6/net/mac80211/driver-ops.h
--- linux/net/mac80211/driver-ops.h	2014-09-24 09:52:43.220644795 +0200
+++ net-next-2.6/net/mac80211/driver-ops.h	2014-10-06 10:49:03.036929049 +0200
@@ -450,7 +450,7 @@
 }
 
 static inline int drv_set_coverage_class(struct ieee80211_local *local,
-					 u8 value)
+					 s16 value)
 {
 	int ret = 0;
 	might_sleep();
diff -urN linux/net/mac80211/ibss.c net-next-2.6/net/mac80211/ibss.c
--- linux/net/mac80211/ibss.c	2014-09-24 09:52:43.224644837 +0200
+++ net-next-2.6/net/mac80211/ibss.c	2014-10-06 10:49:03.036929049 +0200
@@ -6,6 +6,7 @@
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007, Michael Wu <flamingice@sourmilk.net>
  * Copyright 2009, Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -1038,7 +1039,7 @@
 		}
 
 		if (sta && elems->wmm_info)
-			set_sta_flag(sta, WLAN_STA_WME);
+			sta->sta.wme = true;
 
 		if (sta && elems->ht_operation && elems->ht_cap_elem &&
 		    sdata->u.ibss.chandef.width != NL80211_CHAN_WIDTH_20_NOHT &&
diff -urN linux/net/mac80211/ieee80211_i.h net-next-2.6/net/mac80211/ieee80211_i.h
--- linux/net/mac80211/ieee80211_i.h	2014-09-24 09:52:43.224644837 +0200
+++ net-next-2.6/net/mac80211/ieee80211_i.h	2014-10-06 10:49:03.036929049 +0200
@@ -3,6 +3,7 @@
  * Copyright 2005, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007-2010	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -354,6 +355,7 @@
 	IEEE80211_STA_DISABLE_80P80MHZ	= BIT(12),
 	IEEE80211_STA_DISABLE_160MHZ	= BIT(13),
 	IEEE80211_STA_DISABLE_WMM	= BIT(14),
+	IEEE80211_STA_ENABLE_RRM	= BIT(15),
 };
 
 struct ieee80211_mgd_auth_data {
@@ -1367,6 +1369,7 @@
 	const struct ieee80211_wide_bw_chansw_ie *wide_bw_chansw_ie;
 	const u8 *country_elem;
 	const u8 *pwr_constr_elem;
+	const u8 *cisco_dtpc_elem;
 	const struct ieee80211_timeout_interval_ie *timeout_int;
 	const u8 *opmode_notif;
 	const struct ieee80211_sec_chan_offs_ie *sec_chan_offs;
@@ -1587,7 +1590,7 @@
 void __ieee80211_start_rx_ba_session(struct sta_info *sta,
 				     u8 dialog_token, u16 timeout,
 				     u16 start_seq_num, u16 ba_policy, u16 tid,
-				     u16 buf_size, bool tx);
+				     u16 buf_size, bool tx, bool auto_seq);
 void ieee80211_sta_tear_down_BA_sessions(struct sta_info *sta,
 					 enum ieee80211_agg_stop_reason reason);
 void ieee80211_process_delba(struct ieee80211_sub_if_data *sdata,
@@ -1869,7 +1872,6 @@
 int __must_check
 ieee80211_vif_use_reserved_context(struct ieee80211_sub_if_data *sdata);
 int ieee80211_vif_unreserve_chanctx(struct ieee80211_sub_if_data *sdata);
-int ieee80211_vif_use_reserved_switch(struct ieee80211_local *local);
 
 int __must_check
 ieee80211_vif_change_bandwidth(struct ieee80211_sub_if_data *sdata,
@@ -1918,7 +1920,7 @@
 			size_t extra_ies_len);
 int ieee80211_tdls_oper(struct wiphy *wiphy, struct net_device *dev,
 			const u8 *peer, enum nl80211_tdls_operation oper);
-
+void ieee80211_tdls_peer_del_work(struct work_struct *wk);
 
 extern const struct ethtool_ops ieee80211_ethtool_ops;
 
@@ -1929,4 +1931,3 @@
 #endif
 
 #endif /* IEEE80211_I_H */
-void ieee80211_tdls_peer_del_work(struct work_struct *wk);
diff -urN linux/net/mac80211/iface.c net-next-2.6/net/mac80211/iface.c
--- linux/net/mac80211/iface.c	2014-09-24 09:52:43.224644837 +0200
+++ net-next-2.6/net/mac80211/iface.c	2014-10-06 10:49:03.036929049 +0200
@@ -5,6 +5,7 @@
  * Copyright 2005-2006, Devicescape Software, Inc.
  * Copyright (c) 2006 Jiri Benc <jbenc@suse.cz>
  * Copyright 2008, Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -1172,19 +1173,11 @@
 			rx_agg = (void *)&skb->cb;
 			mutex_lock(&local->sta_mtx);
 			sta = sta_info_get_bss(sdata, rx_agg->addr);
-			if (sta) {
-				u16 last_seq;
-
-				last_seq = IEEE80211_SEQ_TO_SN(le16_to_cpu(
-					sta->last_seq_ctrl[rx_agg->tid]));
-
+			if (sta)
 				__ieee80211_start_rx_ba_session(sta,
-						0, 0,
-						ieee80211_sn_inc(last_seq),
-						1, rx_agg->tid,
+						0, 0, 0, 1, rx_agg->tid,
 						IEEE80211_MAX_AMPDU_BUF,
-						false);
-			}
+						false, true);
 			mutex_unlock(&local->sta_mtx);
 		} else if (skb->pkt_type == IEEE80211_SDATA_QUEUE_RX_AGG_STOP) {
 			rx_agg = (void *)&skb->cb;
diff -urN linux/net/mac80211/key.c net-next-2.6/net/mac80211/key.c
--- linux/net/mac80211/key.c	2014-09-24 09:52:43.224644837 +0200
+++ net-next-2.6/net/mac80211/key.c	2014-10-06 10:49:03.036929049 +0200
@@ -3,6 +3,7 @@
  * Copyright 2005-2006, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007-2008	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -130,9 +131,7 @@
 	if (!ret) {
 		key->flags |= KEY_FLAG_UPLOADED_TO_HARDWARE;
 
-		if (!((key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_MMIC) ||
-		      (key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_IV) ||
-		      (key->conf.flags & IEEE80211_KEY_FLAG_PUT_IV_SPACE)))
+		if (!(key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_MMIC))
 			sdata->crypto_tx_tailroom_needed_cnt--;
 
 		WARN_ON((key->conf.flags & IEEE80211_KEY_FLAG_PUT_IV_SPACE) &&
@@ -180,9 +179,7 @@
 	sta = key->sta;
 	sdata = key->sdata;
 
-	if (!((key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_MMIC) ||
-	      (key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_IV) ||
-	      (key->conf.flags & IEEE80211_KEY_FLAG_PUT_IV_SPACE)))
+	if (!(key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_MMIC))
 		increment_tailroom_need_count(sdata);
 
 	ret = drv_set_key(key->local, DISABLE_KEY, sdata,
@@ -425,7 +422,7 @@
 		ieee80211_aes_key_free(key->u.ccmp.tfm);
 	if (key->conf.cipher == WLAN_CIPHER_SUITE_AES_CMAC)
 		ieee80211_aes_cmac_key_free(key->u.aes_cmac.tfm);
-	kfree(key);
+	kzfree(key);
 }
 
 static void __ieee80211_key_destroy(struct ieee80211_key *key,
@@ -878,9 +875,7 @@
 	if (key->flags & KEY_FLAG_UPLOADED_TO_HARDWARE) {
 		key->flags &= ~KEY_FLAG_UPLOADED_TO_HARDWARE;
 
-		if (!((key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_MMIC) ||
-		      (key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_IV) ||
-		      (key->conf.flags & IEEE80211_KEY_FLAG_PUT_IV_SPACE)))
+		if (!(key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_MMIC))
 			increment_tailroom_need_count(key->sdata);
 	}
 
diff -urN linux/net/mac80211/main.c net-next-2.6/net/mac80211/main.c
--- linux/net/mac80211/main.c	2014-09-24 09:52:43.224644837 +0200
+++ net-next-2.6/net/mac80211/main.c	2014-10-06 10:49:03.072929415 +0200
@@ -2,6 +2,7 @@
  * Copyright 2002-2005, Instant802 Networks, Inc.
  * Copyright 2005-2006, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
diff -urN linux/net/mac80211/mesh_pathtbl.c net-next-2.6/net/mac80211/mesh_pathtbl.c
--- linux/net/mac80211/mesh_pathtbl.c	2014-09-24 09:52:43.224644837 +0200
+++ net-next-2.6/net/mac80211/mesh_pathtbl.c	2014-10-06 10:49:03.072929415 +0200
@@ -729,7 +729,7 @@
 	tbl = rcu_dereference(mesh_paths);
 	for_each_mesh_entry(tbl, node, i) {
 		mpath = node->mpath;
-		if (rcu_dereference(mpath->next_hop) == sta &&
+		if (rcu_access_pointer(mpath->next_hop) == sta &&
 		    mpath->flags & MESH_PATH_ACTIVE &&
 		    !(mpath->flags & MESH_PATH_FIXED)) {
 			spin_lock_bh(&mpath->state_lock);
@@ -794,7 +794,7 @@
 	tbl = resize_dereference_mesh_paths();
 	for_each_mesh_entry(tbl, node, i) {
 		mpath = node->mpath;
-		if (rcu_dereference(mpath->next_hop) == sta) {
+		if (rcu_access_pointer(mpath->next_hop) == sta) {
 			spin_lock(&tbl->hashwlock[i]);
 			__mesh_path_del(tbl, node);
 			spin_unlock(&tbl->hashwlock[i]);
diff -urN linux/net/mac80211/mesh_plink.c net-next-2.6/net/mac80211/mesh_plink.c
--- linux/net/mac80211/mesh_plink.c	2014-09-24 09:52:43.224644837 +0200
+++ net-next-2.6/net/mac80211/mesh_plink.c	2014-10-06 10:49:03.360932351 +0200
@@ -431,14 +431,12 @@
 		return NULL;
 
 	sta->plink_state = NL80211_PLINK_LISTEN;
+	sta->sta.wme = true;
 
 	sta_info_pre_move_state(sta, IEEE80211_STA_AUTH);
 	sta_info_pre_move_state(sta, IEEE80211_STA_ASSOC);
 	sta_info_pre_move_state(sta, IEEE80211_STA_AUTHORIZED);
 
-	set_sta_flag(sta, WLAN_STA_WME);
-	sta->sta.wme = true;
-
 	return sta;
 }
 
@@ -1004,7 +1002,6 @@
 	enum ieee80211_self_protected_actioncode ftype;
 	u32 changed = 0;
 	u8 ie_len = elems->peering_len;
-	__le16 _plid, _llid;
 	u16 plid, llid = 0;
 
 	if (!elems->peering) {
@@ -1039,13 +1036,10 @@
 	/* Note the lines below are correct, the llid in the frame is the plid
 	 * from the point of view of this host.
 	 */
-	memcpy(&_plid, PLINK_GET_LLID(elems->peering), sizeof(__le16));
-	plid = le16_to_cpu(_plid);
+	plid = get_unaligned_le16(PLINK_GET_LLID(elems->peering));
 	if (ftype == WLAN_SP_MESH_PEERING_CONFIRM ||
-	    (ftype == WLAN_SP_MESH_PEERING_CLOSE && ie_len == 8)) {
-		memcpy(&_llid, PLINK_GET_PLID(elems->peering), sizeof(__le16));
-		llid = le16_to_cpu(_llid);
-	}
+	    (ftype == WLAN_SP_MESH_PEERING_CLOSE && ie_len == 8))
+		llid = get_unaligned_le16(PLINK_GET_PLID(elems->peering));
 
 	/* WARNING: Only for sta pointer, is dropped & re-acquired */
 	rcu_read_lock();
diff -urN linux/net/mac80211/mlme.c net-next-2.6/net/mac80211/mlme.c
--- linux/net/mac80211/mlme.c	2014-09-24 09:52:43.228644878 +0200
+++ net-next-2.6/net/mac80211/mlme.c	2014-10-06 10:49:03.360932351 +0200
@@ -5,6 +5,7 @@
  * Copyright 2005, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007, Michael Wu <flamingice@sourmilk.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -149,6 +150,7 @@
 ieee80211_determine_chantype(struct ieee80211_sub_if_data *sdata,
 			     struct ieee80211_supported_band *sband,
 			     struct ieee80211_channel *channel,
+			     const struct ieee80211_ht_cap *ht_cap,
 			     const struct ieee80211_ht_operation *ht_oper,
 			     const struct ieee80211_vht_operation *vht_oper,
 			     struct cfg80211_chan_def *chandef, bool tracking)
@@ -162,13 +164,19 @@
 	chandef->center_freq1 = channel->center_freq;
 	chandef->center_freq2 = 0;
 
-	if (!ht_oper || !sband->ht_cap.ht_supported) {
+	if (!ht_cap || !ht_oper || !sband->ht_cap.ht_supported) {
 		ret = IEEE80211_STA_DISABLE_HT | IEEE80211_STA_DISABLE_VHT;
 		goto out;
 	}
 
 	chandef->width = NL80211_CHAN_WIDTH_20;
 
+	if (!(ht_cap->cap_info &
+	      cpu_to_le16(IEEE80211_HT_CAP_SUP_WIDTH_20_40))) {
+		ret = IEEE80211_STA_DISABLE_40MHZ;
+		goto out;
+	}
+
 	ht_cfreq = ieee80211_channel_to_frequency(ht_oper->primary_chan,
 						  channel->band);
 	/* check that channel matches the right operating channel */
@@ -328,6 +336,7 @@
 
 static int ieee80211_config_bw(struct ieee80211_sub_if_data *sdata,
 			       struct sta_info *sta,
+			       const struct ieee80211_ht_cap *ht_cap,
 			       const struct ieee80211_ht_operation *ht_oper,
 			       const struct ieee80211_vht_operation *vht_oper,
 			       const u8 *bssid, u32 *changed)
@@ -367,8 +376,9 @@
 	sband = local->hw.wiphy->bands[chan->band];
 
 	/* calculate new channel (type) based on HT/VHT operation IEs */
-	flags = ieee80211_determine_chantype(sdata, sband, chan, ht_oper,
-					     vht_oper, &chandef, true);
+	flags = ieee80211_determine_chantype(sdata, sband, chan,
+					     ht_cap, ht_oper, vht_oper,
+					     &chandef, true);
 
 	/*
 	 * Downgrade the new channel if we associated with restricted
@@ -663,6 +673,9 @@
 	    (local->hw.flags & IEEE80211_HW_SPECTRUM_MGMT))
 		capab |= WLAN_CAPABILITY_SPECTRUM_MGMT;
 
+	if (ifmgd->flags & IEEE80211_STA_ENABLE_RRM)
+		capab |= WLAN_CAPABILITY_RADIO_MEASURE;
+
 	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
 	memset(mgmt, 0, 24);
 	memcpy(mgmt->da, assoc_data->bss->bssid, ETH_ALEN);
@@ -728,16 +741,17 @@
 		}
 	}
 
-	if (capab & WLAN_CAPABILITY_SPECTRUM_MGMT) {
-		/* 1. power capabilities */
+	if (capab & WLAN_CAPABILITY_SPECTRUM_MGMT ||
+	    capab & WLAN_CAPABILITY_RADIO_MEASURE) {
 		pos = skb_put(skb, 4);
 		*pos++ = WLAN_EID_PWR_CAPABILITY;
 		*pos++ = 2;
 		*pos++ = 0; /* min tx power */
 		 /* max tx power */
 		*pos++ = ieee80211_chandef_max_power(&chanctx_conf->def);
+	}
 
-		/* 2. supported channels */
+	if (capab & WLAN_CAPABILITY_SPECTRUM_MGMT) {
 		/* TODO: get this in reg domain format */
 		pos = skb_put(skb, 2 * sband->n_channels + 2);
 		*pos++ = WLAN_EID_SUPPORTED_CHANNELS;
@@ -1157,19 +1171,21 @@
 			  TU_TO_EXP_TIME(csa_ie.count * cbss->beacon_interval));
 }
 
-static u32 ieee80211_handle_pwr_constr(struct ieee80211_sub_if_data *sdata,
-				       struct ieee80211_channel *channel,
-				       const u8 *country_ie, u8 country_ie_len,
-				       const u8 *pwr_constr_elem)
+static bool
+ieee80211_find_80211h_pwr_constr(struct ieee80211_sub_if_data *sdata,
+				 struct ieee80211_channel *channel,
+				 const u8 *country_ie, u8 country_ie_len,
+				 const u8 *pwr_constr_elem,
+				 int *chan_pwr, int *pwr_reduction)
 {
 	struct ieee80211_country_ie_triplet *triplet;
 	int chan = ieee80211_frequency_to_channel(channel->center_freq);
-	int i, chan_pwr, chan_increment, new_ap_level;
+	int i, chan_increment;
 	bool have_chan_pwr = false;
 
 	/* Invalid IE */
 	if (country_ie_len % 2 || country_ie_len < IEEE80211_COUNTRY_IE_MIN_LEN)
-		return 0;
+		return false;
 
 	triplet = (void *)(country_ie + 3);
 	country_ie_len -= 3;
@@ -1197,7 +1213,7 @@
 		for (i = 0; i < triplet->chans.num_channels; i++) {
 			if (first_channel + i * chan_increment == chan) {
 				have_chan_pwr = true;
-				chan_pwr = triplet->chans.max_power;
+				*chan_pwr = triplet->chans.max_power;
 				break;
 			}
 		}
@@ -1209,18 +1225,76 @@
 		country_ie_len -= 3;
 	}
 
-	if (!have_chan_pwr)
+	if (have_chan_pwr)
+		*pwr_reduction = *pwr_constr_elem;
+	return have_chan_pwr;
+}
+
+static void ieee80211_find_cisco_dtpc(struct ieee80211_sub_if_data *sdata,
+				      struct ieee80211_channel *channel,
+				      const u8 *cisco_dtpc_ie,
+				      int *pwr_level)
+{
+	/* From practical testing, the first data byte of the DTPC element
+	 * seems to contain the requested dBm level, and the CLI on Cisco
+	 * APs clearly state the range is -127 to 127 dBm, which indicates
+	 * a signed byte, although it seemingly never actually goes negative.
+	 * The other byte seems to always be zero.
+	 */
+	*pwr_level = (__s8)cisco_dtpc_ie[4];
+}
+
+static u32 ieee80211_handle_pwr_constr(struct ieee80211_sub_if_data *sdata,
+				       struct ieee80211_channel *channel,
+				       struct ieee80211_mgmt *mgmt,
+				       const u8 *country_ie, u8 country_ie_len,
+				       const u8 *pwr_constr_ie,
+				       const u8 *cisco_dtpc_ie)
+{
+	bool has_80211h_pwr = false, has_cisco_pwr = false;
+	int chan_pwr = 0, pwr_reduction_80211h = 0;
+	int pwr_level_cisco, pwr_level_80211h;
+	int new_ap_level;
+
+	if (country_ie && pwr_constr_ie &&
+	    mgmt->u.probe_resp.capab_info &
+		cpu_to_le16(WLAN_CAPABILITY_SPECTRUM_MGMT)) {
+		has_80211h_pwr = ieee80211_find_80211h_pwr_constr(
+			sdata, channel, country_ie, country_ie_len,
+			pwr_constr_ie, &chan_pwr, &pwr_reduction_80211h);
+		pwr_level_80211h =
+			max_t(int, 0, chan_pwr - pwr_reduction_80211h);
+	}
+
+	if (cisco_dtpc_ie) {
+		ieee80211_find_cisco_dtpc(
+			sdata, channel, cisco_dtpc_ie, &pwr_level_cisco);
+		has_cisco_pwr = true;
+	}
+
+	if (!has_80211h_pwr && !has_cisco_pwr)
 		return 0;
 
-	new_ap_level = max_t(int, 0, chan_pwr - *pwr_constr_elem);
+	/* If we have both 802.11h and Cisco DTPC, apply both limits
+	 * by picking the smallest of the two power levels advertised.
+	 */
+	if (has_80211h_pwr &&
+	    (!has_cisco_pwr || pwr_level_80211h <= pwr_level_cisco)) {
+		sdata_info(sdata,
+			   "Limiting TX power to %d (%d - %d) dBm as advertised by %pM\n",
+			   pwr_level_80211h, chan_pwr, pwr_reduction_80211h,
+			   sdata->u.mgd.bssid);
+		new_ap_level = pwr_level_80211h;
+	} else {  /* has_cisco_pwr is always true here. */
+		sdata_info(sdata,
+			   "Limiting TX power to %d dBm as advertised by %pM\n",
+			   pwr_level_cisco, sdata->u.mgd.bssid);
+		new_ap_level = pwr_level_cisco;
+	}
 
 	if (sdata->ap_power_level == new_ap_level)
 		return 0;
 
-	sdata_info(sdata,
-		   "Limiting TX power to %d (%d - %d) dBm as advertised by %pM\n",
-		   new_ap_level, chan_pwr, *pwr_constr_elem,
-		   sdata->u.mgd.bssid);
 	sdata->ap_power_level = new_ap_level;
 	if (__ieee80211_recalc_txpower(sdata))
 		return BSS_CHANGED_TXPOWER;
@@ -2677,8 +2751,7 @@
 	if (ifmgd->flags & IEEE80211_STA_MFP_ENABLED)
 		set_sta_flag(sta, WLAN_STA_MFP);
 
-	if (elems.wmm_param)
-		set_sta_flag(sta, WLAN_STA_WME);
+	sta->sta.wme = elems.wmm_param;
 
 	err = sta_info_move_state(sta, IEEE80211_STA_ASSOC);
 	if (!err && !(ifmgd->flags & IEEE80211_STA_CONTROL_PORT))
@@ -2744,6 +2817,7 @@
 	struct ieee80211_mgd_assoc_data *assoc_data = ifmgd->assoc_data;
 	u16 capab_info, status_code, aid;
 	struct ieee802_11_elems elems;
+	int ac, uapsd_queues = -1;
 	u8 *pos;
 	bool reassoc;
 	struct cfg80211_bss *bss;
@@ -2813,9 +2887,15 @@
 		 * is set can cause the interface to go idle
 		 */
 		ieee80211_destroy_assoc_data(sdata, true);
+
+		/* get uapsd queues configuration */
+		uapsd_queues = 0;
+		for (ac = 0; ac < IEEE80211_NUM_ACS; ac++)
+			if (sdata->tx_conf[ac].uapsd)
+				uapsd_queues |= BIT(ac);
 	}
 
-	cfg80211_rx_assoc_resp(sdata->dev, bss, (u8 *)mgmt, len);
+	cfg80211_rx_assoc_resp(sdata->dev, bss, (u8 *)mgmt, len, uapsd_queues);
 }
 
 static void ieee80211_rx_bss_info(struct ieee80211_sub_if_data *sdata,
@@ -2885,7 +2965,9 @@
 /*
  * This is the canonical list of information elements we care about,
  * the filter code also gives us all changes to the Microsoft OUI
- * (00:50:F2) vendor IE which is used for WMM which we need to track.
+ * (00:50:F2) vendor IE which is used for WMM which we need to track,
+ * as well as the DTPC IE (part of the Cisco OUI) used for signaling
+ * changes to requested client power.
  *
  * We implement beacon filtering in software since that means we can
  * avoid processing the frame here and in cfg80211, and userspace
@@ -3174,7 +3256,8 @@
 	mutex_lock(&local->sta_mtx);
 	sta = sta_info_get(sdata, bssid);
 
-	if (ieee80211_config_bw(sdata, sta, elems.ht_operation,
+	if (ieee80211_config_bw(sdata, sta,
+				elems.ht_cap_elem, elems.ht_operation,
 				elems.vht_operation, bssid, &changed)) {
 		mutex_unlock(&local->sta_mtx);
 		ieee80211_set_disassoc(sdata, IEEE80211_STYPE_DEAUTH,
@@ -3190,13 +3273,11 @@
 					    rx_status->band, true);
 	mutex_unlock(&local->sta_mtx);
 
-	if (elems.country_elem && elems.pwr_constr_elem &&
-	    mgmt->u.probe_resp.capab_info &
-				cpu_to_le16(WLAN_CAPABILITY_SPECTRUM_MGMT))
-		changed |= ieee80211_handle_pwr_constr(sdata, chan,
-						       elems.country_elem,
-						       elems.country_elem_len,
-						       elems.pwr_constr_elem);
+	changed |= ieee80211_handle_pwr_constr(sdata, chan, mgmt,
+					       elems.country_elem,
+					       elems.country_elem_len,
+					       elems.pwr_constr_elem,
+					       elems.cisco_dtpc_elem);
 
 	ieee80211_bss_info_change_notify(sdata, changed);
 }
@@ -3724,7 +3805,7 @@
 	ifmgd->uapsd_max_sp_len = sdata->local->hw.uapsd_max_sp_len;
 	ifmgd->p2p_noa_index = -1;
 
-	if (sdata->local->hw.flags & IEEE80211_HW_SUPPORTS_DYNAMIC_SMPS)
+	if (sdata->local->hw.wiphy->features & NL80211_FEATURE_DYNAMIC_SMPS)
 		ifmgd->req_smps = IEEE80211_SMPS_AUTOMATIC;
 	else
 		ifmgd->req_smps = IEEE80211_SMPS_OFF;
@@ -3808,6 +3889,7 @@
 {
 	struct ieee80211_local *local = sdata->local;
 	struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
+	const struct ieee80211_ht_cap *ht_cap = NULL;
 	const struct ieee80211_ht_operation *ht_oper = NULL;
 	const struct ieee80211_vht_operation *vht_oper = NULL;
 	struct ieee80211_supported_band *sband;
@@ -3824,14 +3906,17 @@
 
 	if (!(ifmgd->flags & IEEE80211_STA_DISABLE_HT) &&
 	    sband->ht_cap.ht_supported) {
-		const u8 *ht_oper_ie, *ht_cap;
+		const u8 *ht_oper_ie, *ht_cap_ie;
 
 		ht_oper_ie = ieee80211_bss_get_ie(cbss, WLAN_EID_HT_OPERATION);
 		if (ht_oper_ie && ht_oper_ie[1] >= sizeof(*ht_oper))
 			ht_oper = (void *)(ht_oper_ie + 2);
 
-		ht_cap = ieee80211_bss_get_ie(cbss, WLAN_EID_HT_CAPABILITY);
-		if (!ht_cap || ht_cap[1] < sizeof(struct ieee80211_ht_cap)) {
+		ht_cap_ie = ieee80211_bss_get_ie(cbss, WLAN_EID_HT_CAPABILITY);
+		if (ht_cap_ie && ht_cap_ie[1] >= sizeof(*ht_cap))
+			ht_cap = (void *)(ht_cap_ie + 2);
+
+		if (!ht_cap) {
 			ifmgd->flags |= IEEE80211_STA_DISABLE_HT;
 			ht_oper = NULL;
 		}
@@ -3862,7 +3947,7 @@
 
 	ifmgd->flags |= ieee80211_determine_chantype(sdata, sband,
 						     cbss->channel,
-						     ht_oper, vht_oper,
+						     ht_cap, ht_oper, vht_oper,
 						     &chandef, false);
 
 	sdata->needed_rx_chains = min(ieee80211_ht_vht_rx_chains(sdata, cbss),
@@ -4395,6 +4480,11 @@
 		ifmgd->flags &= ~IEEE80211_STA_MFP_ENABLED;
 	}
 
+	if (req->flags & ASSOC_REQ_USE_RRM)
+		ifmgd->flags |= IEEE80211_STA_ENABLE_RRM;
+	else
+		ifmgd->flags &= ~IEEE80211_STA_ENABLE_RRM;
+
 	if (req->crypto.control_port)
 		ifmgd->flags |= IEEE80211_STA_CONTROL_PORT;
 	else
diff -urN linux/net/mac80211/rc80211_minstrel.c net-next-2.6/net/mac80211/rc80211_minstrel.c
--- linux/net/mac80211/rc80211_minstrel.c	2014-09-24 09:52:43.228644878 +0200
+++ net-next-2.6/net/mac80211/rc80211_minstrel.c	2014-10-06 10:49:03.360932351 +0200
@@ -75,7 +75,7 @@
 {
 	int j = MAX_THR_RATES;
 
-	while (j > 0 && mi->r[i].cur_tp > mi->r[tp_list[j - 1]].cur_tp)
+	while (j > 0 && mi->r[i].stats.cur_tp > mi->r[tp_list[j - 1]].stats.cur_tp)
 		j--;
 	if (j < MAX_THR_RATES - 1)
 		memmove(&tp_list[j + 1], &tp_list[j], MAX_THR_RATES - (j + 1));
@@ -92,7 +92,7 @@
 	ratetbl->rate[offset].idx = r->rix;
 	ratetbl->rate[offset].count = r->adjusted_retry_count;
 	ratetbl->rate[offset].count_cts = r->retry_count_cts;
-	ratetbl->rate[offset].count_rts = r->retry_count_rtscts;
+	ratetbl->rate[offset].count_rts = r->stats.retry_count_rtscts;
 }
 
 static void
@@ -140,44 +140,46 @@
 
 	for (i = 0; i < mi->n_rates; i++) {
 		struct minstrel_rate *mr = &mi->r[i];
+		struct minstrel_rate_stats *mrs = &mi->r[i].stats;
 
 		usecs = mr->perfect_tx_time;
 		if (!usecs)
 			usecs = 1000000;
 
-		if (unlikely(mr->attempts > 0)) {
-			mr->sample_skipped = 0;
-			mr->cur_prob = MINSTREL_FRAC(mr->success, mr->attempts);
-			mr->succ_hist += mr->success;
-			mr->att_hist += mr->attempts;
-			mr->probability = minstrel_ewma(mr->probability,
-							mr->cur_prob,
-							EWMA_LEVEL);
+		if (unlikely(mrs->attempts > 0)) {
+			mrs->sample_skipped = 0;
+			mrs->cur_prob = MINSTREL_FRAC(mrs->success,
+						      mrs->attempts);
+			mrs->succ_hist += mrs->success;
+			mrs->att_hist += mrs->attempts;
+			mrs->probability = minstrel_ewma(mrs->probability,
+							 mrs->cur_prob,
+							 EWMA_LEVEL);
 		} else
-			mr->sample_skipped++;
+			mrs->sample_skipped++;
 
-		mr->last_success = mr->success;
-		mr->last_attempts = mr->attempts;
-		mr->success = 0;
-		mr->attempts = 0;
+		mrs->last_success = mrs->success;
+		mrs->last_attempts = mrs->attempts;
+		mrs->success = 0;
+		mrs->attempts = 0;
 
 		/* Update throughput per rate, reset thr. below 10% success */
-		if (mr->probability < MINSTREL_FRAC(10, 100))
-			mr->cur_tp = 0;
+		if (mrs->probability < MINSTREL_FRAC(10, 100))
+			mrs->cur_tp = 0;
 		else
-			mr->cur_tp = mr->probability * (1000000 / usecs);
+			mrs->cur_tp = mrs->probability * (1000000 / usecs);
 
 		/* Sample less often below the 10% chance of success.
 		 * Sample less often above the 95% chance of success. */
-		if (mr->probability > MINSTREL_FRAC(95, 100) ||
-		    mr->probability < MINSTREL_FRAC(10, 100)) {
-			mr->adjusted_retry_count = mr->retry_count >> 1;
+		if (mrs->probability > MINSTREL_FRAC(95, 100) ||
+		    mrs->probability < MINSTREL_FRAC(10, 100)) {
+			mr->adjusted_retry_count = mrs->retry_count >> 1;
 			if (mr->adjusted_retry_count > 2)
 				mr->adjusted_retry_count = 2;
 			mr->sample_limit = 4;
 		} else {
 			mr->sample_limit = -1;
-			mr->adjusted_retry_count = mr->retry_count;
+			mr->adjusted_retry_count = mrs->retry_count;
 		}
 		if (!mr->adjusted_retry_count)
 			mr->adjusted_retry_count = 2;
@@ -190,11 +192,11 @@
 		 * choose the maximum throughput rate as max_prob_rate
 		 * (2) if all success probabilities < 95%, the rate with
 		 * highest success probability is choosen as max_prob_rate */
-		if (mr->probability >= MINSTREL_FRAC(95, 100)) {
-			if (mr->cur_tp >= mi->r[tmp_prob_rate].cur_tp)
+		if (mrs->probability >= MINSTREL_FRAC(95, 100)) {
+			if (mrs->cur_tp >= mi->r[tmp_prob_rate].stats.cur_tp)
 				tmp_prob_rate = i;
 		} else {
-			if (mr->probability >= mi->r[tmp_prob_rate].probability)
+			if (mrs->probability >= mi->r[tmp_prob_rate].stats.probability)
 				tmp_prob_rate = i;
 		}
 	}
@@ -240,14 +242,14 @@
 		if (ndx < 0)
 			continue;
 
-		mi->r[ndx].attempts += ar[i].count;
+		mi->r[ndx].stats.attempts += ar[i].count;
 
 		if ((i != IEEE80211_TX_MAX_RATES - 1) && (ar[i + 1].idx < 0))
-			mi->r[ndx].success += success;
+			mi->r[ndx].stats.success += success;
 	}
 
 	if ((info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) && (i >= 0))
-		mi->sample_count++;
+		mi->sample_packets++;
 
 	if (mi->sample_deferred > 0)
 		mi->sample_deferred--;
@@ -265,7 +267,7 @@
 	unsigned int retry = mr->adjusted_retry_count;
 
 	if (info->control.use_rts)
-		retry = max(2U, min(mr->retry_count_rtscts, retry));
+		retry = max(2U, min(mr->stats.retry_count_rtscts, retry));
 	else if (info->control.use_cts_prot)
 		retry = max(2U, min(mr->retry_count_cts, retry));
 	return retry;
@@ -317,15 +319,15 @@
 		sampling_ratio = mp->lookaround_rate;
 
 	/* increase sum packet counter */
-	mi->packet_count++;
+	mi->total_packets++;
 
 #ifdef CONFIG_MAC80211_DEBUGFS
 	if (mp->fixed_rate_idx != -1)
 		return;
 #endif
 
-	delta = (mi->packet_count * sampling_ratio / 100) -
-			(mi->sample_count + mi->sample_deferred / 2);
+	delta = (mi->total_packets * sampling_ratio / 100) -
+			(mi->sample_packets + mi->sample_deferred / 2);
 
 	/* delta < 0: no sampling required */
 	prev_sample = mi->prev_sample;
@@ -333,10 +335,10 @@
 	if (delta < 0 || (!mrr_capable && prev_sample))
 		return;
 
-	if (mi->packet_count >= 10000) {
+	if (mi->total_packets >= 10000) {
 		mi->sample_deferred = 0;
-		mi->sample_count = 0;
-		mi->packet_count = 0;
+		mi->sample_packets = 0;
+		mi->total_packets = 0;
 	} else if (delta > mi->n_rates * 2) {
 		/* With multi-rate retry, not every planned sample
 		 * attempt actually gets used, due to the way the retry
@@ -347,7 +349,7 @@
 		 * starts getting worse, minstrel would start bursting
 		 * out lots of sampling frames, which would result
 		 * in a large throughput loss. */
-		mi->sample_count += (delta - mi->n_rates * 2);
+		mi->sample_packets += (delta - mi->n_rates * 2);
 	}
 
 	/* get next random rate sample */
@@ -361,7 +363,7 @@
 	 */
 	if (mrr_capable &&
 	    msr->perfect_tx_time > mr->perfect_tx_time &&
-	    msr->sample_skipped < 20) {
+	    msr->stats.sample_skipped < 20) {
 		/* Only use IEEE80211_TX_CTL_RATE_CTRL_PROBE to mark
 		 * packets that have the sampling rate deferred to the
 		 * second MRR stage. Increase the sample counter only
@@ -375,7 +377,7 @@
 		if (!msr->sample_limit != 0)
 			return;
 
-		mi->sample_count++;
+		mi->sample_packets++;
 		if (msr->sample_limit > 0)
 			msr->sample_limit--;
 	}
@@ -384,7 +386,7 @@
 	 * has a probability of >95%, we shouldn't be attempting
 	 * to use it, as this only wastes precious airtime */
 	if (!mrr_capable &&
-	   (mi->r[ndx].probability > MINSTREL_FRAC(95, 100)))
+	   (mi->r[ndx].stats.probability > MINSTREL_FRAC(95, 100)))
 		return;
 
 	mi->prev_sample = true;
@@ -459,6 +461,7 @@
 
 	for (i = 0; i < sband->n_bitrates; i++) {
 		struct minstrel_rate *mr = &mi->r[n];
+		struct minstrel_rate_stats *mrs = &mi->r[n].stats;
 		unsigned int tx_time = 0, tx_time_cts = 0, tx_time_rtscts = 0;
 		unsigned int tx_time_single;
 		unsigned int cw = mp->cw_min;
@@ -471,6 +474,7 @@
 
 		n++;
 		memset(mr, 0, sizeof(*mr));
+		memset(mrs, 0, sizeof(*mrs));
 
 		mr->rix = i;
 		shift = ieee80211_chandef_get_shift(chandef);
@@ -482,9 +486,9 @@
 		/* calculate maximum number of retransmissions before
 		 * fallback (based on maximum segment size) */
 		mr->sample_limit = -1;
-		mr->retry_count = 1;
+		mrs->retry_count = 1;
 		mr->retry_count_cts = 1;
-		mr->retry_count_rtscts = 1;
+		mrs->retry_count_rtscts = 1;
 		tx_time = mr->perfect_tx_time + mi->sp_ack_dur;
 		do {
 			/* add one retransmission */
@@ -501,13 +505,13 @@
 				(mr->retry_count_cts < mp->max_retry))
 				mr->retry_count_cts++;
 			if ((tx_time_rtscts < mp->segment_size) &&
-				(mr->retry_count_rtscts < mp->max_retry))
-				mr->retry_count_rtscts++;
+				(mrs->retry_count_rtscts < mp->max_retry))
+				mrs->retry_count_rtscts++;
 		} while ((tx_time < mp->segment_size) &&
-				(++mr->retry_count < mp->max_retry));
-		mr->adjusted_retry_count = mr->retry_count;
+				(++mr->stats.retry_count < mp->max_retry));
+		mr->adjusted_retry_count = mrs->retry_count;
 		if (!(sband->bitrates[i].flags & IEEE80211_RATE_ERP_G))
-			mr->retry_count_cts = mr->retry_count;
+			mr->retry_count_cts = mrs->retry_count;
 	}
 
 	for (i = n; i < sband->n_bitrates; i++) {
@@ -665,7 +669,7 @@
 	/* convert pkt per sec in kbps (1200 is the average pkt size used for
 	 * computing cur_tp
 	 */
-	return MINSTREL_TRUNC(mi->r[idx].cur_tp) * 1200 * 8 / 1024;
+	return MINSTREL_TRUNC(mi->r[idx].stats.cur_tp) * 1200 * 8 / 1024;
 }
 
 const struct rate_control_ops mac80211_minstrel = {
diff -urN linux/net/mac80211/rc80211_minstrel_debugfs.c net-next-2.6/net/mac80211/rc80211_minstrel_debugfs.c
--- linux/net/mac80211/rc80211_minstrel_debugfs.c	2013-05-02 09:43:20.725515168 +0200
+++ net-next-2.6/net/mac80211/rc80211_minstrel_debugfs.c	2014-10-06 10:49:03.360932351 +0200
@@ -72,6 +72,7 @@
 			"this succ/attempt   success    attempts\n");
 	for (i = 0; i < mi->n_rates; i++) {
 		struct minstrel_rate *mr = &mi->r[i];
+		struct minstrel_rate_stats *mrs = &mi->r[i].stats;
 
 		*(p++) = (i == mi->max_tp_rate[0]) ? 'A' : ' ';
 		*(p++) = (i == mi->max_tp_rate[1]) ? 'B' : ' ';
@@ -81,24 +82,24 @@
 		p += sprintf(p, "%3u%s", mr->bitrate / 2,
 				(mr->bitrate & 1 ? ".5" : "  "));
 
-		tp = MINSTREL_TRUNC(mr->cur_tp / 10);
-		prob = MINSTREL_TRUNC(mr->cur_prob * 1000);
-		eprob = MINSTREL_TRUNC(mr->probability * 1000);
+		tp = MINSTREL_TRUNC(mrs->cur_tp / 10);
+		prob = MINSTREL_TRUNC(mrs->cur_prob * 1000);
+		eprob = MINSTREL_TRUNC(mrs->probability * 1000);
 
 		p += sprintf(p, "  %6u.%1u   %6u.%1u   %6u.%1u        "
 				"   %3u(%3u)  %8llu    %8llu\n",
 				tp / 10, tp % 10,
 				eprob / 10, eprob % 10,
 				prob / 10, prob % 10,
-				mr->last_success,
-				mr->last_attempts,
-				(unsigned long long)mr->succ_hist,
-				(unsigned long long)mr->att_hist);
+				mrs->last_success,
+				mrs->last_attempts,
+				(unsigned long long)mrs->succ_hist,
+				(unsigned long long)mrs->att_hist);
 	}
 	p += sprintf(p, "\nTotal packet count::    ideal %d      "
 			"lookaround %d\n\n",
-			mi->packet_count - mi->sample_count,
-			mi->sample_count);
+			mi->total_packets - mi->sample_packets,
+			mi->sample_packets);
 	ms->len = p - ms->buf;
 
 	return 0;
diff -urN linux/net/mac80211/rc80211_minstrel.h net-next-2.6/net/mac80211/rc80211_minstrel.h
--- linux/net/mac80211/rc80211_minstrel.h	2014-09-24 09:52:43.228644878 +0200
+++ net-next-2.6/net/mac80211/rc80211_minstrel.h	2014-10-06 10:49:03.360932351 +0200
@@ -31,6 +31,27 @@
 	return (new * (EWMA_DIV - weight) + old * weight) / EWMA_DIV;
 }
 
+struct minstrel_rate_stats {
+	/* current / last sampling period attempts/success counters */
+	unsigned int attempts, last_attempts;
+	unsigned int success, last_success;
+
+	/* total attempts/success counters */
+	u64 att_hist, succ_hist;
+
+	/* current throughput */
+	unsigned int cur_tp;
+
+	/* packet delivery probabilities */
+	unsigned int cur_prob, probability;
+
+	/* maximum retry counts */
+	unsigned int retry_count;
+	unsigned int retry_count_rtscts;
+
+	u8 sample_skipped;
+	bool retry_updated;
+};
 
 struct minstrel_rate {
 	int bitrate;
@@ -40,26 +61,10 @@
 	unsigned int ack_time;
 
 	int sample_limit;
-	unsigned int retry_count;
 	unsigned int retry_count_cts;
-	unsigned int retry_count_rtscts;
 	unsigned int adjusted_retry_count;
 
-	u32 success;
-	u32 attempts;
-	u32 last_attempts;
-	u32 last_success;
-	u8 sample_skipped;
-
-	/* parts per thousand */
-	u32 cur_prob;
-	u32 probability;
-
-	/* per-rate throughput */
-	u32 cur_tp;
-
-	u64 succ_hist;
-	u64 att_hist;
+	struct minstrel_rate_stats stats;
 };
 
 struct minstrel_sta_info {
@@ -73,8 +78,8 @@
 
 	u8 max_tp_rate[MAX_THR_RATES];
 	u8 max_prob_rate;
-	unsigned int packet_count;
-	unsigned int sample_count;
+	unsigned int total_packets;
+	unsigned int sample_packets;
 	int sample_deferred;
 
 	unsigned int sample_row;
diff -urN linux/net/mac80211/rc80211_minstrel_ht.c net-next-2.6/net/mac80211/rc80211_minstrel_ht.c
--- linux/net/mac80211/rc80211_minstrel_ht.c	2014-09-24 09:52:43.228644878 +0200
+++ net-next-2.6/net/mac80211/rc80211_minstrel_ht.c	2014-10-06 10:49:03.360932351 +0200
@@ -135,7 +135,7 @@
 static int
 minstrel_ht_get_group_idx(struct ieee80211_tx_rate *rate)
 {
-	return GROUP_IDX((rate->idx / 8) + 1,
+	return GROUP_IDX((rate->idx / MCS_GROUP_RATES) + 1,
 			 !!(rate->flags & IEEE80211_TX_RC_SHORT_GI),
 			 !!(rate->flags & IEEE80211_TX_RC_40_MHZ_WIDTH));
 }
@@ -233,12 +233,151 @@
 }
 
 /*
+ * Find & sort topmost throughput rates
+ *
+ * If multiple rates provide equal throughput the sorting is based on their
+ * current success probability. Higher success probability is preferred among
+ * MCS groups, CCK rates do not provide aggregation and are therefore at last.
+ */
+static void
+minstrel_ht_sort_best_tp_rates(struct minstrel_ht_sta *mi, u8 index,
+			       u8 *tp_list)
+{
+	int cur_group, cur_idx, cur_thr, cur_prob;
+	int tmp_group, tmp_idx, tmp_thr, tmp_prob;
+	int j = MAX_THR_RATES;
+
+	cur_group = index / MCS_GROUP_RATES;
+	cur_idx = index  % MCS_GROUP_RATES;
+	cur_thr = mi->groups[cur_group].rates[cur_idx].cur_tp;
+	cur_prob = mi->groups[cur_group].rates[cur_idx].probability;
+
+	tmp_group = tp_list[j - 1] / MCS_GROUP_RATES;
+	tmp_idx = tp_list[j - 1] % MCS_GROUP_RATES;
+	tmp_thr = mi->groups[tmp_group].rates[tmp_idx].cur_tp;
+	tmp_prob = mi->groups[tmp_group].rates[tmp_idx].probability;
+
+	while (j > 0 && (cur_thr > tmp_thr ||
+	      (cur_thr == tmp_thr && cur_prob > tmp_prob))) {
+		j--;
+		tmp_group = tp_list[j - 1] / MCS_GROUP_RATES;
+		tmp_idx = tp_list[j - 1] % MCS_GROUP_RATES;
+		tmp_thr = mi->groups[tmp_group].rates[tmp_idx].cur_tp;
+		tmp_prob = mi->groups[tmp_group].rates[tmp_idx].probability;
+	}
+
+	if (j < MAX_THR_RATES - 1) {
+		memmove(&tp_list[j + 1], &tp_list[j], (sizeof(*tp_list) *
+		       (MAX_THR_RATES - (j + 1))));
+	}
+	if (j < MAX_THR_RATES)
+		tp_list[j] = index;
+}
+
+/*
+ * Find and set the topmost probability rate per sta and per group
+ */
+static void
+minstrel_ht_set_best_prob_rate(struct minstrel_ht_sta *mi, u8 index)
+{
+	struct minstrel_mcs_group_data *mg;
+	struct minstrel_rate_stats *mr;
+	int tmp_group, tmp_idx, tmp_tp, tmp_prob, max_tp_group;
+
+	mg = &mi->groups[index / MCS_GROUP_RATES];
+	mr = &mg->rates[index % MCS_GROUP_RATES];
+
+	tmp_group = mi->max_prob_rate / MCS_GROUP_RATES;
+	tmp_idx = mi->max_prob_rate % MCS_GROUP_RATES;
+	tmp_tp = mi->groups[tmp_group].rates[tmp_idx].cur_tp;
+	tmp_prob = mi->groups[tmp_group].rates[tmp_idx].probability;
+
+	/* if max_tp_rate[0] is from MCS_GROUP max_prob_rate get selected from
+	 * MCS_GROUP as well as CCK_GROUP rates do not allow aggregation */
+	max_tp_group = mi->max_tp_rate[0] / MCS_GROUP_RATES;
+	if((index / MCS_GROUP_RATES == MINSTREL_CCK_GROUP) &&
+	    (max_tp_group != MINSTREL_CCK_GROUP))
+		return;
+
+	if (mr->probability > MINSTREL_FRAC(75, 100)) {
+		if (mr->cur_tp > tmp_tp)
+			mi->max_prob_rate = index;
+		if (mr->cur_tp > mg->rates[mg->max_group_prob_rate].cur_tp)
+			mg->max_group_prob_rate = index;
+	} else {
+		if (mr->probability > tmp_prob)
+			mi->max_prob_rate = index;
+		if (mr->probability > mg->rates[mg->max_group_prob_rate].probability)
+			mg->max_group_prob_rate = index;
+	}
+}
+
+
+/*
+ * Assign new rate set per sta and use CCK rates only if the fastest
+ * rate (max_tp_rate[0]) is from CCK group. This prohibits such sorted
+ * rate sets where MCS and CCK rates are mixed, because CCK rates can
+ * not use aggregation.
+ */
+static void
+minstrel_ht_assign_best_tp_rates(struct minstrel_ht_sta *mi,
+				 u8 tmp_mcs_tp_rate[MAX_THR_RATES],
+				 u8 tmp_cck_tp_rate[MAX_THR_RATES])
+{
+	unsigned int tmp_group, tmp_idx, tmp_cck_tp, tmp_mcs_tp;
+	int i;
+
+	tmp_group = tmp_cck_tp_rate[0] / MCS_GROUP_RATES;
+	tmp_idx = tmp_cck_tp_rate[0] % MCS_GROUP_RATES;
+	tmp_cck_tp = mi->groups[tmp_group].rates[tmp_idx].cur_tp;
+
+	tmp_group = tmp_mcs_tp_rate[0] / MCS_GROUP_RATES;
+	tmp_idx = tmp_mcs_tp_rate[0] % MCS_GROUP_RATES;
+	tmp_mcs_tp = mi->groups[tmp_group].rates[tmp_idx].cur_tp;
+
+	if (tmp_cck_tp > tmp_mcs_tp) {
+		for(i = 0; i < MAX_THR_RATES; i++) {
+			minstrel_ht_sort_best_tp_rates(mi, tmp_cck_tp_rate[i],
+						       tmp_mcs_tp_rate);
+		}
+	}
+
+}
+
+/*
+ * Try to increase robustness of max_prob rate by decrease number of
+ * streams if possible.
+ */
+static inline void
+minstrel_ht_prob_rate_reduce_streams(struct minstrel_ht_sta *mi)
+{
+	struct minstrel_mcs_group_data *mg;
+	struct minstrel_rate_stats *mr;
+	int tmp_max_streams, group;
+	int tmp_tp = 0;
+
+	tmp_max_streams = minstrel_mcs_groups[mi->max_tp_rate[0] /
+			  MCS_GROUP_RATES].streams;
+	for (group = 0; group < ARRAY_SIZE(minstrel_mcs_groups); group++) {
+		mg = &mi->groups[group];
+		if (!mg->supported || group == MINSTREL_CCK_GROUP)
+			continue;
+		mr = minstrel_get_ratestats(mi, mg->max_group_prob_rate);
+		if (tmp_tp < mr->cur_tp &&
+		   (minstrel_mcs_groups[group].streams < tmp_max_streams)) {
+				mi->max_prob_rate = mg->max_group_prob_rate;
+				tmp_tp = mr->cur_tp;
+		}
+	}
+}
+
+/*
  * Update rate statistics and select new primary rates
  *
  * Rules for rate selection:
  *  - max_prob_rate must use only one stream, as a tradeoff between delivery
  *    probability and throughput during strong fluctuations
- *  - as long as the max prob rate has a probability of more than 3/4, pick
+ *  - as long as the max prob rate has a probability of more than 75%, pick
  *    higher throughput rates, even if the probablity is a bit lower
  */
 static void
@@ -246,9 +385,9 @@
 {
 	struct minstrel_mcs_group_data *mg;
 	struct minstrel_rate_stats *mr;
-	int cur_prob, cur_prob_tp, cur_tp, cur_tp2;
-	int group, i, index;
-	bool mi_rates_valid = false;
+	int group, i, j;
+	u8 tmp_mcs_tp_rate[MAX_THR_RATES], tmp_group_tp_rate[MAX_THR_RATES];
+	u8 tmp_cck_tp_rate[MAX_THR_RATES], index;
 
 	if (mi->ampdu_packets > 0) {
 		mi->avg_ampdu_len = minstrel_ewma(mi->avg_ampdu_len,
@@ -260,13 +399,14 @@
 	mi->sample_slow = 0;
 	mi->sample_count = 0;
 
-	for (group = 0; group < ARRAY_SIZE(minstrel_mcs_groups); group++) {
-		bool mg_rates_valid = false;
+	/* Initialize global rate indexes */
+	for(j = 0; j < MAX_THR_RATES; j++){
+		tmp_mcs_tp_rate[j] = 0;
+		tmp_cck_tp_rate[j] = 0;
+	}
 
-		cur_prob = 0;
-		cur_prob_tp = 0;
-		cur_tp = 0;
-		cur_tp2 = 0;
+	/* Find best rate sets within all MCS groups*/
+	for (group = 0; group < ARRAY_SIZE(minstrel_mcs_groups); group++) {
 
 		mg = &mi->groups[group];
 		if (!mg->supported)
@@ -274,24 +414,16 @@
 
 		mi->sample_count++;
 
+		/* (re)Initialize group rate indexes */
+		for(j = 0; j < MAX_THR_RATES; j++)
+			tmp_group_tp_rate[j] = group;
+
 		for (i = 0; i < MCS_GROUP_RATES; i++) {
 			if (!(mg->supported & BIT(i)))
 				continue;
 
 			index = MCS_GROUP_RATES * group + i;
 
-			/* initialize rates selections starting indexes */
-			if (!mg_rates_valid) {
-				mg->max_tp_rate = mg->max_tp_rate2 =
-					mg->max_prob_rate = i;
-				if (!mi_rates_valid) {
-					mi->max_tp_rate = mi->max_tp_rate2 =
-						mi->max_prob_rate = index;
-					mi_rates_valid = true;
-				}
-				mg_rates_valid = true;
-			}
-
 			mr = &mg->rates[i];
 			mr->retry_updated = false;
 			minstrel_calc_rate_ewma(mr);
@@ -300,82 +432,47 @@
 			if (!mr->cur_tp)
 				continue;
 
-			if ((mr->cur_tp > cur_prob_tp && mr->probability >
-			     MINSTREL_FRAC(3, 4)) || mr->probability > cur_prob) {
-				mg->max_prob_rate = index;
-				cur_prob = mr->probability;
-				cur_prob_tp = mr->cur_tp;
+			/* Find max throughput rate set */
+			if (group != MINSTREL_CCK_GROUP) {
+				minstrel_ht_sort_best_tp_rates(mi, index,
+							       tmp_mcs_tp_rate);
+			} else if (group == MINSTREL_CCK_GROUP) {
+				minstrel_ht_sort_best_tp_rates(mi, index,
+							       tmp_cck_tp_rate);
 			}
 
-			if (mr->cur_tp > cur_tp) {
-				swap(index, mg->max_tp_rate);
-				cur_tp = mr->cur_tp;
-				mr = minstrel_get_ratestats(mi, index);
-			}
-
-			if (index >= mg->max_tp_rate)
-				continue;
-
-			if (mr->cur_tp > cur_tp2) {
-				mg->max_tp_rate2 = index;
-				cur_tp2 = mr->cur_tp;
-			}
-		}
-	}
-
-	/* try to sample all available rates during each interval */
-	mi->sample_count *= 8;
-
-	cur_prob = 0;
-	cur_prob_tp = 0;
-	cur_tp = 0;
-	cur_tp2 = 0;
-	for (group = 0; group < ARRAY_SIZE(minstrel_mcs_groups); group++) {
-		mg = &mi->groups[group];
-		if (!mg->supported)
-			continue;
+			/* Find max throughput rate set within a group */
+			minstrel_ht_sort_best_tp_rates(mi, index,
+						       tmp_group_tp_rate);
 
-		mr = minstrel_get_ratestats(mi, mg->max_tp_rate);
-		if (cur_tp < mr->cur_tp) {
-			mi->max_tp_rate2 = mi->max_tp_rate;
-			cur_tp2 = cur_tp;
-			mi->max_tp_rate = mg->max_tp_rate;
-			cur_tp = mr->cur_tp;
-			mi->max_prob_streams = minstrel_mcs_groups[group].streams - 1;
+			/* Find max probability rate per group and global */
+			minstrel_ht_set_best_prob_rate(mi, index);
 		}
 
-		mr = minstrel_get_ratestats(mi, mg->max_tp_rate2);
-		if (cur_tp2 < mr->cur_tp) {
-			mi->max_tp_rate2 = mg->max_tp_rate2;
-			cur_tp2 = mr->cur_tp;
-		}
+		memcpy(mg->max_group_tp_rate, tmp_group_tp_rate,
+		       sizeof(mg->max_group_tp_rate));
 	}
 
-	if (mi->max_prob_streams < 1)
-		mi->max_prob_streams = 1;
+	/* Assign new rate set per sta */
+	minstrel_ht_assign_best_tp_rates(mi, tmp_mcs_tp_rate, tmp_cck_tp_rate);
+	memcpy(mi->max_tp_rate, tmp_mcs_tp_rate, sizeof(mi->max_tp_rate));
 
-	for (group = 0; group < ARRAY_SIZE(minstrel_mcs_groups); group++) {
-		mg = &mi->groups[group];
-		if (!mg->supported)
-			continue;
-		mr = minstrel_get_ratestats(mi, mg->max_prob_rate);
-		if (cur_prob_tp < mr->cur_tp &&
-		    minstrel_mcs_groups[group].streams <= mi->max_prob_streams) {
-			mi->max_prob_rate = mg->max_prob_rate;
-			cur_prob = mr->cur_prob;
-			cur_prob_tp = mr->cur_tp;
-		}
-	}
+	/* Try to increase robustness of max_prob_rate*/
+	minstrel_ht_prob_rate_reduce_streams(mi);
+
+	/* try to sample all available rates during each interval */
+	mi->sample_count *= 8;
 
 #ifdef CONFIG_MAC80211_DEBUGFS
 	/* use fixed index if set */
 	if (mp->fixed_rate_idx != -1) {
-		mi->max_tp_rate = mp->fixed_rate_idx;
-		mi->max_tp_rate2 = mp->fixed_rate_idx;
+		for (i = 0; i < 4; i++)
+			mi->max_tp_rate[i] = mp->fixed_rate_idx;
 		mi->max_prob_rate = mp->fixed_rate_idx;
 	}
 #endif
 
+	/* Reset update timer */
 	mi->stats_update = jiffies;
 }
 
@@ -420,8 +517,7 @@
 }
 
 static void
-minstrel_downgrade_rate(struct minstrel_ht_sta *mi, unsigned int *idx,
-			bool primary)
+minstrel_downgrade_rate(struct minstrel_ht_sta *mi, u8 *idx, bool primary)
 {
 	int group, orig_group;
 
@@ -437,9 +533,9 @@
 			continue;
 
 		if (primary)
-			*idx = mi->groups[group].max_tp_rate;
+			*idx = mi->groups[group].max_group_tp_rate[0];
 		else
-			*idx = mi->groups[group].max_tp_rate2;
+			*idx = mi->groups[group].max_group_tp_rate[1];
 		break;
 	}
 }
@@ -524,19 +620,19 @@
 	 * check for sudden death of spatial multiplexing,
 	 * downgrade to a lower number of streams if necessary.
 	 */
-	rate = minstrel_get_ratestats(mi, mi->max_tp_rate);
+	rate = minstrel_get_ratestats(mi, mi->max_tp_rate[0]);
 	if (rate->attempts > 30 &&
 	    MINSTREL_FRAC(rate->success, rate->attempts) <
 	    MINSTREL_FRAC(20, 100)) {
-		minstrel_downgrade_rate(mi, &mi->max_tp_rate, true);
+		minstrel_downgrade_rate(mi, &mi->max_tp_rate[0], true);
 		update = true;
 	}
 
-	rate2 = minstrel_get_ratestats(mi, mi->max_tp_rate2);
+	rate2 = minstrel_get_ratestats(mi, mi->max_tp_rate[1]);
 	if (rate2->attempts > 30 &&
 	    MINSTREL_FRAC(rate2->success, rate2->attempts) <
 	    MINSTREL_FRAC(20, 100)) {
-		minstrel_downgrade_rate(mi, &mi->max_tp_rate2, false);
+		minstrel_downgrade_rate(mi, &mi->max_tp_rate[1], false);
 		update = true;
 	}
 
@@ -661,12 +757,12 @@
 	if (!rates)
 		return;
 
-	/* Start with max_tp_rate */
-	minstrel_ht_set_rate(mp, mi, rates, i++, mi->max_tp_rate);
+	/* Start with max_tp_rate[0] */
+	minstrel_ht_set_rate(mp, mi, rates, i++, mi->max_tp_rate[0]);
 
 	if (mp->hw->max_rates >= 3) {
-		/* At least 3 tx rates supported, use max_tp_rate2 next */
-		minstrel_ht_set_rate(mp, mi, rates, i++, mi->max_tp_rate2);
+		/* At least 3 tx rates supported, use max_tp_rate[1] next */
+		minstrel_ht_set_rate(mp, mi, rates, i++, mi->max_tp_rate[1]);
 	}
 
 	if (mp->hw->max_rates >= 2) {
@@ -691,7 +787,7 @@
 {
 	struct minstrel_rate_stats *mr;
 	struct minstrel_mcs_group_data *mg;
-	unsigned int sample_dur, sample_group;
+	unsigned int sample_dur, sample_group, cur_max_tp_streams;
 	int sample_idx = 0;
 
 	if (mi->sample_wait > 0) {
@@ -718,8 +814,8 @@
 	 * to the frame. Hence, don't use sampling for the currently
 	 * used rates.
 	 */
-	if (sample_idx == mi->max_tp_rate ||
-	    sample_idx == mi->max_tp_rate2 ||
+	if (sample_idx == mi->max_tp_rate[0] ||
+	    sample_idx == mi->max_tp_rate[1] ||
 	    sample_idx == mi->max_prob_rate)
 		return -1;
 
@@ -734,9 +830,12 @@
 	 * Make sure that lower rates get sampled only occasionally,
 	 * if the link is working perfectly.
 	 */
+
+	cur_max_tp_streams = minstrel_mcs_groups[mi->max_tp_rate[0] /
+		MCS_GROUP_RATES].streams;
 	sample_dur = minstrel_get_duration(sample_idx);
-	if (sample_dur >= minstrel_get_duration(mi->max_tp_rate2) &&
-	    (mi->max_prob_streams <
+	if (sample_dur >= minstrel_get_duration(mi->max_tp_rate[1]) &&
+	    (cur_max_tp_streams - 1 <
 	     minstrel_mcs_groups[sample_group].streams ||
 	     sample_dur >= minstrel_get_duration(mi->max_prob_rate))) {
 		if (mr->sample_skipped < 20)
@@ -1041,8 +1140,8 @@
 	if (!msp->is_ht)
 		return mac80211_minstrel.get_expected_throughput(priv_sta);
 
-	i = mi->max_tp_rate / MCS_GROUP_RATES;
-	j = mi->max_tp_rate % MCS_GROUP_RATES;
+	i = mi->max_tp_rate[0] / MCS_GROUP_RATES;
+	j = mi->max_tp_rate[0] % MCS_GROUP_RATES;
 
 	/* convert cur_tp from pkt per second in kbps */
 	return mi->groups[i].rates[j].cur_tp * AVG_PKT_SIZE * 8 / 1024;
diff -urN linux/net/mac80211/rc80211_minstrel_ht_debugfs.c net-next-2.6/net/mac80211/rc80211_minstrel_ht_debugfs.c
--- linux/net/mac80211/rc80211_minstrel_ht_debugfs.c	2014-09-24 09:52:43.228644878 +0200
+++ net-next-2.6/net/mac80211/rc80211_minstrel_ht_debugfs.c	2014-10-06 10:49:03.360932351 +0200
@@ -46,8 +46,10 @@
 		else
 			p += sprintf(p, "HT%c0/%cGI ", htmode, gimode);
 
-		*(p++) = (idx == mi->max_tp_rate) ? 'T' : ' ';
-		*(p++) = (idx == mi->max_tp_rate2) ? 't' : ' ';
+		*(p++) = (idx == mi->max_tp_rate[0]) ? 'A' : ' ';
+		*(p++) = (idx == mi->max_tp_rate[1]) ? 'B' : ' ';
+		*(p++) = (idx == mi->max_tp_rate[2]) ? 'C' : ' ';
+		*(p++) = (idx == mi->max_tp_rate[3]) ? 'D' : ' ';
 		*(p++) = (idx == mi->max_prob_rate) ? 'P' : ' ';
 
 		if (i == max_mcs) {
@@ -100,8 +102,8 @@
 
 	file->private_data = ms;
 	p = ms->buf;
-	p += sprintf(p, "type         rate     throughput  ewma prob   this prob  "
-			"retry   this succ/attempt   success    attempts\n");
+	p += sprintf(p, "type           rate     throughput  ewma prob   "
+		     "this prob  retry   this succ/attempt   success    attempts\n");
 
 	p = minstrel_ht_stats_dump(mi, max_mcs, p);
 	for (i = 0; i < max_mcs; i++)
diff -urN linux/net/mac80211/rc80211_minstrel_ht.h net-next-2.6/net/mac80211/rc80211_minstrel_ht.h
--- linux/net/mac80211/rc80211_minstrel_ht.h	2013-05-02 09:43:20.725515168 +0200
+++ net-next-2.6/net/mac80211/rc80211_minstrel_ht.h	2014-10-06 10:49:03.360932351 +0200
@@ -26,28 +26,6 @@
 
 extern const struct mcs_group minstrel_mcs_groups[];
 
-struct minstrel_rate_stats {
-	/* current / last sampling period attempts/success counters */
-	unsigned int attempts, last_attempts;
-	unsigned int success, last_success;
-
-	/* total attempts/success counters */
-	u64 att_hist, succ_hist;
-
-	/* current throughput */
-	unsigned int cur_tp;
-
-	/* packet delivery probabilities */
-	unsigned int cur_prob, probability;
-
-	/* maximum retry counts */
-	unsigned int retry_count;
-	unsigned int retry_count_rtscts;
-
-	bool retry_updated;
-	u8 sample_skipped;
-};
-
 struct minstrel_mcs_group_data {
 	u8 index;
 	u8 column;
@@ -55,10 +33,9 @@
 	/* bitfield of supported MCS rates of this group */
 	u8 supported;
 
-	/* selected primary rates */
-	unsigned int max_tp_rate;
-	unsigned int max_tp_rate2;
-	unsigned int max_prob_rate;
+	/* sorted rate set within a MCS group*/
+	u8 max_group_tp_rate[MAX_THR_RATES];
+	u8 max_group_prob_rate;
 
 	/* MCS rate statistics */
 	struct minstrel_rate_stats rates[MCS_GROUP_RATES];
@@ -74,15 +51,9 @@
 	/* ampdu length (EWMA) */
 	unsigned int avg_ampdu_len;
 
-	/* best throughput rate */
-	unsigned int max_tp_rate;
-
-	/* second best throughput rate */
-	unsigned int max_tp_rate2;
-
-	/* best probability rate */
-	unsigned int max_prob_rate;
-	unsigned int max_prob_streams;
+	/* overall sorted rate set */
+	u8 max_tp_rate[MAX_THR_RATES];
+	u8 max_prob_rate;
 
 	/* time of last status update */
 	unsigned long stats_update;
diff -urN linux/net/mac80211/rx.c net-next-2.6/net/mac80211/rx.c
--- linux/net/mac80211/rx.c	2014-09-24 09:52:43.228644878 +0200
+++ net-next-2.6/net/mac80211/rx.c	2014-10-06 10:49:03.364932391 +0200
@@ -3,6 +3,7 @@
  * Copyright 2005-2006, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007-2010	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -835,6 +836,16 @@
 
 	spin_lock(&tid_agg_rx->reorder_lock);
 
+	/*
+	 * Offloaded BA sessions have no known starting sequence number so pick
+	 * one from first Rxed frame for this tid after BA was started.
+	 */
+	if (unlikely(tid_agg_rx->auto_seq)) {
+		tid_agg_rx->auto_seq = false;
+		tid_agg_rx->ssn = mpdu_seq_num;
+		tid_agg_rx->head_seq_num = mpdu_seq_num;
+	}
+
 	buf_size = tid_agg_rx->buf_size;
 	head_seq_num = tid_agg_rx->head_seq_num;
 
@@ -2725,7 +2736,7 @@
 		sig = status->signal;
 
 	if (cfg80211_rx_mgmt(&rx->sdata->wdev, status->freq, sig,
-			     rx->skb->data, rx->skb->len, 0, GFP_ATOMIC)) {
+			     rx->skb->data, rx->skb->len, 0)) {
 		if (rx->sta)
 			rx->sta->rx_packets++;
 		dev_kfree_skb(rx->skb);
diff -urN linux/net/mac80211/scan.c net-next-2.6/net/mac80211/scan.c
--- linux/net/mac80211/scan.c	2014-09-24 09:52:43.228644878 +0200
+++ net-next-2.6/net/mac80211/scan.c	2014-10-06 10:49:03.420932962 +0200
@@ -6,6 +6,7 @@
  * Copyright 2005, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007, Michael Wu <flamingice@sourmilk.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -1094,7 +1095,7 @@
 	if (rcu_access_pointer(local->sched_scan_sdata)) {
 		ret = drv_sched_scan_stop(local, sdata);
 		if (!ret)
-			rcu_assign_pointer(local->sched_scan_sdata, NULL);
+			RCU_INIT_POINTER(local->sched_scan_sdata, NULL);
 	}
 out:
 	mutex_unlock(&local->mtx);
diff -urN linux/net/mac80211/sta_info.c net-next-2.6/net/mac80211/sta_info.c
--- linux/net/mac80211/sta_info.c	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/sta_info.c	2014-10-06 10:49:03.420932962 +0200
@@ -1,6 +1,7 @@
 /*
  * Copyright 2002-2005, Instant802 Networks, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -1182,7 +1183,7 @@
 	struct sk_buff *skb;
 	int size = sizeof(*nullfunc);
 	__le16 fc;
-	bool qos = test_sta_flag(sta, WLAN_STA_WME);
+	bool qos = sta->sta.wme;
 	struct ieee80211_tx_info *info;
 	struct ieee80211_chanctx_conf *chanctx_conf;
 
@@ -1837,7 +1838,7 @@
 		sinfo->sta_flags.set |= BIT(NL80211_STA_FLAG_AUTHORIZED);
 	if (test_sta_flag(sta, WLAN_STA_SHORT_PREAMBLE))
 		sinfo->sta_flags.set |= BIT(NL80211_STA_FLAG_SHORT_PREAMBLE);
-	if (test_sta_flag(sta, WLAN_STA_WME))
+	if (sta->sta.wme)
 		sinfo->sta_flags.set |= BIT(NL80211_STA_FLAG_WME);
 	if (test_sta_flag(sta, WLAN_STA_MFP))
 		sinfo->sta_flags.set |= BIT(NL80211_STA_FLAG_MFP);
diff -urN linux/net/mac80211/sta_info.h net-next-2.6/net/mac80211/sta_info.h
--- linux/net/mac80211/sta_info.h	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/sta_info.h	2014-10-06 10:49:03.420932962 +0200
@@ -1,5 +1,6 @@
 /*
  * Copyright 2002-2005, Devicescape Software, Inc.
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -31,7 +32,6 @@
  *	when virtual port control is not in use.
  * @WLAN_STA_SHORT_PREAMBLE: Station is capable of receiving short-preamble
  *	frames.
- * @WLAN_STA_WME: Station is a QoS-STA.
  * @WLAN_STA_WDS: Station is one of our WDS peers.
  * @WLAN_STA_CLEAR_PS_FILT: Clear PS filter in hardware (using the
  *	IEEE80211_TX_CTL_CLEAR_PS_FILT control flag) when the next
@@ -69,7 +69,6 @@
 	WLAN_STA_PS_STA,
 	WLAN_STA_AUTHORIZED,
 	WLAN_STA_SHORT_PREAMBLE,
-	WLAN_STA_WME,
 	WLAN_STA_WDS,
 	WLAN_STA_CLEAR_PS_FILT,
 	WLAN_STA_MFP,
@@ -169,6 +168,8 @@
  * @dialog_token: dialog token for aggregation session
  * @rcu_head: RCU head used for freeing this struct
  * @reorder_lock: serializes access to reorder buffer, see below.
+ * @auto_seq: used for offloaded BA sessions to automatically pick head_seq_and
+ *	and ssn.
  *
  * This structure's lifetime is managed by RCU, assignments to
  * the array holding it must hold the aggregation mutex.
@@ -192,6 +193,7 @@
 	u16 buf_size;
 	u16 timeout;
 	u8 dialog_token;
+	bool auto_seq;
 };
 
 /**
@@ -448,6 +450,9 @@
 	enum ieee80211_smps_mode known_smps_mode;
 	const struct ieee80211_cipher_scheme *cipher_scheme;
 
+	/* TDLS timeout data */
+	unsigned long last_tdls_pkt_time;
+
 	/* keep last! */
 	struct ieee80211_sta sta;
 };
diff -urN linux/net/mac80211/status.c net-next-2.6/net/mac80211/status.c
--- linux/net/mac80211/status.c	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/status.c	2014-10-06 10:49:03.420932962 +0200
@@ -3,6 +3,7 @@
  * Copyright 2005-2006, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2008-2010	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -537,6 +538,8 @@
  *  - current throughput (higher value for higher tpt)?
  */
 #define STA_LOST_PKT_THRESHOLD	50
+#define STA_LOST_TDLS_PKT_THRESHOLD	10
+#define STA_LOST_TDLS_PKT_TIME		(10*HZ) /* 10secs since last ACK */
 
 static void ieee80211_lost_packet(struct sta_info *sta, struct sk_buff *skb)
 {
@@ -547,7 +550,20 @@
 	    !(info->flags & IEEE80211_TX_STAT_AMPDU))
 		return;
 
-	if (++sta->lost_packets < STA_LOST_PKT_THRESHOLD)
+	sta->lost_packets++;
+	if (!sta->sta.tdls && sta->lost_packets < STA_LOST_PKT_THRESHOLD)
+		return;
+
+	/*
+	 * If we're in TDLS mode, make sure that all STA_LOST_TDLS_PKT_THRESHOLD
+	 * of the last packets were lost, and that no ACK was received in the
+	 * last STA_LOST_TDLS_PKT_TIME ms, before triggering the CQM packet-loss
+	 * mechanism.
+	 */
+	if (sta->sta.tdls &&
+	    (sta->lost_packets < STA_LOST_TDLS_PKT_THRESHOLD ||
+	     time_before(jiffies,
+			 sta->last_tdls_pkt_time + STA_LOST_TDLS_PKT_TIME)))
 		return;
 
 	cfg80211_cqm_pktloss_notify(sta->sdata->dev, sta->sta.addr,
@@ -694,6 +710,10 @@
 			if (info->flags & IEEE80211_TX_STAT_ACK) {
 				if (sta->lost_packets)
 					sta->lost_packets = 0;
+
+				/* Track when last TDLS packet was ACKed */
+				if (test_sta_flag(sta, WLAN_STA_TDLS_PEER_AUTH))
+					sta->last_tdls_pkt_time = jiffies;
 			} else {
 				ieee80211_lost_packet(sta, skb);
 			}
diff -urN linux/net/mac80211/tdls.c net-next-2.6/net/mac80211/tdls.c
--- linux/net/mac80211/tdls.c	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/tdls.c	2014-10-06 10:49:03.420932962 +0200
@@ -3,6 +3,7 @@
  *
  * Copyright 2006-2010	Johannes Berg <johannes@sipsolutions.net>
  * Copyright 2014, Intel Corporation
+ * Copyright 2014  Intel Mobile Communications GmbH
  *
  * This file is GPLv2 as found in COPYING.
  */
@@ -316,8 +317,7 @@
 	}
 
 	/* add the QoS param IE if both the peer and we support it */
-	if (local->hw.queues >= IEEE80211_NUM_ACS &&
-	    test_sta_flag(sta, WLAN_STA_WME))
+	if (local->hw.queues >= IEEE80211_NUM_ACS && sta->sta.wme)
 		ieee80211_tdls_add_wmm_param_ie(sdata, skb);
 
 	/* add any custom IEs that go before HT operation */
@@ -412,6 +412,9 @@
 	tf->ether_type = cpu_to_be16(ETH_P_TDLS);
 	tf->payload_type = WLAN_TDLS_SNAP_RFTYPE;
 
+	/* network header is after the ethernet header */
+	skb_set_network_header(skb, ETH_HLEN);
+
 	switch (action_code) {
 	case WLAN_TDLS_SETUP_REQUEST:
 		tf->category = WLAN_CATEGORY_TDLS;
diff -urN linux/net/mac80211/trace.h net-next-2.6/net/mac80211/trace.h
--- linux/net/mac80211/trace.h	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/trace.h	2014-10-06 10:49:03.420932962 +0200
@@ -672,13 +672,13 @@
 );
 
 TRACE_EVENT(drv_set_coverage_class,
-	TP_PROTO(struct ieee80211_local *local, u8 value),
+	TP_PROTO(struct ieee80211_local *local, s16 value),
 
 	TP_ARGS(local, value),
 
 	TP_STRUCT__entry(
 		LOCAL_ENTRY
-		__field(u8, value)
+		__field(s16, value)
 	),
 
 	TP_fast_assign(
diff -urN linux/net/mac80211/tx.c net-next-2.6/net/mac80211/tx.c
--- linux/net/mac80211/tx.c	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/tx.c	2014-10-06 10:49:03.420932962 +0200
@@ -3,6 +3,7 @@
  * Copyright 2005-2006, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -1478,7 +1479,10 @@
 		tail_need = max_t(int, tail_need, 0);
 	}
 
-	if (skb_cloned(skb))
+	if (skb_cloned(skb) &&
+	    (!(local->hw.flags & IEEE80211_HW_SUPPORTS_CLONED_SKBS) ||
+	     !skb_clone_writable(skb, ETH_HLEN) ||
+	     sdata->crypto_tx_tailroom_needed_cnt))
 		I802_DEBUG_INC(local->tx_expand_skb_head_cloned);
 	else if (head_need || tail_need)
 		I802_DEBUG_INC(local->tx_expand_skb_head);
@@ -1785,9 +1789,8 @@
  * @skb: packet to be sent
  * @dev: incoming interface
  *
- * Returns: 0 on success (and frees skb in this case) or 1 on failure (skb will
- * not be freed, and caller is responsible for either retrying later or freeing
- * skb).
+ * Returns: NETDEV_TX_OK both on success and on failure. On failure skb will
+ *	be freed.
  *
  * This function takes in an Ethernet header and encapsulates it with suitable
  * IEEE 802.11 header based on which interface the packet is coming in. The
@@ -1844,7 +1847,7 @@
 			memcpy(hdr.addr4, skb->data + ETH_ALEN, ETH_ALEN);
 			hdrlen = 30;
 			authorized = test_sta_flag(sta, WLAN_STA_AUTHORIZED);
-			wme_sta = test_sta_flag(sta, WLAN_STA_WME);
+			wme_sta = sta->sta.wme;
 		}
 		ap_sdata = container_of(sdata->bss, struct ieee80211_sub_if_data,
 					u.ap);
@@ -1957,7 +1960,7 @@
 			if (sta) {
 				authorized = test_sta_flag(sta,
 							WLAN_STA_AUTHORIZED);
-				wme_sta = test_sta_flag(sta, WLAN_STA_WME);
+				wme_sta = sta->sta.wme;
 				tdls_peer = test_sta_flag(sta,
 							  WLAN_STA_TDLS_PEER);
 				tdls_auth = test_sta_flag(sta,
@@ -2035,7 +2038,7 @@
 		sta = sta_info_get(sdata, hdr.addr1);
 		if (sta) {
 			authorized = test_sta_flag(sta, WLAN_STA_AUTHORIZED);
-			wme_sta = test_sta_flag(sta, WLAN_STA_WME);
+			wme_sta = sta->sta.wme;
 		}
 	}
 
@@ -2069,30 +2072,23 @@
 
 	if (unlikely(!multicast && skb->sk &&
 		     skb_shinfo(skb)->tx_flags & SKBTX_WIFI_STATUS)) {
-		struct sk_buff *orig_skb = skb;
+		struct sk_buff *ack_skb = skb_clone_sk(skb);
 
-		skb = skb_clone(skb, GFP_ATOMIC);
-		if (skb) {
+		if (ack_skb) {
 			unsigned long flags;
 			int id;
 
 			spin_lock_irqsave(&local->ack_status_lock, flags);
-			id = idr_alloc(&local->ack_status_frames, orig_skb,
+			id = idr_alloc(&local->ack_status_frames, ack_skb,
 				       1, 0x10000, GFP_ATOMIC);
 			spin_unlock_irqrestore(&local->ack_status_lock, flags);
 
 			if (id >= 0) {
 				info_id = id;
 				info_flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;
-			} else if (skb_shared(skb)) {
-				kfree_skb(orig_skb);
 			} else {
-				kfree_skb(skb);
-				skb = orig_skb;
+				kfree_skb(ack_skb);
 			}
-		} else {
-			/* couldn't clone -- lose tx status ... */
-			skb = orig_skb;
 		}
 	}
 
diff -urN linux/net/mac80211/util.c net-next-2.6/net/mac80211/util.c
--- linux/net/mac80211/util.c	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/util.c	2014-10-06 10:49:03.420932962 +0200
@@ -3,6 +3,7 @@
  * Copyright 2005-2006, Devicescape Software, Inc.
  * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
  * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -1014,6 +1015,31 @@
 			}
 			elems->pwr_constr_elem = pos;
 			break;
+		case WLAN_EID_CISCO_VENDOR_SPECIFIC:
+			/* Lots of different options exist, but we only care
+			 * about the Dynamic Transmit Power Control element.
+			 * First check for the Cisco OUI, then for the DTPC
+			 * tag (0x00).
+			 */
+			if (elen < 4) {
+				elem_parse_failed = true;
+				break;
+			}
+
+			if (pos[0] != 0x00 || pos[1] != 0x40 ||
+			    pos[2] != 0x96 || pos[3] != 0x00)
+				break;
+
+			if (elen != 6) {
+				elem_parse_failed = true;
+				break;
+			}
+
+			if (calc_crc)
+				crc = crc32_be(crc, pos - 2, elen + 2);
+
+			elems->cisco_dtpc_elem = pos;
+			break;
 		case WLAN_EID_TIMEOUT_INTERVAL:
 			if (elen >= sizeof(struct ieee80211_timeout_interval_ie))
 				elems->timeout_int = (void *)pos;
diff -urN linux/net/mac80211/wme.c net-next-2.6/net/mac80211/wme.c
--- linux/net/mac80211/wme.c	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/wme.c	2014-10-06 10:49:03.424933002 +0200
@@ -1,5 +1,6 @@
 /*
  * Copyright 2004, Instant802 Networks, Inc.
+ * Copyright 2013-2014  Intel Mobile Communications GmbH
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -118,7 +119,7 @@
 	case NL80211_IFTYPE_AP_VLAN:
 		sta = rcu_dereference(sdata->u.vlan.sta);
 		if (sta) {
-			qos = test_sta_flag(sta, WLAN_STA_WME);
+			qos = sta->sta.wme;
 			break;
 		}
 	case NL80211_IFTYPE_AP:
@@ -145,7 +146,7 @@
 	if (!sta && ra && !is_multicast_ether_addr(ra)) {
 		sta = sta_info_get(sdata, ra);
 		if (sta)
-			qos = test_sta_flag(sta, WLAN_STA_WME);
+			qos = sta->sta.wme;
 	}
 	rcu_read_unlock();
 
diff -urN linux/net/mac80211/wpa.c net-next-2.6/net/mac80211/wpa.c
--- linux/net/mac80211/wpa.c	2014-09-24 09:52:43.232644921 +0200
+++ net-next-2.6/net/mac80211/wpa.c	2014-10-06 10:49:03.424933002 +0200
@@ -64,8 +64,11 @@
 	if (!info->control.hw_key)
 		tail += IEEE80211_TKIP_ICV_LEN;
 
-	if (WARN_ON(skb_tailroom(skb) < tail ||
-		    skb_headroom(skb) < IEEE80211_TKIP_IV_LEN))
+	if (WARN(skb_tailroom(skb) < tail ||
+		 skb_headroom(skb) < IEEE80211_TKIP_IV_LEN,
+		 "mmic: not enough head/tail (%d/%d,%d/%d)\n",
+		 skb_headroom(skb), IEEE80211_TKIP_IV_LEN,
+		 skb_tailroom(skb), tail))
 		return TX_DROP;
 
 	key = &tx->key->conf.key[NL80211_TKIP_DATA_OFFSET_TX_MIC_KEY];
diff -urN linux/net/mac802154/rx.c net-next-2.6/net/mac802154/rx.c
--- linux/net/mac802154/rx.c	2014-09-24 09:52:43.236644963 +0200
+++ net-next-2.6/net/mac802154/rx.c	2014-10-06 10:49:03.424933002 +0200
@@ -86,9 +86,8 @@
 static void mac802154_rx_worker(struct work_struct *work)
 {
 	struct rx_work *rw = container_of(work, struct rx_work, work);
-	struct sk_buff *skb = rw->skb;
 
-	mac802154_subif_rx(rw->dev, skb, rw->lqi);
+	mac802154_subif_rx(rw->dev, rw->skb, rw->lqi);
 	kfree(rw);
 }
 
@@ -101,7 +100,7 @@
 	if (!skb)
 		return;
 
-	work = kzalloc(sizeof(struct rx_work), GFP_ATOMIC);
+	work = kzalloc(sizeof(*work), GFP_ATOMIC);
 	if (!work)
 		return;
 
diff -urN linux/net/mac802154/tx.c net-next-2.6/net/mac802154/tx.c
--- linux/net/mac802154/tx.c	2014-09-24 09:52:43.236644963 +0200
+++ net-next-2.6/net/mac802154/tx.c	2014-10-06 10:49:03.424933002 +0200
@@ -89,8 +89,7 @@
 
 	if (!(priv->phy->channels_supported[page] & (1 << chan))) {
 		WARN_ON(1);
-		kfree_skb(skb);
-		return NETDEV_TX_OK;
+		goto err_tx;
 	}
 
 	mac802154_monitors_rx(mac802154_to_priv(&priv->hw), skb);
@@ -103,12 +102,10 @@
 		data[1] = crc >> 8;
 	}
 
-	if (skb_cow_head(skb, priv->hw.extra_tx_headroom)) {
-		kfree_skb(skb);
-		return NETDEV_TX_OK;
-	}
+	if (skb_cow_head(skb, priv->hw.extra_tx_headroom))
+		goto err_tx;
 
-	work = kzalloc(sizeof(struct xmit_work), GFP_ATOMIC);
+	work = kzalloc(sizeof(*work), GFP_ATOMIC);
 	if (!work) {
 		kfree_skb(skb);
 		return NETDEV_TX_BUSY;
@@ -129,4 +126,8 @@
 	queue_work(priv->dev_workqueue, &work->work);
 
 	return NETDEV_TX_OK;
+
+err_tx:
+	kfree_skb(skb);
+	return NETDEV_TX_OK;
 }
diff -urN linux/net/mac802154/wpan.c net-next-2.6/net/mac802154/wpan.c
--- linux/net/mac802154/wpan.c	2014-09-24 09:52:43.236644963 +0200
+++ net-next-2.6/net/mac802154/wpan.c	2014-10-06 10:49:03.424933002 +0200
@@ -475,8 +475,7 @@
 	rc = mac802154_llsec_decrypt(&sdata->sec, skb);
 	if (rc) {
 		pr_debug("decryption failed: %i\n", rc);
-		kfree_skb(skb);
-		return NET_RX_DROP;
+		goto fail;
 	}
 
 	sdata->dev->stats.rx_packets++;
@@ -488,9 +487,12 @@
 	default:
 		pr_warn("ieee802154: bad frame received (type = %d)\n",
 			mac_cb(skb)->type);
-		kfree_skb(skb);
-		return NET_RX_DROP;
+		goto fail;
 	}
+
+fail:
+	kfree_skb(skb);
+	return NET_RX_DROP;
 }
 
 static void mac802154_print_addr(const char *name,
