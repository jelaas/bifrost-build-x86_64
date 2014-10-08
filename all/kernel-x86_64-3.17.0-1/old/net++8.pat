diff -urN linux/net/ethernet/eth.c net-next-2.6/net/ethernet/eth.c
--- linux/net/ethernet/eth.c	2014-09-24 09:52:43.120643745 +0200
+++ net-next-2.6/net/ethernet/eth.c	2014-10-06 10:49:00.272900881 +0200
@@ -146,6 +146,33 @@
 EXPORT_SYMBOL(eth_rebuild_header);
 
 /**
+ * eth_get_headlen - determine the the length of header for an ethernet frame
+ * @data: pointer to start of frame
+ * @len: total length of frame
+ *
+ * Make a best effort attempt to pull the length for all of the headers for
+ * a given frame in a linear buffer.
+ */
+u32 eth_get_headlen(void *data, unsigned int len)
+{
+	const struct ethhdr *eth = (const struct ethhdr *)data;
+	struct flow_keys keys;
+
+	/* this should never happen, but better safe than sorry */
+	if (len < sizeof(*eth))
+		return len;
+
+	/* parse any remaining L2/L3 headers, check for L4 */
+	if (!__skb_flow_dissect(NULL, &keys, data,
+				eth->h_proto, sizeof(*eth), len))
+		return max_t(u32, keys.thoff, sizeof(*eth));
+
+	/* parse for any L4 headers */
+	return min_t(u32, __skb_get_poff(NULL, data, &keys, len), len);
+}
+EXPORT_SYMBOL(eth_get_headlen);
+
+/**
  * eth_type_trans - determine the packet's protocol ID.
  * @skb: received socket data
  * @dev: receiving network device
@@ -181,11 +208,8 @@
 	 * variants has been configured on the receiving interface,
 	 * and if so, set skb->protocol without looking at the packet.
 	 */
-	if (unlikely(netdev_uses_dsa_tags(dev)))
-		return htons(ETH_P_DSA);
-
-	if (unlikely(netdev_uses_trailer_tags(dev)))
-		return htons(ETH_P_TRAILER);
+	if (unlikely(netdev_uses_dsa(dev)))
+		return htons(ETH_P_XDSA);
 
 	if (likely(ntohs(eth->h_proto) >= ETH_P_802_3_MIN))
 		return eth->h_proto;
