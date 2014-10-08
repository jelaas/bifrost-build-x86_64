diff -urN linux/net/mpls/mpls_gso.c net-next-2.6/net/mpls/mpls_gso.c
--- linux/net/mpls/mpls_gso.c	2014-09-24 09:52:43.244645047 +0200
+++ net-next-2.6/net/mpls/mpls_gso.c	2014-10-06 10:49:03.424933002 +0200
@@ -65,15 +65,9 @@
 	return segs;
 }
 
-static int mpls_gso_send_check(struct sk_buff *skb)
-{
-	return 0;
-}
-
 static struct packet_offload mpls_mc_offload = {
 	.type = cpu_to_be16(ETH_P_MPLS_MC),
 	.callbacks = {
-		.gso_send_check =	mpls_gso_send_check,
 		.gso_segment    =	mpls_gso_segment,
 	},
 };
@@ -81,7 +75,6 @@
 static struct packet_offload mpls_uc_offload = {
 	.type = cpu_to_be16(ETH_P_MPLS_UC),
 	.callbacks = {
-		.gso_send_check =	mpls_gso_send_check,
 		.gso_segment    =	mpls_gso_segment,
 	},
 };
