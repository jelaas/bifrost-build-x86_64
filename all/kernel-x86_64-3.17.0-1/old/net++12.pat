diff -urN linux/net/sctp/input.c net-next-2.6/net/sctp/input.c
--- linux/net/sctp/input.c	2014-09-24 09:52:43.892651848 +0200
+++ net-next-2.6/net/sctp/input.c	2014-10-06 10:49:04.300941930 +0200
@@ -133,9 +133,13 @@
 	__skb_pull(skb, skb_transport_offset(skb));
 	if (skb->len < sizeof(struct sctphdr))
 		goto discard_it;
-	if (!sctp_checksum_disable && !skb_csum_unnecessary(skb) &&
-		  sctp_rcv_checksum(net, skb) < 0)
+
+	skb->csum_valid = 0; /* Previous value not applicable */
+	if (skb_csum_unnecessary(skb))
+		__skb_decr_checksum_unnecessary(skb);
+	else if (!sctp_checksum_disable && sctp_rcv_checksum(net, skb) < 0)
 		goto discard_it;
+	skb->csum_valid = 1;
 
 	skb_pull(skb, sizeof(struct sctphdr));
 
diff -urN linux/net/sctp/protocol.c net-next-2.6/net/sctp/protocol.c
--- linux/net/sctp/protocol.c	2014-09-24 09:52:43.896651891 +0200
+++ net-next-2.6/net/sctp/protocol.c	2014-10-06 10:49:04.312942052 +0200
@@ -366,7 +366,7 @@
 	if (addr->v4.sin_addr.s_addr != htonl(INADDR_ANY) &&
 	   ret != RTN_LOCAL &&
 	   !sp->inet.freebind &&
-	   !sysctl_ip_nonlocal_bind)
+	   !net->ipv4.sysctl_ip_nonlocal_bind)
 		return 0;
 
 	if (ipv6_only_sock(sctp_opt2sk(sp)))
