--- linux/net/socket.c	2014-09-24 09:52:43.924652185 +0200
+++ net-next-2.6/net/socket.c	2014-10-06 10:49:04.328942215 +0200
@@ -610,7 +610,7 @@
 }
 EXPORT_SYMBOL(sock_release);
 
-void sock_tx_timestamp(const struct sock *sk, __u8 *tx_flags)
+void __sock_tx_timestamp(const struct sock *sk, __u8 *tx_flags)
 {
 	u8 flags = *tx_flags;
 
@@ -626,12 +626,9 @@
 	if (sk->sk_tsflags & SOF_TIMESTAMPING_TX_ACK)
 		flags |= SKBTX_ACK_TSTAMP;
 
-	if (sock_flag(sk, SOCK_WIFI_STATUS))
-		flags |= SKBTX_WIFI_STATUS;
-
 	*tx_flags = flags;
 }
-EXPORT_SYMBOL(sock_tx_timestamp);
+EXPORT_SYMBOL(__sock_tx_timestamp);
 
 static inline int __sock_sendmsg_nosec(struct kiocb *iocb, struct socket *sock,
 				       struct msghdr *msg, size_t size)
