--- drivers/net/ethernet/intel/fm10k/fm10k_main.c.orig	2016-03-15 15:58:21.000000000 +0100
+++ drivers/net/ethernet/intel/fm10k/fm10k_main.c	2016-03-15 16:05:37.000000000 +0100
@@ -1936,6 +1936,10 @@
 {
 	u16 i, rss_i = interface->ring_feature[RING_F_RSS].indices;
 	u32 reta, base;
+	u32 offset = 0;
+
+	if(rss_i > 1)
+		offset = 0x01010101;
 
 	/* If the netdev is initialized we have to maintain table if possible */
 	if (interface->netdev->reg_state != NETREG_UNINITIALIZED) {
@@ -1958,6 +1962,9 @@
 	 * we are generating the results for n and n+2 and then interleaving
 	 * those with the results with n+1 and n+3.
 	 */
+
+	/* Do not distribute to queue 0 */
+	if(offset) rss_i--;
 	for (i = FM10K_RETA_SIZE; i--;) {
 		/* first pass generates n and n+2 */
 		base = ((i * 0x00040004) + 0x00020000) * rss_i;
@@ -1967,7 +1974,7 @@
 		base += 0x00010001 * rss_i;
 		reta |= (base & 0x3F803F80) << 1;
 
-		interface->reta[i] = reta;
+		interface->reta[i] = reta + offset;
 	}
 }
 
