diff -urN linux/lib/Kconfig.debug net-next-2.6/lib/Kconfig.debug
--- linux/lib/Kconfig.debug	2014-09-24 09:52:42.956642025 +0200
+++ net-next-2.6/lib/Kconfig.debug	2014-10-06 10:48:57.712874792 +0200
@@ -1672,7 +1672,8 @@
 	  against the BPF interpreter or BPF JIT compiler depending on the
 	  current setting. This is in particular useful for BPF JIT compiler
 	  development, but also to run regression tests against changes in
-	  the interpreter code.
+	  the interpreter code. It also enables test stubs for eBPF maps and
+	  verifier used by user space verifier testsuite.
 
 	  If unsure, say N.
 
diff -urN linux/lib/random32.c net-next-2.6/lib/random32.c
--- linux/lib/random32.c	2014-09-24 09:52:42.964642108 +0200
+++ net-next-2.6/lib/random32.c	2014-10-06 10:48:58.856886451 +0200
@@ -37,6 +37,7 @@
 #include <linux/jiffies.h>
 #include <linux/random.h>
 #include <linux/sched.h>
+#include <asm/unaligned.h>
 
 #ifdef CONFIG_RANDOM32_SELFTEST
 static void __init prandom_state_selftest(void);
@@ -96,27 +97,23 @@
  *	This is used for pseudo-randomness with no outside seeding.
  *	For more random results, use prandom_bytes().
  */
-void prandom_bytes_state(struct rnd_state *state, void *buf, int bytes)
+void prandom_bytes_state(struct rnd_state *state, void *buf, size_t bytes)
 {
-	unsigned char *p = buf;
-	int i;
+	u8 *ptr = buf;
 
-	for (i = 0; i < round_down(bytes, sizeof(u32)); i += sizeof(u32)) {
-		u32 random = prandom_u32_state(state);
-		int j;
-
-		for (j = 0; j < sizeof(u32); j++) {
-			p[i + j] = random;
-			random >>= BITS_PER_BYTE;
-		}
+	while (bytes >= sizeof(u32)) {
+		put_unaligned(prandom_u32_state(state), (u32 *) ptr);
+		ptr += sizeof(u32);
+		bytes -= sizeof(u32);
 	}
-	if (i < bytes) {
-		u32 random = prandom_u32_state(state);
 
-		for (; i < bytes; i++) {
-			p[i] = random;
-			random >>= BITS_PER_BYTE;
-		}
+	if (bytes > 0) {
+		u32 rem = prandom_u32_state(state);
+		do {
+			*ptr++ = (u8) rem;
+			bytes--;
+			rem >>= BITS_PER_BYTE;
+		} while (bytes > 0);
 	}
 }
 EXPORT_SYMBOL(prandom_bytes_state);
@@ -126,7 +123,7 @@
  *	@buf: where to copy the pseudo-random bytes to
  *	@bytes: the requested number of bytes
  */
-void prandom_bytes(void *buf, int bytes)
+void prandom_bytes(void *buf, size_t bytes)
 {
 	struct rnd_state *state = &get_cpu_var(net_rand_state);
 
@@ -137,7 +134,7 @@
 
 static void prandom_warmup(struct rnd_state *state)
 {
-	/* Calling RNG ten times to satify recurrence condition */
+	/* Calling RNG ten times to satisfy recurrence condition */
 	prandom_u32_state(state);
 	prandom_u32_state(state);
 	prandom_u32_state(state);
@@ -152,7 +149,7 @@
 
 static u32 __extract_hwseed(void)
 {
-	u32 val = 0;
+	unsigned int val = 0;
 
 	(void)(arch_get_random_seed_int(&val) ||
 	       arch_get_random_int(&val));
@@ -228,7 +225,7 @@
 	prandom_seed(entropy);
 
 	/* reseed every ~60 seconds, in [40 .. 80) interval with slack */
-	expires = 40 + (prandom_u32() % 40);
+	expires = 40 + prandom_u32_max(40);
 	seed_timer.expires = jiffies + msecs_to_jiffies(expires * MSEC_PER_SEC);
 
 	add_timer(&seed_timer);
diff -urN linux/lib/rhashtable.c net-next-2.6/lib/rhashtable.c
--- linux/lib/rhashtable.c	2014-10-06 10:59:24.251258923 +0200
+++ net-next-2.6/lib/rhashtable.c	2014-10-06 10:48:58.856886451 +0200
@@ -297,7 +297,7 @@
 
 	ASSERT_RHT_MUTEX(ht);
 
-	if (tbl->size <= HASH_MIN_SIZE)
+	if (ht->shift <= ht->p.min_shift)
 		return 0;
 
 	ntbl = bucket_table_alloc(tbl->size / 2, flags);
@@ -505,9 +505,10 @@
 }
 EXPORT_SYMBOL_GPL(rhashtable_lookup_compare);
 
-static size_t rounded_hashtable_size(unsigned int nelem)
+static size_t rounded_hashtable_size(struct rhashtable_params *params)
 {
-	return max(roundup_pow_of_two(nelem * 4 / 3), HASH_MIN_SIZE);
+	return max(roundup_pow_of_two(params->nelem_hint * 4 / 3),
+		   1UL << params->min_shift);
 }
 
 /**
@@ -565,8 +566,11 @@
 	    (!params->key_len && !params->obj_hashfn))
 		return -EINVAL;
 
+	params->min_shift = max_t(size_t, params->min_shift,
+				  ilog2(HASH_MIN_SIZE));
+
 	if (params->nelem_hint)
-		size = rounded_hashtable_size(params->nelem_hint);
+		size = rounded_hashtable_size(params);
 
 	tbl = bucket_table_alloc(size, GFP_KERNEL);
 	if (tbl == NULL)
diff -urN linux/lib/test_bpf.c net-next-2.6/lib/test_bpf.c
--- linux/lib/test_bpf.c	2014-09-24 09:52:42.976642235 +0200
+++ net-next-2.6/lib/test_bpf.c	2014-10-06 10:48:59.032888243 +0200
@@ -1342,6 +1342,44 @@
 		{ { 0, -1 } }
 	},
 	{
+		"INT: shifts by register",
+		.u.insns_int = {
+			BPF_MOV64_IMM(R0, -1234),
+			BPF_MOV64_IMM(R1, 1),
+			BPF_ALU32_REG(BPF_RSH, R0, R1),
+			BPF_JMP_IMM(BPF_JEQ, R0, 0x7ffffd97, 1),
+			BPF_EXIT_INSN(),
+			BPF_MOV64_IMM(R2, 1),
+			BPF_ALU64_REG(BPF_LSH, R0, R2),
+			BPF_MOV32_IMM(R4, -1234),
+			BPF_JMP_REG(BPF_JEQ, R0, R4, 1),
+			BPF_EXIT_INSN(),
+			BPF_ALU64_IMM(BPF_AND, R4, 63),
+			BPF_ALU64_REG(BPF_LSH, R0, R4), /* R0 <= 46 */
+			BPF_MOV64_IMM(R3, 47),
+			BPF_ALU64_REG(BPF_ARSH, R0, R3),
+			BPF_JMP_IMM(BPF_JEQ, R0, -617, 1),
+			BPF_EXIT_INSN(),
+			BPF_MOV64_IMM(R2, 1),
+			BPF_ALU64_REG(BPF_LSH, R4, R2), /* R4 = 46 << 1 */
+			BPF_JMP_IMM(BPF_JEQ, R4, 92, 1),
+			BPF_EXIT_INSN(),
+			BPF_MOV64_IMM(R4, 4),
+			BPF_ALU64_REG(BPF_LSH, R4, R4), /* R4 = 4 << 4 */
+			BPF_JMP_IMM(BPF_JEQ, R4, 64, 1),
+			BPF_EXIT_INSN(),
+			BPF_MOV64_IMM(R4, 5),
+			BPF_ALU32_REG(BPF_LSH, R4, R4), /* R4 = 5 << 5 */
+			BPF_JMP_IMM(BPF_JEQ, R4, 160, 1),
+			BPF_EXIT_INSN(),
+			BPF_MOV64_IMM(R0, -1),
+			BPF_EXIT_INSN(),
+		},
+		INTERNAL,
+		{ },
+		{ { 0, -1 } }
+	},
+	{
 		"INT: DIV + ABS",
 		.u.insns_int = {
 			BPF_ALU64_REG(BPF_MOV, R6, R1),
@@ -1697,6 +1735,27 @@
 		{ },
 		{ { 1, 0 } },
 	},
+	{
+		"load 64-bit immediate",
+		.u.insns_int = {
+			BPF_LD_IMM64(R1, 0x567800001234LL),
+			BPF_MOV64_REG(R2, R1),
+			BPF_MOV64_REG(R3, R2),
+			BPF_ALU64_IMM(BPF_RSH, R2, 32),
+			BPF_ALU64_IMM(BPF_LSH, R3, 32),
+			BPF_ALU64_IMM(BPF_RSH, R3, 32),
+			BPF_ALU64_IMM(BPF_MOV, R0, 0),
+			BPF_JMP_IMM(BPF_JEQ, R2, 0x5678, 1),
+			BPF_EXIT_INSN(),
+			BPF_JMP_IMM(BPF_JEQ, R3, 0x1234, 1),
+			BPF_EXIT_INSN(),
+			BPF_ALU64_IMM(BPF_MOV, R0, 1),
+			BPF_EXIT_INSN(),
+		},
+		INTERNAL,
+		{ },
+		{ { 0, 1 } }
+	},
 };
 
 static struct net_device dev;
@@ -1798,7 +1857,7 @@
 		break;
 
 	case INTERNAL:
-		fp = kzalloc(bpf_prog_size(flen), GFP_KERNEL);
+		fp = bpf_prog_alloc(bpf_prog_size(flen), 0);
 		if (fp == NULL) {
 			pr_cont("UNEXPECTED_FAIL no memory left\n");
 			*err = -ENOMEM;
@@ -1835,7 +1894,7 @@
 		     int runs, u64 *duration)
 {
 	u64 start, finish;
-	int ret, i;
+	int ret = 0, i;
 
 	start = ktime_to_us(ktime_get());
 
