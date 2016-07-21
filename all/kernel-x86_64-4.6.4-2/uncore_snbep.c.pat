--- arch/x86/events/intel/uncore_snbep.c.orig	2016-07-21 16:02:43.000000000 +0200
+++ arch/x86/events/intel/uncore_snbep.c	2016-07-21 16:05:40.000000000 +0200
@@ -2868,27 +2868,10 @@
 	.format_group		= &hswep_uncore_cbox_format_group,
 };
 
-static struct intel_uncore_type bdx_uncore_sbox = {
-	.name			= "sbox",
-	.num_counters		= 4,
-	.num_boxes		= 4,
-	.perf_ctr_bits		= 48,
-	.event_ctl		= HSWEP_S0_MSR_PMON_CTL0,
-	.perf_ctr		= HSWEP_S0_MSR_PMON_CTR0,
-	.event_mask		= HSWEP_S_MSR_PMON_RAW_EVENT_MASK,
-	.box_ctl		= HSWEP_S0_MSR_PMON_BOX_CTL,
-	.msr_offset		= HSWEP_SBOX_MSR_OFFSET,
-	.ops			= &hswep_uncore_sbox_msr_ops,
-	.format_group		= &hswep_uncore_sbox_format_group,
-};
-
-#define BDX_MSR_UNCORE_SBOX	3
-
 static struct intel_uncore_type *bdx_msr_uncores[] = {
 	&bdx_uncore_ubox,
 	&bdx_uncore_cbox,
 	&hswep_uncore_pcu,
-	&bdx_uncore_sbox,
 	NULL,
 };
 
@@ -2897,10 +2880,6 @@
 	if (bdx_uncore_cbox.num_boxes > boot_cpu_data.x86_max_cores)
 		bdx_uncore_cbox.num_boxes = boot_cpu_data.x86_max_cores;
 	uncore_msr_uncores = bdx_msr_uncores;
-
-	/* BDX-DE doesn't have SBOX */
-	if (boot_cpu_data.x86_model == 86)
-		uncore_msr_uncores[BDX_MSR_UNCORE_SBOX] = NULL;
 }
 
 static struct intel_uncore_type bdx_uncore_ha = {
