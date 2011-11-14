commit 35c745dbc9ac3947d9b61446d0a59b1a86f51636
Author: root <root@gatling.(none)>
Date:   Tue Apr 13 15:56:07 2010 +0200

    Added usual bifrost patches

diff --git a/drivers/net/igb/e1000_mac.c b/drivers/net/igb/e1000_mac.c
index be8d010..e8aa55e 100644
--- a/drivers/net/igb/e1000_mac.c
+++ b/drivers/net/igb/e1000_mac.c
@@ -678,7 +678,7 @@ static s32 igb_set_default_fc(struct e1000_hw *hw)
 		 NVM_WORD0F_ASM_DIR)
 		hw->fc.requested_mode = e1000_fc_tx_pause;
 	else
-		hw->fc.requested_mode = e1000_fc_full;
+		hw->fc.requested_mode = e1000_fc_none; //e1000_fc_full;
 
 out:
 	return ret_val;
diff --git a/drivers/net/ixgbe/ixgbe_common.c b/drivers/net/ixgbe/ixgbe_common.c
index 6eb5814..d240637 100644
--- a/drivers/net/ixgbe/ixgbe_common.c
+++ b/drivers/net/ixgbe/ixgbe_common.c
@@ -1937,6 +1937,8 @@ static s32 ixgbe_setup_fc(struct ixgbe_hw *hw, s32 packetbuf_num)
 	if (hw->fc.requested_mode == ixgbe_fc_default)
 		hw->fc.requested_mode = ixgbe_fc_full;
 
+	hw->fc.requested_mode = ixgbe_fc_none;
+
 	/*
 	 * Set up the 1G flow control advertisement registers so the HW will be
 	 * able to do fc autoneg once the cable is plugged in.  If we end up
diff --git a/drivers/net/ixgbe/ixgbe_main.c b/drivers/net/ixgbe/ixgbe_main.c
index 1b1419c..7935284 100644
--- a/drivers/net/ixgbe/ixgbe_main.c
+++ b/drivers/net/ixgbe/ixgbe_main.c
@@ -2380,9 +2380,9 @@ static void ixgbe_configure_rx(struct ixgbe_adapter *adapter)
 
 	if (adapter->flags & IXGBE_FLAG_RSS_ENABLED) {
 		/* Fill out redirection table */
-		for (i = 0, j = 0; i < 128; i++, j++) {
+		for (i = 0, j = 1; i < 128; i++, j++) { //
 			if (j == adapter->ring_feature[RING_F_RSS].indices)
-				j = 0;
+				j = 1; //
 			/* reta = 4-byte sliding window of
 			 * 0x00..(indices-1)(indices-1)00..etc. */
 			reta = (reta << 8) | (j * 0x11);
diff --git a/drivers/net/ixgbe/ixgbe_phy.c b/drivers/net/ixgbe/ixgbe_phy.c
index d6d5b84..306d0ee 100644
--- a/drivers/net/ixgbe/ixgbe_phy.c
+++ b/drivers/net/ixgbe/ixgbe_phy.c
@@ -678,6 +678,10 @@ s32 ixgbe_identify_sfp_module_generic(struct ixgbe_hw *hw)
 
 		/* This is guaranteed to be 82599, no need to check for NULL */
 		hw->mac.ops.get_device_caps(hw, &enforce_sfp);
+
+		hw->phy.type = ixgbe_phy_sfp_intel; /* Force to Intel to accept all SFP's */
+
+
 		if (!(enforce_sfp & IXGBE_DEVICE_CAPS_ALLOW_ANY_SFP)) {
 			/* Make sure we're a supported PHY type */
 			if (hw->phy.type == ixgbe_phy_sfp_intel) {
diff --git a/drivers/net/tulip/tulip_core.c b/drivers/net/tulip/tulip_core.c
index 22e766e..fc4ac6a 100644
--- a/drivers/net/tulip/tulip_core.c
+++ b/drivers/net/tulip/tulip_core.c
@@ -47,7 +47,7 @@ static char version[] __devinitdata =
 /* Maximum events (Rx packets, etc.) to handle at each interrupt. */
 static unsigned int max_interrupt_work = 25;
 
-#define MAX_UNITS 8
+#define MAX_UNITS 16
 /* Used to pass the full-duplex flag, etc. */
 static int full_duplex[MAX_UNITS];
 static int options[MAX_UNITS];
diff --git a/net/core/dev.c b/net/core/dev.c
index 876b111..5559369 100644
--- a/net/core/dev.c
+++ b/net/core/dev.c
@@ -5404,7 +5404,7 @@ int dev_change_net_namespace(struct net_device *dev, struct net *net, const char
 	if (dev->features & NETIF_F_NETNS_LOCAL)
 		goto out;
 
-#ifdef CONFIG_SYSFS
+#if 0 // CONFIG_SYSFS
 	/* Don't allow real devices to be moved when sysfs
 	 * is enabled.
 	 */
diff --git a/net/core/pktgen.c b/net/core/pktgen.c
index 2ad68da..48d004c 100644
--- a/net/core/pktgen.c
+++ b/net/core/pktgen.c
@@ -114,7 +114,9 @@
  * Fixed src_mac command to set source mac of packet to value specified in
  * command by Adit Ranadive <adit.262@gmail.com>
  *
+ * Receiver support and rate control by Daniel Turull <daniel.turull@gmail.com>
  */
+
 #include <linux/sys.h>
 #include <linux/types.h>
 #include <linux/module.h>
@@ -169,7 +171,7 @@
 #include <asm/dma.h>
 #include <asm/div64.h>		/* do_div */
 
-#define VERSION 	"2.73"
+#define VERSION 	"2.73g"
 #define IP_NAME_SZ 32
 #define MAX_MPLS_LABELS 16 /* This is the max label stack depth */
 #define MPLS_STACK_BOTTOM htonl(0x00000100)
@@ -204,8 +206,10 @@
 
 /* Used to help with determining the pkts on receive */
 #define PKTGEN_MAGIC 0xbe9be955
+#define PKTGEN_MAGIC_NET htonl(PKTGEN_MAGIC)
 #define PG_PROC_DIR "pktgen"
 #define PGCTRL	    "pgctrl"
+#define PGRX 	    "pgrx"
 static struct proc_dir_entry *pg_proc_dir;
 
 #define MAX_CFLOWS  65536
@@ -213,6 +217,8 @@ static struct proc_dir_entry *pg_proc_dir;
 #define VLAN_TAG_SIZE(x) ((x)->vlan_id == 0xffff ? 0 : 4)
 #define SVLAN_TAG_SIZE(x) ((x)->svlan_id == 0xffff ? 0 : 4)
 
+#define CONFIG_TIME 1000
+
 struct flow_state {
 	__be32 cur_daddr;
 	int count;
@@ -375,6 +381,7 @@ struct pktgen_dev {
 	u16 queue_map_max;
 	int node;               /* Memory node */
 
+	int config;
 #ifdef CONFIG_XFRM
 	__u8	ipsmode;		/* IPSEC mode (config) */
 	__u8	ipsproto;		/* IPSEC type (config) */
@@ -406,6 +413,36 @@ struct pktgen_thread {
 	struct completion start_done;
 };
 
+#define RX_COUNTER 	1
+#define RX_BASIC 	2
+#define RX_TIME		3
+#define PG_DISPLAY_TEXT 0
+#define PG_DISPLAY_NO_TEXT 1
+	/*Recevier parameters per cpu*/
+struct pktgen_rx {
+	u64 rx_packets; 		/*packets arrived*/
+	u64 rx_bytes;			/*bytes arrived*/
+
+	ktime_t start_time;		/*first time stamp of a packet*/
+	ktime_t last_time;		/*last packet arrival */
+	ktime_t last_time_skb;		/*last packet arrival */
+	__be32 last_seq;		/*last sequence number */
+	u64	last_time_tsc;
+	u64	inter_arrival_sum;
+	u64	inter_arrival_square_sum;
+	u64	inter_arrival_samples;
+	u64	inter_arrival_min;
+	u64	inter_arrival_max;
+};
+
+struct pktgen_rx_global {
+	u8 stats_option;
+	u8 display_option;
+	u64 rx_packets_expected;
+	int clone;
+	struct net_device * idev;
+};
+
 #define REMOVE 1
 #define FIND   0
 
@@ -438,6 +475,16 @@ static void pktgen_stop_all_threads_ifs(void);
 static void pktgen_stop(struct pktgen_thread *t);
 static void pktgen_clear_counters(struct pktgen_dev *pkt_dev);
 
+/*Receiver side functions*/
+int pktgen_rcv_basic(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
+int pktgen_rcv_time(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
+int pktgen_rcv_counter(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
+static int pktgen_add_rx(const char *ifname);
+int pktgen_set_statistics(const char * f);
+int pktgen_set_display(const char * f);
+static int pktgen_clean_rx(void);
+void pg_reset_rx(void);
+
 static unsigned int scan_ip6(const char *s, char ip[16]);
 static unsigned int fmt_ip6(char *s, const char ip[16]);
 
@@ -450,10 +497,21 @@ static int debug  __read_mostly;
 static DEFINE_MUTEX(pktgen_thread_lock);
 static LIST_HEAD(pktgen_threads);
 
+DEFINE_PER_CPU(struct pktgen_rx,pktgen_rx_data);
+static struct pktgen_rx_global *pg_rx_global;
+static int pg_initialized=0;
+
 static struct notifier_block pktgen_notifier_block = {
 	.notifier_call = pktgen_device_event,
 };
 
+/*Reception functions test*/
+static struct packet_type pktgen_packet_type __read_mostly = {
+	.type = __constant_htons(ETH_P_IP),
+	.func = pktgen_rcv_basic, 
+};
+
+
 /*
  * /proc handling functions
  *
@@ -954,6 +1012,17 @@ static ssize_t pktgen_if_write(struct file *file,
 		sprintf(pg_result, "OK: debug=%u", debug);
 		return count;
 	}
+	
+	/*if (!strcmp(name, "config")) {
+		len = num_arg(&user_buffer[i], 10, &value);
+		if (len < 0)
+			return len;
+
+		i += len;
+		pkt_dev->config = value;
+		sprintf(pg_result, "OK: config=%u", debug);
+		return count;
+	}*/
 
 	if (!strcmp(name, "frags")) {
 		len = num_arg(&user_buffer[i], 10, &value);
@@ -980,6 +1049,36 @@ static ssize_t pktgen_if_write(struct file *file,
 			(unsigned long long) pkt_dev->delay);
 		return count;
 	}
+	if (!strcmp(name, "rate")) {
+		len = num_arg(&user_buffer[i], 10, &value);
+		if (len < 0)
+			return len;
+
+		i += len;
+		if(value==0)
+			return len;
+		pkt_dev->delay=pkt_dev->min_pkt_size*8*NSEC_PER_USEC/value;
+		printk(KERN_INFO
+			 "pktgen: Delay set at: %llu ns\n",pkt_dev->delay);
+
+		sprintf(pg_result, "OK: rate=%lu",value);
+		return count;
+	}
+	if (!strcmp(name, "ratep")) {
+		len = num_arg(&user_buffer[i], 10, &value);
+		if (len < 0)
+			return len;
+
+		i += len;
+		if(value==0)
+			return len;
+		pkt_dev->delay=NSEC_PER_SEC/value;
+		printk(KERN_INFO
+			 "pktgen: Delay set at: %llu ns\n",pkt_dev->delay);
+
+		sprintf(pg_result, "OK: rate=%lu",value);
+		return count;
+	}
 	if (!strcmp(name, "udp_src_min")) {
 		len = num_arg(&user_buffer[i], 10, &value);
 		if (len < 0)
@@ -1842,6 +1941,268 @@ static const struct file_operations pktgen_thread_fops = {
 	.release = single_release,
 };
 
+#define DISPLAY_RX(opt,seq,fmt,fmt1, args...) \
+	if(opt==PG_DISPLAY_TEXT)seq_printf(seq, fmt1 , ## args);\
+	else seq_printf(seq, fmt , ## args);
+/*show Receiver statistics*/
+static int pgrx_show(struct seq_file *seq, void *v)
+{
+	__u64 bps,mbps,pps;
+	int cpu;
+	int option=PG_DISPLAY_TEXT;
+	u64 total_packets=0,total_bytes=0,work_time_us=0,packets=0,bytes=0;
+	__u64 inter_arrival_average=0, inter_arrival_var=0;
+	__u64 inter_arrival_average_ns=0,inter_arrival_var_ns2=0;
+	__u64 inter_arrival_max_ns=0,inter_arrival_min_ns=0;
+	ktime_t start_global, stop_global,tmp;
+	start_global.tv64=0;
+	stop_global.tv64=0;
+
+	seq_puts(seq, "\t\tRECEPTION STATISTICS\n");
+	if(pg_initialized==0){
+		seq_puts(seq, "Not enabled.\n");
+		return 0;
+	}
+	option=pg_rx_global->display_option;
+	DISPLAY_RX(option,seq,"CPU rx_pkts rx_bytes work_time pps Mb/s bps",
+		"\tPER-CPU Stats\n");
+	if(pg_rx_global->stats_option>RX_BASIC){
+		DISPLAY_RX(option,seq,
+			" inter_arrival_average inter_arrival_var inter_arrival_min inter_arrival_max", "\n");
+	}
+	for_each_online_cpu(cpu) {
+		DISPLAY_RX(option,seq,"\n%d ","CPU %d:",cpu);
+		packets=per_cpu(pktgen_rx_data,cpu).rx_packets;
+		bytes=per_cpu(pktgen_rx_data,cpu).rx_bytes;
+
+		total_packets+=packets;
+		total_bytes+=bytes;
+		DISPLAY_RX(option,seq,"%llu %llu ", 
+			"\tRx packets: %llu\t Rx bytes: %llu\n",
+			packets, bytes);
+
+		tmp=per_cpu(pktgen_rx_data,cpu).start_time;
+		if(start_global.tv64==0 && tmp.tv64!=0)
+			start_global=tmp;
+		else if(tmp.tv64<start_global.tv64 && tmp.tv64!=0)
+			start_global=tmp;
+
+		tmp=per_cpu(pktgen_rx_data,cpu).last_time;
+		if(ktime_to_ns(tmp)>ktime_to_ns(stop_global))
+			stop_global=tmp;
+
+		work_time_us = ktime_to_us(ktime_sub(
+			per_cpu(pktgen_rx_data,cpu).last_time,
+			per_cpu(pktgen_rx_data,cpu).start_time));
+		
+		if(work_time_us==0){
+			continue;
+		}
+
+		bps=div64_u64(bytes*8*USEC_PER_SEC,work_time_us);
+		mbps = bps;
+		do_div(mbps, 1000000);
+		pps = div64_u64(packets * USEC_PER_SEC,work_time_us);
+
+		DISPLAY_RX(option,seq,"%llu ","\tWorktime %llu us \n",
+			work_time_us);
+		DISPLAY_RX(option,seq,"%llu %llu %llu ",
+			"\tRate:  %llupps %llu Mb/sec (%llubps) \n",
+			(unsigned long long)pps,
+			(unsigned long long)mbps,
+		    	(unsigned long long)bps);
+
+		if(pg_rx_global->stats_option==RX_BASIC)
+			continue;
+			
+		if(per_cpu(pktgen_rx_data,cpu).inter_arrival_samples==0)
+			continue;
+
+		inter_arrival_average=
+			per_cpu(pktgen_rx_data,cpu).inter_arrival_sum/
+			per_cpu(pktgen_rx_data,cpu).inter_arrival_samples;
+		inter_arrival_var=
+			(per_cpu(pktgen_rx_data,cpu).inter_arrival_square_sum/
+			per_cpu(pktgen_rx_data,cpu).inter_arrival_samples)-
+			(inter_arrival_average*inter_arrival_average);
+		if(tsc_khz>0){
+			inter_arrival_average_ns=inter_arrival_average*
+				NSEC_PER_MSEC/tsc_khz;
+			inter_arrival_var_ns2=inter_arrival_var*
+				NSEC_PER_MSEC/tsc_khz;
+			inter_arrival_max_ns=per_cpu(pktgen_rx_data,cpu).
+				inter_arrival_max*NSEC_PER_MSEC/tsc_khz;
+			inter_arrival_min_ns=per_cpu(pktgen_rx_data,cpu).
+				inter_arrival_min*NSEC_PER_MSEC/tsc_khz;
+		}
+		DISPLAY_RX(option,seq," ","\tInter-arrival:\n");
+		DISPLAY_RX(option,seq,"%llu %llu ",
+			"\t\tAverage: %llu ns Variance %llu ns2\n",
+			inter_arrival_average_ns,
+			inter_arrival_var_ns2);
+		DISPLAY_RX(option,seq, "%llu %llu ",
+			"\t\tMax: %llu ns Min:: %llu ns\n", 
+			inter_arrival_max_ns,
+			inter_arrival_min_ns);
+	
+	}
+
+	DISPLAY_RX(option,seq,"\nG ","\n\tGlobal Statistics\n");
+
+	DISPLAY_RX(option,seq,"%llu %llu ",
+		"Packets Rx: %llu\t Bytes Rx: %llu \n",
+		(unsigned long long) total_packets,
+		(unsigned long long ) total_bytes);
+
+	/*Bandwidth*/	
+	work_time_us = ktime_to_us(ktime_sub(stop_global,start_global));
+
+	DISPLAY_RX(option,seq,"%llu ","Worktime  %llu us",
+		work_time_us);
+
+	if(work_time_us==0){
+		DISPLAY_RX(option,seq,"\n","\n");
+		return 0;
+	}
+	bps=div64_u64(total_bytes*8*USEC_PER_SEC,work_time_us);
+	mbps = bps;
+	do_div(mbps, 1000000);
+	pps = div64_u64(total_packets * USEC_PER_SEC,work_time_us);
+
+	//seq_puts(seq,"Received throughput: \n");
+
+	DISPLAY_RX(option,seq,"%llu %llu %llu\n",
+		"\n %llupps %llu Mb/sec (%llubps)\n",
+		(unsigned long long)pps,
+		(unsigned long long)mbps,
+		(unsigned long long)bps);
+
+	return 0;
+}
+/*receiver configuration*/
+static ssize_t pgrx_write(struct file *file, const char __user * user_buffer,
+			    size_t count, loff_t * ppos)
+{
+	int i = 0, max, len, ret;
+	char name[40];
+
+	if (count < 1) {
+		//      sprintf(pg_result, "Wrong command format");
+		return -EINVAL;
+	}
+
+	max = count - i;
+	len = count_trail_chars(&user_buffer[i], max);
+	if (len < 0)
+		return len;
+
+	i += len;
+
+	/* Read variable name */
+
+	len = strn_len(&user_buffer[i], sizeof(name) - 1);
+	if (len < 0)
+		return len;
+
+	memset(name, 0, sizeof(name));
+	if (copy_from_user(name, &user_buffer[i], len))
+		return -EFAULT;
+	i += len;
+
+	max = count - i;
+	len = count_trail_chars(&user_buffer[i], max);
+	if (len < 0)
+		return len;
+
+	i += len;
+
+	if (debug)
+		printk(KERN_DEBUG "pktgen: t=%s, count=%lu\n",
+		       name, (unsigned long)count);
+
+	if(!strcmp(name,"rx")){
+		char f[32];
+		memset(f, 0, 32);
+		len = strn_len(&user_buffer[i], sizeof(f) - 1);
+		if (len < 0) {
+			ret = len;
+			goto out;
+		}
+		if (copy_from_user(f, &user_buffer[i], len))
+			return -EFAULT;
+		i += len;
+		
+		if(debug)
+			printk(KERN_INFO "pktgen: Adding rx %s\n",f);
+		pktgen_add_rx(f);
+		ret = count;
+		goto out;
+	}else if(!strcmp(name,"rx_reset")){
+		ret=count;
+		pg_reset_rx();
+		if(debug)
+			printk(KERN_INFO "pktgen: Reseting reception\n");
+		goto out;
+	}else if(!strcmp(name,"statistics")){
+		char f[32];
+		memset(f, 0, 32);
+		len = strn_len(&user_buffer[i], sizeof(f) - 1);
+		if (len < 0) {
+			ret = len;
+			goto out;
+		}
+		if (copy_from_user(f, &user_buffer[i], len))
+			return -EFAULT;
+		i += len;
+		if(debug)printk(KERN_INFO "Setting statistics to %s\n",f);
+		//pktgen_packet_type
+		pktgen_set_statistics(f); 
+		ret = count;
+		goto out;
+	}else if(!strcmp(name,"display")){
+		char f[32];
+		memset(f, 0, 32);
+		len = strn_len(&user_buffer[i], sizeof(f) - 1);
+		if (len < 0) {
+			ret = len;
+			goto out;
+		}
+		if (copy_from_user(f, &user_buffer[i], len))
+			return -EFAULT;
+		i += len;
+
+		if(debug)printk(KERN_INFO "Setting display to %s\n",f);
+		//pktgen_packet_type
+		pktgen_set_display(f);
+		ret = count;
+		goto out;
+	}else if(!strcmp(name,"rx_disable")){
+		ret=count;
+		pktgen_clean_rx();
+		if(debug)
+			printk(KERN_INFO "pktgen: Cleaning reception\n");
+	}else
+		printk(KERN_WARNING "pktgen: Unknown command: %s\n", name);
+
+	ret = count;
+
+out:
+	return ret;
+}
+
+static int pgrx_open(struct inode *inode, struct file *file)
+{
+	return single_open(file, pgrx_show, PDE(inode)->data);
+}
+
+static const struct file_operations pktgen_rx_fops = {
+	.owner   = THIS_MODULE,
+	.open    = pgrx_open,
+	.read    = seq_read,
+	.llseek  = seq_lseek,
+	.write   = pgrx_write,
+	.release = single_release,
+};
 /* Think find or remove for NN */
 static struct pktgen_dev *__pktgen_NN_threads(const char *ifname, int remove)
 {
@@ -2142,15 +2503,15 @@ static void spin(struct pktgen_dev *pkt_dev, ktime_t spin_until)
 	hrtimer_init_on_stack(&t.timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
 	hrtimer_set_expires(&t.timer, spin_until);
 
-	remaining = ktime_to_us(hrtimer_expires_remaining(&t.timer));
+	remaining = ktime_to_ns(hrtimer_expires_remaining(&t.timer));
 	if (remaining <= 0) {
 		pkt_dev->next_tx = ktime_add_ns(spin_until, pkt_dev->delay);
 		return;
 	}
 
 	start_time = ktime_now();
-	if (remaining < 100)
-		udelay(remaining); 	/* really small just spin */
+	if (remaining < 100000)
+		ndelay(remaining); 	/* really small just spin */
 	else {
 		/* see do_nanosleep */
 		hrtimer_init_sleeper(&t, current);
@@ -2170,7 +2531,7 @@ static void spin(struct pktgen_dev *pkt_dev, ktime_t spin_until)
 	end_time = ktime_now();
 
 	pkt_dev->idle_acc += ktime_to_ns(ktime_sub(end_time, start_time));
-	pkt_dev->next_tx = ktime_add_ns(end_time, pkt_dev->delay);
+	pkt_dev->next_tx = ktime_add_ns(spin_until, pkt_dev->delay);
 }
 
 static inline void set_pkt_overhead(struct pktgen_dev *pkt_dev)
@@ -2754,10 +3115,11 @@ static struct sk_buff *fill_packet_ipv4(struct net_device *odev,
 	 */
 	if (pgh) {
 		struct timeval timestamp;
-
 		pgh->pgh_magic = htonl(PKTGEN_MAGIC);
-		pgh->seq_num = htonl(pkt_dev->seq_num);
-
+		/*if(unlikely(pkt_dev->config && pkt_dev->sofar==0))
+			pgh->seq_num = 0;
+		else*/
+			pgh->seq_num = htonl(pkt_dev->seq_num);
 		do_gettimeofday(&timestamp);
 		pgh->tv_sec = htonl(timestamp.tv_sec);
 		pgh->tv_usec = htonl(timestamp.tv_usec);
@@ -3297,7 +3659,7 @@ static void show_results(struct pktgen_dev *pkt_dev, int nr_frags)
 
 	mbps = bps;
 	do_div(mbps, 1000000);
-	p += sprintf(p, "  %llupps %lluMb/sec (%llubps) errors: %llu",
+	p += sprintf(p, "  %llupps %llu Mb/sec (%llubps) errors: %llu",
 		     (unsigned long long)pps,
 		     (unsigned long long)mbps,
 		     (unsigned long long)bps,
@@ -3474,7 +3836,6 @@ static void pktgen_xmit(struct pktgen_dev *pkt_dev)
 			      ++pkt_dev->clone_count >= pkt_dev->clone_skb)) {
 		/* build a new pkt */
 		kfree_skb(pkt_dev->skb);
-
 		pkt_dev->skb = fill_packet(odev, pkt_dev);
 		if (pkt_dev->skb == NULL) {
 			printk(KERN_ERR "pktgen: ERROR: couldn't "
@@ -3487,7 +3848,14 @@ static void pktgen_xmit(struct pktgen_dev *pkt_dev)
 		pkt_dev->allocated_skbs++;
 		pkt_dev->clone_count = 0;	/* reset counter */
 	}
-
+	/*if(unlikely(pkt_dev->config && pkt_dev->sofar==1)){
+		spin(pkt_dev,ktime_add_us(pkt_dev->next_tx,CONFIG_TIME));
+		pkt_dev->sofar--;
+		pkt_dev->config=0;
+		pkt_dev->clone_count = pkt_dev->clone_skb;
+		pkt_dev->started_at=ktime_now();
+	}*/
+		
 	if (pkt_dev->delay && pkt_dev->last_ok)
 		spin(pkt_dev, pkt_dev->next_tx);
 
@@ -3723,6 +4091,8 @@ static int pktgen_add_device(struct pktgen_thread *t, const char *ifname)
 	pkt_dev->svlan_id = 0xffff;
 	pkt_dev->node = -1;
 
+//	pkt_dev->config=0;
+
 	err = pktgen_setup_dev(pkt_dev, ifname);
 	if (err)
 		goto out1;
@@ -3852,6 +4222,262 @@ static int pktgen_remove_device(struct pktgen_thread *t,
 	return 0;
 }
 
+void pg_reset_rx(void)
+{
+	int cpu;
+	for_each_online_cpu(cpu) {
+		per_cpu(pktgen_rx_data,cpu).rx_packets=0;
+		per_cpu(pktgen_rx_data,cpu).rx_bytes=0;
+		per_cpu(pktgen_rx_data,cpu).last_seq=0;
+		per_cpu(pktgen_rx_data,cpu).last_time.tv64=0;
+		per_cpu(pktgen_rx_data,cpu).last_time_skb.tv64=0;
+		per_cpu(pktgen_rx_data,cpu).start_time.tv64=0;
+		per_cpu(pktgen_rx_data,cpu).inter_arrival_sum=0;
+		per_cpu(pktgen_rx_data,cpu).inter_arrival_square_sum=0;
+		per_cpu(pktgen_rx_data,cpu).inter_arrival_samples=0;
+		per_cpu(pktgen_rx_data,cpu).inter_arrival_max=0;
+		per_cpu(pktgen_rx_data,cpu).inter_arrival_min=ULLONG_MAX;
+	}		
+}
+static int pktgen_add_rx(const char *ifname)
+{
+	int err=0;
+	struct net_device *idev=NULL;
+
+	pg_reset_rx();
+
+	idev = pktgen_dev_get_by_name(NULL, ifname);
+	if (!idev)
+		printk(KERN_INFO 
+			"pktgen: device not present %s. Using all\n", ifname);
+
+	if(!pg_initialized){
+		pg_rx_global=kmalloc(sizeof(struct pktgen_rx_global),
+			GFP_KERNEL);
+		pg_rx_global->stats_option=RX_BASIC;
+		pg_rx_global->display_option=PG_DISPLAY_TEXT;
+
+		pg_rx_global->clone=0;
+		pg_rx_global->rx_packets_expected=0;
+		pktgen_packet_type.dev=idev;
+		dev_add_pack(&pktgen_packet_type);
+		err=0;
+		pg_initialized=1;
+	}else{
+		dev_remove_pack(&pktgen_packet_type);
+		pktgen_packet_type.dev=idev;
+		dev_add_pack(&pktgen_packet_type);
+		err=0;
+	}
+	pg_reset_rx();
+	return err;
+}
+
+/*Function for select the type of statisitcs*/
+int pktgen_set_statistics(const char *f)
+{
+	if(pg_rx_global==NULL)
+		return -ENOMEM;
+	if(!strcmp(f,"counter")){
+		net_disable_timestamp();
+		pg_rx_global->stats_option=RX_COUNTER;
+		pktgen_packet_type.func=pktgen_rcv_counter;
+		return 0;
+	}else if (!strcmp(f,"basic")){
+		net_disable_timestamp();
+		pg_rx_global->stats_option=RX_BASIC;
+		pktgen_packet_type.func=pktgen_rcv_basic;
+		return 0;
+	}else if(!strcmp(f,"time")){
+		net_enable_timestamp();
+		pg_rx_global->stats_option=RX_TIME;
+		pktgen_packet_type.func=pktgen_rcv_time;
+
+		return 0;
+	}else
+		return -EINVAL;
+
+}
+
+int pktgen_set_display(const char *f)
+{
+	if(pg_rx_global==NULL)
+		return -ENOMEM;
+	if(!strcmp(f,"text")){
+		pg_rx_global->display_option=PG_DISPLAY_TEXT;
+		return 0;
+	}else if(!strcmp(f,"no_text")){
+		pg_rx_global->display_option=PG_DISPLAY_NO_TEXT;
+		return 0;
+	}else
+		return -EINVAL;
+}
+
+/*
+ * Function for clean the statitics and disable the reception of packets
+ */
+static int pktgen_clean_rx(void)
+{
+	if(pg_initialized){
+		net_disable_timestamp();
+		kfree(pg_rx_global);
+		dev_remove_pack(&pktgen_packet_type);
+		pg_initialized=0;
+	}
+	return 0;
+}
+/*
+ * Check the packet header if its a configuration packet.
+ * If it is, configure pktgen receiver
+ */
+
+static int is_configure_packet(struct pktgen_hdr *pgh)
+{
+	if(pgh->seq_num!=0)
+		return 0;
+	printk(KERN_INFO "pktgen: received configure packet \n");
+	pg_reset_rx();
+	/*Read parameters*/
+	/*TODO implement function*/
+	return 0;
+}
+
+/*
+ * Function that gets the necessary data for througput calculation
+ */
+static int throughput_data(struct sk_buff *skb, struct pktgen_hdr *pgh)
+{
+	__be32 seq_num= htonl(pgh->seq_num);
+	if(unlikely(__get_cpu_var(pktgen_rx_data).rx_packets==0))
+		//__get_cpu_var(pktgen_rx_data).start_time=skb_get_ktime(skb);
+		__get_cpu_var(pktgen_rx_data).start_time=ktime_now();
+	
+	/*TODO change acording the flow chart*/
+	//__get_cpu_var(pktgen_rx_data).last_time=skb_get_ktime(skb);
+	__get_cpu_var(pktgen_rx_data).last_time=ktime_now();
+
+	__get_cpu_var(pktgen_rx_data).last_seq=seq_num;
+	return 0;
+}
+/*
+ * Function to collect inter_arrival data
+ * Should be called before throughput
+*/
+static int inter_arrival_calc(struct sk_buff *skb)
+{
+	u64 inter_arrival=0,last_time=0;
+	unsigned long long tsc_now;	
+
+	rdtscll(tsc_now);
+	last_time=__get_cpu_var(pktgen_rx_data).last_time_tsc;
+	if(last_time==0){ //first packet
+		__get_cpu_var(pktgen_rx_data).last_time_tsc=tsc_now;
+		return 0;
+	}
+
+	inter_arrival=tsc_now-last_time;
+	__get_cpu_var(pktgen_rx_data).inter_arrival_sum+=inter_arrival;
+	__get_cpu_var(pktgen_rx_data).inter_arrival_square_sum+=
+		inter_arrival*inter_arrival;
+	__get_cpu_var(pktgen_rx_data).inter_arrival_samples++;
+
+	if(inter_arrival>__get_cpu_var(pktgen_rx_data).inter_arrival_max)
+		__get_cpu_var(pktgen_rx_data).inter_arrival_max=inter_arrival;
+	if(inter_arrival<__get_cpu_var(pktgen_rx_data).inter_arrival_min)
+		__get_cpu_var(pktgen_rx_data).inter_arrival_min=inter_arrival;
+	/*Maybe is not necessary due it's also in throughput*/
+	__get_cpu_var(pktgen_rx_data).last_time_tsc=tsc_now;
+	
+	return 0;
+}	
+
+static int jitter_calc(struct sk_buff *skb)
+{
+	return 0;
+}
+static int latency_calc(struct sk_buff *skb)
+{
+	
+	return 0;
+}
+
+/*Reception function*/
+int pktgen_rcv_counter(struct sk_buff *skb, struct net_device *dev, 
+			struct packet_type *pt, struct net_device *orig_dev)
+{
+	/*check magic*/
+	struct iphdr *iph=ip_hdr(skb);
+	struct pktgen_hdr *pgh = (struct pktgen_hdr *)(((char *)(iph)) + 28);
+
+	/*CHECK PKTGEN MAGIC*/
+	if(unlikely(pgh->pgh_magic!= PKTGEN_MAGIC_NET))
+		goto end;
+	
+	if(unlikely(is_configure_packet(pgh)))
+		goto end;	
+
+	/*update counter of packets*/
+	__get_cpu_var(pktgen_rx_data).rx_packets++;
+	__get_cpu_var(pktgen_rx_data).rx_bytes+=skb->len+14;
+	
+end:
+	kfree_skb(skb);
+	return 0;
+}
+
+
+int pktgen_rcv_basic(struct sk_buff *skb, struct net_device *dev,
+			 struct packet_type *pt, struct net_device *orig_dev)
+{
+	/*check magic*/
+	struct iphdr *iph=ip_hdr(skb);
+	struct pktgen_hdr *pgh = (struct pktgen_hdr *)(((char *)(iph)) + 28);
+	if(unlikely(pgh->pgh_magic!= PKTGEN_MAGIC_NET))
+		goto end;
+	
+	if(unlikely(is_configure_packet(pgh)))
+		goto end;	
+
+	throughput_data(skb,pgh);	
+
+	/*update counter of packets*/
+	__get_cpu_var(pktgen_rx_data).rx_packets++;
+	__get_cpu_var(pktgen_rx_data).rx_bytes+=skb->len+14;
+end:
+	kfree_skb(skb);
+	return 0;
+}
+
+
+
+int pktgen_rcv_time(struct sk_buff *skb, struct net_device *dev,
+			 struct packet_type *pt, struct net_device *orig_dev)
+{
+	/*check magic*/
+	struct iphdr *iph=ip_hdr(skb);
+	struct pktgen_hdr *pgh = (struct pktgen_hdr *)(((char *)(iph)) + 28);
+	if(unlikely(pgh->pgh_magic!= PKTGEN_MAGIC_NET))
+		goto end;
+	
+	if(unlikely(is_configure_packet(pgh)))
+		goto end;	
+
+	inter_arrival_calc(skb);
+	
+	jitter_calc(skb);
+
+	latency_calc(skb);
+	
+	throughput_data(skb,pgh);	
+
+	/*update counter of packets*/
+	__get_cpu_var(pktgen_rx_data).rx_packets++;
+	__get_cpu_var(pktgen_rx_data).rx_bytes+=skb->len+14;
+end:
+	kfree_skb(skb);
+	return 0;
+}
+
 static int __init pg_init(void)
 {
 	int cpu;
@@ -3874,6 +4500,15 @@ static int __init pg_init(void)
 	/* Register us to receive netdevice events */
 	register_netdevice_notifier(&pktgen_notifier_block);
 
+	/*Create proc rx*/	
+	pe = proc_create(PGRX, 0600, pg_proc_dir, &pktgen_rx_fops);
+	if (pe == NULL) {
+		printk(KERN_ERR "pktgen: ERROR: cannot create %s "
+		       "procfs entry.\n", PGRX);
+		proc_net_remove(&init_net, PG_PROC_DIR);
+		return -EINVAL;
+	}
+
 	for_each_online_cpu(cpu) {
 		int err;
 
@@ -3887,6 +4522,8 @@ static int __init pg_init(void)
 		printk(KERN_ERR "pktgen: ERROR: Initialization failed for "
 		       "all threads\n");
 		unregister_netdevice_notifier(&pktgen_notifier_block);
+		pktgen_clean_rx();
+		remove_proc_entry(PGRX, pg_proc_dir);
 		remove_proc_entry(PGCTRL, pg_proc_dir);
 		proc_net_remove(&init_net, PG_PROC_DIR);
 		return -ENODEV;
@@ -3912,6 +4549,10 @@ static void __exit pg_cleanup(void)
 
 	/* Un-register us from receiving netdevice events */
 	unregister_netdevice_notifier(&pktgen_notifier_block);
+	
+	pktgen_clean_rx();
+	/*remove rx proc*/
+	remove_proc_entry(PGRX, pg_proc_dir);
 
 	/* Clean up proc file system */
 	remove_proc_entry(PGCTRL, pg_proc_dir);
diff --git a/net/sched/sch_sfq.c b/net/sched/sch_sfq.c
index c5a9ac5..6a69f1f 100644
--- a/net/sched/sch_sfq.c
+++ b/net/sched/sch_sfq.c
@@ -76,11 +76,11 @@
 
 	It is easy to increase these values, but not in flight.  */
 
-#define SFQ_DEPTH		128
+#define SFQ_DEPTH		1024
 #define SFQ_HASH_DIVISOR	1024
 
 /* This type should contain at least SFQ_DEPTH*2 values */
-typedef unsigned char sfq_index;
+typedef unsigned short sfq_index;
 
 struct sfq_head
 {
