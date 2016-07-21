ccflags-y += $(MLNX_CFLAGS)

obj-$(CONFIG_MLX5_CORE)		+= mlx5_core.o

mlx5_core-y :=	main.o cmd.o debugfs.o fw.o eq.o uar.o pagealloc.o \
		health.o mcg.o cq.o srq.o alloc.o qp.o port.o mr.o pd.o   \
		mad.o wq.o vport.o transobj.o en_main.o \
		en_ethtool.o en_tx.o en_rx.o en_txrx.o \
		sriov.o params.o en_debugfs.o en_selftest.o en_sysfs.o en_ecn.o \
		en_dcb_nl.o fs_cmd.o fs_core.o fs_debugfs.o en_fs.o \
		eswitch.o vxlan.o en_clock.o en_sniffer.o rl.o
mlx5_core-$(CONFIG_RFS_ACCEL) +=  en_arfs.o
