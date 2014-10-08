diff -urN linux/net/dsa/dsa.c net-next-2.6/net/dsa/dsa.c
--- linux/net/dsa/dsa.c	2014-09-24 09:52:43.120643745 +0200
+++ net-next-2.6/net/dsa/dsa.c	2014-10-06 10:49:00.268900840 +0200
@@ -10,7 +10,6 @@
  */
 
 #include <linux/list.h>
-#include <linux/netdevice.h>
 #include <linux/platform_device.h>
 #include <linux/slab.h>
 #include <linux/module.h>
@@ -44,7 +43,7 @@
 EXPORT_SYMBOL_GPL(unregister_switch_driver);
 
 static struct dsa_switch_driver *
-dsa_switch_probe(struct mii_bus *bus, int sw_addr, char **_name)
+dsa_switch_probe(struct device *host_dev, int sw_addr, char **_name)
 {
 	struct dsa_switch_driver *ret;
 	struct list_head *list;
@@ -59,7 +58,7 @@
 
 		drv = list_entry(list, struct dsa_switch_driver, list);
 
-		name = drv->probe(bus, sw_addr);
+		name = drv->probe(host_dev, sw_addr);
 		if (name != NULL) {
 			ret = drv;
 			break;
@@ -76,7 +75,7 @@
 /* basic switch operations **************************************************/
 static struct dsa_switch *
 dsa_switch_setup(struct dsa_switch_tree *dst, int index,
-		 struct device *parent, struct mii_bus *bus)
+		 struct device *parent, struct device *host_dev)
 {
 	struct dsa_chip_data *pd = dst->pd->chip + index;
 	struct dsa_switch_driver *drv;
@@ -89,7 +88,7 @@
 	/*
 	 * Probe for switch model.
 	 */
-	drv = dsa_switch_probe(bus, pd->sw_addr, &name);
+	drv = dsa_switch_probe(host_dev, pd->sw_addr, &name);
 	if (drv == NULL) {
 		printk(KERN_ERR "%s[%d]: could not detect attached switch\n",
 		       dst->master_netdev->name, index);
@@ -110,8 +109,7 @@
 	ds->index = index;
 	ds->pd = dst->pd->chip + index;
 	ds->drv = drv;
-	ds->master_mii_bus = bus;
-
+	ds->master_dev = host_dev;
 
 	/*
 	 * Validate supplied switch configuration.
@@ -144,14 +142,44 @@
 		goto out;
 	}
 
+	/* Make the built-in MII bus mask match the number of ports,
+	 * switch drivers can override this later
+	 */
+	ds->phys_mii_mask = ds->phys_port_mask;
+
 	/*
 	 * If the CPU connects to this switch, set the switch tree
 	 * tagging protocol to the preferred tagging format of this
 	 * switch.
 	 */
-	if (ds->dst->cpu_switch == index)
-		ds->dst->tag_protocol = drv->tag_protocol;
+	if (dst->cpu_switch == index) {
+		switch (drv->tag_protocol) {
+#ifdef CONFIG_NET_DSA_TAG_DSA
+		case DSA_TAG_PROTO_DSA:
+			dst->rcv = dsa_netdev_ops.rcv;
+			break;
+#endif
+#ifdef CONFIG_NET_DSA_TAG_EDSA
+		case DSA_TAG_PROTO_EDSA:
+			dst->rcv = edsa_netdev_ops.rcv;
+			break;
+#endif
+#ifdef CONFIG_NET_DSA_TAG_TRAILER
+		case DSA_TAG_PROTO_TRAILER:
+			dst->rcv = trailer_netdev_ops.rcv;
+			break;
+#endif
+#ifdef CONFIG_NET_DSA_TAG_BRCM
+		case DSA_TAG_PROTO_BRCM:
+			dst->rcv = brcm_netdev_ops.rcv;
+			break;
+#endif
+		default:
+			break;
+		}
 
+		dst->tag_protocol = drv->tag_protocol;
+	}
 
 	/*
 	 * Do basic register setup.
@@ -210,6 +238,51 @@
 {
 }
 
+#ifdef CONFIG_PM_SLEEP
+static int dsa_switch_suspend(struct dsa_switch *ds)
+{
+	int i, ret = 0;
+
+	/* Suspend slave network devices */
+	for (i = 0; i < DSA_MAX_PORTS; i++) {
+		if (!(ds->phys_port_mask & (1 << i)))
+			continue;
+
+		ret = dsa_slave_suspend(ds->ports[i]);
+		if (ret)
+			return ret;
+	}
+
+	if (ds->drv->suspend)
+		ret = ds->drv->suspend(ds);
+
+	return ret;
+}
+
+static int dsa_switch_resume(struct dsa_switch *ds)
+{
+	int i, ret = 0;
+
+	if (ds->drv->resume)
+		ret = ds->drv->resume(ds);
+
+	if (ret)
+		return ret;
+
+	/* Resume slave network devices */
+	for (i = 0; i < DSA_MAX_PORTS; i++) {
+		if (!(ds->phys_port_mask & (1 << i)))
+			continue;
+
+		ret = dsa_slave_resume(ds->ports[i]);
+		if (ret)
+			return ret;
+	}
+
+	return 0;
+}
+#endif
+
 
 /* link polling *************************************************************/
 static void dsa_link_poll_work(struct work_struct *ugly)
@@ -256,7 +329,7 @@
 	return device_find_child(parent, class, dev_is_class);
 }
 
-static struct mii_bus *dev_to_mii_bus(struct device *dev)
+struct mii_bus *dsa_host_dev_to_mii_bus(struct device *dev)
 {
 	struct device *d;
 
@@ -272,6 +345,7 @@
 
 	return NULL;
 }
+EXPORT_SYMBOL_GPL(dsa_host_dev_to_mii_bus);
 
 static struct net_device *dev_to_net_device(struct device *dev)
 {
@@ -410,7 +484,8 @@
 		chip_index++;
 		cd = &pd->chip[chip_index];
 
-		cd->mii_bus = &mdio_bus->dev;
+		cd->of_node = child;
+		cd->host_dev = &mdio_bus->dev;
 
 		sw_addr = of_get_property(child, "reg", NULL);
 		if (!sw_addr)
@@ -431,6 +506,8 @@
 			if (!port_name)
 				continue;
 
+			cd->port_dn[port_index] = port;
+
 			cd->port_names[port_index] = kstrdup(port_name,
 					GFP_KERNEL);
 			if (!cd->port_names[port_index]) {
@@ -534,17 +611,9 @@
 	dst->cpu_port = -1;
 
 	for (i = 0; i < pd->nr_chips; i++) {
-		struct mii_bus *bus;
 		struct dsa_switch *ds;
 
-		bus = dev_to_mii_bus(pd->chip[i].mii_bus);
-		if (bus == NULL) {
-			printk(KERN_ERR "%s[%d]: no mii bus found for "
-				"dsa switch\n", dev->name, i);
-			continue;
-		}
-
-		ds = dsa_switch_setup(dst, i, &pdev->dev, bus);
+		ds = dsa_switch_setup(dst, i, &pdev->dev, pd->chip[i].host_dev);
 		if (IS_ERR(ds)) {
 			printk(KERN_ERR "%s[%d]: couldn't create dsa switch "
 				"instance (error %ld)\n", dev->name, i,
@@ -608,7 +677,62 @@
 {
 }
 
+static int dsa_switch_rcv(struct sk_buff *skb, struct net_device *dev,
+			  struct packet_type *pt, struct net_device *orig_dev)
+{
+	struct dsa_switch_tree *dst = dev->dsa_ptr;
+
+	if (unlikely(dst == NULL)) {
+		kfree_skb(skb);
+		return 0;
+	}
+
+	return dst->rcv(skb, dev, pt, orig_dev);
+}
+
+static struct packet_type dsa_pack_type __read_mostly = {
+	.type	= cpu_to_be16(ETH_P_XDSA),
+	.func	= dsa_switch_rcv,
+};
+
+#ifdef CONFIG_PM_SLEEP
+static int dsa_suspend(struct device *d)
+{
+	struct platform_device *pdev = to_platform_device(d);
+	struct dsa_switch_tree *dst = platform_get_drvdata(pdev);
+	int i, ret = 0;
+
+	for (i = 0; i < dst->pd->nr_chips; i++) {
+		struct dsa_switch *ds = dst->ds[i];
+
+		if (ds != NULL)
+			ret = dsa_switch_suspend(ds);
+	}
+
+	return ret;
+}
+
+static int dsa_resume(struct device *d)
+{
+	struct platform_device *pdev = to_platform_device(d);
+	struct dsa_switch_tree *dst = platform_get_drvdata(pdev);
+	int i, ret = 0;
+
+	for (i = 0; i < dst->pd->nr_chips; i++) {
+		struct dsa_switch *ds = dst->ds[i];
+
+		if (ds != NULL)
+			ret = dsa_switch_resume(ds);
+	}
+
+	return ret;
+}
+#endif
+
+static SIMPLE_DEV_PM_OPS(dsa_pm_ops, dsa_suspend, dsa_resume);
+
 static const struct of_device_id dsa_of_match_table[] = {
+	{ .compatible = "brcm,bcm7445-switch-v4.0" },
 	{ .compatible = "marvell,dsa", },
 	{}
 };
@@ -622,6 +746,7 @@
 		.name	= "dsa",
 		.owner	= THIS_MODULE,
 		.of_match_table = dsa_of_match_table,
+		.pm	= &dsa_pm_ops,
 	},
 };
 
@@ -633,30 +758,15 @@
 	if (rc)
 		return rc;
 
-#ifdef CONFIG_NET_DSA_TAG_DSA
-	dev_add_pack(&dsa_packet_type);
-#endif
-#ifdef CONFIG_NET_DSA_TAG_EDSA
-	dev_add_pack(&edsa_packet_type);
-#endif
-#ifdef CONFIG_NET_DSA_TAG_TRAILER
-	dev_add_pack(&trailer_packet_type);
-#endif
+	dev_add_pack(&dsa_pack_type);
+
 	return 0;
 }
 module_init(dsa_init_module);
 
 static void __exit dsa_cleanup_module(void)
 {
-#ifdef CONFIG_NET_DSA_TAG_TRAILER
-	dev_remove_pack(&trailer_packet_type);
-#endif
-#ifdef CONFIG_NET_DSA_TAG_EDSA
-	dev_remove_pack(&edsa_packet_type);
-#endif
-#ifdef CONFIG_NET_DSA_TAG_DSA
-	dev_remove_pack(&dsa_packet_type);
-#endif
+	dev_remove_pack(&dsa_pack_type);
 	platform_driver_unregister(&dsa_driver);
 }
 module_exit(dsa_cleanup_module);
diff -urN linux/net/dsa/dsa_priv.h net-next-2.6/net/dsa/dsa_priv.h
--- linux/net/dsa/dsa_priv.h	2013-05-02 09:43:20.609515169 +0200
+++ net-next-2.6/net/dsa/dsa_priv.h	2014-10-06 10:49:00.268900840 +0200
@@ -12,7 +12,13 @@
 #define __DSA_PRIV_H
 
 #include <linux/phy.h>
-#include <net/dsa.h>
+#include <linux/netdevice.h>
+
+struct dsa_device_ops {
+	netdev_tx_t (*xmit)(struct sk_buff *skb, struct net_device *dev);
+	int (*rcv)(struct sk_buff *skb, struct net_device *dev,
+		   struct packet_type *pt, struct net_device *orig_dev);
+};
 
 struct dsa_slave_priv {
 	/*
@@ -20,6 +26,8 @@
 	 * switch port.
 	 */
 	struct net_device	*dev;
+	netdev_tx_t		(*xmit)(struct sk_buff *skb,
+					struct net_device *dev);
 
 	/*
 	 * Which switch this port is a part of, and the port index
@@ -33,28 +41,35 @@
 	 * to this port.
 	 */
 	struct phy_device	*phy;
+	phy_interface_t		phy_interface;
+	int			old_link;
+	int			old_pause;
+	int			old_duplex;
 };
 
 /* dsa.c */
 extern char dsa_driver_version[];
 
 /* slave.c */
+extern const struct dsa_device_ops notag_netdev_ops;
 void dsa_slave_mii_bus_init(struct dsa_switch *ds);
 struct net_device *dsa_slave_create(struct dsa_switch *ds,
 				    struct device *parent,
 				    int port, char *name);
+int dsa_slave_suspend(struct net_device *slave_dev);
+int dsa_slave_resume(struct net_device *slave_dev);
 
 /* tag_dsa.c */
-netdev_tx_t dsa_xmit(struct sk_buff *skb, struct net_device *dev);
-extern struct packet_type dsa_packet_type;
+extern const struct dsa_device_ops dsa_netdev_ops;
 
 /* tag_edsa.c */
-netdev_tx_t edsa_xmit(struct sk_buff *skb, struct net_device *dev);
-extern struct packet_type edsa_packet_type;
+extern const struct dsa_device_ops edsa_netdev_ops;
 
 /* tag_trailer.c */
-netdev_tx_t trailer_xmit(struct sk_buff *skb, struct net_device *dev);
-extern struct packet_type trailer_packet_type;
+extern const struct dsa_device_ops trailer_netdev_ops;
+
+/* tag_brcm.c */
+extern const struct dsa_device_ops brcm_netdev_ops;
 
 
 #endif
diff -urN linux/net/dsa/Kconfig net-next-2.6/net/dsa/Kconfig
--- linux/net/dsa/Kconfig	2013-05-02 09:43:20.609515169 +0200
+++ net-next-2.6/net/dsa/Kconfig	2014-10-06 10:49:00.268900840 +0200
@@ -12,6 +12,9 @@
 if NET_DSA
 
 # tagging formats
+config NET_DSA_TAG_BRCM
+	bool
+
 config NET_DSA_TAG_DSA
 	bool
 
diff -urN linux/net/dsa/Makefile net-next-2.6/net/dsa/Makefile
--- linux/net/dsa/Makefile	2013-05-02 09:43:20.609515169 +0200
+++ net-next-2.6/net/dsa/Makefile	2014-10-06 10:49:00.268900840 +0200
@@ -3,6 +3,7 @@
 dsa_core-y += dsa.o slave.o
 
 # tagging formats
+dsa_core-$(CONFIG_NET_DSA_TAG_BRCM) += tag_brcm.o
 dsa_core-$(CONFIG_NET_DSA_TAG_DSA) += tag_dsa.o
 dsa_core-$(CONFIG_NET_DSA_TAG_EDSA) += tag_edsa.o
 dsa_core-$(CONFIG_NET_DSA_TAG_TRAILER) += tag_trailer.o
diff -urN linux/net/dsa/slave.c net-next-2.6/net/dsa/slave.c
--- linux/net/dsa/slave.c	2014-09-24 09:52:43.120643745 +0200
+++ net-next-2.6/net/dsa/slave.c	2014-10-06 10:49:00.268900840 +0200
@@ -9,9 +9,10 @@
  */
 
 #include <linux/list.h>
-#include <linux/netdevice.h>
 #include <linux/etherdevice.h>
 #include <linux/phy.h>
+#include <linux/of_net.h>
+#include <linux/of_mdio.h>
 #include "dsa_priv.h"
 
 /* slave mii_bus handling ***************************************************/
@@ -19,7 +20,7 @@
 {
 	struct dsa_switch *ds = bus->priv;
 
-	if (ds->phys_port_mask & (1 << addr))
+	if (ds->phys_mii_mask & (1 << addr))
 		return ds->drv->phy_read(ds, addr, reg);
 
 	return 0xffff;
@@ -29,7 +30,7 @@
 {
 	struct dsa_switch *ds = bus->priv;
 
-	if (ds->phys_port_mask & (1 << addr))
+	if (ds->phys_mii_mask & (1 << addr))
 		return ds->drv->phy_write(ds, addr, reg, val);
 
 	return 0;
@@ -43,7 +44,7 @@
 	ds->slave_mii_bus->write = dsa_slave_phy_write;
 	snprintf(ds->slave_mii_bus->id, MII_BUS_ID_SIZE, "dsa-%d:%.2x",
 			ds->index, ds->pd->sw_addr);
-	ds->slave_mii_bus->parent = &ds->master_mii_bus->dev;
+	ds->slave_mii_bus->parent = ds->master_dev;
 }
 
 
@@ -61,6 +62,7 @@
 {
 	struct dsa_slave_priv *p = netdev_priv(dev);
 	struct net_device *master = p->parent->dst->master_netdev;
+	struct dsa_switch *ds = p->parent;
 	int err;
 
 	if (!(master->flags & IFF_UP))
@@ -83,8 +85,20 @@
 			goto clear_allmulti;
 	}
 
+	if (ds->drv->port_enable) {
+		err = ds->drv->port_enable(ds, p->port, p->phy);
+		if (err)
+			goto clear_promisc;
+	}
+
+	if (p->phy)
+		phy_start(p->phy);
+
 	return 0;
 
+clear_promisc:
+	if (dev->flags & IFF_PROMISC)
+		dev_set_promiscuity(master, 0);
 clear_allmulti:
 	if (dev->flags & IFF_ALLMULTI)
 		dev_set_allmulti(master, -1);
@@ -99,6 +113,10 @@
 {
 	struct dsa_slave_priv *p = netdev_priv(dev);
 	struct net_device *master = p->parent->dst->master_netdev;
+	struct dsa_switch *ds = p->parent;
+
+	if (p->phy)
+		phy_stop(p->phy);
 
 	dev_mc_unsync(master, dev);
 	dev_uc_unsync(master, dev);
@@ -110,6 +128,9 @@
 	if (!ether_addr_equal(dev->dev_addr, master->dev_addr))
 		dev_uc_del(master, dev->dev_addr);
 
+	if (ds->drv->port_disable)
+		ds->drv->port_disable(ds, p->port, p->phy);
+
 	return 0;
 }
 
@@ -171,6 +192,24 @@
 	return -EOPNOTSUPP;
 }
 
+static netdev_tx_t dsa_slave_xmit(struct sk_buff *skb, struct net_device *dev)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+
+	return p->xmit(skb, dev);
+}
+
+static netdev_tx_t dsa_slave_notag_xmit(struct sk_buff *skb,
+					struct net_device *dev)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+
+	skb->dev = p->parent->dst->master_netdev;
+	dev_queue_xmit(skb);
+
+	return NETDEV_TX_OK;
+}
+
 
 /* ethtool operations *******************************************************/
 static int
@@ -282,6 +321,65 @@
 	return -EOPNOTSUPP;
 }
 
+static void dsa_slave_get_wol(struct net_device *dev, struct ethtool_wolinfo *w)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+	struct dsa_switch *ds = p->parent;
+
+	if (ds->drv->get_wol)
+		ds->drv->get_wol(ds, p->port, w);
+}
+
+static int dsa_slave_set_wol(struct net_device *dev, struct ethtool_wolinfo *w)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+	struct dsa_switch *ds = p->parent;
+	int ret = -EOPNOTSUPP;
+
+	if (ds->drv->set_wol)
+		ret = ds->drv->set_wol(ds, p->port, w);
+
+	return ret;
+}
+
+static int dsa_slave_set_eee(struct net_device *dev, struct ethtool_eee *e)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+	struct dsa_switch *ds = p->parent;
+	int ret;
+
+	if (!ds->drv->set_eee)
+		return -EOPNOTSUPP;
+
+	ret = ds->drv->set_eee(ds, p->port, p->phy, e);
+	if (ret)
+		return ret;
+
+	if (p->phy)
+		ret = phy_ethtool_set_eee(p->phy, e);
+
+	return ret;
+}
+
+static int dsa_slave_get_eee(struct net_device *dev, struct ethtool_eee *e)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+	struct dsa_switch *ds = p->parent;
+	int ret;
+
+	if (!ds->drv->get_eee)
+		return -EOPNOTSUPP;
+
+	ret = ds->drv->get_eee(ds, p->port, e);
+	if (ret)
+		return ret;
+
+	if (p->phy)
+		ret = phy_ethtool_get_eee(p->phy, e);
+
+	return ret;
+}
+
 static const struct ethtool_ops dsa_slave_ethtool_ops = {
 	.get_settings		= dsa_slave_get_settings,
 	.set_settings		= dsa_slave_set_settings,
@@ -291,46 +389,143 @@
 	.get_strings		= dsa_slave_get_strings,
 	.get_ethtool_stats	= dsa_slave_get_ethtool_stats,
 	.get_sset_count		= dsa_slave_get_sset_count,
+	.set_wol		= dsa_slave_set_wol,
+	.get_wol		= dsa_slave_get_wol,
+	.set_eee		= dsa_slave_set_eee,
+	.get_eee		= dsa_slave_get_eee,
 };
 
-#ifdef CONFIG_NET_DSA_TAG_DSA
-static const struct net_device_ops dsa_netdev_ops = {
-	.ndo_init		= dsa_slave_init,
-	.ndo_open	 	= dsa_slave_open,
-	.ndo_stop		= dsa_slave_close,
-	.ndo_start_xmit		= dsa_xmit,
-	.ndo_change_rx_flags	= dsa_slave_change_rx_flags,
-	.ndo_set_rx_mode	= dsa_slave_set_rx_mode,
-	.ndo_set_mac_address	= dsa_slave_set_mac_address,
-	.ndo_do_ioctl		= dsa_slave_ioctl,
-};
-#endif
-#ifdef CONFIG_NET_DSA_TAG_EDSA
-static const struct net_device_ops edsa_netdev_ops = {
+static const struct net_device_ops dsa_slave_netdev_ops = {
 	.ndo_init		= dsa_slave_init,
 	.ndo_open	 	= dsa_slave_open,
 	.ndo_stop		= dsa_slave_close,
-	.ndo_start_xmit		= edsa_xmit,
+	.ndo_start_xmit		= dsa_slave_xmit,
 	.ndo_change_rx_flags	= dsa_slave_change_rx_flags,
 	.ndo_set_rx_mode	= dsa_slave_set_rx_mode,
 	.ndo_set_mac_address	= dsa_slave_set_mac_address,
 	.ndo_do_ioctl		= dsa_slave_ioctl,
 };
-#endif
-#ifdef CONFIG_NET_DSA_TAG_TRAILER
-static const struct net_device_ops trailer_netdev_ops = {
-	.ndo_init		= dsa_slave_init,
-	.ndo_open	 	= dsa_slave_open,
-	.ndo_stop		= dsa_slave_close,
-	.ndo_start_xmit		= trailer_xmit,
-	.ndo_change_rx_flags	= dsa_slave_change_rx_flags,
-	.ndo_set_rx_mode	= dsa_slave_set_rx_mode,
-	.ndo_set_mac_address	= dsa_slave_set_mac_address,
-	.ndo_do_ioctl		= dsa_slave_ioctl,
-};
-#endif
+
+static void dsa_slave_adjust_link(struct net_device *dev)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+	struct dsa_switch *ds = p->parent;
+	unsigned int status_changed = 0;
+
+	if (p->old_link != p->phy->link) {
+		status_changed = 1;
+		p->old_link = p->phy->link;
+	}
+
+	if (p->old_duplex != p->phy->duplex) {
+		status_changed = 1;
+		p->old_duplex = p->phy->duplex;
+	}
+
+	if (p->old_pause != p->phy->pause) {
+		status_changed = 1;
+		p->old_pause = p->phy->pause;
+	}
+
+	if (ds->drv->adjust_link && status_changed)
+		ds->drv->adjust_link(ds, p->port, p->phy);
+
+	if (status_changed)
+		phy_print_status(p->phy);
+}
+
+static int dsa_slave_fixed_link_update(struct net_device *dev,
+				       struct fixed_phy_status *status)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+	struct dsa_switch *ds = p->parent;
+
+	if (ds->drv->fixed_link_update)
+		ds->drv->fixed_link_update(ds, p->port, status);
+
+	return 0;
+}
 
 /* slave device setup *******************************************************/
+static void dsa_slave_phy_setup(struct dsa_slave_priv *p,
+				struct net_device *slave_dev)
+{
+	struct dsa_switch *ds = p->parent;
+	struct dsa_chip_data *cd = ds->pd;
+	struct device_node *phy_dn, *port_dn;
+	bool phy_is_fixed = false;
+	u32 phy_flags = 0;
+	int ret;
+
+	port_dn = cd->port_dn[p->port];
+	p->phy_interface = of_get_phy_mode(port_dn);
+
+	phy_dn = of_parse_phandle(port_dn, "phy-handle", 0);
+	if (of_phy_is_fixed_link(port_dn)) {
+		/* In the case of a fixed PHY, the DT node associated
+		 * to the fixed PHY is the Port DT node
+		 */
+		ret = of_phy_register_fixed_link(port_dn);
+		if (ret) {
+			pr_err("failed to register fixed PHY\n");
+			return;
+		}
+		phy_is_fixed = true;
+		phy_dn = port_dn;
+	}
+
+	if (ds->drv->get_phy_flags)
+		phy_flags = ds->drv->get_phy_flags(ds, p->port);
+
+	if (phy_dn)
+		p->phy = of_phy_connect(slave_dev, phy_dn,
+					dsa_slave_adjust_link, phy_flags,
+					p->phy_interface);
+
+	if (p->phy && phy_is_fixed)
+		fixed_phy_set_link_update(p->phy, dsa_slave_fixed_link_update);
+
+	/* We could not connect to a designated PHY, so use the switch internal
+	 * MDIO bus instead
+	 */
+	if (!p->phy)
+		p->phy = ds->slave_mii_bus->phy_map[p->port];
+	else
+		pr_info("attached PHY at address %d [%s]\n",
+			p->phy->addr, p->phy->drv->name);
+}
+
+int dsa_slave_suspend(struct net_device *slave_dev)
+{
+	struct dsa_slave_priv *p = netdev_priv(slave_dev);
+
+	netif_device_detach(slave_dev);
+
+	if (p->phy) {
+		phy_stop(p->phy);
+		p->old_pause = -1;
+		p->old_link = -1;
+		p->old_duplex = -1;
+		phy_suspend(p->phy);
+	}
+
+	return 0;
+}
+
+int dsa_slave_resume(struct net_device *slave_dev)
+{
+	struct dsa_slave_priv *p = netdev_priv(slave_dev);
+
+	netif_device_attach(slave_dev);
+
+	if (p->phy) {
+		phy_resume(p->phy);
+		phy_start(p->phy);
+	}
+
+	return 0;
+}
+
 struct net_device *
 dsa_slave_create(struct dsa_switch *ds, struct device *parent,
 		 int port, char *name)
@@ -349,35 +544,48 @@
 	slave_dev->ethtool_ops = &dsa_slave_ethtool_ops;
 	eth_hw_addr_inherit(slave_dev, master);
 	slave_dev->tx_queue_len = 0;
+	slave_dev->netdev_ops = &dsa_slave_netdev_ops;
+
+	SET_NETDEV_DEV(slave_dev, parent);
+	slave_dev->dev.of_node = ds->pd->port_dn[port];
+	slave_dev->vlan_features = master->vlan_features;
+
+	p = netdev_priv(slave_dev);
+	p->dev = slave_dev;
+	p->parent = ds;
+	p->port = port;
 
 	switch (ds->dst->tag_protocol) {
 #ifdef CONFIG_NET_DSA_TAG_DSA
-	case htons(ETH_P_DSA):
-		slave_dev->netdev_ops = &dsa_netdev_ops;
+	case DSA_TAG_PROTO_DSA:
+		p->xmit = dsa_netdev_ops.xmit;
 		break;
 #endif
 #ifdef CONFIG_NET_DSA_TAG_EDSA
-	case htons(ETH_P_EDSA):
-		slave_dev->netdev_ops = &edsa_netdev_ops;
+	case DSA_TAG_PROTO_EDSA:
+		p->xmit = edsa_netdev_ops.xmit;
 		break;
 #endif
 #ifdef CONFIG_NET_DSA_TAG_TRAILER
-	case htons(ETH_P_TRAILER):
-		slave_dev->netdev_ops = &trailer_netdev_ops;
+	case DSA_TAG_PROTO_TRAILER:
+		p->xmit = trailer_netdev_ops.xmit;
+		break;
+#endif
+#ifdef CONFIG_NET_DSA_TAG_BRCM
+	case DSA_TAG_PROTO_BRCM:
+		p->xmit = brcm_netdev_ops.xmit;
 		break;
 #endif
 	default:
-		BUG();
+		p->xmit	= dsa_slave_notag_xmit;
+		break;
 	}
 
-	SET_NETDEV_DEV(slave_dev, parent);
-	slave_dev->vlan_features = master->vlan_features;
+	p->old_pause = -1;
+	p->old_link = -1;
+	p->old_duplex = -1;
 
-	p = netdev_priv(slave_dev);
-	p->dev = slave_dev;
-	p->parent = ds;
-	p->port = port;
-	p->phy = ds->slave_mii_bus->phy_map[port];
+	dsa_slave_phy_setup(p, slave_dev);
 
 	ret = register_netdev(slave_dev);
 	if (ret) {
@@ -390,6 +598,9 @@
 	netif_carrier_off(slave_dev);
 
 	if (p->phy != NULL) {
+		if (ds->drv->get_phy_flags(ds, port))
+			p->phy->dev_flags |= ds->drv->get_phy_flags(ds, port);
+
 		phy_attach(slave_dev, dev_name(&p->phy->dev),
 			   PHY_INTERFACE_MODE_GMII);
 
@@ -397,7 +608,6 @@
 		p->phy->speed = 0;
 		p->phy->duplex = 0;
 		p->phy->advertising = p->phy->supported | ADVERTISED_Autoneg;
-		phy_start_aneg(p->phy);
 	}
 
 	return slave_dev;
diff -urN linux/net/dsa/tag_brcm.c net-next-2.6/net/dsa/tag_brcm.c
--- linux/net/dsa/tag_brcm.c	1970-01-01 01:00:00.000000000 +0100
+++ net-next-2.6/net/dsa/tag_brcm.c	2014-10-06 10:49:00.272900881 +0200
@@ -0,0 +1,171 @@
+/*
+ * Broadcom tag support
+ *
+ * Copyright (C) 2014 Broadcom Corporation
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published by
+ * the Free Software Foundation; either version 2 of the License, or
+ * (at your option) any later version.
+ */
+
+#include <linux/etherdevice.h>
+#include <linux/list.h>
+#include <linux/slab.h>
+#include "dsa_priv.h"
+
+/* This tag length is 4 bytes, older ones were 6 bytes, we do not
+ * handle them
+ */
+#define BRCM_TAG_LEN	4
+
+/* Tag is constructed and desconstructed using byte by byte access
+ * because the tag is placed after the MAC Source Address, which does
+ * not make it 4-bytes aligned, so this might cause unaligned accesses
+ * on most systems where this is used.
+ */
+
+/* Ingress and egress opcodes */
+#define BRCM_OPCODE_SHIFT	5
+#define BRCM_OPCODE_MASK	0x7
+
+/* Ingress fields */
+/* 1st byte in the tag */
+#define BRCM_IG_TC_SHIFT	2
+#define BRCM_IG_TC_MASK		0x7
+/* 2nd byte in the tag */
+#define BRCM_IG_TE_MASK		0x3
+#define BRCM_IG_TS_SHIFT	7
+/* 3rd byte in the tag */
+#define BRCM_IG_DSTMAP2_MASK	1
+#define BRCM_IG_DSTMAP1_MASK	0xff
+
+/* Egress fields */
+
+/* 2nd byte in the tag */
+#define BRCM_EG_CID_MASK	0xff
+
+/* 3rd byte in the tag */
+#define BRCM_EG_RC_MASK		0xff
+#define  BRCM_EG_RC_RSVD	(3 << 6)
+#define  BRCM_EG_RC_EXCEPTION	(1 << 5)
+#define  BRCM_EG_RC_PROT_SNOOP	(1 << 4)
+#define  BRCM_EG_RC_PROT_TERM	(1 << 3)
+#define  BRCM_EG_RC_SWITCH	(1 << 2)
+#define  BRCM_EG_RC_MAC_LEARN	(1 << 1)
+#define  BRCM_EG_RC_MIRROR	(1 << 0)
+#define BRCM_EG_TC_SHIFT	5
+#define BRCM_EG_TC_MASK		0x7
+#define BRCM_EG_PID_MASK	0x1f
+
+static netdev_tx_t brcm_tag_xmit(struct sk_buff *skb, struct net_device *dev)
+{
+	struct dsa_slave_priv *p = netdev_priv(dev);
+	u8 *brcm_tag;
+
+	dev->stats.tx_packets++;
+	dev->stats.tx_bytes += skb->len;
+
+	if (skb_cow_head(skb, BRCM_TAG_LEN) < 0)
+		goto out_free;
+
+	skb_push(skb, BRCM_TAG_LEN);
+
+	memmove(skb->data, skb->data + BRCM_TAG_LEN, 2 * ETH_ALEN);
+
+	/* Build the tag after the MAC Source Address */
+	brcm_tag = skb->data + 2 * ETH_ALEN;
+
+	/* Set the ingress opcode, traffic class, tag enforcment is
+	 * deprecated
+	 */
+	brcm_tag[0] = (1 << BRCM_OPCODE_SHIFT) |
+			((skb->priority << BRCM_IG_TC_SHIFT) & BRCM_IG_TC_MASK);
+	brcm_tag[1] = 0;
+	brcm_tag[2] = 0;
+	if (p->port == 8)
+		brcm_tag[2] = BRCM_IG_DSTMAP2_MASK;
+	brcm_tag[3] = (1 << p->port) & BRCM_IG_DSTMAP1_MASK;
+
+	/* Queue the SKB for transmission on the parent interface, but
+	 * do not modify its EtherType
+	 */
+	skb->dev = p->parent->dst->master_netdev;
+	dev_queue_xmit(skb);
+
+	return NETDEV_TX_OK;
+
+out_free:
+	kfree_skb(skb);
+	return NETDEV_TX_OK;
+}
+
+static int brcm_tag_rcv(struct sk_buff *skb, struct net_device *dev,
+			struct packet_type *pt, struct net_device *orig_dev)
+{
+	struct dsa_switch_tree *dst = dev->dsa_ptr;
+	struct dsa_switch *ds;
+	int source_port;
+	u8 *brcm_tag;
+
+	if (unlikely(dst == NULL))
+		goto out_drop;
+
+	ds = dst->ds[0];
+
+	skb = skb_unshare(skb, GFP_ATOMIC);
+	if (skb == NULL)
+		goto out;
+
+	if (unlikely(!pskb_may_pull(skb, BRCM_TAG_LEN)))
+		goto out_drop;
+
+	/* skb->data points to the EtherType, the tag is right before it */
+	brcm_tag = skb->data - 2;
+
+	/* The opcode should never be different than 0b000 */
+	if (unlikely((brcm_tag[0] >> BRCM_OPCODE_SHIFT) & BRCM_OPCODE_MASK))
+		goto out_drop;
+
+	/* We should never see a reserved reason code without knowing how to
+	 * handle it
+	 */
+	WARN_ON(brcm_tag[2] & BRCM_EG_RC_RSVD);
+
+	/* Locate which port this is coming from */
+	source_port = brcm_tag[3] & BRCM_EG_PID_MASK;
+
+	/* Validate port against switch setup, either the port is totally */
+	if (source_port >= DSA_MAX_PORTS || ds->ports[source_port] == NULL)
+		goto out_drop;
+
+	/* Remove Broadcom tag and update checksum */
+	skb_pull_rcsum(skb, BRCM_TAG_LEN);
+
+	/* Move the Ethernet DA and SA */
+	memmove(skb->data - ETH_HLEN,
+		skb->data - ETH_HLEN - BRCM_TAG_LEN,
+		2 * ETH_ALEN);
+
+	skb_push(skb, ETH_HLEN);
+	skb->pkt_type = PACKET_HOST;
+	skb->dev = ds->ports[source_port];
+	skb->protocol = eth_type_trans(skb, skb->dev);
+
+	skb->dev->stats.rx_packets++;
+	skb->dev->stats.rx_bytes += skb->len;
+
+	netif_receive_skb(skb);
+
+	return 0;
+
+out_drop:
+	kfree_skb(skb);
+out:
+	return 0;
+}
+
+const struct dsa_device_ops brcm_netdev_ops = {
+	.xmit	= brcm_tag_xmit,
+	.rcv	= brcm_tag_rcv,
+};
diff -urN linux/net/dsa/tag_dsa.c net-next-2.6/net/dsa/tag_dsa.c
--- linux/net/dsa/tag_dsa.c	2013-05-02 09:43:20.609515169 +0200
+++ net-next-2.6/net/dsa/tag_dsa.c	2014-10-06 10:49:00.272900881 +0200
@@ -10,13 +10,12 @@
 
 #include <linux/etherdevice.h>
 #include <linux/list.h>
-#include <linux/netdevice.h>
 #include <linux/slab.h>
 #include "dsa_priv.h"
 
 #define DSA_HLEN	4
 
-netdev_tx_t dsa_xmit(struct sk_buff *skb, struct net_device *dev)
+static netdev_tx_t dsa_xmit(struct sk_buff *skb, struct net_device *dev)
 {
 	struct dsa_slave_priv *p = netdev_priv(dev);
 	u8 *dsa_header;
@@ -186,7 +185,7 @@
 	return 0;
 }
 
-struct packet_type dsa_packet_type __read_mostly = {
-	.type	= cpu_to_be16(ETH_P_DSA),
-	.func	= dsa_rcv,
+const struct dsa_device_ops dsa_netdev_ops = {
+	.xmit	= dsa_xmit,
+	.rcv	= dsa_rcv,
 };
diff -urN linux/net/dsa/tag_edsa.c net-next-2.6/net/dsa/tag_edsa.c
--- linux/net/dsa/tag_edsa.c	2013-05-02 09:43:20.609515169 +0200
+++ net-next-2.6/net/dsa/tag_edsa.c	2014-10-06 10:49:00.272900881 +0200
@@ -10,14 +10,13 @@
 
 #include <linux/etherdevice.h>
 #include <linux/list.h>
-#include <linux/netdevice.h>
 #include <linux/slab.h>
 #include "dsa_priv.h"
 
 #define DSA_HLEN	4
 #define EDSA_HLEN	8
 
-netdev_tx_t edsa_xmit(struct sk_buff *skb, struct net_device *dev)
+static netdev_tx_t edsa_xmit(struct sk_buff *skb, struct net_device *dev)
 {
 	struct dsa_slave_priv *p = netdev_priv(dev);
 	u8 *edsa_header;
@@ -205,7 +204,7 @@
 	return 0;
 }
 
-struct packet_type edsa_packet_type __read_mostly = {
-	.type	= cpu_to_be16(ETH_P_EDSA),
-	.func	= edsa_rcv,
+const struct dsa_device_ops edsa_netdev_ops = {
+	.xmit	= edsa_xmit,
+	.rcv	= edsa_rcv,
 };
diff -urN linux/net/dsa/tag_trailer.c net-next-2.6/net/dsa/tag_trailer.c
--- linux/net/dsa/tag_trailer.c	2013-05-02 09:43:20.609515169 +0200
+++ net-next-2.6/net/dsa/tag_trailer.c	2014-10-06 10:49:00.272900881 +0200
@@ -10,11 +10,10 @@
 
 #include <linux/etherdevice.h>
 #include <linux/list.h>
-#include <linux/netdevice.h>
 #include <linux/slab.h>
 #include "dsa_priv.h"
 
-netdev_tx_t trailer_xmit(struct sk_buff *skb, struct net_device *dev)
+static netdev_tx_t trailer_xmit(struct sk_buff *skb, struct net_device *dev)
 {
 	struct dsa_slave_priv *p = netdev_priv(dev);
 	struct sk_buff *nskb;
@@ -114,7 +113,7 @@
 	return 0;
 }
 
-struct packet_type trailer_packet_type __read_mostly = {
-	.type	= cpu_to_be16(ETH_P_TRAILER),
-	.func	= trailer_rcv,
+const struct dsa_device_ops trailer_netdev_ops = {
+	.xmit	= trailer_xmit,
+	.rcv	= trailer_rcv,
 };
