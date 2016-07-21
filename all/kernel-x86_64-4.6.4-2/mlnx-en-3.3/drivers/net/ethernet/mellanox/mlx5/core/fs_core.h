/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _MLX5_FS_CORE_
#define _MLX5_FS_CORE_

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/mutex.h>

#include <linux/mlx5/fs.h>

enum fs_type {
	FS_TYPE_NAMESPACE,
	FS_TYPE_PRIO,
	FS_TYPE_FLOW_TABLE,
	FS_TYPE_FLOW_GROUP,
	FS_TYPE_FLOW_ENTRY,
	FS_TYPE_FLOW_DEST
};

enum fs_ft_type {
	FS_FT_NIC_RX          = 0x0,
	FS_FT_ESW_EGRESS_ACL  = 0x2,
	FS_FT_ESW_INGRESS_ACL = 0x3,
	FS_FT_FDB             = 0X4,
	FS_FT_SNIFFER_RX      = 0x5,
	FS_FT_SNIFFER_TX      = 0x6
};

enum fs_fte_status {
	FS_FTE_STATUS_EXISTING = 1UL << 0,
};

struct fs_debugfs_base {
	struct dentry		*dir;
	struct dentry		*type;
	struct dentry           *users_refcount;
};

/* Should always be the first variable in the struct */
struct fs_base {
	struct list_head		list;
	struct fs_base			*parent;
	enum fs_type			type;
	struct kref			refcount;
	/* lock the node for writing and traversing */
	struct mutex			lock;
	struct completion		complete;
	atomic_t			users_refcount;
	const char			*name;
	struct fs_debugfs_base		debugfs;
};

struct fs_debugfs_dst {
	struct dentry *type;
	union {
		struct dentry *tir;
		struct dentry *ft;
	};
};

struct mlx5_flow_rule {
	struct fs_base				base;
	struct mlx5_flow_destination		dest_attr;
	struct list_head			clients_data;
	/*protect clients lits*/
	struct mutex				clients_lock;
	struct fs_debugfs_dst			debugfs;
};

struct fs_debugfs_match_misc_params {
	struct dentry *dir;
	struct dentry *src_port;
};

struct fs_debugfs_match_layer_2_4 {
	struct dentry *dir;
	struct dentry *dmac;
	struct dentry *smac;
	struct dentry *vid;
	struct dentry *src_ip;
	struct dentry *dst_ip;
	struct dentry *udp_sport;
	struct dentry *udp_dport;
	struct dentry *tcp_sport;
	struct dentry *tcp_dport;
	struct dentry *ethertype;
	struct dentry *ip_protocol;
};

struct fs_debugfs_match_header_ctx {
	struct fs_base *base;
	char	*addr;
	struct fs_debugfs_match_layer_2_4	header_files;
};

struct fs_debugfs_misc_params_ctx {
	struct fs_base *base;
	char	*addr;
	struct fs_debugfs_match_misc_params	misc_params;
};

struct fs_debugfs_match_criteria {
	struct dentry *dir;
	struct fs_debugfs_match_header_ctx		outer_headers_ctx;
	struct fs_debugfs_match_header_ctx		inner_headers_ctx;
	struct fs_debugfs_misc_params_ctx		misc_params_ctx;
};

struct fs_debugfs_fte {
	struct dentry				*index;
	struct dentry				*action;
	struct dentry				*flow_tag;
	struct dentry				*dests_size;
	struct dentry				*dests;
	struct fs_debugfs_match_criteria	match_criteria;
};

struct fs_fte {
	struct fs_base				base;
	u32					val[MLX5_ST_SZ_DW(fte_match_param)];
	uint32_t				dests_size;
	uint32_t				flow_tag;
	struct list_head			dests;
	uint32_t				index; /* index in ft */
	u8					action; /* MLX5_FLOW_CONTEXT_ACTION */
	enum fs_fte_status			status;
	struct fs_debugfs_fte			debugfs;
};

struct fs_debugfs_ft {
	struct dentry		*max_fte;
	struct dentry		*level;
	struct dentry		*id;
	struct {
		struct dentry	*dir;
		struct dentry	*max_types;
		struct dentry	*num_types;
	} autogroup;
	struct dentry		*fgs;
};

struct mlx5_flow_table {
	struct fs_base			base;
	/* sorted list by start_index */
	struct list_head		fgs;
	struct {
		bool				active;
		unsigned int			max_types;
		unsigned int			num_types;
		u32				flags;
	} autogroup;
	unsigned int			max_fte;
	unsigned int			level;
	uint32_t			id;
	u16                             vport;
	enum fs_ft_type			type;
	unsigned int			shared_refcount;
	struct mlx5_flow_table		*next_ft;
	struct fs_debugfs_ft		debugfs;
};

struct fs_debugfs_prio {
	struct dentry		*prio;
	struct dentry		*ns;
	struct dentry		*fts;
};

enum fs_prio_flags {
	MLX5_CORE_FS_PRIO_SHARED = 1
};

struct fs_prio {
	struct fs_base			base;
	struct list_head		objs; /* each object is a namespace or ft */
	unsigned int			num_levels;
	unsigned int			start_level;
	unsigned int			num_ft;
	unsigned int			max_ns;
	unsigned int			prio;
	struct fs_debugfs_prio		debugfs;
	/*When create shared flow table, this lock should be taken*/
	struct  mutex			shared_lock;
	u8				flags;
};

struct fs_debugfs_ns {
	struct dentry		*prios;
};

struct mlx5_flow_namespace {
	/* parent == NULL => root ns */
	struct	fs_base			base;
	/* sorted by priority number */
	struct	list_head		prios; /* list of fs_prios */
	struct  list_head		list_notifiers;
	struct	rw_semaphore		notifiers_rw_sem;
	struct  rw_semaphore		dests_rw_sem;
	struct	fs_debugfs_ns		debugfs;
};

struct mlx5_flow_root_namespace {
	struct mlx5_flow_namespace	ns;
	struct mlx5_flow_table		*ft_level_0;
	enum   fs_ft_type		table_type;
	struct mlx5_core_dev		*dev;
	struct mlx5_flow_table		*root_ft;
	/* When chaining flow-tables, this lock should be taken */
	struct mutex			fs_chain_lock;
};

struct fs_debugfs_mask {
	struct dentry				*match_criteria_enable;
	struct fs_debugfs_match_criteria	match_criteria;
};

struct fs_debugfs_fg {
	struct dentry				*start_index;
	struct dentry				*max_ftes;
	struct dentry				*num_ftes;
	struct dentry				*id;
	struct dentry				*ftes;
	struct fs_debugfs_mask			mask;
};

struct mlx5_flow_group {
	struct fs_base			base;
	struct list_head		ftes;
	struct mlx5_core_fs_mask	mask;
	uint32_t			start_index;
	uint32_t			max_ftes;
	uint32_t			num_ftes;
	uint32_t			id;
	struct fs_debugfs_fg		debugfs;
};

struct mlx5_flow_handler {
	struct list_head list;
	rule_event_fn add_dst_cb;
	rule_event_fn del_dst_cb;
	void *client_context;
	struct mlx5_flow_namespace *ns;
};

struct fs_client_priv_data {
	struct mlx5_flow_handler *fs_handler;
	struct list_head list;
	void   *client_dst_data;
};

/* debugfs API */
void fs_debugfs_remove(struct fs_base *base);
int fs_debugfs_add(struct fs_base *base);
void update_debugfs_dir_name(struct fs_base *base, const char *name);
void _fs_remove_node(struct kref *kref);
#define fs_get_obj(v, _base)  {v = container_of((_base), typeof(*v), base); }
#define fs_get_parent(v, child)  {v = (child)->base.parent ?		     \
				  container_of((child)->base.parent,	     \
					       typeof(*v), base) : NULL; }

#define fs_list_for_each_entry(pos, cond, root)		\
	list_for_each_entry(pos, root, base.list)	\
		if (!(cond)) {} else

#define fs_list_for_each_entry_continue(pos, cond, root)	\
	list_for_each_entry_continue(pos, root, base.list)	\
		if (!(cond)) {} else

#define fs_list_for_each_entry_reverse(pos, cond, root)		\
	list_for_each_entry_reverse(pos, root, base.list)	\
		if (!(cond)) {} else

#define fs_list_for_each_entry_continue_reverse(pos, cond, root)	\
	list_for_each_entry_continue_reverse(pos, root, base.list)	\
		if (!(cond)) {} else

#define fs_for_each_ft(pos, prio)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_FLOW_TABLE, \
			       &(prio)->objs)

#define fs_for_each_ft_reverse(pos, prio)			\
	fs_list_for_each_entry_reverse(pos,			\
				       (pos)->base.type == FS_TYPE_FLOW_TABLE, \
				       &(prio)->objs)

#define fs_for_each_ns(pos, prio)			\
	fs_list_for_each_entry(pos,			\
			       (pos)->base.type == FS_TYPE_NAMESPACE, \
			       &(prio)->objs)

#define fs_for_each_ns_or_ft_reverse(pos, prio)			\
	list_for_each_entry_reverse(pos, &(prio)->objs, list)		\
		if (!((pos)->type == FS_TYPE_NAMESPACE ||		\
		      (pos)->type == FS_TYPE_FLOW_TABLE)) {} else

#define fs_for_each_ns_or_ft(pos, prio)			\
	list_for_each_entry(pos, &(prio)->objs, list)		\
		if (!((pos)->type == FS_TYPE_NAMESPACE ||	\
		      (pos)->type == FS_TYPE_FLOW_TABLE)) {} else

#define fs_for_each_ns_or_ft_continue_reverse(pos, prio)		\
	list_for_each_entry_continue_reverse(pos, &(prio)->objs, list)	\
		if (!((pos)->type == FS_TYPE_NAMESPACE ||		\
		      (pos)->type == FS_TYPE_FLOW_TABLE)) {} else

#define fs_for_each_ns_or_ft_continue(pos, prio)			\
	list_for_each_entry_continue(pos, &(prio)->objs, list)		\
		if (!((pos)->type == FS_TYPE_NAMESPACE ||		\
		      (pos)->type == FS_TYPE_FLOW_TABLE)) {} else

#define fs_for_each_prio(pos, ns)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_PRIO, \
			       &(ns)->prios)

#define fs_for_each_prio_reverse(pos, ns)			\
	fs_list_for_each_entry_reverse(pos, (pos)->base.type == FS_TYPE_PRIO, \
				       &(ns)->prios)

#define fs_for_each_prio_continue(pos, ns)			\
	fs_list_for_each_entry_continue(pos, (pos)->base.type == FS_TYPE_PRIO, \
				       &(ns)->prios)

#define fs_for_each_prio_continue_reverse(pos, ns)			\
	fs_list_for_each_entry_continue_reverse(pos,			\
						(pos)->base.type == FS_TYPE_PRIO, \
						&(ns)->prios)

#define fs_for_each_fg(pos, ft)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_FLOW_GROUP, \
			       &(ft)->fgs)

#define fs_for_each_fte(pos, fg)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_FLOW_ENTRY, \
			       &(fg)->ftes)
#define fs_for_each_dst(pos, fte)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_FLOW_DEST, \
			       &(fte)->dests)

int mlx5_cmd_fs_create_ft(struct mlx5_core_dev *dev,
			  u16 vport,
			  enum fs_ft_type type, unsigned int level,
			  unsigned int log_size, struct mlx5_flow_table *next_ft,
			  unsigned int *table_id);

int mlx5_cmd_fs_destroy_ft(struct mlx5_core_dev *dev,
			   u16 vport,
			   enum fs_ft_type type, unsigned int table_id);

int mlx5_cmd_fs_create_fg(struct mlx5_core_dev *dev,
			  u32 *in,
			  u16 vport,
			  enum fs_ft_type type, unsigned int table_id,
			  unsigned int *group_id);

int mlx5_cmd_fs_destroy_fg(struct mlx5_core_dev *dev,
			   u16 vport,
			   enum fs_ft_type type, unsigned int table_id,
			   unsigned int group_id);


int mlx5_cmd_fs_set_fte(struct mlx5_core_dev *dev,
			u16 vport,
			enum fs_fte_status *fte_status,
			u32 *match_val,
			enum fs_ft_type type, unsigned int table_id,
			unsigned int index, unsigned int group_id,
			unsigned int flow_tag,
			unsigned short action, int dest_size,
			struct list_head *dests);  /* mlx5_flow_desination */

int mlx5_cmd_fs_delete_fte(struct mlx5_core_dev *dev,
			   u16 vport,
			   enum fs_fte_status *fte_status,
			   enum fs_ft_type type, unsigned int table_id,
			   unsigned int index);

int mlx5_cmd_update_root_ft(struct mlx5_core_dev *dev,
			    enum fs_ft_type type,
			    unsigned int id);

int mlx5_cmd_modify_flow_table(struct mlx5_core_dev *dev,
			       struct mlx5_flow_table *ft,
			       struct mlx5_flow_table *next_ft);

int mlx5_init_fs(struct mlx5_core_dev *dev);
void mlx5_cleanup_fs(struct mlx5_core_dev *dev);
#endif
