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

#include "en.h"
#include <linux/mlx5/fs.h>
#include "linux/mlx5/vport.h"

enum {
	SNIFFER_ADD = 1,
	SNIFFER_DEL = 2,
};

enum mlx5e_sniffer_rule_type {
	SNIFFER_RULE,
	LEFTOVERS_RULE,
};

enum {
	MAX_SNIFF_FTES_PER_FG = (FS_MAX_ENTRIES / MAX_SNIFFER_FLOW_RULE_NUM),
};

struct mlx5e_info {
	struct list_head  list;
	struct mlx5e_priv *priv;
};

static struct list_head  mlx5e_dev_list;
static struct mutex mlx5e_dev_list_mutex;

/*Private functions*/
static void sniffer_del_rule_handler(struct work_struct *_work);
static void sniffer_add_rule_handler(struct work_struct *_work);

static void mlx5e_sniffer_build_tir_ctx(
	struct mlx5e_priv *priv,
	u32 *tirc,
	int tt)
{
	/*same domain*/
	MLX5_SET(tirc, tirc, transport_domain, priv->tdn);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
	MLX5_SET(tirc, tirc, inline_rqn, priv->channel[0]->rq.rqn);
}

static void mlx5e_sniffer_del_rule_info(
			struct mlx5_sniffer_rule_info *tmp)
{
	if (!tmp)
		return;

	kfree(tmp->fg_mask);
	kfree(tmp->fte_match_value);
	kfree(tmp);
}

static int mlx5e_sniffer_save_rule_info(
			struct mlx5_sniffer_rule_info **rule_info,
			struct mlx5_flow_rule *rule,
			struct mlx5_flow_rule_node *rule_node,
			int rule_type)
{
	struct mlx5_sniffer_rule_info *tmp;

	tmp = mlx5_vzalloc(sizeof(struct mlx5_sniffer_rule_info));
	if (!tmp)
		goto clean_up;

	tmp->fg_mask = mlx5_vzalloc(sizeof(struct mlx5_core_fs_mask));
	if (!tmp->fg_mask)
		goto clean_up;

	tmp->fte_match_value = mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!tmp->fte_match_value)
		goto clean_up;

	if (rule) { /*bypass rules*/
		mlx5_get_match_criteria(tmp->fg_mask->match_criteria, rule);
		mlx5_get_match_value(tmp->fte_match_value, rule);
		tmp->fg_mask->match_criteria_enable
			= mlx5_get_match_criteria_enable(rule);
	} else { /*roce rules*/
		memcpy(
			tmp->fg_mask->match_criteria,
			rule_node->match_criteria,
			sizeof(rule_node->match_criteria));
		memcpy(
			tmp->fte_match_value,
			rule_node->match_value,
			sizeof(rule_node->match_value));
		tmp->fg_mask->match_criteria_enable
			= rule_node->match_criteria_enable;
	}

	tmp->rule_type = rule_type;
	*rule_info = tmp;

	return 0;

clean_up:
	mlx5e_sniffer_del_rule_info(tmp);
	return -ENOMEM;
}

/*0 not match, 1 match*/
static bool mlx5e_sniffer_is_match_rule(
	struct mlx5_sniffer_rule_info *rule_info,
	struct mlx5_flow_rule *rule2)
{
	struct mlx5_core_fs_mask *fg_mask1 = NULL;
	struct mlx5_core_fs_mask *fg_mask2 = NULL;

	u32 *fte_match_value1 = NULL;
	u32 *fte_match_value2 = NULL;

	bool match = 0;

	/*Initialize*/
	fte_match_value1 = rule_info->fte_match_value;
	fg_mask1 = rule_info->fg_mask;

	fte_match_value2 = mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!fte_match_value2)
		goto clean_up;

	fg_mask2 = mlx5_vzalloc(sizeof(struct mlx5_core_fs_mask));
	if (!fg_mask2)
		goto clean_up;

	/*Get values*/
	mlx5_get_match_criteria(fg_mask2->match_criteria, rule2);
	mlx5_get_match_value(fte_match_value2, rule2);
	fg_mask2->match_criteria_enable = mlx5_get_match_criteria_enable(rule2);

	/*Compare*/
	match = 1;
	if (!(fs_match_exact_mask(
			fg_mask1->match_criteria_enable,
			fg_mask2->match_criteria_enable,
			fg_mask1->match_criteria,
			fg_mask2->match_criteria) &&
		fs_match_exact_val(
			fg_mask1,
			fte_match_value1,
			fte_match_value2))) {
		match = 0;
		goto clean_up;
	}

clean_up:
	kfree(fte_match_value2);
	kfree(fg_mask2);
	return match;
}

/*-1 : not exists*/
static int mlx5e_sniffer_check_rule_exist(
			struct mlx5_sniffer_rule_info *rule_info,
			struct mlx5e_sniffer_flow *flow_arr,
			int number_of_rule)
{
	int i;

	for (i = 0; i < number_of_rule; i++) {
		if (flow_arr[i].valid == 0)
			continue;

		if (mlx5e_sniffer_is_match_rule(
					rule_info,
					flow_arr[i].rx_dst))
			return i;
	}

	return -1;
}

static void mlx5e_sniffer_send_workqueue(
	struct mlx5e_priv *priv,
	struct mlx5_flow_rule *rule,
	int action, int rule_type)
{
	struct sniffer_work *work;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return;

	if (action == SNIFFER_ADD)
		INIT_WORK(&work->work, sniffer_add_rule_handler);
	else
		INIT_WORK(&work->work, sniffer_del_rule_handler);

	work->priv = priv;
	if (mlx5e_sniffer_save_rule_info(
		&work->rule_info, rule, NULL, rule_type)) {
			kfree(work);
			return;
	}
	queue_work(priv->fs.sniffer.sniffer_wq, &work->work);
}

static int mlx5e_sniffer_create_tx_rule(struct mlx5e_priv *priv)
{
	struct mlx5_flow_destination dest;
	u32 *match_criteria_value;
	int err = 0;
	int match_len = MLX5_ST_SZ_BYTES(fte_match_param);

	/*Create no filter rule*/
	match_criteria_value = mlx5_vzalloc(match_len);
	if (!match_criteria_value)
		return -ENOMEM;

	dest.tir_num = priv->sniffer_tirn[MLX5E_SNIFFER_TX];
	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	priv->fs.sniffer.tx_dst =
		mlx5_add_flow_rule(
			priv->fs.sniffer.tx_ft,
			0,
			match_criteria_value,
			match_criteria_value,
			MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
			MLX5_FS_SNIFFER_FLOW_TAG,
			&dest);
	if (IS_ERR_OR_NULL(priv->fs.sniffer.tx_dst)) {
		err = PTR_ERR(priv->fs.sniffer.tx_dst);
		priv->fs.sniffer.tx_dst = NULL;
	}

	kvfree(match_criteria_value);
	return err;
}

static int mlx5e_sniffer_build_flow(
				int index,
				struct mlx5e_priv *priv,
				struct mlx5_sniffer_rule_info *rule_info)
{
	int err;
	u32 *fg_match_criteria = NULL;
	u8 fg_match_criteria_enable;
	u32 *fte_match_value = NULL;
	struct mlx5_flow_destination dest;

	/*Copy fg, fte parameters*/
	fg_match_criteria = rule_info->fg_mask->match_criteria;
	fte_match_value = rule_info->fte_match_value;
	fg_match_criteria_enable = rule_info->fg_mask->match_criteria_enable;

	err = 0;
	if (rule_info->rule_type == SNIFFER_RULE) {
		/*Create rx and tx fte*/
		dest.tir_num = priv->sniffer_tirn[MLX5E_SNIFFER_RX];
		dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;

		priv->fs.sniffer.flow_arr[index].rx_dst =
			mlx5_add_flow_rule(
				priv->fs.sniffer.rx_ft,
				fg_match_criteria_enable,
				fg_match_criteria,
				fte_match_value,
				MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				MLX5_FS_SNIFFER_FLOW_TAG,
				&dest);
		if (IS_ERR_OR_NULL(priv->fs.sniffer.flow_arr[index].rx_dst)) {
			err = PTR_ERR(priv->fs.sniffer.flow_arr[index].rx_dst);
			priv->fs.sniffer.flow_arr[index].rx_dst = NULL;
			goto error;
		}

		priv->fs.sniffer.flow_arr[index].valid = 1;
		priv->fs.sniffer.flow_arr[index].ref_cnt = 1;
	} else { /*Leftovers*/
		/*Create rx leftovers fte*/
		dest.tir_num = priv->sniffer_tirn[MLX5E_LEFTOVERS_RX];
		dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
		priv->fs.sniffer.leftovers_flow_arr[index].rx_dst =
			mlx5_add_flow_rule(
				priv->fs.sniffer.leftovers_ft,
				fg_match_criteria_enable,
				fg_match_criteria,
				fte_match_value,
				MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				MLX5_FS_DEFAULT_FLOW_TAG, /*Bypass  flow tag*/
				&dest);
		if (IS_ERR_OR_NULL(
			priv->fs.sniffer.leftovers_flow_arr[index].rx_dst)) {
			err = PTR_ERR(priv->fs.sniffer.leftovers_flow_arr[index].rx_dst);
			priv->fs.sniffer.leftovers_flow_arr[index].rx_dst = NULL;
			goto error;
		}

		priv->fs.sniffer.leftovers_flow_arr[index].valid = 1;
		priv->fs.sniffer.leftovers_flow_arr[index].ref_cnt = 1;
	}

error:
	return err;
}

static void update_flow_table_info(
	int rule_type,
	struct mlx5e_priv *priv,
	struct mlx5e_sniffer_flow **flow_arr,
	int *number_of_rule)
{
	if (rule_type == SNIFFER_RULE) {
		*flow_arr = priv->fs.sniffer.flow_arr;
		*number_of_rule = MAX_SNIFFER_FLOW_RULE_NUM;
	} else {
		*flow_arr = priv->fs.sniffer.leftovers_flow_arr;
		*number_of_rule = LEFTOVERS_RULE_NUM;
	}
}

static void sniffer_del_rule_handler(struct work_struct *_work)
{
	struct sniffer_work *work;
	struct mlx5_sniffer_rule_info *rule_info;
	struct mlx5e_priv *priv;
	struct mlx5e_sniffer_flow *flow_arr;
	int number_of_rule;

	int i;

	work = container_of(_work, struct sniffer_work, work);
	priv = work->priv;
	rule_info = work->rule_info;

	update_flow_table_info(
		work->rule_info->rule_type,
		priv,
		&flow_arr,
		&number_of_rule);

	for (i = 0; i < number_of_rule; i++) {
		if (flow_arr[i].valid == 0)
			continue;

		if (mlx5e_sniffer_is_match_rule(
				rule_info,
				flow_arr[i].rx_dst)) {
			flow_arr[i].ref_cnt--;

			/*Quit if this is not the last dests in ALL FTs*/
			if (flow_arr[i].ref_cnt)
				break;

			if (flow_arr[i].rx_dst)
				mlx5_del_flow_rule(flow_arr[i].rx_dst);

			flow_arr[i].valid = 0;
			flow_arr[i].ref_cnt = 0;

			break;
		}
	}

	mlx5e_sniffer_del_rule_info(work->rule_info);
	kfree(work);
}

static void sniffer_add_rule_handler(struct work_struct *_work)
{
	struct sniffer_work *work;
	struct mlx5_sniffer_rule_info *rule_info;
	struct mlx5e_priv *priv;
	struct mlx5e_sniffer_flow *flow_arr;
	int number_of_rule;

	int i, err, match_idx;

	work = container_of(_work, struct sniffer_work, work);
	priv = work->priv;
	rule_info = work->rule_info;

	update_flow_table_info(
		work->rule_info->rule_type,
		priv,
		&flow_arr,
		&number_of_rule);

	/*Increase ref_cnt if rule already exists*/
	match_idx = mlx5e_sniffer_check_rule_exist(
					rule_info,
					flow_arr,
					number_of_rule);

	if (match_idx >= 0) {
		/*Leftovers FT is single FT with no duplicated rules*/
		WARN_ON(work->rule_info->rule_type == LEFTOVERS_RULE);
		flow_arr[match_idx].ref_cnt++;
		goto out;
	}

	err = 0;
	for (i = 0; i < number_of_rule; i++) {
		if (flow_arr[i].valid == 0) {
			err = mlx5e_sniffer_build_flow
					(i, priv, rule_info);
			if (err)
				mlx5_core_err(priv->mdev, "failed to create sniffer rule\n");
			break;
		}
	}

out:
	mlx5e_sniffer_del_rule_info(work->rule_info);
	kfree(work);
}

static int mlx5e_sniffer_del_bypass_rule_callback_fn(
			struct mlx5_flow_rule *rule,
			bool ctx_changed,
			void *client_data,
			void *context)
{
	struct mlx5e_priv *priv;

	priv = (struct mlx5e_priv *)context;

	/*Skip if event is deactivated*/
	if (!priv->fs.sniffer.bypass_event)
		return 0;

	/*No duplicated rule guaranteed by this check*/
	if (!ctx_changed)
		return 0;

	mlx5e_sniffer_send_workqueue(priv, rule, SNIFFER_DEL, SNIFFER_RULE);
	return 0;
}

static int mlx5e_sniffer_add_bypass_rule_callback_fn(
				struct mlx5_flow_rule *rule,
				bool ctx_changed,
				void *client_data,
				void *context)
{
	struct mlx5e_priv *priv;

	priv = (struct mlx5e_priv *)context;

	/*Skip if event is deactivated*/
	if (!priv->fs.sniffer.bypass_event)
		return 0;

	/*Skip if this rules appeared before */
	if (client_data)
		return 0;

	/*Flag the rule by setting  a non-NULL address*/
	if (mlx5_set_rule_private_data(
		rule,
		priv->fs.sniffer.bypass_event,
		(void *)1))
		return 0;

	/*Check if this is new FTE*/
	if (!ctx_changed)
		return 0;

	mlx5e_sniffer_send_workqueue(priv, rule, SNIFFER_ADD, SNIFFER_RULE);
	return 0;
}

static int mlx5e_sniffer_free_resources(struct mlx5e_priv *priv)
{
	int i;

	if (priv->fs.sniffer.bypass_event)
		mlx5_unregister_rule_notifier(priv->fs.sniffer.bypass_event);
	priv->fs.sniffer.bypass_event = NULL;

	if (priv->fs.sniffer.sniffer_wq)
		destroy_workqueue(priv->fs.sniffer.sniffer_wq);
	priv->fs.sniffer.sniffer_wq = NULL;

	/*Delete rules*/
	for (i = 0; i < MAX_SNIFFER_FLOW_RULE_NUM; i++) {
		if (!priv->fs.sniffer.flow_arr[i].valid)
			continue;

		if (priv->fs.sniffer.flow_arr[i].rx_dst)
			mlx5_del_flow_rule(
				priv->fs.sniffer.flow_arr[i].rx_dst);
	}

	if (priv->fs.sniffer.tx_dst)
		mlx5_del_flow_rule(
			priv->fs.sniffer.tx_dst);

	for (i = 0; i < LEFTOVERS_RULE_NUM; i++) {
		if (!priv->fs.sniffer.leftovers_flow_arr[i].valid)
			continue;

		if (priv->fs.sniffer.leftovers_flow_arr[i].rx_dst)
			mlx5_del_flow_rule(
				priv->fs.sniffer.leftovers_flow_arr[i].rx_dst);
	}

	/*Delete tables*/
	if (priv->fs.sniffer.rx_ft)
		mlx5_destroy_flow_table(priv->fs.sniffer.rx_ft);

	if (priv->fs.sniffer.tx_ft)
		mlx5_destroy_flow_table(priv->fs.sniffer.tx_ft);

	if (priv->fs.sniffer.leftovers_ft)
		mlx5_destroy_flow_table(priv->fs.sniffer.leftovers_ft);

	/*Clean up*/
	memset(
		priv->fs.sniffer.flow_arr,
		0,
		sizeof(priv->fs.sniffer.flow_arr));

	memset(
		priv->fs.sniffer.leftovers_flow_arr,
		0,
		sizeof(priv->fs.sniffer.leftovers_flow_arr));

	priv->fs.sniffer.rx_ft = NULL;
	priv->fs.sniffer.tx_ft = NULL;
	priv->fs.sniffer.leftovers_ft = NULL;

	return 0;
}

/*Work around for leftover ruless
Hard code two rules from create_leftovers_rule in infiniband/hw/mlx5/main.c*/
static int mlx5e_sniffer_build_leftovers_rule(struct mlx5e_priv *priv)
{
	struct sniffer_work *work;
	struct mlx5_flow_rule_node *rule_node;
	int err = 0;

	void *outer_headers_c;
	void *outer_headers_v;
	static const char mcast_mac[ETH_ALEN] = {0x1};
	static const char empty_mac[ETH_ALEN] = {};

	rule_node = kzalloc(sizeof(*rule_node), GFP_KERNEL);
	if (!rule_node)
		return -ENOMEM;
	memset(rule_node->match_criteria, 0, sizeof(*rule_node->match_criteria));
	memset(rule_node->match_value, 0, sizeof(*rule_node->match_value));

	outer_headers_c = MLX5_ADDR_OF(fte_match_param, rule_node->match_criteria, outer_headers);
	outer_headers_v = MLX5_ADDR_OF(fte_match_param, rule_node->match_value, outer_headers);

	/*Build mcast rule*/
	memcpy(
		MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c, dmac_47_16),
		mcast_mac,
		ETH_ALEN);
	memcpy(
		MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_v, dmac_47_16),
		mcast_mac,
		ETH_ALEN);
	rule_node->match_criteria_enable =
		(!outer_header_zero(rule_node->match_criteria)) << 0;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work) {
		err = -ENOENT;
		goto error;
	}
	INIT_WORK(&work->work, sniffer_add_rule_handler);
	work->priv = priv;
	if (mlx5e_sniffer_save_rule_info(
		&work->rule_info, NULL,
		rule_node, LEFTOVERS_RULE)) {
		err = -ENOENT;
		goto error;
	}
	queue_work(priv->fs.sniffer.sniffer_wq, &work->work);

	/*Build ucast rule*/
	memcpy(MLX5_ADDR_OF(
		fte_match_set_lyr_2_4, outer_headers_v, dmac_47_16),
		empty_mac,
		ETH_ALEN);
	rule_node->match_criteria_enable =
		(!outer_header_zero(rule_node->match_criteria)) << 0;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work) {
		err = -ENOENT;
		goto error;
	}
	INIT_WORK(&work->work, sniffer_add_rule_handler);
	work->priv = priv;
	if (mlx5e_sniffer_save_rule_info(
		&work->rule_info, NULL,
		rule_node, LEFTOVERS_RULE)) {
		err = -ENOENT;
		goto error;
	}
	queue_work(priv->fs.sniffer.sniffer_wq, &work->work);
	goto cleanup;

error:
	kfree(work);

cleanup:
	kfree(rule_node);
	return err;
}

/*RoCE related functions*/
static int mlx5e_sniffer_collect_roce_rule(struct mlx5e_priv *priv, int action)
{
	struct sniffer_work *work;
	struct mlx5_flow_rules_list *rules;
	struct mlx5_flow_rule_node *rule_node;
	u8  roce_version_cap;
	int err;

	roce_version_cap = MLX5_CAP_ROCE(priv->mdev, roce_version);

	rules = get_roce_flow_rules(roce_version_cap);
	if (!rules)
		return -ENOENT;

	list_for_each_entry(rule_node, &rules->head, list) {
		/*Send workqueue*/
		work = kzalloc(sizeof(*work), GFP_KERNEL);
		if (!work) {
			err = -ENOMEM;
			goto error;
		}

		if (action == SNIFFER_ADD)
			INIT_WORK(&work->work, sniffer_add_rule_handler);
		else
			INIT_WORK(&work->work, sniffer_del_rule_handler);

		work->priv = priv;
		err = mlx5e_sniffer_save_rule_info(
			&work->rule_info, NULL,
			rule_node, SNIFFER_RULE);
		if (err) {
				kfree(work);
				goto error;
		}
		queue_work(priv->fs.sniffer.sniffer_wq, &work->work);
	}

	err = 0;

error:
	mlx5_del_flow_rules_list(rules);
	return err;
}

static int mlx5e_sniffer_add_dev_info(struct mlx5e_priv *priv)
{
	struct mlx5e_info *dev_info;
	int err = 0;

	mutex_lock(&mlx5e_dev_list_mutex);

	dev_info = kzalloc(sizeof(*dev_info), GFP_KERNEL);
	if (!dev_info) {
		err = -ENOMEM;
		goto out;
	}
	dev_info->priv = priv;
	list_add(&dev_info->list, &mlx5e_dev_list);

out:
	mutex_unlock(&mlx5e_dev_list_mutex);
	return err;
}

static int mlx5e_sniffer_del_dev_info(struct mlx5e_priv *priv)
{
	struct mlx5e_info *dev_info;

	mutex_lock(&mlx5e_dev_list_mutex);

	list_for_each_entry(dev_info, &mlx5e_dev_list, list) {
		if (!memcmp(dev_info->priv, priv, sizeof(*priv))) {
			list_del(&dev_info->list);
			kfree(dev_info);
			break;
		}
	}

	mutex_unlock(&mlx5e_dev_list_mutex);
	return 0;
}

static struct mlx5e_priv *
mlx5e_sniffer_find_dev_info_entry(struct mlx5_core_dev *mdev)
{
	struct mlx5e_info *dev_info;

	list_for_each_entry(dev_info, &mlx5e_dev_list, list) {
		if (dev_info->priv->mdev == mdev)
			return dev_info->priv;
	}

	return NULL;
}

/*Public functions*/
void mlx5e_sniffer_initialize_private_data(void)
{
	INIT_LIST_HEAD(&mlx5e_dev_list);
	mutex_init(&mlx5e_dev_list_mutex);
}

void mlx5e_sniffer_roce_mode_notify(
	struct mlx5_core_dev *mdev,
	int action)
{
	struct mlx5e_priv *priv;

	mutex_lock(&mlx5e_dev_list_mutex);

	priv = mlx5e_sniffer_find_dev_info_entry(mdev);
	if (!priv)
		goto out;

	switch (action) {
	case ROCE_ON:
		mlx5e_sniffer_collect_roce_rule(priv, SNIFFER_ADD);
		break;

	case ROCE_OFF:
		mlx5e_sniffer_collect_roce_rule(priv, SNIFFER_DEL);
		break;
	default:
		break;
	}

out:
	mutex_unlock(&mlx5e_dev_list_mutex);
}
EXPORT_SYMBOL(mlx5e_sniffer_roce_mode_notify);

int mlx5e_sniffer_open_tir(struct mlx5e_priv *priv, int tt)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 *in;
	void *tirc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = mlx5_vzalloc(inlen);

	if (!in)
		return -ENOMEM;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	mlx5e_sniffer_build_tir_ctx(priv, tirc, tt);
	err = mlx5_core_create_tir(mdev, in, inlen, &priv->sniffer_tirn[tt]);

	kfree(in);
	return err;
}

int mlx5e_sniffer_turn_off(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	mlx5e_sniffer_free_resources(priv);
	mlx5e_sniffer_del_dev_info(priv);

	return 0;
}

int mlx5e_sniffer_turn_on(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_flow_namespace *p_bypass_ns;
	struct mlx5_flow_namespace *p_sniffer_rx_ns;
	struct mlx5_flow_namespace *p_sniffer_tx_ns;
	struct mlx5_flow_namespace *p_leftovers_ns;
	char wq_name[12];
	u8 enable;

	int err = 0;

	/*For leftovers*/
	unsigned int priority;
	char name[FT_NAME_STR_SZ];
	int n_ent, n_grp;

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		netdev_err(dev, "Device is already closed\n");
		return -EPERM;
	}

	/*1. Setup workqueue*/
	sprintf(
		wq_name, "sniffer%02x%02x",
		(u8)mdev->pdev->bus->number,
		(u8)mdev->pdev->devfn);
	priv->fs.sniffer.sniffer_wq = create_singlethread_workqueue(wq_name);
	if (!priv->fs.sniffer.sniffer_wq)
		return -ENOMEM;

	/*2. Get all name space*/
	p_sniffer_rx_ns =
		mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_SNIFFER_RX);
	if (!p_sniffer_rx_ns)
		return -ENOENT;

	p_sniffer_tx_ns =
		mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_SNIFFER_TX);
	if (!p_sniffer_tx_ns)
		return -ENOENT;

	/*Don't fail if bypass ns does not exist*/
	p_bypass_ns =
		mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_BYPASS);

	p_leftovers_ns =
		mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_LEFTOVERS);
	if (!p_leftovers_ns)
		return -ENOENT;

	/*3. Build flow table*/
	priv->fs.sniffer.rx_ft = mlx5_create_auto_grouped_flow_table(
					p_sniffer_rx_ns,
					0,
					"sniff_rx_ft",
				       MAX_SNIFFER_FLOW_RULE_NUM * MAX_SNIFF_FTES_PER_FG + 1,
				       MAX_SNIFFER_FLOW_RULE_NUM,
				       0, MLX5_FS_AUTOGROUP_SAVE_SPARE_SPACE);
	if (IS_ERR(priv->fs.sniffer.rx_ft)) {
		priv->fs.sniffer.rx_ft = NULL;
		err = PTR_ERR(priv->fs.sniffer.rx_ft);
		goto error;
	}

	priv->fs.sniffer.tx_ft = mlx5_create_auto_grouped_flow_table(
					p_sniffer_tx_ns,
					0,
					"sniff_tx_ft",
					1,
					1,
					0, 0);
	if (IS_ERR(priv->fs.sniffer.tx_ft)) {
		priv->fs.sniffer.tx_ft = NULL;
		err = PTR_ERR(priv->fs.sniffer.tx_ft);
		goto error;
	}

	build_leftovers_ft_param(name, &priority, &n_ent, &n_grp);
	priv->fs.sniffer.leftovers_ft = mlx5_create_auto_grouped_flow_table(
					p_leftovers_ns,
					priority,
					name,
					n_ent,
					n_grp, 0,
					MLX5_FS_AUTOGROUP_SAVE_SPARE_SPACE);
	if (IS_ERR(priv->fs.sniffer.leftovers_ft)) {
		priv->fs.sniffer.leftovers_ft = NULL;
		err = PTR_ERR(priv->fs.sniffer.leftovers_ft);
		goto error;
	}

	/*4. Build leftovers rules*/
	err = mlx5e_sniffer_build_leftovers_rule(priv);
	if (err)
		goto error;

	/*4a Build tx sniffer rule*/
	err = mlx5e_sniffer_create_tx_rule(priv);
	if (err)
		goto error;

	/*Event can happen after this line*/

	/*5. Register call backs for bypass name space */
	if (p_bypass_ns) {
		priv->fs.sniffer.bypass_event =
			mlx5_register_rule_notifier(
				mdev,
				MLX5_FLOW_NAMESPACE_BYPASS,
				&mlx5e_sniffer_add_bypass_rule_callback_fn,
				&mlx5e_sniffer_del_bypass_rule_callback_fn,
				priv);
		if (IS_ERR_OR_NULL(priv->fs.sniffer.bypass_event)) {
			err = PTR_ERR(priv->fs.sniffer.bypass_event);
			priv->fs.sniffer.bypass_event = NULL;
			goto error;
		}
	}

	/*6. Collect and build bypass rules*/
	if (p_bypass_ns)
		mlx5_flow_iterate_existing_rules(
			p_bypass_ns,
			&mlx5e_sniffer_add_bypass_rule_callback_fn,
			priv);

	/*7. Collect and build roce rules*/
	/*Add device to linked list for roce add/remove call back*/
	err = mlx5e_sniffer_add_dev_info(priv);
	if (err)
		goto error;

	err = mlx5_query_nic_vport_roce_en(mdev, &enable);
	if (err)
		goto error1;

	if (enable) {
		err = mlx5e_sniffer_collect_roce_rule(priv, SNIFFER_ADD);
		if (err)
			goto error1;
	}

	return err;

error1:
	mlx5e_sniffer_del_dev_info(priv);

error:
	mlx5e_sniffer_free_resources(priv);
	return err;
}
