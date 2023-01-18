// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/scext4/sysfs.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Theodore Ts'o (tytso@mit.edu)
 *
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>

#include "scext4.h"
#include "scext4_jbd3.h"

typedef enum {
	attr_noop,
	attr_delayed_allocation_blocks,
	attr_session_write_kbytes,
	attr_lifetime_write_kbytes,
	attr_reserved_clusters,
	attr_sra_exceeded_retry_limit,
	attr_inode_readahead,
	attr_trigger_test_error,
	attr_first_error_time,
	attr_last_error_time,
	attr_feature,
	attr_pointer_ui,
	attr_pointer_atomic,
	attr_journal_task,
} attr_id_t;

typedef enum {
	ptr_explicit,
	ptr_scext4_sb_info_offset,
	ptr_scext4_super_block_offset,
} attr_ptr_t;

static const char proc_dirname[] = "fs/scext4";
static struct proc_dir_entry *scext4_proc_root;

struct scext4_attr {
	struct attribute attr;
	short attr_id;
	short attr_ptr;
	union {
		int offset;
		void *explicit_ptr;
	} u;
};

static ssize_t session_write_kbytes_show(struct scext4_sb_info *sbi, char *buf)
{
	struct super_block *sb = sbi->s_buddy_cache->i_sb;

	if (!sb->s_bdev->bd_part)
		return snprintf(buf, PAGE_SIZE, "0\n");
	return snprintf(buf, PAGE_SIZE, "%lu\n",
			(part_stat_read(sb->s_bdev->bd_part,
					sectors[STAT_WRITE]) -
			 sbi->s_sectors_written_start) >> 1);
}

static ssize_t lifetime_write_kbytes_show(struct scext4_sb_info *sbi, char *buf)
{
	struct super_block *sb = sbi->s_buddy_cache->i_sb;

	if (!sb->s_bdev->bd_part)
		return snprintf(buf, PAGE_SIZE, "0\n");
	return snprintf(buf, PAGE_SIZE, "%llu\n",
			(unsigned long long)(sbi->s_kbytes_written +
			((part_stat_read(sb->s_bdev->bd_part,
					 sectors[STAT_WRITE]) -
			  SCEXT4_SB(sb)->s_sectors_written_start) >> 1)));
}

static ssize_t inode_readahead_blks_store(struct scext4_sb_info *sbi,
					  const char *buf, size_t count)
{
	unsigned long t;
	int ret;

	ret = kstrtoul(skip_spaces(buf), 0, &t);
	if (ret)
		return ret;

	if (t && (!is_power_of_2(t) || t > 0x40000000))
		return -EINVAL;

	sbi->s_inode_readahead_blks = t;
	return count;
}

static ssize_t reserved_clusters_store(struct scext4_sb_info *sbi,
				   const char *buf, size_t count)
{
	unsigned long long val;
	scext4_fsblk_t clusters = (scext4_blocks_count(sbi->s_es) >>
				 sbi->s_cluster_bits);
	int ret;

	ret = kstrtoull(skip_spaces(buf), 0, &val);
	if (ret || val >= clusters)
		return -EINVAL;

	atomic64_set(&sbi->s_resv_clusters, val);
	return count;
}

static ssize_t trigger_test_error(struct scext4_sb_info *sbi,
				  const char *buf, size_t count)
{
	int len = count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (len && buf[len-1] == '\n')
		len--;

	if (len)
		scext4_error(sbi->s_sb, "%.*s", len, buf);
	return count;
}

static ssize_t journal_task_show(struct scext4_sb_info *sbi, char *buf)
{
	if (!sbi->s_journal)
		return snprintf(buf, PAGE_SIZE, "<none>\n");
	return snprintf(buf, PAGE_SIZE, "%d\n",
			task_pid_vnr(sbi->s_journal->j_task));
}

#define SCEXT4_ATTR(_name,_mode,_id)					\
static struct scext4_attr scext4_attr_##_name = {				\
	.attr = {.name = __stringify(_name), .mode = _mode },		\
	.attr_id = attr_##_id,						\
}

#define SCEXT4_ATTR_FUNC(_name,_mode)  SCEXT4_ATTR(_name,_mode,_name)

#define SCEXT4_ATTR_FEATURE(_name)   SCEXT4_ATTR(_name, 0444, feature)

#define SCEXT4_ATTR_OFFSET(_name,_mode,_id,_struct,_elname)	\
static struct scext4_attr scext4_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.attr_id = attr_##_id,					\
	.attr_ptr = ptr_##_struct##_offset,			\
	.u = {							\
		.offset = offsetof(struct _struct, _elname),\
	},							\
}

#define SCEXT4_RO_ATTR_ES_UI(_name,_elname)				\
	SCEXT4_ATTR_OFFSET(_name, 0444, pointer_ui, scext4_super_block, _elname)

#define SCEXT4_RW_ATTR_SBI_UI(_name,_elname)	\
	SCEXT4_ATTR_OFFSET(_name, 0644, pointer_ui, scext4_sb_info, _elname)

#define SCEXT4_ATTR_PTR(_name,_mode,_id,_ptr) \
static struct scext4_attr scext4_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.attr_id = attr_##_id,					\
	.attr_ptr = ptr_explicit,				\
	.u = {							\
		.explicit_ptr = _ptr,				\
	},							\
}

#define ATTR_LIST(name) &scext4_attr_##name.attr

SCEXT4_ATTR_FUNC(delayed_allocation_blocks, 0444);
SCEXT4_ATTR_FUNC(session_write_kbytes, 0444);
SCEXT4_ATTR_FUNC(lifetime_write_kbytes, 0444);
SCEXT4_ATTR_FUNC(reserved_clusters, 0644);
SCEXT4_ATTR_FUNC(sra_exceeded_retry_limit, 0444);

SCEXT4_ATTR_OFFSET(inode_readahead_blks, 0644, inode_readahead,
		 scext4_sb_info, s_inode_readahead_blks);
SCEXT4_RW_ATTR_SBI_UI(inode_goal, s_inode_goal);
SCEXT4_RW_ATTR_SBI_UI(mb_stats, s_mb_stats);
SCEXT4_RW_ATTR_SBI_UI(mb_max_to_scan, s_mb_max_to_scan);
SCEXT4_RW_ATTR_SBI_UI(mb_min_to_scan, s_mb_min_to_scan);
SCEXT4_RW_ATTR_SBI_UI(mb_order2_req, s_mb_order2_reqs);
SCEXT4_RW_ATTR_SBI_UI(mb_stream_req, s_mb_stream_request);
SCEXT4_RW_ATTR_SBI_UI(mb_group_prealloc, s_mb_group_prealloc);
SCEXT4_RW_ATTR_SBI_UI(extent_max_zeroout_kb, s_extent_max_zeroout_kb);
SCEXT4_ATTR(trigger_fs_error, 0200, trigger_test_error);
SCEXT4_RW_ATTR_SBI_UI(err_ratelimit_interval_ms, s_err_ratelimit_state.interval);
SCEXT4_RW_ATTR_SBI_UI(err_ratelimit_burst, s_err_ratelimit_state.burst);
SCEXT4_RW_ATTR_SBI_UI(warning_ratelimit_interval_ms, s_warning_ratelimit_state.interval);
SCEXT4_RW_ATTR_SBI_UI(warning_ratelimit_burst, s_warning_ratelimit_state.burst);
SCEXT4_RW_ATTR_SBI_UI(msg_ratelimit_interval_ms, s_msg_ratelimit_state.interval);
SCEXT4_RW_ATTR_SBI_UI(msg_ratelimit_burst, s_msg_ratelimit_state.burst);
SCEXT4_RO_ATTR_ES_UI(errors_count, s_error_count);
SCEXT4_ATTR(first_error_time, 0444, first_error_time);
SCEXT4_ATTR(last_error_time, 0444, last_error_time);
SCEXT4_ATTR(journal_task, 0444, journal_task);

static unsigned int old_bump_val = 128;
SCEXT4_ATTR_PTR(max_writeback_mb_bump, 0444, pointer_ui, &old_bump_val);

static struct attribute *scext4_attrs[] = {
	ATTR_LIST(delayed_allocation_blocks),
	ATTR_LIST(session_write_kbytes),
	ATTR_LIST(lifetime_write_kbytes),
	ATTR_LIST(reserved_clusters),
	ATTR_LIST(sra_exceeded_retry_limit),
	ATTR_LIST(inode_readahead_blks),
	ATTR_LIST(inode_goal),
	ATTR_LIST(mb_stats),
	ATTR_LIST(mb_max_to_scan),
	ATTR_LIST(mb_min_to_scan),
	ATTR_LIST(mb_order2_req),
	ATTR_LIST(mb_stream_req),
	ATTR_LIST(mb_group_prealloc),
	ATTR_LIST(max_writeback_mb_bump),
	ATTR_LIST(extent_max_zeroout_kb),
	ATTR_LIST(trigger_fs_error),
	ATTR_LIST(err_ratelimit_interval_ms),
	ATTR_LIST(err_ratelimit_burst),
	ATTR_LIST(warning_ratelimit_interval_ms),
	ATTR_LIST(warning_ratelimit_burst),
	ATTR_LIST(msg_ratelimit_interval_ms),
	ATTR_LIST(msg_ratelimit_burst),
	ATTR_LIST(errors_count),
	ATTR_LIST(first_error_time),
	ATTR_LIST(last_error_time),
	ATTR_LIST(journal_task),
	NULL,
};
ATTRIBUTE_GROUPS(scext4);

/* Features this copy of scext4 supports */
SCEXT4_ATTR_FEATURE(lazy_itable_init);
SCEXT4_ATTR_FEATURE(batched_discard);
SCEXT4_ATTR_FEATURE(meta_bg_resize);
#ifdef CONFIG_FS_ENCRYPTION
SCEXT4_ATTR_FEATURE(encryption);
#endif
#ifdef CONFIG_UNICODE
SCEXT4_ATTR_FEATURE(casefold);
#endif
#ifdef CONFIG_FS_VERITY
SCEXT4_ATTR_FEATURE(verity);
#endif
SCEXT4_ATTR_FEATURE(metadata_csum_seed);

static struct attribute *scext4_feat_attrs[] = {
	ATTR_LIST(lazy_itable_init),
	ATTR_LIST(batched_discard),
	ATTR_LIST(meta_bg_resize),
#ifdef CONFIG_FS_ENCRYPTION
	ATTR_LIST(encryption),
#endif
#ifdef CONFIG_UNICODE
	ATTR_LIST(casefold),
#endif
#ifdef CONFIG_FS_VERITY
	ATTR_LIST(verity),
#endif
	ATTR_LIST(metadata_csum_seed),
	NULL,
};
ATTRIBUTE_GROUPS(scext4_feat);

static void *calc_ptr(struct scext4_attr *a, struct scext4_sb_info *sbi)
{
	switch (a->attr_ptr) {
	case ptr_explicit:
		return a->u.explicit_ptr;
	case ptr_scext4_sb_info_offset:
		return (void *) (((char *) sbi) + a->u.offset);
	case ptr_scext4_super_block_offset:
		return (void *) (((char *) sbi->s_es) + a->u.offset);
	}
	return NULL;
}

static ssize_t __print_tstamp(char *buf, __le32 lo, __u8 hi)
{
	return snprintf(buf, PAGE_SIZE, "%lld",
			((time64_t)hi << 32) + le32_to_cpu(lo));
}

#define print_tstamp(buf, es, tstamp) \
	__print_tstamp(buf, (es)->tstamp, (es)->tstamp ## _hi)

static ssize_t scext4_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct scext4_sb_info *sbi = container_of(kobj, struct scext4_sb_info,
						s_kobj);
	struct scext4_attr *a = container_of(attr, struct scext4_attr, attr);
	void *ptr = calc_ptr(a, sbi);

	switch (a->attr_id) {
	case attr_delayed_allocation_blocks:
		return snprintf(buf, PAGE_SIZE, "%llu\n",
				(s64) SCEXT4_C2B(sbi,
		       percpu_counter_sum(&sbi->s_dirtyclusters_counter)));
	case attr_session_write_kbytes:
		return session_write_kbytes_show(sbi, buf);
	case attr_lifetime_write_kbytes:
		return lifetime_write_kbytes_show(sbi, buf);
	case attr_reserved_clusters:
		return snprintf(buf, PAGE_SIZE, "%llu\n",
				(unsigned long long)
				atomic64_read(&sbi->s_resv_clusters));
	case attr_sra_exceeded_retry_limit:
		return snprintf(buf, PAGE_SIZE, "%llu\n",
				(unsigned long long)
			percpu_counter_sum(&sbi->s_sra_exceeded_retry_limit));
	case attr_inode_readahead:
	case attr_pointer_ui:
		if (!ptr)
			return 0;
		if (a->attr_ptr == ptr_scext4_super_block_offset)
			return snprintf(buf, PAGE_SIZE, "%u\n",
					le32_to_cpup(ptr));
		else
			return snprintf(buf, PAGE_SIZE, "%u\n",
					*((unsigned int *) ptr));
	case attr_pointer_atomic:
		if (!ptr)
			return 0;
		return snprintf(buf, PAGE_SIZE, "%d\n",
				atomic_read((atomic_t *) ptr));
	case attr_feature:
		return snprintf(buf, PAGE_SIZE, "supported\n");
	case attr_first_error_time:
		return print_tstamp(buf, sbi->s_es, s_first_error_time);
	case attr_last_error_time:
		return print_tstamp(buf, sbi->s_es, s_last_error_time);
	case attr_journal_task:
		return journal_task_show(sbi, buf);
	}

	return 0;
}

static ssize_t scext4_attr_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t len)
{
	struct scext4_sb_info *sbi = container_of(kobj, struct scext4_sb_info,
						s_kobj);
	struct scext4_attr *a = container_of(attr, struct scext4_attr, attr);
	void *ptr = calc_ptr(a, sbi);
	unsigned long t;
	int ret;

	switch (a->attr_id) {
	case attr_reserved_clusters:
		return reserved_clusters_store(sbi, buf, len);
	case attr_pointer_ui:
		if (!ptr)
			return 0;
		ret = kstrtoul(skip_spaces(buf), 0, &t);
		if (ret)
			return ret;
		if (a->attr_ptr == ptr_scext4_super_block_offset)
			*((__le32 *) ptr) = cpu_to_le32(t);
		else
			*((unsigned int *) ptr) = t;
		return len;
	case attr_inode_readahead:
		return inode_readahead_blks_store(sbi, buf, len);
	case attr_trigger_test_error:
		return trigger_test_error(sbi, buf, len);
	}
	return 0;
}

static void scext4_sb_release(struct kobject *kobj)
{
	struct scext4_sb_info *sbi = container_of(kobj, struct scext4_sb_info,
						s_kobj);
	complete(&sbi->s_kobj_unregister);
}

static const struct sysfs_ops scext4_attr_ops = {
	.show	= scext4_attr_show,
	.store	= scext4_attr_store,
};

static struct kobj_type scext4_sb_ktype = {
	.default_groups = scext4_groups,
	.sysfs_ops	= &scext4_attr_ops,
	.release	= scext4_sb_release,
};

static struct kobj_type scext4_feat_ktype = {
	.default_groups = scext4_feat_groups,
	.sysfs_ops	= &scext4_attr_ops,
	.release	= (void (*)(struct kobject *))kfree,
};

static struct kobject *scext4_root;

static struct kobject *scext4_feat;

int scext4_register_sysfs(struct super_block *sb)
{
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	int err;

	init_completion(&sbi->s_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_kobj, &scext4_sb_ktype, scext4_root,
				   "%s", sb->s_id);
	if (err) {
		kobject_put(&sbi->s_kobj);
		wait_for_completion(&sbi->s_kobj_unregister);
		return err;
	}

	if (scext4_proc_root)
		sbi->s_proc = proc_mkdir(sb->s_id, scext4_proc_root);
	if (sbi->s_proc) {
		proc_create_single_data("options", S_IRUGO, sbi->s_proc,
				scext4_seq_options_show, sb);
		proc_create_single_data("es_shrinker_info", S_IRUGO,
				sbi->s_proc, scext4_seq_es_shrinker_info_show,
				sb);
		proc_create_seq_data("mb_groups", S_IRUGO, sbi->s_proc,
				&scext4_mb_seq_groups_ops, sb);
	}
	return 0;
}

void scext4_unregister_sysfs(struct super_block *sb)
{
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);

	if (sbi->s_proc)
		remove_proc_subtree(sb->s_id, scext4_proc_root);
	kobject_del(&sbi->s_kobj);
}

int __init scext4_init_sysfs(void)
{
	int ret;

	scext4_root = kobject_create_and_add("scext4", fs_kobj);
	if (!scext4_root)
		return -ENOMEM;

	scext4_feat = kzalloc(sizeof(*scext4_feat), GFP_KERNEL);
	if (!scext4_feat) {
		ret = -ENOMEM;
		goto root_err;
	}

	ret = kobject_init_and_add(scext4_feat, &scext4_feat_ktype,
				   scext4_root, "features");
	if (ret)
		goto feat_err;

	scext4_proc_root = proc_mkdir(proc_dirname, NULL);
	return ret;

feat_err:
	kobject_put(scext4_feat);
	scext4_feat = NULL;
root_err:
	kobject_put(scext4_root);
	scext4_root = NULL;
	return ret;
}

void scext4_exit_sysfs(void)
{
	kobject_put(scext4_feat);
	scext4_feat = NULL;
	kobject_put(scext4_root);
	scext4_root = NULL;
	remove_proc_entry(proc_dirname, NULL);
	scext4_proc_root = NULL;
}

