// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014 Red Hat, Inc.
 * All Rights Reserved.
 */

#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_sysfs.h"
#include "scxfs_log_priv.h"
#include "scxfs_mount.h"

struct scxfs_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobject, char *buf);
	ssize_t (*store)(struct kobject *kobject, const char *buf,
			 size_t count);
};

static inline struct scxfs_sysfs_attr *
to_attr(struct attribute *attr)
{
	return container_of(attr, struct scxfs_sysfs_attr, attr);
}

#define SCXFS_SYSFS_ATTR_RW(name) \
	static struct scxfs_sysfs_attr scxfs_sysfs_attr_##name = __ATTR_RW(name)
#define SCXFS_SYSFS_ATTR_RO(name) \
	static struct scxfs_sysfs_attr scxfs_sysfs_attr_##name = __ATTR_RO(name)
#define SCXFS_SYSFS_ATTR_WO(name) \
	static struct scxfs_sysfs_attr scxfs_sysfs_attr_##name = __ATTR_WO(name)

#define ATTR_LIST(name) &scxfs_sysfs_attr_##name.attr

STATIC ssize_t
scxfs_sysfs_object_show(
	struct kobject		*kobject,
	struct attribute	*attr,
	char			*buf)
{
	struct scxfs_sysfs_attr *scxfs_attr = to_attr(attr);

	return scxfs_attr->show ? scxfs_attr->show(kobject, buf) : 0;
}

STATIC ssize_t
scxfs_sysfs_object_store(
	struct kobject		*kobject,
	struct attribute	*attr,
	const char		*buf,
	size_t			count)
{
	struct scxfs_sysfs_attr *scxfs_attr = to_attr(attr);

	return scxfs_attr->store ? scxfs_attr->store(kobject, buf, count) : 0;
}

static const struct sysfs_ops scxfs_sysfs_ops = {
	.show = scxfs_sysfs_object_show,
	.store = scxfs_sysfs_object_store,
};

static struct attribute *scxfs_mp_attrs[] = {
	NULL,
};

struct kobj_type scxfs_mp_ktype = {
	.release = scxfs_sysfs_release,
	.sysfs_ops = &scxfs_sysfs_ops,
	.default_attrs = scxfs_mp_attrs,
};

#ifdef DEBUG
/* debug */

STATIC ssize_t
bug_on_assert_store(
	struct kobject		*kobject,
	const char		*buf,
	size_t			count)
{
	int			ret;
	int			val;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val == 1)
		scxfs_globals.bug_on_assert = true;
	else if (val == 0)
		scxfs_globals.bug_on_assert = false;
	else
		return -EINVAL;

	return count;
}

STATIC ssize_t
bug_on_assert_show(
	struct kobject		*kobject,
	char			*buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", scxfs_globals.bug_on_assert ? 1 : 0);
}
SCXFS_SYSFS_ATTR_RW(bug_on_assert);

STATIC ssize_t
log_recovery_delay_store(
	struct kobject	*kobject,
	const char	*buf,
	size_t		count)
{
	int		ret;
	int		val;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val < 0 || val > 60)
		return -EINVAL;

	scxfs_globals.log_recovery_delay = val;

	return count;
}

STATIC ssize_t
log_recovery_delay_show(
	struct kobject	*kobject,
	char		*buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", scxfs_globals.log_recovery_delay);
}
SCXFS_SYSFS_ATTR_RW(log_recovery_delay);

STATIC ssize_t
mount_delay_store(
	struct kobject	*kobject,
	const char	*buf,
	size_t		count)
{
	int		ret;
	int		val;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val < 0 || val > 60)
		return -EINVAL;

	scxfs_globals.mount_delay = val;

	return count;
}

STATIC ssize_t
mount_delay_show(
	struct kobject	*kobject,
	char		*buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", scxfs_globals.mount_delay);
}
SCXFS_SYSFS_ATTR_RW(mount_delay);

static ssize_t
always_cow_store(
	struct kobject	*kobject,
	const char	*buf,
	size_t		count)
{
	ssize_t		ret;

	ret = kstrtobool(buf, &scxfs_globals.always_cow);
	if (ret < 0)
		return ret;
	return count;
}

static ssize_t
always_cow_show(
	struct kobject	*kobject,
	char		*buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", scxfs_globals.always_cow);
}
SCXFS_SYSFS_ATTR_RW(always_cow);

#ifdef DEBUG
/*
 * Override how many threads the parallel work queue is allowed to create.
 * This has to be a debug-only global (instead of an errortag) because one of
 * the main users of parallel workqueues is mount time quotacheck.
 */
STATIC ssize_t
pwork_threads_store(
	struct kobject	*kobject,
	const char	*buf,
	size_t		count)
{
	int		ret;
	int		val;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val < -1 || val > num_possible_cpus())
		return -EINVAL;

	scxfs_globals.pwork_threads = val;

	return count;
}

STATIC ssize_t
pwork_threads_show(
	struct kobject	*kobject,
	char		*buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", scxfs_globals.pwork_threads);
}
SCXFS_SYSFS_ATTR_RW(pwork_threads);
#endif /* DEBUG */

static struct attribute *scxfs_dbg_attrs[] = {
	ATTR_LIST(bug_on_assert),
	ATTR_LIST(log_recovery_delay),
	ATTR_LIST(mount_delay),
	ATTR_LIST(always_cow),
#ifdef DEBUG
	ATTR_LIST(pwork_threads),
#endif
	NULL,
};

struct kobj_type scxfs_dbg_ktype = {
	.release = scxfs_sysfs_release,
	.sysfs_ops = &scxfs_sysfs_ops,
	.default_attrs = scxfs_dbg_attrs,
};

#endif /* DEBUG */

/* stats */

static inline struct xstats *
to_xstats(struct kobject *kobject)
{
	struct scxfs_kobj *kobj = to_kobj(kobject);

	return container_of(kobj, struct xstats, xs_kobj);
}

STATIC ssize_t
stats_show(
	struct kobject	*kobject,
	char		*buf)
{
	struct xstats	*stats = to_xstats(kobject);

	return scxfs_stats_format(stats->xs_stats, buf);
}
SCXFS_SYSFS_ATTR_RO(stats);

STATIC ssize_t
stats_clear_store(
	struct kobject	*kobject,
	const char	*buf,
	size_t		count)
{
	int		ret;
	int		val;
	struct xstats	*stats = to_xstats(kobject);

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val != 1)
		return -EINVAL;

	scxfs_stats_clearall(stats->xs_stats);
	return count;
}
SCXFS_SYSFS_ATTR_WO(stats_clear);

static struct attribute *scxfs_stats_attrs[] = {
	ATTR_LIST(stats),
	ATTR_LIST(stats_clear),
	NULL,
};

struct kobj_type scxfs_stats_ktype = {
	.release = scxfs_sysfs_release,
	.sysfs_ops = &scxfs_sysfs_ops,
	.default_attrs = scxfs_stats_attrs,
};

/* xlog */

static inline struct xlog *
to_xlog(struct kobject *kobject)
{
	struct scxfs_kobj *kobj = to_kobj(kobject);

	return container_of(kobj, struct xlog, l_kobj);
}

STATIC ssize_t
log_head_lsn_show(
	struct kobject	*kobject,
	char		*buf)
{
	int cycle;
	int block;
	struct xlog *log = to_xlog(kobject);

	spin_lock(&log->l_icloglock);
	cycle = log->l_curr_cycle;
	block = log->l_curr_block;
	spin_unlock(&log->l_icloglock);

	return snprintf(buf, PAGE_SIZE, "%d:%d\n", cycle, block);
}
SCXFS_SYSFS_ATTR_RO(log_head_lsn);

STATIC ssize_t
log_tail_lsn_show(
	struct kobject	*kobject,
	char		*buf)
{
	int cycle;
	int block;
	struct xlog *log = to_xlog(kobject);

	xlog_crack_atomic_lsn(&log->l_tail_lsn, &cycle, &block);
	return snprintf(buf, PAGE_SIZE, "%d:%d\n", cycle, block);
}
SCXFS_SYSFS_ATTR_RO(log_tail_lsn);

STATIC ssize_t
reserve_grant_head_show(
	struct kobject	*kobject,
	char		*buf)

{
	int cycle;
	int bytes;
	struct xlog *log = to_xlog(kobject);

	xlog_crack_grant_head(&log->l_reserve_head.grant, &cycle, &bytes);
	return snprintf(buf, PAGE_SIZE, "%d:%d\n", cycle, bytes);
}
SCXFS_SYSFS_ATTR_RO(reserve_grant_head);

STATIC ssize_t
write_grant_head_show(
	struct kobject	*kobject,
	char		*buf)
{
	int cycle;
	int bytes;
	struct xlog *log = to_xlog(kobject);

	xlog_crack_grant_head(&log->l_write_head.grant, &cycle, &bytes);
	return snprintf(buf, PAGE_SIZE, "%d:%d\n", cycle, bytes);
}
SCXFS_SYSFS_ATTR_RO(write_grant_head);

static struct attribute *scxfs_log_attrs[] = {
	ATTR_LIST(log_head_lsn),
	ATTR_LIST(log_tail_lsn),
	ATTR_LIST(reserve_grant_head),
	ATTR_LIST(write_grant_head),
	NULL,
};

struct kobj_type scxfs_log_ktype = {
	.release = scxfs_sysfs_release,
	.sysfs_ops = &scxfs_sysfs_ops,
	.default_attrs = scxfs_log_attrs,
};

/*
 * Metadata IO error configuration
 *
 * The sysfs structure here is:
 *	...xfs/<dev>/error/<class>/<errno>/<error_attrs>
 *
 * where <class> allows us to discriminate between data IO and metadata IO,
 * and any other future type of IO (e.g. special inode or directory error
 * handling) we care to support.
 */
static inline struct scxfs_error_cfg *
to_error_cfg(struct kobject *kobject)
{
	struct scxfs_kobj *kobj = to_kobj(kobject);
	return container_of(kobj, struct scxfs_error_cfg, kobj);
}

static inline struct scxfs_mount *
err_to_mp(struct kobject *kobject)
{
	struct scxfs_kobj *kobj = to_kobj(kobject);
	return container_of(kobj, struct scxfs_mount, m_error_kobj);
}

static ssize_t
max_retries_show(
	struct kobject	*kobject,
	char		*buf)
{
	int		retries;
	struct scxfs_error_cfg *cfg = to_error_cfg(kobject);

	if (cfg->max_retries == SCXFS_ERR_RETRY_FOREVER)
		retries = -1;
	else
		retries = cfg->max_retries;

	return snprintf(buf, PAGE_SIZE, "%d\n", retries);
}

static ssize_t
max_retries_store(
	struct kobject	*kobject,
	const char	*buf,
	size_t		count)
{
	struct scxfs_error_cfg *cfg = to_error_cfg(kobject);
	int		ret;
	int		val;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val < -1)
		return -EINVAL;

	if (val == -1)
		cfg->max_retries = SCXFS_ERR_RETRY_FOREVER;
	else
		cfg->max_retries = val;
	return count;
}
SCXFS_SYSFS_ATTR_RW(max_retries);

static ssize_t
retry_timeout_seconds_show(
	struct kobject	*kobject,
	char		*buf)
{
	int		timeout;
	struct scxfs_error_cfg *cfg = to_error_cfg(kobject);

	if (cfg->retry_timeout == SCXFS_ERR_RETRY_FOREVER)
		timeout = -1;
	else
		timeout = jiffies_to_msecs(cfg->retry_timeout) / MSEC_PER_SEC;

	return snprintf(buf, PAGE_SIZE, "%d\n", timeout);
}

static ssize_t
retry_timeout_seconds_store(
	struct kobject	*kobject,
	const char	*buf,
	size_t		count)
{
	struct scxfs_error_cfg *cfg = to_error_cfg(kobject);
	int		ret;
	int		val;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	/* 1 day timeout maximum, -1 means infinite */
	if (val < -1 || val > 86400)
		return -EINVAL;

	if (val == -1)
		cfg->retry_timeout = SCXFS_ERR_RETRY_FOREVER;
	else {
		cfg->retry_timeout = msecs_to_jiffies(val * MSEC_PER_SEC);
		ASSERT(msecs_to_jiffies(val * MSEC_PER_SEC) < LONG_MAX);
	}
	return count;
}
SCXFS_SYSFS_ATTR_RW(retry_timeout_seconds);

static ssize_t
fail_at_unmount_show(
	struct kobject	*kobject,
	char		*buf)
{
	struct scxfs_mount	*mp = err_to_mp(kobject);

	return snprintf(buf, PAGE_SIZE, "%d\n", mp->m_fail_unmount);
}

static ssize_t
fail_at_unmount_store(
	struct kobject	*kobject,
	const char	*buf,
	size_t		count)
{
	struct scxfs_mount	*mp = err_to_mp(kobject);
	int		ret;
	int		val;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val < 0 || val > 1)
		return -EINVAL;

	mp->m_fail_unmount = val;
	return count;
}
SCXFS_SYSFS_ATTR_RW(fail_at_unmount);

static struct attribute *scxfs_error_attrs[] = {
	ATTR_LIST(max_retries),
	ATTR_LIST(retry_timeout_seconds),
	NULL,
};


static struct kobj_type scxfs_error_cfg_ktype = {
	.release = scxfs_sysfs_release,
	.sysfs_ops = &scxfs_sysfs_ops,
	.default_attrs = scxfs_error_attrs,
};

static struct kobj_type scxfs_error_ktype = {
	.release = scxfs_sysfs_release,
	.sysfs_ops = &scxfs_sysfs_ops,
};

/*
 * Error initialization tables. These need to be ordered in the same
 * order as the enums used to index the array. All class init tables need to
 * define a "default" behaviour as the first entry, all other entries can be
 * empty.
 */
struct scxfs_error_init {
	char		*name;
	int		max_retries;
	int		retry_timeout;	/* in seconds */
};

static const struct scxfs_error_init scxfs_error_meta_init[SCXFS_ERR_ERRNO_MAX] = {
	{ .name = "default",
	  .max_retries = SCXFS_ERR_RETRY_FOREVER,
	  .retry_timeout = SCXFS_ERR_RETRY_FOREVER,
	},
	{ .name = "EIO",
	  .max_retries = SCXFS_ERR_RETRY_FOREVER,
	  .retry_timeout = SCXFS_ERR_RETRY_FOREVER,
	},
	{ .name = "ENOSPC",
	  .max_retries = SCXFS_ERR_RETRY_FOREVER,
	  .retry_timeout = SCXFS_ERR_RETRY_FOREVER,
	},
	{ .name = "ENODEV",
	  .max_retries = 0,	/* We can't recover from devices disappearing */
	  .retry_timeout = 0,
	},
};

static int
scxfs_error_sysfs_init_class(
	struct scxfs_mount	*mp,
	int			class,
	const char		*parent_name,
	struct scxfs_kobj		*parent_kobj,
	const struct scxfs_error_init init[])
{
	struct scxfs_error_cfg	*cfg;
	int			error;
	int			i;

	ASSERT(class < SCXFS_ERR_CLASS_MAX);

	error = scxfs_sysfs_init(parent_kobj, &scxfs_error_ktype,
				&mp->m_error_kobj, parent_name);
	if (error)
		return error;

	for (i = 0; i < SCXFS_ERR_ERRNO_MAX; i++) {
		cfg = &mp->m_error_cfg[class][i];
		error = scxfs_sysfs_init(&cfg->kobj, &scxfs_error_cfg_ktype,
					parent_kobj, init[i].name);
		if (error)
			goto out_error;

		cfg->max_retries = init[i].max_retries;
		if (init[i].retry_timeout == SCXFS_ERR_RETRY_FOREVER)
			cfg->retry_timeout = SCXFS_ERR_RETRY_FOREVER;
		else
			cfg->retry_timeout = msecs_to_jiffies(
					init[i].retry_timeout * MSEC_PER_SEC);
	}
	return 0;

out_error:
	/* unwind the entries that succeeded */
	for (i--; i >= 0; i--) {
		cfg = &mp->m_error_cfg[class][i];
		scxfs_sysfs_del(&cfg->kobj);
	}
	scxfs_sysfs_del(parent_kobj);
	return error;
}

int
scxfs_error_sysfs_init(
	struct scxfs_mount	*mp)
{
	int			error;

	/* .../xfs/<dev>/error/ */
	error = scxfs_sysfs_init(&mp->m_error_kobj, &scxfs_error_ktype,
				&mp->m_kobj, "error");
	if (error)
		return error;

	error = sysfs_create_file(&mp->m_error_kobj.kobject,
				  ATTR_LIST(fail_at_unmount));

	if (error)
		goto out_error;

	/* .../xfs/<dev>/error/metadata/ */
	error = scxfs_error_sysfs_init_class(mp, SCXFS_ERR_METADATA,
				"metadata", &mp->m_error_meta_kobj,
				scxfs_error_meta_init);
	if (error)
		goto out_error;

	return 0;

out_error:
	scxfs_sysfs_del(&mp->m_error_kobj);
	return error;
}

void
scxfs_error_sysfs_del(
	struct scxfs_mount	*mp)
{
	struct scxfs_error_cfg	*cfg;
	int			i, j;

	for (i = 0; i < SCXFS_ERR_CLASS_MAX; i++) {
		for (j = 0; j < SCXFS_ERR_ERRNO_MAX; j++) {
			cfg = &mp->m_error_cfg[i][j];

			scxfs_sysfs_del(&cfg->kobj);
		}
	}
	scxfs_sysfs_del(&mp->m_error_meta_kobj);
	scxfs_sysfs_del(&mp->m_error_kobj);
}

struct scxfs_error_cfg *
scxfs_error_get_cfg(
	struct scxfs_mount	*mp,
	int			error_class,
	int			error)
{
	struct scxfs_error_cfg	*cfg;

	if (error < 0)
		error = -error;

	switch (error) {
	case EIO:
		cfg = &mp->m_error_cfg[error_class][SCXFS_ERR_EIO];
		break;
	case ENOSPC:
		cfg = &mp->m_error_cfg[error_class][SCXFS_ERR_ENOSPC];
		break;
	case ENODEV:
		cfg = &mp->m_error_cfg[error_class][SCXFS_ERR_ENODEV];
		break;
	default:
		cfg = &mp->m_error_cfg[error_class][SCXFS_ERR_DEFAULT];
		break;
	}

	return cfg;
}
