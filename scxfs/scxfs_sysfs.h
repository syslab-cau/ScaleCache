// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014 Red Hat, Inc.
 * All Rights Reserved.
 */

#ifndef __SCXFS_SYSFS_H__
#define __SCXFS_SYSFS_H__

extern struct kobj_type scxfs_mp_ktype;	/* scxfs_mount */
extern struct kobj_type scxfs_dbg_ktype;	/* debug */
extern struct kobj_type scxfs_log_ktype;	/* xlog */
extern struct kobj_type scxfs_stats_ktype;	/* stats */

static inline struct scxfs_kobj *
to_kobj(struct kobject *kobject)
{
	return container_of(kobject, struct scxfs_kobj, kobject);
}

static inline void
scxfs_sysfs_release(struct kobject *kobject)
{
	struct scxfs_kobj *kobj = to_kobj(kobject);
	complete(&kobj->complete);
}

static inline int
scxfs_sysfs_init(
	struct scxfs_kobj		*kobj,
	struct kobj_type	*ktype,
	struct scxfs_kobj		*parent_kobj,
	const char		*name)
{
	struct kobject		*parent;

	parent = parent_kobj ? &parent_kobj->kobject : NULL;
	init_completion(&kobj->complete);
	return kobject_init_and_add(&kobj->kobject, ktype, parent, "%s", name);
}

static inline void
scxfs_sysfs_del(
	struct scxfs_kobj	*kobj)
{
	kobject_del(&kobj->kobject);
	kobject_put(&kobj->kobject);
	wait_for_completion(&kobj->complete);
}

int	scxfs_error_sysfs_init(struct scxfs_mount *mp);
void	scxfs_error_sysfs_del(struct scxfs_mount *mp);

#endif	/* __SCXFS_SYSFS_H__ */
