// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_SUPER_H__
#define __SCXFS_SUPER_H__

#include <linux/exportfs.h>

#ifdef CONFIG_XFS_QUOTA
extern int scxfs_qm_init(void);
extern void scxfs_qm_exit(void);
#else
# define scxfs_qm_init()	(0)
# define scxfs_qm_exit()	do { } while (0)
#endif

#ifdef CONFIG_XFS_POSIX_ACL
# define SCXFS_ACL_STRING		"ACLs, "
# define set_posix_acl_flag(sb)	((sb)->s_flags |= SB_POSIXACL)
#else
# define SCXFS_ACL_STRING
# define set_posix_acl_flag(sb)	do { } while (0)
#endif

#define SCXFS_SECURITY_STRING	"security attributes, "

#ifdef CONFIG_XFS_RT
# define SCXFS_REALTIME_STRING	"realtime, "
#else
# define SCXFS_REALTIME_STRING
#endif

#ifdef CONFIG_XFS_ONLINE_SCRUB
# define SCXFS_SCRUB_STRING	"scrub, "
#else
# define SCXFS_SCRUB_STRING
#endif

#ifdef CONFIG_XFS_ONLINE_REPAIR
# define SCXFS_REPAIR_STRING	"repair, "
#else
# define SCXFS_REPAIR_STRING
#endif

#ifdef CONFIG_XFS_WARN
# define SCXFS_WARN_STRING	"verbose warnings, "
#else
# define SCXFS_WARN_STRING
#endif

#ifdef DEBUG
# define SCXFS_DBG_STRING		"debug"
#else
# define SCXFS_DBG_STRING		"no debug"
#endif

#define SCXFS_VERSION_STRING	"SGI SCXFS"
#define SCXFS_BUILD_OPTIONS	SCXFS_ACL_STRING \
				SCXFS_SECURITY_STRING \
				SCXFS_REALTIME_STRING \
				SCXFS_SCRUB_STRING \
				SCXFS_REPAIR_STRING \
				SCXFS_WARN_STRING \
				SCXFS_DBG_STRING /* DBG must be last */

struct scxfs_inode;
struct scxfs_mount;
struct scxfs_buftarg;
struct block_device;

extern void scxfs_quiesce_attr(struct scxfs_mount *mp);
extern void scxfs_flush_inodes(struct scxfs_mount *mp);
extern void scxfs_blkdev_issue_flush(struct scxfs_buftarg *);
extern scxfs_agnumber_t scxfs_set_inode_alloc(struct scxfs_mount *,
					   scxfs_agnumber_t agcount);

extern const struct export_operations scxfs_export_operations;
extern const struct xattr_handler *scxfs_xattr_handlers[];
extern const struct quotactl_ops scxfs_quotactl_operations;

extern void scxfs_reinit_percpu_counters(struct scxfs_mount *mp);

extern struct workqueue_struct *scxfs_discard_wq;

#define SCXFS_M(sb)		((struct scxfs_mount *)((sb)->s_fs_info))

#endif	/* __SCXFS_SUPER_H__ */
