// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2001-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_SYSCTL_H__
#define __SCXFS_SYSCTL_H__

#include <linux/sysctl.h>

/*
 * Tunable scxfs parameters
 */

typedef struct scxfs_sysctl_val {
	int min;
	int val;
	int max;
} scxfs_sysctl_val_t;

typedef struct scxfs_param {
	scxfs_sysctl_val_t sgid_inherit;	/* Inherit S_ISGID if process' GID is
					 * not a member of parent dir GID. */
	scxfs_sysctl_val_t symlink_mode;	/* Link creat mode affected by umask */
	scxfs_sysctl_val_t panic_mask;	/* bitmask to cause panic on errors. */
	scxfs_sysctl_val_t error_level;	/* Degree of reporting for problems  */
	scxfs_sysctl_val_t syncd_timer;	/* Interval between xfssyncd wakeups */
	scxfs_sysctl_val_t stats_clear;	/* Reset all SCXFS statistics to zero. */
	scxfs_sysctl_val_t inherit_sync;	/* Inherit the "sync" inode flag. */
	scxfs_sysctl_val_t inherit_nodump;/* Inherit the "nodump" inode flag. */
	scxfs_sysctl_val_t inherit_noatim;/* Inherit the "noatime" inode flag. */
	scxfs_sysctl_val_t scxfs_buf_timer;	/* Interval between xfsbufd wakeups. */
	scxfs_sysctl_val_t scxfs_buf_age;	/* Metadata buffer age before flush. */
	scxfs_sysctl_val_t inherit_nosym;	/* Inherit the "nosymlinks" flag. */
	scxfs_sysctl_val_t rotorstep;	/* inode32 AG rotoring control knob */
	scxfs_sysctl_val_t inherit_nodfrg;/* Inherit the "nodefrag" inode flag. */
	scxfs_sysctl_val_t fstrm_timer;	/* Filestream dir-AG assoc'n timeout. */
	scxfs_sysctl_val_t eofb_timer;	/* Interval between eofb scan wakeups */
	scxfs_sysctl_val_t cowb_timer;	/* Interval between cowb scan wakeups */
} scxfs_param_t;

/*
 * scxfs_error_level:
 *
 * How much error reporting will be done when internal problems are
 * encountered.  These problems normally return an EFSCORRUPTED to their
 * caller, with no other information reported.
 *
 * 0	No error reports
 * 1	Report EFSCORRUPTED errors that will cause a filesystem shutdown
 * 5	Report all EFSCORRUPTED errors (all of the above errors, plus any
 *	additional errors that are known to not cause shutdowns)
 *
 * scxfs_panic_mask bit 0x8 turns the error reports into panics
 */

enum {
	/* SCXFS_REFCACHE_SIZE = 1 */
	/* SCXFS_REFCACHE_PURGE = 2 */
	/* SCXFS_RESTRICT_CHOWN = 3 */
	SCXFS_SGID_INHERIT = 4,
	SCXFS_SYMLINK_MODE = 5,
	SCXFS_PANIC_MASK = 6,
	SCXFS_ERRLEVEL = 7,
	SCXFS_SYNCD_TIMER = 8,
	/* SCXFS_PROBE_DMAPI = 9 */
	/* SCXFS_PROBE_IOOPS = 10 */
	/* SCXFS_PROBE_QUOTA = 11 */
	SCXFS_STATS_CLEAR = 12,
	SCXFS_INHERIT_SYNC = 13,
	SCXFS_INHERIT_NODUMP = 14,
	SCXFS_INHERIT_NOATIME = 15,
	SCXFS_BUF_TIMER = 16,
	SCXFS_BUF_AGE = 17,
	/* SCXFS_IO_BYPASS = 18 */
	SCXFS_INHERIT_NOSYM = 19,
	SCXFS_ROTORSTEP = 20,
	SCXFS_INHERIT_NODFRG = 21,
	SCXFS_FILESTREAM_TIMER = 22,
};

extern scxfs_param_t	scxfs_params;

struct scxfs_globals {
#ifdef DEBUG
	int	pwork_threads;		/* parallel workqueue threads */
#endif
	int	log_recovery_delay;	/* log recovery delay (secs) */
	int	mount_delay;		/* mount setup delay (secs) */
	bool	bug_on_assert;		/* BUG() the kernel on assert failure */
	bool	always_cow;		/* use COW fork for all overwrites */
};
extern struct scxfs_globals	scxfs_globals;

#ifdef CONFIG_SYSCTL
extern int scxfs_sysctl_register(void);
extern void scxfs_sysctl_unregister(void);
#else
# define scxfs_sysctl_register()		(0)
# define scxfs_sysctl_unregister()	do { } while (0)
#endif /* CONFIG_SYSCTL */

#endif /* __SCXFS_SYSCTL_H__ */
