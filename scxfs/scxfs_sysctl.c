// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2001-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_error.h"

static struct ctl_table_header *scxfs_table_header;

#ifdef CONFIG_PROC_FS
STATIC int
scxfs_stats_clear_proc_handler(
	struct ctl_table	*ctl,
	int			write,
	void			__user *buffer,
	size_t			*lenp,
	loff_t			*ppos)
{
	int		ret, *valp = ctl->data;

	ret = proc_dointvec_minmax(ctl, write, buffer, lenp, ppos);

	if (!ret && write && *valp) {
		scxfs_stats_clearall(xfsstats.xs_stats);
		scxfs_stats_clear = 0;
	}

	return ret;
}

STATIC int
scxfs_panic_mask_proc_handler(
	struct ctl_table	*ctl,
	int			write,
	void			__user *buffer,
	size_t			*lenp,
	loff_t			*ppos)
{
	int		ret, *valp = ctl->data;

	ret = proc_dointvec_minmax(ctl, write, buffer, lenp, ppos);
	if (!ret && write) {
		scxfs_panic_mask = *valp;
#ifdef DEBUG
		scxfs_panic_mask |= (SCXFS_PTAG_SHUTDOWN_CORRUPT | SCXFS_PTAG_LOGRES);
#endif
	}
	return ret;
}
#endif /* CONFIG_PROC_FS */

static struct ctl_table scxfs_table[] = {
	{
		.procname	= "irix_sgid_inherit",
		.data		= &scxfs_params.sgid_inherit.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.sgid_inherit.min,
		.extra2		= &scxfs_params.sgid_inherit.max
	},
	{
		.procname	= "irix_symlink_mode",
		.data		= &scxfs_params.symlink_mode.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.symlink_mode.min,
		.extra2		= &scxfs_params.symlink_mode.max
	},
	{
		.procname	= "panic_mask",
		.data		= &scxfs_params.panic_mask.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= scxfs_panic_mask_proc_handler,
		.extra1		= &scxfs_params.panic_mask.min,
		.extra2		= &scxfs_params.panic_mask.max
	},

	{
		.procname	= "error_level",
		.data		= &scxfs_params.error_level.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.error_level.min,
		.extra2		= &scxfs_params.error_level.max
	},
	{
		.procname	= "xfssyncd_centisecs",
		.data		= &scxfs_params.syncd_timer.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.syncd_timer.min,
		.extra2		= &scxfs_params.syncd_timer.max
	},
	{
		.procname	= "inherit_sync",
		.data		= &scxfs_params.inherit_sync.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.inherit_sync.min,
		.extra2		= &scxfs_params.inherit_sync.max
	},
	{
		.procname	= "inherit_nodump",
		.data		= &scxfs_params.inherit_nodump.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.inherit_nodump.min,
		.extra2		= &scxfs_params.inherit_nodump.max
	},
	{
		.procname	= "inherit_noatime",
		.data		= &scxfs_params.inherit_noatim.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.inherit_noatim.min,
		.extra2		= &scxfs_params.inherit_noatim.max
	},
	{
		.procname	= "inherit_nosymlinks",
		.data		= &scxfs_params.inherit_nosym.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.inherit_nosym.min,
		.extra2		= &scxfs_params.inherit_nosym.max
	},
	{
		.procname	= "rotorstep",
		.data		= &scxfs_params.rotorstep.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.rotorstep.min,
		.extra2		= &scxfs_params.rotorstep.max
	},
	{
		.procname	= "inherit_nodefrag",
		.data		= &scxfs_params.inherit_nodfrg.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.inherit_nodfrg.min,
		.extra2		= &scxfs_params.inherit_nodfrg.max
	},
	{
		.procname	= "filestream_centisecs",
		.data		= &scxfs_params.fstrm_timer.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.fstrm_timer.min,
		.extra2		= &scxfs_params.fstrm_timer.max,
	},
	{
		.procname	= "speculative_prealloc_lifetime",
		.data		= &scxfs_params.eofb_timer.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.eofb_timer.min,
		.extra2		= &scxfs_params.eofb_timer.max,
	},
	{
		.procname	= "speculative_cow_prealloc_lifetime",
		.data		= &scxfs_params.cowb_timer.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &scxfs_params.cowb_timer.min,
		.extra2		= &scxfs_params.cowb_timer.max,
	},
	/* please keep this the last entry */
#ifdef CONFIG_PROC_FS
	{
		.procname	= "stats_clear",
		.data		= &scxfs_params.stats_clear.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= scxfs_stats_clear_proc_handler,
		.extra1		= &scxfs_params.stats_clear.min,
		.extra2		= &scxfs_params.stats_clear.max
	},
#endif /* CONFIG_PROC_FS */

	{}
};

static struct ctl_table scxfs_dir_table[] = {
	{
		.procname	= "scxfs",
		.mode		= 0555,
		.child		= scxfs_table
	},
	{}
};

static struct ctl_table scxfs_root_table[] = {
	{
		.procname	= "fs",
		.mode		= 0555,
		.child		= scxfs_dir_table
	},
	{}
};

int
scxfs_sysctl_register(void)
{
	scxfs_table_header = register_sysctl_table(scxfs_root_table);
	if (!scxfs_table_header)
		return -ENOMEM;
	return 0;
}

void
scxfs_sysctl_unregister(void)
{
	unregister_sysctl_table(scxfs_table_header);
}
