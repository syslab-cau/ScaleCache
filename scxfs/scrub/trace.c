// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_btree.h"
#include "scrub/scrub.h"

/* Figure out which block the btree cursor was pointing to. */
static inline scxfs_fsblock_t
xchk_btree_cur_fsbno(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	if (level < cur->bc_nlevels && cur->bc_bufs[level])
		return SCXFS_DADDR_TO_FSB(cur->bc_mp, cur->bc_bufs[level]->b_bn);
	else if (level == cur->bc_nlevels - 1 &&
		 cur->bc_flags & SCXFS_BTREE_LONG_PTRS)
		return SCXFS_INO_TO_FSB(cur->bc_mp, cur->bc_private.b.ip->i_ino);
	else if (!(cur->bc_flags & SCXFS_BTREE_LONG_PTRS))
		return SCXFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno, 0);
	return NULLFSBLOCK;
}

/*
 * We include this last to have the helpers above available for the trace
 * event implementations.
 */
#define CREATE_TRACE_POINTS
#include "scrub/trace.h"
