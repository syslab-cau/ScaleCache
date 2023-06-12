// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_SCRUB_H__
#define __SCXFS_SCRUB_H__

#ifndef CONFIG_XFS_ONLINE_SCRUB
# define scxfs_scrub_metadata(ip, sm)	(-ENOTTY)
#else
int scxfs_scrub_metadata(struct scxfs_inode *ip, struct scxfs_scrub_metadata *sm);
#endif /* CONFIG_XFS_ONLINE_SCRUB */

#endif	/* __SCXFS_SCRUB_H__ */
