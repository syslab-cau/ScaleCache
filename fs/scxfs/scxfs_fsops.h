// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_FSOPS_H__
#define	__SCXFS_FSOPS_H__

extern int scxfs_growfs_data(scxfs_mount_t *mp, scxfs_growfs_data_t *in);
extern int scxfs_growfs_log(scxfs_mount_t *mp, scxfs_growfs_log_t *in);
extern void scxfs_fs_counts(scxfs_mount_t *mp, scxfs_fsop_counts_t *cnt);
extern int scxfs_reserve_blocks(scxfs_mount_t *mp, uint64_t *inval,
				scxfs_fsop_resblks_t *outval);
extern int scxfs_fs_goingdown(scxfs_mount_t *mp, uint32_t inflags);

extern int scxfs_fs_reserve_ag_blocks(struct scxfs_mount *mp);
extern int scxfs_fs_unreserve_ag_blocks(struct scxfs_mount *mp);

#endif	/* __SCXFS_FSOPS_H__ */
