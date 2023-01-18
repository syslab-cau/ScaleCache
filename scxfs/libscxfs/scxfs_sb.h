// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_SB_H__
#define	__SCXFS_SB_H__

struct scxfs_mount;
struct scxfs_sb;
struct scxfs_dsb;
struct scxfs_trans;
struct scxfs_fsop_geom;
struct scxfs_perag;

/*
 * perag get/put wrappers for ref counting
 */
extern struct scxfs_perag *scxfs_perag_get(struct scxfs_mount *, scxfs_agnumber_t);
extern struct scxfs_perag *scxfs_perag_get_tag(struct scxfs_mount *, scxfs_agnumber_t,
					   int tag);
extern void	scxfs_perag_put(struct scxfs_perag *pag);
extern int	scxfs_initialize_perag_data(struct scxfs_mount *, scxfs_agnumber_t);

extern void	scxfs_log_sb(struct scxfs_trans *tp);
extern int	scxfs_sync_sb(struct scxfs_mount *mp, bool wait);
extern int	scxfs_sync_sb_buf(struct scxfs_mount *mp);
extern void	scxfs_sb_mount_common(struct scxfs_mount *mp, struct scxfs_sb *sbp);
extern void	scxfs_sb_from_disk(struct scxfs_sb *to, struct scxfs_dsb *from);
extern void	scxfs_sb_to_disk(struct scxfs_dsb *to, struct scxfs_sb *from);
extern void	scxfs_sb_quota_from_disk(struct scxfs_sb *sbp);

extern int	scxfs_update_secondary_sbs(struct scxfs_mount *mp);

#define SCXFS_FS_GEOM_MAX_STRUCT_VER	(4)
extern void	scxfs_fs_geometry(struct scxfs_sb *sbp, struct scxfs_fsop_geom *geo,
				int struct_version);
extern int	scxfs_sb_read_secondary(struct scxfs_mount *mp,
				struct scxfs_trans *tp, scxfs_agnumber_t agno,
				struct scxfs_buf **bpp);
extern int	scxfs_sb_get_secondary(struct scxfs_mount *mp,
				struct scxfs_trans *tp, scxfs_agnumber_t agno,
				struct scxfs_buf **bpp);

#endif	/* __SCXFS_SB_H__ */
