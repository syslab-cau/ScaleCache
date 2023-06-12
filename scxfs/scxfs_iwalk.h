/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2019 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_IWALK_H__
#define __SCXFS_IWALK_H__

/*
 * Return codes for the inode/inobt walk function are 0 to continue iterating,
 * and non-zero to stop iterating.  Any non-zero value will be passed up to the
 * iwalk or inobt_walk caller.  The special value -ECANCELED can be used to
 * stop iteration, as neither iwalk nor inobt_walk will ever generate that
 * error code on their own.
 */

/* Walk all inodes in the filesystem starting from @startino. */
typedef int (*scxfs_iwalk_fn)(struct scxfs_mount *mp, struct scxfs_trans *tp,
			    scxfs_ino_t ino, void *data);

int scxfs_iwalk(struct scxfs_mount *mp, struct scxfs_trans *tp, scxfs_ino_t startino,
		unsigned int flags, scxfs_iwalk_fn iwalk_fn,
		unsigned int inode_records, void *data);
int scxfs_iwalk_threaded(struct scxfs_mount *mp, scxfs_ino_t startino,
		unsigned int flags, scxfs_iwalk_fn iwalk_fn,
		unsigned int inode_records, bool poll, void *data);

/* Only iterate inodes within the same AG as @startino. */
#define SCXFS_IWALK_SAME_AG	(0x1)

#define SCXFS_IWALK_FLAGS_ALL	(SCXFS_IWALK_SAME_AG)

/* Walk all inode btree records in the filesystem starting from @startino. */
typedef int (*scxfs_inobt_walk_fn)(struct scxfs_mount *mp, struct scxfs_trans *tp,
				 scxfs_agnumber_t agno,
				 const struct scxfs_inobt_rec_incore *irec,
				 void *data);

int scxfs_inobt_walk(struct scxfs_mount *mp, struct scxfs_trans *tp,
		scxfs_ino_t startino, unsigned int flags,
		scxfs_inobt_walk_fn inobt_walk_fn, unsigned int inobt_records,
		void *data);

/* Only iterate inobt records within the same AG as @startino. */
#define SCXFS_INOBT_WALK_SAME_AG	(SCXFS_IWALK_SAME_AG)

#define SCXFS_INOBT_WALK_FLAGS_ALL (SCXFS_INOBT_WALK_SAME_AG)

#endif /* __SCXFS_IWALK_H__ */
