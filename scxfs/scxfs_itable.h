// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001 Silicon Graphics, Inc.  All Rights Reserved.
 */
#ifndef __SCXFS_ITABLE_H__
#define	__SCXFS_ITABLE_H__

/* In-memory representation of a userspace request for batch inode data. */
struct scxfs_ibulk {
	struct scxfs_mount	*mp;
	void __user		*ubuffer; /* user output buffer */
	scxfs_ino_t		startino; /* start with this inode */
	unsigned int		icount;   /* number of elements in ubuffer */
	unsigned int		ocount;   /* number of records returned */
	unsigned int		flags;    /* see SCXFS_IBULK_FLAG_* */
};

/* Only iterate within the same AG as startino */
#define SCXFS_IBULK_SAME_AG	(SCXFS_IWALK_SAME_AG)

/*
 * Advance the user buffer pointer by one record of the given size.  If the
 * buffer is now full, return the appropriate error code.
 */
static inline int
scxfs_ibulk_advance(
	struct scxfs_ibulk	*breq,
	size_t			bytes)
{
	char __user		*b = breq->ubuffer;

	breq->ubuffer = b + bytes;
	breq->ocount++;
	return breq->ocount == breq->icount ? -ECANCELED : 0;
}

/*
 * Return stat information in bulk (by-inode) for the filesystem.
 */

/*
 * Return codes for the formatter function are 0 to continue iterating, and
 * non-zero to stop iterating.  Any non-zero value will be passed up to the
 * bulkstat/inumbers caller.  The special value -ECANCELED can be used to stop
 * iteration, as neither bulkstat nor inumbers will ever generate that error
 * code on their own.
 */

typedef int (*bulkstat_one_fmt_pf)(struct scxfs_ibulk *breq,
		const struct scxfs_bulkstat *bstat);

int scxfs_bulkstat_one(struct scxfs_ibulk *breq, bulkstat_one_fmt_pf formatter);
int scxfs_bulkstat(struct scxfs_ibulk *breq, bulkstat_one_fmt_pf formatter);
void scxfs_bulkstat_to_bstat(struct scxfs_mount *mp, struct scxfs_bstat *bs1,
		const struct scxfs_bulkstat *bstat);

typedef int (*inumbers_fmt_pf)(struct scxfs_ibulk *breq,
		const struct scxfs_inumbers *igrp);

int scxfs_inumbers(struct scxfs_ibulk *breq, inumbers_fmt_pf formatter);
void scxfs_inumbers_to_inogrp(struct scxfs_inogrp *ig1,
		const struct scxfs_inumbers *ig);

#endif	/* __SCXFS_ITABLE_H__ */
