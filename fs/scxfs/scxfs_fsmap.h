// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_FSMAP_H__
#define __SCXFS_FSMAP_H__

struct fsmap;

/* internal fsmap representation */
struct scxfs_fsmap {
	dev_t		fmr_device;	/* device id */
	uint32_t	fmr_flags;	/* mapping flags */
	uint64_t	fmr_physical;	/* device offset of segment */
	uint64_t	fmr_owner;	/* owner id */
	scxfs_fileoff_t	fmr_offset;	/* file offset of segment */
	scxfs_filblks_t	fmr_length;	/* length of segment, blocks */
};

struct scxfs_fsmap_head {
	uint32_t	fmh_iflags;	/* control flags */
	uint32_t	fmh_oflags;	/* output flags */
	unsigned int	fmh_count;	/* # of entries in array incl. input */
	unsigned int	fmh_entries;	/* # of entries filled in (output). */

	struct scxfs_fsmap fmh_keys[2];	/* low and high keys */
};

void scxfs_fsmap_to_internal(struct scxfs_fsmap *dest, struct fsmap *src);

int scxfs_getfsmap(struct scxfs_mount *mp, struct scxfs_fsmap_head *head,
		struct fsmap *out_recs);

#endif /* __SCXFS_FSMAP_H__ */
