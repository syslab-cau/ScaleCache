// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2003-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_IOMAP_H__
#define __SCXFS_IOMAP_H__

#include <linux/iomap.h>

struct scxfs_inode;
struct scxfs_bmbt_irec;

int scxfs_iomap_write_direct(struct scxfs_inode *, scxfs_off_t, size_t,
			struct scxfs_bmbt_irec *, int);
int scxfs_iomap_write_unwritten(struct scxfs_inode *, scxfs_off_t, scxfs_off_t, bool);

int scxfs_bmbt_to_iomap(struct scxfs_inode *, struct iomap *,
		struct scxfs_bmbt_irec *, bool shared);
scxfs_extlen_t scxfs_eof_alignment(struct scxfs_inode *ip, scxfs_extlen_t extsize);

static inline scxfs_filblks_t
scxfs_aligned_fsb_count(
	scxfs_fileoff_t		offset_fsb,
	scxfs_filblks_t		count_fsb,
	scxfs_extlen_t		extsz)
{
	if (extsz) {
		scxfs_extlen_t	align;

		div_u64_rem(offset_fsb, extsz, &align);
		if (align)
			count_fsb += align;
		div_u64_rem(count_fsb, extsz, &align);
		if (align)
			count_fsb += extsz - align;
	}

	return count_fsb;
}

extern const struct iomap_ops scxfs_iomap_ops;
extern const struct iomap_ops scxfs_seek_iomap_ops;
extern const struct iomap_ops scxfs_xattr_iomap_ops;

#endif /* __SCXFS_IOMAP_H__*/
