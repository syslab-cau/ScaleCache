// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_BIT_H__
#define	__SCXFS_BIT_H__

/*
 * SCXFS bit manipulation routines.
 */

/*
 * masks with n high/low bits set, 64-bit values
 */
static inline uint64_t scxfs_mask64hi(int n)
{
	return (uint64_t)-1 << (64 - (n));
}
static inline uint32_t scxfs_mask32lo(int n)
{
	return ((uint32_t)1 << (n)) - 1;
}
static inline uint64_t scxfs_mask64lo(int n)
{
	return ((uint64_t)1 << (n)) - 1;
}

/* Get high bit set out of 32-bit argument, -1 if none set */
static inline int scxfs_highbit32(uint32_t v)
{
	return fls(v) - 1;
}

/* Get high bit set out of 64-bit argument, -1 if none set */
static inline int scxfs_highbit64(uint64_t v)
{
	return fls64(v) - 1;
}

/* Get low bit set out of 32-bit argument, -1 if none set */
static inline int scxfs_lowbit32(uint32_t v)
{
	return ffs(v) - 1;
}

/* Get low bit set out of 64-bit argument, -1 if none set */
static inline int scxfs_lowbit64(uint64_t v)
{
	uint32_t	w = (uint32_t)v;
	int		n = 0;

	if (w) {	/* lower bits */
		n = ffs(w);
	} else {	/* upper bits */
		w = (uint32_t)(v >> 32);
		if (w) {
			n = ffs(w);
			if (n)
				n += 32;
		}
	}
	return n - 1;
}

/* Return whether bitmap is empty (1 == empty) */
extern int scxfs_bitmap_empty(uint *map, uint size);

/* Count continuous one bits in map starting with start_bit */
extern int scxfs_contig_bits(uint *map, uint size, uint start_bit);

/* Find next set bit in map */
extern int scxfs_next_bit(uint *map, uint size, uint start_bit);

#endif	/* __SCXFS_BIT_H__ */
