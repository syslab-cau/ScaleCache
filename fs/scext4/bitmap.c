// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/scext4/bitmap.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/buffer_head.h>
#include "scext4.h"

unsigned int scext4_count_free(char *bitmap, unsigned int numchars)
{
	return numchars * BITS_PER_BYTE - memweight(bitmap, numchars);
}

int scext4_inode_bitmap_csum_verify(struct super_block *sb, scext4_group_t group,
				  struct scext4_group_desc *gdp,
				  struct buffer_head *bh, int sz)
{
	__u32 hi;
	__u32 provided, calculated;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);

	if (!scext4_has_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_inode_bitmap_csum_lo);
	calculated = scext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= SCEXT4_BG_INODE_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_inode_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	return provided == calculated;
}

void scext4_inode_bitmap_csum_set(struct super_block *sb, scext4_group_t group,
				struct scext4_group_desc *gdp,
				struct buffer_head *bh, int sz)
{
	__u32 csum;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);

	if (!scext4_has_metadata_csum(sb))
		return;

	csum = scext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_inode_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= SCEXT4_BG_INODE_BITMAP_CSUM_HI_END)
		gdp->bg_inode_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}

int scext4_block_bitmap_csum_verify(struct super_block *sb, scext4_group_t group,
				  struct scext4_group_desc *gdp,
				  struct buffer_head *bh)
{
	__u32 hi;
	__u32 provided, calculated;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	int sz = SCEXT4_CLUSTERS_PER_GROUP(sb) / 8;

	if (!scext4_has_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_block_bitmap_csum_lo);
	calculated = scext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= SCEXT4_BG_BLOCK_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_block_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	if (provided == calculated)
		return 1;

	return 0;
}

void scext4_block_bitmap_csum_set(struct super_block *sb, scext4_group_t group,
				struct scext4_group_desc *gdp,
				struct buffer_head *bh)
{
	int sz = SCEXT4_CLUSTERS_PER_GROUP(sb) / 8;
	__u32 csum;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);

	if (!scext4_has_metadata_csum(sb))
		return;

	csum = scext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_block_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= SCEXT4_BG_BLOCK_BITMAP_CSUM_HI_END)
		gdp->bg_block_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}
