// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/scext4/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by
 *  Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/cred.h>

#include <asm/byteorder.h>

#include "scext4.h"
#include "scext4_jbd3.h"
#include "xattr.h"
#include "acl.h"

#include <trace/events/scext4.h>

/*
 * ialloc.c contains the inodes allocation and deallocation routines
 */

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */

/*
 * To avoid calling the atomic setbit hundreds or thousands of times, we only
 * need to use it within a single byte (to ensure we get endianness right).
 * We can use memset for the rest of the bitmap as there are no other users.
 */
void scext4_mark_bitmap_end(int start_bit, int end_bit, char *bitmap)
{
	int i;

	if (start_bit >= end_bit)
		return;

	scext4_debug("mark end bits +%d through +%d used\n", start_bit, end_bit);
	for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++)
		scext4_set_bit(i, bitmap);
	if (i < end_bit)
		memset(bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}

void scext4_end_bitmap_read(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh);
		set_bitmap_uptodate(bh);
	}
	unlock_buffer(bh);
	put_bh(bh);
}

static int scext4_validate_inode_bitmap(struct super_block *sb,
				      struct scext4_group_desc *desc,
				      scext4_group_t block_group,
				      struct buffer_head *bh)
{
	scext4_fsblk_t	blk;
	struct scext4_group_info *grp = scext4_get_group_info(sb, block_group);

	if (buffer_verified(bh))
		return 0;
	if (SCEXT4_MB_GRP_IBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	scext4_lock_group(sb, block_group);
	if (buffer_verified(bh))
		goto verified;
	blk = scext4_inode_bitmap(sb, desc);
	if (!scext4_inode_bitmap_csum_verify(sb, block_group, desc, bh,
					   SCEXT4_INODES_PER_GROUP(sb) / 8)) {
		scext4_unlock_group(sb, block_group);
		scext4_error(sb, "Corrupt inode bitmap - block_group = %u, "
			   "inode_bitmap = %llu", block_group, blk);
		scext4_mark_group_bitmap_corrupted(sb, block_group,
					SCEXT4_GROUP_INFO_IBITMAP_CORRUPT);
		return -EFSBADCRC;
	}
	set_buffer_verified(bh);
verified:
	scext4_unlock_group(sb, block_group);
	return 0;
}

/*
 * Read the inode allocation bitmap for a given block_group, reading
 * into the specified slot in the superblock's bitmap cache.
 *
 * Return buffer_head of bitmap on success or NULL.
 */
static struct buffer_head *
scext4_read_inode_bitmap(struct super_block *sb, scext4_group_t block_group)
{
	struct scext4_group_desc *desc;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	struct buffer_head *bh = NULL;
	scext4_fsblk_t bitmap_blk;
	int err;

	desc = scext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);

	bitmap_blk = scext4_inode_bitmap(sb, desc);
	if ((bitmap_blk <= le32_to_cpu(sbi->s_es->s_first_data_block)) ||
	    (bitmap_blk >= scext4_blocks_count(sbi->s_es))) {
		scext4_error(sb, "Invalid inode bitmap blk %llu in "
			   "block_group %u", bitmap_blk, block_group);
		scext4_mark_group_bitmap_corrupted(sb, block_group,
					SCEXT4_GROUP_INFO_IBITMAP_CORRUPT);
		return ERR_PTR(-EFSCORRUPTED);
	}
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		scext4_warning(sb, "Cannot read inode bitmap - "
			     "block_group = %u, inode_bitmap = %llu",
			     block_group, bitmap_blk);
		return ERR_PTR(-ENOMEM);
	}
	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}

	scext4_lock_group(sb, block_group);
	if (scext4_has_group_desc_csum(sb) &&
	    (desc->bg_flags & cpu_to_le16(SCEXT4_BG_INODE_UNINIT))) {
		if (block_group == 0) {
			scext4_unlock_group(sb, block_group);
			unlock_buffer(bh);
			scext4_error(sb, "Inode bitmap for bg 0 marked "
				   "uninitialized");
			err = -EFSCORRUPTED;
			goto out;
		}
		memset(bh->b_data, 0, (SCEXT4_INODES_PER_GROUP(sb) + 7) / 8);
		scext4_mark_bitmap_end(SCEXT4_INODES_PER_GROUP(sb),
				     sb->s_blocksize * 8, bh->b_data);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		scext4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		return bh;
	}
	scext4_unlock_group(sb, block_group);

	if (buffer_uptodate(bh)) {
		/*
		 * if not uninit if bh is uptodate,
		 * bitmap is also uptodate
		 */
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}
	/*
	 * submit the buffer_head for reading
	 */
	trace_scext4_load_inode_bitmap(sb, block_group);
	bh->b_end_io = scext4_end_bitmap_read;
	get_bh(bh);
	submit_bh(REQ_OP_READ, REQ_META | REQ_PRIO, bh);
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh)) {
		put_bh(bh);
		scext4_error(sb, "Cannot read inode bitmap - "
			   "block_group = %u, inode_bitmap = %llu",
			   block_group, bitmap_blk);
		scext4_mark_group_bitmap_corrupted(sb, block_group,
				SCEXT4_GROUP_INFO_IBITMAP_CORRUPT);
		return ERR_PTR(-EIO);
	}

verify:
	err = scext4_validate_inode_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 *
 * HOWEVER: we must make sure that we get no aliases,
 * which means that we have to call "clear_inode()"
 * _before_ we mark the inode not in use in the inode
 * bitmaps. Otherwise a newly created file might use
 * the same inode number (not actually the same pointer
 * though), and then we'd have two inodes sharing the
 * same inode number and space on the harddisk.
 */
void scext4_free_inode(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	int is_directory;
	unsigned long ino;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	scext4_group_t block_group;
	unsigned long bit;
	struct scext4_group_desc *gdp;
	struct scext4_super_block *es;
	struct scext4_sb_info *sbi;
	int fatal = 0, err, count, cleared;
	struct scext4_group_info *grp;

	if (!sb) {
		printk(KERN_ERR "SCEXT4-fs: %s:%d: inode on "
		       "nonexistent device\n", __func__, __LINE__);
		return;
	}
	if (atomic_read(&inode->i_count) > 1) {
		scext4_msg(sb, KERN_ERR, "%s:%d: inode #%lu: count=%d",
			 __func__, __LINE__, inode->i_ino,
			 atomic_read(&inode->i_count));
		return;
	}
	if (inode->i_nlink) {
		scext4_msg(sb, KERN_ERR, "%s:%d: inode #%lu: nlink=%d\n",
			 __func__, __LINE__, inode->i_ino, inode->i_nlink);
		return;
	}
	sbi = SCEXT4_SB(sb);

	ino = inode->i_ino;
	scext4_debug("freeing inode %lu\n", ino);
	trace_scext4_free_inode(inode);

	dquot_initialize(inode);
	dquot_free_inode(inode);

	is_directory = S_ISDIR(inode->i_mode);

	/* Do this BEFORE marking the inode not in use or returning an error */
	scext4_clear_inode(inode);

	es = sbi->s_es;
	if (ino < SCEXT4_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		scext4_error(sb, "reserved or nonexistent inode %lu", ino);
		goto error_return;
	}
	block_group = (ino - 1) / SCEXT4_INODES_PER_GROUP(sb);
	bit = (ino - 1) % SCEXT4_INODES_PER_GROUP(sb);
	bitmap_bh = scext4_read_inode_bitmap(sb, block_group);
	/* Don't bother if the inode bitmap is corrupt. */
	grp = scext4_get_group_info(sb, block_group);
	if (IS_ERR(bitmap_bh)) {
		fatal = PTR_ERR(bitmap_bh);
		bitmap_bh = NULL;
		goto error_return;
	}
	if (unlikely(SCEXT4_MB_GRP_IBITMAP_CORRUPT(grp))) {
		fatal = -EFSCORRUPTED;
		goto error_return;
	}

	BUFFER_TRACE(bitmap_bh, "get_write_access");
	fatal = scext4_journal_get_write_access(handle, bitmap_bh);
	if (fatal)
		goto error_return;

	fatal = -ESRCH;
	gdp = scext4_get_group_desc(sb, block_group, &bh2);
	if (gdp) {
		BUFFER_TRACE(bh2, "get_write_access");
		fatal = scext4_journal_get_write_access(handle, bh2);
	}
	scext4_lock_group(sb, block_group);
	cleared = scext4_test_and_clear_bit(bit, bitmap_bh->b_data);
	if (fatal || !cleared) {
		scext4_unlock_group(sb, block_group);
		goto out;
	}

	count = scext4_free_inodes_count(sb, gdp) + 1;
	scext4_free_inodes_set(sb, gdp, count);
	if (is_directory) {
		count = scext4_used_dirs_count(sb, gdp) - 1;
		scext4_used_dirs_set(sb, gdp, count);
		percpu_counter_dec(&sbi->s_dirs_counter);
	}
	scext4_inode_bitmap_csum_set(sb, block_group, gdp, bitmap_bh,
				   SCEXT4_INODES_PER_GROUP(sb) / 8);
	scext4_group_desc_csum_set(sb, block_group, gdp);
	scext4_unlock_group(sb, block_group);

	percpu_counter_inc(&sbi->s_freeinodes_counter);
	if (sbi->s_log_groups_per_flex) {
		struct flex_groups *fg;

		fg = sbi_array_rcu_deref(sbi, s_flex_groups,
					 scext4_flex_group(sbi, block_group));
		atomic_inc(&fg->free_inodes);
		if (is_directory)
			atomic_dec(&fg->used_dirs);
	}
	BUFFER_TRACE(bh2, "call scext4_handle_dirty_metadata");
	fatal = scext4_handle_dirty_metadata(handle, NULL, bh2);
out:
	if (cleared) {
		BUFFER_TRACE(bitmap_bh, "call scext4_handle_dirty_metadata");
		err = scext4_handle_dirty_metadata(handle, NULL, bitmap_bh);
		if (!fatal)
			fatal = err;
	} else {
		scext4_error(sb, "bit already cleared for inode %lu", ino);
		scext4_mark_group_bitmap_corrupted(sb, block_group,
					SCEXT4_GROUP_INFO_IBITMAP_CORRUPT);
	}

error_return:
	brelse(bitmap_bh);
	scext4_std_error(sb, fatal);
}

struct orlov_stats {
	__u64 free_clusters;
	__u32 free_inodes;
	__u32 used_dirs;
};

/*
 * Helper function for Orlov's allocator; returns critical information
 * for a particular block group or flex_bg.  If flex_size is 1, then g
 * is a block group number; otherwise it is flex_bg number.
 */
static void get_orlov_stats(struct super_block *sb, scext4_group_t g,
			    int flex_size, struct orlov_stats *stats)
{
	struct scext4_group_desc *desc;

	if (flex_size > 1) {
		struct flex_groups *fg = sbi_array_rcu_deref(SCEXT4_SB(sb),
							     s_flex_groups, g);
		stats->free_inodes = atomic_read(&fg->free_inodes);
		stats->free_clusters = atomic64_read(&fg->free_clusters);
		stats->used_dirs = atomic_read(&fg->used_dirs);
		return;
	}

	desc = scext4_get_group_desc(sb, g, NULL);
	if (desc) {
		stats->free_inodes = scext4_free_inodes_count(sb, desc);
		stats->free_clusters = scext4_free_group_clusters(sb, desc);
		stats->used_dirs = scext4_used_dirs_count(sb, desc);
	} else {
		stats->free_inodes = 0;
		stats->free_clusters = 0;
		stats->used_dirs = 0;
	}
}

/*
 * Orlov's allocator for directories.
 *
 * We always try to spread first-level directories.
 *
 * If there are blockgroups with both free inodes and free blocks counts
 * not worse than average we return one with smallest directory count.
 * Otherwise we simply return a random group.
 *
 * For the rest rules look so:
 *
 * It's OK to put directory into a group unless
 * it has too many directories already (max_dirs) or
 * it has too few free inodes left (min_inodes) or
 * it has too few free blocks left (min_blocks) or
 * Parent's group is preferred, if it doesn't satisfy these
 * conditions we search cyclically through the rest. If none
 * of the groups look good we just look for a group with more
 * free inodes than average (starting at parent's group).
 */

static int find_group_orlov(struct super_block *sb, struct inode *parent,
			    scext4_group_t *group, umode_t mode,
			    const struct qstr *qstr)
{
	scext4_group_t parent_group = SCEXT4_I(parent)->i_block_group;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	scext4_group_t real_ngroups = scext4_get_groups_count(sb);
	int inodes_per_group = SCEXT4_INODES_PER_GROUP(sb);
	unsigned int freei, avefreei, grp_free;
	scext4_fsblk_t freeb, avefreec;
	unsigned int ndirs;
	int max_dirs, min_inodes;
	scext4_grpblk_t min_clusters;
	scext4_group_t i, grp, g, ngroups;
	struct scext4_group_desc *desc;
	struct orlov_stats stats;
	int flex_size = scext4_flex_bg_size(sbi);
	struct dx_hash_info hinfo;

	ngroups = real_ngroups;
	if (flex_size > 1) {
		ngroups = (real_ngroups + flex_size - 1) >>
			sbi->s_log_groups_per_flex;
		parent_group >>= sbi->s_log_groups_per_flex;
	}

	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	avefreei = freei / ngroups;
	freeb = SCEXT4_C2B(sbi,
		percpu_counter_read_positive(&sbi->s_freeclusters_counter));
	avefreec = freeb;
	do_div(avefreec, ngroups);
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

	if (S_ISDIR(mode) &&
	    ((parent == d_inode(sb->s_root)) ||
	     (scext4_test_inode_flag(parent, SCEXT4_INODE_TOPDIR)))) {
		int best_ndir = inodes_per_group;
		int ret = -1;

		if (qstr) {
			hinfo.hash_version = DX_HASH_HALF_MD4;
			hinfo.seed = sbi->s_hash_seed;
			scext4fs_dirhash(parent, qstr->name, qstr->len, &hinfo);
			grp = hinfo.hash;
		} else
			grp = prandom_u32();
		parent_group = (unsigned)grp % ngroups;
		for (i = 0; i < ngroups; i++) {
			g = (parent_group + i) % ngroups;
			get_orlov_stats(sb, g, flex_size, &stats);
			if (!stats.free_inodes)
				continue;
			if (stats.used_dirs >= best_ndir)
				continue;
			if (stats.free_inodes < avefreei)
				continue;
			if (stats.free_clusters < avefreec)
				continue;
			grp = g;
			ret = 0;
			best_ndir = stats.used_dirs;
		}
		if (ret)
			goto fallback;
	found_flex_bg:
		if (flex_size == 1) {
			*group = grp;
			return 0;
		}

		/*
		 * We pack inodes at the beginning of the flexgroup's
		 * inode tables.  Block allocation decisions will do
		 * something similar, although regular files will
		 * start at 2nd block group of the flexgroup.  See
		 * scext4_ext_find_goal() and scext4_find_near().
		 */
		grp *= flex_size;
		for (i = 0; i < flex_size; i++) {
			if (grp+i >= real_ngroups)
				break;
			desc = scext4_get_group_desc(sb, grp+i, NULL);
			if (desc && scext4_free_inodes_count(sb, desc)) {
				*group = grp+i;
				return 0;
			}
		}
		goto fallback;
	}

	max_dirs = ndirs / ngroups + inodes_per_group / 16;
	min_inodes = avefreei - inodes_per_group*flex_size / 4;
	if (min_inodes < 1)
		min_inodes = 1;
	min_clusters = avefreec - SCEXT4_CLUSTERS_PER_GROUP(sb)*flex_size / 4;

	/*
	 * Start looking in the flex group where we last allocated an
	 * inode for this parent directory
	 */
	if (SCEXT4_I(parent)->i_last_alloc_group != ~0) {
		parent_group = SCEXT4_I(parent)->i_last_alloc_group;
		if (flex_size > 1)
			parent_group >>= sbi->s_log_groups_per_flex;
	}

	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		get_orlov_stats(sb, grp, flex_size, &stats);
		if (stats.used_dirs >= max_dirs)
			continue;
		if (stats.free_inodes < min_inodes)
			continue;
		if (stats.free_clusters < min_clusters)
			continue;
		goto found_flex_bg;
	}

fallback:
	ngroups = real_ngroups;
	avefreei = freei / ngroups;
fallback_retry:
	parent_group = SCEXT4_I(parent)->i_block_group;
	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		desc = scext4_get_group_desc(sb, grp, NULL);
		if (desc) {
			grp_free = scext4_free_inodes_count(sb, desc);
			if (grp_free && grp_free >= avefreei) {
				*group = grp;
				return 0;
			}
		}
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback_retry;
	}

	return -1;
}

static int find_group_other(struct super_block *sb, struct inode *parent,
			    scext4_group_t *group, umode_t mode)
{
	scext4_group_t parent_group = SCEXT4_I(parent)->i_block_group;
	scext4_group_t i, last, ngroups = scext4_get_groups_count(sb);
	struct scext4_group_desc *desc;
	int flex_size = scext4_flex_bg_size(SCEXT4_SB(sb));

	/*
	 * Try to place the inode is the same flex group as its
	 * parent.  If we can't find space, use the Orlov algorithm to
	 * find another flex group, and store that information in the
	 * parent directory's inode information so that use that flex
	 * group for future allocations.
	 */
	if (flex_size > 1) {
		int retry = 0;

	try_again:
		parent_group &= ~(flex_size-1);
		last = parent_group + flex_size;
		if (last > ngroups)
			last = ngroups;
		for  (i = parent_group; i < last; i++) {
			desc = scext4_get_group_desc(sb, i, NULL);
			if (desc && scext4_free_inodes_count(sb, desc)) {
				*group = i;
				return 0;
			}
		}
		if (!retry && SCEXT4_I(parent)->i_last_alloc_group != ~0) {
			retry = 1;
			parent_group = SCEXT4_I(parent)->i_last_alloc_group;
			goto try_again;
		}
		/*
		 * If this didn't work, use the Orlov search algorithm
		 * to find a new flex group; we pass in the mode to
		 * avoid the topdir algorithms.
		 */
		*group = parent_group + flex_size;
		if (*group > ngroups)
			*group = 0;
		return find_group_orlov(sb, parent, group, mode, NULL);
	}

	/*
	 * Try to place the inode in its parent directory
	 */
	*group = parent_group;
	desc = scext4_get_group_desc(sb, *group, NULL);
	if (desc && scext4_free_inodes_count(sb, desc) &&
	    scext4_free_group_clusters(sb, desc))
		return 0;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	*group = (*group + parent->i_ino) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some free
	 * blocks.
	 */
	for (i = 1; i < ngroups; i <<= 1) {
		*group += i;
		if (*group >= ngroups)
			*group -= ngroups;
		desc = scext4_get_group_desc(sb, *group, NULL);
		if (desc && scext4_free_inodes_count(sb, desc) &&
		    scext4_free_group_clusters(sb, desc))
			return 0;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */
	*group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++*group >= ngroups)
			*group = 0;
		desc = scext4_get_group_desc(sb, *group, NULL);
		if (desc && scext4_free_inodes_count(sb, desc))
			return 0;
	}

	return -1;
}

/*
 * In no journal mode, if an inode has recently been deleted, we want
 * to avoid reusing it until we're reasonably sure the inode table
 * block has been written back to disk.  (Yes, these values are
 * somewhat arbitrary...)
 */
#define RECENTCY_MIN	60
#define RECENTCY_DIRTY	300

static int recently_deleted(struct super_block *sb, scext4_group_t group, int ino)
{
	struct scext4_group_desc	*gdp;
	struct scext4_inode	*raw_inode;
	struct buffer_head	*bh;
	int inodes_per_block = SCEXT4_SB(sb)->s_inodes_per_block;
	int offset, ret = 0;
	int recentcy = RECENTCY_MIN;
	u32 dtime, now;

	gdp = scext4_get_group_desc(sb, group, NULL);
	if (unlikely(!gdp))
		return 0;

	bh = sb_find_get_block(sb, scext4_inode_table(sb, gdp) +
		       (ino / inodes_per_block));
	if (!bh || !buffer_uptodate(bh))
		/*
		 * If the block is not in the buffer cache, then it
		 * must have been written out.
		 */
		goto out;

	offset = (ino % inodes_per_block) * SCEXT4_INODE_SIZE(sb);
	raw_inode = (struct scext4_inode *) (bh->b_data + offset);

	/* i_dtime is only 32 bits on disk, but we only care about relative
	 * times in the range of a few minutes (i.e. long enough to sync a
	 * recently-deleted inode to disk), so using the low 32 bits of the
	 * clock (a 68 year range) is enough, see time_before32() */
	dtime = le32_to_cpu(raw_inode->i_dtime);
	now = ktime_get_real_seconds();
	if (buffer_dirty(bh))
		recentcy += RECENTCY_DIRTY;

	if (dtime && time_before32(dtime, now) &&
	    time_before32(now, dtime + recentcy))
		ret = 1;
out:
	brelse(bh);
	return ret;
}

static int find_inode_bit(struct super_block *sb, scext4_group_t group,
			  struct buffer_head *bitmap, unsigned long *ino)
{
next:
	*ino = scext4_find_next_zero_bit((unsigned long *)
				       bitmap->b_data,
				       SCEXT4_INODES_PER_GROUP(sb), *ino);
	if (*ino >= SCEXT4_INODES_PER_GROUP(sb))
		return 0;

	if ((SCEXT4_SB(sb)->s_journal == NULL) &&
	    recently_deleted(sb, group, *ino)) {
		*ino = *ino + 1;
		if (*ino < SCEXT4_INODES_PER_GROUP(sb))
			goto next;
		return 0;
	}

	return 1;
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory's block
 * group to find a free inode.
 */
struct inode *__scext4_new_inode(handle_t *handle, struct inode *dir,
			       umode_t mode, const struct qstr *qstr,
			       __u32 goal, uid_t *owner, __u32 i_flags,
			       int handle_type, unsigned int line_no,
			       int nblocks)
{
	struct super_block *sb;
	struct buffer_head *inode_bitmap_bh = NULL;
	struct buffer_head *group_desc_bh;
	scext4_group_t ngroups, group = 0;
	unsigned long ino = 0;
	struct inode *inode;
	struct scext4_group_desc *gdp = NULL;
	struct scext4_inode_info *ei;
	struct scext4_sb_info *sbi;
	int ret2, err;
	struct inode *ret;
	scext4_group_t i;
	scext4_group_t flex_group;
	struct scext4_group_info *grp;
	int encrypt = 0;

	/* Cannot create files in a deleted directory */
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	sb = dir->i_sb;
	sbi = SCEXT4_SB(sb);

	if (unlikely(scext4_forced_shutdown(sbi)))
		return ERR_PTR(-EIO);

	if ((IS_ENCRYPTED(dir) || DUMMY_ENCRYPTION_ENABLED(sbi)) &&
	    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)) &&
	    !(i_flags & SCEXT4_EA_INODE_FL)) {
		err = fscrypt_get_encryption_info(dir);
		if (err)
			return ERR_PTR(err);
		if (!fscrypt_has_encryption_key(dir))
			return ERR_PTR(-ENOKEY);
		encrypt = 1;
	}

	if (!handle && sbi->s_journal && !(i_flags & SCEXT4_EA_INODE_FL)) {
#ifdef CONFIG_SCEXT4_FS_POSIX_ACL
		struct posix_acl *p = get_acl(dir, ACL_TYPE_DEFAULT);

		if (IS_ERR(p))
			return ERR_CAST(p);
		if (p) {
			int acl_size = p->a_count * sizeof(scext4_acl_entry);

			nblocks += (S_ISDIR(mode) ? 2 : 1) *
				__scext4_xattr_set_credits(sb, NULL /* inode */,
					NULL /* block_bh */, acl_size,
					true /* is_create */);
			posix_acl_release(p);
		}
#endif

#ifdef CONFIG_SECURITY
		{
			int num_security_xattrs = 1;

#ifdef CONFIG_INTEGRITY
			num_security_xattrs++;
#endif
			/*
			 * We assume that security xattrs are never
			 * more than 1k.  In practice they are under
			 * 128 bytes.
			 */
			nblocks += num_security_xattrs *
				__scext4_xattr_set_credits(sb, NULL /* inode */,
					NULL /* block_bh */, 1024,
					true /* is_create */);
		}
#endif
		if (encrypt)
			nblocks += __scext4_xattr_set_credits(sb,
					NULL /* inode */, NULL /* block_bh */,
					FSCRYPT_SET_CONTEXT_MAX_SIZE,
					true /* is_create */);
	}

	ngroups = scext4_get_groups_count(sb);
	trace_scext4_request_inode(dir, mode);
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ei = SCEXT4_I(inode);

	/*
	 * Initialize owners and quota early so that we don't have to account
	 * for quota initialization worst case in standard inode creating
	 * transaction
	 */
	if (owner) {
		inode->i_mode = mode;
		i_uid_write(inode, owner[0]);
		i_gid_write(inode, owner[1]);
	} else if (test_opt(sb, GRPID)) {
		inode->i_mode = mode;
		inode->i_uid = current_fsuid();
		inode->i_gid = dir->i_gid;
	} else
		inode_init_owner(inode, dir, mode);

	if (scext4_has_feature_project(sb) &&
	    scext4_test_inode_flag(dir, SCEXT4_INODE_PROJINHERIT))
		ei->i_projid = SCEXT4_I(dir)->i_projid;
	else
		ei->i_projid = make_kprojid(&init_user_ns, SCEXT4_DEF_PROJID);

	err = dquot_initialize(inode);
	if (err)
		goto out;

	if (!goal)
		goal = sbi->s_inode_goal;

	if (goal && goal <= le32_to_cpu(sbi->s_es->s_inodes_count)) {
		group = (goal - 1) / SCEXT4_INODES_PER_GROUP(sb);
		ino = (goal - 1) % SCEXT4_INODES_PER_GROUP(sb);
		ret2 = 0;
		goto got_group;
	}

	if (S_ISDIR(mode))
		ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
	else
		ret2 = find_group_other(sb, dir, &group, mode);

got_group:
	SCEXT4_I(dir)->i_last_alloc_group = group;
	err = -ENOSPC;
	if (ret2 == -1)
		goto out;

	/*
	 * Normally we will only go through one pass of this loop,
	 * unless we get unlucky and it turns out the group we selected
	 * had its last inode grabbed by someone else.
	 */
	for (i = 0; i < ngroups; i++, ino = 0) {
		err = -EIO;

		gdp = scext4_get_group_desc(sb, group, &group_desc_bh);
		if (!gdp)
			goto out;

		/*
		 * Check free inodes count before loading bitmap.
		 */
		if (scext4_free_inodes_count(sb, gdp) == 0)
			goto next_group;

		grp = scext4_get_group_info(sb, group);
		/* Skip groups with already-known suspicious inode tables */
		if (SCEXT4_MB_GRP_IBITMAP_CORRUPT(grp))
			goto next_group;

		brelse(inode_bitmap_bh);
		inode_bitmap_bh = scext4_read_inode_bitmap(sb, group);
		/* Skip groups with suspicious inode tables */
		if (SCEXT4_MB_GRP_IBITMAP_CORRUPT(grp) ||
		    IS_ERR(inode_bitmap_bh)) {
			inode_bitmap_bh = NULL;
			goto next_group;
		}

repeat_in_this_group:
		ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
		if (!ret2)
			goto next_group;

		if (group == 0 && (ino + 1) < SCEXT4_FIRST_INO(sb)) {
			scext4_error(sb, "reserved inode found cleared - "
				   "inode=%lu", ino + 1);
			scext4_mark_group_bitmap_corrupted(sb, group,
					SCEXT4_GROUP_INFO_IBITMAP_CORRUPT);
			goto next_group;
		}

		if (!handle) {
			BUG_ON(nblocks <= 0);
			handle = __scext4_journal_start_sb(dir->i_sb, line_no,
							 handle_type, nblocks,
							 0);
			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				scext4_std_error(sb, err);
				goto out;
			}
		}
		BUFFER_TRACE(inode_bitmap_bh, "get_write_access");
		err = scext4_journal_get_write_access(handle, inode_bitmap_bh);
		if (err) {
			scext4_std_error(sb, err);
			goto out;
		}
		scext4_lock_group(sb, group);
		ret2 = scext4_test_and_set_bit(ino, inode_bitmap_bh->b_data);
		if (ret2) {
			/* Someone already took the bit. Repeat the search
			 * with lock held.
			 */
			ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
			if (ret2) {
				scext4_set_bit(ino, inode_bitmap_bh->b_data);
				ret2 = 0;
			} else {
				ret2 = 1; /* we didn't grab the inode */
			}
		}
		scext4_unlock_group(sb, group);
		ino++;		/* the inode bitmap is zero-based */
		if (!ret2)
			goto got; /* we grabbed the inode! */

		if (ino < SCEXT4_INODES_PER_GROUP(sb))
			goto repeat_in_this_group;
next_group:
		if (++group == ngroups)
			group = 0;
	}
	err = -ENOSPC;
	goto out;

got:
	BUFFER_TRACE(inode_bitmap_bh, "call scext4_handle_dirty_metadata");
	err = scext4_handle_dirty_metadata(handle, NULL, inode_bitmap_bh);
	if (err) {
		scext4_std_error(sb, err);
		goto out;
	}

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	err = scext4_journal_get_write_access(handle, group_desc_bh);
	if (err) {
		scext4_std_error(sb, err);
		goto out;
	}

	/* We may have to initialize the block bitmap if it isn't already */
	if (scext4_has_group_desc_csum(sb) &&
	    gdp->bg_flags & cpu_to_le16(SCEXT4_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		block_bitmap_bh = scext4_read_block_bitmap(sb, group);
		if (IS_ERR(block_bitmap_bh)) {
			err = PTR_ERR(block_bitmap_bh);
			goto out;
		}
		BUFFER_TRACE(block_bitmap_bh, "get block bitmap access");
		err = scext4_journal_get_write_access(handle, block_bitmap_bh);
		if (err) {
			brelse(block_bitmap_bh);
			scext4_std_error(sb, err);
			goto out;
		}

		BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
		err = scext4_handle_dirty_metadata(handle, NULL, block_bitmap_bh);

		/* recheck and clear flag under lock if we still need to */
		scext4_lock_group(sb, group);
		if (scext4_has_group_desc_csum(sb) &&
		    (gdp->bg_flags & cpu_to_le16(SCEXT4_BG_BLOCK_UNINIT))) {
			gdp->bg_flags &= cpu_to_le16(~SCEXT4_BG_BLOCK_UNINIT);
			scext4_free_group_clusters_set(sb, gdp,
				scext4_free_clusters_after_init(sb, group, gdp));
			scext4_block_bitmap_csum_set(sb, group, gdp,
						   block_bitmap_bh);
			scext4_group_desc_csum_set(sb, group, gdp);
		}
		scext4_unlock_group(sb, group);
		brelse(block_bitmap_bh);

		if (err) {
			scext4_std_error(sb, err);
			goto out;
		}
	}

	/* Update the relevant bg descriptor fields */
	if (scext4_has_group_desc_csum(sb)) {
		int free;
		struct scext4_group_info *grp = scext4_get_group_info(sb, group);

		down_read(&grp->alloc_sem); /* protect vs itable lazyinit */
		scext4_lock_group(sb, group); /* while we modify the bg desc */
		free = SCEXT4_INODES_PER_GROUP(sb) -
			scext4_itable_unused_count(sb, gdp);
		if (gdp->bg_flags & cpu_to_le16(SCEXT4_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~SCEXT4_BG_INODE_UNINIT);
			free = 0;
		}
		/*
		 * Check the relative inode number against the last used
		 * relative inode number in this group. if it is greater
		 * we need to update the bg_itable_unused count
		 */
		if (ino > free)
			scext4_itable_unused_set(sb, gdp,
					(SCEXT4_INODES_PER_GROUP(sb) - ino));
		up_read(&grp->alloc_sem);
	} else {
		scext4_lock_group(sb, group);
	}

	scext4_free_inodes_set(sb, gdp, scext4_free_inodes_count(sb, gdp) - 1);
	if (S_ISDIR(mode)) {
		scext4_used_dirs_set(sb, gdp, scext4_used_dirs_count(sb, gdp) + 1);
		if (sbi->s_log_groups_per_flex) {
			scext4_group_t f = scext4_flex_group(sbi, group);

			atomic_inc(&sbi_array_rcu_deref(sbi, s_flex_groups,
							f)->used_dirs);
		}
	}
	if (scext4_has_group_desc_csum(sb)) {
		scext4_inode_bitmap_csum_set(sb, group, gdp, inode_bitmap_bh,
					   SCEXT4_INODES_PER_GROUP(sb) / 8);
		scext4_group_desc_csum_set(sb, group, gdp);
	}
	scext4_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh, "call scext4_handle_dirty_metadata");
	err = scext4_handle_dirty_metadata(handle, NULL, group_desc_bh);
	if (err) {
		scext4_std_error(sb, err);
		goto out;
	}

	percpu_counter_dec(&sbi->s_freeinodes_counter);
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);

	if (sbi->s_log_groups_per_flex) {
		flex_group = scext4_flex_group(sbi, group);
		atomic_dec(&sbi_array_rcu_deref(sbi, s_flex_groups,
						flex_group)->free_inodes);
	}

	inode->i_ino = ino + group * SCEXT4_INODES_PER_GROUP(sb);
	/* This is the optimal IO size (for stat), not the fs block size */
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	ei->i_crtime = inode->i_mtime;

	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	/* Don't inherit extent flag from directory, amongst others. */
	ei->i_flags =
		scext4_mask_flags(mode, SCEXT4_I(dir)->i_flags & SCEXT4_FL_INHERITED);
	ei->i_flags |= i_flags;
	ei->i_file_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_group = group;
	ei->i_last_alloc_group = ~0;

	scext4_set_inode_flags(inode);
	if (IS_DIRSYNC(inode))
		scext4_handle_sync(handle);
	if (insert_inode_locked(inode) < 0) {
		/*
		 * Likely a bitmap corruption causing inode to be allocated
		 * twice.
		 */
		err = -EIO;
		scext4_error(sb, "failed to insert inode %lu: doubly allocated?",
			   inode->i_ino);
		scext4_mark_group_bitmap_corrupted(sb, group,
					SCEXT4_GROUP_INFO_IBITMAP_CORRUPT);
		goto out;
	}
	inode->i_generation = prandom_u32();

	/* Precompute checksum seed for inode metadata */
	if (scext4_has_metadata_csum(sb)) {
		__u32 csum;
		__le32 inum = cpu_to_le32(inode->i_ino);
		__le32 gen = cpu_to_le32(inode->i_generation);
		csum = scext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum,
				   sizeof(inum));
		ei->i_csum_seed = scext4_chksum(sbi, csum, (__u8 *)&gen,
					      sizeof(gen));
	}

	scext4_clear_state_flags(ei); /* Only relevant on 32-bit archs */
	scext4_set_inode_state(inode, SCEXT4_STATE_NEW);

	ei->i_extra_isize = sbi->s_want_extra_isize;
	ei->i_inline_off = 0;
	if (scext4_has_feature_inline_data(sb))
		scext4_set_inode_state(inode, SCEXT4_STATE_MAY_INLINE_DATA);
	ret = inode;
	err = dquot_alloc_inode(inode);
	if (err)
		goto fail_drop;

	/*
	 * Since the encryption xattr will always be unique, create it first so
	 * that it's less likely to end up in an external xattr block and
	 * prevent its deduplication.
	 */
	if (encrypt) {
		err = fscrypt_inherit_context(dir, inode, handle, true);
		if (err)
			goto fail_free_drop;
	}

	if (!(ei->i_flags & SCEXT4_EA_INODE_FL)) {
		err = scext4_init_acl(handle, inode, dir);
		if (err)
			goto fail_free_drop;

		err = scext4_init_security(handle, inode, dir, qstr);
		if (err)
			goto fail_free_drop;
	}

	if (scext4_has_feature_extents(sb)) {
		/* set extent flag only for directory, file and normal symlink*/
		if (S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode)) {
			scext4_set_inode_flag(inode, SCEXT4_INODE_EXTENTS);
			scext4_ext_tree_init(handle, inode);
		}
	}

	if (scext4_handle_valid(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		ei->i_datasync_tid = handle->h_transaction->t_tid;
	}

	err = scext4_mark_inode_dirty(handle, inode);
	if (err) {
		scext4_std_error(sb, err);
		goto fail_free_drop;
	}

	scext4_debug("allocating inode %lu\n", inode->i_ino);
	trace_scext4_allocate_inode(inode, dir, mode);
	brelse(inode_bitmap_bh);
	return ret;

fail_free_drop:
	dquot_free_inode(inode);
fail_drop:
	clear_nlink(inode);
	unlock_new_inode(inode);
out:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	brelse(inode_bitmap_bh);
	return ERR_PTR(err);
}

/* Verify that we are loading a valid orphan from disk */
struct inode *scext4_orphan_get(struct super_block *sb, unsigned long ino)
{
	unsigned long max_ino = le32_to_cpu(SCEXT4_SB(sb)->s_es->s_inodes_count);
	scext4_group_t block_group;
	int bit;
	struct buffer_head *bitmap_bh = NULL;
	struct inode *inode = NULL;
	int err = -EFSCORRUPTED;

	if (ino < SCEXT4_FIRST_INO(sb) || ino > max_ino)
		goto bad_orphan;

	block_group = (ino - 1) / SCEXT4_INODES_PER_GROUP(sb);
	bit = (ino - 1) % SCEXT4_INODES_PER_GROUP(sb);
	bitmap_bh = scext4_read_inode_bitmap(sb, block_group);
	if (IS_ERR(bitmap_bh))
		return ERR_CAST(bitmap_bh);

	/* Having the inode bit set should be a 100% indicator that this
	 * is a valid orphan (no e2fsck run on fs).  Orphans also include
	 * inodes that were being truncated, so we can't check i_nlink==0.
	 */
	if (!scext4_test_bit(bit, bitmap_bh->b_data))
		goto bad_orphan;

	inode = scext4_iget(sb, ino, SCEXT4_IGET_NORMAL);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		scext4_error(sb, "couldn't read orphan inode %lu (err %d)",
			   ino, err);
		return inode;
	}

	/*
	 * If the orphans has i_nlinks > 0 then it should be able to
	 * be truncated, otherwise it won't be removed from the orphan
	 * list during processing and an infinite loop will result.
	 * Similarly, it must not be a bad inode.
	 */
	if ((inode->i_nlink && !scext4_can_truncate(inode)) ||
	    is_bad_inode(inode))
		goto bad_orphan;

	if (NEXT_ORPHAN(inode) > max_ino)
		goto bad_orphan;
	brelse(bitmap_bh);
	return inode;

bad_orphan:
	scext4_error(sb, "bad orphan inode %lu", ino);
	if (bitmap_bh)
		printk(KERN_ERR "scext4_test_bit(bit=%d, block=%llu) = %d\n",
		       bit, (unsigned long long)bitmap_bh->b_blocknr,
		       scext4_test_bit(bit, bitmap_bh->b_data));
	if (inode) {
		printk(KERN_ERR "is_bad_inode(inode)=%d\n",
		       is_bad_inode(inode));
		printk(KERN_ERR "NEXT_ORPHAN(inode)=%u\n",
		       NEXT_ORPHAN(inode));
		printk(KERN_ERR "max_ino=%lu\n", max_ino);
		printk(KERN_ERR "i_nlink=%u\n", inode->i_nlink);
		/* Avoid freeing blocks if we got a bad deleted inode */
		if (inode->i_nlink == 0)
			inode->i_blocks = 0;
		iput(inode);
	}
	brelse(bitmap_bh);
	return ERR_PTR(err);
}

unsigned long scext4_count_free_inodes(struct super_block *sb)
{
	unsigned long desc_count;
	struct scext4_group_desc *gdp;
	scext4_group_t i, ngroups = scext4_get_groups_count(sb);
#ifdef SCEXT4FS_DEBUG
	struct scext4_super_block *es;
	unsigned long bitmap_count, x;
	struct buffer_head *bitmap_bh = NULL;

	es = SCEXT4_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;
	for (i = 0; i < ngroups; i++) {
		gdp = scext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += scext4_free_inodes_count(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = scext4_read_inode_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = scext4_count_free(bitmap_bh->b_data,
				    SCEXT4_INODES_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %lu: stored = %d, counted = %lu\n",
			(unsigned long) i, scext4_free_inodes_count(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "scext4_count_free_inodes: "
	       "stored = %u, computed = %lu, %lu\n",
	       le32_to_cpu(es->s_free_inodes_count), desc_count, bitmap_count);
	return desc_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = scext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += scext4_free_inodes_count(sb, gdp);
		cond_resched();
	}
	return desc_count;
#endif
}

/* Called at mount-time, super-block is locked */
unsigned long scext4_count_dirs(struct super_block * sb)
{
	unsigned long count = 0;
	scext4_group_t i, ngroups = scext4_get_groups_count(sb);

	for (i = 0; i < ngroups; i++) {
		struct scext4_group_desc *gdp = scext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		count += scext4_used_dirs_count(sb, gdp);
	}
	return count;
}

/*
 * Zeroes not yet zeroed inode table - just write zeroes through the whole
 * inode table. Must be called without any spinlock held. The only place
 * where it is called from on active part of filesystem is scext4lazyinit
 * thread, so we do not need any special locks, however we have to prevent
 * inode allocation from the current group, so we take alloc_sem lock, to
 * block scext4_new_inode() until we are finished.
 */
int scext4_init_inode_table(struct super_block *sb, scext4_group_t group,
				 int barrier)
{
	struct scext4_group_info *grp = scext4_get_group_info(sb, group);
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	struct scext4_group_desc *gdp = NULL;
	struct buffer_head *group_desc_bh;
	handle_t *handle;
	scext4_fsblk_t blk;
	int num, ret = 0, used_blks = 0;

	/* This should not happen, but just to be sure check this */
	if (sb_rdonly(sb)) {
		ret = 1;
		goto out;
	}

	gdp = scext4_get_group_desc(sb, group, &group_desc_bh);
	if (!gdp)
		goto out;

	/*
	 * We do not need to lock this, because we are the only one
	 * handling this flag.
	 */
	if (gdp->bg_flags & cpu_to_le16(SCEXT4_BG_INODE_ZEROED))
		goto out;

	handle = scext4_journal_start_sb(sb, SCEXT4_HT_MISC, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out;
	}

	down_write(&grp->alloc_sem);
	/*
	 * If inode bitmap was already initialized there may be some
	 * used inodes so we need to skip blocks with used inodes in
	 * inode table.
	 */
	if (!(gdp->bg_flags & cpu_to_le16(SCEXT4_BG_INODE_UNINIT)))
		used_blks = DIV_ROUND_UP((SCEXT4_INODES_PER_GROUP(sb) -
			    scext4_itable_unused_count(sb, gdp)),
			    sbi->s_inodes_per_block);

	if ((used_blks < 0) || (used_blks > sbi->s_itb_per_group) ||
	    ((group == 0) && ((SCEXT4_INODES_PER_GROUP(sb) -
			       scext4_itable_unused_count(sb, gdp)) <
			      SCEXT4_FIRST_INO(sb)))) {
		scext4_error(sb, "Something is wrong with group %u: "
			   "used itable blocks: %d; "
			   "itable unused count: %u",
			   group, used_blks,
			   scext4_itable_unused_count(sb, gdp));
		ret = 1;
		goto err_out;
	}

	blk = scext4_inode_table(sb, gdp) + used_blks;
	num = sbi->s_itb_per_group - used_blks;

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	ret = scext4_journal_get_write_access(handle,
					    group_desc_bh);
	if (ret)
		goto err_out;

	/*
	 * Skip zeroout if the inode table is full. But we set the ZEROED
	 * flag anyway, because obviously, when it is full it does not need
	 * further zeroing.
	 */
	if (unlikely(num == 0))
		goto skip_zeroout;

	scext4_debug("going to zero out inode table in group %d\n",
		   group);
	ret = sb_issue_zeroout(sb, blk, num, GFP_NOFS);
	if (ret < 0)
		goto err_out;
	if (barrier)
		blkdev_issue_flush(sb->s_bdev, GFP_NOFS, NULL);

skip_zeroout:
	scext4_lock_group(sb, group);
	gdp->bg_flags |= cpu_to_le16(SCEXT4_BG_INODE_ZEROED);
	scext4_group_desc_csum_set(sb, group, gdp);
	scext4_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh,
		     "call scext4_handle_dirty_metadata");
	ret = scext4_handle_dirty_metadata(handle, NULL,
					 group_desc_bh);

err_out:
	up_write(&grp->alloc_sem);
	scext4_journal_stop(handle);
out:
	return ret;
}
