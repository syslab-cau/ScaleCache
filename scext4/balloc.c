// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/scext4/balloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  Enhanced block allocation by Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include "scext4.h"
#include "scext4_jbd3.h"
#include "mballoc.h"

#include <trace/events/scext4.h>

static unsigned scext4_num_base_meta_clusters(struct super_block *sb,
					    scext4_group_t block_group);
/*
 * balloc.c contains the blocks allocation and deallocation routines
 */

/*
 * Calculate block group number for a given block number
 */
scext4_group_t scext4_get_group_number(struct super_block *sb,
				   scext4_fsblk_t block)
{
	scext4_group_t group;

	if (test_opt2(sb, STD_GROUP_SIZE))
		group = (block -
			 le32_to_cpu(SCEXT4_SB(sb)->s_es->s_first_data_block)) >>
			(SCEXT4_BLOCK_SIZE_BITS(sb) + SCEXT4_CLUSTER_BITS(sb) + 3);
	else
		scext4_get_group_no_and_offset(sb, block, &group, NULL);
	return group;
}

/*
 * Calculate the block group number and offset into the block/cluster
 * allocation bitmap, given a block number
 */
void scext4_get_group_no_and_offset(struct super_block *sb, scext4_fsblk_t blocknr,
		scext4_group_t *blockgrpp, scext4_grpblk_t *offsetp)
{
	struct scext4_super_block *es = SCEXT4_SB(sb)->s_es;
	scext4_grpblk_t offset;

	blocknr = blocknr - le32_to_cpu(es->s_first_data_block);
	offset = do_div(blocknr, SCEXT4_BLOCKS_PER_GROUP(sb)) >>
		SCEXT4_SB(sb)->s_cluster_bits;
	if (offsetp)
		*offsetp = offset;
	if (blockgrpp)
		*blockgrpp = blocknr;

}

/*
 * Check whether the 'block' lives within the 'block_group'. Returns 1 if so
 * and 0 otherwise.
 */
static inline int scext4_block_in_group(struct super_block *sb,
				      scext4_fsblk_t block,
				      scext4_group_t block_group)
{
	scext4_group_t actual_group;

	actual_group = scext4_get_group_number(sb, block);
	return (actual_group == block_group) ? 1 : 0;
}

/* Return the number of clusters used for file system metadata; this
 * represents the overhead needed by the file system.
 */
static unsigned scext4_num_overhead_clusters(struct super_block *sb,
					   scext4_group_t block_group,
					   struct scext4_group_desc *gdp)
{
	unsigned num_clusters;
	int block_cluster = -1, inode_cluster = -1, itbl_cluster = -1, i, c;
	scext4_fsblk_t start = scext4_group_first_block_no(sb, block_group);
	scext4_fsblk_t itbl_blk;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);

	/* This is the number of clusters used by the superblock,
	 * block group descriptors, and reserved block group
	 * descriptor blocks */
	num_clusters = scext4_num_base_meta_clusters(sb, block_group);

	/*
	 * For the allocation bitmaps and inode table, we first need
	 * to check to see if the block is in the block group.  If it
	 * is, then check to see if the cluster is already accounted
	 * for in the clusters used for the base metadata cluster, or
	 * if we can increment the base metadata cluster to include
	 * that block.  Otherwise, we will have to track the cluster
	 * used for the allocation bitmap or inode table explicitly.
	 * Normally all of these blocks are contiguous, so the special
	 * case handling shouldn't be necessary except for *very*
	 * unusual file system layouts.
	 */
	if (scext4_block_in_group(sb, scext4_block_bitmap(sb, gdp), block_group)) {
		block_cluster = SCEXT4_B2C(sbi,
					 scext4_block_bitmap(sb, gdp) - start);
		if (block_cluster < num_clusters)
			block_cluster = -1;
		else if (block_cluster == num_clusters) {
			num_clusters++;
			block_cluster = -1;
		}
	}

	if (scext4_block_in_group(sb, scext4_inode_bitmap(sb, gdp), block_group)) {
		inode_cluster = SCEXT4_B2C(sbi,
					 scext4_inode_bitmap(sb, gdp) - start);
		if (inode_cluster < num_clusters)
			inode_cluster = -1;
		else if (inode_cluster == num_clusters) {
			num_clusters++;
			inode_cluster = -1;
		}
	}

	itbl_blk = scext4_inode_table(sb, gdp);
	for (i = 0; i < sbi->s_itb_per_group; i++) {
		if (scext4_block_in_group(sb, itbl_blk + i, block_group)) {
			c = SCEXT4_B2C(sbi, itbl_blk + i - start);
			if ((c < num_clusters) || (c == inode_cluster) ||
			    (c == block_cluster) || (c == itbl_cluster))
				continue;
			if (c == num_clusters) {
				num_clusters++;
				continue;
			}
			num_clusters++;
			itbl_cluster = c;
		}
	}

	if (block_cluster != -1)
		num_clusters++;
	if (inode_cluster != -1)
		num_clusters++;

	return num_clusters;
}

static unsigned int num_clusters_in_group(struct super_block *sb,
					  scext4_group_t block_group)
{
	unsigned int blocks;

	if (block_group == scext4_get_groups_count(sb) - 1) {
		/*
		 * Even though mke2fs always initializes the first and
		 * last group, just in case some other tool was used,
		 * we need to make sure we calculate the right free
		 * blocks.
		 */
		blocks = scext4_blocks_count(SCEXT4_SB(sb)->s_es) -
			scext4_group_first_block_no(sb, block_group);
	} else
		blocks = SCEXT4_BLOCKS_PER_GROUP(sb);
	return SCEXT4_NUM_B2C(SCEXT4_SB(sb), blocks);
}

/* Initializes an uninitialized block bitmap */
static int scext4_init_block_bitmap(struct super_block *sb,
				   struct buffer_head *bh,
				   scext4_group_t block_group,
				   struct scext4_group_desc *gdp)
{
	unsigned int bit, bit_max;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	scext4_fsblk_t start, tmp;

	J_ASSERT_BH(bh, buffer_locked(bh));

	/* If checksum is bad mark all blocks used to prevent allocation
	 * essentially implementing a per-group read-only flag. */
	if (!scext4_group_desc_csum_verify(sb, block_group, gdp)) {
		scext4_mark_group_bitmap_corrupted(sb, block_group,
					SCEXT4_GROUP_INFO_BBITMAP_CORRUPT |
					SCEXT4_GROUP_INFO_IBITMAP_CORRUPT);
		return -EFSBADCRC;
	}
	memset(bh->b_data, 0, sb->s_blocksize);

	bit_max = scext4_num_base_meta_clusters(sb, block_group);
	if ((bit_max >> 3) >= bh->b_size)
		return -EFSCORRUPTED;

	for (bit = 0; bit < bit_max; bit++)
		scext4_set_bit(bit, bh->b_data);

	start = scext4_group_first_block_no(sb, block_group);

	/* Set bits for block and inode bitmaps, and inode table */
	tmp = scext4_block_bitmap(sb, gdp);
	if (scext4_block_in_group(sb, tmp, block_group))
		scext4_set_bit(SCEXT4_B2C(sbi, tmp - start), bh->b_data);

	tmp = scext4_inode_bitmap(sb, gdp);
	if (scext4_block_in_group(sb, tmp, block_group))
		scext4_set_bit(SCEXT4_B2C(sbi, tmp - start), bh->b_data);

	tmp = scext4_inode_table(sb, gdp);
	for (; tmp < scext4_inode_table(sb, gdp) +
		     sbi->s_itb_per_group; tmp++) {
		if (scext4_block_in_group(sb, tmp, block_group))
			scext4_set_bit(SCEXT4_B2C(sbi, tmp - start), bh->b_data);
	}

	/*
	 * Also if the number of blocks within the group is less than
	 * the blocksize * 8 ( which is the size of bitmap ), set rest
	 * of the block bitmap to 1
	 */
	scext4_mark_bitmap_end(num_clusters_in_group(sb, block_group),
			     sb->s_blocksize * 8, bh->b_data);
	return 0;
}

/* Return the number of free blocks in a block group.  It is used when
 * the block bitmap is uninitialized, so we can't just count the bits
 * in the bitmap. */
unsigned scext4_free_clusters_after_init(struct super_block *sb,
				       scext4_group_t block_group,
				       struct scext4_group_desc *gdp)
{
	return num_clusters_in_group(sb, block_group) - 
		scext4_num_overhead_clusters(sb, block_group, gdp);
}

/*
 * The free blocks are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.  The descriptors are loaded in memory
 * when a file system is mounted (see scext4_fill_super).
 */

/**
 * scext4_get_group_desc() -- load group descriptor from disk
 * @sb:			super block
 * @block_group:	given block group
 * @bh:			pointer to the buffer head to store the block
 *			group descriptor
 */
struct scext4_group_desc * scext4_get_group_desc(struct super_block *sb,
					     scext4_group_t block_group,
					     struct buffer_head **bh)
{
	unsigned int group_desc;
	unsigned int offset;
	scext4_group_t ngroups = scext4_get_groups_count(sb);
	struct scext4_group_desc *desc;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	struct buffer_head *bh_p;

	if (block_group >= ngroups) {
		scext4_error(sb, "block_group >= groups_count - block_group = %u,"
			   " groups_count = %u", block_group, ngroups);

		return NULL;
	}

	group_desc = block_group >> SCEXT4_DESC_PER_BLOCK_BITS(sb);
	offset = block_group & (SCEXT4_DESC_PER_BLOCK(sb) - 1);
	bh_p = sbi_array_rcu_deref(sbi, s_group_desc, group_desc);
	/*
	 * sbi_array_rcu_deref returns with rcu unlocked, this is ok since
	 * the pointer being dereferenced won't be dereferenced again. By
	 * looking at the usage in add_new_gdb() the value isn't modified,
	 * just the pointer, and so it remains valid.
	 */
	if (!bh_p) {
		scext4_error(sb, "Group descriptor not loaded - "
			   "block_group = %u, group_desc = %u, desc = %u",
			   block_group, group_desc, offset);
		return NULL;
	}

	desc = (struct scext4_group_desc *)(
		(__u8 *)bh_p->b_data +
		offset * SCEXT4_DESC_SIZE(sb));
	if (bh)
		*bh = bh_p;
	return desc;
}

/*
 * Return the block number which was discovered to be invalid, or 0 if
 * the block bitmap is valid.
 */
static scext4_fsblk_t scext4_valid_block_bitmap(struct super_block *sb,
					    struct scext4_group_desc *desc,
					    scext4_group_t block_group,
					    struct buffer_head *bh)
{
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	scext4_grpblk_t offset;
	scext4_grpblk_t next_zero_bit;
	scext4_grpblk_t max_bit = SCEXT4_CLUSTERS_PER_GROUP(sb);
	scext4_fsblk_t blk;
	scext4_fsblk_t group_first_block;

	if (scext4_has_feature_flex_bg(sb)) {
		/* with FLEX_BG, the inode/block bitmaps and itable
		 * blocks may not be in the group at all
		 * so the bitmap validation will be skipped for those groups
		 * or it has to also read the block group where the bitmaps
		 * are located to verify they are set.
		 */
		return 0;
	}
	group_first_block = scext4_group_first_block_no(sb, block_group);

	/* check whether block bitmap block number is set */
	blk = scext4_block_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || SCEXT4_B2C(sbi, offset) >= max_bit ||
	    !scext4_test_bit(SCEXT4_B2C(sbi, offset), bh->b_data))
		/* bad block bitmap */
		return blk;

	/* check whether the inode bitmap block number is set */
	blk = scext4_inode_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || SCEXT4_B2C(sbi, offset) >= max_bit ||
	    !scext4_test_bit(SCEXT4_B2C(sbi, offset), bh->b_data))
		/* bad block bitmap */
		return blk;

	/* check whether the inode table block number is set */
	blk = scext4_inode_table(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || SCEXT4_B2C(sbi, offset) >= max_bit ||
	    SCEXT4_B2C(sbi, offset + sbi->s_itb_per_group) >= max_bit)
		return blk;
	next_zero_bit = scext4_find_next_zero_bit(bh->b_data,
			SCEXT4_B2C(sbi, offset + sbi->s_itb_per_group),
			SCEXT4_B2C(sbi, offset));
	if (next_zero_bit <
	    SCEXT4_B2C(sbi, offset + sbi->s_itb_per_group))
		/* bad bitmap for inode tables */
		return blk;
	return 0;
}

static int scext4_validate_block_bitmap(struct super_block *sb,
				      struct scext4_group_desc *desc,
				      scext4_group_t block_group,
				      struct buffer_head *bh)
{
	scext4_fsblk_t	blk;
	struct scext4_group_info *grp = scext4_get_group_info(sb, block_group);

	if (buffer_verified(bh))
		return 0;
	if (SCEXT4_MB_GRP_BBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	scext4_lock_group(sb, block_group);
	if (buffer_verified(bh))
		goto verified;
	if (unlikely(!scext4_block_bitmap_csum_verify(sb, block_group,
			desc, bh))) {
		scext4_unlock_group(sb, block_group);
		scext4_error(sb, "bg %u: bad block bitmap checksum", block_group);
		scext4_mark_group_bitmap_corrupted(sb, block_group,
					SCEXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EFSBADCRC;
	}
	blk = scext4_valid_block_bitmap(sb, desc, block_group, bh);
	if (unlikely(blk != 0)) {
		scext4_unlock_group(sb, block_group);
		scext4_error(sb, "bg %u: block %llu: invalid block bitmap",
			   block_group, blk);
		scext4_mark_group_bitmap_corrupted(sb, block_group,
					SCEXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EFSCORRUPTED;
	}
	set_buffer_verified(bh);
verified:
	scext4_unlock_group(sb, block_group);
	return 0;
}

/**
 * scext4_read_block_bitmap_nowait()
 * @sb:			super block
 * @block_group:	given block group
 *
 * Read the bitmap for a given block_group,and validate the
 * bits for block/inode/inode tables are set in the bitmaps
 *
 * Return buffer_head on success or NULL in case of failure.
 */
struct buffer_head *
scext4_read_block_bitmap_nowait(struct super_block *sb, scext4_group_t block_group)
{
	struct scext4_group_desc *desc;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	struct buffer_head *bh;
	scext4_fsblk_t bitmap_blk;
	int err;

	desc = scext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);
	bitmap_blk = scext4_block_bitmap(sb, desc);
	if ((bitmap_blk <= le32_to_cpu(sbi->s_es->s_first_data_block)) ||
	    (bitmap_blk >= scext4_blocks_count(sbi->s_es))) {
		scext4_error(sb, "Invalid block bitmap block %llu in "
			   "block_group %u", bitmap_blk, block_group);
		scext4_mark_group_bitmap_corrupted(sb, block_group,
					SCEXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return ERR_PTR(-EFSCORRUPTED);
	}
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		scext4_warning(sb, "Cannot get buffer for block bitmap - "
			     "block_group = %u, block_bitmap = %llu",
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
	    (desc->bg_flags & cpu_to_le16(SCEXT4_BG_BLOCK_UNINIT))) {
		if (block_group == 0) {
			scext4_unlock_group(sb, block_group);
			unlock_buffer(bh);
			scext4_error(sb, "Block bitmap for bg 0 marked "
				   "uninitialized");
			err = -EFSCORRUPTED;
			goto out;
		}
		err = scext4_init_block_bitmap(sb, bh, block_group, desc);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		scext4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		if (err) {
			scext4_error(sb, "Failed to init block bitmap for group "
				   "%u: %d", block_group, err);
			goto out;
		}
		goto verify;
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
	set_buffer_new(bh);
	trace_scext4_read_block_bitmap_load(sb, block_group);
	bh->b_end_io = scext4_end_bitmap_read;
	get_bh(bh);
	submit_bh(REQ_OP_READ, REQ_META | REQ_PRIO, bh);
	return bh;
verify:
	err = scext4_validate_block_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}

/* Returns 0 on success, 1 on error */
int scext4_wait_block_bitmap(struct super_block *sb, scext4_group_t block_group,
			   struct buffer_head *bh)
{
	struct scext4_group_desc *desc;

	if (!buffer_new(bh))
		return 0;
	desc = scext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return -EFSCORRUPTED;
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh)) {
		scext4_error(sb, "Cannot read block bitmap - "
			   "block_group = %u, block_bitmap = %llu",
			   block_group, (unsigned long long) bh->b_blocknr);
		scext4_mark_group_bitmap_corrupted(sb, block_group,
					SCEXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EIO;
	}
	clear_buffer_new(bh);
	/* Panic or remount fs read-only if block bitmap is invalid */
	return scext4_validate_block_bitmap(sb, desc, block_group, bh);
}

struct buffer_head *
scext4_read_block_bitmap(struct super_block *sb, scext4_group_t block_group)
{
	struct buffer_head *bh;
	int err;

	bh = scext4_read_block_bitmap_nowait(sb, block_group);
	if (IS_ERR(bh))
		return bh;
	err = scext4_wait_block_bitmap(sb, block_group, bh);
	if (err) {
		put_bh(bh);
		return ERR_PTR(err);
	}
	return bh;
}

/**
 * scext4_has_free_clusters()
 * @sbi:	in-core super block structure.
 * @nclusters:	number of needed blocks
 * @flags:	flags from scext4_mb_new_blocks()
 *
 * Check if filesystem has nclusters free & available for allocation.
 * On success return 1, return 0 on failure.
 */
static int scext4_has_free_clusters(struct scext4_sb_info *sbi,
				  s64 nclusters, unsigned int flags)
{
	s64 free_clusters, dirty_clusters, rsv, resv_clusters;
	struct percpu_counter *fcc = &sbi->s_freeclusters_counter;
	struct percpu_counter *dcc = &sbi->s_dirtyclusters_counter;

	free_clusters  = percpu_counter_read_positive(fcc);
	dirty_clusters = percpu_counter_read_positive(dcc);
	resv_clusters = atomic64_read(&sbi->s_resv_clusters);

	/*
	 * r_blocks_count should always be multiple of the cluster ratio so
	 * we are safe to do a plane bit shift only.
	 */
	rsv = (scext4_r_blocks_count(sbi->s_es) >> sbi->s_cluster_bits) +
	      resv_clusters;

	if (free_clusters - (nclusters + rsv + dirty_clusters) <
					SCEXT4_FREECLUSTERS_WATERMARK) {
		free_clusters  = percpu_counter_sum_positive(fcc);
		dirty_clusters = percpu_counter_sum_positive(dcc);
	}
	/* Check whether we have space after accounting for current
	 * dirty clusters & root reserved clusters.
	 */
	if (free_clusters >= (rsv + nclusters + dirty_clusters))
		return 1;

	/* Hm, nope.  Are (enough) root reserved clusters available? */
	if (uid_eq(sbi->s_resuid, current_fsuid()) ||
	    (!gid_eq(sbi->s_resgid, GLOBAL_ROOT_GID) && in_group_p(sbi->s_resgid)) ||
	    capable(CAP_SYS_RESOURCE) ||
	    (flags & SCEXT4_MB_USE_ROOT_BLOCKS)) {

		if (free_clusters >= (nclusters + dirty_clusters +
				      resv_clusters))
			return 1;
	}
	/* No free blocks. Let's see if we can dip into reserved pool */
	if (flags & SCEXT4_MB_USE_RESERVED) {
		if (free_clusters >= (nclusters + dirty_clusters))
			return 1;
	}

	return 0;
}

int scext4_claim_free_clusters(struct scext4_sb_info *sbi,
			     s64 nclusters, unsigned int flags)
{
	if (scext4_has_free_clusters(sbi, nclusters, flags)) {
		percpu_counter_add(&sbi->s_dirtyclusters_counter, nclusters);
		return 0;
	} else
		return -ENOSPC;
}

/**
 * scext4_should_retry_alloc() - check if a block allocation should be retried
 * @sb:			superblock
 * @retries:		number of retry attempts made so far
 *
 * scext4_should_retry_alloc() is called when ENOSPC is returned while
 * attempting to allocate blocks.  If there's an indication that a pending
 * journal transaction might free some space and allow another attempt to
 * succeed, this function will wait for the current or committing transaction
 * to complete and then return TRUE.
 */
int scext4_should_retry_alloc(struct super_block *sb, int *retries)
{
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);

	if (!sbi->s_journal)
		return 0;

	if (++(*retries) > 3) {
		percpu_counter_inc(&sbi->s_sra_exceeded_retry_limit);
		return 0;
	}

	/*
	 * if there's no indication that blocks are about to be freed it's
	 * possible we just missed a transaction commit that did so
	 */
	smp_mb();
	if (sbi->s_mb_free_pending == 0)
		return scext4_has_free_clusters(sbi, 1, 0);

	/*
	 * it's possible we've just missed a transaction commit here,
	 * so ignore the returned status
	 */
	jbd_debug(1, "%s: retrying operation after ENOSPC\n", sb->s_id);
	(void) jbd3_journal_force_commit_nested(sbi->s_journal);
	return 1;
}

/*
 * scext4_new_meta_blocks() -- allocate block for meta data (indexing) blocks
 *
 * @handle:             handle to this transaction
 * @inode:              file inode
 * @goal:               given target block(filesystem wide)
 * @count:		pointer to total number of clusters needed
 * @errp:               error code
 *
 * Return 1st allocated block number on success, *count stores total account
 * error stores in errp pointer
 */
scext4_fsblk_t scext4_new_meta_blocks(handle_t *handle, struct inode *inode,
				  scext4_fsblk_t goal, unsigned int flags,
				  unsigned long *count, int *errp)
{
	struct scext4_allocation_request ar;
	scext4_fsblk_t ret;

	memset(&ar, 0, sizeof(ar));
	/* Fill with neighbour allocated blocks */
	ar.inode = inode;
	ar.goal = goal;
	ar.len = count ? *count : 1;
	ar.flags = flags;

	ret = scext4_mb_new_blocks(handle, &ar, errp);
	if (count)
		*count = ar.len;
	/*
	 * Account for the allocated meta blocks.  We will never
	 * fail EDQUOT for metdata, but we do account for it.
	 */
	if (!(*errp) && (flags & SCEXT4_MB_DELALLOC_RESERVED)) {
		dquot_alloc_block_nofail(inode,
				SCEXT4_C2B(SCEXT4_SB(inode->i_sb), ar.len));
	}
	return ret;
}

/**
 * scext4_count_free_clusters() -- count filesystem free clusters
 * @sb:		superblock
 *
 * Adds up the number of free clusters from each block group.
 */
scext4_fsblk_t scext4_count_free_clusters(struct super_block *sb)
{
	scext4_fsblk_t desc_count;
	struct scext4_group_desc *gdp;
	scext4_group_t i;
	scext4_group_t ngroups = scext4_get_groups_count(sb);
	struct scext4_group_info *grp;
#ifdef SCEXT4FS_DEBUG
	struct scext4_super_block *es;
	scext4_fsblk_t bitmap_count;
	unsigned int x;
	struct buffer_head *bitmap_bh = NULL;

	es = SCEXT4_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;

	for (i = 0; i < ngroups; i++) {
		gdp = scext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (SCEXT4_SB(sb)->s_group_info)
			grp = scext4_get_group_info(sb, i);
		if (!grp || !SCEXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += scext4_free_group_clusters(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = scext4_read_block_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = scext4_count_free(bitmap_bh->b_data,
				    SCEXT4_CLUSTERS_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %u: stored = %d, counted = %u\n",
			i, scext4_free_group_clusters(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "scext4_count_free_clusters: stored = %llu"
	       ", computed = %llu, %llu\n",
	       SCEXT4_NUM_B2C(SCEXT4_SB(sb), scext4_free_blocks_count(es)),
	       desc_count, bitmap_count);
	return bitmap_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = scext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (SCEXT4_SB(sb)->s_group_info)
			grp = scext4_get_group_info(sb, i);
		if (!grp || !SCEXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += scext4_free_group_clusters(sb, gdp);
	}

	return desc_count;
#endif
}

static inline int test_root(scext4_group_t a, int b)
{
	while (1) {
		if (a < b)
			return 0;
		if (a == b)
			return 1;
		if ((a % b) != 0)
			return 0;
		a = a / b;
	}
}

/**
 *	scext4_bg_has_super - number of blocks used by the superblock in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the superblock (primary or backup)
 *	in this group.  Currently this will be only 0 or 1.
 */
int scext4_bg_has_super(struct super_block *sb, scext4_group_t group)
{
	struct scext4_super_block *es = SCEXT4_SB(sb)->s_es;

	if (group == 0)
		return 1;
	if (scext4_has_feature_sparse_super2(sb)) {
		if (group == le32_to_cpu(es->s_backup_bgs[0]) ||
		    group == le32_to_cpu(es->s_backup_bgs[1]))
			return 1;
		return 0;
	}
	if ((group <= 1) || !scext4_has_feature_sparse_super(sb))
		return 1;
	if (!(group & 1))
		return 0;
	if (test_root(group, 3) || (test_root(group, 5)) ||
	    test_root(group, 7))
		return 1;

	return 0;
}

static unsigned long scext4_bg_num_gdb_meta(struct super_block *sb,
					scext4_group_t group)
{
	unsigned long metagroup = group / SCEXT4_DESC_PER_BLOCK(sb);
	scext4_group_t first = metagroup * SCEXT4_DESC_PER_BLOCK(sb);
	scext4_group_t last = first + SCEXT4_DESC_PER_BLOCK(sb) - 1;

	if (group == first || group == first + 1 || group == last)
		return 1;
	return 0;
}

static unsigned long scext4_bg_num_gdb_nometa(struct super_block *sb,
					scext4_group_t group)
{
	if (!scext4_bg_has_super(sb, group))
		return 0;

	if (scext4_has_feature_meta_bg(sb))
		return le32_to_cpu(SCEXT4_SB(sb)->s_es->s_first_meta_bg);
	else
		return SCEXT4_SB(sb)->s_gdb_count;
}

/**
 *	scext4_bg_num_gdb - number of blocks used by the group table in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the group descriptor table
 *	(primary or backup) in this group.  In the future there may be a
 *	different number of descriptor blocks in each group.
 */
unsigned long scext4_bg_num_gdb(struct super_block *sb, scext4_group_t group)
{
	unsigned long first_meta_bg =
			le32_to_cpu(SCEXT4_SB(sb)->s_es->s_first_meta_bg);
	unsigned long metagroup = group / SCEXT4_DESC_PER_BLOCK(sb);

	if (!scext4_has_feature_meta_bg(sb) || metagroup < first_meta_bg)
		return scext4_bg_num_gdb_nometa(sb, group);

	return scext4_bg_num_gdb_meta(sb,group);

}

/*
 * This function returns the number of file system metadata clusters at
 * the beginning of a block group, including the reserved gdt blocks.
 */
static unsigned scext4_num_base_meta_clusters(struct super_block *sb,
				     scext4_group_t block_group)
{
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	unsigned num;

	/* Check for superblock and gdt backups in this group */
	num = scext4_bg_has_super(sb, block_group);

	if (!scext4_has_feature_meta_bg(sb) ||
	    block_group < le32_to_cpu(sbi->s_es->s_first_meta_bg) *
			  sbi->s_desc_per_block) {
		if (num) {
			num += scext4_bg_num_gdb(sb, block_group);
			num += le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);
		}
	} else { /* For META_BG_BLOCK_GROUPS */
		num += scext4_bg_num_gdb(sb, block_group);
	}
	return SCEXT4_NUM_B2C(sbi, num);
}
/**
 *	scext4_inode_to_goal_block - return a hint for block allocation
 *	@inode: inode for block allocation
 *
 *	Return the ideal location to start allocating blocks for a
 *	newly created inode.
 */
scext4_fsblk_t scext4_inode_to_goal_block(struct inode *inode)
{
	struct scext4_inode_info *ei = SCEXT4_I(inode);
	scext4_group_t block_group;
	scext4_grpblk_t colour;
	int flex_size = scext4_flex_bg_size(SCEXT4_SB(inode->i_sb));
	scext4_fsblk_t bg_start;
	scext4_fsblk_t last_block;

	block_group = ei->i_block_group;
	if (flex_size >= SCEXT4_FLEX_SIZE_DIR_ALLOC_SCHEME) {
		/*
		 * If there are at least SCEXT4_FLEX_SIZE_DIR_ALLOC_SCHEME
		 * block groups per flexgroup, reserve the first block
		 * group for directories and special files.  Regular
		 * files will start at the second block group.  This
		 * tends to speed up directory access and improves
		 * fsck times.
		 */
		block_group &= ~(flex_size-1);
		if (S_ISREG(inode->i_mode))
			block_group++;
	}
	bg_start = scext4_group_first_block_no(inode->i_sb, block_group);
	last_block = scext4_blocks_count(SCEXT4_SB(inode->i_sb)->s_es) - 1;

	/*
	 * If we are doing delayed allocation, we don't need take
	 * colour into account.
	 */
	if (test_opt(inode->i_sb, DELALLOC))
		return bg_start;

	if (bg_start + SCEXT4_BLOCKS_PER_GROUP(inode->i_sb) <= last_block)
		colour = (current->pid % 16) *
			(SCEXT4_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	else
		colour = (current->pid % 16) * ((last_block - bg_start) / 16);
	return bg_start + colour;
}

