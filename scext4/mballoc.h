// SPDX-License-Identifier: GPL-2.0
/*
 *  fs/scext4/mballoc.h
 *
 *  Written by: Alex Tomas <alex@clusterfs.com>
 *
 */
#ifndef _SCEXT4_MBALLOC_H
#define _SCEXT4_MBALLOC_H

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/proc_fs.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include "scext4_jbd3.h"
#include "scext4.h"

/*
 */
#ifdef CONFIG_SCEXT4_DEBUG
extern ushort scext4_mballoc_debug;

#define mb_debug(n, fmt, ...)	                                        \
do {									\
	if ((n) <= scext4_mballoc_debug) {				\
		printk(KERN_DEBUG "(%s, %d): %s: " fmt,			\
		       __FILE__, __LINE__, __func__, ##__VA_ARGS__);	\
	}								\
} while (0)
#else
#define mb_debug(n, fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

#define SCEXT4_MB_HISTORY_ALLOC		1	/* allocation */
#define SCEXT4_MB_HISTORY_PREALLOC	2	/* preallocated blocks used */

/*
 * How long mballoc can look for a best extent (in found extents)
 */
#define MB_DEFAULT_MAX_TO_SCAN		200

/*
 * How long mballoc must look for a best extent
 */
#define MB_DEFAULT_MIN_TO_SCAN		10

/*
 * with 'scext4_mb_stats' allocator will collect stats that will be
 * shown at umount. The collecting costs though!
 */
#define MB_DEFAULT_STATS		0

/*
 * files smaller than MB_DEFAULT_STREAM_THRESHOLD are served
 * by the stream allocator, which purpose is to pack requests
 * as close each to other as possible to produce smooth I/O traffic
 * We use locality group prealloc space for stream request.
 * We can tune the same via /proc/fs/scext4/<parition>/stream_req
 */
#define MB_DEFAULT_STREAM_THRESHOLD	16	/* 64K */

/*
 * for which requests use 2^N search using buddies
 */
#define MB_DEFAULT_ORDER2_REQS		2

/*
 * default group prealloc size 512 blocks
 */
#define MB_DEFAULT_GROUP_PREALLOC	512


struct scext4_free_data {
	/* this links the free block information from sb_info */
	struct list_head		efd_list;

	/* this links the free block information from group_info */
	struct rb_node			efd_node;

	/* group which free block extent belongs */
	scext4_group_t			efd_group;

	/* free block extent */
	scext4_grpblk_t			efd_start_cluster;
	scext4_grpblk_t			efd_count;

	/* transaction which freed this extent */
	tid_t				efd_tid;
};

struct scext4_prealloc_space {
	struct list_head	pa_inode_list;
	struct list_head	pa_group_list;
	union {
		struct list_head pa_tmp_list;
		struct rcu_head	pa_rcu;
	} u;
	spinlock_t		pa_lock;
	atomic_t		pa_count;
	unsigned		pa_deleted;
	scext4_fsblk_t		pa_pstart;	/* phys. block */
	scext4_lblk_t		pa_lstart;	/* log. block */
	scext4_grpblk_t		pa_len;		/* len of preallocated chunk */
	scext4_grpblk_t		pa_free;	/* how many blocks are free */
	unsigned short		pa_type;	/* pa type. inode or group */
	spinlock_t		*pa_obj_lock;
	struct inode		*pa_inode;	/* hack, for history only */
};

enum {
	MB_INODE_PA = 0,
	MB_GROUP_PA = 1
};

struct scext4_free_extent {
	scext4_lblk_t fe_logical;
	scext4_grpblk_t fe_start;	/* In cluster units */
	scext4_group_t fe_group;
	scext4_grpblk_t fe_len;	/* In cluster units */
};

/*
 * Locality group:
 *   we try to group all related changes together
 *   so that writeback can flush/allocate them together as well
 *   Size of lg_prealloc_list hash is determined by MB_DEFAULT_GROUP_PREALLOC
 *   (512). We store prealloc space into the hash based on the pa_free blocks
 *   order value.ie, fls(pa_free)-1;
 */
#define PREALLOC_TB_SIZE 10
struct scext4_locality_group {
	/* for allocator */
	/* to serialize allocates */
	struct mutex		lg_mutex;
	/* list of preallocations */
	struct list_head	lg_prealloc_list[PREALLOC_TB_SIZE];
	spinlock_t		lg_prealloc_lock;
};

struct scext4_allocation_context {
	struct inode *ac_inode;
	struct super_block *ac_sb;

	/* original request */
	struct scext4_free_extent ac_o_ex;

	/* goal request (normalized ac_o_ex) */
	struct scext4_free_extent ac_g_ex;

	/* the best found extent */
	struct scext4_free_extent ac_b_ex;

	/* copy of the best found extent taken before preallocation efforts */
	struct scext4_free_extent ac_f_ex;

	__u16 ac_groups_scanned;
	__u16 ac_found;
	__u16 ac_tail;
	__u16 ac_buddy;
	__u16 ac_flags;		/* allocation hints */
	__u8 ac_status;
	__u8 ac_criteria;
	__u8 ac_2order;		/* if request is to allocate 2^N blocks and
				 * N > 0, the field stores N, otherwise 0 */
	__u8 ac_op;		/* operation, for history only */
	struct page *ac_bitmap_page;
	struct page *ac_buddy_page;
	struct scext4_prealloc_space *ac_pa;
	struct scext4_locality_group *ac_lg;
};

#define AC_STATUS_CONTINUE	1
#define AC_STATUS_FOUND		2
#define AC_STATUS_BREAK		3

struct scext4_buddy {
	struct page *bd_buddy_page;
	void *bd_buddy;
	struct page *bd_bitmap_page;
	void *bd_bitmap;
	struct scext4_group_info *bd_info;
	struct super_block *bd_sb;
	__u16 bd_blkbits;
	scext4_group_t bd_group;
};

static inline scext4_fsblk_t scext4_grp_offs_to_block(struct super_block *sb,
					struct scext4_free_extent *fex)
{
	return scext4_group_first_block_no(sb, fex->fe_group) +
		(fex->fe_start << SCEXT4_SB(sb)->s_cluster_bits);
}

typedef int (*scext4_mballoc_query_range_fn)(
	struct super_block		*sb,
	scext4_group_t			agno,
	scext4_grpblk_t			start,
	scext4_grpblk_t			len,
	void				*priv);

int
scext4_mballoc_query_range(
	struct super_block		*sb,
	scext4_group_t			agno,
	scext4_grpblk_t			start,
	scext4_grpblk_t			end,
	scext4_mballoc_query_range_fn	formatter,
	void				*priv);

#endif
