// SPDX-License-Identifier: GPL-2.0
/*
 *  fs/scext4/extents_status.h
 *
 * Written by Yongqiang Yang <xiaoqiangnk@gmail.com>
 * Modified by
 *	Allison Henderson <achender@linux.vnet.ibm.com>
 *	Zheng Liu <wenqing.lz@taobao.com>
 *
 */

#ifndef _SCEXT4_EXTENTS_STATUS_H
#define _SCEXT4_EXTENTS_STATUS_H

/*
 * Turn on ES_DEBUG__ to get lots of info about extent status operations.
 */
#ifdef ES_DEBUG__
#define es_debug(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#else
#define es_debug(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

/*
 * With ES_AGGRESSIVE_TEST defined, the result of es caching will be
 * checked with old map_block's result.
 */
#define ES_AGGRESSIVE_TEST__

/*
 * These flags live in the high bits of extent_status.es_pblk
 */
enum {
	ES_WRITTEN_B,
	ES_UNWRITTEN_B,
	ES_DELAYED_B,
	ES_HOLE_B,
	ES_REFERENCED_B,
	ES_FLAGS
};

#define ES_SHIFT (sizeof(scext4_fsblk_t)*8 - ES_FLAGS)
#define ES_MASK (~((scext4_fsblk_t)0) << ES_SHIFT)

#define EXTENT_STATUS_WRITTEN	(1 << ES_WRITTEN_B)
#define EXTENT_STATUS_UNWRITTEN (1 << ES_UNWRITTEN_B)
#define EXTENT_STATUS_DELAYED	(1 << ES_DELAYED_B)
#define EXTENT_STATUS_HOLE	(1 << ES_HOLE_B)
#define EXTENT_STATUS_REFERENCED	(1 << ES_REFERENCED_B)

#define ES_TYPE_MASK	((scext4_fsblk_t)(EXTENT_STATUS_WRITTEN | \
			  EXTENT_STATUS_UNWRITTEN | \
			  EXTENT_STATUS_DELAYED | \
			  EXTENT_STATUS_HOLE) << ES_SHIFT)

struct scext4_sb_info;
struct scext4_extent;

struct extent_status {
	struct rb_node rb_node;
	scext4_lblk_t es_lblk;	/* first logical block extent covers */
	scext4_lblk_t es_len;	/* length of extent in block */
	scext4_fsblk_t es_pblk;	/* first physical block */
};

struct scext4_es_tree {
	struct rb_root root;
	struct extent_status *cache_es;	/* recently accessed extent */
};

struct scext4_es_stats {
	unsigned long es_stats_shrunk;
	struct percpu_counter es_stats_cache_hits;
	struct percpu_counter es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

/*
 * Pending cluster reservations for bigalloc file systems
 *
 * A cluster with a pending reservation is a logical cluster shared by at
 * least one extent in the extents status tree with delayed and unwritten
 * status and at least one other written or unwritten extent.  The
 * reservation is said to be pending because a cluster reservation would
 * have to be taken in the event all blocks in the cluster shared with
 * written or unwritten extents were deleted while the delayed and
 * unwritten blocks remained.
 *
 * The set of pending cluster reservations is an auxiliary data structure
 * used with the extents status tree to implement reserved cluster/block
 * accounting for bigalloc file systems.  The set is kept in memory and
 * records all pending cluster reservations.
 *
 * Its primary function is to avoid the need to read extents from the
 * disk when invalidating pages as a result of a truncate, punch hole, or
 * collapse range operation.  Page invalidation requires a decrease in the
 * reserved cluster count if it results in the removal of all delayed
 * and unwritten extents (blocks) from a cluster that is not shared with a
 * written or unwritten extent, and no decrease otherwise.  Determining
 * whether the cluster is shared can be done by searching for a pending
 * reservation on it.
 *
 * Secondarily, it provides a potentially faster method for determining
 * whether the reserved cluster count should be increased when a physical
 * cluster is deallocated as a result of a truncate, punch hole, or
 * collapse range operation.  The necessary information is also present
 * in the extents status tree, but might be more rapidly accessed in
 * the pending reservation set in many cases due to smaller size.
 *
 * The pending cluster reservation set is implemented as a red-black tree
 * with the goal of minimizing per page search time overhead.
 */

struct pending_reservation {
	struct rb_node rb_node;
	scext4_lblk_t lclu;
};

struct scext4_pending_tree {
	struct rb_root root;
};

extern int __init scext4_init_es(void);
extern void scext4_exit_es(void);
extern void scext4_es_init_tree(struct scext4_es_tree *tree);

extern int scext4_es_insert_extent(struct inode *inode, scext4_lblk_t lblk,
				 scext4_lblk_t len, scext4_fsblk_t pblk,
				 unsigned int status);
extern void scext4_es_cache_extent(struct inode *inode, scext4_lblk_t lblk,
				 scext4_lblk_t len, scext4_fsblk_t pblk,
				 unsigned int status);
extern int scext4_es_remove_extent(struct inode *inode, scext4_lblk_t lblk,
				 scext4_lblk_t len);
extern void scext4_es_find_extent_range(struct inode *inode,
				      int (*match_fn)(struct extent_status *es),
				      scext4_lblk_t lblk, scext4_lblk_t end,
				      struct extent_status *es);
extern int scext4_es_lookup_extent(struct inode *inode, scext4_lblk_t lblk,
				 scext4_lblk_t *next_lblk,
				 struct extent_status *es);
extern bool scext4_es_scan_range(struct inode *inode,
			       int (*matching_fn)(struct extent_status *es),
			       scext4_lblk_t lblk, scext4_lblk_t end);
extern bool scext4_es_scan_clu(struct inode *inode,
			     int (*matching_fn)(struct extent_status *es),
			     scext4_lblk_t lblk);

static inline unsigned int scext4_es_status(struct extent_status *es)
{
	return es->es_pblk >> ES_SHIFT;
}

static inline unsigned int scext4_es_type(struct extent_status *es)
{
	return (es->es_pblk & ES_TYPE_MASK) >> ES_SHIFT;
}

static inline int scext4_es_is_written(struct extent_status *es)
{
	return (scext4_es_type(es) & EXTENT_STATUS_WRITTEN) != 0;
}

static inline int scext4_es_is_unwritten(struct extent_status *es)
{
	return (scext4_es_type(es) & EXTENT_STATUS_UNWRITTEN) != 0;
}

static inline int scext4_es_is_delayed(struct extent_status *es)
{
	return (scext4_es_type(es) & EXTENT_STATUS_DELAYED) != 0;
}

static inline int scext4_es_is_hole(struct extent_status *es)
{
	return (scext4_es_type(es) & EXTENT_STATUS_HOLE) != 0;
}

static inline int scext4_es_is_mapped(struct extent_status *es)
{
	return (scext4_es_is_written(es) || scext4_es_is_unwritten(es));
}

static inline int scext4_es_is_delonly(struct extent_status *es)
{
	return (scext4_es_is_delayed(es) && !scext4_es_is_unwritten(es));
}

static inline void scext4_es_set_referenced(struct extent_status *es)
{
	es->es_pblk |= ((scext4_fsblk_t)EXTENT_STATUS_REFERENCED) << ES_SHIFT;
}

static inline void scext4_es_clear_referenced(struct extent_status *es)
{
	es->es_pblk &= ~(((scext4_fsblk_t)EXTENT_STATUS_REFERENCED) << ES_SHIFT);
}

static inline int scext4_es_is_referenced(struct extent_status *es)
{
	return (scext4_es_status(es) & EXTENT_STATUS_REFERENCED) != 0;
}

static inline scext4_fsblk_t scext4_es_pblock(struct extent_status *es)
{
	return es->es_pblk & ~ES_MASK;
}

static inline void scext4_es_store_pblock(struct extent_status *es,
					scext4_fsblk_t pb)
{
	scext4_fsblk_t block;

	block = (pb & ~ES_MASK) | (es->es_pblk & ES_MASK);
	es->es_pblk = block;
}

static inline void scext4_es_store_status(struct extent_status *es,
					unsigned int status)
{
	es->es_pblk = (((scext4_fsblk_t)status << ES_SHIFT) & ES_MASK) |
		      (es->es_pblk & ~ES_MASK);
}

static inline void scext4_es_store_pblock_status(struct extent_status *es,
					       scext4_fsblk_t pb,
					       unsigned int status)
{
	es->es_pblk = (((scext4_fsblk_t)status << ES_SHIFT) & ES_MASK) |
		      (pb & ~ES_MASK);
}

extern int scext4_es_register_shrinker(struct scext4_sb_info *sbi);
extern void scext4_es_unregister_shrinker(struct scext4_sb_info *sbi);

extern int scext4_seq_es_shrinker_info_show(struct seq_file *seq, void *v);

extern int __init scext4_init_pending(void);
extern void scext4_exit_pending(void);
extern void scext4_init_pending_tree(struct scext4_pending_tree *tree);
extern void scext4_remove_pending(struct inode *inode, scext4_lblk_t lblk);
extern bool scext4_is_pending(struct inode *inode, scext4_lblk_t lblk);
extern int scext4_es_insert_delayed_block(struct inode *inode, scext4_lblk_t lblk,
					bool allocated);
extern unsigned int scext4_es_delayed_clu(struct inode *inode, scext4_lblk_t lblk,
					scext4_lblk_t len);
extern void scext4_clear_inode_es(struct inode *inode);

#endif /* _SCEXT4_EXTENTS_STATUS_H */
