// SPDX-License-Identifier: GPL-2.0+
/*
 * XArray implementation
 * Copyright (c) 2017-2018 Microsoft Corporation
 * Copyright (c) 2018-2020 Oracle
 * Author: Matthew Wilcox <willy@infradead.org>
 */

#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "cc_xarray.h"

#include <linux/xarray.h>

/*
 * Coding conventions in this file:
 *
 * @xa is used to refer to the entire xarray.
 * @xas is the 'xarray operation state'.  It may be either a pointer to
 * an xa_state, or an xa_state stored on the stack.  This is an unfortunate
 * ambiguity.
 * @index is the index of the entry being operated on
 * @mark is an cc_xa_mark_t; a small number indicating one of the mark bits.
 * @node refers to an xa_node; usually the primary one being operated on by
 * this function.
 * @offset is the index into the slots array inside an xa_node.
 * @parent refers to the @xa_node closer to the head than @node.
 * @entry refers to something stored in a slot in the xarray
 */

static inline unsigned int xa_lock_type(const struct xarray *xa)
{
	return (__force unsigned int)xa->xa_flags & 3;
}

static inline void cc_xas_lock_type(struct xa_state *xas, unsigned int lock_type)
{
	if (lock_type == CC_XA_LOCK_IRQ)
		cc_xas_lock_irq(xas);
	else if (lock_type == CC_XA_LOCK_BH)
		cc_xas_lock_bh(xas);
	else
		cc_xas_lock(xas);
}

static inline void cc_xas_unlock_type(struct xa_state *xas, unsigned int lock_type)
{
	if (lock_type == CC_XA_LOCK_IRQ)
		cc_xas_unlock_irq(xas);
	else if (lock_type == CC_XA_LOCK_BH)
		cc_xas_unlock_bh(xas);
	else
		cc_xas_unlock(xas);
}

static inline bool cc_xa_track_free(const struct xarray *xa)
{
	return xa->xa_flags & CC_XA_FLAGS_TRACK_FREE;
}

static inline bool cc_xa_zero_busy(const struct xarray *xa)
{
	return xa->xa_flags & CC_XA_FLAGS_ZERO_BUSY;
}

static inline void cc_xa_mark_set(struct xarray *xa, cc_xa_mark_t mark)
{
	if (!(xa->xa_flags & CC_XA_FLAGS_MARK(mark)))
		xa->xa_flags |= CC_XA_FLAGS_MARK(mark);
}

static inline void cc_xa_mark_clear(struct xarray *xa, cc_xa_mark_t mark)
{
	if (xa->xa_flags & CC_XA_FLAGS_MARK(mark))
		xa->xa_flags &= ~(CC_XA_FLAGS_MARK(mark));
}

static inline unsigned long *node_marks(struct xa_node *node, cc_xa_mark_t mark)
{
	return node->marks[(__force unsigned)mark];
}

static inline bool node_get_mark(struct xa_node *node,
		unsigned int offset, cc_xa_mark_t mark)
{
	return test_bit(offset, node_marks(node, mark));
}

/* returns true if the bit was set */
static inline bool node_set_mark(struct xa_node *node, unsigned int offset,
				cc_xa_mark_t mark)
{
	return __test_and_set_bit(offset, node_marks(node, mark));
}

/* returns true if the bit was set */
static inline bool node_clear_mark(struct xa_node *node, unsigned int offset,
				cc_xa_mark_t mark)
{
	return __test_and_clear_bit(offset, node_marks(node, mark));
}

static inline bool node_any_mark(struct xa_node *node, cc_xa_mark_t mark)
{
	return !bitmap_empty(node_marks(node, mark), CC_XA_CHUNK_SIZE);
}

static inline void node_mark_all(struct xa_node *node, cc_xa_mark_t mark)
{
	bitmap_fill(node_marks(node, mark), CC_XA_CHUNK_SIZE);
}

#if 0
static inline bool logical_delete(struct xa_node *node)
{
	return __test_and_set_bit(node->del, 1);
}
#endif 

#define mark_inc(mark) do { \
	mark = (__force cc_xa_mark_t)((__force unsigned)(mark) + 1); \
} while (0)

/*
 * cc_xas_squash_marks() - Merge all marks to the first entry
 * @xas: Array operation state.
 * 
 * Set a mark on the first entry if any entry has it set.  Clear marks on
 * all sibling entries.
 */
static void cc_xas_squash_marks(const struct xa_state *xas)
{
	unsigned int mark = 0;
	unsigned int limit = xas->xa_offset + xas->xa_sibs + 1;

	if (!xas->xa_sibs)
		return;

	do {
		unsigned long *marks = xas->xa_node->marks[mark];
		if (find_next_bit(marks, limit, xas->xa_offset + 1) == limit)
			continue;
		__set_bit(xas->xa_offset, marks);
		bitmap_clear(marks, xas->xa_offset + 1, xas->xa_sibs);
	} while (mark++ != (__force unsigned)CC_XA_MARK_MAX);
}

/* extracts the offset within this node from the index */
static unsigned int get_offset(unsigned long index, struct xa_node *node)
{
	return (index >> node->shift) & CC_XA_CHUNK_MASK;
}

static void cc_xas_set_offset(struct xa_state *xas)
{
	xas->xa_offset = get_offset(xas->xa_index, xas->xa_node);
}

/* move the index either forwards (find) or backwards (sibling slot) */
static void cc_xas_move_index(struct xa_state *xas, unsigned long offset)
{
	unsigned int shift = xas->xa_node->shift;
	xas->xa_index &= ~CC_XA_CHUNK_MASK << shift;
	xas->xa_index += offset << shift;
}

static void cc_xas_advance(struct xa_state *xas)
{
	xas->xa_offset++;
	cc_xas_move_index(xas, xas->xa_offset);
}

static void *set_bounds(struct xa_state *xas)
{
	//xas->xa_node = CC_XAS_BOUNDS;
	cc_xas_set_xa_node(xas, CC_XAS_BOUNDS);
	return NULL;
}

/*
 * Starts a walk.  If the @xas is already valid, we assume that it's on
 * the right path and just return where we've got to.  If we're in an
 * error state, return NULL.  If the index is outside the current scope
 * of the xarray, return NULL without changing @xas->xa_node.  Otherwise
 * set @xas->xa_node to NULL and return the current head of the array.
 */
static void *cc_xas_start(struct xa_state *xas)
{
	void *entry;

	if (cc_xas_valid(xas))
		return cc_xas_reload(xas);
	if (cc_xas_error(xas))
		return NULL;

	entry = cc_xa_head(xas->xa);
	if (!cc_xa_is_node(entry)) {
		if (xas->xa_index)
			return set_bounds(xas);
	} else {
		if ((xas->xa_index >> cc_xa_to_node(entry)->shift) > CC_XA_CHUNK_MASK)
			return set_bounds(xas);
	}

	//xas->xa_node = NULL;
	cc_xas_set_xa_node(xas, NULL);
	return entry;
}

static void *cc_xas_descend(struct xa_state *xas, struct xa_node *node)
{
	unsigned int offset = get_offset(xas->xa_index, node);
	void *entry = cc_xa_entry(xas->xa, node, offset);
	
	//xas->xa_node = node;
	cc_xas_set_xa_node(xas, node);
	if (cc_xa_is_sibling(entry)) {
		offset = cc_xa_to_sibling(entry);
		entry = cc_xa_entry(xas->xa, node, offset);
	}

	xas->xa_offset = offset;
	return entry;
}

/**
 * cc_xas_load() - Load an entry from the XArray (advanced).
 * @xas: XArray operation state.
 *
 * Usually walks the @xas to the appropriate state to load the entry
 * stored at xa_index.  However, it will do nothing and return %NULL if
 * @xas is in an error state.  cc_xas_load() will never expand the tree.
 *
 * If the xa_state is set up to operate on a multi-index entry, cc_xas_load()
 * may return %NULL or an internal entry, even if there are entries
 * present within the range specified by @xas.
 *
 * Context: Any context.  The caller should hold the xa_lock or the RCU lock.
 * Return: Usually an entry in the XArray, but see description for exceptions.
 */
#include <linux/sched.h>

void *cc_xas_load(struct xa_state *xas, bool rewind)
{
	struct xa_node *parent = NULL;
	void *entry = cc_xas_start(xas);
	void **slot;
	struct xa_node *node = NULL;

	while (cc_xa_is_node(entry)) {
		struct xa_node *node = cc_xa_to_node(entry);
		//unsigned short refcnt = __sync_fetch_and_add(&node->refcnt, 0);
		//CC_XA_NODE_BUG_ON(node, node->refcnt > 0);
		//if (refcnt > 0)
		//	printk("[@%px] pid: %d, node->shift: %u ->refcnt: %hu\n", node, current->pid, node->shift, refcnt);

		if (node->refcnt > 60000) {
			printk("[WARNING!!] [@%p] before get_node refcnt: %hu (%s:%d)\n", node, node->refcnt, __func__, __LINE__);
			CC_XA_NODE_BUG_ON(node, 1);
		}
		
		node = cc_xa_get_node(xas, cc_xa_to_node(entry));

/*sys */
		while(__sync_fetch_and_add(&node->gc_flag, 0)){
			//wait for other thread	
		}


		if (__sync_fetch_and_add(&node->del, 0)) {
			//printk("node logically deleted! returning null\n");
			entry = NULL;
			cc_xas_reset(xas);
			break;
		}

		if (xas->xa_shift > node->shift) 
			break;
descend:
		entry = cc_xas_descend(xas, node);
		//parent_slot = &node->slots[xas->xa_offset];
		// it is okay to put node here, since xas->xa_node got refcnt in xas_descend()
		//cc_xa_put_node(node);
		if (node->shift == 0) {		// reached leaf node
			//CC_XA_NODE_BUG_ON(node, cc_xa_node_is_gc(entry));
			break;
		}
	}
	if (rewind)
		cc_xas_rewind_refcnt(xas);

	return entry;
}
//EXPORT_SYMBOL_GPL(cc_xas_load);

void *cc_xas_load_debug(struct xa_state *xas)
{
	struct xa_node *parent = NULL;
	void *entry = cc_xas_start(xas);
	void **slot;
	struct xa_node *node = NULL;

	while (cc_xa_is_node(entry)) {
		struct xa_node *node = cc_xa_to_node(entry);
		//unsigned short refcnt = __sync_fetch_and_add(&node->refcnt, 0);
		//CC_XA_NODE_BUG_ON(node, node->refcnt > 0);
		//if (refcnt > 0)
		//	printk("[@%px] pid: %d, node->shift: %u ->refcnt: %hu\n", node, current->pid, node->shift, refcnt);

		if (node->refcnt > 60000) {
			printk("[WARNING!!] [@%p] before get_node refcnt: %hu (%s:%d)\n", node, node->refcnt, __func__, __LINE__);
			CC_XA_NODE_BUG_ON(node, 1);
		}
		
		node = cc_xa_get_node(xas, cc_xa_to_node(entry));
		if (__sync_fetch_and_add(&node->gc_flag, 0)) {
			printk("node logically deleted! returning null\n");
			return NULL;
		}
		cc_xa_dump_node(node);

		if (xas->xa_shift > node->shift) 
			break;
descend:
		entry = cc_xas_descend(xas, node);
		//parent_slot = &node->slots[xas->xa_offset];
		// it is okay to put node here, since xas->xa_node got refcnt in xas_descend()
		//cc_xa_put_node(node);
		if (node->shift == 0) {		// reached leaf node
			//CC_XA_NODE_BUG_ON(node, cc_xa_node_is_gc(entry));
			break;
		}
	}

	return entry;
}

/* Move the radix tree node cache here */
extern struct kmem_cache *radix_tree_node_cachep;
extern void radix_tree_node_rcu_free(struct rcu_head *head);

#define CC_XA_RCU_FREE	((struct xarray *)1)

static void xa_node_free(struct xa_node *node)
{
	CC_XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
	node->array = CC_XA_RCU_FREE;
	//call_rcu(&node->rcu_head, radix_tree_node_rcu_free);
	radix_tree_node_rcu_free(&node->rcu_head);
}

/*
 * cc_xas_destroy() - Free any resources allocated during the XArray operation.
 * @xas: XArray operation state.
 *
 * This function is now internal-only.
 */
static void cc_xas_destroy(struct xa_state *xas)
{
	struct xa_node *next, *node = xas->xa_alloc;

	while (node) {
		CC_XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
		next = rcu_dereference_raw(node->parent);
		radix_tree_node_rcu_free(&node->rcu_head);
		xas->xa_alloc = node = next;
	}
}

/**
 * cc_xas_nomem() - Allocate memory if needed.
 * @xas: XArray operation state.
 * @gfp: Memory allocation flags.
 *
 * If we need to add new nodes to the XArray, we try to allocate memory
 * with GFP_NOWAIT while holding the lock, which will usually succeed.
 * If it fails, @xas is flagged as needing memory to continue.  The caller
 * should drop the lock and call cc_xas_nomem().  If cc_xas_nomem() succeeds,
 * the caller should retry the operation.
 *
 * Forward progress is guaranteed as one node is allocated here and
 * stored in the xa_state where it will be found by cc_xas_alloc().  More
 * nodes will likely be found in the slab allocator, but we do not tie
 * them up here.
 *
 * Return: true if memory was needed, and was successfully allocated.
 */
bool cc_xas_nomem(struct xa_state *xas, gfp_t gfp)
{
	if (xas->xa_node != CC_XA_ERROR(-ENOMEM)) {
		cc_xas_destroy(xas);
		return false;
	}
	if (xas->xa->xa_flags & CC_XA_FLAGS_ACCOUNT)
		gfp |= __GFP_ACCOUNT;
	xas->xa_alloc = kmem_cache_alloc(radix_tree_node_cachep, gfp);
	if (!xas->xa_alloc)
		return false;
	xas->xa_alloc->parent = NULL;
	CC_XA_NODE_BUG_ON(xas->xa_alloc, !list_empty(&xas->xa_alloc->private_list));
	//xas->xa_node = CC_XAS_RESTART;
	cc_xas_set_xa_node(xas, CC_XAS_RESTART);
	return true;
}
//EXPORT_SYMBOL_GPL(cc_xas_nomem);

/*
 * __cc_xas_nomem() - Drop locks and allocate memory if needed.
 * @xas: XArray operation state.
 * @gfp: Memory allocation flags.
 *
 * Internal variant of cc_xas_nomem().
 *
 * Return: true if memory was needed, and was successfully allocated.
 */
static bool __cc_xas_nomem(struct xa_state *xas, gfp_t gfp)
	__must_hold(xas->xa->xa_lock)
{
	unsigned int lock_type = xa_lock_type(xas->xa);

	if (xas->xa_node != CC_XA_ERROR(-ENOMEM)) {
		cc_xas_destroy(xas);
		return false;
	}
	if (xas->xa->xa_flags & CC_XA_FLAGS_ACCOUNT)
		gfp |= __GFP_ACCOUNT;
	if (gfpflags_allow_blocking(gfp)) {
		cc_xas_unlock_type(xas, lock_type);
		xas->xa_alloc = kmem_cache_alloc(radix_tree_node_cachep, gfp);
		cc_xas_lock_type(xas, lock_type);
	} else {
		xas->xa_alloc = kmem_cache_alloc(radix_tree_node_cachep, gfp);
	}
	if (!xas->xa_alloc)
		return false;
	xas->xa_alloc->parent = NULL;
	CC_XA_NODE_BUG_ON(xas->xa_alloc, !list_empty(&xas->xa_alloc->private_list));
	//xas->xa_node = CC_XAS_RESTART;
	cc_xas_set_xa_node(xas, CC_XAS_RESTART);
	return true;
}

static void cc_xas_update(struct xa_state *xas, struct xa_node *node)
{
//	if (xas->xa_update)
//		xas->xa_update(node);
//	else
//		CC_XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
}

static void *cc_xas_alloc(struct xa_state *xas, unsigned int shift)
{
	struct xa_node *parent = xas->xa_node;
	struct xa_node *node = xas->xa_alloc;

	if (cc_xas_invalid(xas))
		return NULL;

	if (node) {
		xas->xa_alloc = NULL;
	} else {
		gfp_t gfp = GFP_NOWAIT | __GFP_NOWARN;

		if (xas->xa->xa_flags & CC_XA_FLAGS_ACCOUNT)
			gfp |= __GFP_ACCOUNT;

		node = kmem_cache_alloc(radix_tree_node_cachep, gfp); 
		if (!node) {
			cc_xas_set_err(xas, -ENOMEM);
			return NULL;
		}
	}

	if (parent) {
		int parent_cnt;
		node->offset = xas->xa_offset;
		//parent->count++;
		//parent_cnt = __sync_add_and_fetch(&parent->count, 1);
		//CC_XA_NODE_BUG_ON(node, parent_cnt > CC_XA_CHUNK_SIZE);
		//cc_xas_update(xas, parent);
	}
	CC_XA_NODE_BUG_ON(node, shift > BITS_PER_LONG);
	CC_XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
	node->shift = shift;
	node->count = 0;
	node->nr_values = 0;
	node->refcnt = 0;
	node->gc_flag = 0;
	node->del = 0;
	RCU_INIT_POINTER(node->parent, xas->xa_node);
	node->array = xas->xa;

	return node;
}

#ifdef CONFIG_XARRAY_MULTI
/* Returns the number of indices covered by a given xa_state */
static unsigned long cc_xas_size(const struct xa_state *xas)
{
	return (xas->xa_sibs + 1UL) << xas->xa_shift;
}
#endif

/*
 * Use this to calculate the maximum index that will need to be created
 * in order to add the entry described by @xas.  Because we cannot store a
 * multi-index entry at index 0, the calculation is a little more complex
 * than you might expect.
 */
static unsigned long cc_xas_max(struct xa_state *xas)
{
	unsigned long max = xas->xa_index;

#ifdef CONFIG_XARRAY_MULTI
	if (xas->xa_shift || xas->xa_sibs) {
		unsigned long mask = cc_xas_size(xas) - 1;
		max |= mask;
		if (mask == max)
			max++;
	}
#endif

	return max;
}

/* The maximum index that can be contained in the array without expanding it */
static unsigned long max_index(void *entry)
{
	if (!cc_xa_is_node(entry))
		return 0;
	return (CC_XA_CHUNK_SIZE << cc_xa_to_node(entry)->shift) - 1;
}

static void cc_xas_shrink(struct xa_state *xas)
{
	struct xarray *xa = xas->xa;
	struct xa_node *node = xas->xa_node;

	for (;;) {
		void *entry;

		CC_XA_NODE_BUG_ON(node, node->count > CC_XA_CHUNK_SIZE);
		if (node->count != 1)
			break;
		entry = cc_xa_entry_locked(xa, node, 0);
		if (!entry)
			break;
		if (!cc_xa_is_node(entry) && node->shift)
			break;
		if (cc_xa_is_zero(entry) && cc_xa_zero_busy(xa))
			entry = NULL;
		//xas->xa_node = CC_XAS_BOUNDS;
		cc_xas_set_xa_node(xas, CC_XAS_BOUNDS);

		RCU_INIT_POINTER(xa->xa_head, entry);
		if (cc_xa_track_free(xa) && !node_get_mark(node, 0, CC_XA_FREE_MARK))
			cc_xa_mark_clear(xa, CC_XA_FREE_MARK);

		node->count = 0;
		node->nr_values = 0;
		if (!cc_xa_is_node(entry))
			RCU_INIT_POINTER(node->slots[0], CC_XA_RETRY_ENTRY);
		cc_xas_update(xas, node);
		//xa_node_free(node);
		
		/*
		if (!logical_delete (node))
			pr_debug("Error !");
		*/

		if (!cc_xa_is_node(entry))
			break;
		node = cc_xa_to_node(entry);
		node->parent = NULL;
	}
}

#include <linux/sched.h>

/*
 * cc_xas_delete_node() - Attempt to delete an xa_node
 * @xas: Array operation state.
 *
 * Attempts to delete the @xas->xa_node.  This will fail if xa->node has
 * a non-zero reference count.
 */
static void cc_xas_delete_node(struct xa_state *xas)
{
	struct xa_node *node = xas->xa_node;
	void *temp;

	for (;;) {
		struct xa_node *parent;
		unsigned char parent_cnt;
		int gg_count = 65535;
		unsigned char count;
		unsigned short refcnt = 0;

		if (!cc_xa_parent(xas->xa, node))	// Check if node is root node
			break;

		CC_XA_NODE_BUG_ON(node, node->count > CC_XA_CHUNK_SIZE);
		if (count = __sync_fetch_and_add(&node->count, 0))	// Check if entry count is not zero.
			break;
		
		//if (__sync_fetch_and_add(&node->parent->count, 0) > 1) {
		//	printk("parent->count %d\n", node->parent->count);
		//	break;
		//}
		// Return if gc_flag is already set. --> Someone else is already doing gc...
		if (!__sync_bool_compare_and_swap(&node->gc_flag, 0, 1))
			break;
		
		/* 
		 * At this point, 
		 * 1) node is not root node.
		 * 2) node has no entries 
		 * 3) this thread is performing gc... 
		 * */
		cc_xas_set_xa_node(xas, NULL);	// to put refcnt of xas->xa_node

		/* if there are other threads in the parent node */
		if (__sync_fetch_and_add(&node->parent->refcnt, 0) > 1) {
			printk("parent->refcnt %d\n", node->parent->refcnt);
			CC_XA_NODE_BUG_ON(node, !__sync_bool_compare_and_swap(&node->gc_flag, 1, 0));
			cc_xas_set_xa_node(xas, node);
			break;
		}

		/* if there are other threads in the node */
		if (__sync_fetch_and_add(&node->refcnt, 0) > 1) {
			printk("node->refcnt %d\n", node->refcnt);
			CC_XA_NODE_BUG_ON(node, !__sync_bool_compare_and_swap(&node->gc_flag, 1, 0));
			cc_xas_set_xa_node(xas, node);
			break;
		}

		//CC_XA_NODE_BUG_ON(node, node->shift);

		//CC_XA_NODE_BUG_ON(node, (refcnt = __sync_fetch_and_add(&node->refcnt, 0)) == 0);
		
		//parent = cc_xa_get_node(node->parent);
		parent = xa_parent_locked(xas->xa, node);
		//xas->xa_node = parent;
		cc_xas_set_xa_node(xas, parent);
		xas->xa_offset = node->offset;
	
		pr_cont("deleting node[@%px]... count %u parent @%px\n", node, count, parent);
		//xa_node_free(node);
		CC_XA_NODE_BUG_ON(node, !__sync_bool_compare_and_swap(&node->del, 0, 1));

		if (!parent) {
			xas->xa->xa_head = NULL;
			//xas->xa_node = CC_XAS_BOUNDS;
			cc_xas_set_xa_node(xas, CC_XAS_BOUNDS);
			return;
		}

		//parent->slots[xas->xa_offset] = NULL;
		//temp = parent->slots[xas->xa_offset];
		//while (!__sync_bool_compare_and_swap(&parent->slots[xas->xa_offset], temp, NULL))
		//	temp = parent->slots[xas->xa_offset];

		parent_cnt = __sync_sub_and_fetch(&parent->count, 1);
		CC_XA_NODE_BUG_ON(parent, parent_cnt > CC_XA_CHUNK_SIZE);
		CC_XA_NODE_BUG_ON(node, !__sync_bool_compare_and_swap(&node->gc_flag, 1, 0));
		node = parent;
		cc_xas_update(xas, node);
	}

	//if (!node->parent)
	//	cc_xas_shrink(xas);
}

// static void cc_xas_delete_node(struct xa_state *xas)
// {
// 	struct xa_node *node = xas->xa_node;

// 	for (;;) {
// 		struct xa_node *parent;
// 		unsigned char node_cnt, parent_cnt;

// 		node_cnt = __sync_fetch_and_add(&node->count, 0);
// 		CC_XA_NODE_BUG_ON(node, node_cnt > CC_XA_CHUNK_SIZE);
// 		if (node_cnt)
// 			break;


// 		parent = __sync_fetch_and_add(&node->parent, 0);
// 		xas->xa_node = parent;
// 		xas->xa_offset = node->offset;
// 		//xa_node_free(node);

// 		if (!parent) {
// 			//xas->xa->xa_head = NULL;
// 			xas->xa_node = CC_XAS_BOUNDS;
// 			return;
// 		}

// 		//parent->slots[xas->xa_offset] = NULL;
// 		parent_cnt = __sync_sub_and_fetch(&parent->count, 1);
// 		CC_XA_NODE_BUG_ON(parent, parent_cnt > CC_XA_CHUNK_SIZE);
// 		node = parent;
// 		cc_xas_update(xas, node);
// 	}

// 	if (!node->parent)
// 		cc_xas_shrink(xas);
// }

/**
 * cc_xas_free_nodes() - Free this node and all nodes that it references
 * @xas: Array operation state.
 * @top: Node to free
 *
 * This node has been removed from the tree.  We must now free it and all
 * of its subnodes.  There may be RCU walkers with references into the tree,
 * so we must replace all entries with retry markers.
 */
static void cc_xas_free_nodes(struct xa_state *xas, struct xa_node *top)
{
	unsigned int offset = 0;
	struct xa_node *node = top;
	//struct xa_node *node = cc_xa_get_node(top);
	
	//if (node == CC_XAS_RESTART)
	//	return;

	printk("%s\n", __func__);
	

	for (;;) {
		void *entry = cc_xa_entry_locked(xas->xa, node, offset);

		if (node->shift && cc_xa_is_node(entry)) {
			struct xa_node *child;
			// descend to left most slot until we reach leaf node
			child = cc_xa_to_node(entry);
			//child = cc_xa_get_node(cc_xa_to_node(entry));
			//if (child == CC_XAS_RESTART) 
			//	goto next;
			//cc_xa_put_node(node);
			node = child;
			offset = 0;
			continue;
		}
		if (entry) 	// replace with RETRY entry
			RCU_INIT_POINTER(node->slots[offset], CC_XA_RETRY_ENTRY);
next:
		offset++;	// replace every slots in this node 1with RETRY entry
		while (offset == CC_XA_CHUNK_SIZE) {
			struct xa_node *parent;

			parent = cc_xa_parent_locked(xas->xa, node);
			offset = node->offset + 1;
			node->count = 0;
			node->nr_values = 0;
			cc_xas_update(xas, node);
			//cc_xa_put_node(node);
			xa_node_free(node);
			if (node == top)
				return;
			//node = cc_xa_get_node(parent);
			node = parent;
		}
	}
}

/*
 * cc_xas_expand adds nodes to the head of the tree until it has reached
 * sufficient height to be able to contain @xas->xa_index
 */
static int cc_xas_expand(struct xa_state *xas, void *head)
{
	struct xarray *xa = xas->xa;
	struct xa_node *node = NULL, *oldroot = NULL;
	unsigned int shift = 0;
	unsigned long max = cc_xas_max(xas);
	void *tmp_head;

	if (!head) {	// xarray is empty!
		if (max == 0)
			return 0;
		while ((max >> shift) >= CC_XA_CHUNK_SIZE)
			shift += CC_XA_CHUNK_SHIFT;
		return shift + CC_XA_CHUNK_SHIFT;
	} else if (cc_xa_is_node(head)) {
		//pr_cont("(%s:%d) ", __func__, __LINE__);
		//node = cc_xa_get_node(xas, cc_xa_to_node(head));
		node = cc_xa_to_node(head);
		if (node == CC_XAS_RESTART) {
			printk("Root Node being destroyed!! Something went wrong!\n");
			return -1;
		}
		shift = node->shift + CC_XA_CHUNK_SHIFT;
	}
	// else: xarray head is pointing entry!

	//xas->xa_node = NULL;
	cc_xas_set_xa_node(xas, NULL);

	while (max > max_index(head)) { 
		cc_xa_mark_t mark = 0;

		CC_XA_NODE_BUG_ON(node, shift > BITS_PER_LONG);
		node = cc_xas_alloc(xas, shift); // alloc new node
		if (!node) {
			//cc_xa_put_node(cc_xa_to_node(head));
			return -ENOMEM;
		}
		node->count = 1;
		if (cc_xa_is_value(head))
			node->nr_values = 1;
		RCU_INIT_POINTER(node->slots[0], head);

		/* Propagate the aggregated mark info to the new child */
		for (;;) {
			if (cc_xa_track_free(xa) && mark == CC_XA_FREE_MARK) {
				node_mark_all(node, CC_XA_FREE_MARK);
				if (!cc_xa_marked(xa, CC_XA_FREE_MARK)) {
					node_clear_mark(node, 0, CC_XA_FREE_MARK);
					cc_xa_mark_set(xa, CC_XA_FREE_MARK);
				}
			} else if (cc_xa_marked(xa, mark)) {
				node_set_mark(node, 0, mark);
			}
			if (mark == CC_XA_MARK_MAX)
				break;
			mark_inc(mark);
		}

		/*
		 * Now that the new node is fully initialised, we can add
		 * it to the tree
		 */
		if (cc_xa_is_node(head)) {
			//cc_xa_to_node(head)->offset = 0;
			oldroot = cc_xa_to_node(head);
			oldroot->offset = 0;
			//rcu_assign_pointer(cc_xa_to_node(head)->parent, node); 
			// Perform CAS
			struct xa_node *tmp_node = cc_xa_parent(xas->xa, oldroot);
			if (tmp_node != NULL || !__sync_bool_compare_and_swap(
				    &oldroot->parent, tmp_node, node)) {
				struct xa_node *parent = __sync_fetch_and_add(&oldroot->parent, 0);
				xa_node_free(node);
				head = cc_xa_mk_node(parent);
				//cc_xa_put_node(oldroot);
				goto ascend;
			}
			//cc_xa_put_node(oldroot);
		}
		// Perform CAS
		tmp_head = head;
		head = cc_xa_mk_node(node);
		//rcu_assign_pointer(xa->xa_head, head);
		if (!__sync_bool_compare_and_swap(&xa->xa_head, tmp_head, head)) {
			xa_node_free(node);
			head = cc_xa_head(xas->xa);
			goto ascend;
		}
		cc_xas_update(xas, node);
ascend:
		shift += CC_XA_CHUNK_SHIFT;
	}

	//xas->xa_node = node;
	cc_xas_set_xa_node(xas, node);
	//if (cc_xas_is_node(xas))
	//	cc_xa_put_node(node);	// it is okay to put node here, since xas->xa_node got refcnt
	return shift;
}

/*
 * cc_xas_create() - Create a slot to store an entry in.
 * @xas: XArray operation state.
 * @allow_root: %true if we can store the entry in the root directly
 *
 * Most users will not need to call this function directly, as it is called
 * by cc_xas_store().  It is useful for doing conditional store operations
 * (see the cc_xa_cmpxchg() implementation for an example).
 *
 * Return: If the slot already existed, returns the contents of this slot.
 * If the slot was newly created, returns %NULL.  If it failed to create the
 * slot, returns %NULL and indicates the error in @xas.
 *
 * Notice that the node containing the slot returned from this function 
 * got refcnt increased. User of this function must decrease refcnt of the node.
 */
static void *cc_xas_create(struct xa_state *xas, bool allow_root)
{
	struct xarray *xa = xas->xa;
	void *entry, *temp;
	void __rcu **slot;
	struct xa_node *node = xas->xa_node;
	int shift;
	unsigned int order = xas->xa_shift;
	struct xa_node *parent = NULL;

	if (cc_xas_top(node)) { 
		entry = cc_xa_head_locked(xa); 
		//xas->xa_node = NULL;
		cc_xas_set_xa_node(xas, NULL);
		if (!entry && cc_xa_zero_busy(xa)) {
			printk("ZERO ENTRY!!\n");
			entry = CC_XA_ZERO_ENTRY;
		}
		shift = cc_xas_expand(xas, entry);
		if (shift < 0)
			return NULL;
		if (!shift && !allow_root)
			shift = CC_XA_CHUNK_SHIFT;
		entry = cc_xa_head_locked(xa);
		slot = &xas->xa->xa_head;
	} else if (cc_xas_error(xas)) {
		return NULL;
	} else if (node) {
		unsigned int offset = xas->xa_offset;

		BUG_ON((unsigned long)node < 100);

		shift = node->shift;
		entry = cc_xa_entry_locked(xa, node, offset);
		slot = &node->slots[offset];
	} else {
		shift = 0;
		entry = cc_xa_head_locked(xa);
		slot = &xas->xa->xa_head;
	}

	while (shift > order) {
		shift -= CC_XA_CHUNK_SHIFT;
		//if (!cc_xas_top(node)) {
		//}
		if (!entry) {
			void *curr;
			struct xa_node *parent = xas->xa_node;
			node = cc_xa_get_node(xas, cc_xas_alloc(xas, shift));
			if (!node)
				break;
			if (cc_xa_track_free(xa))
				node_mark_all(node, CC_XA_FREE_MARK);
			//rcu_assign_pointer(*slot, cc_xa_mk_node(node));
			if (curr = __sync_val_compare_and_swap(
					slot, NULL, cc_xa_mk_node(node)) != NULL) {
				//cc_xa_put_node(node);	// TODO: delete from the list!!
				printk("CAS failed! (%s:%d)\n", __func__, __LINE__);

				struct node_trace_entry *entry = container_of(&node, struct node_trace_entry, node);
				BUG_ON((unsigned long) entry < 100);
				list_del(&entry->list);
				xa_node_free(node);
				kfree(entry);
				//pr_cont("(%s:%d) ", __func__, __LINE__);
				node = cc_xa_get_node(xas, cc_xa_to_node(curr));
				goto descend;
			}
			if (parent) {
				BUG_ON((unsigned long) parent < 100);
				int parent_cnt = __sync_add_and_fetch(&parent->count, 1);
				CC_XA_NODE_BUG_ON(node, parent_cnt > CC_XA_CHUNK_SIZE);
				cc_xas_update(xas, parent);
			}
		} else if (cc_xa_is_node(entry)) {
			BUG_ON((unsigned long) cc_xa_to_node(entry) < 100);
			//pr_cont("(%s:%d) ", __func__, __LINE__);
			node = cc_xa_get_node(xas, cc_xa_to_node(entry));

			while (__sync_fetch_and_add(&node->gc_flag, 0)) {
				// wait for other thread
			}

			if (__sync_bool_compare_and_swap(&node->del, 1, 0)) {
				// if the node is marked as deleted, reuse it.
				parent = cc_xa_parent(xas->xa, node);
				if (parent) {
					BUG_ON((unsigned long) parent < 100);
					__sync_add_and_fetch(&parent->count, 1);
				}
				printk("reusing node[@%px]... parent @%px (%s:%d)\n", node, parent, __func__, __LINE__);
				goto descend;
			}
		} else {	// node is leaf node and entry is pointer or value
			//node = cc_xa_get_node(node);
			printk(" node is leaf node and entry is pointer or value\n");
			break;
		}
descend:
		//if (parent)
		//	unlock_node(parent);
		//lock_node(node);
		entry = cc_xas_descend(xas, node);
		slot = &node->slots[xas->xa_offset];
		//if (shift > order)
		CC_XA_NODE_BUG_ON(node, !node);
		//cc_xa_put_node(node);
		parent = node;
	}

	CC_XA_NODE_BUG_ON(node, shift);

	return entry;
}

/**
 * cc_xas_create_range() - Ensure that stores to this range will succeed
 * @xas: XArray operation state.
 *
 * Creates all of the slots in the range covered by @xas.  Sets @xas to
 * create single-index entries and positions it at the beginning of the
 * range.  This is for the benefit of users which have not yet been
 * converted to use multi-index entries.
 */
void cc_xas_create_range(struct xa_state *xas)
{
	unsigned long index = xas->xa_index;
	unsigned char shift = xas->xa_shift;
	unsigned char sibs = xas->xa_sibs;

	xas->xa_index |= ((sibs + 1) << shift) - 1;
	if (cc_xas_is_node(xas) && xas->xa_node->shift == xas->xa_shift)
		xas->xa_offset |= sibs;
	xas->xa_shift = 0;
	xas->xa_sibs = 0;

	printk("%s\n", __func__);

	for (;;) {
		cc_xas_create(xas, true);
		cc_xas_rewind_refcnt(xas);
		if (cc_xas_error(xas))
			goto restore;
		if (xas->xa_index <= (index | CC_XA_CHUNK_MASK))
			goto success;
		xas->xa_index -= CC_XA_CHUNK_SIZE;

		for (;;) {
			struct xa_node *node = xas->xa_node;
			//xas->xa_node = cc_xa_parent_locked(xas->xa, node);
			cc_xas_set_xa_node(xas, cc_xa_parent_locked(xas->xa, node));
			xas->xa_offset = node->offset - 1;
			if (node->offset != 0)
				break;
		}
	}

restore:
	xas->xa_shift = shift;
	xas->xa_sibs = sibs;
	xas->xa_index = index;
	return;
success:
	xas->xa_index = index;
	if (xas->xa_node)
		cc_xas_set_offset(xas);
}
//EXPORT_SYMBOL_GPL(cc_xas_create_range);

static void update_node(struct xa_state *xas, struct xa_node *node,
		int count, int values)
{
	int node_count, nr_values;

	if (!node || (!count && !values))
		return;

	CC_XA_NODE_BUG_ON(node, count > 1 || count < -1);

	// node->count += count;
	// node->nr_values += values;
	node_count = __sync_add_and_fetch(&node->count, count);
	nr_values = __sync_add_and_fetch(&node->nr_values, values);
	//CC_XA_NODE_BUG_ON(node, (node_count > CC_XA_CHUNK_SIZE) &&
	//			(node_count < (U8_MAX - CC_XA_CHUNK_SIZE)));
	//CC_XA_NODE_BUG_ON(node, (nr_values > CC_XA_CHUNK_SIZE) && 
	//			(nr_values < (U8_MAX - CC_XA_CHUNK_SIZE)));
	cc_xas_update(xas, node);
/*	if (count < 0)
		cc_xas_delete_node(xas);
*/
	/* sys
	 *
	 * if(node_count < 0)
	 * 	printk("%s, node_count: %d is minus\n", __func__, node_count);
	 * if(node_count <= 0 && count < 0)
	 	cc_xas_delete_node(xas);
	 *
	 */
	
	 if(node_count < 0)
	 	printk("%s, node_count: %d is minus\n", __func__, node_count);
	 if(node_count <= 0 && count < 0)
	 	cc_xas_delete_node(xas);


	//if (count < 0)
	//{
	//	if (!node->del){
	// 		__sync_fetch_and_add(&node->del, 1);
	// 	}
	//		
	//}


	//if (node->del){
	//	if (count > 0)
	//		__sync_fetch_and_sub(&node->del, 1);
	//}
}

/**
 * cc_xas_store() - Store this entry in the XArray.
 * @xas: XArray operation state.
 * @entry: New entry.
 *
 * If @xas is operating on a multi-index entry, the entry returned by this
 * function is essentially meaningless (it may be an internal entry or it
 * may be %NULL, even if there are non-NULL entries at some of the indices
 * covered by the range).  This is not a problem for any current users,
 * and can be changed if needed.
 *
 * Return: The old entry at this index.
 */
void *cc_xas_store(struct xa_state *xas, void *entry)
{
	struct xa_node *node;
	void __rcu **slot = &xas->xa->xa_head;	// slot pointer
	unsigned int offset, max;
	int count = 0;
	int values = 0;
	void *first, *next;			// slot iterator
	bool value = cc_xa_is_value(entry);
	void *temp = cc_xa_head(xas->xa);
	int test=0;

	BUG_ON(!xas);


	if (entry) {
		// entry is not node and not error -> then the new node could be root
		bool allow_root = !cc_xa_is_node(entry) && !cc_xa_is_zero(entry);
		first = cc_xas_create(xas, allow_root); // create slot to move pointer in
	} else {
		first = cc_xas_load(xas, false);		// if entry is NULL -> no store?
	}

	if (cc_xas_invalid(xas)){
		printk("xas invalid! (%s:%d)\n", __func__, __LINE__);
		return first;
	}

	if (!first && !cc_xa_is_value(first)) {		// first is page
		if (!entry && !cc_xa_is_value(entry)) {	// entry is page
			printk("Insert & Insert!");
		
		}
	}

	node = xas->xa_node;
	if (node && (xas->xa_shift < node->shift))
		xas->xa_sibs = 0;
	if ((first == entry) && !xas->xa_sibs)	// no need to update slot! It's already same!
		return first;

	next = first;
	offset = xas->xa_offset;		// update offset, the slot mask
	max = xas->xa_offset + xas->xa_sibs;	// max number of leaves
	if (node) {
		slot = &node->slots[offset];	// get slot pointer
		//if(__sync_fetch_and_add(slot, 0) != NULL){
		//	test = 1;	
		//}

		if (xas->xa_sibs)
			cc_xas_squash_marks(xas);
	}
	if (!entry)
		cc_xas_init_marks(xas);

	for (;;) {
		void *curr;
		/*
		 * Must clear the marks before setting the entry to NULL,
		 * otherwise cc_xas_for_each_marked may find a NULL entry and
		 * stop early.  rcu_assign_pointer contains a release barrier
		 * so the mark clearing will appear to happen before the
		 * entry is set to NULL.
		 */
		if (node)
			temp = node->slots[offset];
		
	/*	
		while (!__sync_bool_compare_and_swap(slot, temp, entry)) {
			if(test == 1){
				printk("%s, test: %d\n", __func__, test);	
			}

			if (node)
				temp = node->slots[offset];
		}
*/
		 
		if ((curr = __sync_val_compare_and_swap(slot, next, entry)) != next) {
			// entry: page
			//if (!entry && !cc_xa_is_value(entry)) {	// page or NULL
				BUG();
				printk("%s, test: %d\n", __func__, test);	
				cc_xas_set_err(xas, -EEXIST);
				return curr;
			//}
			// entry: shadow
			
			// entry: NULL
			//
		}
			

		if (cc_xa_is_node(next) && (!node || node->shift)) { // coming from scan_shadow_nodes()
			
			if (cc_xa_to_node(next)->shift)
				printk("Isolated node was not Leaf Node!!");

			// TODO: Modify into lock-free version!!
			cc_xas_free_nodes(xas, cc_xa_to_node(next));
		}
		if (!node)
			break;
		count += !next - !entry;
		values += !cc_xa_is_value(first) - !value;
		if (entry) {	// insert
			if (offset == max)		// single index entry
				break;
			if (!cc_xa_is_sibling(entry))	// multi index entry
				entry = cc_xa_mk_sibling(xas->xa_offset);
		} else {	// delete
			if (offset == CC_XA_CHUNK_MASK)
				break;
		}
		next = cc_xa_entry_locked(xas->xa, node, ++offset);
		if (!cc_xa_is_sibling(next)) {
			if (!entry && (offset > max))
				break;
			first = next;
		}
		slot++;
	}

	update_node(xas, node, count, values);
	//cc_xa_dump_node(node);
//	if (xas->xa_node) {
//		node = xas->xa_node;
//		cc_xa_put_node(node);
//	}
	cc_xas_rewind_refcnt(xas);
	return first;
}
//EXPORT_SYMBOL_GPL(cc_xas_store);

/**
 * cc_xas_get_mark() - Returns the state of this mark.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Return: true if the mark is set, false if the mark is clear or @xas
 * is in an error state.
 */
bool cc_xas_get_mark(const struct xa_state *xas, cc_xa_mark_t mark)
{
	if (cc_xas_invalid(xas))
		return false;
	if (!xas->xa_node)
		return cc_xa_marked(xas->xa, mark);
	return node_get_mark(xas->xa_node, xas->xa_offset, mark);
}
//EXPORT_SYMBOL_GPL(cc_xas_get_mark);

/**
 * cc_xas_set_mark() - Sets the mark on this entry and its parents.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Sets the specified mark on this entry, and walks up the tree setting it
 * on all the ancestor entries.  Does nothing if @xas has not been walked to
 * an entry, or is in an error state.
 */
void cc_xas_set_mark(const struct xa_state *xas, cc_xa_mark_t mark)
{
	struct xa_node *node = xas->xa_node;
	unsigned int offset = xas->xa_offset;

	if (cc_xas_invalid(xas))
		return;

	while (node) {
		if (node_set_mark(node, offset, mark))
			return;
		offset = node->offset;
		node = cc_xa_parent_locked(xas->xa, node);
	}

	if (!cc_xa_marked(xas->xa, mark))
		cc_xa_mark_set(xas->xa, mark);
}
//EXPORT_SYMBOL_GPL(cc_xas_set_mark);

/**
 * cc_xas_clear_mark() - Clears the mark on this entry and its parents.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Clears the specified mark on this entry, and walks back to the head
 * attempting to clear it on all the ancestor entries.  Does nothing if
 * @xas has not been walked to an entry, or is in an error state.
 */
void cc_xas_clear_mark(const struct xa_state *xas, cc_xa_mark_t mark)
{
	struct xa_node *node = xas->xa_node;
	unsigned int offset = xas->xa_offset;

	if (cc_xas_invalid(xas))
		return;

	while (node) {
		if (!node_clear_mark(node, offset, mark))
			return;
		if (node_any_mark(node, mark))
			return;

		offset = node->offset;
		node = cc_xa_parent_locked(xas->xa, node);
	}

	if (cc_xa_marked(xas->xa, mark))
		cc_xa_mark_clear(xas->xa, mark);
}
//EXPORT_SYMBOL_GPL(cc_xas_clear_mark);

/**
 * cc_xas_init_marks() - Initialise all marks for the entry
 * @xas: Array operations state.
 *
 * Initialise all marks for the entry specified by @xas.  If we're tracking
 * free entries with a mark, we need to set it on all entries.  All other
 * marks are cleared.
 *
 * This implementation is not as efficient as it could be; we may walk
 * up the tree multiple times.
 */
void cc_xas_init_marks(const struct xa_state *xas)
{
	cc_xa_mark_t mark = 0;

	for (;;) {
		if (cc_xa_track_free(xas->xa) && mark == CC_XA_FREE_MARK)
			cc_xas_set_mark(xas, mark);
		else
			cc_xas_clear_mark(xas, mark);
		if (mark == CC_XA_MARK_MAX)
			break;
		mark_inc(mark);
	}
}
//EXPORT_SYMBOL_GPL(cc_xas_init_marks);

#ifdef CONFIG_XARRAY_MULTI
static unsigned int node_get_marks(struct xa_node *node, unsigned int offset)
{
	unsigned int marks = 0;
	cc_xa_mark_t mark = CC_XA_MARK_0;

	for (;;) {
		if (node_get_mark(node, offset, mark))
			marks |= 1 << (__force unsigned int)mark;
		if (mark == CC_XA_MARK_MAX)
			break;
		mark_inc(mark);
	}

	return marks;
}

static void node_set_marks(struct xa_node *node, unsigned int offset,
			struct xa_node *child, unsigned int marks)
{
	cc_xa_mark_t mark = CC_XA_MARK_0;

	for (;;) {
		if (marks & (1 << (__force unsigned int)mark)) {
			node_set_mark(node, offset, mark);
			if (child)
				node_mark_all(child, mark);
		}
		if (mark == CC_XA_MARK_MAX)
			break;
		mark_inc(mark);
	}
}

/**
 * cc_xas_split_alloc() - Allocate memory for splitting an entry.
 * @xas: XArray operation state.
 * @entry: New entry which will be stored in the array.
 * @order: New entry order.
 * @gfp: Memory allocation flags.
 *
 * This function should be called before calling cc_xas_split().
 * If necessary, it will allocate new nodes (and fill them with @entry)
 * to prepare for the upcoming split of an entry of @order size into
 * entries of the order stored in the @xas.
 *
 * Context: May sleep if @gfp flags permit.
 */
void cc_xas_split_alloc(struct xa_state *xas, void *entry, unsigned int order,
		gfp_t gfp)
{
	unsigned int sibs = (1 << (order % CC_XA_CHUNK_SHIFT)) - 1;
	unsigned int mask = xas->xa_sibs;

	/* XXX: no support for splitting really large entries yet */
	if (WARN_ON(xas->xa_shift + 2 * CC_XA_CHUNK_SHIFT < order))
		goto nomem;
	if (xas->xa_shift + CC_XA_CHUNK_SHIFT > order)
		return;

	do {
		unsigned int i;
		void *sibling;
		struct xa_node *node;

		node = kmem_cache_alloc(radix_tree_node_cachep, gfp);
		if (!node)
			goto nomem;
		node->array = xas->xa;
		node->refcnt = 0;
		node->gc_flag = 0;
		node->del = 0;
		for (i = 0; i < CC_XA_CHUNK_SIZE; i++) {
			if ((i & mask) == 0) {
				RCU_INIT_POINTER(node->slots[i], entry);
				sibling = cc_xa_mk_sibling(0);
			} else {
				RCU_INIT_POINTER(node->slots[i], sibling);
			}
		}
		RCU_INIT_POINTER(node->parent, xas->xa_alloc);
		xas->xa_alloc = node;
	} while (sibs-- > 0);

	return;
nomem:
	cc_xas_destroy(xas);
	cc_xas_set_err(xas, -ENOMEM);
}
//EXPORT_SYMBOL_GPL(cc_xas_split_alloc);

/**
 * cc_xas_split() - Split a multi-index entry into smaller entries.
 * @xas: XArray operation state.
 * @entry: New entry to store in the array.
 * @order: New entry order.
 *
 * The value in the entry is copied to all the replacement entries.
 *
 * Context: Any context.  The caller should hold the xa_lock.
 */
void cc_xas_split(struct xa_state *xas, void *entry, unsigned int order)
{
	unsigned int sibs = (1 << (order % CC_XA_CHUNK_SHIFT)) - 1;
	unsigned int offset, marks;
	struct xa_node *node;
	void *curr = cc_xas_load(xas, false);
	int values = 0;

	node = xas->xa_node;
	if (cc_xas_top(node)) {
		cc_xas_rewind_refcnt(xas);
		return;
	}

	marks = node_get_marks(node, xas->xa_offset);

	offset = xas->xa_offset + sibs;
	do {
		if (xas->xa_shift < node->shift) {
			struct xa_node *child = xas->xa_alloc;

			xas->xa_alloc = rcu_dereference_raw(child->parent);
			child->shift = node->shift - CC_XA_CHUNK_SHIFT;
			child->offset = offset;
			child->count = CC_XA_CHUNK_SIZE;
			child->nr_values = cc_xa_is_value(entry) ?
					CC_XA_CHUNK_SIZE : 0;
			child->refcnt = 0;
			child->gc_flag = 0;
			child->del = 0;
			RCU_INIT_POINTER(child->parent, node);
			node_set_marks(node, offset, child, marks);
			rcu_assign_pointer(node->slots[offset],
					cc_xa_mk_node(child));
			if (cc_xa_is_value(curr))
				values--;
		} else {
			unsigned int canon = offset - xas->xa_sibs;

			node_set_marks(node, canon, NULL, marks);
			rcu_assign_pointer(node->slots[canon], entry);
			while (offset > canon)
				rcu_assign_pointer(node->slots[offset--],
						cc_xa_mk_sibling(canon));
			values += (cc_xa_is_value(entry) - cc_xa_is_value(curr)) *
					(xas->xa_sibs + 1);
		}
	} while (offset-- > xas->xa_offset);

	__sync_fetch_and_add(&node->nr_values, values);
	cc_xas_rewind_refcnt(xas);
}
//EXPORT_SYMBOL_GPL(cc_xas_split);
#endif

/**
 * cc_xas_pause() - Pause a walk to drop a lock.
 * @xas: XArray operation state.
 *
 * Some users need to pause a walk and drop the lock they're holding in
 * order to yield to a higher priority thread or carry out an operation
 * on an entry.  Those users should call this function before they drop
 * the lock.  It resets the @xas to be suitable for the next iteration
 * of the loop after the user has reacquired the lock.  If most entries
 * found during a walk require you to call cc_xas_pause(), the cc_xa_for_each()
 * iterator may be more appropriate.
 *
 * Note that cc_xas_pause() only works for forward iteration.  If a user needs
 * to pause a reverse iteration, we will need a cc_xas_pause_rev().
 */
void cc_xas_pause(struct xa_state *xas)
{
	struct xa_node *node = xas->xa_node;

	if (cc_xas_invalid(xas))
		return;

	//xas->xa_node = CC_XAS_RESTART;
	cc_xas_set_xa_node(xas, CC_XAS_RESTART);
	if (node) {
		unsigned long offset = xas->xa_offset;
		while (++offset < CC_XA_CHUNK_SIZE) {
			if (!cc_xa_is_sibling(cc_xa_entry(xas->xa, node, offset)))
				break;
		}
		xas->xa_index += (offset - xas->xa_offset) << node->shift;
		if (xas->xa_index == 0)
			//xas->xa_node = CC_XAS_BOUNDS;
			cc_xas_set_xa_node(xas, CC_XAS_BOUNDS);
	} else {
		xas->xa_index++;
	}
}
//EXPORT_SYMBOL_GPL(cc_xas_pause);

/*
 * __cc_xas_prev() - Find the previous entry in the XArray.
 * @xas: XArray operation state.
 *
 * Helper function for cc_xas_prev() which handles all the complex cases
 * out of line.
 */
void *__cc_xas_prev(struct xa_state *xas)
{
	void *entry;

	if (!cc_xas_frozen(xas->xa_node))
		xas->xa_index--;
	if (!xas->xa_node)
		return set_bounds(xas);
	if (cc_xas_not_node(xas->xa_node))
		return cc_xas_load(xas, true);

	if (xas->xa_offset != get_offset(xas->xa_index, xas->xa_node))
		xas->xa_offset--;

	while (xas->xa_offset == 255) {
		xas->xa_offset = xas->xa_node->offset - 1;
		//xas->xa_node = cc_xa_parent(xas->xa, xas->xa_node);
		cc_xas_set_xa_node(xas, cc_xa_parent(xas->xa, xas->xa_node));
		if (!xas->xa_node)
			return set_bounds(xas);
	}

	for (;;) {
		entry = cc_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
		if (!cc_xa_is_node(entry))
			return entry;

		//xas->xa_node = cc_xa_to_node(entry);
		cc_xas_set_xa_node(xas, cc_xa_to_node(entry));
		cc_xas_set_offset(xas);
	}
}
//EXPORT_SYMBOL_GPL(__cc_xas_prev);

/*
 * __cc_xas_next() - Find the next entry in the XArray.
 * @xas: XArray operation state.
 *
 * Helper function for cc_xas_next() which handles all the complex cases
 * out of line.
 */
void *__cc_xas_next(struct xa_state *xas)
{
	void *entry;

	if (!cc_xas_frozen(xas->xa_node))
		xas->xa_index++;
	if (!xas->xa_node)
		return set_bounds(xas);
	if (cc_xas_not_node(xas->xa_node))
		return cc_xas_load(xas, true);

	if (xas->xa_offset != get_offset(xas->xa_index, xas->xa_node))
		xas->xa_offset++;

	while (xas->xa_offset == CC_XA_CHUNK_SIZE) {
		xas->xa_offset = xas->xa_node->offset + 1;
		//xas->xa_node = cc_xa_parent(xas->xa, xas->xa_node);
		cc_xas_set_xa_node(xas, cc_xa_parent(xas->xa, xas->xa_node));
		if (!xas->xa_node)
			return set_bounds(xas);
	}

	for (;;) {
		entry = cc_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
		if (!cc_xa_is_node(entry))
			return entry;

		//xas->xa_node = cc_xa_to_node(entry);
		cc_xas_set_xa_node(xas, cc_xa_to_node(entry));
		cc_xas_set_offset(xas);
	}
}
//EXPORT_SYMBOL_GPL(__cc_xas_next);

/**
 * cc_xas_find() - Find the next present entry in the XArray.
 * @xas: XArray operation state.
 * @max: Highest index to return.
 *
 * If the @xas has not yet been walked to an entry, return the entry
 * which has an index >= xas.xa_index.  If it has been walked, the entry
 * currently being pointed at has been processed, and so we move to the
 * next entry.
 *
 * If no entry is found and the array is smaller than @max, the iterator
 * is set to the smallest index not yet in the array.  This allows @xas
 * to be immediately passed to cc_xas_store().
 *
 * Return: The entry, if found, otherwise %NULL.
 */
void *cc_xas_find(struct xa_state *xas, unsigned long max)
{
	void *entry;

	if (cc_xas_error(xas) || xas->xa_node == CC_XAS_BOUNDS)
		return NULL;
	if (xas->xa_index > max)
		return set_bounds(xas);

	if (!xas->xa_node) {
		xas->xa_index = 1;
		return set_bounds(xas);
	} else if (xas->xa_node == CC_XAS_RESTART) {
		entry = cc_xas_load(xas, false);
		if (entry || cc_xas_not_node(xas->xa_node)) {
			cc_xas_rewind_refcnt(xas);
			return entry;
		}
	} else if (!xas->xa_node->shift &&
		    xas->xa_offset != (xas->xa_index & CC_XA_CHUNK_MASK)) {
		xas->xa_offset = ((xas->xa_index - 1) & CC_XA_CHUNK_MASK) + 1;
	}

	cc_xas_advance(xas);

	while (xas->xa_node && (xas->xa_index <= max)) {
		if (unlikely(xas->xa_offset == CC_XA_CHUNK_SIZE)) {
			xas->xa_offset = xas->xa_node->offset + 1;
			//xas->xa_node = cc_xa_parent(xas->xa, xas->xa_node);
			cc_xas_set_xa_node(xas, cc_xa_parent(xas->xa, xas->xa_node));
			continue;
		}

		entry = cc_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
		if (cc_xa_is_node(entry)) {
			//xas->xa_node = cc_xa_to_node(entry);
			cc_xas_set_xa_node(xas, cc_xa_to_node(entry));
			xas->xa_offset = 0;
			continue;
		}
		if (entry && !cc_xa_is_sibling(entry)) {
			cc_xas_rewind_refcnt(xas);
			return entry;
		}

		cc_xas_advance(xas);
	}

	if (!xas->xa_node)
		//xas->xa_node = CC_XAS_BOUNDS;
		cc_xas_set_xa_node(xas, CC_XAS_BOUNDS);
	cc_xas_rewind_refcnt(xas);
	return NULL;
}
//EXPORT_SYMBOL_GPL(cc_xas_find);

/**
 * cc_xas_find_marked() - Find the next marked entry in the XArray.
 * @xas: XArray operation state.
 * @max: Highest index to return.
 * @mark: Mark number to search for.
 *
 * If the @xas has not yet been walked to an entry, return the marked entry
 * which has an index >= xas.xa_index.  If it has been walked, the entry
 * currently being pointed at has been processed, and so we return the
 * first marked entry with an index > xas.xa_index.
 *
 * If no marked entry is found and the array is smaller than @max, @xas is
 * set to the bounds state and xas->xa_index is set to the smallest index
 * not yet in the array.  This allows @xas to be immediately passed to
 * cc_xas_store().
 *
 * If no entry is found before @max is reached, @xas is set to the restart
 * state.
 *
 * Return: The entry, if found, otherwise %NULL.
 */
void *cc_xas_find_marked(struct xa_state *xas, unsigned long max, cc_xa_mark_t mark)
{
	bool advance = true;
	unsigned int offset;
	void *entry;
	struct xa_node *node;

	if (cc_xas_error(xas))
		return NULL;
	if (xas->xa_index > max)
		goto max;

	if (!xas->xa_node) {
		xas->xa_index = 1;
		goto out;
	} else if (cc_xas_top(xas->xa_node)) {
		advance = false;
		entry = cc_xa_head(xas->xa);
		//xas->xa_node = NULL;
		cc_xas_set_xa_node(xas, NULL);
		if (xas->xa_index > max_index(entry))
			goto out;
		if (!cc_xa_is_node(entry)) {
			if (cc_xa_marked(xas->xa, mark))
				return entry;
			xas->xa_index = 1;
			goto out;
		}

		node = cc_xa_to_node(entry);
		//xas->xa_node = node;
		cc_xas_set_xa_node(xas, node);
		xas->xa_offset = xas->xa_index >> xas->xa_node->shift;
	}

	while (xas->xa_index <= max) {
		if (unlikely(xas->xa_offset == CC_XA_CHUNK_SIZE)) {
			xas->xa_offset = xas->xa_node->offset + 1;
			//xas->xa_node = cc_xa_parent(xas->xa, xas->xa_node);
			cc_xas_set_xa_node(xas, cc_xa_parent(xas->xa, xas->xa_node));
			if (!xas->xa_node)
				break;
			advance = false;
			continue;
		}

		if (!advance) {
			entry = cc_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
			if (cc_xa_is_sibling(entry)) {
				xas->xa_offset = cc_xa_to_sibling(entry);
				cc_xas_move_index(xas, xas->xa_offset);
			}
		}

		offset = cc_xas_find_chunk(xas, advance, mark);
		if (offset > xas->xa_offset) {
			advance = false;
			cc_xas_move_index(xas, offset);
			/* Mind the wrap */
			if ((xas->xa_index - 1) >= max)
				goto max;
			xas->xa_offset = offset;
			if (offset == CC_XA_CHUNK_SIZE)
				continue;
		}

		entry = cc_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
		if (!entry && !(cc_xa_track_free(xas->xa) && mark == CC_XA_FREE_MARK))
			continue;
		if (!cc_xa_is_node(entry))
			return entry;
		//xas->xa_node = cc_xa_to_node(entry);
		cc_xas_set_xa_node(xas, cc_xa_to_node(entry));
		cc_xas_set_offset(xas);
	}

out:
	if (xas->xa_index > max)
		goto max;
	return set_bounds(xas);
max:
	//xas->xa_node = CC_XAS_RESTART;
	cc_xas_set_xa_node(xas, CC_XAS_RESTART);
	return NULL;
}
//EXPORT_SYMBOL_GPL(cc_xas_find_marked);

/**
 * cc_xas_find_conflict() - Find the next present entry in a range.
 * @xas: XArray operation state.
 *
 * The @xas describes both a range and a position within that range.
 *
 * Context: Any context.  Expects xa_lock to be held.
 * Return: The next entry in the range covered by @xas or %NULL.
 */
void *cc_xas_find_conflict(struct xa_state *xas)
{
	void *curr;

	if (cc_xas_error(xas))
		return NULL;

	if (!xas->xa_node)
		return NULL;

	if (cc_xas_top(xas->xa_node)) {
		curr = cc_xas_start(xas);
		if (!curr)
			return NULL;
		while (cc_xa_is_node(curr)) {
			struct xa_node *node = cc_xa_get_node(xas, cc_xa_to_node(curr));
			while(__sync_fetch_and_add(&node->gc_flag, 0)){
				//wait for other thread	
			}
			if (__sync_fetch_and_add(&node->del, 0)) {
				printk("node logically deleted! returning null\n");
				return NULL;
			}
			curr = cc_xas_descend(xas, node);
			//cc_xa_put_node(node);
		}
		if (curr) {
			cc_xas_rewind_refcnt(xas);
			return curr;
		}
	}

	if (xas->xa_node->shift > xas->xa_shift) {
		cc_xas_rewind_refcnt(xas);
		return NULL;
	}
	//printk("AH?\n");
	for (;;) {
		if (xas->xa_node->shift == xas->xa_shift) {
			if ((xas->xa_offset & xas->xa_sibs) == xas->xa_sibs)
				break;
		} else if (xas->xa_offset == CC_XA_CHUNK_MASK) {
			xas->xa_offset = xas->xa_node->offset;
			//xas->xa_node = cc_xa_parent_locked(xas->xa, xas->xa_node);
			cc_xas_set_xa_node(xas, cc_xa_parent_locked(xas->xa, xas->xa_node));
			if (!xas->xa_node)
				break;
			continue;
		}
		curr = cc_xa_entry_locked(xas->xa, xas->xa_node, ++xas->xa_offset);
		if (cc_xa_is_sibling(curr))
			continue;
		while (cc_xa_is_node(curr)) {
			//xas->xa_node = cc_xa_to_node(curr);
			cc_xas_set_xa_node(xas, cc_xa_to_node(curr));
			xas->xa_offset = 0;
			curr = cc_xa_entry_locked(xas->xa, xas->xa_node, 0);
		}
		if (curr) {
			cc_xas_rewind_refcnt(xas);
			return curr;
		}
	}
	xas->xa_offset -= xas->xa_sibs;
	cc_xas_rewind_refcnt(xas);
	return NULL;
}
//EXPORT_SYMBOL_GPL(cc_xas_find_conflict);

#if 1
void cc_xa_garbage_collect_entry(struct xarray *xa, void *entry, unsigned long index, unsigned long shift, int *flag)
{
	if (!entry){	
		return;
	}


	if (cc_xa_is_node(entry)) {
		if (shift == 0) {
			//pr_cont("%px\n", entry);
		} else {
			unsigned long i;
			struct xa_node *node = cc_xa_to_node(entry);	
			if (!node->count || node->del){
				struct xa_node *parent;
				parent = node->parent;

				if (!parent) {
					cc_xa_destroy(xa);
					return;
				}
				parent->slots[node->offset] = NULL;
				parent->count--;
				*flag = 0;
				//cc_xa_node_free(node);
				entry = NULL;
				kmem_cache_free(radix_tree_node_cachep, node);
				return;
			}
			//cc_xa_dump_node(node);
			for (i = 0; i < CC_XA_CHUNK_SIZE; i++){
				cc_xa_garbage_collect_entry(xa, node->slots[i],
				      index + (i << node->shift), node->shift, flag);
				if (!cc_xa_head(xa))
					return;
			}
		}
	}
}

/**
 * cc_xa_garbage_collector() - Store this entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Meh -u origin masterory allocation flags.
 *
 * Set NUll to entries that have CC_XA_MARK_DEL marks
 */
void cc_xa_garbage_collector(struct xarray *xa)
{
	void *entry;
	int *flag;
	flag = kmalloc(sizeof(int), GFP_KERNEL);
	for (;;){
		if (xa)
			entry = xa->xa_head;
		else
			return;
		if (!entry){
			//cc_xa_destroy(xa);
			kfree(flag);
			return;
		}
		struct xa_node *node = NULL;
		unsigned int shift = 0;

		if (cc_xa_is_node(entry)) {
			node = cc_xa_to_node(entry);
			shift = node->shift + CC_XA_CHUNK_SHIFT;
		}
		cc_xa_dump(xa);
		*flag = 1;
		cc_xa_garbage_collect_entry(xa, entry, 0, shift, flag);
		if (*flag)
			break;
	}
	kfree(flag);
}
//EXPORT_SYMBOL(cc_xa_garbage_collector);
#endif

/**
 * cc_xa_load() - Load an entry from an XArray.
 * @xa: XArray.
 * @index: index into array.
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: The entry at @index in @xa.
 */
void *cc_xa_load(struct xarray *xa, unsigned long index)
{
	CC_XA_STATE(xas, xa, index);
	void *entry;

	rcu_read_lock();
	do {
		entry = cc_xas_load(&xas, true);
		if (cc_xa_is_zero(entry))
			entry = NULL;
	} while (cc_xas_retry(&xas, entry));
	rcu_read_unlock();
	cc_xas_clear_xa_node(&xas);
	return entry;
}
//EXPORT_SYMBOL(cc_xa_load);

static void *cc_xas_result(struct xa_state *xas, void *curr)
{
	if (cc_xa_is_zero(curr))
		return NULL;
	if (cc_xas_error(xas))
		curr = xas->xa_node;
	return curr;
}

/**
 * __cc_xa_erase() - Erase this entry from the XArray while locked.
 * @xa: XArray.
 * @index: Index into array.
 *
 * After this function returns, loading from @index will return %NULL.
 * If the index is part of a multi-index entry, all indices will be erased
 * and none of the entries will be part of a multi-index entry.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.
 * Return: The entry which used to be at this index.
 */
void *__cc_xa_erase(struct xarray *xa, unsigned long index)
{
	void *result;
	
	CC_XA_STATE(xas, xa, index);
	result = cc_xas_result(&xas, cc_xas_store(&xas, NULL));
	cc_xas_clear_xa_node(&xas);
	return result;
}
//EXPORT_SYMBOL(__cc_xa_erase);

/**
 * cc_xa_erase() - Erase this entry from the XArray.
 * @xa: XArray.
 * @index: Index of entry.
 *
 * After this function returns, loading from @index will return %NULL.
 * If the index is part of a multi-index entry, all indices will be erased
 * and none of the entries will be part of a multi-index entry.
 *
 * Context: Any context.  Takes and releases the xa_lock.
 * Return: The entry which used to be at this index.
 */
void *cc_xa_erase(struct xarray *xa, unsigned long index)
{
	void *entry;

	//xa_lock(xa);
	entry = __cc_xa_erase(xa, index);
	//xa_unlock(xa);

	return entry;
}
//EXPORT_SYMBOL(cc_xa_erase);

/**
 * __cc_xa_store() - Store this entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * You must already be holding the xa_lock when calling this function.
 * It will drop the lock if needed to allocate memory, and then reacquire
 * it afterwards.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.  May
 * release and reacquire xa_lock if @gfp flags permit.
 * Return: The old entry at this index or cc_xa_err() if an error happened.
 */
void *__cc_xa_store(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp)
{
	CC_XA_STATE(xas, xa, index);
	void *curr, *result;

	if (WARN_ON_ONCE(cc_xa_is_advanced(entry)))
		return CC_XA_ERROR(-EINVAL);
	if (cc_xa_track_free(xa) && !entry)
		entry = CC_XA_ZERO_ENTRY;

	do {
		curr = cc_xas_store(&xas, entry);
		if (cc_xa_track_free(xa))
			cc_xas_clear_mark(&xas, CC_XA_FREE_MARK);
	} while (__cc_xas_nomem(&xas, gfp)); 

	result = cc_xas_result(&xas, curr);
	cc_xas_clear_xa_node(&xas);
	return result;
}
//EXPORT_SYMBOL(__cc_xa_store);

/**
 * cc_xa_store() - Store this entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * After this function returns, loads from this index will return @entry.
 * Storing into an existing multi-index entry updates the entry of every index.
 * The marks associated with @index are unaffected unless @entry is %NULL.
 *
 * Context: Any context.  Takes and releases the xa_lock.
 * May sleep if the @gfp flags permit.
 * Return: The old entry at this index on success, cc_xa_err(-EINVAL) if @entry
 * cannot be stored in an XArray, or cc_xa_err(-ENOMEM) if memory allocation
 * failed.
 */
void *cc_xa_store(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp)
{
	void *curr;

	xa_lock(xa);
	curr = __cc_xa_store(xa, index, entry, gfp);
	xa_unlock(xa);

	return curr;
}
//EXPORT_SYMBOL(cc_xa_store);

/**
 * __cc_xa_cmpxchg() - Store this entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @old: Old value to test against.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * You must already be holding the xa_lock when calling this function.
 * It will drop the lock if needed to allocate memory, and then reacquire
 * it afterwards.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.  May
 * release and reacquire xa_lock if @gfp flags permit.
 * Return: The old entry at this index or cc_xa_err() if an error happened.
 */
void *__cc_xa_cmpxchg(struct xarray *xa, unsigned long index,
			void *old, void *entry, gfp_t gfp)
{
	CC_XA_STATE(xas, xa, index);
	void *curr;

	if (WARN_ON_ONCE(cc_xa_is_advanced(entry)))
		return CC_XA_ERROR(-EINVAL);

	do {
		curr = cc_xas_load(&xas, false);
		if (curr == old) {
			cc_xas_store(&xas, entry);
			if (cc_xa_track_free(xa) && entry && !curr)
				cc_xas_clear_mark(&xas, CC_XA_FREE_MARK);
		}
		cc_xas_rewind_refcnt(&xas);
	} while (__cc_xas_nomem(&xas, gfp));

	return cc_xas_result(&xas, curr);
}
//EXPORT_SYMBOL(__cc_xa_cmpxchg);

/**
 * __cc_xa_insert() - Store this entry in the XArray if no entry is present.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * Inserting a NULL entry will store a reserved entry (like cc_xa_reserve())
 * if no entry is present.  Inserting will fail if a reserved entry is
 * present, even though loading from this index will return NULL.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.  May
 * release and reacquire xa_lock if @gfp flags permit.
 * Return: 0 if the store succeeded.  -EBUSY if another entry was present.
 * -ENOMEM if memory could not be allocated.
 */
int __cc_xa_insert(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp)
{
	CC_XA_STATE(xas, xa, index);
	void *curr;
	int result;

	if (WARN_ON_ONCE(cc_xa_is_advanced(entry)))
		return -EINVAL;
	if (!entry)
		entry = CC_XA_ZERO_ENTRY;

	do {
		curr = cc_xas_load(&xas, false);   //check if the node is exist or not?
		if (!curr) {
			cc_xas_store(&xas, entry);
			if (cc_xa_track_free(xa))
				cc_xas_clear_mark(&xas, CC_XA_FREE_MARK);
		} else {
			cc_xas_set_err(&xas, -EBUSY);
		}
		cc_xas_rewind_refcnt(&xas);
	} while (__cc_xas_nomem(&xas, gfp));
	
	result = cc_xas_error(&xas);
	cc_xas_clear_xa_node(&xas);
	return result;
}
//EXPORT_SYMBOL(__cc_xa_insert);

#ifdef CONFIG_XARRAY_MULTI
static void cc_xas_set_range(struct xa_state *xas, unsigned long first,
		unsigned long last)
{
	unsigned int shift = 0;
	unsigned long sibs = last - first;
	unsigned int offset = CC_XA_CHUNK_MASK;

	cc_xas_set(xas, first);

	while ((first & CC_XA_CHUNK_MASK) == 0) {
		if (sibs < CC_XA_CHUNK_MASK)
			break;
		if ((sibs == CC_XA_CHUNK_MASK) && (offset < CC_XA_CHUNK_MASK))
			break;
		shift += CC_XA_CHUNK_SHIFT;
		if (offset == CC_XA_CHUNK_MASK)
			offset = sibs & CC_XA_CHUNK_MASK;
		sibs >>= CC_XA_CHUNK_SHIFT;
		first >>= CC_XA_CHUNK_SHIFT;
	}

	offset = first & CC_XA_CHUNK_MASK;
	if (offset + sibs > CC_XA_CHUNK_MASK)
		sibs = CC_XA_CHUNK_MASK - offset;
	if ((((first + sibs + 1) << shift) - 1) > last)
		sibs -= 1;

	xas->xa_shift = shift;
	xas->xa_sibs = sibs;
}

/**
 * cc_xa_store_range() - Store this entry at a range of indices in the XArray.
 * @xa: XArray.
 * @first: First index to affect.
 * @last: Last index to affect.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * After this function returns, loads from any index between @first and @last,
 * inclusive will return @entry.
 * Storing into an existing multi-index entry updates the entry of every index.
 * The marks associated with @index are unaffected unless @entry is %NULL.
 *
 * Context: Process context.  Takes and releases the xa_lock.  May sleep
 * if the @gfp flags permit.
 * Return: %NULL on success, cc_xa_err(-EINVAL) if @entry cannot be stored in
 * an XArray, or cc_xa_err(-ENOMEM) if memory allocation failed.
 */
void *cc_xa_store_range(struct xarray *xa, unsigned long first,
		unsigned long last, void *entry, gfp_t gfp)
{
	void *result;
	CC_XA_STATE(xas, xa, 0);

	if (WARN_ON_ONCE(cc_xa_is_internal(entry)))
		return CC_XA_ERROR(-EINVAL);
	if (last < first)
		return CC_XA_ERROR(-EINVAL);

	do {
		cc_xas_lock(&xas);
		if (entry) {
			unsigned int order = BITS_PER_LONG;
			if (last + 1)
				order = __ffs(last + 1);
			cc_xas_set_order(&xas, last, order);
			cc_xas_create(&xas, true);
			if (cc_xas_error(&xas))
				goto unlock;
		}
		do {
			cc_xas_set_range(&xas, first, last);
			cc_xas_store(&xas, entry);
			if (cc_xas_error(&xas))
				goto unlock;
			first += cc_xas_size(&xas);
		} while (first <= last);
unlock:
		cc_xas_unlock(&xas);
	} while (cc_xas_nomem(&xas, gfp));

	result = cc_xas_result(&xas, NULL);
	cc_xas_rewind_refcnt(&xas);
	cc_xas_clear_xa_node(&xas);
	return result;
}
//EXPORT_SYMBOL(cc_xa_store_range);

/**
 * cc_xa_get_order() - Get the order of an entry.
 * @xa: XArray.
 * @index: Index of the entry.
 *
 * Return: A number between 0 and 63 indicating the order of the entry.
 */
int cc_xa_get_order(struct xarray *xa, unsigned long index)
{
	CC_XA_STATE(xas, xa, index);
	void *entry;
	int order = 0;

	rcu_read_lock();
	entry = cc_xas_load(&xas, true);

	if (!entry)
		goto unlock;

	if (!xas.xa_node)
		goto unlock;

	for (;;) {
		unsigned int slot = xas.xa_offset + (1 << order);

		if (slot >= CC_XA_CHUNK_SIZE)
			break;
		if (!cc_xa_is_sibling(__sync_fetch_and_add(&xas.xa_node->slots[slot], 0)))
			break;
		order++;
	}

	order += xas.xa_node->shift;
unlock:
	rcu_read_unlock();
	cc_xas_clear_xa_node(&xas);

	return order;
}
//EXPORT_SYMBOL(cc_xa_get_order);
#endif /* CONFIG_XARRAY_MULTI */

/**
 * __cc_xa_alloc() - Find somewhere to store this entry in the XArray.
 * @xa: XArray.
 * @id: Pointer to ID.
 * @limit: Range for allocated ID.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * Finds an empty entry in @xa between @limit.min and @limit.max,
 * stores the index into the @id pointer, then stores the entry at
 * that index.  A concurrent lookup will not see an uninitialised @id.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.  May
 * release and reacquire xa_lock if @gfp flags permit.
 * Return: 0 on success, -ENOMEM if memory could not be allocated or
 * -EBUSY if there are no free entries in @limit.
 */
int __cc_xa_alloc(struct xarray *xa, u32 *id, void *entry,
		struct cc_xa_limit limit, gfp_t gfp)
{
	int result;
	CC_XA_STATE(xas, xa, 0);

	if (WARN_ON_ONCE(cc_xa_is_advanced(entry)))
		return -EINVAL;
	if (WARN_ON_ONCE(!cc_xa_track_free(xa)))
		return -EINVAL;

	if (!entry)
		entry = CC_XA_ZERO_ENTRY;

	do {
		xas.xa_index = limit.min;
		cc_xas_find_marked(&xas, limit.max, CC_XA_FREE_MARK);
		if (xas.xa_node == CC_XAS_RESTART)
			cc_xas_set_err(&xas, -EBUSY);
		else
			*id = xas.xa_index;
		cc_xas_store(&xas, entry);
		cc_xas_clear_mark(&xas, CC_XA_FREE_MARK);
	} while (__cc_xas_nomem(&xas, gfp));

	result = cc_xas_error(&xas);
	cc_xas_clear_xa_node(&xas);
	return result;
}
//EXPORT_SYMBOL(__xa_alloc);

/**
 * __cc_xa_alloc_cyclic() - Find somewhere to store this entry in the XArray.
 * @xa: XArray.
 * @id: Pointer to ID.
 * @entry: New entry.
 * @limit: Range of allocated ID.
 * @next: Pointer to next ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Finds an empty entry in @xa between @limit.min and @limit.max,
 * stores the index into the @id pointer, then stores the entry at
 * that index.  A concurrent lookup will not see an uninitialised @id.
 * The search for an empty entry will start at @next and will wrap
 * around if necessary.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.  May
 * release and reacquire xa_lock if @gfp flags permit.
 * Return: 0 if the allocation succeeded without wrapping.  1 if the
 * allocation succeeded after wrapping, -ENOMEM if memory could not be
 * allocated or -EBUSY if there are no free entries in @limit.
 */
int __cc_xa_alloc_cyclic(struct xarray *xa, u32 *id, void *entry,
		struct cc_xa_limit limit, u32 *next, gfp_t gfp)
{
	u32 min = limit.min;
	int ret;

	limit.min = max(min, *next);
	ret = __cc_xa_alloc(xa, id, entry, limit, gfp);
	if ((xa->xa_flags & CC_XA_FLAGS_ALLOC_WRAPPED) && ret == 0) {
		xa->xa_flags &= ~CC_XA_FLAGS_ALLOC_WRAPPED;
		ret = 1;
	}

	if (ret < 0 && limit.min > min) {
		limit.min = min;
		ret = __cc_xa_alloc(xa, id, entry, limit, gfp);
		if (ret == 0)
			ret = 1;
	}

	if (ret >= 0) {
		*next = *id + 1;
		if (*next == 0)
			xa->xa_flags |= CC_XA_FLAGS_ALLOC_WRAPPED;
	}
	return ret;
}
//EXPORT_SYMBOL(__cc_xa_alloc_cyclic);

/**
 * __cc_xa_set_mark() - Set this mark on this entry while locked.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Attempting to set a mark on a %NULL entry does not succeed.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.
 */
void __cc_xa_set_mark(struct xarray *xa, unsigned long index, cc_xa_mark_t mark)
{
	CC_XA_STATE(xas, xa, index);
	void *entry = cc_xas_load(&xas, true);

	if (entry)
		cc_xas_set_mark(&xas, mark);
	cc_xas_clear_xa_node(&xas);
}
//EXPORT_SYMBOL(__cc_xa_set_mark);

/**
 * __cc_xa_clear_mark() - Clear this mark on this entry while locked.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.
 */
void __cc_xa_clear_mark(struct xarray *xa, unsigned long index, cc_xa_mark_t mark)
{
	CC_XA_STATE(xas, xa, index);
	void *entry = cc_xas_load(&xas, true);

	if (entry)
		cc_xas_clear_mark(&xas, mark);
	cc_xas_clear_xa_node(&xas);
}
//EXPORT_SYMBOL(__cc_xa_clear_mark);

/**
 * cc_xa_get_mark() - Inquire whether this mark is set on this entry.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * This function uses the RCU read lock, so the result may be out of date
 * by the time it returns.  If you need the result to be stable, use a lock.
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: True if the entry at @index has this mark set, false if it doesn't.
 */
bool cc_xa_get_mark(struct xarray *xa, unsigned long index, cc_xa_mark_t mark)
{
	CC_XA_STATE(xas, xa, index);
	void *entry;

	rcu_read_lock();
	entry = cc_xas_start(&xas);
	while (cc_xas_get_mark(&xas, mark)) {
		if (!cc_xa_is_node(entry))
			goto found;
		entry = cc_xas_descend(&xas, cc_xa_to_node(entry));
	}
	rcu_read_unlock();
	cc_xas_clear_xa_node(&xas);
	return false;
 found:
	rcu_read_unlock();
	cc_xas_clear_xa_node(&xas);
	return true;
}
//EXPORT_SYMBOL(cc_xa_get_mark);

/**
 * cc_xa_set_mark() - Set this mark on this entry.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Attempting to set a mark on a %NULL entry does not succeed.
 *
 * Context: Process context.  Takes and releases the xa_lock.
 */
void cc_xa_set_mark(struct xarray *xa, unsigned long index, cc_xa_mark_t mark)
{
	xa_lock(xa);
	__cc_xa_set_mark(xa, index, mark);
	xa_unlock(xa);
}
//EXPORT_SYMBOL(cc_xa_set_mark);

/**
 * cc_xa_clear_mark() - Clear this mark on this entry.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Clearing a mark always succeeds.
 *
 * Context: Process context.  Takes and releases the xa_lock.
 */
void cc_xa_clear_mark(struct xarray *xa, unsigned long index, cc_xa_mark_t mark)
{
	xa_lock(xa);
	__cc_xa_clear_mark(xa, index, mark);
	xa_unlock(xa);
}
//EXPORT_SYMBOL(cc_xa_clear_mark);

/**
 * cc_xa_find() - Search the XArray for an entry.
 * @xa: XArray.
 * @indexp: Pointer to an index.
 * @max: Maximum index to search to.
 * @filter: Selection criterion.
 *
 * Finds the entry in @xa which matches the @filter, and has the lowest
 * index that is at least @indexp and no more than @max.
 * If an entry is found, @indexp is updated to be the index of the entry.
 * This function is protected by the RCU read lock, so it may not find
 * entries which are being simultaneously added.  It will not return an
 * %CC_XA_RETRY_ENTRY; if you need to see retry entries, use cc_xas_find().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: The entry, if found, otherwise %NULL.
 */
void *cc_xa_find(struct xarray *xa, unsigned long *indexp,
			unsigned long max, cc_xa_mark_t filter)
{
	CC_XA_STATE(xas, xa, *indexp);
	void *entry;

	rcu_read_lock();
	do {
		if ((__force unsigned int)filter < CC_XA_MAX_MARKS)
			entry = cc_xas_find_marked(&xas, max, filter);
		else
			entry = cc_xas_find(&xas, max);
	} while (cc_xas_retry(&xas, entry));
	rcu_read_unlock();

	if (entry)
		*indexp = xas.xa_index;
	cc_xas_clear_xa_node(&xas);
	return entry;
}
//EXPORT_SYMBOL(cc_xa_find);

static bool cc_xas_sibling(struct xa_state *xas)
{
	struct xa_node *node = xas->xa_node;
	unsigned long mask;

	if (!node)
		return false;
	mask = (CC_XA_CHUNK_SIZE << node->shift) - 1;
	return (xas->xa_index & mask) >
		((unsigned long)xas->xa_offset << node->shift);
}

#if 0
void cc_xa_garbage_collect_node(const struct xa_node *node){
	if (node -> del)
		xa_node_free(node);
}
#endif

/**
 * cc_xa_find_after() - Search the XArray for a present entry.
 * @xa: XArray.
 * @indexp: Pointer to an index.
 * @max: Maximum index to search to.
 * @filter: Selection criterion.
 *
 * Finds the entry in @xa which matches the @filter and has the lowest
 * index that is above @indexp and no more than @max.
 * If an entry is found, @indexp is updated to be the index of the entry.
 * This function is protected by the RCU read lock, so it may miss entries
 * which are being simultaneously added.  It will not return an
 * %CC_XA_RETRY_ENTRY; if you need to see retry entries, use cc_xas_find().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: The pointer, if found, otherwise %NULL.
 */
void *cc_xa_find_after(struct xarray *xa, unsigned long *indexp,
			unsigned long max, cc_xa_mark_t filter)
{
	CC_XA_STATE(xas, xa, *indexp + 1);
	void *entry;

	if (xas.xa_index == 0)
		return NULL;

	rcu_read_lock();
	for (;;) {
		if ((__force unsigned int)filter < CC_XA_MAX_MARKS)
			entry = cc_xas_find_marked(&xas, max, filter);
		else
			entry = cc_xas_find(&xas, max);

		if (cc_xas_invalid(&xas))
			break;
		if (cc_xas_sibling(&xas))
			continue;
		if (!cc_xas_retry(&xas, entry))
			break;
	}
	rcu_read_unlock();

	if (entry)
		*indexp = xas.xa_index;
	cc_xas_clear_xa_node(&xas);
	return entry;
}
//EXPORT_SYMBOL(cc_xa_find_after);

static unsigned int cc_xas_extract_present(struct xa_state *xas, void **dst,
			unsigned long max, unsigned int n)
{
	void *entry;
	unsigned int i = 0;

	rcu_read_lock();
	cc_xas_for_each(xas, entry, max) {
		if (cc_xas_retry(xas, entry))
			continue;
		dst[i++] = entry;
		if (i == n)
			break;
	}
	rcu_read_unlock();
	cc_xas_clear_xa_node(xas);

	return i;
}

static unsigned int cc_xas_extract_marked(struct xa_state *xas, void **dst,
			unsigned long max, unsigned int n, cc_xa_mark_t mark)
{
	void *entry;
	unsigned int i = 0;

	rcu_read_lock();
	cc_xas_for_each_marked(xas, entry, max, mark) {
		if (cc_xas_retry(xas, entry))
			continue;
		dst[i++] = entry;
		if (i == n)
			break;
	}
	rcu_read_unlock();
	cc_xas_clear_xa_node(xas);

	return i;
}

/**
 * cc_xa_extract() - Copy selected entries from the XArray into a normal array.
 * @xa: The source XArray to copy from.
 * @dst: The buffer to copy entries into.
 * @start: The first index in the XArray eligible to be selected.
 * @max: The last index in the XArray eligible to be selected.
 * @n: The maximum number of entries to copy.
 * @filter: Selection criterion.
 *
 * Copies up to @n entries that match @filter from the XArray.  The
 * copied entries will have indices between @start and @max, inclusive.
 *
 * The @filter may be an XArray mark value, in which case entries which are
 * marked with that mark will be copied.  It may also be %cc_xa_PRESENT, in
 * which case all entries which are not %NULL will be copied.
 *
 * The entries returned may not represent a snapshot of the XArray at a
 * moment in time.  For example, if another thread stores to index 5, then
 * index 10, calling cc_xa_extract() may return the old contents of index 5
 * and the new contents of index 10.  Indices not modified while this
 * function is running will not be skipped.
 *
 * If you need stronger guarantees, holding the xa_lock across calls to this
 * function will prevent concurrent modification.
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: The number of entries copied.
 */
unsigned int cc_xa_extract(struct xarray *xa, void **dst, unsigned long start,
			unsigned long max, unsigned int n, cc_xa_mark_t filter)
{
	CC_XA_STATE(xas, xa, start);

	if (!n)
		return 0;

	if ((__force unsigned int)filter < CC_XA_MAX_MARKS)
		return cc_xas_extract_marked(&xas, dst, max, n, filter);
	return cc_xas_extract_present(&xas, dst, max, n);
}
//EXPORT_SYMBOL(cc_xa_extract);

/**
 * cc_xa_destroy() - Free all internal data structures.
 * @xa: XArray.
 *
 * After calling this function, the XArray is empty and has freed all memory
 * allocated for its internal data structures.  You are responsible for
 * freeing the objects referenced by the XArray.
 *
 * Context: Any context.  Takes and releases the xa_lock, interrupt-safe.
 */
void cc_xa_destroy(struct xarray *xa)
{
	CC_XA_STATE(xas, xa, 0);
	unsigned long flags;
	void *entry;

	xas.xa_node = NULL;
	cc_xas_lock_irqsave(&xas, flags);
	entry = cc_xa_head_locked(xa);
	RCU_INIT_POINTER(xa->xa_head, NULL);
	cc_xas_init_marks(&xas);
	if (cc_xa_zero_busy(xa))
		cc_xa_mark_clear(xa, CC_XA_FREE_MARK);
	/* lockdep checks we're still holding the lock in cc_xas_free_nodes() */
	if (cc_xa_is_node(entry))
		cc_xas_free_nodes(&xas, cc_xa_to_node(entry));
	cc_xas_unlock_irqrestore(&xas, flags);
	cc_xas_clear_xa_node(&xas);
}
//EXPORT_SYMBOL(cc_xa_destroy);

//#ifdef cc_xa_DEBUG
void cc_xa_dump_node(const struct xa_node *node)
{
	unsigned i, j;

	if (!node)
		return;
	if ((unsigned long)node & 3) {
		pr_cont("node %px\n", node);
		return;
	}

	pr_cont("node @%px %s %d parent @%px shift %d count %d values %d "
		"array @%px list @%px @%px marks",
		node, node->parent ? "offset" : "max", node->offset,
		node->parent, node->shift, node->count, node->nr_values,
		node->array, node->private_list.prev, node->private_list.next);
	for (i = 0; i < CC_XA_MAX_MARKS; i++)
		for (j = 0; j < CC_XA_MARK_LONGS; j++)
			pr_cont(" %lx", node->marks[i][j]);
	pr_cont(" gc_flag %d del %d refcnt %hu", 
			node->gc_flag, node->del, node->refcnt);
	pr_cont("\n");
}

void cc_xa_dump_index(unsigned long index, unsigned int shift)
{
	if (!shift)
		pr_info("%lu: ", index);
	else if (shift >= BITS_PER_LONG)
		pr_info("0-%lu: ", ~0UL);
	else
		pr_info("%lu-%lu: ", index, index | ((1UL << shift) - 1));
}

void cc_xa_dump_entry(const void *entry, unsigned long index, unsigned long shift)
{
	if (!entry)
		return;

	cc_xa_dump_index(index, shift);

	if (cc_xa_is_node(entry)) {
		if (shift == 0) {
			pr_cont("%px\n", entry);
		} else {
			unsigned long i;
			struct xa_node *node = cc_xa_to_node(entry);
			cc_xa_dump_node(node);
			pr_info("Check size = %d \n", XA_CHUNK_SIZE);
			for (i = 0; i < XA_CHUNK_SIZE; i++)
				cc_xa_dump_entry(&node->slots[i],
				      index + (i << node->shift), node->shift);
		}
	} else if (cc_xa_is_value(entry))
		pr_cont("value %ld (0x%lx) [%px]\n", cc_xa_to_value(entry),
						cc_xa_to_value(entry), entry);
	else if (!cc_xa_is_internal(entry))
		pr_cont("%px\n", entry);
	else if (cc_xa_is_retry(entry))
		pr_cont("retry (%ld)\n", cc_xa_to_internal(entry));
	else if (cc_xa_is_sibling(entry))
		pr_cont("sibling (slot %ld)\n", cc_xa_to_sibling(entry));
	else if (cc_xa_is_zero(entry))
		pr_cont("zero (%ld)\n", cc_xa_to_internal(entry));
	else
		pr_cont("UNKNOWN ENTRY (%px)\n", entry);
}

void cc_xa_dump(const struct xarray *xa)
{
	void *entry = cc_xa_head(xa);
	unsigned int shift = 0;

	pr_info("xarray: %px head %px flags %x marks %d %d %d\n", xa, entry,
			xa->xa_flags, cc_xa_marked(xa, CC_XA_MARK_0),
			cc_xa_marked(xa, CC_XA_MARK_1), cc_xa_marked(xa, CC_XA_MARK_2));
	if (cc_xa_is_node(entry))
		shift = cc_xa_to_node(entry)->shift + CC_XA_CHUNK_SHIFT;
	cc_xa_dump_entry(entry, 0, shift);
}
//#endif
