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
#include "lf_xarray.h"

#include <linux/xarray.h>

/*
 * Coding conventions in this file:
 *
 * @xa is used to refer to the entire xarray.
 * @xas is the 'xarray operation state'.  It may be either a pointer to
 * an xa_state, or an xa_state stored on the stack.  This is an unfortunate
 * ambiguity.
 * @index is the index of the entry being operated on
 * @mark is an lf_xa_mark_t; a small number indicating one of the mark bits.
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

static inline void lf_xas_lock_type(struct xa_state *xas, unsigned int lock_type)
{
	if (lock_type == LF_XA_LOCK_IRQ)
		lf_xas_lock_irq(xas);
	else if (lock_type == LF_XA_LOCK_BH)
		lf_xas_lock_bh(xas);
	else
		lf_xas_lock(xas);
}

static inline void lf_xas_unlock_type(struct xa_state *xas, unsigned int lock_type)
{
	if (lock_type == LF_XA_LOCK_IRQ)
		lf_xas_unlock_irq(xas);
	else if (lock_type == LF_XA_LOCK_BH)
		lf_xas_unlock_bh(xas);
	else
		lf_xas_unlock(xas);
}

static inline bool lf_xa_track_free(const struct xarray *xa)
{
	return xa->xa_flags & LF_XA_FLAGS_TRACK_FREE;
}

static inline bool lf_xa_zero_busy(const struct xarray *xa)
{
	return xa->xa_flags & LF_XA_FLAGS_ZERO_BUSY;
}

static inline void lf_xa_mark_set(struct xarray *xa, lf_xa_mark_t mark)
{
	if (!(xa->xa_flags & LF_XA_FLAGS_MARK(mark)))
		xa->xa_flags |= LF_XA_FLAGS_MARK(mark);
}

static inline void lf_xa_mark_clear(struct xarray *xa, lf_xa_mark_t mark)
{
	if (xa->xa_flags & LF_XA_FLAGS_MARK(mark))
		xa->xa_flags &= ~(LF_XA_FLAGS_MARK(mark));
}

static inline unsigned long *node_marks(struct xa_node *node, lf_xa_mark_t mark)
{
	return node->marks[(__force unsigned)mark];
}

static inline bool node_get_mark(struct xa_node *node,
		unsigned int offset, lf_xa_mark_t mark)
{
	return test_bit(offset, node_marks(node, mark));
}

/* returns true if the bit was set */
static inline bool node_set_mark(struct xa_node *node, unsigned int offset,
				lf_xa_mark_t mark)
{
	return __test_and_set_bit(offset, node_marks(node, mark));
}

/* returns true if the bit was set */
static inline bool node_clear_mark(struct xa_node *node, unsigned int offset,
				lf_xa_mark_t mark)
{
	return __test_and_clear_bit(offset, node_marks(node, mark));
}

static inline bool node_any_mark(struct xa_node *node, lf_xa_mark_t mark)
{
	return !bitmap_empty(node_marks(node, mark), LF_XA_CHUNK_SIZE);
}

static inline void node_mark_all(struct xa_node *node, lf_xa_mark_t mark)
{
	bitmap_fill(node_marks(node, mark), LF_XA_CHUNK_SIZE);
}

#if 0
static inline bool logical_delete(struct xa_node *node)
{
	return __test_and_set_bit(node->del, 1);
}
#endif 

#define mark_inc(mark) do { \
	mark = (__force lf_xa_mark_t)((__force unsigned)(mark) + 1); \
} while (0)

/*
 * lf_xas_squash_marks() - Merge all marks to the first entry
 * @xas: Array operation state.
 * 
 * Set a mark on the first entry if any entry has it set.  Clear marks on
 * all sibling entries.
 */
static void lf_xas_squash_marks(const struct xa_state *xas)
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
	} while (mark++ != (__force unsigned)LF_XA_MARK_MAX);
}

/* extracts the offset within this node from the index */
static unsigned int get_offset(unsigned long index, struct xa_node *node)
{
	return (index >> node->shift) & LF_XA_CHUNK_MASK;
}

static void lf_xas_set_offset(struct xa_state *xas)
{
	xas->xa_offset = get_offset(xas->xa_index, xas->xa_node);
}

/* move the index either forwards (find) or backwards (sibling slot) */
static void lf_xas_move_index(struct xa_state *xas, unsigned long offset)
{
	unsigned int shift = xas->xa_node->shift;
	xas->xa_index &= ~LF_XA_CHUNK_MASK << shift;
	xas->xa_index += offset << shift;
}

static void lf_xas_advance(struct xa_state *xas)
{
	xas->xa_offset++;
	lf_xas_move_index(xas, xas->xa_offset);
}

static void *set_bounds(struct xa_state *xas)
{
	xas->xa_node = LF_XAS_BOUNDS;
	return NULL;
}

/*
 * Starts a walk.  If the @xas is already valid, we assume that it's on
 * the right path and just return where we've got to.  If we're in an
 * error state, return NULL.  If the index is outside the current scope
 * of the xarray, return NULL without changing @xas->xa_node.  Otherwise
 * set @xas->xa_node to NULL and return the current head of the array.
 */
static void *lf_xas_start(struct xa_state *xas)
{
	void *entry;

	if (lf_xas_valid(xas))
		return lf_xas_reload(xas);
	if (lf_xas_error(xas))
		return NULL;

	entry = xa_head(xas->xa);
	if (!lf_xa_is_node(entry)) {
		if (xas->xa_index)
			return set_bounds(xas);
	} else {
		if ((xas->xa_index >> lf_xa_to_node(entry)->shift) > LF_XA_CHUNK_MASK)
			return set_bounds(xas);
	}

	xas->xa_node = NULL;
	return entry;
}

static void *lf_xas_descend(struct xa_state *xas, struct xa_node *node)
{
	unsigned int offset = get_offset(xas->xa_index, node);
	void *entry = lf_xa_entry(xas->xa, node, offset);

	xas->xa_node = node;
	if (lf_xa_is_sibling(entry)) {
		offset = lf_xa_to_sibling(entry);
		entry = lf_xa_entry(xas->xa, node, offset);
	}

	xas->xa_offset = offset;
	return entry;
}

/**
 * lf_xas_load() - Load an entry from the XArray (advanced).
 * @xas: XArray operation state.
 *
 * Usually walks the @xas to the appropriate state to load the entry
 * stored at xa_index.  However, it will do nothing and return %NULL if
 * @xas is in an error state.  lf_xas_load() will never expand the tree.
 *
 * If the xa_state is set up to operate on a multi-index entry, lf_xas_load()
 * may return %NULL or an internal entry, even if there are entries
 * present within the range specified by @xas.
 *
 * Context: Any context.  The caller should hold the xa_lock or the RCU lock.
 * Return: Usually an entry in the XArray, but see description for exceptions.
 */


void *lf_xas_load(struct xa_state *xas)
{
	void *entry = lf_xas_start(xas);

	while (lf_xa_is_node(entry)) {
		struct xa_node *node = lf_xa_to_node(entry);

		if (__sync_fetch_and_add(&node->del, 0) == 1)	// logically deleted
			return NULL;
		if (xas->xa_shift > node->shift)
			break;
		entry = lf_xas_descend(xas, node);
		if (node->shift == 0)				// reached leaf node
			break;
	}
	return entry;
}
//EXPORT_SYMBOL_GPL(lf_xas_load);

/* Move the radix tree node cache here */
extern struct kmem_cache *radix_tree_node_cachep;
extern void radix_tree_node_rcu_free(struct rcu_head *head);

#define LF_XA_RCU_FREE	((struct xarray *)1)

static void xa_node_free(struct xa_node *node)
{
	LF_XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
	node->array = LF_XA_RCU_FREE;
	call_rcu(&node->rcu_head, radix_tree_node_rcu_free);
}

/*
 * lf_xas_destroy() - Free any resources allocated during the XArray operation.
 * @xas: XArray operation state.
 *
 * This function is now internal-only.
 */
static void lf_xas_destroy(struct xa_state *xas)
{
	struct xa_node *next, *node = xas->xa_alloc;

	while (node) {
		LF_XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
		next = rcu_dereference_raw(node->parent);
		radix_tree_node_rcu_free(&node->rcu_head);
		xas->xa_alloc = node = next;
	}
}

/**
 * lf_xas_nomem() - Allocate memory if needed.
 * @xas: XArray operation state.
 * @gfp: Memory allocation flags.
 *
 * If we need to add new nodes to the XArray, we try to allocate memory
 * with GFP_NOWAIT while holding the lock, which will usually succeed.
 * If it fails, @xas is flagged as needing memory to continue.  The caller
 * should drop the lock and call lf_xas_nomem().  If lf_xas_nomem() succeeds,
 * the caller should retry the operation.
 *
 * Forward progress is guaranteed as one node is allocated here and
 * stored in the xa_state where it will be found by lf_xas_alloc().  More
 * nodes will likely be found in the slab allocator, but we do not tie
 * them up here.
 *
 * Return: true if memory was needed, and was successfully allocated.
 */
bool lf_xas_nomem(struct xa_state *xas, gfp_t gfp)
{
	if (xas->xa_node != LF_XA_ERROR(-ENOMEM)) {
		lf_xas_destroy(xas);
		return false;
	}
	if (xas->xa->xa_flags & LF_XA_FLAGS_ACCOUNT)
		gfp |= __GFP_ACCOUNT;
	xas->xa_alloc = kmem_cache_alloc(radix_tree_node_cachep, gfp);
	if (!xas->xa_alloc)
		return false;
	xas->xa_alloc->parent = NULL;
	LF_XA_NODE_BUG_ON(xas->xa_alloc, !list_empty(&xas->xa_alloc->private_list));
	xas->xa_node = LF_XAS_RESTART;
	return true;
}
//EXPORT_SYMBOL_GPL(lf_xas_nomem);

/*
 * __lf_xas_nomem() - Drop locks and allocate memory if needed.
 * @xas: XArray operation state.
 * @gfp: Memory allocation flags.
 *
 * Internal variant of lf_xas_nomem().
 *
 * Return: true if memory was needed, and was successfully allocated.
 */
static bool __lf_xas_nomem(struct xa_state *xas, gfp_t gfp)
	__must_hold(xas->xa->xa_lock)
{
	unsigned int lock_type = xa_lock_type(xas->xa);

	if (xas->xa_node != LF_XA_ERROR(-ENOMEM)) {
		lf_xas_destroy(xas);
		return false;
	}
	if (xas->xa->xa_flags & LF_XA_FLAGS_ACCOUNT)
		gfp |= __GFP_ACCOUNT;
	if (gfpflags_allow_blocking(gfp)) {
		lf_xas_unlock_type(xas, lock_type);
		xas->xa_alloc = kmem_cache_alloc(radix_tree_node_cachep, gfp);
		lf_xas_lock_type(xas, lock_type);
	} else {
		xas->xa_alloc = kmem_cache_alloc(radix_tree_node_cachep, gfp);
	}
	if (!xas->xa_alloc)
		return false;
	xas->xa_alloc->parent = NULL;
	LF_XA_NODE_BUG_ON(xas->xa_alloc, !list_empty(&xas->xa_alloc->private_list));
	xas->xa_node = LF_XAS_RESTART;
	return true;
}

static void lf_xas_update(struct xa_state *xas, struct xa_node *node)
{
	if (xas->xa_update)
		xas->xa_update(node);
	else
		LF_XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
}

static void *lf_xas_alloc(struct xa_state *xas, unsigned int shift)
{
	struct xa_node *parent = xas->xa_node;
	struct xa_node *node = xas->xa_alloc;

	if (lf_xas_invalid(xas))
		return NULL;

	if (node) {
		xas->xa_alloc = NULL;
	} else {
		gfp_t gfp = GFP_NOWAIT | __GFP_NOWARN;

		if (xas->xa->xa_flags & LF_XA_FLAGS_ACCOUNT)
			gfp |= __GFP_ACCOUNT;

		node = kmem_cache_alloc(radix_tree_node_cachep, gfp); 
		if (!node) {
			lf_xas_set_err(xas, -ENOMEM);
			return NULL;
		}
	}

	if (parent) {
		node->offset = xas->xa_offset;
		parent->count++;
		LF_XA_NODE_BUG_ON(node, parent->count > LF_XA_CHUNK_SIZE);
		lf_xas_update(xas, parent);
	}
	LF_XA_NODE_BUG_ON(node, shift > BITS_PER_LONG);
	LF_XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
	node->shift = shift;
	node->count = 0;
	node->nr_values = 0;
	RCU_INIT_POINTER(node->parent, xas->xa_node);
	node->array = xas->xa;

	return node;
}

#ifdef CONFIG_XARRAY_MULTI
/* Returns the number of indices covered by a given xa_state */
static unsigned long lf_xas_size(const struct xa_state *xas)
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
static unsigned long lf_xas_max(struct xa_state *xas)
{
	unsigned long max = xas->xa_index;

#ifdef CONFIG_XARRAY_MULTI
	if (xas->xa_shift || xas->xa_sibs) {
		unsigned long mask = lf_xas_size(xas) - 1;
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
	if (!lf_xa_is_node(entry))
		return 0;
	return (LF_XA_CHUNK_SIZE << lf_xa_to_node(entry)->shift) - 1;
}

static void lf_xas_shrink(struct xa_state *xas)
{
	struct xarray *xa = xas->xa;
	struct xa_node *node = xas->xa_node;

	for (;;) {
		void *entry;

		LF_XA_NODE_BUG_ON(node, node->count > LF_XA_CHUNK_SIZE);
		if (node->count != 1)
			break;
		//entry = lf_xa_entry_locked(xa, node, 0);
		entry = lf_xa_entry(xa, node, 0);
		if (!entry)
			break;
		if (!lf_xa_is_node(entry) && node->shift)
			break;
		if (lf_xa_is_zero(entry) && lf_xa_zero_busy(xa))
			entry = NULL;
		xas->xa_node = LF_XAS_BOUNDS;

		RCU_INIT_POINTER(xa->xa_head, entry);
		if (lf_xa_track_free(xa) && !node_get_mark(node, 0, LF_XA_FREE_MARK))
			lf_xa_mark_clear(xa, LF_XA_FREE_MARK);

		node->count = 0;
		node->nr_values = 0;
		if (!lf_xa_is_node(entry))
			RCU_INIT_POINTER(node->slots[0], LF_XA_RETRY_ENTRY);
		lf_xas_update(xas, node);
		//xa_node_free(node);
		
		/*
		if (!logical_delete (node))
			pr_debug("Error !");
		*/

		if (!lf_xa_is_node(entry))
			break;
		node = lf_xa_to_node(entry);
		node->parent = NULL;
	}
}

/*
 * lf_xas_delete_node() - Attempt to delete an xa_node
 * @xas: Array operation state.
 *
 * Attempts to delete the @xas->xa_node.  This will fail if xa->node has
 * a non-zero reference count.
 */
static void lf_xas_delete_node(struct xa_state *xas)
{
	struct xa_node *node = xas->xa_node;
	unsigned char deleted = __sync_fetch_and_add(&node->del, 0);

	for (;;) {
		struct xa_node *parent;
		unsigned char node_cnt, parent_cnt;

		node_cnt = __sync_fetch_and_add(&node->count, 0);
		LF_XA_NODE_BUG_ON(node, node_cnt > LF_XA_CHUNK_SIZE);
		if (deleted || node_cnt)
			break;

		if (__sync_bool_compare_and_swap(&node->del, deleted, 
					!__sync_fetch_and_add(&node->count, 0)))
			break;

		parent = __sync_fetch_and_add(&node->parent, 0);
		xas->xa_node = parent;
		xas->xa_offset = node->offset;
		//xa_node_free(node);

		if (!parent) {
			//xas->xa->xa_head = NULL;
			xas->xa_node = LF_XAS_BOUNDS;
			return;
		}

		//parent->slots[xas->xa_offset] = NULL;
		parent_cnt = __sync_sub_and_fetch(&parent->count, 1);
		LF_XA_NODE_BUG_ON(parent, parent_cnt > LF_XA_CHUNK_SIZE);
		node = parent;
		deleted = __sync_fetch_and_add(&node->del, 0);
		lf_xas_update(xas, node);
	}

	//if (!node->parent)
	//	lf_xas_shrink(xas);
}

/**
 * lf_xas_free_nodes() - Free this node and all nodes that it references
 * @xas: Array operation state.
 * @top: Node to free
 *
 * This node has been removed from the tree.  We must now free it and all
 * of its subnodes.  There may be RCU walkers with references into the tree,
 * so we must replace all entries with retry markers.
 */
static void lf_xas_free_nodes(struct xa_state *xas, struct xa_node *top)
{
	unsigned int offset = 0;
	struct xa_node *node = top;

	for (;;) {
		void *entry = lf_xa_entry_locked(xas->xa, node, offset);

		if (node->shift && lf_xa_is_node(entry)) {
			node = lf_xa_to_node(entry);
			offset = 0;
			continue;
		}
		if (entry)
			RCU_INIT_POINTER(node->slots[offset], LF_XA_RETRY_ENTRY);
		offset++;
		while (offset == LF_XA_CHUNK_SIZE) {
			struct xa_node *parent;

			parent = lf_xa_parent_locked(xas->xa, node);
			offset = node->offset + 1;
			node->count = 0;
			node->nr_values = 0;
			lf_xas_update(xas, node);
			xa_node_free(node);
			if (node == top)
				return;
			node = parent;
		}
	}
}

/*
 * lf_xas_expand adds nodes to the head of the tree until it has reached
 * sufficient height to be able to contain @xas->xa_index
 */
static int lf_xas_expand(struct xa_state *xas, void *head)
{
	struct xarray *xa = xas->xa;
	struct xa_node *node = NULL, *tmp_node;
	unsigned int shift = 0;
	unsigned long max = lf_xas_max(xas);
	void *tmp_head;

	if (!head) {
		if (max == 0)
			return 0;
		while ((max >> shift) >= LF_XA_CHUNK_SIZE)
			shift += LF_XA_CHUNK_SHIFT;
		return shift + LF_XA_CHUNK_SHIFT;
	} else if (lf_xa_is_node(head)) {
		node = lf_xa_to_node(head);
		shift = node->shift + LF_XA_CHUNK_SHIFT;
	}
	xas->xa_node = NULL;

	while (max > max_index(head)) { 
		lf_xa_mark_t mark = 0;

		LF_XA_NODE_BUG_ON(node, shift > BITS_PER_LONG);
		node = lf_xas_alloc(xas, shift); // alloc new node
		if (!node)
			return -ENOMEM;

		node->count = 1;
		if (lf_xa_is_value(head))
			node->nr_values = 1;
		RCU_INIT_POINTER(node->slots[0], head);

		/* Propagate the aggregated mark info to the new child */
		for (;;) {
			if (lf_xa_track_free(xa) && mark == LF_XA_FREE_MARK) {
				node_mark_all(node, LF_XA_FREE_MARK);
				if (!lf_xa_marked(xa, LF_XA_FREE_MARK)) {
					node_clear_mark(node, 0, LF_XA_FREE_MARK);
					lf_xa_mark_set(xa, LF_XA_FREE_MARK);
				}
			} else if (lf_xa_marked(xa, mark)) {
				node_set_mark(node, 0, mark);
			}
			if (mark == LF_XA_MARK_MAX)
				break;
			mark_inc(mark);
		}

		/*
		 * Now that the new node is fully initialised, we can add
		 * it to the tree
		 */
		if (lf_xa_is_node(head)) {
			lf_xa_to_node(head)->offset = 0;
			//rcu_assign_pointer(lf_xa_to_node(head)->parent, node); 
			// Perform CAS
			tmp_node = lf_xa_to_node(head)->parent;
			if (tmp_node != NULL || !__sync_bool_compare_and_swap(
				    &lf_xa_to_node(head)->parent, tmp_node, node)) {
				struct xa_node *parent = __sync_fetch_and_add(
						&lf_xa_to_node(head)->parent, 0);
				xa_node_free(node);
				head = lf_xa_mk_node(parent);
				goto ascend;
			}
		}
		// Perform CAS
		tmp_head = head;
		head = lf_xa_mk_node(node);
		//rcu_assign_pointer(xa->xa_head, head);
		if (!__sync_bool_compare_and_swap(&xa->xa_head, tmp_head, head)) {
			xa_node_free(node);
			head = __sync_fetch_and_add(&xa->xa_head, 0);
			goto ascend;
		}
		lf_xas_update(xas, node);
ascend:
		shift += LF_XA_CHUNK_SHIFT;
	}

	xas->xa_node = node;
	return shift;
}

/*
 * lf_xas_create() - Create a slot to store an entry in.
 * @xas: XArray operation state.
 * @allow_root: %true if we can store the entry in the root directly
 *
 * Most users will not need to call this function directly, as it is called
 * by lf_xas_store().  It is useful for doing conditional store operations
 * (see the lf_xa_cmpxchg() implementation for an example).
 *
 * Return: If the slot already existed, returns the contents of this slot.
 * If the slot was newly created, returns %NULL.  If it failed to create the
 * slot, returns %NULL and indicates the error in @xas.
 */
static void *lf_xas_create(struct xa_state *xas, bool allow_root)
{
	struct xarray *xa = xas->xa;
	void *entry, *temp;
	void __rcu **slot;
	struct xa_node *node = xas->xa_node;
	int shift;
	unsigned int order = xas->xa_shift;

	if (lf_xas_top(node)) { 
		//entry = xa_head_locked(xa); 
		entry = __sync_fetch_and_add(&xa->xa_head, 0); 
		xas->xa_node = NULL;
		if (!entry && lf_xa_zero_busy(xa))
			entry = LF_XA_ZERO_ENTRY;
		shift = lf_xas_expand(xas, entry);
		if (shift < 0)
			return NULL;
		if (!shift && !allow_root)
			shift = LF_XA_CHUNK_SHIFT;
		entry = xa_head_locked(xa);
		slot = &xa->xa_head;
	} else if (lf_xas_error(xas)) {
		return NULL;
	} else if (node) {
		unsigned int offset = xas->xa_offset;

		shift = node->shift;
		entry = lf_xa_entry_locked(xa, node, offset);
		slot = &node->slots[offset];
	} else {
		shift = 0;
		entry = xa_head_locked(xa);
		slot = &xa->xa_head;
	}

	while (shift > order) {
		shift -= LF_XA_CHUNK_SHIFT;
		if (!entry) {
			node = lf_xas_alloc(xas, shift);
			if (!node)
				break;
			if (lf_xa_track_free(xa))
				node_mark_all(node, LF_XA_FREE_MARK);
			//rcu_assign_pointer(*slot, lf_xa_mk_node(node));
			temp = entry;
			if (!__sync_bool_compare_and_swap(
					    slot, temp, lf_xa_mk_node(node))) {
				xa_node_free(node);
				node = lf_xa_to_node(*slot);
				goto descend;
			}
		} else if (lf_xa_is_node(entry)) {
			node = lf_xa_to_node(entry);
			if (__sync_fetch_and_add(&node->del, 0) == 1) {
				struct xa_node *parent = node->parent;
				if (parent)
					__sync_fetch_and_add(&parent->count, 1);
				__sync_lock_test_and_set(&node->del, 0);
			}
		} else {
			break;
		}
descend:
		entry = lf_xas_descend(xas, node);
		slot = &node->slots[xas->xa_offset];
	}

	return entry;
}

/**
 * lf_xas_create_range() - Ensure that stores to this range will succeed
 * @xas: XArray operation state.
 *
 * Creates all of the slots in the range covered by @xas.  Sets @xas to
 * create single-index entries and positions it at the beginning of the
 * range.  This is for the benefit of users which have not yet been
 * converted to use multi-index entries.
 */
void lf_xas_create_range(struct xa_state *xas)
{
	unsigned long index = xas->xa_index;
	unsigned char shift = xas->xa_shift;
	unsigned char sibs = xas->xa_sibs;

	xas->xa_index |= ((sibs + 1) << shift) - 1;
	if (lf_xas_is_node(xas) && xas->xa_node->shift == xas->xa_shift)
		xas->xa_offset |= sibs;
	xas->xa_shift = 0;
	xas->xa_sibs = 0;

	for (;;) {
		lf_xas_create(xas, true);
		if (lf_xas_error(xas))
			goto restore;
		if (xas->xa_index <= (index | LF_XA_CHUNK_MASK))
			goto success;
		xas->xa_index -= LF_XA_CHUNK_SIZE;

		for (;;) {
			struct xa_node *node = xas->xa_node;
			xas->xa_node = lf_xa_parent_locked(xas->xa, node);
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
		lf_xas_set_offset(xas);
}
//EXPORT_SYMBOL_GPL(lf_xas_create_range);

static void update_node(struct xa_state *xas, struct xa_node *node,
		int count, int values)
{
	if (!node || (!count && !values))
		return;

	// node->count += count;
	// node->nr_values += values;
	__sync_fetch_and_add(&node->count, count);
	__sync_fetch_and_add(&node->nr_values, values);
	LF_XA_NODE_BUG_ON(node, node->count > LF_XA_CHUNK_SIZE);
	LF_XA_NODE_BUG_ON(node, node->nr_values > LF_XA_CHUNK_SIZE);
	lf_xas_update(xas, node);
	// if (count < 0)
	// 	lf_xas_delete_node(xas);
	if (count < 0)
	{
		if (!node->del){
	 		__sync_fetch_and_add(&node->del, 1);
	 	}
			
	}


	if (node->del){
		if (count > 0)
			__sync_fetch_and_sub(&node->del, 1);
	}
}

/**
 * lf_xas_store() - Store this entry in the XArray.
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
void *lf_xas_store(struct xa_state *xas, void *entry)
{
	struct xa_node *node;
	void __rcu **slot = &xas->xa->xa_head;
	unsigned int offset, max;
	int count = 0;
	int values = 0;
	void *first, *next;
	bool value = lf_xa_is_value(entry);
	void *temp = xas->xa->xa_head;

	if (entry) {
		// entry is not node and not error -> then the new node could be root
		bool allow_root = !lf_xa_is_node(entry) && !lf_xa_is_zero(entry);
		first = lf_xas_create(xas, allow_root); // create slot to move pointer in
	} else {
		first = lf_xas_load(xas);		// if entry is NULL -> no store?
	}

	if (lf_xas_invalid(xas))
		return first;
	node = xas->xa_node;
	if (node && (xas->xa_shift < node->shift))
		xas->xa_sibs = 0;
	if ((first == entry) && !xas->xa_sibs)
		return first;

	next = first;
	offset = xas->xa_offset;		// update offset, the slot mask
	max = xas->xa_offset + xas->xa_sibs;	// max number of leaves
	if (node) {
		slot = &node->slots[offset];	// get slot pointer
		if (xas->xa_sibs)
			lf_xas_squash_marks(xas);
	}
	if (!entry)
		lf_xas_init_marks(xas);

	for (;;) {
		/*
		 * Must clear the marks before setting the entry to NULL,
		 * otherwise lf_xas_for_each_marked may find a NULL entry and
		 * stop early.  rcu_assign_pointer contains a release barrier
		 * so the mark clearing will appear to happen before the
		 * entry is set to NULL.
		 */
		if (node)
			temp = node->slots[offset];
			
		while (!__sync_bool_compare_and_swap(slot, temp, entry)) {
			if (node)
				temp = node->slots[offset];
		}

		if (lf_xa_is_node(next) && (!node || node->shift))
			lf_xas_free_nodes(xas, lf_xa_to_node(next));
		if (!node)
			break;
		count += !next - !entry;
		values += !lf_xa_is_value(first) - !value;
		if (entry) {
			if (offset == max)
				break;
			if (!lf_xa_is_sibling(entry))
				entry = lf_xa_mk_sibling(xas->xa_offset);
		} else {
			if (offset == LF_XA_CHUNK_MASK)
				break;
		}
		//next = lf_xa_entry_locked(xas->xa, node, ++offset);
		next = node->slots[++offset];
		if (!lf_xa_is_sibling(next)) {
			if (!entry && (offset > max))
				break;
			first = next;
		}
		//slot++;
		__sync_fetch_and_add(&slot, 1);
	}

	update_node(xas, node, count, values);
	//lf_xa_dump_node(node);
	return first;
}
//EXPORT_SYMBOL_GPL(lf_xas_store);

/**
 * lf_xas_get_mark() - Returns the state of this mark.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Return: true if the mark is set, false if the mark is clear or @xas
 * is in an error state.
 */
bool lf_xas_get_mark(const struct xa_state *xas, lf_xa_mark_t mark)
{
	if (lf_xas_invalid(xas))
		return false;
	if (!xas->xa_node)
		return lf_xa_marked(xas->xa, mark);
	return node_get_mark(xas->xa_node, xas->xa_offset, mark);
}
//EXPORT_SYMBOL_GPL(lf_xas_get_mark);

/**
 * lf_xas_set_mark() - Sets the mark on this entry and its parents.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Sets the specified mark on this entry, and walks up the tree setting it
 * on all the ancestor entries.  Does nothing if @xas has not been walked to
 * an entry, or is in an error state.
 */
void lf_xas_set_mark(const struct xa_state *xas, lf_xa_mark_t mark)
{
	struct xa_node *node = xas->xa_node;
	unsigned int offset = xas->xa_offset;

	if (lf_xas_invalid(xas))
		return;

	while (node) {
		if (node_set_mark(node, offset, mark))
			return;
		offset = node->offset;
		node = lf_xa_parent_locked(xas->xa, node);
	}

	if (!lf_xa_marked(xas->xa, mark))
		lf_xa_mark_set(xas->xa, mark);
}
//EXPORT_SYMBOL_GPL(lf_xas_set_mark);

/**
 * lf_xas_clear_mark() - Clears the mark on this entry and its parents.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Clears the specified mark on this entry, and walks back to the head
 * attempting to clear it on all the ancestor entries.  Does nothing if
 * @xas has not been walked to an entry, or is in an error state.
 */
void lf_xas_clear_mark(const struct xa_state *xas, lf_xa_mark_t mark)
{
	struct xa_node *node = xas->xa_node;
	unsigned int offset = xas->xa_offset;

	if (lf_xas_invalid(xas))
		return;

	while (node) {
		if (!node_clear_mark(node, offset, mark))
			return;
		if (node_any_mark(node, mark))
			return;

		offset = node->offset;
		node = lf_xa_parent_locked(xas->xa, node);
	}

	if (lf_xa_marked(xas->xa, mark))
		lf_xa_mark_clear(xas->xa, mark);
}
//EXPORT_SYMBOL_GPL(lf_xas_clear_mark);

/**
 * lf_xas_init_marks() - Initialise all marks for the entry
 * @xas: Array operations state.
 *
 * Initialise all marks for the entry specified by @xas.  If we're tracking
 * free entries with a mark, we need to set it on all entries.  All other
 * marks are cleared.
 *
 * This implementation is not as efficient as it could be; we may walk
 * up the tree multiple times.
 */
void lf_xas_init_marks(const struct xa_state *xas)
{
	lf_xa_mark_t mark = 0;

	for (;;) {
		if (lf_xa_track_free(xas->xa) && mark == LF_XA_FREE_MARK)
			lf_xas_set_mark(xas, mark);
		else
			lf_xas_clear_mark(xas, mark);
		if (mark == LF_XA_MARK_MAX)
			break;
		mark_inc(mark);
	}
}
//EXPORT_SYMBOL_GPL(lf_xas_init_marks);

#ifdef CONFIG_XARRAY_MULTI
static unsigned int node_get_marks(struct xa_node *node, unsigned int offset)
{
	unsigned int marks = 0;
	lf_xa_mark_t mark = LF_XA_MARK_0;

	for (;;) {
		if (node_get_mark(node, offset, mark))
			marks |= 1 << (__force unsigned int)mark;
		if (mark == LF_XA_MARK_MAX)
			break;
		mark_inc(mark);
	}

	return marks;
}

static void node_set_marks(struct xa_node *node, unsigned int offset,
			struct xa_node *child, unsigned int marks)
{
	lf_xa_mark_t mark = LF_XA_MARK_0;

	for (;;) {
		if (marks & (1 << (__force unsigned int)mark)) {
			node_set_mark(node, offset, mark);
			if (child)
				node_mark_all(child, mark);
		}
		if (mark == LF_XA_MARK_MAX)
			break;
		mark_inc(mark);
	}
}

/**
 * lf_xas_split_alloc() - Allocate memory for splitting an entry.
 * @xas: XArray operation state.
 * @entry: New entry which will be stored in the array.
 * @order: New entry order.
 * @gfp: Memory allocation flags.
 *
 * This function should be called before calling lf_xas_split().
 * If necessary, it will allocate new nodes (and fill them with @entry)
 * to prepare for the upcoming split of an entry of @order size into
 * entries of the order stored in the @xas.
 *
 * Context: May sleep if @gfp flags permit.
 */
void lf_xas_split_alloc(struct xa_state *xas, void *entry, unsigned int order,
		gfp_t gfp)
{
	unsigned int sibs = (1 << (order % LF_XA_CHUNK_SHIFT)) - 1;
	unsigned int mask = xas->xa_sibs;

	/* XXX: no support for splitting really large entries yet */
	if (WARN_ON(xas->xa_shift + 2 * LF_XA_CHUNK_SHIFT < order))
		goto nomem;
	if (xas->xa_shift + LF_XA_CHUNK_SHIFT > order)
		return;

	do {
		unsigned int i;
		void *sibling;
		struct xa_node *node;

		node = kmem_cache_alloc(radix_tree_node_cachep, gfp);
		if (!node)
			goto nomem;
		node->array = xas->xa;
		for (i = 0; i < LF_XA_CHUNK_SIZE; i++) {
			if ((i & mask) == 0) {
				RCU_INIT_POINTER(node->slots[i], entry);
				sibling = lf_xa_mk_sibling(0);
			} else {
				RCU_INIT_POINTER(node->slots[i], sibling);
			}
		}
		RCU_INIT_POINTER(node->parent, xas->xa_alloc);
		xas->xa_alloc = node;
	} while (sibs-- > 0);

	return;
nomem:
	lf_xas_destroy(xas);
	lf_xas_set_err(xas, -ENOMEM);
}
//EXPORT_SYMBOL_GPL(lf_xas_split_alloc);

/**
 * lf_xas_split() - Split a multi-index entry into smaller entries.
 * @xas: XArray operation state.
 * @entry: New entry to store in the array.
 * @order: New entry order.
 *
 * The value in the entry is copied to all the replacement entries.
 *
 * Context: Any context.  The caller should hold the xa_lock.
 */
void lf_xas_split(struct xa_state *xas, void *entry, unsigned int order)
{
	unsigned int sibs = (1 << (order % LF_XA_CHUNK_SHIFT)) - 1;
	unsigned int offset, marks;
	struct xa_node *node;
	void *curr = lf_xas_load(xas);
	int values = 0;

	node = xas->xa_node;
	if (lf_xas_top(node))
		return;

	marks = node_get_marks(node, xas->xa_offset);

	offset = xas->xa_offset + sibs;
	do {
		if (xas->xa_shift < node->shift) {
			struct xa_node *child = xas->xa_alloc;

			xas->xa_alloc = rcu_dereference_raw(child->parent);
			child->shift = node->shift - LF_XA_CHUNK_SHIFT;
			child->offset = offset;
			child->count = LF_XA_CHUNK_SIZE;
			child->nr_values = lf_xa_is_value(entry) ?
					LF_XA_CHUNK_SIZE : 0;
			RCU_INIT_POINTER(child->parent, node);
			node_set_marks(node, offset, child, marks);
			rcu_assign_pointer(node->slots[offset],
					lf_xa_mk_node(child));
			if (lf_xa_is_value(curr))
				values--;
		} else {
			unsigned int canon = offset - xas->xa_sibs;

			node_set_marks(node, canon, NULL, marks);
			rcu_assign_pointer(node->slots[canon], entry);
			while (offset > canon)
				rcu_assign_pointer(node->slots[offset--],
						lf_xa_mk_sibling(canon));
			values += (lf_xa_is_value(entry) - lf_xa_is_value(curr)) *
					(xas->xa_sibs + 1);
		}
	} while (offset-- > xas->xa_offset);

	node->nr_values += values;
}
//EXPORT_SYMBOL_GPL(lf_xas_split);
#endif

/**
 * lf_xas_pause() - Pause a walk to drop a lock.
 * @xas: XArray operation state.
 *
 * Some users need to pause a walk and drop the lock they're holding in
 * order to yield to a higher priority thread or carry out an operation
 * on an entry.  Those users should call this function before they drop
 * the lock.  It resets the @xas to be suitable for the next iteration
 * of the loop after the user has reacquired the lock.  If most entries
 * found during a walk require you to call lf_xas_pause(), the lf_xa_for_each()
 * iterator may be more appropriate.
 *
 * Note that lf_xas_pause() only works for forward iteration.  If a user needs
 * to pause a reverse iteration, we will need a lf_xas_pause_rev().
 */
void lf_xas_pause(struct xa_state *xas)
{
	struct xa_node *node = xas->xa_node;

	if (lf_xas_invalid(xas))
		return;

	xas->xa_node = LF_XAS_RESTART;
	if (node) {
		unsigned long offset = xas->xa_offset;
		while (++offset < LF_XA_CHUNK_SIZE) {
			if (!lf_xa_is_sibling(lf_xa_entry(xas->xa, node, offset)))
				break;
		}
		xas->xa_index += (offset - xas->xa_offset) << node->shift;
		if (xas->xa_index == 0)
			xas->xa_node = LF_XAS_BOUNDS;
	} else {
		xas->xa_index++;
	}
}
//EXPORT_SYMBOL_GPL(lf_xas_pause);

/*
 * __lf_xas_prev() - Find the previous entry in the XArray.
 * @xas: XArray operation state.
 *
 * Helper function for lf_xas_prev() which handles all the complex cases
 * out of line.
 */
void *__lf_xas_prev(struct xa_state *xas)
{
	void *entry;

	if (!lf_xas_frozen(xas->xa_node))
		xas->xa_index--;
	if (!xas->xa_node)
		return set_bounds(xas);
	if (lf_xas_not_node(xas->xa_node))
		return lf_xas_load(xas);

	if (xas->xa_offset != get_offset(xas->xa_index, xas->xa_node))
		xas->xa_offset--;

	while (xas->xa_offset == 255) {
		xas->xa_offset = xas->xa_node->offset - 1;
		xas->xa_node = lf_xa_parent(xas->xa, xas->xa_node);
		if (!xas->xa_node)
			return set_bounds(xas);
	}

	for (;;) {
		entry = lf_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
		if (!lf_xa_is_node(entry))
			return entry;

		xas->xa_node = lf_xa_to_node(entry);
		lf_xas_set_offset(xas);
	}
}
//EXPORT_SYMBOL_GPL(__lf_xas_prev);

/*
 * __lf_xas_next() - Find the next entry in the XArray.
 * @xas: XArray operation state.
 *
 * Helper function for lf_xas_next() which handles all the complex cases
 * out of line.
 */
void *__lf_xas_next(struct xa_state *xas)
{
	void *entry;

	if (!lf_xas_frozen(xas->xa_node))
		xas->xa_index++;
	if (!xas->xa_node)
		return set_bounds(xas);
	if (lf_xas_not_node(xas->xa_node))
		return lf_xas_load(xas);

	if (xas->xa_offset != get_offset(xas->xa_index, xas->xa_node))
		xas->xa_offset++;

	while (xas->xa_offset == LF_XA_CHUNK_SIZE) {
		xas->xa_offset = xas->xa_node->offset + 1;
		xas->xa_node = lf_xa_parent(xas->xa, xas->xa_node);
		if (!xas->xa_node)
			return set_bounds(xas);
	}

	for (;;) {
		entry = lf_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
		if (!lf_xa_is_node(entry))
			return entry;

		xas->xa_node = lf_xa_to_node(entry);
		lf_xas_set_offset(xas);
	}
}
//EXPORT_SYMBOL_GPL(__lf_xas_next);

/**
 * lf_xas_find() - Find the next present entry in the XArray.
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
 * to be immediately passed to lf_xas_store().
 *
 * Return: The entry, if found, otherwise %NULL.
 */
void *lf_xas_find(struct xa_state *xas, unsigned long max)
{
	void *entry;

	if (lf_xas_error(xas) || xas->xa_node == LF_XAS_BOUNDS)
		return NULL;
	if (xas->xa_index > max)
		return set_bounds(xas);

	if (!xas->xa_node) {
		xas->xa_index = 1;
		return set_bounds(xas);
	} else if (xas->xa_node == LF_XAS_RESTART) {
		entry = lf_xas_load(xas);
		if (entry || lf_xas_not_node(xas->xa_node))
			return entry;
	} else if (!xas->xa_node->shift &&
		    xas->xa_offset != (xas->xa_index & LF_XA_CHUNK_MASK)) {
		xas->xa_offset = ((xas->xa_index - 1) & LF_XA_CHUNK_MASK) + 1;
	}

	lf_xas_advance(xas);

	while (xas->xa_node && (xas->xa_index <= max)) {
		if (unlikely(xas->xa_offset == LF_XA_CHUNK_SIZE)) {
			xas->xa_offset = xas->xa_node->offset + 1;
			xas->xa_node = lf_xa_parent(xas->xa, xas->xa_node);
			continue;
		}

		entry = lf_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
		if (lf_xa_is_node(entry)) {
			xas->xa_node = lf_xa_to_node(entry);
			xas->xa_offset = 0;
			continue;
		}
		if (entry && !lf_xa_is_sibling(entry))
			return entry;

		lf_xas_advance(xas);
	}

	if (!xas->xa_node)
		xas->xa_node = LF_XAS_BOUNDS;
	return NULL;
}
//EXPORT_SYMBOL_GPL(lf_xas_find);

/**
 * lf_xas_find_marked() - Find the next marked entry in the XArray.
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
 * lf_xas_store().
 *
 * If no entry is found before @max is reached, @xas is set to the restart
 * state.
 *
 * Return: The entry, if found, otherwise %NULL.
 */
void *lf_xas_find_marked(struct xa_state *xas, unsigned long max, lf_xa_mark_t mark)
{
	bool advance = true;
	unsigned int offset;
	void *entry;

	if (lf_xas_error(xas))
		return NULL;
	if (xas->xa_index > max)
		goto max;

	if (!xas->xa_node) {
		xas->xa_index = 1;
		goto out;
	} else if (lf_xas_top(xas->xa_node)) {
		advance = false;
		entry = xa_head(xas->xa);
		xas->xa_node = NULL;
		if (xas->xa_index > max_index(entry))
			goto out;
		if (!lf_xa_is_node(entry)) {
			if (lf_xa_marked(xas->xa, mark))
				return entry;
			xas->xa_index = 1;
			goto out;
		}
		xas->xa_node = lf_xa_to_node(entry);
		xas->xa_offset = xas->xa_index >> xas->xa_node->shift;
	}

	while (xas->xa_index <= max) {
		if (unlikely(xas->xa_offset == LF_XA_CHUNK_SIZE)) {
			xas->xa_offset = xas->xa_node->offset + 1;
			xas->xa_node = lf_xa_parent(xas->xa, xas->xa_node);
			if (!xas->xa_node)
				break;
			advance = false;
			continue;
		}

		if (!advance) {
			entry = lf_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
			if (lf_xa_is_sibling(entry)) {
				xas->xa_offset = lf_xa_to_sibling(entry);
				lf_xas_move_index(xas, xas->xa_offset);
			}
		}

		offset = lf_xas_find_chunk(xas, advance, mark);
		if (offset > xas->xa_offset) {
			advance = false;
			lf_xas_move_index(xas, offset);
			/* Mind the wrap */
			if ((xas->xa_index - 1) >= max)
				goto max;
			xas->xa_offset = offset;
			if (offset == LF_XA_CHUNK_SIZE)
				continue;
		}

		entry = lf_xa_entry(xas->xa, xas->xa_node, xas->xa_offset);
		if (!entry && !(lf_xa_track_free(xas->xa) && mark == LF_XA_FREE_MARK))
			continue;
		if (!lf_xa_is_node(entry))
			return entry;
		xas->xa_node = lf_xa_to_node(entry);
		lf_xas_set_offset(xas);
	}

out:
	if (xas->xa_index > max)
		goto max;
	return set_bounds(xas);
max:
	xas->xa_node = LF_XAS_RESTART;
	return NULL;
}
//EXPORT_SYMBOL_GPL(lf_xas_find_marked);

/**
 * lf_xas_find_conflict() - Find the next present entry in a range.
 * @xas: XArray operation state.
 *
 * The @xas describes both a range and a position within that range.
 *
 * Context: Any context.  Expects xa_lock to be held.
 * Return: The next entry in the range covered by @xas or %NULL.
 */
void *lf_xas_find_conflict(struct xa_state *xas)
{
	void *curr;

	if (lf_xas_error(xas))
		return NULL;

	if (!xas->xa_node)
		return NULL;

	if (lf_xas_top(xas->xa_node)) {
		curr = lf_xas_start(xas);
		if (!curr)
			return NULL;
		while (lf_xa_is_node(curr)) {
			struct xa_node *node = lf_xa_to_node(curr);
			curr = lf_xas_descend(xas, node);
		}
		if (curr)
			return curr;
	}

	if (xas->xa_node->shift > xas->xa_shift)
		return NULL;

	for (;;) {
		if (xas->xa_node->shift == xas->xa_shift) {
			if ((xas->xa_offset & xas->xa_sibs) == xas->xa_sibs)
				break;
		} else if (xas->xa_offset == LF_XA_CHUNK_MASK) {
			xas->xa_offset = xas->xa_node->offset;
			xas->xa_node = lf_xa_parent_locked(xas->xa, xas->xa_node);
			if (!xas->xa_node)
				break;
			continue;
		}
		curr = lf_xa_entry_locked(xas->xa, xas->xa_node, ++xas->xa_offset);
		if (lf_xa_is_sibling(curr))
			continue;
		while (lf_xa_is_node(curr)) {
			xas->xa_node = lf_xa_to_node(curr);
			xas->xa_offset = 0;
			//curr = lf_xa_entry_locked(xas->xa, xas->xa_node, 0);
			curr = lf_xa_entry(xas->xa, xas->xa_node, 0);
		}
		if (curr)
			return curr;
	}
	xas->xa_offset -= xas->xa_sibs;
	return NULL;
}
//EXPORT_SYMBOL_GPL(lf_xas_find_conflict);

void lf_xa_garbage_collect_entry(struct xarray *xa, void *entry, unsigned long index, unsigned long shift, int *flag)
{
	if (!entry){	
		return;
	}


	if (lf_xa_is_node(entry)) {
		if (shift == 0) {
			//pr_cont("%px\n", entry);
		} else {
			unsigned long i;
			struct xa_node *node = lf_xa_to_node(entry);	
			if (!node->count || node->del){
				struct xa_node *parent;
				parent = node->parent;

				if (!parent) {
					lf_xa_destroy(xa);
					return;
				}
				parent->slots[node->offset] = NULL;
				parent->count--;
				*flag = 0;
				//lf_xa_node_free(node);
				entry = NULL;
				kmem_cache_free(radix_tree_node_cachep, node);
				return;
			}
			//lf_xa_dump_node(node);
			for (i = 0; i < LF_XA_CHUNK_SIZE; i++){
				lf_xa_garbage_collect_entry(xa, node->slots[i],
				      index + (i << node->shift), node->shift, flag);
				if (!xa->xa_head)
					return;
			}
		}
	}
}

/**
 * lf_xa_garbage_collector() - Store this entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * Set NUll to entries that have LF_XA_MARK_DEL marks
 */
void lf_xa_garbage_collector(struct xarray *xa)
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
			//lf_xa_destroy(xa);
			kfree(flag);
			return;
		}
		struct xa_node *node = NULL;
		unsigned int shift = 0;

		if (lf_xa_is_node(entry)) {
			node = lf_xa_to_node(entry);
			shift = node->shift + LF_XA_CHUNK_SHIFT;
		}
		lf_xa_dump(xa);
		*flag = 1;
		lf_xa_garbage_collect_entry(xa, entry, 0, shift, flag);
		if (*flag)
			break;
	}
	kfree(flag);
}
//EXPORT_SYMBOL(lf_xa_garbage_collector);


/**
 * lf_xa_load() - Load an entry from an XArray.
 * @xa: XArray.
 * @index: index into array.
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: The entry at @index in @xa.
 */
void *lf_xa_load(struct xarray *xa, unsigned long index)
{
	XA_STATE(xas, xa, index);
	void *entry;

	//rcu_read_lock();
	do {
		entry = lf_xas_load(&xas);
		if (lf_xa_is_zero(entry))
			entry = NULL;
	} while (lf_xas_retry(&xas, entry));
	//rcu_read_unlock();
	return entry;
}
//EXPORT_SYMBOL(lf_xa_load);

static void *lf_xas_result(struct xa_state *xas, void *curr)
{
	if (lf_xa_is_zero(curr))
		return NULL;
	if (lf_xas_error(xas))
		curr = xas->xa_node;
	return curr;
}

/**
 * __lf_xa_erase() - Erase this entry from the XArray while locked.
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
void *__lf_xa_erase(struct xarray *xa, unsigned long index)
{
	XA_STATE(xas, xa, index);
	return lf_xas_result(&xas, lf_xas_store(&xas, NULL));
}
//EXPORT_SYMBOL(__lf_xa_erase);

/**
 * lf_xa_erase() - Erase this entry from the XArray.   //kiet : index vs entry?
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
void *lf_xa_erase(struct xarray *xa, unsigned long index)
{
	void *entry;

	//xa_lock(xa);
	entry = __lf_xa_erase(xa, index);
	//lf_xa_unlock(xa);

	return entry;
}
//EXPORT_SYMBOL(lf_xa_erase);

/**
 * __lf_xa_store() - Store this entry in the XArray.
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
 * Return: The old entry at this index or lf_xa_err() if an error happened.
 */
void *__lf_xa_store(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp)
{
	XA_STATE(xas, xa, index);
	void *curr;

	if (WARN_ON_ONCE(lf_xa_is_advanced(entry)))
		return LF_XA_ERROR(-EINVAL);
	if (lf_xa_track_free(xa) && !entry)
		entry = LF_XA_ZERO_ENTRY;

	do {
		curr = lf_xas_store(&xas, entry);
		if (lf_xa_track_free(xa))
			lf_xas_clear_mark(&xas, LF_XA_FREE_MARK);
	} while (__lf_xas_nomem(&xas, gfp)); 

	return lf_xas_result(&xas, curr);
}
//EXPORT_SYMBOL(__lf_xa_store);

/**
 * lf_xa_store() - Store this entry in the XArray.
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
 * Return: The old entry at this index on success, lf_xa_err(-EINVAL) if @entry
 * cannot be stored in an XArray, or lf_xa_err(-ENOMEM) if memory allocation
 * failed.
 */
void *lf_xa_store(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp)
{
	void *curr;

	//xa_lock(xa);
	curr = __lf_xa_store(xa, index, entry, gfp);
	//lf_xa_unlock(xa);

	return curr;
}
//EXPORT_SYMBOL(lf_xa_store);

/**
 * __lf_xa_cmpxchg() - Store this entry in the XArray.
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
 * Return: The old entry at this index or lf_xa_err() if an error happened.
 */
void *__lf_xa_cmpxchg(struct xarray *xa, unsigned long index,
			void *old, void *entry, gfp_t gfp)
{
	XA_STATE(xas, xa, index);
	void *curr;

	if (WARN_ON_ONCE(lf_xa_is_advanced(entry)))
		return LF_XA_ERROR(-EINVAL);

	do {
		curr = lf_xas_load(&xas);
		if (curr == old) {
			lf_xas_store(&xas, entry);
			if (lf_xa_track_free(xa) && entry && !curr)
				lf_xas_clear_mark(&xas, LF_XA_FREE_MARK);
		}
	} while (__lf_xas_nomem(&xas, gfp));

	return lf_xas_result(&xas, curr);
}
//EXPORT_SYMBOL(__lf_xa_cmpxchg);

/**
 * __lf_xa_insert() - Store this entry in the XArray if no entry is present.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * Inserting a NULL entry will store a reserved entry (like lf_xa_reserve())
 * if no entry is present.  Inserting will fail if a reserved entry is
 * present, even though loading from this index will return NULL.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.  May
 * release and reacquire xa_lock if @gfp flags permit.
 * Return: 0 if the store succeeded.  -EBUSY if another entry was present.
 * -ENOMEM if memory could not be allocated.
 */
int __lf_xa_insert(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp)
{
	XA_STATE(xas, xa, index);
	void *curr;

	if (WARN_ON_ONCE(lf_xa_is_advanced(entry)))
		return -EINVAL;
	if (!entry)
		entry = LF_XA_ZERO_ENTRY;

	do {
		curr = lf_xas_load(&xas);   //check if the node is exist or not?
		if (!curr) {
			lf_xas_store(&xas, entry);
			if (lf_xa_track_free(xa))
				lf_xas_clear_mark(&xas, LF_XA_FREE_MARK);
		} else {
			lf_xas_set_err(&xas, -EBUSY);
		}
	} while (__lf_xas_nomem(&xas, gfp));
	
	return lf_xas_error(&xas);
}
//EXPORT_SYMBOL(__lf_xa_insert);

#ifdef CONFIG_XARRAY_MULTI
static void lf_xas_set_range(struct xa_state *xas, unsigned long first,
		unsigned long last)
{
	unsigned int shift = 0;
	unsigned long sibs = last - first;
	unsigned int offset = LF_XA_CHUNK_MASK;

	lf_xas_set(xas, first);

	while ((first & LF_XA_CHUNK_MASK) == 0) {
		if (sibs < LF_XA_CHUNK_MASK)
			break;
		if ((sibs == LF_XA_CHUNK_MASK) && (offset < LF_XA_CHUNK_MASK))
			break;
		shift += LF_XA_CHUNK_SHIFT;
		if (offset == LF_XA_CHUNK_MASK)
			offset = sibs & LF_XA_CHUNK_MASK;
		sibs >>= LF_XA_CHUNK_SHIFT;
		first >>= LF_XA_CHUNK_SHIFT;
	}

	offset = first & LF_XA_CHUNK_MASK;
	if (offset + sibs > LF_XA_CHUNK_MASK)
		sibs = LF_XA_CHUNK_MASK - offset;
	if ((((first + sibs + 1) << shift) - 1) > last)
		sibs -= 1;

	xas->xa_shift = shift;
	xas->xa_sibs = sibs;
}

/**
 * lf_xa_store_range() - Store this entry at a range of indices in the XArray.
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
 * Return: %NULL on success, lf_xa_err(-EINVAL) if @entry cannot be stored in
 * an XArray, or lf_xa_err(-ENOMEM) if memory allocation failed.
 */
void *lf_xa_store_range(struct xarray *xa, unsigned long first,
		unsigned long last, void *entry, gfp_t gfp)
{
	XA_STATE(xas, xa, 0);

	if (WARN_ON_ONCE(lf_xa_is_internal(entry)))
		return LF_XA_ERROR(-EINVAL);
	if (last < first)
		return LF_XA_ERROR(-EINVAL);

	do {
		lf_xas_lock(&xas);
		if (entry) {
			unsigned int order = BITS_PER_LONG;
			if (last + 1)
				order = __ffs(last + 1);
			lf_xas_set_order(&xas, last, order);
			lf_xas_create(&xas, true);
			if (lf_xas_error(&xas))
				goto unlock;
		}
		do {
			lf_xas_set_range(&xas, first, last);
			lf_xas_store(&xas, entry);
			if (lf_xas_error(&xas))
				goto unlock;
			first += lf_xas_size(&xas);
		} while (first <= last);
unlock:
		lf_xas_unlock(&xas);
	} while (lf_xas_nomem(&xas, gfp));

	return lf_xas_result(&xas, NULL);
}
//EXPORT_SYMBOL(lf_xa_store_range);

/**
 * lf_xa_get_order() - Get the order of an entry.
 * @xa: XArray.
 * @index: Index of the entry.
 *
 * Return: A number between 0 and 63 indicating the order of the entry.
 */
int lf_xa_get_order(struct xarray *xa, unsigned long index)
{
	XA_STATE(xas, xa, index);
	void *entry;
	int order = 0;

	rcu_read_lock();
	entry = lf_xas_load(&xas);

	if (!entry)
		goto unlock;

	if (!xas.xa_node)
		goto unlock;

	for (;;) {
		unsigned int slot = xas.xa_offset + (1 << order);

		if (slot >= LF_XA_CHUNK_SIZE)
			break;
		if (!lf_xa_is_sibling(xas.xa_node->slots[slot]))
			break;
		order++;
	}

	order += xas.xa_node->shift;
unlock:
	rcu_read_unlock();

	return order;
}
//EXPORT_SYMBOL(lf_xa_get_order);
#endif /* CONFIG_XARRAY_MULTI */

/**
 * __k_lf_xa_alloc() - Find somewhere to store this entry in the XArray.
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
int __k_lf_xa_alloc(struct xarray *xa, u32 *id, void *entry,
		struct lf_xa_limit limit, gfp_t gfp)
{
	XA_STATE(xas, xa, 0);

	if (WARN_ON_ONCE(lf_xa_is_advanced(entry)))
		return -EINVAL;
	if (WARN_ON_ONCE(!lf_xa_track_free(xa)))
		return -EINVAL;

	if (!entry)
		entry = LF_XA_ZERO_ENTRY;

	do {
		xas.xa_index = limit.min;
		lf_xas_find_marked(&xas, limit.max, LF_XA_FREE_MARK);
		if (xas.xa_node == LF_XAS_RESTART)
			lf_xas_set_err(&xas, -EBUSY);
		else
			*id = xas.xa_index;
		lf_xas_store(&xas, entry);
		lf_xas_clear_mark(&xas, LF_XA_FREE_MARK);
	} while (__lf_xas_nomem(&xas, gfp));

	return lf_xas_error(&xas);
}
//EXPORT_SYMBOL(__xa_alloc);

/**
 * __lf_xa_alloc_cyclic() - Find somewhere to store this entry in the XArray.
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
int __lf_xa_alloc_cyclic(struct xarray *xa, u32 *id, void *entry,
		struct lf_xa_limit limit, u32 *next, gfp_t gfp)
{
	u32 min = limit.min;
	int ret;

	limit.min = max(min, *next);
	ret = __k_lf_xa_alloc(xa, id, entry, limit, gfp);
	if ((xa->xa_flags & LF_XA_FLAGS_ALLOC_WRAPPED) && ret == 0) {
		xa->xa_flags &= ~LF_XA_FLAGS_ALLOC_WRAPPED;
		ret = 1;
	}

	if (ret < 0 && limit.min > min) {
		limit.min = min;
		ret = __k_lf_xa_alloc(xa, id, entry, limit, gfp);
		if (ret == 0)
			ret = 1;
	}

	if (ret >= 0) {
		*next = *id + 1;
		if (*next == 0)
			xa->xa_flags |= LF_XA_FLAGS_ALLOC_WRAPPED;
	}
	return ret;
}
//EXPORT_SYMBOL(__lf_xa_alloc_cyclic);

/**
 * __lf_xa_set_mark() - Set this mark on this entry while locked.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Attempting to set a mark on a %NULL entry does not succeed.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.
 */
void __lf_xa_set_mark(struct xarray *xa, unsigned long index, lf_xa_mark_t mark)
{
	XA_STATE(xas, xa, index);
	void *entry = lf_xas_load(&xas);

	if (entry)
		lf_xas_set_mark(&xas, mark);
}
//EXPORT_SYMBOL(__lf_xa_set_mark);

/**
 * __lf_xa_clear_mark() - Clear this mark on this entry while locked.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.
 */
void __lf_xa_clear_mark(struct xarray *xa, unsigned long index, lf_xa_mark_t mark)
{
	XA_STATE(xas, xa, index);
	void *entry = lf_xas_load(&xas);

	if (entry)
		lf_xas_clear_mark(&xas, mark);
}
//EXPORT_SYMBOL(__lf_xa_clear_mark);

/**
 * lf_xa_get_mark() - Inquire whether this mark is set on this entry.
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
bool lf_xa_get_mark(struct xarray *xa, unsigned long index, lf_xa_mark_t mark)
{
	XA_STATE(xas, xa, index);
	void *entry;

	rcu_read_lock();
	entry = lf_xas_start(&xas);
	while (lf_xas_get_mark(&xas, mark)) {
		if (!lf_xa_is_node(entry))
			goto found;
		entry = lf_xas_descend(&xas, lf_xa_to_node(entry));
	}
	rcu_read_unlock();
	return false;
 found:
	rcu_read_unlock();
	return true;
}
//EXPORT_SYMBOL(lf_xa_get_mark);

/**
 * lf_xa_set_mark() - Set this mark on this entry.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Attempting to set a mark on a %NULL entry does not succeed.
 *
 * Context: Process context.  Takes and releases the xa_lock.
 */
void lf_xa_set_mark(struct xarray *xa, unsigned long index, lf_xa_mark_t mark)
{
	xa_lock(xa);
	__lf_xa_set_mark(xa, index, mark);
	lf_xa_unlock(xa);
}
//EXPORT_SYMBOL(lf_xa_set_mark);

/**
 * lf_xa_clear_mark() - Clear this mark on this entry.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Clearing a mark always succeeds.
 *
 * Context: Process context.  Takes and releases the xa_lock.
 */
void lf_xa_clear_mark(struct xarray *xa, unsigned long index, lf_xa_mark_t mark)
{
	xa_lock(xa);
	__lf_xa_clear_mark(xa, index, mark);
	lf_xa_unlock(xa);
}
//EXPORT_SYMBOL(lf_xa_clear_mark);

/**
 * lf_xa_find() - Search the XArray for an entry.
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
 * %LF_XA_RETRY_ENTRY; if you need to see retry entries, use lf_xas_find().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: The entry, if found, otherwise %NULL.
 */
void *lf_xa_find(struct xarray *xa, unsigned long *indexp,
			unsigned long max, lf_xa_mark_t filter)
{
	XA_STATE(xas, xa, *indexp);
	void *entry;

	rcu_read_lock();
	do {
		if ((__force unsigned int)filter < LF_XA_MAX_MARKS)
			entry = lf_xas_find_marked(&xas, max, filter);
		else
			entry = lf_xas_find(&xas, max);
	} while (lf_xas_retry(&xas, entry));
	rcu_read_unlock();

	if (entry)
		*indexp = xas.xa_index;
	return entry;
}
//EXPORT_SYMBOL(lf_xa_find);

static bool lf_xas_sibling(struct xa_state *xas)
{
	struct xa_node *node = xas->xa_node;
	unsigned long mask;

	if (!node)
		return false;
	mask = (LF_XA_CHUNK_SIZE << node->shift) - 1;
	return (xas->xa_index & mask) >
		((unsigned long)xas->xa_offset << node->shift);
}

#if 0
void lf_xa_garbage_collect_node(const struct xa_node *node){
	if (node -> del)
		xa_node_free(node);
}
#endif

/**
 * lf_xa_find_after() - Search the XArray for a present entry.
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
 * %LF_XA_RETRY_ENTRY; if you need to see retry entries, use lf_xas_find().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: The pointer, if found, otherwise %NULL.
 */
void *lf_xa_find_after(struct xarray *xa, unsigned long *indexp,
			unsigned long max, lf_xa_mark_t filter)
{
	XA_STATE(xas, xa, *indexp + 1);
	void *entry;

	if (xas.xa_index == 0)
		return NULL;

	rcu_read_lock();
	for (;;) {
		if ((__force unsigned int)filter < LF_XA_MAX_MARKS)
			entry = lf_xas_find_marked(&xas, max, filter);
		else
			entry = lf_xas_find(&xas, max);

		if (lf_xas_invalid(&xas))
			break;
		if (lf_xas_sibling(&xas))
			continue;
		if (!lf_xas_retry(&xas, entry))
			break;
	}
	rcu_read_unlock();

	if (entry)
		*indexp = xas.xa_index;
	return entry;
}
//EXPORT_SYMBOL(lf_xa_find_after);

static unsigned int lf_xas_extract_present(struct xa_state *xas, void **dst,
			unsigned long max, unsigned int n)
{
	void *entry;
	unsigned int i = 0;

	rcu_read_lock();
	lf_xas_for_each(xas, entry, max) {
		if (lf_xas_retry(xas, entry))
			continue;
		dst[i++] = entry;
		if (i == n)
			break;
	}
	rcu_read_unlock();

	return i;
}

static unsigned int lf_xas_extract_marked(struct xa_state *xas, void **dst,
			unsigned long max, unsigned int n, lf_xa_mark_t mark)
{
	void *entry;
	unsigned int i = 0;

	rcu_read_lock();
	lf_xas_for_each_marked(xas, entry, max, mark) {
		if (lf_xas_retry(xas, entry))
			continue;
		dst[i++] = entry;
		if (i == n)
			break;
	}
	rcu_read_unlock();

	return i;
}

/**
 * lf_xa_extract() - Copy selected entries from the XArray into a normal array.
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
 * marked with that mark will be copied.  It may also be %lf_xa_PRESENT, in
 * which case all entries which are not %NULL will be copied.
 *
 * The entries returned may not represent a snapshot of the XArray at a
 * moment in time.  For example, if another thread stores to index 5, then
 * index 10, calling lf_xa_extract() may return the old contents of index 5
 * and the new contents of index 10.  Indices not modified while this
 * function is running will not be skipped.
 *
 * If you need stronger guarantees, holding the xa_lock across calls to this
 * function will prevent concurrent modification.
 *
 * Context: Any context.  Takes and releases the RCU lock.
 * Return: The number of entries copied.
 */
unsigned int lf_xa_extract(struct xarray *xa, void **dst, unsigned long start,
			unsigned long max, unsigned int n, lf_xa_mark_t filter)
{
	XA_STATE(xas, xa, start);

	if (!n)
		return 0;

	if ((__force unsigned int)filter < LF_XA_MAX_MARKS)
		return lf_xas_extract_marked(&xas, dst, max, n, filter);
	return lf_xas_extract_present(&xas, dst, max, n);
}
//EXPORT_SYMBOL(lf_xa_extract);

/**
 * lf_xa_destroy() - Free all internal data structures.
 * @xa: XArray.
 *
 * After calling this function, the XArray is empty and has freed all memory
 * allocated for its internal data structures.  You are responsible for
 * freeing the objects referenced by the XArray.
 *
 * Context: Any context.  Takes and releases the xa_lock, interrupt-safe.
 */
void lf_xa_destroy(struct xarray *xa)
{
	XA_STATE(xas, xa, 0);
	unsigned long flags;
	void *entry;

	xas.xa_node = NULL;
	lf_xas_lock_irqsave(&xas, flags);
	entry = xa_head_locked(xa);
	RCU_INIT_POINTER(xa->xa_head, NULL);
	lf_xas_init_marks(&xas);
	if (lf_xa_zero_busy(xa))
		lf_xa_mark_clear(xa, LF_XA_FREE_MARK);
	/* lockdep checks we're still holding the lock in lf_xas_free_nodes() */
	if (lf_xa_is_node(entry))
		lf_xas_free_nodes(&xas, lf_xa_to_node(entry));
	lf_xas_unlock_irqrestore(&xas, flags);
}
//EXPORT_SYMBOL(lf_xa_destroy);

//kiet debug

//#ifdef lf_xa_DEBUG
void lf_xa_dump_node(const struct xa_node *node)
{
	unsigned i, j;

	if (!node)
		return;
	if ((unsigned long)node & 3) {
		pr_cont("node %px\n", node);
		return;
	}

	pr_cont("node %px %s %d parent %px shift %d count %d values %d "
		"array %px list %px %px marks",
		node, node->parent ? "offset" : "max", node->offset,
		node->parent, node->shift, node->count, node->nr_values,
		node->array, node->private_list.prev, node->private_list.next);
	for (i = 0; i < LF_XA_MAX_MARKS; i++)
		for (j = 0; j < LF_XA_MARK_LONGS; j++)
			pr_cont(" %lx", node->marks[i][j]);
	pr_cont("\n");
}

void lf_xa_dump_index(unsigned long index, unsigned int shift)
{
	if (!shift)
		pr_info("%lu: ", index);
	else if (shift >= BITS_PER_LONG)
		pr_info("0-%lu: ", ~0UL);
	else
		pr_info("%lu-%lu: ", index, index | ((1UL << shift) - 1));
}

void lf_xa_dump_entry(const void *entry, unsigned long index, unsigned long shift)
{
	if (!entry)
		return;

	lf_xa_dump_index(index, shift);

	if (lf_xa_is_node(entry)) {
		if (shift == 0) {
			pr_cont("%px\n", entry);
		} else {
			unsigned long i;
			struct xa_node *node = lf_xa_to_node(entry);
			lf_xa_dump_node(node);
			for (i = 0; i < LF_XA_CHUNK_SIZE; i++)
				lf_xa_dump_entry(node->slots[i],
				      index + (i << node->shift), node->shift);
		}
	} else if (lf_xa_is_value(entry))
		pr_cont("value %ld (0x%lx) [%px]\n", lf_xa_to_value(entry),
						lf_xa_to_value(entry), entry);
	else if (!lf_xa_is_internal(entry))
		pr_cont("%px\n", entry);
	else if (lf_xa_is_retry(entry))
		pr_cont("retry (%ld)\n", lf_xa_to_internal(entry));
	else if (lf_xa_is_sibling(entry))
		pr_cont("sibling (slot %ld)\n", lf_xa_to_sibling(entry));
	else if (lf_xa_is_zero(entry))
		pr_cont("zero (%ld)\n", lf_xa_to_internal(entry));
	else
		pr_cont("UNKNOWN ENTRY (%px)\n", entry);
}

void lf_xa_dump(const struct xarray *xa)
{
	void *entry = xa->xa_head;
	unsigned int shift = 0;

	pr_info("xarray: %px head %px flags %x marks %d %d %d\n", xa, entry,
			xa->xa_flags, lf_xa_marked(xa, LF_XA_MARK_0),
			lf_xa_marked(xa, LF_XA_MARK_1), lf_xa_marked(xa, LF_XA_MARK_2));
	if (lf_xa_is_node(entry))
		shift = lf_xa_to_node(entry)->shift + LF_XA_CHUNK_SHIFT;
	lf_xa_dump_entry(entry, 0, shift);
}
//#endif
