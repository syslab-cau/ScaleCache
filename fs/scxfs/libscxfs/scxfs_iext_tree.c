// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2017 Christoph Hellwig.
 */

#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_bit.h"
#include "scxfs_log_format.h"
#include "scxfs_inode.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_trace.h"

/*
 * In-core extent record layout:
 *
 * +-------+----------------------------+
 * | 00:53 | all 54 bits of startoff    |
 * | 54:63 | low 10 bits of startblock  |
 * +-------+----------------------------+
 * | 00:20 | all 21 bits of length      |
 * |    21 | unwritten extent bit       |
 * | 22:63 | high 42 bits of startblock |
 * +-------+----------------------------+
 */
#define SCXFS_IEXT_STARTOFF_MASK		scxfs_mask64lo(BMBT_STARTOFF_BITLEN)
#define SCXFS_IEXT_LENGTH_MASK		scxfs_mask64lo(BMBT_BLOCKCOUNT_BITLEN)
#define SCXFS_IEXT_STARTBLOCK_MASK	scxfs_mask64lo(BMBT_STARTBLOCK_BITLEN)

struct scxfs_iext_rec {
	uint64_t			lo;
	uint64_t			hi;
};

/*
 * Given that the length can't be a zero, only an empty hi value indicates an
 * unused record.
 */
static bool scxfs_iext_rec_is_empty(struct scxfs_iext_rec *rec)
{
	return rec->hi == 0;
}

static inline void scxfs_iext_rec_clear(struct scxfs_iext_rec *rec)
{
	rec->lo = 0;
	rec->hi = 0;
}

static void
scxfs_iext_set(
	struct scxfs_iext_rec	*rec,
	struct scxfs_bmbt_irec	*irec)
{
	ASSERT((irec->br_startoff & ~SCXFS_IEXT_STARTOFF_MASK) == 0);
	ASSERT((irec->br_blockcount & ~SCXFS_IEXT_LENGTH_MASK) == 0);
	ASSERT((irec->br_startblock & ~SCXFS_IEXT_STARTBLOCK_MASK) == 0);

	rec->lo = irec->br_startoff & SCXFS_IEXT_STARTOFF_MASK;
	rec->hi = irec->br_blockcount & SCXFS_IEXT_LENGTH_MASK;

	rec->lo |= (irec->br_startblock << 54);
	rec->hi |= ((irec->br_startblock & ~scxfs_mask64lo(10)) << (22 - 10));

	if (irec->br_state == SCXFS_EXT_UNWRITTEN)
		rec->hi |= (1 << 21);
}

static void
scxfs_iext_get(
	struct scxfs_bmbt_irec	*irec,
	struct scxfs_iext_rec	*rec)
{
	irec->br_startoff = rec->lo & SCXFS_IEXT_STARTOFF_MASK;
	irec->br_blockcount = rec->hi & SCXFS_IEXT_LENGTH_MASK;

	irec->br_startblock = rec->lo >> 54;
	irec->br_startblock |= (rec->hi & scxfs_mask64hi(42)) >> (22 - 10);

	if (rec->hi & (1 << 21))
		irec->br_state = SCXFS_EXT_UNWRITTEN;
	else
		irec->br_state = SCXFS_EXT_NORM;
}

enum {
	NODE_SIZE	= 256,
	KEYS_PER_NODE	= NODE_SIZE / (sizeof(uint64_t) + sizeof(void *)),
	RECS_PER_LEAF	= (NODE_SIZE - (2 * sizeof(struct scxfs_iext_leaf *))) /
				sizeof(struct scxfs_iext_rec),
};

/*
 * In-core extent btree block layout:
 *
 * There are two types of blocks in the btree: leaf and inner (non-leaf) blocks.
 *
 * The leaf blocks are made up by %KEYS_PER_NODE extent records, which each
 * contain the startoffset, blockcount, startblock and unwritten extent flag.
 * See above for the exact format, followed by pointers to the previous and next
 * leaf blocks (if there are any).
 *
 * The inner (non-leaf) blocks first contain KEYS_PER_NODE lookup keys, followed
 * by an equal number of pointers to the btree blocks at the next lower level.
 *
 *		+-------+-------+-------+-------+-------+----------+----------+
 * Leaf:	| rec 1 | rec 2 | rec 3 | rec 4 | rec N | prev-ptr | next-ptr |
 *		+-------+-------+-------+-------+-------+----------+----------+
 *
 *		+-------+-------+-------+-------+-------+-------+------+-------+
 * Inner:	| key 1 | key 2 | key 3 | key N | ptr 1 | ptr 2 | ptr3 | ptr N |
 *		+-------+-------+-------+-------+-------+-------+------+-------+
 */
struct scxfs_iext_node {
	uint64_t		keys[KEYS_PER_NODE];
#define SCXFS_IEXT_KEY_INVALID	(1ULL << 63)
	void			*ptrs[KEYS_PER_NODE];
};

struct scxfs_iext_leaf {
	struct scxfs_iext_rec	recs[RECS_PER_LEAF];
	struct scxfs_iext_leaf	*prev;
	struct scxfs_iext_leaf	*next;
};

inline scxfs_extnum_t scxfs_iext_count(struct scxfs_ifork *ifp)
{
	return ifp->if_bytes / sizeof(struct scxfs_iext_rec);
}

static inline int scxfs_iext_max_recs(struct scxfs_ifork *ifp)
{
	if (ifp->if_height == 1)
		return scxfs_iext_count(ifp);
	return RECS_PER_LEAF;
}

static inline struct scxfs_iext_rec *cur_rec(struct scxfs_iext_cursor *cur)
{
	return &cur->leaf->recs[cur->pos];
}

static inline bool scxfs_iext_valid(struct scxfs_ifork *ifp,
		struct scxfs_iext_cursor *cur)
{
	if (!cur->leaf)
		return false;
	if (cur->pos < 0 || cur->pos >= scxfs_iext_max_recs(ifp))
		return false;
	if (scxfs_iext_rec_is_empty(cur_rec(cur)))
		return false;
	return true;
}

static void *
scxfs_iext_find_first_leaf(
	struct scxfs_ifork	*ifp)
{
	struct scxfs_iext_node	*node = ifp->if_u1.if_root;
	int			height;

	if (!ifp->if_height)
		return NULL;

	for (height = ifp->if_height; height > 1; height--) {
		node = node->ptrs[0];
		ASSERT(node);
	}

	return node;
}

static void *
scxfs_iext_find_last_leaf(
	struct scxfs_ifork	*ifp)
{
	struct scxfs_iext_node	*node = ifp->if_u1.if_root;
	int			height, i;

	if (!ifp->if_height)
		return NULL;

	for (height = ifp->if_height; height > 1; height--) {
		for (i = 1; i < KEYS_PER_NODE; i++)
			if (!node->ptrs[i])
				break;
		node = node->ptrs[i - 1];
		ASSERT(node);
	}

	return node;
}

void
scxfs_iext_first(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_cursor	*cur)
{
	cur->pos = 0;
	cur->leaf = scxfs_iext_find_first_leaf(ifp);
}

void
scxfs_iext_last(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_cursor	*cur)
{
	int			i;

	cur->leaf = scxfs_iext_find_last_leaf(ifp);
	if (!cur->leaf) {
		cur->pos = 0;
		return;
	}

	for (i = 1; i < scxfs_iext_max_recs(ifp); i++) {
		if (scxfs_iext_rec_is_empty(&cur->leaf->recs[i]))
			break;
	}
	cur->pos = i - 1;
}

void
scxfs_iext_next(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_cursor	*cur)
{
	if (!cur->leaf) {
		ASSERT(cur->pos <= 0 || cur->pos >= RECS_PER_LEAF);
		scxfs_iext_first(ifp, cur);
		return;
	}

	ASSERT(cur->pos >= 0);
	ASSERT(cur->pos < scxfs_iext_max_recs(ifp));

	cur->pos++;
	if (ifp->if_height > 1 && !scxfs_iext_valid(ifp, cur) &&
	    cur->leaf->next) {
		cur->leaf = cur->leaf->next;
		cur->pos = 0;
	}
}

void
scxfs_iext_prev(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_cursor	*cur)
{
	if (!cur->leaf) {
		ASSERT(cur->pos <= 0 || cur->pos >= RECS_PER_LEAF);
		scxfs_iext_last(ifp, cur);
		return;
	}

	ASSERT(cur->pos >= 0);
	ASSERT(cur->pos <= RECS_PER_LEAF);

recurse:
	do {
		cur->pos--;
		if (scxfs_iext_valid(ifp, cur))
			return;
	} while (cur->pos > 0);

	if (ifp->if_height > 1 && cur->leaf->prev) {
		cur->leaf = cur->leaf->prev;
		cur->pos = RECS_PER_LEAF;
		goto recurse;
	}
}

static inline int
scxfs_iext_key_cmp(
	struct scxfs_iext_node	*node,
	int			n,
	scxfs_fileoff_t		offset)
{
	if (node->keys[n] > offset)
		return 1;
	if (node->keys[n] < offset)
		return -1;
	return 0;
}

static inline int
scxfs_iext_rec_cmp(
	struct scxfs_iext_rec	*rec,
	scxfs_fileoff_t		offset)
{
	uint64_t		rec_offset = rec->lo & SCXFS_IEXT_STARTOFF_MASK;
	uint32_t		rec_len = rec->hi & SCXFS_IEXT_LENGTH_MASK;

	if (rec_offset > offset)
		return 1;
	if (rec_offset + rec_len <= offset)
		return -1;
	return 0;
}

static void *
scxfs_iext_find_level(
	struct scxfs_ifork	*ifp,
	scxfs_fileoff_t		offset,
	int			level)
{
	struct scxfs_iext_node	*node = ifp->if_u1.if_root;
	int			height, i;

	if (!ifp->if_height)
		return NULL;

	for (height = ifp->if_height; height > level; height--) {
		for (i = 1; i < KEYS_PER_NODE; i++)
			if (scxfs_iext_key_cmp(node, i, offset) > 0)
				break;

		node = node->ptrs[i - 1];
		if (!node)
			break;
	}

	return node;
}

static int
scxfs_iext_node_pos(
	struct scxfs_iext_node	*node,
	scxfs_fileoff_t		offset)
{
	int			i;

	for (i = 1; i < KEYS_PER_NODE; i++) {
		if (scxfs_iext_key_cmp(node, i, offset) > 0)
			break;
	}

	return i - 1;
}

static int
scxfs_iext_node_insert_pos(
	struct scxfs_iext_node	*node,
	scxfs_fileoff_t		offset)
{
	int			i;

	for (i = 0; i < KEYS_PER_NODE; i++) {
		if (scxfs_iext_key_cmp(node, i, offset) > 0)
			return i;
	}

	return KEYS_PER_NODE;
}

static int
scxfs_iext_node_nr_entries(
	struct scxfs_iext_node	*node,
	int			start)
{
	int			i;

	for (i = start; i < KEYS_PER_NODE; i++) {
		if (node->keys[i] == SCXFS_IEXT_KEY_INVALID)
			break;
	}

	return i;
}

static int
scxfs_iext_leaf_nr_entries(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_leaf	*leaf,
	int			start)
{
	int			i;

	for (i = start; i < scxfs_iext_max_recs(ifp); i++) {
		if (scxfs_iext_rec_is_empty(&leaf->recs[i]))
			break;
	}

	return i;
}

static inline uint64_t
scxfs_iext_leaf_key(
	struct scxfs_iext_leaf	*leaf,
	int			n)
{
	return leaf->recs[n].lo & SCXFS_IEXT_STARTOFF_MASK;
}

static void
scxfs_iext_grow(
	struct scxfs_ifork	*ifp)
{
	struct scxfs_iext_node	*node = kmem_zalloc(NODE_SIZE, KM_NOFS);
	int			i;

	if (ifp->if_height == 1) {
		struct scxfs_iext_leaf *prev = ifp->if_u1.if_root;

		node->keys[0] = scxfs_iext_leaf_key(prev, 0);
		node->ptrs[0] = prev;
	} else  {
		struct scxfs_iext_node *prev = ifp->if_u1.if_root;

		ASSERT(ifp->if_height > 1);

		node->keys[0] = prev->keys[0];
		node->ptrs[0] = prev;
	}

	for (i = 1; i < KEYS_PER_NODE; i++)
		node->keys[i] = SCXFS_IEXT_KEY_INVALID;

	ifp->if_u1.if_root = node;
	ifp->if_height++;
}

static void
scxfs_iext_update_node(
	struct scxfs_ifork	*ifp,
	scxfs_fileoff_t		old_offset,
	scxfs_fileoff_t		new_offset,
	int			level,
	void			*ptr)
{
	struct scxfs_iext_node	*node = ifp->if_u1.if_root;
	int			height, i;

	for (height = ifp->if_height; height > level; height--) {
		for (i = 0; i < KEYS_PER_NODE; i++) {
			if (i > 0 && scxfs_iext_key_cmp(node, i, old_offset) > 0)
				break;
			if (node->keys[i] == old_offset)
				node->keys[i] = new_offset;
		}
		node = node->ptrs[i - 1];
		ASSERT(node);
	}

	ASSERT(node == ptr);
}

static struct scxfs_iext_node *
scxfs_iext_split_node(
	struct scxfs_iext_node	**nodep,
	int			*pos,
	int			*nr_entries)
{
	struct scxfs_iext_node	*node = *nodep;
	struct scxfs_iext_node	*new = kmem_zalloc(NODE_SIZE, KM_NOFS);
	const int		nr_move = KEYS_PER_NODE / 2;
	int			nr_keep = nr_move + (KEYS_PER_NODE & 1);
	int			i = 0;

	/* for sequential append operations just spill over into the new node */
	if (*pos == KEYS_PER_NODE) {
		*nodep = new;
		*pos = 0;
		*nr_entries = 0;
		goto done;
	}


	for (i = 0; i < nr_move; i++) {
		new->keys[i] = node->keys[nr_keep + i];
		new->ptrs[i] = node->ptrs[nr_keep + i];

		node->keys[nr_keep + i] = SCXFS_IEXT_KEY_INVALID;
		node->ptrs[nr_keep + i] = NULL;
	}

	if (*pos >= nr_keep) {
		*nodep = new;
		*pos -= nr_keep;
		*nr_entries = nr_move;
	} else {
		*nr_entries = nr_keep;
	}
done:
	for (; i < KEYS_PER_NODE; i++)
		new->keys[i] = SCXFS_IEXT_KEY_INVALID;
	return new;
}

static void
scxfs_iext_insert_node(
	struct scxfs_ifork	*ifp,
	uint64_t		offset,
	void			*ptr,
	int			level)
{
	struct scxfs_iext_node	*node, *new;
	int			i, pos, nr_entries;

again:
	if (ifp->if_height < level)
		scxfs_iext_grow(ifp);

	new = NULL;
	node = scxfs_iext_find_level(ifp, offset, level);
	pos = scxfs_iext_node_insert_pos(node, offset);
	nr_entries = scxfs_iext_node_nr_entries(node, pos);

	ASSERT(pos >= nr_entries || scxfs_iext_key_cmp(node, pos, offset) != 0);
	ASSERT(nr_entries <= KEYS_PER_NODE);

	if (nr_entries == KEYS_PER_NODE)
		new = scxfs_iext_split_node(&node, &pos, &nr_entries);

	/*
	 * Update the pointers in higher levels if the first entry changes
	 * in an existing node.
	 */
	if (node != new && pos == 0 && nr_entries > 0)
		scxfs_iext_update_node(ifp, node->keys[0], offset, level, node);

	for (i = nr_entries; i > pos; i--) {
		node->keys[i] = node->keys[i - 1];
		node->ptrs[i] = node->ptrs[i - 1];
	}
	node->keys[pos] = offset;
	node->ptrs[pos] = ptr;

	if (new) {
		offset = new->keys[0];
		ptr = new;
		level++;
		goto again;
	}
}

static struct scxfs_iext_leaf *
scxfs_iext_split_leaf(
	struct scxfs_iext_cursor	*cur,
	int			*nr_entries)
{
	struct scxfs_iext_leaf	*leaf = cur->leaf;
	struct scxfs_iext_leaf	*new = kmem_zalloc(NODE_SIZE, KM_NOFS);
	const int		nr_move = RECS_PER_LEAF / 2;
	int			nr_keep = nr_move + (RECS_PER_LEAF & 1);
	int			i;

	/* for sequential append operations just spill over into the new node */
	if (cur->pos == RECS_PER_LEAF) {
		cur->leaf = new;
		cur->pos = 0;
		*nr_entries = 0;
		goto done;
	}

	for (i = 0; i < nr_move; i++) {
		new->recs[i] = leaf->recs[nr_keep + i];
		scxfs_iext_rec_clear(&leaf->recs[nr_keep + i]);
	}

	if (cur->pos >= nr_keep) {
		cur->leaf = new;
		cur->pos -= nr_keep;
		*nr_entries = nr_move;
	} else {
		*nr_entries = nr_keep;
	}
done:
	if (leaf->next)
		leaf->next->prev = new;
	new->next = leaf->next;
	new->prev = leaf;
	leaf->next = new;
	return new;
}

static void
scxfs_iext_alloc_root(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_cursor	*cur)
{
	ASSERT(ifp->if_bytes == 0);

	ifp->if_u1.if_root = kmem_zalloc(sizeof(struct scxfs_iext_rec), KM_NOFS);
	ifp->if_height = 1;

	/* now that we have a node step into it */
	cur->leaf = ifp->if_u1.if_root;
	cur->pos = 0;
}

static void
scxfs_iext_realloc_root(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_cursor	*cur)
{
	int64_t new_size = ifp->if_bytes + sizeof(struct scxfs_iext_rec);
	void *new;

	/* account for the prev/next pointers */
	if (new_size / sizeof(struct scxfs_iext_rec) == RECS_PER_LEAF)
		new_size = NODE_SIZE;

	new = kmem_realloc(ifp->if_u1.if_root, new_size, KM_NOFS);
	memset(new + ifp->if_bytes, 0, new_size - ifp->if_bytes);
	ifp->if_u1.if_root = new;
	cur->leaf = new;
}

/*
 * Increment the sequence counter on extent tree changes. If we are on a COW
 * fork, this allows the writeback code to skip looking for a COW extent if the
 * COW fork hasn't changed. We use WRITE_ONCE here to ensure the update to the
 * sequence counter is seen before the modifications to the extent tree itself
 * take effect.
 */
static inline void scxfs_iext_inc_seq(struct scxfs_ifork *ifp)
{
	WRITE_ONCE(ifp->if_seq, READ_ONCE(ifp->if_seq) + 1);
}

void
scxfs_iext_insert(
	struct scxfs_inode	*ip,
	struct scxfs_iext_cursor	*cur,
	struct scxfs_bmbt_irec	*irec,
	int			state)
{
	struct scxfs_ifork	*ifp = scxfs_iext_state_to_fork(ip, state);
	scxfs_fileoff_t		offset = irec->br_startoff;
	struct scxfs_iext_leaf	*new = NULL;
	int			nr_entries, i;

	scxfs_iext_inc_seq(ifp);

	if (ifp->if_height == 0)
		scxfs_iext_alloc_root(ifp, cur);
	else if (ifp->if_height == 1)
		scxfs_iext_realloc_root(ifp, cur);

	nr_entries = scxfs_iext_leaf_nr_entries(ifp, cur->leaf, cur->pos);
	ASSERT(nr_entries <= RECS_PER_LEAF);
	ASSERT(cur->pos >= nr_entries ||
	       scxfs_iext_rec_cmp(cur_rec(cur), irec->br_startoff) != 0);

	if (nr_entries == RECS_PER_LEAF)
		new = scxfs_iext_split_leaf(cur, &nr_entries);

	/*
	 * Update the pointers in higher levels if the first entry changes
	 * in an existing node.
	 */
	if (cur->leaf != new && cur->pos == 0 && nr_entries > 0) {
		scxfs_iext_update_node(ifp, scxfs_iext_leaf_key(cur->leaf, 0),
				offset, 1, cur->leaf);
	}

	for (i = nr_entries; i > cur->pos; i--)
		cur->leaf->recs[i] = cur->leaf->recs[i - 1];
	scxfs_iext_set(cur_rec(cur), irec);
	ifp->if_bytes += sizeof(struct scxfs_iext_rec);

	trace_scxfs_iext_insert(ip, cur, state, _RET_IP_);

	if (new)
		scxfs_iext_insert_node(ifp, scxfs_iext_leaf_key(new, 0), new, 2);
}

static struct scxfs_iext_node *
scxfs_iext_rebalance_node(
	struct scxfs_iext_node	*parent,
	int			*pos,
	struct scxfs_iext_node	*node,
	int			nr_entries)
{
	/*
	 * If the neighbouring nodes are completely full, or have different
	 * parents, we might never be able to merge our node, and will only
	 * delete it once the number of entries hits zero.
	 */
	if (nr_entries == 0)
		return node;

	if (*pos > 0) {
		struct scxfs_iext_node *prev = parent->ptrs[*pos - 1];
		int nr_prev = scxfs_iext_node_nr_entries(prev, 0), i;

		if (nr_prev + nr_entries <= KEYS_PER_NODE) {
			for (i = 0; i < nr_entries; i++) {
				prev->keys[nr_prev + i] = node->keys[i];
				prev->ptrs[nr_prev + i] = node->ptrs[i];
			}
			return node;
		}
	}

	if (*pos + 1 < scxfs_iext_node_nr_entries(parent, *pos)) {
		struct scxfs_iext_node *next = parent->ptrs[*pos + 1];
		int nr_next = scxfs_iext_node_nr_entries(next, 0), i;

		if (nr_entries + nr_next <= KEYS_PER_NODE) {
			/*
			 * Merge the next node into this node so that we don't
			 * have to do an additional update of the keys in the
			 * higher levels.
			 */
			for (i = 0; i < nr_next; i++) {
				node->keys[nr_entries + i] = next->keys[i];
				node->ptrs[nr_entries + i] = next->ptrs[i];
			}

			++*pos;
			return next;
		}
	}

	return NULL;
}

static void
scxfs_iext_remove_node(
	struct scxfs_ifork	*ifp,
	scxfs_fileoff_t		offset,
	void			*victim)
{
	struct scxfs_iext_node	*node, *parent;
	int			level = 2, pos, nr_entries, i;

	ASSERT(level <= ifp->if_height);
	node = scxfs_iext_find_level(ifp, offset, level);
	pos = scxfs_iext_node_pos(node, offset);
again:
	ASSERT(node->ptrs[pos]);
	ASSERT(node->ptrs[pos] == victim);
	kmem_free(victim);

	nr_entries = scxfs_iext_node_nr_entries(node, pos) - 1;
	offset = node->keys[0];
	for (i = pos; i < nr_entries; i++) {
		node->keys[i] = node->keys[i + 1];
		node->ptrs[i] = node->ptrs[i + 1];
	}
	node->keys[nr_entries] = SCXFS_IEXT_KEY_INVALID;
	node->ptrs[nr_entries] = NULL;

	if (pos == 0 && nr_entries > 0) {
		scxfs_iext_update_node(ifp, offset, node->keys[0], level, node);
		offset = node->keys[0];
	}

	if (nr_entries >= KEYS_PER_NODE / 2)
		return;

	if (level < ifp->if_height) {
		/*
		 * If we aren't at the root yet try to find a neighbour node to
		 * merge with (or delete the node if it is empty), and then
		 * recurse up to the next level.
		 */
		level++;
		parent = scxfs_iext_find_level(ifp, offset, level);
		pos = scxfs_iext_node_pos(parent, offset);

		ASSERT(pos != KEYS_PER_NODE);
		ASSERT(parent->ptrs[pos] == node);

		node = scxfs_iext_rebalance_node(parent, &pos, node, nr_entries);
		if (node) {
			victim = node;
			node = parent;
			goto again;
		}
	} else if (nr_entries == 1) {
		/*
		 * If we are at the root and only one entry is left we can just
		 * free this node and update the root pointer.
		 */
		ASSERT(node == ifp->if_u1.if_root);
		ifp->if_u1.if_root = node->ptrs[0];
		ifp->if_height--;
		kmem_free(node);
	}
}

static void
scxfs_iext_rebalance_leaf(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_cursor	*cur,
	struct scxfs_iext_leaf	*leaf,
	scxfs_fileoff_t		offset,
	int			nr_entries)
{
	/*
	 * If the neighbouring nodes are completely full we might never be able
	 * to merge our node, and will only delete it once the number of
	 * entries hits zero.
	 */
	if (nr_entries == 0)
		goto remove_node;

	if (leaf->prev) {
		int nr_prev = scxfs_iext_leaf_nr_entries(ifp, leaf->prev, 0), i;

		if (nr_prev + nr_entries <= RECS_PER_LEAF) {
			for (i = 0; i < nr_entries; i++)
				leaf->prev->recs[nr_prev + i] = leaf->recs[i];

			if (cur->leaf == leaf) {
				cur->leaf = leaf->prev;
				cur->pos += nr_prev;
			}
			goto remove_node;
		}
	}

	if (leaf->next) {
		int nr_next = scxfs_iext_leaf_nr_entries(ifp, leaf->next, 0), i;

		if (nr_entries + nr_next <= RECS_PER_LEAF) {
			/*
			 * Merge the next node into this node so that we don't
			 * have to do an additional update of the keys in the
			 * higher levels.
			 */
			for (i = 0; i < nr_next; i++) {
				leaf->recs[nr_entries + i] =
					leaf->next->recs[i];
			}

			if (cur->leaf == leaf->next) {
				cur->leaf = leaf;
				cur->pos += nr_entries;
			}

			offset = scxfs_iext_leaf_key(leaf->next, 0);
			leaf = leaf->next;
			goto remove_node;
		}
	}

	return;
remove_node:
	if (leaf->prev)
		leaf->prev->next = leaf->next;
	if (leaf->next)
		leaf->next->prev = leaf->prev;
	scxfs_iext_remove_node(ifp, offset, leaf);
}

static void
scxfs_iext_free_last_leaf(
	struct scxfs_ifork	*ifp)
{
	ifp->if_height--;
	kmem_free(ifp->if_u1.if_root);
	ifp->if_u1.if_root = NULL;
}

void
scxfs_iext_remove(
	struct scxfs_inode	*ip,
	struct scxfs_iext_cursor	*cur,
	int			state)
{
	struct scxfs_ifork	*ifp = scxfs_iext_state_to_fork(ip, state);
	struct scxfs_iext_leaf	*leaf = cur->leaf;
	scxfs_fileoff_t		offset = scxfs_iext_leaf_key(leaf, 0);
	int			i, nr_entries;

	trace_scxfs_iext_remove(ip, cur, state, _RET_IP_);

	ASSERT(ifp->if_height > 0);
	ASSERT(ifp->if_u1.if_root != NULL);
	ASSERT(scxfs_iext_valid(ifp, cur));

	scxfs_iext_inc_seq(ifp);

	nr_entries = scxfs_iext_leaf_nr_entries(ifp, leaf, cur->pos) - 1;
	for (i = cur->pos; i < nr_entries; i++)
		leaf->recs[i] = leaf->recs[i + 1];
	scxfs_iext_rec_clear(&leaf->recs[nr_entries]);
	ifp->if_bytes -= sizeof(struct scxfs_iext_rec);

	if (cur->pos == 0 && nr_entries > 0) {
		scxfs_iext_update_node(ifp, offset, scxfs_iext_leaf_key(leaf, 0), 1,
				leaf);
		offset = scxfs_iext_leaf_key(leaf, 0);
	} else if (cur->pos == nr_entries) {
		if (ifp->if_height > 1 && leaf->next)
			cur->leaf = leaf->next;
		else
			cur->leaf = NULL;
		cur->pos = 0;
	}

	if (nr_entries >= RECS_PER_LEAF / 2)
		return;

	if (ifp->if_height > 1)
		scxfs_iext_rebalance_leaf(ifp, cur, leaf, offset, nr_entries);
	else if (nr_entries == 0)
		scxfs_iext_free_last_leaf(ifp);
}

/*
 * Lookup the extent covering bno.
 *
 * If there is an extent covering bno return the extent index, and store the
 * expanded extent structure in *gotp, and the extent cursor in *cur.
 * If there is no extent covering bno, but there is an extent after it (e.g.
 * it lies in a hole) return that extent in *gotp and its cursor in *cur
 * instead.
 * If bno is beyond the last extent return false, and return an invalid
 * cursor value.
 */
bool
scxfs_iext_lookup_extent(
	struct scxfs_inode	*ip,
	struct scxfs_ifork	*ifp,
	scxfs_fileoff_t		offset,
	struct scxfs_iext_cursor	*cur,
	struct scxfs_bmbt_irec	*gotp)
{
	SCXFS_STATS_INC(ip->i_mount, xs_look_exlist);

	cur->leaf = scxfs_iext_find_level(ifp, offset, 1);
	if (!cur->leaf) {
		cur->pos = 0;
		return false;
	}

	for (cur->pos = 0; cur->pos < scxfs_iext_max_recs(ifp); cur->pos++) {
		struct scxfs_iext_rec *rec = cur_rec(cur);

		if (scxfs_iext_rec_is_empty(rec))
			break;
		if (scxfs_iext_rec_cmp(rec, offset) >= 0)
			goto found;
	}

	/* Try looking in the next node for an entry > offset */
	if (ifp->if_height == 1 || !cur->leaf->next)
		return false;
	cur->leaf = cur->leaf->next;
	cur->pos = 0;
	if (!scxfs_iext_valid(ifp, cur))
		return false;
found:
	scxfs_iext_get(gotp, cur_rec(cur));
	return true;
}

/*
 * Returns the last extent before end, and if this extent doesn't cover
 * end, update end to the end of the extent.
 */
bool
scxfs_iext_lookup_extent_before(
	struct scxfs_inode	*ip,
	struct scxfs_ifork	*ifp,
	scxfs_fileoff_t		*end,
	struct scxfs_iext_cursor	*cur,
	struct scxfs_bmbt_irec	*gotp)
{
	/* could be optimized to not even look up the next on a match.. */
	if (scxfs_iext_lookup_extent(ip, ifp, *end - 1, cur, gotp) &&
	    gotp->br_startoff <= *end - 1)
		return true;
	if (!scxfs_iext_prev_extent(ifp, cur, gotp))
		return false;
	*end = gotp->br_startoff + gotp->br_blockcount;
	return true;
}

void
scxfs_iext_update_extent(
	struct scxfs_inode	*ip,
	int			state,
	struct scxfs_iext_cursor	*cur,
	struct scxfs_bmbt_irec	*new)
{
	struct scxfs_ifork	*ifp = scxfs_iext_state_to_fork(ip, state);

	scxfs_iext_inc_seq(ifp);

	if (cur->pos == 0) {
		struct scxfs_bmbt_irec	old;

		scxfs_iext_get(&old, cur_rec(cur));
		if (new->br_startoff != old.br_startoff) {
			scxfs_iext_update_node(ifp, old.br_startoff,
					new->br_startoff, 1, cur->leaf);
		}
	}

	trace_scxfs_bmap_pre_update(ip, cur, state, _RET_IP_);
	scxfs_iext_set(cur_rec(cur), new);
	trace_scxfs_bmap_post_update(ip, cur, state, _RET_IP_);
}

/*
 * Return true if the cursor points at an extent and return the extent structure
 * in gotp.  Else return false.
 */
bool
scxfs_iext_get_extent(
	struct scxfs_ifork	*ifp,
	struct scxfs_iext_cursor	*cur,
	struct scxfs_bmbt_irec	*gotp)
{
	if (!scxfs_iext_valid(ifp, cur))
		return false;
	scxfs_iext_get(gotp, cur_rec(cur));
	return true;
}

/*
 * This is a recursive function, because of that we need to be extremely
 * careful with stack usage.
 */
static void
scxfs_iext_destroy_node(
	struct scxfs_iext_node	*node,
	int			level)
{
	int			i;

	if (level > 1) {
		for (i = 0; i < KEYS_PER_NODE; i++) {
			if (node->keys[i] == SCXFS_IEXT_KEY_INVALID)
				break;
			scxfs_iext_destroy_node(node->ptrs[i], level - 1);
		}
	}

	kmem_free(node);
}

void
scxfs_iext_destroy(
	struct scxfs_ifork	*ifp)
{
	scxfs_iext_destroy_node(ifp->if_u1.if_root, ifp->if_height);

	ifp->if_bytes = 0;
	ifp->if_height = 0;
	ifp->if_u1.if_root = NULL;
}
