/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _CC_XARRAY_H
#define _CC_XARRAY_H
/*
 * Concurrent eXtensible Arrays
 * Based on XArray implementation
 * Copyright (c) 2017 Microsoft Corporation
 * Original Author: Matthew Wilcox <willy@infradead.org>
 *
 * See Documentation/core-api/xarray.rst for how to use the XArray.
 */

#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/slab.h>


/*
 * The bottom two bits of the entry determine how the XArray interprets
 * the contents:
 *
 * 00: Pointer entry
 * 10: Internal entry
 * x1: Value entry or tagged pointer
 *
 * Attempting to store internal entries in the XArray is a bug.
 *
 * Most internal entries are pointers to the next node in the tree.
 * The following internal entries have a special meaning:
 *
 * 0-62: Sibling entries
 * 256: Zero entry
 * 257: Retry entry
 *
 * Errors are also represented as internal entries, but use the negative
 * space (-4094 to -2).  They're never stored in the slots array; only
 * returned by the normal API.
 */

#define BITS_PER_CC_XA_VALUE	(BITS_PER_LONG - 1)

/**
 * cc_xa_mk_value() - Create an XArray entry from an integer.
 * @v: Value to store in XArray.
 *
 * Context: Any context.
 * Return: An entry suitable for storing in the XArray.
 */
static inline void *cc_xa_mk_value(unsigned long v)
{
	WARN_ON((long)v < 0);
	return (void *)((v << 1) | 1);
}

/**
 * cc_xa_to_value() - Get value stored in an XArray entry.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: The value stored in the XArray entry.
 */
static inline unsigned long cc_xa_to_value(const void *entry)
{
	return (unsigned long)entry >> 1;
}

/**
 * cc_xa_is_value() - Determine if an entry is a value.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: True if the entry is a value, false if it is a pointer.
 */
static inline bool cc_xa_is_value(const void *entry)
{
	return (unsigned long)entry & 1;
}

/**
 * cc_xa_tag_pointer() - Create an XArray entry for a tagged pointer.
 * @p: Plain pointer.
 * @tag: Tag value (0, 1 or 3).
 *
 * If the user of the XArray prefers, they can tag their pointers instead
 * of storing value entries.  Three tags are available (0, 1 and 3).
 * These are distinct from the cc_xa_mark_t as they are not replicated up
 * through the array and cannot be searched for.
 *
 * Context: Any context.
 * Return: An XArray entry.
 */
static inline void *cc_xa_tag_pointer(void *p, unsigned long tag)
{
	return (void *)((unsigned long)p | tag);
}

/**
 * cc_xa_untag_pointer() - Turn an XArray entry into a plain pointer.
 * @entry: XArray entry.
 *
 * If you have stored a tagged pointer in the XArray, call this function
 * to get the untagged version of the pointer.
 *
 * Context: Any context.
 * Return: A pointer.
 */
static inline void *cc_xa_untag_pointer(void *entry)
{
	return (void *)((unsigned long)entry & ~3UL);
}

/**
 * cc_xa_pointer_tag() - Get the tag stored in an XArray entry.
 * @entry: XArray entry.
 *
 * If you have stored a tagged pointer in the XArray, call this function
 * to get the tag of that pointer.
 *
 * Context: Any context.
 * Return: A tag.
 */
static inline unsigned int cc_xa_pointer_tag(void *entry)
{
	return (unsigned long)entry & 3UL;
}

/*
 * cc_xa_mk_internal() - Create an internal entry.
 * @v: Value to turn into an internal entry.
 *
 * Internal entries are used for a number of purposes.  Entries 0-255 are
 * used for sibling entries (only 0-62 are used by the current code).  256
 * is used for the retry entry.  257 is used for the reserved / zero entry.
 * Negative internal entries are used to represent errnos.  Node pointers
 * are also tagged as internal entries in some situations.
 *
 * Context: Any context.
 * Return: An XArray internal entry corresponding to this value.
 */
static inline void *cc_xa_mk_internal(unsigned long v)
{
	return (void *)((v << 2) | 2);
}

/*
 * cc_xa_to_internal() - Extract the value from an internal entry.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: The value which was stored in the internal entry.
 */
static inline unsigned long cc_xa_to_internal(const void *entry)
{
	return (unsigned long)entry >> 2;
}

/*
 * cc_xa_is_internal() - Is the entry an internal entry?
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: %true if the entry is an internal entry.
 */
static inline bool cc_xa_is_internal(const void *entry)
{
	return ((unsigned long)entry & 3) == 2;
}

#define CC_XA_ZERO_ENTRY		cc_xa_mk_internal(257)

/**
 * cc_xa_is_zero() - Is the entry a zero entry?
 * @entry: Entry retrieved from the XArray
 *
 * The normal API will return NULL as the contents of a slot containing
 * a zero entry.  You can only see zero entries by using the advanced API.
 *
 * Return: %true if the entry is a zero entry.
 */
static inline bool cc_xa_is_zero(const void *entry)
{
	return unlikely(entry == CC_XA_ZERO_ENTRY);
}

/**
 * cc_xa_is_err() - Report whether an XArray operation returned an error
 * @entry: Result from calling an XArray function
 *
 * If an XArray operation cannot complete an operation, it will return
 * a special value indicating an error.  This function tells you
 * whether an error occurred; cc_xa_err() tells you which error occurred.
 *
 * Context: Any context.
 * Return: %true if the entry indicates an error.
 */
static inline bool cc_xa_is_err(const void *entry)
{
	return unlikely(cc_xa_is_internal(entry) &&
			entry >= cc_xa_mk_internal(-MAX_ERRNO));
}

/**
 * cc_xa_err() - Turn an XArray result into an errno.
 * @entry: Result from calling an XArray function.
 *
 * If an XArray operation cannot complete an operation, it will return
 * a special pointer value which encodes an errno.  This function extracts
 * the errno from the pointer value, or returns 0 if the pointer does not
 * represent an errno.
 *
 * Context: Any context.
 * Return: A negative errno or 0.
 */
static inline int cc_xa_err(void *entry)
{
	/* cc_xa_to_internal() would not do sign extension. */
	if (cc_xa_is_err(entry))
		return (long)entry >> 2;
	return 0;
}

/**
 * struct cc_xa_limit - Represents a range of IDs.
 * @min: The lowest ID to allocate (inclusive).
 * @max: The maximum ID to allocate (inclusive).
 *
 * This structure is used either directly or via the CC_XA_LIMIT() macro
 * to communicate the range of IDs that are valid for allocation.
 * Two common ranges are predefined for you:
 * * cc_xa_limit_32b	- [0 - UINT_MAX]
 * * cc_xa_limit_31b	- [0 - INT_MAX]
 */
struct cc_xa_limit {
	u32 max;
	u32 min;
};

#define CC_XA_LIMIT(_min, _max) (struct cc_xa_limit) { .min = _min, .max = _max }

#define cc_xa_limit_32b	CC_XA_LIMIT(0, UINT_MAX)
#define cc_xa_limit_31b	CC_XA_LIMIT(0, INT_MAX)

typedef unsigned __bitwise cc_xa_mark_t;
#define CC_XA_MARK_0		((__force cc_xa_mark_t)0U)
#define CC_XA_MARK_1		((__force cc_xa_mark_t)1U)
#define CC_XA_MARK_2		((__force cc_xa_mark_t)2U)
/* Private: Do not use this flag directly */
#define __CC_XA_FLAGS_IS_CCXARRAY	((__force cc_xa_mark_t)3U)
#define CC_XA_PRESENT		((__force cc_xa_mark_t)8U)
#define CC_XA_MARK_MAX		CC_XA_MARK_2
#define CC_XA_FREE_MARK		CC_XA_MARK_0

enum cc_xa_lock_type {
	CC_XA_LOCK_IRQ = 1,
	CC_XA_LOCK_BH = 2,
};

/*
 * Values for xa_flags.  The radix tree stores its GFP flags in the xa_flags,
 * and we remain compatible with that.
 */
#define CC_XA_FLAGS_LOCK_IRQ	((__force gfp_t)CC_XA_LOCK_IRQ)
#define CC_XA_FLAGS_LOCK_BH	((__force gfp_t)CC_XA_LOCK_BH)
#define CC_XA_FLAGS_TRACK_FREE	((__force gfp_t)4U)
#define CC_XA_FLAGS_ZERO_BUSY	((__force gfp_t)8U)
#define CC_XA_FLAGS_ALLOC_WRAPPED	((__force gfp_t)16U)
#define CC_XA_FLAGS_ACCOUNT	((__force gfp_t)32U)
#define CC_XA_FLAGS_MARK(mark)	((__force gfp_t)((1U << __GFP_BITS_SHIFT) << \
						(__force unsigned)(mark)))

/* ALLOC is for a normal 0-based alloc.  ALLOC1 is for an 1-based alloc */
#define CC_XA_FLAGS_ALLOC	(CC_XA_FLAGS_TRACK_FREE | CC_XA_FLAGS_MARK(CC_XA_FREE_MARK))
#define CC_XA_FLAGS_ALLOC1	(CC_XA_FLAGS_TRACK_FREE | CC_XA_FLAGS_ZERO_BUSY)

#define CC_XARRAY(xarray)	((__force struct cc_xarray *)(xarray))
#define TO_XARRAY(cc_xarray)	((__force struct xarray *)(cc_xarray))

/**
 * struct cc_xarray - The anchor of the Concurrent XArray.
 * @xa_lock: Lock that protects the contents of the Concurrent XArray.
 *
 * To use the cc_xarray, define it statically or embed it in your data structure.
 * It is a very small data structure, so it does not usually make sense to
 * allocate it separately and keep a pointer to it in your data structure.
 *
 * You may use the xa_lock to protect your own data structures as well.
 */
/*
 * If all of the entries in the array are NULL, @xa_head is a NULL pointer.
 * If the only non-NULL entry in the array is at index 0, @xa_head is that
 * entry.  If any other entry in the array is non-NULL, @xa_head points
 * to a @cc_xa_node.
 */
struct cc_xarray {
	spinlock_t	xa_lock;	/* 4 bytes */
/* private: The rest of the data structure is not to be used directly. */
	gfp_t		xa_flags;	/* 4 bytes */
	void __rcu *	xa_head;	/* 8 bytes */
};
/* sizeof(struct xarray) == 16 */

#define CC_XARRAY_INIT(name, flags) {						\
	.xa_lock = __SPIN_LOCK_UNLOCKED(name.xa_lock),				\
	.xa_flags = (flags | CC_XA_FLAGS_MARK(__CC_XA_FLAGS_IS_CCXARRAY)),	\
	.xa_head = NULL,							\
}

/**
 * DEFINE_CC_XARRAY_FLAGS() - Define an XArray with custom flags.
 * @name: A string that names your XArray.
 * @flags: CC_XA_FLAG values.
 *
 * This is intended for file scope definitions of XArrays.  It declares
 * and initialises an empty XArray with the chosen name and flags.  It is
 * equivalent to calling cc_xa_init_flags() on the array, but it does the
 * initialisation at compiletime instead of runtime.
 */
#define DEFINE_CC_XARRAY_FLAGS(name, flags)				\
	struct cc_xarray name = CC_XARRAY_INIT(name, flags)

/**
 * DEFINE_CC_XARRAY() - Define an XArray.
 * @name: A string that names your XArray.
 *
 * This is intended for file scope definitions of XArrays.  It declares
 * and initialises an empty XArray with the chosen name.  It is equivalent
 * to calling cc_xa_init() on the array, but it does the initialisation at
 * compiletime instead of runtime.
 */
#define DEFINE_CC_XARRAY(name) DEFINE_CC_XARRAY_FLAGS(name, 0)

/**
 * DEFINE_CC_XARRAY_ALLOC() - Define an XArray which allocates IDs starting at 0.
 * @name: A string that names your XArray.
 *
 * This is intended for file scope definitions of allocating XArrays.
 * See also DEFINE_CC_XARRAY().
 */
#define DEFINE_CC_XARRAY_ALLOC(name) DEFINE_CC_XARRAY_FLAGS(name, CC_XA_FLAGS_ALLOC)

/**
 * DEFINE_CC_XARRAY_ALLOC1() - Define an XArray which allocates IDs starting at 1.
 * @name: A string that names your XArray.
 *
 * This is intended for file scope definitions of allocating XArrays.
 * See also DEFINE_CC_XARRAY().
 */
#define DEFINE_CC_XARRAY_ALLOC1(name) DEFINE_CC_XARRAY_FLAGS(name, CC_XA_FLAGS_ALLOC1)

void *cc_xa_load(struct cc_xarray *, unsigned long index);
void *cc_xa_store(struct cc_xarray *, unsigned long index, void *entry, gfp_t);
void *cc_xa_erase(struct cc_xarray *, unsigned long index);
void *cc_xa_store_range(struct cc_xarray *, unsigned long first, unsigned long last,
			void *entry, gfp_t);
bool cc_xa_get_mark(struct cc_xarray *, unsigned long index, cc_xa_mark_t);
void cc_xa_set_mark(struct cc_xarray *, unsigned long index, cc_xa_mark_t);
void cc_xa_clear_mark(struct cc_xarray *, unsigned long index, cc_xa_mark_t);
void *cc_xa_find(struct cc_xarray *xa, unsigned long *index,
		unsigned long max, cc_xa_mark_t) __attribute__((nonnull(2)));
void *cc_xa_find_after(struct cc_xarray *xa, unsigned long *index,
		unsigned long max, cc_xa_mark_t) __attribute__((nonnull(2)));
unsigned int cc_xa_extract(struct cc_xarray *, void **dst, unsigned long start,
		unsigned long max, unsigned int n, cc_xa_mark_t);
void cc_xa_destroy(struct cc_xarray *);

/**
 * cc_xa_init_flags() - Initialise an empty XArray with flags.
 * @xa: XArray.
 * @flags: CC_XA_FLAG values.
 *
 * If you need to initialise an XArray with special flags (eg you need
 * to take the lock from interrupt context), use this function instead
 * of cc_xa_init().
 *
 * Context: Any context.
 */
static inline void cc_xa_init_flags(struct cc_xarray *xa, gfp_t flags)
{
	spin_lock_init(&xa->xa_lock);
	xa->xa_flags = (flags | CC_XA_FLAGS_MARK(__CC_XA_FLAGS_IS_CCXARRAY));
	xa->xa_head = NULL;
}

/**
 * cc_xa_init() - Initialise an empty XArray.
 * @xa: XArray.
 *
 * An empty XArray is full of NULL entries.
 *
 * Context: Any context.
 */
static inline void cc_xa_init(struct cc_xarray *xa)
{
	cc_xa_init_flags(xa, 0);
}

static inline void *cc_xa_head(const struct cc_xarray *xa);

/**
 * cc_xa_empty() - Determine if an array has any present entries.
 * @xa: XArray.
 *
 * Context: Any context.
 * Return: %true if the array contains only NULL pointers.
 */
static inline bool cc_xa_empty(const struct cc_xarray *xa)
{
	return cc_xa_head(xa) == NULL;
}

/**
 * cc_xa_is_ccxarray() - Determine if an array is a Concurrent XArray.
 * @xa: Concurrent XArray.
 *
 * Context: Any context.
 * Return: %true if the array is a Concurrent XArray.
 */
static inline bool cc_xa_is_ccxarray(struct cc_xarray *xa)
{
	return xa->xa_flags & CC_XA_FLAGS_MARK(__CC_XA_FLAGS_IS_CCXARRAY);
}

/**
 * cc_xa_marked() - Inquire whether any entry in this array has a mark set
 * @xa: Array
 * @mark: Mark value
 *
 * Context: Any context.
 * Return: %true if any entry has this mark set.
 */
static inline bool cc_xa_marked(const struct cc_xarray *xa, cc_xa_mark_t mark)
{
	return xa->xa_flags & CC_XA_FLAGS_MARK(mark);
}

/**
 * cc_xa_for_each_start() - Iterate over a portion of an XArray.
 * @xa: XArray.
 * @index: Index of @entry.
 * @entry: Entry retrieved from array.
 * @start: First index to retrieve from array.
 *
 * During the iteration, @entry will have the value of the entry stored
 * in @xa at @index.  You may modify @index during the iteration if you
 * want to skip or reprocess indices.  It is safe to modify the array
 * during the iteration.  At the end of the iteration, @entry will be set
 * to NULL and @index will have a value less than or equal to max.
 *
 * cc_xa_for_each_start() is O(n.log(n)) while cc_xas_for_each() is O(n).  You have
 * to handle your own locking with cc_xas_for_each(), and if you have to unlock
 * after each iteration, it will also end up being O(n.log(n)).
 * cc_xa_for_each_start() will spin if it hits a retry entry; if you intend to
 * see retry entries, you should use the cc_xas_for_each() iterator instead.
 * The cc_xas_for_each() iterator will expand into more inline code than
 * cc_xa_for_each_start().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 */
#define cc_xa_for_each_start(xa, index, entry, start)			\
	for (index = start,						\
	     entry = cc_xa_find(xa, &index, ULONG_MAX, CC_XA_PRESENT);	\
	     entry;							\
	     entry = cc_xa_find_after(xa, &index, ULONG_MAX, CC_XA_PRESENT))

/**
 * cc_xa_for_each() - Iterate over present entries in an XArray.
 * @xa: XArray.
 * @index: Index of @entry.
 * @entry: Entry retrieved from array.
 *
 * During the iteration, @entry will have the value of the entry stored
 * in @xa at @index.  You may modify @index during the iteration if you want
 * to skip or reprocess indices.  It is safe to modify the array during the
 * iteration.  At the end of the iteration, @entry will be set to NULL and
 * @index will have a value less than or equal to max.
 *
 * cc_xa_for_each() is O(n.log(n)) while cc_xas_for_each() is O(n).  You have
 * to handle your own locking with cc_xas_for_each(), and if you have to unlock
 * after each iteration, it will also end up being O(n.log(n)).  cc_xa_for_each()
 * will spin if it hits a retry entry; if you intend to see retry entries,
 * you should use the cc_xas_for_each() iterator instead.  The cc_xas_for_each()
 * iterator will expand into more inline code than cc_xa_for_each().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 */
#define cc_xa_for_each(xa, index, entry) \
	cc_xa_for_each_start(xa, index, entry, 0)

/**
 * cc_xa_for_each_marked() - Iterate over marked entries in an XArray.
 * @xa: XArray.
 * @index: Index of @entry.
 * @entry: Entry retrieved from array.
 * @filter: Selection criterion.
 *
 * During the iteration, @entry will have the value of the entry stored
 * in @xa at @index.  The iteration will skip all entries in the array
 * which do not match @filter.  You may modify @index during the iteration
 * if you want to skip or reprocess indices.  It is safe to modify the array
 * during the iteration.  At the end of the iteration, @entry will be set to
 * NULL and @index will have a value less than or equal to max.
 *
 * cc_xa_for_each_marked() is O(n.log(n)) while cc_xas_for_each_marked() is O(n).
 * You have to handle your own locking with cc_xas_for_each(), and if you have
 * to unlock after each iteration, it will also end up being O(n.log(n)).
 * cc_xa_for_each_marked() will spin if it hits a retry entry; if you intend to
 * see retry entries, you should use the cc_xas_for_each_marked() iterator
 * instead.  The cc_xas_for_each_marked() iterator will expand into more inline
 * code than cc_xa_for_each_marked().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 */
#define cc_xa_for_each_marked(xa, index, entry, filter) \
	for (index = 0, entry = cc_xa_find(xa, &index, ULONG_MAX, filter); \
	     entry; entry = cc_xa_find_after(xa, &index, ULONG_MAX, filter))

#define cc_xa_trylock(xa)		spin_trylock(&(xa)->xa_lock)
#define cc_xa_lock(xa)			spin_lock(&(xa)->xa_lock)
#define cc_xa_unlock(xa)		spin_unlock(&(xa)->xa_lock)
#define cc_xa_lock_bh(xa)		spin_lock_bh(&(xa)->xa_lock)
#define cc_xa_unlock_bh(xa)		spin_unlock_bh(&(xa)->xa_lock)
#define cc_xa_lock_irq(xa)		spin_lock_irq(&(xa)->xa_lock)
#define cc_xa_unlock_irq(xa)		spin_unlock_irq(&(xa)->xa_lock)
#define cc_xa_lock_irqsave(xa, flags) \
				spin_lock_irqsave(&(xa)->xa_lock, flags)
#define cc_xa_unlock_irqrestore(xa, flags) \
				spin_unlock_irqrestore(&(xa)->xa_lock, flags)
#define cc_xas_is_ccxarray(xas)	\
			cc_xa_is_ccxarray((__force struct cc_xarray*)(xas)->xa)

/*
 * Versions of the normal API which require the caller to hold the
 * xa_lock.  If the GFP flags allow it, they will drop the lock to
 * allocate memory, then reacquire it afterwards.  These functions
 * may also re-enable interrupts if the XArray flags indicate the
 * locking should be interrupt safe.
 */
void *__cc_xa_erase(struct cc_xarray *, unsigned long index);
void *__cc_xa_store(struct cc_xarray *, unsigned long index, void *entry, gfp_t);
void *__cc_xa_cmpxchg(struct cc_xarray *, unsigned long index, void *old,
		void *entry, gfp_t);
int __must_check __cc_xa_insert(struct cc_xarray *, unsigned long index,
		void *entry, gfp_t);
int __must_check __cc_xa_alloc(struct cc_xarray *, u32 *id, void *entry,
		struct xa_limit, gfp_t);
int __must_check __cc_xa_alloc_cyclic(struct cc_xarray *, u32 *id, void *entry,
		struct xa_limit, u32 *next, gfp_t);
void __cc_xa_set_mark(struct cc_xarray *, unsigned long index, cc_xa_mark_t);
void __cc_xa_clear_mark(struct cc_xarray *, unsigned long index, cc_xa_mark_t);

/**
 * cc_xa_store_bh() - Store this entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * This function is like calling cc_xa_store() except it disables softirqs
 * while holding the array lock.
 *
 * Context: Any context.  Takes and releases the xa_lock while
 * disabling softirqs.
 * Return: The entry which used to be at this index.
 */
static inline void *cc_xa_store_bh(struct cc_xarray *xa, unsigned long index,
		void *entry, gfp_t gfp)
{
	void *curr;

	cc_xa_lock_bh(xa);
	curr = __cc_xa_store(xa, index, entry, gfp);
	cc_xa_unlock_bh(xa);

	return curr;
}

/**
 * cc_xa_store_irq() - Store this entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * This function is like calling cc_xa_store() except it disables interrupts
 * while holding the array lock.
 *
 * Context: Process context.  Takes and releases the xa_lock while
 * disabling interrupts.
 * Return: The entry which used to be at this index.
 */
static inline void *cc_xa_store_irq(struct cc_xarray *xa, unsigned long index,
		void *entry, gfp_t gfp)
{
	void *curr;

	cc_xa_lock_irq(xa);
	curr = __cc_xa_store(xa, index, entry, gfp);
	cc_xa_unlock_irq(xa);

	return curr;
}

/**
 * cc_xa_erase_bh() - Erase this entry from the XArray.
 * @xa: XArray.
 * @index: Index of entry.
 *
 * After this function returns, loading from @index will return %NULL.
 * If the index is part of a multi-index entry, all indices will be erased
 * and none of the entries will be part of a multi-index entry.
 *
 * Context: Any context.  Takes and releases the xa_lock while
 * disabling softirqs.
 * Return: The entry which used to be at this index.
 */
static inline void *cc_xa_erase_bh(struct cc_xarray *xa, unsigned long index)
{
	void *entry;

	cc_xa_lock_bh(xa);
	entry = __cc_xa_erase(xa, index);
	cc_xa_unlock_bh(xa);

	return entry;
}

/**
 * cc_xa_erase_irq() - Erase this entry from the XArray.
 * @xa: XArray.
 * @index: Index of entry.
 *
 * After this function returns, loading from @index will return %NULL.
 * If the index is part of a multi-index entry, all indices will be erased
 * and none of the entries will be part of a multi-index entry.
 *
 * Context: Process context.  Takes and releases the xa_lock while
 * disabling interrupts.
 * Return: The entry which used to be at this index.
 */
static inline void *cc_xa_erase_irq(struct cc_xarray *xa, unsigned long index)
{
	void *entry;

	cc_xa_lock_irq(xa);
	entry = __cc_xa_erase(xa, index);
	cc_xa_unlock_irq(xa);

	return entry;
}

/**
 * cc_xa_cmpxchg() - Conditionally replace an entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @old: Old value to test against.
 * @entry: New value to place in array.
 * @gfp: Memory allocation flags.
 *
 * If the entry at @index is the same as @old, replace it with @entry.
 * If the return value is equal to @old, then the exchange was successful.
 *
 * Context: Any context.  Takes and releases the xa_lock.  May sleep
 * if the @gfp flags permit.
 * Return: The old value at this index or cc_xa_err() if an error happened.
 */
static inline void *cc_xa_cmpxchg(struct cc_xarray *xa, unsigned long index,
			void *old, void *entry, gfp_t gfp)
{
	void *curr;

	cc_xa_lock(xa);
	curr = __cc_xa_cmpxchg(xa, index, old, entry, gfp);
	cc_xa_unlock(xa);

	return curr;
}

/**
 * cc_xa_cmpxchg_bh() - Conditionally replace an entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @old: Old value to test against.
 * @entry: New value to place in array.
 * @gfp: Memory allocation flags.
 *
 * This function is like calling cc_xa_cmpxchg() except it disables softirqs
 * while holding the array lock.
 *
 * Context: Any context.  Takes and releases the xa_lock while
 * disabling softirqs.  May sleep if the @gfp flags permit.
 * Return: The old value at this index or cc_xa_err() if an error happened.
 */
static inline void *cc_xa_cmpxchg_bh(struct cc_xarray *xa, unsigned long index,
			void *old, void *entry, gfp_t gfp)
{
	void *curr;

	cc_xa_lock_bh(xa);
	curr = __cc_xa_cmpxchg(xa, index, old, entry, gfp);
	cc_xa_unlock_bh(xa);

	return curr;
}

/**
 * cc_xa_cmpxchg_irq() - Conditionally replace an entry in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @old: Old value to test against.
 * @entry: New value to place in array.
 * @gfp: Memory allocation flags.
 *
 * This function is like calling cc_xa_cmpxchg() except it disables interrupts
 * while holding the array lock.
 *
 * Context: Process context.  Takes and releases the xa_lock while
 * disabling interrupts.  May sleep if the @gfp flags permit.
 * Return: The old value at this index or cc_xa_err() if an error happened.
 */
static inline void *cc_xa_cmpxchg_irq(struct cc_xarray *xa, unsigned long index,
			void *old, void *entry, gfp_t gfp)
{
	void *curr;

	cc_xa_lock_irq(xa);
	curr = __cc_xa_cmpxchg(xa, index, old, entry, gfp);
	cc_xa_unlock_irq(xa);

	return curr;
}

/**
 * cc_xa_insert() - Store this entry in the XArray unless another entry is
 *			already present.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * Inserting a NULL entry will store a reserved entry (like cc_xa_reserve())
 * if no entry is present.  Inserting will fail if a reserved entry is
 * present, even though loading from this index will return NULL.
 *
 * Context: Any context.  Takes and releases the xa_lock.  May sleep if
 * the @gfp flags permit.
 * Return: 0 if the store succeeded.  -EBUSY if another entry was present.
 * -ENOMEM if memory could not be allocated.
 */
static inline int __must_check cc_xa_insert(struct cc_xarray *xa,
		unsigned long index, void *entry, gfp_t gfp)
{
	int err;

	cc_xa_lock(xa);
	err = __cc_xa_insert(xa, index, entry, gfp);
	cc_xa_unlock(xa);

	return err;
}

/**
 * cc_xa_insert_bh() - Store this entry in the XArray unless another entry is
 *			already present.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * Inserting a NULL entry will store a reserved entry (like cc_xa_reserve())
 * if no entry is present.  Inserting will fail if a reserved entry is
 * present, even though loading from this index will return NULL.
 *
 * Context: Any context.  Takes and releases the xa_lock while
 * disabling softirqs.  May sleep if the @gfp flags permit.
 * Return: 0 if the store succeeded.  -EBUSY if another entry was present.
 * -ENOMEM if memory could not be allocated.
 */
static inline int __must_check cc_xa_insert_bh(struct cc_xarray *xa,
		unsigned long index, void *entry, gfp_t gfp)
{
	int err;

	cc_xa_lock_bh(xa);
	err = __cc_xa_insert(xa, index, entry, gfp);
	cc_xa_unlock_bh(xa);

	return err;
}

/**
 * cc_xa_insert_irq() - Store this entry in the XArray unless another entry is
 *			already present.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * Inserting a NULL entry will store a reserved entry (like cc_xa_reserve())
 * if no entry is present.  Inserting will fail if a reserved entry is
 * present, even though loading from this index will return NULL.
 *
 * Context: Process context.  Takes and releases the xa_lock while
 * disabling interrupts.  May sleep if the @gfp flags permit.
 * Return: 0 if the store succeeded.  -EBUSY if another entry was present.
 * -ENOMEM if memory could not be allocated.
 */
static inline int __must_check cc_xa_insert_irq(struct cc_xarray *xa,
		unsigned long index, void *entry, gfp_t gfp)
{
	int err;

	cc_xa_lock_irq(xa);
	err = __cc_xa_insert(xa, index, entry, gfp);
	cc_xa_unlock_irq(xa);

	return err;
}

/**
 * cc_xa_alloc() - Find somewhere to store this entry in the XArray.
 * @xa: XArray.
 * @id: Pointer to ID.
 * @entry: New entry.
 * @limit: Range of ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Finds an empty entry in @xa between @limit.min and @limit.max,
 * stores the index into the @id pointer, then stores the entry at
 * that index.  A concurrent lookup will not see an uninitialised @id.
 *
 * Context: Any context.  Takes and releases the xa_lock.  May sleep if
 * the @gfp flags permit.
 * Return: 0 on success, -ENOMEM if memory could not be allocated or
 * -EBUSY if there are no free entries in @limit.
 */
static inline __must_check int cc_xa_alloc(struct cc_xarray *xa, u32 *id,
		void *entry, struct xa_limit limit, gfp_t gfp)
{
	int err;

	cc_xa_lock(xa);
	err = __cc_xa_alloc(xa, id, entry, limit, gfp);
	cc_xa_unlock(xa);

	return err;
}

/**
 * cc_xa_alloc_bh() - Find somewhere to store this entry in the XArray.
 * @xa: XArray.
 * @id: Pointer to ID.
 * @entry: New entry.
 * @limit: Range of ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Finds an empty entry in @xa between @limit.min and @limit.max,
 * stores the index into the @id pointer, then stores the entry at
 * that index.  A concurrent lookup will not see an uninitialised @id.
 *
 * Context: Any context.  Takes and releases the xa_lock while
 * disabling softirqs.  May sleep if the @gfp flags permit.
 * Return: 0 on success, -ENOMEM if memory could not be allocated or
 * -EBUSY if there are no free entries in @limit.
 */
static inline int __must_check cc_xa_alloc_bh(struct cc_xarray *xa, u32 *id,
		void *entry, struct xa_limit limit, gfp_t gfp)
{
	int err;

	cc_xa_lock_bh(xa);
	err = __cc_xa_alloc(xa, id, entry, limit, gfp);
	cc_xa_unlock_bh(xa);

	return err;
}

/**
 * cc_xa_alloc_irq() - Find somewhere to store this entry in the XArray.
 * @xa: XArray.
 * @id: Pointer to ID.
 * @entry: New entry.
 * @limit: Range of ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Finds an empty entry in @xa between @limit.min and @limit.max,
 * stores the index into the @id pointer, then stores the entry at
 * that index.  A concurrent lookup will not see an uninitialised @id.
 *
 * Context: Process context.  Takes and releases the xa_lock while
 * disabling interrupts.  May sleep if the @gfp flags permit.
 * Return: 0 on success, -ENOMEM if memory could not be allocated or
 * -EBUSY if there are no free entries in @limit.
 */
static inline int __must_check cc_xa_alloc_irq(struct cc_xarray *xa, u32 *id,
		void *entry, struct xa_limit limit, gfp_t gfp)
{
	int err;

	cc_xa_lock_irq(xa);
	err = __cc_xa_alloc(xa, id, entry, limit, gfp);
	cc_xa_unlock_irq(xa);

	return err;
}

/**
 * cc_xa_alloc_cyclic() - Find somewhere to store this entry in the XArray.
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
 * Context: Any context.  Takes and releases the xa_lock.  May sleep if
 * the @gfp flags permit.
 * Return: 0 if the allocation succeeded without wrapping.  1 if the
 * allocation succeeded after wrapping, -ENOMEM if memory could not be
 * allocated or -EBUSY if there are no free entries in @limit.
 */
static inline int cc_xa_alloc_cyclic(struct cc_xarray *xa, u32 *id, void *entry,
		struct xa_limit limit, u32 *next, gfp_t gfp)
{
	int err;

	cc_xa_lock(xa);
	err = __cc_xa_alloc_cyclic(xa, id, entry, limit, next, gfp);
	cc_xa_unlock(xa);

	return err;
}

/**
 * cc_xa_alloc_cyclic_bh() - Find somewhere to store this entry in the XArray.
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
 * Context: Any context.  Takes and releases the xa_lock while
 * disabling softirqs.  May sleep if the @gfp flags permit.
 * Return: 0 if the allocation succeeded without wrapping.  1 if the
 * allocation succeeded after wrapping, -ENOMEM if memory could not be
 * allocated or -EBUSY if there are no free entries in @limit.
 */
static inline int cc_xa_alloc_cyclic_bh(struct cc_xarray *xa, u32 *id, void *entry,
		struct xa_limit limit, u32 *next, gfp_t gfp)
{
	int err;

	cc_xa_lock_bh(xa);
	err = __cc_xa_alloc_cyclic(xa, id, entry, limit, next, gfp);
	cc_xa_unlock_bh(xa);

	return err;
}

/**
 * cc_xa_alloc_cyclic_irq() - Find somewhere to store this entry in the XArray.
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
 * Context: Process context.  Takes and releases the xa_lock while
 * disabling interrupts.  May sleep if the @gfp flags permit.
 * Return: 0 if the allocation succeeded without wrapping.  1 if the
 * allocation succeeded after wrapping, -ENOMEM if memory could not be
 * allocated or -EBUSY if there are no free entries in @limit.
 */
static inline int cc_xa_alloc_cyclic_irq(struct cc_xarray *xa, u32 *id, void *entry,
		struct xa_limit limit, u32 *next, gfp_t gfp)
{
	int err;

	cc_xa_lock_irq(xa);
	err = __cc_xa_alloc_cyclic(xa, id, entry, limit, next, gfp);
	cc_xa_unlock_irq(xa);

	return err;
}

/**
 * cc_xa_reserve() - Reserve this index in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @gfp: Memory allocation flags.
 *
 * Ensures there is somewhere to store an entry at @index in the array.
 * If there is already something stored at @index, this function does
 * nothing.  If there was nothing there, the entry is marked as reserved.
 * Loading from a reserved entry returns a %NULL pointer.
 *
 * If you do not use the entry that you have reserved, call cc_xa_release()
 * or cc_xa_erase() to free any unnecessary memory.
 *
 * Context: Any context.  Takes and releases the xa_lock.
 * May sleep if the @gfp flags permit.
 * Return: 0 if the reservation succeeded or -ENOMEM if it failed.
 */
static inline __must_check
int cc_xa_reserve(struct cc_xarray *xa, unsigned long index, gfp_t gfp)
{
	return cc_xa_err(cc_xa_cmpxchg(xa, index, NULL, CC_XA_ZERO_ENTRY, gfp));
}

/**
 * cc_xa_reserve_bh() - Reserve this index in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @gfp: Memory allocation flags.
 *
 * A softirq-disabling version of cc_xa_reserve().
 *
 * Context: Any context.  Takes and releases the xa_lock while
 * disabling softirqs.
 * Return: 0 if the reservation succeeded or -ENOMEM if it failed.
 */
static inline __must_check
int cc_xa_reserve_bh(struct cc_xarray *xa, unsigned long index, gfp_t gfp)
{
	return cc_xa_err(cc_xa_cmpxchg_bh(xa, index, NULL, CC_XA_ZERO_ENTRY, gfp));
}

/**
 * cc_xa_reserve_irq() - Reserve this index in the XArray.
 * @xa: XArray.
 * @index: Index into array.
 * @gfp: Memory allocation flags.
 *
 * An interrupt-disabling version of cc_xa_reserve().
 *
 * Context: Process context.  Takes and releases the xa_lock while
 * disabling interrupts.
 * Return: 0 if the reservation succeeded or -ENOMEM if it failed.
 */
static inline __must_check
int cc_xa_reserve_irq(struct cc_xarray *xa, unsigned long index, gfp_t gfp)
{
	return cc_xa_err(cc_xa_cmpxchg_irq(xa, index, NULL, CC_XA_ZERO_ENTRY, gfp));
}

/**
 * cc_xa_release() - Release a reserved entry.
 * @xa: XArray.
 * @index: Index of entry.
 *
 * After calling cc_xa_reserve(), you can call this function to release the
 * reservation.  If the entry at @index has been stored to, this function
 * will do nothing.
 */
static inline void cc_xa_release(struct cc_xarray *xa, unsigned long index)
{
	cc_xa_cmpxchg(xa, index, CC_XA_ZERO_ENTRY, NULL, 0);
}

/* Everything below here is the Advanced API.  Proceed with caution. */

/*
 * The cc_xarray is constructed out of a set of 'chunks' of pointers.  Choosing
 * the best chunk size requires some tradeoffs.  A power of two recommends
 * itself so that we can walk the tree based purely on shifts and masks.
 * Generally, the larger the better; as the number of slots per level of the
 * tree increases, the less tall the tree needs to be.  But that needs to be
 * balanced against the memory consumption of each node.  On a 64-bit system,
 * cc_xa_node is currently 576 bytes, and we get 7 of them per 4kB page.  If we
 * doubled the number of slots per node, we'd get only 3 nodes per 4kB page.
 */
#ifndef CC_XA_CHUNK_SHIFT
#define CC_XA_CHUNK_SHIFT		(CONFIG_BASE_SMALL ? 4 : 6)
#endif
#define CC_XA_CHUNK_SIZE		(1UL << CC_XA_CHUNK_SHIFT)
#define CC_XA_CHUNK_MASK		(CC_XA_CHUNK_SIZE - 1)
#define CC_XA_MAX_MARKS		3
#define CC_XA_MARK_LONGS		DIV_ROUND_UP(CC_XA_CHUNK_SIZE, BITS_PER_LONG)

/*
 * @count is the count of every non-NULL element in the ->slots array
 * whether that is a value entry, a retry entry, a user pointer,
 * a sibling entry or a pointer to the next level of the tree.
 * @nr_values is the count of every element in ->slots which is
 * either a value entry or a sibling of a value entry.
 */
struct cc_xa_node {
	unsigned char	shift;		/* Bits remaining in each slot */
	unsigned char	offset;		/* Slot offset in parent */
	unsigned char	count;		/* Total entry count */
	unsigned char	nr_values;	/* Value entry count */
	unsigned char	gc_flag;	/* Under deleting */
	unsigned char	del;		/* Logically deleted */
	unsigned short	refcnt;		/* Referencing users */
	struct cc_xa_node __rcu *parent;	/* NULL at top of tree */
	struct cc_xarray	*array;		/* The array we belong to */
	union {
		struct list_head private_list;	/* For tree user */
		struct rcu_head	rcu_head;	/* Used when freeing node */
	};
	void __rcu	*slots[CC_XA_CHUNK_SIZE];
	union {
		unsigned long	tags[CC_XA_MAX_MARKS][CC_XA_MARK_LONGS];
		unsigned long	marks[CC_XA_MAX_MARKS][CC_XA_MARK_LONGS];
	};
};

void cc_xa_dump(const struct cc_xarray *);
void cc_xa_dump_node(const struct cc_xa_node *);

void cc_xa_garbage_collector(struct cc_xarray *xa);

#define CC_XA_DEBUG
#ifdef CC_XA_DEBUG
#define CC_XA_BUG_ON(xa, x) do {				\
		if (x) {					\
			cc_xa_dump(xa);				\
			BUG();					\
		}						\
	} while (0)
#define CC_XA_NODE_BUG_ON(node, x) do {				\
		if (x) {					\
			if (node) cc_xa_dump_node(node);	\
			BUG();					\
		}						\
	} while (0)
#define CC_XA_NODE_WARN_ON(node, x, format...) do {		\
		if (x) {					\
			if (node) cc_xa_dump_node(node);	\
			WARN_ONCE(x, format);			\
		}						\
	} while (0)
#else
#define CC_XA_BUG_ON(xa, x)	do { } while (0)
#define CC_XA_NODE_BUG_ON(node, x)	do { } while (0)
#define CC_XA_NODE_WARN_ON(node, x, format...)	do { } while (0)
#endif
#undef CC_XA_DEBUG

/* Private */
static inline void *cc_xa_head(const struct cc_xarray *xa)
{
	//return rcu_dereference_check(xa->xa_head,
	//					lockdep_is_held(&xa->xa_lock));
	return __atomic_load_n(&xa->xa_head, __ATOMIC_SEQ_CST);
}

/* Private */
static inline void *cc_xa_head_locked(const struct cc_xarray *xa)
{
	//return rcu_dereference_protected(xa->xa_head,
	//					lockdep_is_held(&xa->xa_lock));
	return __atomic_load_n(&xa->xa_head, __ATOMIC_SEQ_CST);
}

/* Private */
static inline void *cc_xa_entry(const struct cc_xarray *xa,
				const struct cc_xa_node *node, unsigned int offset)
{
	CC_XA_NODE_BUG_ON(node, offset >= CC_XA_CHUNK_SIZE);
	//return rcu_dereference_check(node->slots[offset],
	//					lockdep_is_held(&xa->xa_lock));
	return __atomic_load_n(&node->slots[offset], __ATOMIC_SEQ_CST);
}

/* Private */
static inline void *cc_xa_entry_locked(const struct cc_xarray *xa,
				const struct cc_xa_node *node, unsigned int offset)
{
	CC_XA_NODE_BUG_ON(node, offset >= CC_XA_CHUNK_SIZE);
	//return rcu_dereference_protected(node->slots[offset],
	//					lockdep_is_held(&xa->xa_lock));
	return __atomic_load_n(&node->slots[offset], __ATOMIC_SEQ_CST);
}

/* Private */
static inline struct cc_xa_node *cc_xa_parent(const struct cc_xarray *xa,
					const struct cc_xa_node *node)
{
	//return rcu_dereference_check(node->parent,
	//					lockdep_is_held(&xa->xa_lock));
	return __atomic_load_n(&node->parent, __ATOMIC_SEQ_CST);
}

/* Private */
static inline struct cc_xa_node *cc_xa_parent_locked(const struct cc_xarray *xa,
					const struct cc_xa_node *node)
{
	//return rcu_dereference_protected(node->parent,
	//					lockdep_is_held(&xa->xa_lock));
	return __atomic_load_n(&node->parent, __ATOMIC_SEQ_CST);
}

/* Private */
static inline void *cc_xa_mk_node(const struct cc_xa_node *node)
{
	return (void *)((unsigned long)node | 2);
}

/* Private */
static inline struct cc_xa_node *cc_xa_to_node(const void *entry)
{
	return (struct cc_xa_node *)((unsigned long)entry - 2);
}

/* Private */
static inline bool cc_xa_is_node(const void *entry)
{
	return cc_xa_is_internal(entry) && (unsigned long)entry > 4096;
}

/* Private */
static inline void *cc_xa_mk_sibling(unsigned int offset)
{
	return cc_xa_mk_internal(offset);
}

/* Private */
static inline unsigned long cc_xa_to_sibling(const void *entry)
{
	return cc_xa_to_internal(entry);
}

/**
 * cc_xa_is_sibling() - Is the entry a sibling entry?
 * @entry: Entry retrieved from the XArray
 *
 * Return: %true if the entry is a sibling entry.
 */
static inline bool cc_xa_is_sibling(const void *entry)
{
	return IS_ENABLED(CONFIG_XARRAY_MULTI) && cc_xa_is_internal(entry) &&
		(entry < cc_xa_mk_sibling(CC_XA_CHUNK_SIZE - 1));
}

#define CC_XA_RETRY_ENTRY		cc_xa_mk_internal(256)

/**
 * cc_xa_is_retry() - Is the entry a retry entry?
 * @entry: Entry retrieved from the XArray
 *
 * Return: %true if the entry is a retry entry.
 */
static inline bool cc_xa_is_retry(const void *entry)
{
	return unlikely(entry == CC_XA_RETRY_ENTRY);
}

/**
 * cc_xa_is_advanced() - Is the entry only permitted for the advanced API?
 * @entry: Entry to be stored in the XArray.
 *
 * Return: %true if the entry cannot be stored by the normal API.
 */
static inline bool cc_xa_is_advanced(const void *entry)
{
	return cc_xa_is_internal(entry) && (entry <= CC_XA_RETRY_ENTRY);
}

/**
 * typedef xa_update_node_t - A callback function from the XArray.
 * @node: The node which is being processed
 *
 * This function is called every time the XArray updates the count of
 * present and value entries in a node.  It allows advanced users to
 * maintain the private_list in the node.
 *
 * Context: The xa_lock is held and interrupts may be disabled.
 *	    Implementations should not drop the xa_lock, nor re-enable
 *	    interrupts.
 */
typedef void (*cc_xa_update_node_t)(struct cc_xa_node *node);

/*
 * The cc_xa_state is opaque to its users.  It contains various different pieces
 * of state involved in the current operation on the XArray.  It should be
 * declared on the stack and passed between the various internal routines.
 * The various elements in it should not be accessed directly, but only
 * through the provided accessor functions.  The below documentation is for
 * the benefit of those working on the code, not for users of the XArray.
 *
 * @xa_node usually points to the cc_xa_node containing the slot we're operating
 * on (and @xa_offset is the offset in the slots array).  If there is a
 * single entry in the array at index 0, there are no allocated cc_xa_nodes to
 * point to, and so we store %NULL in @xa_node.  @xa_node is set to
 * the value %CC_XAS_RESTART if the cc_xa_state is not walked to the correct
 * position in the tree of nodes for this operation.  If an error occurs
 * during an operation, it is set to an %CC_XAS_ERROR value.  If we run off the
 * end of the allocated nodes, it is set to %CC_XAS_BOUNDS.
 */
struct cc_xa_state {
	struct cc_xarray *xa;
	unsigned long xa_index;
	unsigned char xa_shift;
	unsigned char xa_sibs;
	unsigned char xa_offset;
	unsigned char xa_pad;		/* Helps gcc generate better code */
	union {
		struct cc_xa_node * const xa_node;
		struct cc_xa_node *__xa_node;	/* Private, do not access directly! */
	};
	struct cc_xa_node *xa_alloc;
	cc_xa_update_node_t xa_update;
	struct cc_xa_node *trace_root;	/* Node trace root */
	struct cc_xa_node *trace_leaf;	/* Node trace leaf */
	int nr_refget;			/* Counter for get_node */
};

/*
 * We encode errnos in the xas->xa_node.  If an error has happened, we need to
 * drop the lock to fix it, and once we've done so the cc_xa_state is invalid.
 */
#define CC_XA_ERROR(errno) ((struct cc_xa_node *)(((unsigned long)errno << 2) | 2UL))
#define CC_XAS_BOUNDS	((struct cc_xa_node *)1UL)
#define CC_XAS_RESTART	((struct cc_xa_node *)3UL)

#define __CC_XA_STATE(name, array, index, shift, sibs)  {	\
	.xa = array,						\
	.xa_index = index,					\
	.xa_shift = shift,					\
	.xa_sibs = sibs,					\
	.xa_offset = 0,						\
	.xa_pad = 0,						\
	.xa_node = CC_XAS_RESTART,				\
	.xa_alloc = NULL,					\
	.xa_update = NULL,					\
	.trace_root = NULL,					\
	.trace_leaf = NULL,					\
	.nr_refget = 0,						\
}

/**
 * CC_XA_STATE() - Declare an XArray operation state.
 * @name: Name of this operation state (usually xas).
 * @array: Array to operate on.
 * @index: Initial index of interest.
 *
 * Declare and initialise an cc_xa_state on the stack.
 */
#define CC_XA_STATE(name, array, index)				\
	struct cc_xa_state name = __CC_XA_STATE(name, array, index, 0, 0)

/**
 * CC_XA_STATE_ORDER() - Declare an XArray operation state.
 * @name: Name of this operation state (usually xas).
 * @array: Array to operate on.
 * @index: Initial index of interest.
 * @order: Order of entry.
 *
 * Declare and initialise an cc_xa_state on the stack.  This variant of
 * CC_XA_STATE() allows you to specify the 'order' of the element you
 * want to operate on.`
 */
#define CC_XA_STATE_ORDER(name, array, index, order)		\
	struct cc_xa_state name = __CC_XA_STATE(name, array,	\
			(index >> order) << order,		\
			order - (order % CC_XA_CHUNK_SHIFT),	\
			(1U << (order % CC_XA_CHUNK_SHIFT)) - 1)

#define cc_xas_marked(xas, mark)	cc_xa_marked((xas)->xa, (mark))
#define cc_xas_trylock(xas)		cc_xa_trylock((xas)->xa)
#define cc_xas_lock(xas)		cc_xa_lock((xas)->xa)
#define cc_xas_unlock(xas)		cc_xa_unlock((xas)->xa)
#define cc_xas_lock_bh(xas)		cc_xa_lock_bh((xas)->xa)
#define cc_xas_unlock_bh(xas)		cc_xa_unlock_bh((xas)->xa)
#define cc_xas_lock_irq(xas)		cc_xa_lock_irq((xas)->xa)
#define cc_xas_unlock_irq(xas)		cc_xa_unlock_irq((xas)->xa)
#define cc_xas_lock_irqsave(xas, flags) \
					cc_xa_lock_irqsave((xas)->xa, flags)
#define cc_xas_unlock_irqrestore(xas, flags) \
					cc_xa_unlock_irqrestore((xas)->xa, flags)

static inline bool cc_xas_not_node(const struct cc_xa_node *node);

/* Private */
static inline int
cc_xa_put_node(struct cc_xa_state *xas, struct cc_xa_node *node)
{
	int refcnt;
	if (cc_xas_not_node(node))
		return -1;
	refcnt = __sync_fetch_and_sub(&node->refcnt, 1);
	if ((--xas->nr_refget) < 0)
		pr_err("nr_refget-- negative!!\n");
	CC_XA_NODE_WARN_ON(node, refcnt == 0, "refcount-- OVERFLOW!!");
	/* Reached node trace root, clear the root node */
	if (xas->trace_root == node) {
		xas->trace_root = NULL;
		xas->trace_leaf = NULL;
	}
	return refcnt-1;
}

/* Private */
static inline struct cc_xa_node *
cc_xa_get_node(struct cc_xa_state *xas, struct cc_xa_node *node)
{
	int refcnt;

	if (cc_xas_not_node(node))
		return node;
	refcnt = __sync_fetch_and_add(&node->refcnt, 1);
	CC_XA_NODE_WARN_ON(node, refcnt == USHRT_MAX, "refcount++ OVERFLOW!!");

	/* Set node trace root */
	if (!xas->trace_root)
		xas->trace_root = node;
	xas->trace_leaf = node;
	xas->nr_refget++;
	return node;
}

/**
 * cc_xas_error() - Return an errno stored in the cc_xa_state.
 * @xas: XArray operation state.
 *
 * Return: 0 if no error has been noted.  A negative errno if one has.
 */
static inline int cc_xas_error(const struct cc_xa_state *xas)
{
	return cc_xa_err(xas->xa_node);
}

static inline void cc_xas_set_xa_node(struct cc_xa_state *xas, struct cc_xa_node *node);

/**
 * cc_xas_set_err() - Note an error in the cc_xa_state.
 * @xas: XArray operation state.
 * @err: Negative error number.
 *
 * Only call this function with a negative @err; zero or positive errors
 * will probably not behave the way you think they should.  If you want
 * to clear the error from an cc_xa_state, use cc_xas_reset().
 */
static inline void cc_xas_set_err(struct cc_xa_state *xas, long err)
{
	//xas->xa_node = CC_XA_ERROR(err);
	cc_xas_set_xa_node(xas, CC_XA_ERROR(err));
}

/**
 * cc_xas_invalid() - Is the xas in a retry or error state?
 * @xas: XArray operation state.
 *
 * Return: %true if the xas cannot be used for operations.
 */
static inline bool cc_xas_invalid(const struct cc_xa_state *xas)
{
	return ((unsigned long)xas->xa_node & 3);
}

/**
 * cc_xas_valid() - Is the xas a valid cursor into the array?
 * @xas: XArray operation state.
 *
 * Return: %true if the xas can be used for operations.
 */
static inline bool cc_xas_valid(const struct cc_xa_state *xas)
{
	return !cc_xas_invalid(xas);
}

/**
 * cc_xas_is_node() - Does the xas point to a node?
 * @xas: XArray operation state.
 *
 * Return: %true if the xas currently references a node.
 */
static inline bool cc_xas_is_node(const struct cc_xa_state *xas)
{
	return cc_xas_valid(xas) && xas->xa_node;
}

/* True if the pointer is something other than a node */
static inline bool cc_xas_not_node(const struct cc_xa_node *node)
{
	return ((unsigned long)node & 3) || !node;
}

/* Set xas.xa_node and increase refcnt, after decreasing old xa_node refcnt */
static inline void
cc_xas_set_xa_node(struct cc_xa_state *xas, struct cc_xa_node *node)
{
	struct cc_xa_node *old = xas->xa_node;
	int refcnt = -1;

	if (old == node)
		return;

	if (!cc_xas_not_node(node)) {
		refcnt = __sync_fetch_and_add(&node->refcnt, 1);
		CC_XA_NODE_WARN_ON(node, refcnt == USHRT_MAX, "refcount++ OVERFLOW!!");
	}

	xas->__xa_node = node;
	if (!cc_xas_not_node(old)) {
		refcnt = __sync_fetch_and_sub(&old->refcnt, 1);
		CC_XA_NODE_WARN_ON(node, refcnt == 0, "refcount-- OVERFLOW!!");
	}
}

/* Revert node's refcnt in the node_trace list and remove from the list */
static inline void cc_xas_rewind_refcnt(struct cc_xa_state *xas)
{
	struct cc_xa_node *node = xas->trace_leaf;

	while (!cc_xas_not_node(node)) {
		cc_xa_put_node(xas, node);
		if (xas->trace_root == NULL) {
			xas->trace_leaf = NULL;
			break;
		}
		node = cc_xa_parent(xas->xa, node);
	}
	CC_XA_BUG_ON(xas->xa, xas->nr_refget);
}

/* True if the node represents RESTART or an error */
static inline bool cc_xas_frozen(struct cc_xa_node *node)
{
	return (unsigned long)node & 2;
}

/* True if the node represents head-of-tree, RESTART or BOUNDS */
static inline bool cc_xas_top(const struct cc_xa_node *node)
{
	return node <= CC_XAS_RESTART;
}

/**
 * cc_xas_reset() - Reset an XArray operation state.
 * @xas: XArray operation state.
 *
 * Resets the error or walk state of the @xas so future walks of the
 * array will start from the root.  Use this if you have dropped the
 * cc_xarray lock and want to reuse the cc_xa_state.
 *
 * Decreases xas->xa_node refcnt.
 *
 * Context: Any context.
 */
static inline void cc_xas_reset(struct cc_xa_state *xas)
{
	//xas->xa_node = CC_XAS_RESTART;
	cc_xas_set_xa_node(xas, CC_XAS_RESTART);
}

/* Decrease xas->xa_node refcnt and reset xas->xa_node */
#define cc_xas_clear_xa_node(xas)	cc_xas_reset(xas)

/**
 * cc_xas_retry() - Retry the operation if appropriate.
 * @xas: XArray operation state.
 * @entry: Entry from cc_xarray.
 *
 * The advanced functions may sometimes return an internal entry, such as
 * a retry entry or a zero entry.  This function sets up the @xas to restart
 * the walk from the head of the array if needed.
 *
 * Context: Any context.
 * Return: true if the operation needs to be retried.
 */
static inline bool cc_xas_retry(struct cc_xa_state *xas, const void *entry)
{
	if (cc_xa_is_zero(entry))
		return true;
	if (!cc_xa_is_retry(entry))
		return false;
	cc_xas_reset(xas);
	return true;
}

void *cc_xas_load(struct cc_xa_state *, bool rewind);
void *cc_xas_store(struct cc_xa_state *, void *entry);
void *cc_xas_find(struct cc_xa_state *, unsigned long max);
void *cc_xas_find_conflict(struct cc_xa_state *);

bool cc_xas_get_mark(const struct cc_xa_state *, cc_xa_mark_t);
void cc_xas_set_mark(const struct cc_xa_state *, cc_xa_mark_t);
void cc_xas_clear_mark(const struct cc_xa_state *, cc_xa_mark_t);
void *cc_xas_find_marked(struct cc_xa_state *, unsigned long max, cc_xa_mark_t);
void cc_xas_init_marks(const struct cc_xa_state *);

bool cc_xas_nomem(struct cc_xa_state *, gfp_t);
void cc_xas_pause(struct cc_xa_state *);

void cc_xas_create_range(struct cc_xa_state *);

#ifdef CONFIG_XARRAY_MULTI
int cc_xa_get_order(struct cc_xarray *, unsigned long index);
void cc_xas_split(struct cc_xa_state *, void *entry, unsigned int order);
void cc_xas_split_alloc(struct cc_xa_state *, void *entry, unsigned int order, gfp_t);
#else
static inline int cc_xa_get_order(struct cc_xarray *xa, unsigned long index)
{
	return 0;
}

static inline void cc_xas_split(struct cc_xa_state *xas, void *entry,
		unsigned int order)
{
	cc_xas_store(xas, entry);
}

static inline void cc_xas_split_alloc(struct cc_xa_state *xas, void *entry,
		unsigned int order, gfp_t gfp)
{
}
#endif

void cc_xa_garbage_collector(struct cc_xarray *xa);

/**
 * cc_xas_reload() - Refetch an entry from the cc_xarray.
 * @xas: XArray operation state.
 *
 * Use this function to check that a previously loaded entry still has
 * the same value.  This is useful for the lockless pagecache lookup where
 * we walk the array with only the RCU lock to protect us, lock the page,
 * then check that the page hasn't moved since we looked it up.
 *
 * The caller guarantees that @xas is still valid.  If it may be in an
 * error or restart state, call cc_xas_load() instead.
 *
 * Return: The entry at this location in the cc_xarray.
 */
static inline void *cc_xas_reload(struct cc_xa_state *xas)
{
	struct cc_xa_node *node = xas->xa_node;

	if (node)
		return cc_xa_entry(xas->xa, node, xas->xa_offset);
	return cc_xa_head(xas->xa);
}

/**
 * cc_xas_set() - Set up XArray operation state for a different index.
 * @xas: XArray operation state.
 * @index: New index into the XArray.
 *
 * Move the operation state to refer to a different index.  This will
 * have the effect of starting a walk from the top; see cc_xas_next()
 * to move to an adjacent index.
 */
static inline void cc_xas_set(struct cc_xa_state *xas, unsigned long index)
{
	xas->xa_index = index;
	//xas->xa_node = CC_XAS_RESTART;
	cc_xas_set_xa_node(xas, CC_XAS_RESTART);
}

/**
 * cc_xas_set_order() - Set up XArray operation state for a multislot entry.
 * @xas: XArray operation state.
 * @index: Target of the operation.
 * @order: Entry occupies 2^@order indices.
 */
static inline void cc_xas_set_order(struct cc_xa_state *xas, unsigned long index,
					unsigned int order)
{
#ifdef CONFIG_XARRAY_MULTI
	xas->xa_index = order < BITS_PER_LONG ? (index >> order) << order : 0;
	xas->xa_shift = order - (order % CC_XA_CHUNK_SHIFT);
	xas->xa_sibs = (1 << (order % CC_XA_CHUNK_SHIFT)) - 1;
	//xas->xa_node = CC_XAS_RESTART;
	cc_xas_set_xa_node(xas, CC_XAS_RESTART);
#else
	BUG_ON(order > 0);
	cc_xas_set(xas, index);
#endif
}

/**
 * cc_xas_set_update() - Set up XArray operation state for a callback.
 * @xas: XArray operation state.
 * @update: Function to call when updating a node.
 *
 * The XArray can notify a caller after it has updated an cc_xa_node.
 * This is advanced functionality and is only needed by the page cache.
 */
static inline void cc_xas_set_update(struct cc_xa_state *xas, cc_xa_update_node_t update)
{
	xas->xa_update = update;
}

void cc_workingset_update_node(struct cc_xa_node *node);
#define cc_mapping_set_update(xas, mapping) do {			\
	if (!dax_mapping(mapping) && !shmem_mapping(mapping))		\
		cc_xas_set_update(xas, cc_workingset_update_node);	\
} while (0)

/**
 * cc_xas_next_entry() - Advance iterator to next present entry.
 * @xas: XArray operation state.
 * @max: Highest index to return.
 *
 * cc_xas_next_entry() is an inline function to optimise cc_xarray traversal for
 * speed.  It is equivalent to calling cc_xas_find(), and will call cc_xas_find()
 * for all the hard cases.
 *
 * Return: The next present entry after the one currently referred to by @xas.
 */
static inline void *cc_xas_next_entry(struct cc_xa_state *xas, unsigned long max)
{
	struct cc_xa_node *node = xas->xa_node;
	void *entry;

	if (unlikely(cc_xas_not_node(node) || node->shift ||
			xas->xa_offset != (xas->xa_index & CC_XA_CHUNK_MASK)))
		return cc_xas_find(xas, max);

	/* wait for other thread */
	while (__atomic_load_n(&node->gc_flag, __ATOMIC_SEQ_CST))
		cpu_relax();

	/* node logically deleted! returning NULL */
	if (__atomic_load_n(&node->del, __ATOMIC_SEQ_CST)) {
		cc_xas_reset(xas);
		return NULL;
	}

	do {
		if (unlikely(xas->xa_index >= max))
			return cc_xas_find(xas, max);
		if (unlikely(xas->xa_offset == CC_XA_CHUNK_MASK))
			return cc_xas_find(xas, max);
		entry = cc_xa_entry(xas->xa, node, xas->xa_offset + 1);
		if (unlikely(cc_xa_is_internal(entry)))
			return cc_xas_find(xas, max);
		xas->xa_offset++;
		xas->xa_index++;
	} while (!entry);

	return entry;
}

/* Private */
static inline unsigned int cc_xas_find_chunk(struct cc_xa_state *xas, bool advance,
		cc_xa_mark_t mark)
{
	unsigned long *addr = xas->xa_node->marks[(__force unsigned)mark];
	unsigned int offset = xas->xa_offset;

	if (advance)
		offset++;
	if (CC_XA_CHUNK_SIZE == BITS_PER_LONG) {
		if (offset < CC_XA_CHUNK_SIZE) {
			unsigned long data = *addr & (~0UL << offset);
			if (data)
				return __ffs(data);
		}
		return CC_XA_CHUNK_SIZE;
	}

	return find_next_bit(addr, CC_XA_CHUNK_SIZE, offset);
}

/**
 * cc_xas_next_marked() - Advance iterator to next marked entry.
 * @xas: XArray operation state.
 * @max: Highest index to return.
 * @mark: Mark to search for.
 *
 * cc_xas_next_marked() is an inline function to optimise cc_xarray traversal 
 * for speed.  It is equivalent to calling cc_xas_find_marked(), and will call
 * cc_xas_find_marked() for all the hard cases.
 *
 * Return: The next marked entry after the one currently referred to by @xas.
 */
static inline void *cc_xas_next_marked(struct cc_xa_state *xas, unsigned long max,
								cc_xa_mark_t mark)
{
	struct cc_xa_node *node = xas->xa_node;
	void *entry;
	unsigned int offset;

	if (unlikely(cc_xas_not_node(node) || node->shift))
		return cc_xas_find_marked(xas, max, mark);
	offset = cc_xas_find_chunk(xas, true, mark);
	xas->xa_offset = offset;
	xas->xa_index = (xas->xa_index & ~CC_XA_CHUNK_MASK) + offset;
	if (xas->xa_index > max)
		return NULL;
	if (offset == CC_XA_CHUNK_SIZE)
		return cc_xas_find_marked(xas, max, mark);
	entry = cc_xa_entry(xas->xa, node, offset);
	if (!entry)
		return cc_xas_find_marked(xas, max, mark);
	return entry;
}

/*
 * If iterating while holding a lock, drop the lock and reschedule
 * every %CC_XA_CHECK_SCHED loops.
 */
enum {
	CC_XA_CHECK_SCHED = 4096,
};

/**
 * cc_xas_for_each() - Iterate over a range of an XArray.
 * @xas: XArray operation state.
 * @entry: Entry retrieved from the array.
 * @max: Maximum index to retrieve from array.
 *
 * The loop body will be executed for each entry present in the cc_xarray
 * between the current xas position and @max.  @entry will be set to
 * the entry retrieved from the cc_xarray.  It is safe to delete entries
 * from the array in the loop body.  You should hold either the RCU lock
 * or the xa_lock while iterating.  If you need to drop the lock, call
 * cc_xas_pause() first.
 */
#define cc_xas_for_each(xas, entry, max) \
	for (entry = cc_xas_find(xas, max); entry; \
	     entry = cc_xas_next_entry(xas, max))

/**
 * cc_xas_for_each_marked() - Iterate over a range of an XArray.
 * @xas: XArray operation state.
 * @entry: Entry retrieved from the array.
 * @max: Maximum index to retrieve from array.
 * @mark: Mark to search for.
 *
 * The loop body will be executed for each marked entry in the cc_xarray
 * between the current xas position and @max.  @entry will be set to
 * the entry retrieved from the cc_xarray.  It is safe to delete entries
 * from the array in the loop body.  You should hold either the RCU lock
 * or the xa_lock while iterating.  If you need to drop the lock, call
 * cc_xas_pause() first.
 */
#define cc_xas_for_each_marked(xas, entry, max, mark) \
	for (entry = cc_xas_find_marked(xas, max, mark); entry; \
	     entry = cc_xas_next_marked(xas, max, mark))

/**
 * cc_xas_for_each_conflict() - Iterate over a range of an XArray.
 * @xas: XArray operation state.
 * @entry: Entry retrieved from the array.
 *
 * The loop body will be executed for each entry in the XArray that lies
 * within the range specified by @xas.  If the loop completes successfully,
 * any entries that lie in this range will be replaced by @entry.  The caller
 * may break out of the loop; if they do so, the contents of the XArray will
 * be unchanged.  The operation may fail due to an out of memory condition.
 * The caller may also call cc_xa_set_err() to exit the loop while setting an
 * error to record the reason.
 */
#define cc_xas_for_each_conflict(xas, entry) \
	while ((entry = cc_xas_find_conflict(xas)))

void *__cc_xas_next(struct cc_xa_state *);
void *__cc_xas_prev(struct cc_xa_state *);

/**
 * cc_xas_prev() - Move iterator to previous index.
 * @xas: XArray operation state.
 *
 * If the @xas was in an error state, it will remain in an error state
 * and this function will return %NULL.  If the @xas has never been walked,
 * it will have the effect of calling cc_xas_load().  Otherwise one will be
 * subtracted from the index and the state will be walked to the correct
 * location in the array for the next operation.
 *
 * If the iterator was referencing index 0, this function wraps
 * around to %ULONG_MAX.
 *
 * Return: The entry at the new index.  This may be %NULL or an internal
 * entry.
 */
static inline void *cc_xas_prev(struct cc_xa_state *xas)
{
	struct cc_xa_node *node = xas->xa_node;

	if (unlikely(cc_xas_not_node(node) || node->shift ||
				xas->xa_offset == 0))
		return __cc_xas_prev(xas);

	xas->xa_index--;
	xas->xa_offset--;
	return cc_xa_entry(xas->xa, node, xas->xa_offset);
}

/**
 * cc_xas_next() - Move state to next index.
 * @xas: XArray operation state.
 *
 * If the @xas was in an error state, it will remain in an error state
 * and this function will return %NULL.  If the @xas has never been walked,
 * it will have the effect of calling cc_xas_load().  Otherwise one will be
 * added to the index and the state will be walked to the correct
 * location in the array for the next operation.
 *
 * If the iterator was referencing index %ULONG_MAX, this function wraps
 * around to 0.
 *
 * Return: The entry at the new index.  This may be %NULL or an internal
 * entry.
 */
static inline void *cc_xas_next(struct cc_xa_state *xas)
{
	struct cc_xa_node *node = xas->xa_node;

	if (unlikely(cc_xas_not_node(node) || node->shift ||
				xas->xa_offset == CC_XA_CHUNK_MASK))
		return __cc_xas_next(xas);

	xas->xa_index++;
	xas->xa_offset++;
	return cc_xa_entry(xas->xa, node, xas->xa_offset);
}

#endif /* _CC_XARRAY_H */
