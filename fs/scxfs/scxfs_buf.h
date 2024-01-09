// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_BUF_H__
#define __SCXFS_BUF_H__

#include <linux/list.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/uio.h>
#include <linux/list_lru.h>

/*
 *	Base types
 */

#define SCXFS_BUF_DADDR_NULL	((scxfs_daddr_t) (-1LL))

#define XBF_READ	 (1 << 0) /* buffer intended for reading from device */
#define XBF_WRITE	 (1 << 1) /* buffer intended for writing to device */
#define XBF_READ_AHEAD	 (1 << 2) /* asynchronous read-ahead */
#define XBF_NO_IOACCT	 (1 << 3) /* bypass I/O accounting (non-LRU bufs) */
#define XBF_ASYNC	 (1 << 4) /* initiator will not wait for completion */
#define XBF_DONE	 (1 << 5) /* all pages in the buffer uptodate */
#define XBF_STALE	 (1 << 6) /* buffer has been staled, do not find it */
#define XBF_WRITE_FAIL	 (1 << 7) /* async writes have failed on this buffer */

/* flags used only as arguments to access routines */
#define XBF_TRYLOCK	 (1 << 16)/* lock requested, but do not wait */
#define XBF_UNMAPPED	 (1 << 17)/* do not map the buffer */

/* flags used only internally */
#define _XBF_PAGES	 (1 << 20)/* backed by refcounted pages */
#define _XBF_KMEM	 (1 << 21)/* backed by heap memory */
#define _XBF_DELWRI_Q	 (1 << 22)/* buffer on a delwri queue */

typedef unsigned int scxfs_buf_flags_t;

#define SCXFS_BUF_FLAGS \
	{ XBF_READ,		"READ" }, \
	{ XBF_WRITE,		"WRITE" }, \
	{ XBF_READ_AHEAD,	"READ_AHEAD" }, \
	{ XBF_NO_IOACCT,	"NO_IOACCT" }, \
	{ XBF_ASYNC,		"ASYNC" }, \
	{ XBF_DONE,		"DONE" }, \
	{ XBF_STALE,		"STALE" }, \
	{ XBF_WRITE_FAIL,	"WRITE_FAIL" }, \
	{ XBF_TRYLOCK,		"TRYLOCK" },	/* should never be set */\
	{ XBF_UNMAPPED,		"UNMAPPED" },	/* ditto */\
	{ _XBF_PAGES,		"PAGES" }, \
	{ _XBF_KMEM,		"KMEM" }, \
	{ _XBF_DELWRI_Q,	"DELWRI_Q" }


/*
 * Internal state flags.
 */
#define SCXFS_BSTATE_DISPOSE	 (1 << 0)	/* buffer being discarded */
#define SCXFS_BSTATE_IN_FLIGHT	 (1 << 1)	/* I/O in flight */

/*
 * The scxfs_buftarg contains 2 notions of "sector size" -
 *
 * 1) The metadata sector size, which is the minimum unit and
 *    alignment of IO which will be performed by metadata operations.
 * 2) The device logical sector size
 *
 * The first is specified at mkfs time, and is stored on-disk in the
 * superblock's sb_sectsize.
 *
 * The latter is derived from the underlying device, and controls direct IO
 * alignment constraints.
 */
typedef struct scxfs_buftarg {
	dev_t			bt_dev;
	struct block_device	*bt_bdev;
	struct dax_device	*bt_daxdev;
	struct scxfs_mount	*bt_mount;
	unsigned int		bt_meta_sectorsize;
	size_t			bt_meta_sectormask;
	size_t			bt_logical_sectorsize;
	size_t			bt_logical_sectormask;

	/* LRU control structures */
	struct shrinker		bt_shrinker;
	struct list_lru		bt_lru;

	struct percpu_counter	bt_io_count;
} scxfs_buftarg_t;

struct scxfs_buf;
typedef void (*scxfs_buf_iodone_t)(struct scxfs_buf *);


#define XB_PAGES	2

struct scxfs_buf_map {
	scxfs_daddr_t		bm_bn;	/* block number for I/O */
	int			bm_len;	/* size of I/O */
};

#define DEFINE_SINGLE_BUF_MAP(map, blkno, numblk) \
	struct scxfs_buf_map (map) = { .bm_bn = (blkno), .bm_len = (numblk) };

struct scxfs_buf_ops {
	char *name;
	union {
		__be32 magic[2];	/* v4 and v5 on disk magic values */
		__be16 magic16[2];	/* v4 and v5 on disk magic values */
	};
	void (*verify_read)(struct scxfs_buf *);
	void (*verify_write)(struct scxfs_buf *);
	scxfs_failaddr_t (*verify_struct)(struct scxfs_buf *bp);
};

typedef struct scxfs_buf {
	/*
	 * first cacheline holds all the fields needed for an uncontended cache
	 * hit to be fully processed. The semaphore straddles the cacheline
	 * boundary, but the counter and lock sits on the first cacheline,
	 * which is the only bit that is touched if we hit the semaphore
	 * fast-path on locking.
	 */
	struct rhash_head	b_rhash_head;	/* pag buffer hash node */
	scxfs_daddr_t		b_bn;		/* block number of buffer */
	int			b_length;	/* size of buffer in BBs */
	atomic_t		b_hold;		/* reference count */
	atomic_t		b_lru_ref;	/* lru reclaim ref count */
	scxfs_buf_flags_t		b_flags;	/* status flags */
	struct semaphore	b_sema;		/* semaphore for lockables */

	/*
	 * concurrent access to b_lru and b_lru_flags are protected by
	 * bt_lru_lock and not by b_sema
	 */
	struct list_head	b_lru;		/* lru list */
	spinlock_t		b_lock;		/* internal state lock */
	unsigned int		b_state;	/* internal state flags */
	int			b_io_error;	/* internal IO error state */
	wait_queue_head_t	b_waiters;	/* unpin waiters */
	struct list_head	b_list;
	struct scxfs_perag	*b_pag;		/* contains rbtree root */
	struct scxfs_mount	*b_mount;
	scxfs_buftarg_t		*b_target;	/* buffer target (device) */
	void			*b_addr;	/* virtual address of buffer */
	struct work_struct	b_ioend_work;
	scxfs_buf_iodone_t	b_iodone;	/* I/O completion function */
	struct completion	b_iowait;	/* queue for I/O waiters */
	struct scxfs_buf_log_item	*b_log_item;
	struct list_head	b_li_list;	/* Log items list head */
	struct scxfs_trans	*b_transp;
	struct page		**b_pages;	/* array of page pointers */
	struct page		*b_page_array[XB_PAGES]; /* inline pages */
	struct scxfs_buf_map	*b_maps;	/* compound buffer map */
	struct scxfs_buf_map	__b_map;	/* inline compound buffer map */
	int			b_map_count;
	atomic_t		b_pin_count;	/* pin count */
	atomic_t		b_io_remaining;	/* #outstanding I/O requests */
	unsigned int		b_page_count;	/* size of page array */
	unsigned int		b_offset;	/* page offset in first page */
	int			b_error;	/* error code on I/O */

	/*
	 * async write failure retry count. Initialised to zero on the first
	 * failure, then when it exceeds the maximum configured without a
	 * success the write is considered to be failed permanently and the
	 * iodone handler will take appropriate action.
	 *
	 * For retry timeouts, we record the jiffie of the first failure. This
	 * means that we can change the retry timeout for buffers already under
	 * I/O and thus avoid getting stuck in a retry loop with a long timeout.
	 *
	 * last_error is used to ensure that we are getting repeated errors, not
	 * different errors. e.g. a block device might change ENOSPC to EIO when
	 * a failure timeout occurs, so we want to re-initialise the error
	 * retry behaviour appropriately when that happens.
	 */
	int			b_retries;
	unsigned long		b_first_retry_time; /* in jiffies */
	int			b_last_error;

	const struct scxfs_buf_ops	*b_ops;
} scxfs_buf_t;

/* Finding and Reading Buffers */
struct scxfs_buf *scxfs_buf_incore(struct scxfs_buftarg *target,
			   scxfs_daddr_t blkno, size_t numblks,
			   scxfs_buf_flags_t flags);

struct scxfs_buf *scxfs_buf_get_map(struct scxfs_buftarg *target,
			       struct scxfs_buf_map *map, int nmaps,
			       scxfs_buf_flags_t flags);
struct scxfs_buf *scxfs_buf_read_map(struct scxfs_buftarg *target,
			       struct scxfs_buf_map *map, int nmaps,
			       scxfs_buf_flags_t flags,
			       const struct scxfs_buf_ops *ops);
void scxfs_buf_readahead_map(struct scxfs_buftarg *target,
			       struct scxfs_buf_map *map, int nmaps,
			       const struct scxfs_buf_ops *ops);

static inline struct scxfs_buf *
scxfs_buf_get(
	struct scxfs_buftarg	*target,
	scxfs_daddr_t		blkno,
	size_t			numblks)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);
	return scxfs_buf_get_map(target, &map, 1, 0);
}

static inline struct scxfs_buf *
scxfs_buf_read(
	struct scxfs_buftarg	*target,
	scxfs_daddr_t		blkno,
	size_t			numblks,
	scxfs_buf_flags_t		flags,
	const struct scxfs_buf_ops *ops)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);
	return scxfs_buf_read_map(target, &map, 1, flags, ops);
}

static inline void
scxfs_buf_readahead(
	struct scxfs_buftarg	*target,
	scxfs_daddr_t		blkno,
	size_t			numblks,
	const struct scxfs_buf_ops *ops)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);
	return scxfs_buf_readahead_map(target, &map, 1, ops);
}

struct scxfs_buf *scxfs_buf_get_uncached(struct scxfs_buftarg *target, size_t numblks,
				int flags);
int scxfs_buf_read_uncached(struct scxfs_buftarg *target, scxfs_daddr_t daddr,
			  size_t numblks, int flags, struct scxfs_buf **bpp,
			  const struct scxfs_buf_ops *ops);
void scxfs_buf_hold(struct scxfs_buf *bp);

/* Releasing Buffers */
extern void scxfs_buf_free(scxfs_buf_t *);
extern void scxfs_buf_rele(scxfs_buf_t *);

/* Locking and Unlocking Buffers */
extern int scxfs_buf_trylock(scxfs_buf_t *);
extern void scxfs_buf_lock(scxfs_buf_t *);
extern void scxfs_buf_unlock(scxfs_buf_t *);
#define scxfs_buf_islocked(bp) \
	((bp)->b_sema.count <= 0)

/* Buffer Read and Write Routines */
extern int scxfs_bwrite(struct scxfs_buf *bp);
extern void scxfs_buf_ioend(struct scxfs_buf *bp);
extern void __scxfs_buf_ioerror(struct scxfs_buf *bp, int error,
		scxfs_failaddr_t failaddr);
#define scxfs_buf_ioerror(bp, err) __scxfs_buf_ioerror((bp), (err), __this_address)
extern void scxfs_buf_ioerror_alert(struct scxfs_buf *, const char *func);

extern int __scxfs_buf_submit(struct scxfs_buf *bp, bool);
static inline int scxfs_buf_submit(struct scxfs_buf *bp)
{
	bool wait = bp->b_flags & XBF_ASYNC ? false : true;
	return __scxfs_buf_submit(bp, wait);
}

void scxfs_buf_zero(struct scxfs_buf *bp, size_t boff, size_t bsize);

/* Buffer Utility Routines */
extern void *scxfs_buf_offset(struct scxfs_buf *, size_t);
extern void scxfs_buf_stale(struct scxfs_buf *bp);

/* Delayed Write Buffer Routines */
extern void scxfs_buf_delwri_cancel(struct list_head *);
extern bool scxfs_buf_delwri_queue(struct scxfs_buf *, struct list_head *);
extern int scxfs_buf_delwri_submit(struct list_head *);
extern int scxfs_buf_delwri_submit_nowait(struct list_head *);
extern int scxfs_buf_delwri_pushbuf(struct scxfs_buf *, struct list_head *);

/* Buffer Daemon Setup Routines */
extern int scxfs_buf_init(void);
extern void scxfs_buf_terminate(void);

/*
 * These macros use the IO block map rather than b_bn. b_bn is now really
 * just for the buffer cache index for cached buffers. As IO does not use b_bn
 * anymore, uncached buffers do not use b_bn at all and hence must modify the IO
 * map directly. Uncached buffers are not allowed to be discontiguous, so this
 * is safe to do.
 *
 * In future, uncached buffers will pass the block number directly to the io
 * request function and hence these macros will go away at that point.
 */
#define SCXFS_BUF_ADDR(bp)		((bp)->b_maps[0].bm_bn)
#define SCXFS_BUF_SET_ADDR(bp, bno)	((bp)->b_maps[0].bm_bn = (scxfs_daddr_t)(bno))

void scxfs_buf_set_ref(struct scxfs_buf *bp, int lru_ref);

/*
 * If the buffer is already on the LRU, do nothing. Otherwise set the buffer
 * up with a reference count of 0 so it will be tossed from the cache when
 * released.
 */
static inline void scxfs_buf_oneshot(struct scxfs_buf *bp)
{
	if (!list_empty(&bp->b_lru) || atomic_read(&bp->b_lru_ref) > 1)
		return;
	atomic_set(&bp->b_lru_ref, 0);
}

static inline int scxfs_buf_ispinned(struct scxfs_buf *bp)
{
	return atomic_read(&bp->b_pin_count);
}

static inline void scxfs_buf_relse(scxfs_buf_t *bp)
{
	scxfs_buf_unlock(bp);
	scxfs_buf_rele(bp);
}

static inline int
scxfs_buf_verify_cksum(struct scxfs_buf *bp, unsigned long cksum_offset)
{
	return scxfs_verify_cksum(bp->b_addr, BBTOB(bp->b_length),
				cksum_offset);
}

static inline void
scxfs_buf_update_cksum(struct scxfs_buf *bp, unsigned long cksum_offset)
{
	scxfs_update_cksum(bp->b_addr, BBTOB(bp->b_length),
			 cksum_offset);
}

/*
 *	Handling of buftargs.
 */
extern scxfs_buftarg_t *scxfs_alloc_buftarg(struct scxfs_mount *,
			struct block_device *, struct dax_device *);
extern void scxfs_free_buftarg(struct scxfs_buftarg *);
extern void scxfs_wait_buftarg(scxfs_buftarg_t *);
extern int scxfs_setsize_buftarg(scxfs_buftarg_t *, unsigned int);

#define scxfs_getsize_buftarg(buftarg)	block_size((buftarg)->bt_bdev)
#define scxfs_readonly_buftarg(buftarg)	bdev_read_only((buftarg)->bt_bdev)

static inline int
scxfs_buftarg_dma_alignment(struct scxfs_buftarg *bt)
{
	return queue_dma_alignment(bt->bt_bdev->bd_disk->queue);
}

int scxfs_buf_reverify(struct scxfs_buf *bp, const struct scxfs_buf_ops *ops);
bool scxfs_verify_magic(struct scxfs_buf *bp, __be32 dmagic);
bool scxfs_verify_magic16(struct scxfs_buf *bp, __be16 dmagic);

#endif	/* __SCXFS_BUF_H__ */
