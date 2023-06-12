// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2006-2007 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_MRU_CACHE_H__
#define __SCXFS_MRU_CACHE_H__

struct scxfs_mru_cache;

struct scxfs_mru_cache_elem {
	struct list_head list_node;
	unsigned long	key;
};

/* Function pointer type for callback to free a client's data pointer. */
typedef void (*scxfs_mru_cache_free_func_t)(void *, struct scxfs_mru_cache_elem *);

int scxfs_mru_cache_init(void);
void scxfs_mru_cache_uninit(void);
int scxfs_mru_cache_create(struct scxfs_mru_cache **mrup, void *data,
		unsigned int lifetime_ms, unsigned int grp_count,
		scxfs_mru_cache_free_func_t free_func);
void scxfs_mru_cache_destroy(struct scxfs_mru_cache *mru);
int scxfs_mru_cache_insert(struct scxfs_mru_cache *mru, unsigned long key,
		struct scxfs_mru_cache_elem *elem);
struct scxfs_mru_cache_elem *
scxfs_mru_cache_remove(struct scxfs_mru_cache *mru, unsigned long key);
void scxfs_mru_cache_delete(struct scxfs_mru_cache *mru, unsigned long key);
struct scxfs_mru_cache_elem *
scxfs_mru_cache_lookup(struct scxfs_mru_cache *mru, unsigned long key);
void scxfs_mru_cache_done(struct scxfs_mru_cache *mru);

#endif /* __SCXFS_MRU_CACHE_H__ */
