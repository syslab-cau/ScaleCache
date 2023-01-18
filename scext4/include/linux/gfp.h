/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SCEXT4_GFP_H
#define __SCEXT4_GFP_H

#include <linux/mmdebug.h>
#include <linux/mmzone.h>
#include <linux/stddef.h>
#include <linux/linkage.h>
#include <linux/topology.h>

struct page *
__scext4_alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order, int preferred_nid,
							nodemask_t *nodemask);

static inline struct page *
__scext4_alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid)
{
	return __scext4_alloc_pages_nodemask(gfp_mask, order, preferred_nid, NULL);
}

/*
 * Allocate pages, preferring the node given as nid. The node must be valid and
 * online. For more general interface, see alloc_pages_node().
 */
static inline struct page *
__scext4_alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
	VM_WARN_ON((gfp_mask & __GFP_THISNODE) && !node_online(nid));
	
	return __scext4_alloc_pages(gfp_mask, order, nid);
}

/*
 * Allocate pages, preferring the node given as nid. When nid == NUMA_NO_NODE,
 * prefer the current CPU's closest node. Otherwise node must be valid and
 * online.
 */
static inline struct page *scext4_alloc_pages_node(int nid, gfp_t gfp_mask,
						unsigned int order)
{
	if (nid == NUMA_NO_NODE)
		nid = numa_mem_id();

	return __scext4_alloc_pages_node(nid, gfp_mask, order);
}

#ifdef CONFIG_NUMA
extern struct page *scext4_alloc_pages_current(gfp_t gfp_mask, unsigned order);

static inline struct page *
scext4_alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	return scext4_alloc_pages_current(gfp_mask, order);
}
#else
#define scext4_alloc_pages(gfp_mask, order) \
		scext4_alloc_pages_node(numa_node_id(), gfp_mask, order)
#endif

#endif /* __SCEXT4_GFP_H */
