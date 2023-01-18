// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_ATTR_SF_H__
#define	__SCXFS_ATTR_SF_H__

/*
 * Attribute storage when stored inside the inode.
 *
 * Small attribute lists are packed as tightly as possible so as
 * to fit into the literal area of the inode.
 */
typedef struct scxfs_attr_sf_hdr scxfs_attr_sf_hdr_t;
typedef struct scxfs_attr_sf_entry scxfs_attr_sf_entry_t;

/*
 * We generate this then sort it, attr_list() must return things in hash-order.
 */
typedef struct scxfs_attr_sf_sort {
	uint8_t		entno;		/* entry number in original list */
	uint8_t		namelen;	/* length of name value (no null) */
	uint8_t		valuelen;	/* length of value */
	uint8_t		flags;		/* flags bits (see scxfs_attr_leaf.h) */
	scxfs_dahash_t	hash;		/* this entry's hash value */
	unsigned char	*name;		/* name value, pointer into buffer */
} scxfs_attr_sf_sort_t;

#define SCXFS_ATTR_SF_ENTSIZE_BYNAME(nlen,vlen)	/* space name/value uses */ \
	(((int)sizeof(scxfs_attr_sf_entry_t)-1 + (nlen)+(vlen)))
#define SCXFS_ATTR_SF_ENTSIZE_MAX			/* max space for name&value */ \
	((1 << (NBBY*(int)sizeof(uint8_t))) - 1)
#define SCXFS_ATTR_SF_ENTSIZE(sfep)		/* space an entry uses */ \
	((int)sizeof(scxfs_attr_sf_entry_t)-1 + (sfep)->namelen+(sfep)->valuelen)
#define SCXFS_ATTR_SF_NEXTENTRY(sfep)		/* next entry in struct */ \
	((scxfs_attr_sf_entry_t *)((char *)(sfep) + SCXFS_ATTR_SF_ENTSIZE(sfep)))
#define SCXFS_ATTR_SF_TOTSIZE(dp)			/* total space in use */ \
	(be16_to_cpu(((scxfs_attr_shortform_t *)	\
		((dp)->i_afp->if_u1.if_data))->hdr.totsize))

#endif	/* __SCXFS_ATTR_SF_H__ */
