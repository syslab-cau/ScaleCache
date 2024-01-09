// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_EXTFREE_ITEM_H__
#define	__SCXFS_EXTFREE_ITEM_H__

/* kernel only EFI/EFD definitions */

struct scxfs_mount;
struct kmem_zone;

/*
 * Max number of extents in fast allocation path.
 */
#define	SCXFS_EFI_MAX_FAST_EXTENTS	16

/*
 * Define EFI flag bits. Manipulated by set/clear/test_bit operators.
 */
#define	SCXFS_EFI_RECOVERED	1

/*
 * This is the "extent free intention" log item.  It is used to log the fact
 * that some extents need to be free.  It is used in conjunction with the
 * "extent free done" log item described below.
 *
 * The EFI is reference counted so that it is not freed prior to both the EFI
 * and EFD being committed and unpinned. This ensures the EFI is inserted into
 * the AIL even in the event of out of order EFI/EFD processing. In other words,
 * an EFI is born with two references:
 *
 * 	1.) an EFI held reference to track EFI AIL insertion
 * 	2.) an EFD held reference to track EFD commit
 *
 * On allocation, both references are the responsibility of the caller. Once the
 * EFI is added to and dirtied in a transaction, ownership of reference one
 * transfers to the transaction. The reference is dropped once the EFI is
 * inserted to the AIL or in the event of failure along the way (e.g., commit
 * failure, log I/O error, etc.). Note that the caller remains responsible for
 * the EFD reference under all circumstances to this point. The caller has no
 * means to detect failure once the transaction is committed, however.
 * Therefore, an EFD is required after this point, even in the event of
 * unrelated failure.
 *
 * Once an EFD is allocated and dirtied in a transaction, reference two
 * transfers to the transaction. The EFD reference is dropped once it reaches
 * the unpin handler. Similar to the EFI, the reference also drops in the event
 * of commit failure or log I/O errors. Note that the EFD is not inserted in the
 * AIL, so at this point both the EFI and EFD are freed.
 */
typedef struct scxfs_efi_log_item {
	struct scxfs_log_item	efi_item;
	atomic_t		efi_refcount;
	atomic_t		efi_next_extent;
	unsigned long		efi_flags;	/* misc flags */
	scxfs_efi_log_format_t	efi_format;
} scxfs_efi_log_item_t;

/*
 * This is the "extent free done" log item.  It is used to log
 * the fact that some extents earlier mentioned in an efi item
 * have been freed.
 */
typedef struct scxfs_efd_log_item {
	struct scxfs_log_item	efd_item;
	scxfs_efi_log_item_t	*efd_efip;
	uint			efd_next_extent;
	scxfs_efd_log_format_t	efd_format;
} scxfs_efd_log_item_t;

/*
 * Max number of extents in fast allocation path.
 */
#define	SCXFS_EFD_MAX_FAST_EXTENTS	16

extern struct kmem_zone	*scxfs_efi_zone;
extern struct kmem_zone	*scxfs_efd_zone;

scxfs_efi_log_item_t	*scxfs_efi_init(struct scxfs_mount *, uint);
int			scxfs_efi_copy_format(scxfs_log_iovec_t *buf,
					    scxfs_efi_log_format_t *dst_efi_fmt);
void			scxfs_efi_item_free(scxfs_efi_log_item_t *);
void			scxfs_efi_release(struct scxfs_efi_log_item *);

int			scxfs_efi_recover(struct scxfs_mount *mp,
					struct scxfs_efi_log_item *efip);

#endif	/* __SCXFS_EXTFREE_ITEM_H__ */
