// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/scext4/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  scext4 symlink handling code
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include "scext4.h"
#include "xattr.h"

static const char *scext4_encrypted_get_link(struct dentry *dentry,
					   struct inode *inode,
					   struct delayed_call *done)
{
	struct page *cpage = NULL;
	const void *caddr;
	unsigned int max_size;
	const char *paddr;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	if (scext4_inode_is_fast_symlink(inode)) {
		caddr = SCEXT4_I(inode)->i_data;
		max_size = sizeof(SCEXT4_I(inode)->i_data);
	} else {
		cpage = read_mapping_page(inode->i_mapping, 0, NULL);
		if (IS_ERR(cpage))
			return ERR_CAST(cpage);
		caddr = page_address(cpage);
		max_size = inode->i_sb->s_blocksize;
	}

	paddr = fscrypt_get_symlink(inode, caddr, max_size, done);
	if (cpage)
		put_page(cpage);
	return paddr;
}

const struct inode_operations scext4_encrypted_symlink_inode_operations = {
	.get_link	= scext4_encrypted_get_link,
	.setattr	= scext4_setattr,
	.getattr	= scext4_getattr,
	.listxattr	= scext4_listxattr,
};

const struct inode_operations scext4_symlink_inode_operations = {
	.get_link	= page_get_link,
	.setattr	= scext4_setattr,
	.getattr	= scext4_getattr,
	.listxattr	= scext4_listxattr,
};

const struct inode_operations scext4_fast_symlink_inode_operations = {
	.get_link	= simple_get_link,
	.setattr	= scext4_setattr,
	.getattr	= scext4_getattr,
	.listxattr	= scext4_listxattr,
};
