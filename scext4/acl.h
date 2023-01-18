// SPDX-License-Identifier: GPL-2.0
/*
  File: fs/scext4/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>

#define SCEXT4_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} scext4_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} scext4_acl_entry_short;

typedef struct {
	__le32		a_version;
} scext4_acl_header;

static inline size_t scext4_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(scext4_acl_header) +
		       count * sizeof(scext4_acl_entry_short);
	} else {
		return sizeof(scext4_acl_header) +
		       4 * sizeof(scext4_acl_entry_short) +
		       (count - 4) * sizeof(scext4_acl_entry);
	}
}

static inline int scext4_acl_count(size_t size)
{
	ssize_t s;
	size -= sizeof(scext4_acl_header);
	s = size - 4 * sizeof(scext4_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(scext4_acl_entry_short))
			return -1;
		return size / sizeof(scext4_acl_entry_short);
	} else {
		if (s % sizeof(scext4_acl_entry))
			return -1;
		return s / sizeof(scext4_acl_entry) + 4;
	}
}

#ifdef CONFIG_EXT4_FS_POSIX_ACL

/* acl.c */
struct posix_acl *scext4_get_acl(struct inode *inode, int type);
int scext4_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int scext4_init_acl(handle_t *, struct inode *, struct inode *);

#else  /* CONFIG_EXT4_FS_POSIX_ACL */
#include <linux/sched.h>
#define scext4_get_acl NULL
#define scext4_set_acl NULL

static inline int
scext4_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif  /* CONFIG_EXT4_FS_POSIX_ACL */

