// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_ERROR_H__
#define	__SCXFS_ERROR_H__

struct scxfs_mount;

extern void scxfs_error_report(const char *tag, int level, struct scxfs_mount *mp,
			const char *filename, int linenum,
			scxfs_failaddr_t failaddr);
extern void scxfs_corruption_error(const char *tag, int level,
			struct scxfs_mount *mp, void *buf, size_t bufsize,
			const char *filename, int linenum,
			scxfs_failaddr_t failaddr);
extern void scxfs_buf_verifier_error(struct scxfs_buf *bp, int error,
			const char *name, void *buf, size_t bufsz,
			scxfs_failaddr_t failaddr);
extern void scxfs_verifier_error(struct scxfs_buf *bp, int error,
			scxfs_failaddr_t failaddr);
extern void scxfs_inode_verifier_error(struct scxfs_inode *ip, int error,
			const char *name, void *buf, size_t bufsz,
			scxfs_failaddr_t failaddr);

#define	SCXFS_ERROR_REPORT(e, lvl, mp)	\
	scxfs_error_report(e, lvl, mp, __FILE__, __LINE__, __return_address)
#define	SCXFS_CORRUPTION_ERROR(e, lvl, mp, buf, bufsize)	\
	scxfs_corruption_error(e, lvl, mp, buf, bufsize, \
			     __FILE__, __LINE__, __return_address)

#define SCXFS_ERRLEVEL_OFF	0
#define SCXFS_ERRLEVEL_LOW	1
#define SCXFS_ERRLEVEL_HIGH	5

/* Dump 128 bytes of any corrupt buffer */
#define SCXFS_CORRUPTION_DUMP_LEN		(128)

/*
 * Macros to set EFSCORRUPTED & return/branch.
 */
#define	SCXFS_WANT_CORRUPTED_GOTO(mp, x, l)	\
	{ \
		int fs_is_ok = (x); \
		ASSERT(fs_is_ok); \
		if (unlikely(!fs_is_ok)) { \
			SCXFS_ERROR_REPORT("SCXFS_WANT_CORRUPTED_GOTO", \
					 SCXFS_ERRLEVEL_LOW, mp); \
			error = -EFSCORRUPTED; \
			goto l; \
		} \
	}

#define	SCXFS_WANT_CORRUPTED_RETURN(mp, x)	\
	{ \
		int fs_is_ok = (x); \
		ASSERT(fs_is_ok); \
		if (unlikely(!fs_is_ok)) { \
			SCXFS_ERROR_REPORT("SCXFS_WANT_CORRUPTED_RETURN", \
					 SCXFS_ERRLEVEL_LOW, mp); \
			return -EFSCORRUPTED; \
		} \
	}

#ifdef DEBUG
extern int scxfs_errortag_init(struct scxfs_mount *mp);
extern void scxfs_errortag_del(struct scxfs_mount *mp);
extern bool scxfs_errortag_test(struct scxfs_mount *mp, const char *expression,
		const char *file, int line, unsigned int error_tag);
#define SCXFS_TEST_ERROR(expr, mp, tag)		\
	((expr) || scxfs_errortag_test((mp), #expr, __FILE__, __LINE__, (tag)))

extern int scxfs_errortag_get(struct scxfs_mount *mp, unsigned int error_tag);
extern int scxfs_errortag_set(struct scxfs_mount *mp, unsigned int error_tag,
		unsigned int tag_value);
extern int scxfs_errortag_add(struct scxfs_mount *mp, unsigned int error_tag);
extern int scxfs_errortag_clearall(struct scxfs_mount *mp);
#else
#define scxfs_errortag_init(mp)			(0)
#define scxfs_errortag_del(mp)
#define SCXFS_TEST_ERROR(expr, mp, tag)		(expr)
#define scxfs_errortag_set(mp, tag, val)		(ENOSYS)
#define scxfs_errortag_add(mp, tag)		(ENOSYS)
#define scxfs_errortag_clearall(mp)		(ENOSYS)
#endif /* DEBUG */

/*
 * SCXFS panic tags -- allow a call to scxfs_alert_tag() be turned into
 *			a panic by setting scxfs_panic_mask in a sysctl.
 */
#define		SCXFS_NO_PTAG			0
#define		SCXFS_PTAG_IFLUSH			0x00000001
#define		SCXFS_PTAG_LOGRES			0x00000002
#define		SCXFS_PTAG_AILDELETE		0x00000004
#define		SCXFS_PTAG_ERROR_REPORT		0x00000008
#define		SCXFS_PTAG_SHUTDOWN_CORRUPT	0x00000010
#define		SCXFS_PTAG_SHUTDOWN_IOERROR	0x00000020
#define		SCXFS_PTAG_SHUTDOWN_LOGERROR	0x00000040
#define		SCXFS_PTAG_FSBLOCK_ZERO		0x00000080
#define		SCXFS_PTAG_VERIFIER_ERROR		0x00000100

#endif	/* __SCXFS_ERROR_H__ */
