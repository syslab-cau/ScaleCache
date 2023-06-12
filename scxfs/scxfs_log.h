// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_LOG_H__
#define __SCXFS_LOG_H__

struct scxfs_cil_ctx;

struct scxfs_log_vec {
	struct scxfs_log_vec	*lv_next;	/* next lv in build list */
	int			lv_niovecs;	/* number of iovecs in lv */
	struct scxfs_log_iovec	*lv_iovecp;	/* iovec array */
	struct scxfs_log_item	*lv_item;	/* owner */
	char			*lv_buf;	/* formatted buffer */
	int			lv_bytes;	/* accounted space in buffer */
	int			lv_buf_len;	/* aligned size of buffer */
	int			lv_size;	/* size of allocated lv */
};

#define SCXFS_LOG_VEC_ORDERED	(-1)

static inline void *
xlog_prepare_iovec(struct scxfs_log_vec *lv, struct scxfs_log_iovec **vecp,
		uint type)
{
	struct scxfs_log_iovec *vec = *vecp;

	if (vec) {
		ASSERT(vec - lv->lv_iovecp < lv->lv_niovecs);
		vec++;
	} else {
		vec = &lv->lv_iovecp[0];
	}

	vec->i_type = type;
	vec->i_addr = lv->lv_buf + lv->lv_buf_len;

	ASSERT(IS_ALIGNED((unsigned long)vec->i_addr, sizeof(uint64_t)));

	*vecp = vec;
	return vec->i_addr;
}

/*
 * We need to make sure the next buffer is naturally aligned for the biggest
 * basic data type we put into it.  We already accounted for this padding when
 * sizing the buffer.
 *
 * However, this padding does not get written into the log, and hence we have to
 * track the space used by the log vectors separately to prevent log space hangs
 * due to inaccurate accounting (i.e. a leak) of the used log space through the
 * CIL context ticket.
 */
static inline void
xlog_finish_iovec(struct scxfs_log_vec *lv, struct scxfs_log_iovec *vec, int len)
{
	lv->lv_buf_len += round_up(len, sizeof(uint64_t));
	lv->lv_bytes += len;
	vec->i_len = len;
}

static inline void *
xlog_copy_iovec(struct scxfs_log_vec *lv, struct scxfs_log_iovec **vecp,
		uint type, void *data, int len)
{
	void *buf;

	buf = xlog_prepare_iovec(lv, vecp, type);
	memcpy(buf, data, len);
	xlog_finish_iovec(lv, *vecp, len);
	return buf;
}

/*
 * By comparing each component, we don't have to worry about extra
 * endian issues in treating two 32 bit numbers as one 64 bit number
 */
static inline scxfs_lsn_t	_lsn_cmp(scxfs_lsn_t lsn1, scxfs_lsn_t lsn2)
{
	if (CYCLE_LSN(lsn1) != CYCLE_LSN(lsn2))
		return (CYCLE_LSN(lsn1)<CYCLE_LSN(lsn2))? -999 : 999;

	if (BLOCK_LSN(lsn1) != BLOCK_LSN(lsn2))
		return (BLOCK_LSN(lsn1)<BLOCK_LSN(lsn2))? -999 : 999;

	return 0;
}

#define	SCXFS_LSN_CMP(x,y) _lsn_cmp(x,y)

/*
 * Flags to scxfs_log_force()
 *
 *	SCXFS_LOG_SYNC:	Synchronous force in-core log to disk
 */
#define SCXFS_LOG_SYNC		0x1

/* Log manager interfaces */
struct scxfs_mount;
struct xlog_in_core;
struct xlog_ticket;
struct scxfs_log_item;
struct scxfs_item_ops;
struct scxfs_trans;

scxfs_lsn_t scxfs_log_done(struct scxfs_mount *mp,
		       struct xlog_ticket *ticket,
		       struct xlog_in_core **iclog,
		       bool regrant);
int	  scxfs_log_force(struct scxfs_mount *mp, uint flags);
int	  scxfs_log_force_lsn(struct scxfs_mount *mp, scxfs_lsn_t lsn, uint flags,
		int *log_forced);
int	  scxfs_log_mount(struct scxfs_mount	*mp,
			struct scxfs_buftarg	*log_target,
			scxfs_daddr_t		start_block,
			int		 	num_bblocks);
int	  scxfs_log_mount_finish(struct scxfs_mount *mp);
void	scxfs_log_mount_cancel(struct scxfs_mount *);
scxfs_lsn_t xlog_assign_tail_lsn(struct scxfs_mount *mp);
scxfs_lsn_t xlog_assign_tail_lsn_locked(struct scxfs_mount *mp);
void	  scxfs_log_space_wake(struct scxfs_mount *mp);
int	  scxfs_log_release_iclog(struct scxfs_mount *mp,
			 struct xlog_in_core	 *iclog);
int	  scxfs_log_reserve(struct scxfs_mount *mp,
			  int		   length,
			  int		   count,
			  struct xlog_ticket **ticket,
			  uint8_t		   clientid,
			  bool		   permanent);
int	  scxfs_log_regrant(struct scxfs_mount *mp, struct xlog_ticket *tic);
void      scxfs_log_unmount(struct scxfs_mount *mp);
int	  scxfs_log_force_umount(struct scxfs_mount *mp, int logerror);

struct xlog_ticket *scxfs_log_ticket_get(struct xlog_ticket *ticket);
void	  scxfs_log_ticket_put(struct xlog_ticket *ticket);

void	scxfs_log_commit_cil(struct scxfs_mount *mp, struct scxfs_trans *tp,
				scxfs_lsn_t *commit_lsn, bool regrant);
void	xlog_cil_process_committed(struct list_head *list, bool aborted);
bool	scxfs_log_item_in_current_chkpt(struct scxfs_log_item *lip);

void	scxfs_log_work_queue(struct scxfs_mount *mp);
void	scxfs_log_quiesce(struct scxfs_mount *mp);
bool	scxfs_log_check_lsn(struct scxfs_mount *, scxfs_lsn_t);
bool	scxfs_log_in_recovery(struct scxfs_mount *);

#endif	/* __SCXFS_LOG_H__ */
