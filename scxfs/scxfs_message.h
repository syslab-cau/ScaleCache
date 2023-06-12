/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SCXFS_MESSAGE_H
#define __SCXFS_MESSAGE_H 1

struct scxfs_mount;

extern __printf(2, 3)
void scxfs_emerg(const struct scxfs_mount *mp, const char *fmt, ...);
extern __printf(2, 3)
void scxfs_alert(const struct scxfs_mount *mp, const char *fmt, ...);
extern __printf(3, 4)
void scxfs_alert_tag(const struct scxfs_mount *mp, int tag, const char *fmt, ...);
extern __printf(2, 3)
void scxfs_crit(const struct scxfs_mount *mp, const char *fmt, ...);
extern __printf(2, 3)
void scxfs_err(const struct scxfs_mount *mp, const char *fmt, ...);
extern __printf(2, 3)
void scxfs_warn(const struct scxfs_mount *mp, const char *fmt, ...);
extern __printf(2, 3)
void scxfs_notice(const struct scxfs_mount *mp, const char *fmt, ...);
extern __printf(2, 3)
void scxfs_info(const struct scxfs_mount *mp, const char *fmt, ...);

#ifdef DEBUG
extern __printf(2, 3)
void scxfs_debug(const struct scxfs_mount *mp, const char *fmt, ...);
#else
static inline __printf(2, 3)
void scxfs_debug(const struct scxfs_mount *mp, const char *fmt, ...)
{
}
#endif

#define scxfs_printk_ratelimited(func, dev, fmt, ...)		\
do {									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	if (__ratelimit(&_rs))						\
		func(dev, fmt, ##__VA_ARGS__);			\
} while (0)

#define scxfs_emerg_ratelimited(dev, fmt, ...)				\
	scxfs_printk_ratelimited(scxfs_emerg, dev, fmt, ##__VA_ARGS__)
#define scxfs_alert_ratelimited(dev, fmt, ...)				\
	scxfs_printk_ratelimited(scxfs_alert, dev, fmt, ##__VA_ARGS__)
#define scxfs_crit_ratelimited(dev, fmt, ...)				\
	scxfs_printk_ratelimited(scxfs_crit, dev, fmt, ##__VA_ARGS__)
#define scxfs_err_ratelimited(dev, fmt, ...)				\
	scxfs_printk_ratelimited(scxfs_err, dev, fmt, ##__VA_ARGS__)
#define scxfs_warn_ratelimited(dev, fmt, ...)				\
	scxfs_printk_ratelimited(scxfs_warn, dev, fmt, ##__VA_ARGS__)
#define scxfs_notice_ratelimited(dev, fmt, ...)				\
	scxfs_printk_ratelimited(scxfs_notice, dev, fmt, ##__VA_ARGS__)
#define scxfs_info_ratelimited(dev, fmt, ...)				\
	scxfs_printk_ratelimited(scxfs_info, dev, fmt, ##__VA_ARGS__)
#define scxfs_debug_ratelimited(dev, fmt, ...)				\
	scxfs_printk_ratelimited(scxfs_debug, dev, fmt, ##__VA_ARGS__)

extern void assfail(char *expr, char *f, int l);
extern void asswarn(char *expr, char *f, int l);

extern void scxfs_hex_dump(void *p, int length);

#endif	/* __SCXFS_MESSAGE_H */
