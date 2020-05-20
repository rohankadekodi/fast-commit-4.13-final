/*
 * Interface between ext4 and JBD
 */

#include "ext4_jbd2.h"
#include "ext4_extents.h"
#include <linux/dax.h>

#include <trace/events/ext4.h>

/* Just increment the non-pointer handle value */
static handle_t *ext4_get_nojournal(void)
{
	handle_t *handle = current->journal_info;
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt >= EXT4_NOJOURNAL_MAX_REF_COUNT);

	ref_cnt++;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
	return handle;
}


/* Decrement the non-pointer handle value */
static void ext4_put_nojournal(handle_t *handle)
{
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt == 0);

	ref_cnt--;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
}

/*
 * Wrappers for jbd2_journal_start/end.
 */
static int ext4_journal_check_start(struct super_block *sb)
{
	journal_t *journal;

	might_sleep();

	if (unlikely(ext4_forced_shutdown(EXT4_SB(sb))))
		return -EIO;

	if (sb->s_flags & MS_RDONLY)
		return -EROFS;
	WARN_ON(sb->s_writers.frozen == SB_FREEZE_COMPLETE);
	journal = EXT4_SB(sb)->s_journal;
	/*
	 * Special case here: if the journal has aborted behind our
	 * backs (eg. EIO in the commit thread), then we still need to
	 * take the FS itself readonly cleanly.
	 */
	if (journal && is_journal_aborted(journal)) {
		ext4_abort(sb, "Detected aborted journal");
		return -EROFS;
	}
	return 0;
}

handle_t *__ext4_journal_start_sb(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks)
{
	journal_t *journal;
	int err;

	trace_ext4_journal_start(sb, blocks, rsv_blocks, _RET_IP_);
	err = ext4_journal_check_start(sb);
	if (err < 0)
		return ERR_PTR(err);

	journal = EXT4_SB(sb)->s_journal;
	if (!journal)
		return ext4_get_nojournal();
	return jbd2__journal_start(journal, blocks, rsv_blocks, GFP_NOFS,
				   type, line);
}

int __ext4_journal_stop(const char *where, unsigned int line, handle_t *handle)
{
	struct super_block *sb;
	int err;
	int rc;

	if (!ext4_handle_valid(handle)) {
		ext4_put_nojournal(handle);
		return 0;
	}

	err = handle->h_err;
	if (!handle->h_transaction) {
		rc = jbd2_journal_stop(handle);
		return err ? err : rc;
	}

	sb = handle->h_transaction->t_journal->j_private;
	rc = jbd2_journal_stop(handle);

	if (!err)
		err = rc;
	if (err)
		__ext4_std_error(sb, where, line, err);
	return err;
}

handle_t *__ext4_journal_start_reserved(handle_t *handle, unsigned int line,
					int type)
{
	struct super_block *sb;
	int err;

	if (!ext4_handle_valid(handle))
		return ext4_get_nojournal();

	sb = handle->h_journal->j_private;
	trace_ext4_journal_start_reserved(sb, handle->h_buffer_credits,
					  _RET_IP_);
	err = ext4_journal_check_start(sb);
	if (err < 0) {
		jbd2_journal_free_reserved(handle);
		return ERR_PTR(err);
	}

	err = jbd2_journal_start_reserved(handle, type, line);
	if (err < 0)
		return ERR_PTR(err);
	return handle;
}

static void ext4_journal_abort_handle(const char *caller, unsigned int line,
				      const char *err_fn,
				      struct buffer_head *bh,
				      handle_t *handle, int err)
{
	char nbuf[16];
	const char *errstr = ext4_decode_error(NULL, err, nbuf);

	BUG_ON(!ext4_handle_valid(handle));

	if (bh)
		BUFFER_TRACE(bh, "abort");

	if (!handle->h_err)
		handle->h_err = err;

	if (is_handle_aborted(handle))
		return;

	printk(KERN_ERR "EXT4-fs: %s:%d: aborting transaction: %s in %s\n",
	       caller, line, errstr, err_fn);

	jbd2_journal_abort_handle(handle);
}

int __ext4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	if (ext4_handle_valid(handle)) {
		struct super_block *sb;

		sb = handle->h_transaction->t_journal->j_private;
		if (unlikely(ext4_forced_shutdown(EXT4_SB(sb)))) {
			jbd2_journal_abort_handle(handle);
			return -EIO;
		}
		err = jbd2_journal_get_write_access(handle, bh);
		if (err)
			ext4_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
	}
	return err;
}

/*
 * The ext4 forget function must perform a revoke if we are freeing data
 * which has been journaled.  Metadata (eg. indirect blocks) must be
 * revoked in all cases.
 *
 * "bh" may be NULL: a metadata block may have been freed from memory
 * but there may still be a record of it in the journal, and that record
 * still needs to be revoked.
 *
 * If the handle isn't valid we're not journaling, but we still need to
 * call into ext4_journal_revoke() to put the buffer head.
 */
int __ext4_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, ext4_fsblk_t blocknr)
{
	int err;

	might_sleep();

	trace_ext4_forget(inode, is_metadata, blocknr);
	BUFFER_TRACE(bh, "enter");

	jbd_debug(4, "forgetting bh %p: is_metadata = %d, mode %o, "
		  "data mode %x\n",
		  bh, is_metadata, inode->i_mode,
		  test_opt(inode->i_sb, DATA_FLAGS));

	/* In the no journal case, we can just do a bforget and return */
	if (!ext4_handle_valid(handle)) {
		bforget(bh);
		return 0;
	}

	/* Never use the revoke function if we are doing full data
	 * journaling: there is no need to, and a V1 superblock won't
	 * support it.  Otherwise, only skip the revoke on un-journaled
	 * data blocks. */

	if (test_opt(inode->i_sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA ||
	    (!is_metadata && !ext4_should_journal_data(inode))) {
		if (bh) {
			BUFFER_TRACE(bh, "call jbd2_journal_forget");
			err = jbd2_journal_forget(handle, bh);
			if (err)
				ext4_journal_abort_handle(where, line, __func__,
							  bh, handle, err);
			return err;
		}
		return 0;
	}

	/*
	 * data!=journal && (is_metadata || should_journal_data(inode))
	 */
	BUFFER_TRACE(bh, "call jbd2_journal_revoke");
	err = jbd2_journal_revoke(handle, blocknr, bh);
	if (err) {
		ext4_journal_abort_handle(where, line, __func__,
					  bh, handle, err);
		__ext4_abort(inode->i_sb, where, line,
			   "error %d when attempting revoke", err);
	}
	BUFFER_TRACE(bh, "exit");
	return err;
}

int __ext4_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_get_create_access(handle, bh);
		if (err)
			ext4_journal_abort_handle(where, line, __func__,
						  bh, handle, err);
	}
	return err;
}

int __ext4_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	set_buffer_meta(bh);
	set_buffer_prio(bh);
	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_dirty_metadata(handle, bh);
		/* Errors can only happen due to aborted journal or a nasty bug */
		if (!is_handle_aborted(handle) && WARN_ON_ONCE(err)) {
			ext4_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
			if (inode == NULL) {
				pr_err("EXT4: jbd2_journal_dirty_metadata "
				       "failed: handle type %u started at "
				       "line %u, credits %u/%u, errcode %d",
				       handle->h_type,
				       handle->h_line_no,
				       handle->h_requested_credits,
				       handle->h_buffer_credits, err);
				return err;
			}
			ext4_error_inode(inode, where, line,
					 bh->b_blocknr,
					 "journal_dirty_metadata failed: "
					 "handle type %u started at line %u, "
					 "credits %u/%u, errcode %d",
					 handle->h_type,
					 handle->h_line_no,
					 handle->h_requested_credits,
					 handle->h_buffer_credits, err);
		}
	} else {
		if (inode)
			mark_buffer_dirty_inode(bh, inode);
		else
			mark_buffer_dirty(bh);
		if (inode && inode_needs_sync(inode)) {
			sync_dirty_buffer(bh);
			if (buffer_req(bh) && !buffer_uptodate(bh)) {
				struct ext4_super_block *es;

				es = EXT4_SB(inode->i_sb)->s_es;
				es->s_last_error_block =
					cpu_to_le64(bh->b_blocknr);
				ext4_error_inode(inode, where, line,
						 bh->b_blocknr,
					"IO error syncing itable block");
				err = -EIO;
			}
		}
	}
	return err;
}

int __ext4_handle_dirty_super(const char *where, unsigned int line,
			      handle_t *handle, struct super_block *sb)
{
	struct buffer_head *bh = EXT4_SB(sb)->s_sbh;
	int err = 0;

	ext4_superblock_csum_set(sb);
	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_dirty_metadata(handle, bh);
		if (err)
			ext4_journal_abort_handle(where, line, __func__,
						  bh, handle, err);
	} else
		mark_buffer_dirty(bh);
	return err;
}

static struct kmem_cache *ext4_fc_dentry_cachep;

static inline
void ext4_reset_inode_fc_info(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	ei->i_fc_tid = 0;
	ei->i_fc_lblk_start = 0;
	ei->i_fc_lblk_end = 0;
	ext4_clear_inode_state(inode, EXT4_STATE_FC_ELIGIBLE);
}

void ext4_init_inode_fc_info(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	ext4_reset_inode_fc_info(inode);
	ext4_clear_inode_state(inode, EXT4_STATE_FC_COMMITTING);
	INIT_LIST_HEAD(&ei->i_fc_list);
}

static void ext4_fc_enqueue_inode(struct inode *inode)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

	if (!test_opt2(inode->i_sb, JOURNAL_FAST_COMMIT) ||
	    (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY))
		return;

	spin_lock(&sbi->s_fc_lock);
	if (list_empty(&EXT4_I(inode)->i_fc_list)) {
		if (sbi->s_fc_q_locked)
			list_add_tail(&EXT4_I(inode)->i_fc_list, &sbi->s_fc_staging_q);
		else
			list_add_tail(&EXT4_I(inode)->i_fc_list, &sbi->s_fc_q);
	}
	spin_unlock(&sbi->s_fc_lock);
}

static inline tid_t get_running_txn_tid(struct super_block *sb)
{
	if (EXT4_SB(sb)->s_journal)
		return EXT4_SB(sb)->s_journal->j_commit_sequence + 1;
	return 0;
}

void ext4_fc_del(struct inode *inode)
{
	if (!test_opt2(inode->i_sb, JOURNAL_FAST_COMMIT) ||
	    (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY))
		return;

restart:
	spin_lock(&EXT4_SB(inode->i_sb)->s_fc_lock);
	if (list_empty(&EXT4_I(inode)->i_fc_list)) {
		spin_unlock(&EXT4_SB(inode->i_sb)->s_fc_lock);
		return;
	}

	if (ext4_test_inode_state(inode, EXT4_STATE_FC_COMMITTING)) {
		struct ext4_inode_info *ei = EXT4_I(inode);
		wait_queue_head_t *wq;
#if (BITS_PER_LONG < 64)
		DEFINE_WAIT_BIT(wait, &ei->i_state_flags,
				EXT4_STATE_FC_COMMITTING);
		wq = bit_waitqueue(&ei->i_state_flags,
				   EXT4_STATE_FC_COMMITTING);
#else
		DEFINE_WAIT_BIT(wait, &ei->i_flags,
				EXT4_STATE_FC_COMMITTING);
		wq = bit_waitqueue(&ei->i_flags,
				   EXT4_STATE_FC_COMMITTING);
#endif
		prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
		spin_unlock(&EXT4_SB(inode->i_sb)->s_fc_lock);
		schedule();
		finish_wait(wq, &wait.wq_entry);
		goto restart;
	}
	list_del_init(&EXT4_I(inode)->i_fc_list);
	spin_unlock(&EXT4_SB(inode->i_sb)->s_fc_lock);
}

bool ext4_is_inode_fc_ineligible(struct inode *inode)
{
	if (get_running_txn_tid(inode->i_sb) == EXT4_I(inode)->i_fc_tid)
		return !ext4_test_inode_state(inode, EXT4_STATE_FC_ELIGIBLE);
	return false;
}

void ext4_fc_mark_ineligible(struct inode *inode, int reason)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct ext4_inode_info *ei = EXT4_I(inode);

	if (!test_opt2(inode->i_sb, JOURNAL_FAST_COMMIT) ||
	    (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY))
		return;

	WARN_ON(reason >= EXT4_FC_REASON_MAX);
	sbi->s_fc_stats.fc_ineligible_reason_count[reason]++;
	if (sbi->s_journal)
		ei->i_fc_tid = get_running_txn_tid(inode->i_sb);
	ext4_clear_inode_state(inode, EXT4_STATE_FC_ELIGIBLE);

	ext4_fc_enqueue_inode(inode);
}

void ext4_fc_disable(struct super_block *sb, int reason)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	sbi->s_mount_state |= EXT4_FC_INELIGIBLE;
	WARN_ON(reason >= EXT4_FC_REASON_MAX);
	sbi->s_fc_stats.fc_ineligible_reason_count[reason]++;
}

/*
 * Generic fast commit tracking function. If this is the first
 * time this we are called after a full commit, we initialize
 * fast commit fields and then call __fc_track_fn() with
 * update = 0. If we have already been called after a full commit,
 * we pass update = 1. Based on that, the track function can
 * determine if it needs to track a field for the first time
 * or if it needs to just update the previously tracked value.
 */
static int __ext4_fc_track_template(
	struct inode *inode,
	int (*__fc_track_fn)(struct inode *, void *, bool),
	void *args)
{
	tid_t running_txn_tid = get_running_txn_tid(inode->i_sb);
	bool update = false;
	struct ext4_inode_info *ei = EXT4_I(inode);
	int ret;

	if (!test_opt2(inode->i_sb, JOURNAL_FAST_COMMIT) ||
	    (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY))
		return -EOPNOTSUPP;

	write_lock(&ei->i_fc_lock);
	if (running_txn_tid == ei->i_fc_tid) {
		if (!ext4_test_inode_state(inode, EXT4_STATE_FC_ELIGIBLE)) {
			write_unlock(&ei->i_fc_lock);
			return -EINVAL;
		}
		update = true;
	} else {
		ext4_reset_inode_fc_info(inode);
		ei->i_fc_tid = running_txn_tid;
		ext4_set_inode_state(inode, EXT4_STATE_FC_ELIGIBLE);
	}
	ret = __fc_track_fn(inode, args, update);
	write_unlock(&ei->i_fc_lock);

	ext4_fc_enqueue_inode(inode);

	return ret;
}

struct __ext4_dentry_update_args {
	struct dentry *dentry;
	int op;
};

static int __ext4_dentry_update(struct inode *inode, void *arg, bool update)
{
	struct ext4_fc_dentry_update *node;
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct __ext4_dentry_update_args *dentry_update =
		(struct __ext4_dentry_update_args *)arg;
	struct dentry *dentry = dentry_update->dentry;

	write_unlock(&ei->i_fc_lock);
	node = kmem_cache_alloc(ext4_fc_dentry_cachep, GFP_NOFS);
	if (!node) {
		ext4_fc_disable(inode->i_sb, EXT4_FC_REASON_MEM);
		write_lock(&ei->i_fc_lock);
		return -ENOMEM;
	}

	node->fcd_delete = 0;
	node->fcd_op = dentry_update->op;
	node->fcd_parent = dentry->d_parent->d_inode->i_ino;
	node->fcd_ino = inode->i_ino;
	if (dentry->d_name.len > DNAME_INLINE_LEN) {
		node->fcd_name.name = kmalloc(dentry->d_name.len + 1,
						GFP_KERNEL);
		if (!node->fcd_iname) {
			kmem_cache_free(ext4_fc_dentry_cachep, node);
			return -ENOMEM;
		}
		memcpy((u8 *)node->fcd_name.name, dentry->d_name.name,
			dentry->d_name.len);
	} else {
		memcpy(node->fcd_iname, dentry->d_name.name,
			dentry->d_name.len);
		node->fcd_name.name = node->fcd_iname;
	}
	node->fcd_name.len = dentry->d_name.len;

	spin_lock(&EXT4_SB(inode->i_sb)->s_fc_lock);
	list_add_tail(&node->fcd_list, &EXT4_SB(inode->i_sb)->s_fc_dentry_q);
	spin_unlock(&EXT4_SB(inode->i_sb)->s_fc_lock);
	write_lock(&ei->i_fc_lock);

	return 0;
}

void ext4_fc_track_unlink(struct inode *inode, struct dentry *dentry)
{
	struct __ext4_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = EXT4_FC_TAG_DEL_DENTRY;

	ret = __ext4_fc_track_template(inode, __ext4_dentry_update,
				       (void *)&args);
	trace_ext4_fc_track_unlink(inode, dentry, ret);
}

void ext4_fc_track_link(struct inode *inode, struct dentry *dentry)
{
	struct __ext4_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = EXT4_FC_TAG_ADD_DENTRY;

	ret = __ext4_fc_track_template(inode, __ext4_dentry_update,
				       (void *)&args);
	trace_ext4_fc_track_link(inode, dentry, ret);
}

void ext4_fc_track_create(struct inode *inode, struct dentry *dentry)
{
	struct __ext4_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = EXT4_FC_TAG_CREAT_DENTRY;

	ret = __ext4_fc_track_template(inode, __ext4_dentry_update,
				       (void *)&args);
	trace_ext4_fc_track_create(inode, dentry, ret);
}

static int __ext4_fc_add_inode(struct inode *inode, void *arg, bool update)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	if (update)
		return -EEXIST;

	ei->i_fc_lblk_start = (i_size_read(inode) - 1) >> inode->i_blkbits;
	ei->i_fc_lblk_end = (i_size_read(inode) - 1) >> inode->i_blkbits;

	return 0;
}

void ext4_fc_track_inode(struct inode *inode)
{
	int ret;

	ret = __ext4_fc_track_template(inode, __ext4_fc_add_inode, NULL);
	trace_ext4_fc_track_inode(inode, ret);
}

struct __ext4_fc_track_range_args {
	ext4_lblk_t start, end;
};

#define MIN(__a, __b)  ((__a) < (__b) ? (__a) : (__b))
#define MAX(__a, __b)  ((__a) > (__b) ? (__a) : (__b))

int __ext4_fc_track_range(struct inode *inode, void *arg, bool update)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct __ext4_fc_track_range_args *__arg =
		(struct __ext4_fc_track_range_args *)arg;

	if (inode->i_ino < EXT4_FIRST_INO(inode->i_sb)) {
		ext4_debug("Special inode %ld being modified\n", inode->i_ino);
		return -ECANCELED;
	}

	if (update) {
		ei->i_fc_lblk_start = MIN(ei->i_fc_lblk_start, __arg->start);
		ei->i_fc_lblk_end = MAX(ei->i_fc_lblk_end, __arg->end);
	} else {
		ei->i_fc_lblk_start = __arg->start;
		ei->i_fc_lblk_end = __arg->end;
	}

	return 0;
}

void ext4_fc_track_range(struct inode *inode, ext4_lblk_t start,
			 ext4_lblk_t end)
{
	struct __ext4_fc_track_range_args args;
	int ret;

	args.start = start;
	args.end = end;

	ret = __ext4_fc_track_template(inode,
					__ext4_fc_track_range, &args);

	trace_ext4_fc_track_range(inode, start, end, ret);
}

static void ext4_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	BUFFER_TRACE(bh, "");
	if (uptodate) {
		ext4_debug("%s: Block %lu up-to-date",
			   __func__, bh->b_blocknr);
		set_buffer_uptodate(bh);
	} else {
		ext4_debug("%s: Block %lu not up-to-date",
			   __func__, bh->b_blocknr);
		clear_buffer_uptodate(bh);
	}

	unlock_buffer(bh);
}

void submit_fc_bh(struct buffer_head *bh)
{
	lock_buffer(bh);
	clear_buffer_dirty(bh);
	set_buffer_uptodate(bh);
	bh->b_end_io = ext4_end_buffer_io_sync;
	submit_bh(REQ_OP_WRITE, REQ_SYNC, bh);
}


u8 *__ext4_alloc_fc_bytes_pmem(struct super_block *sb, int len)
{
	unsigned long pmem_kaddr;
	unsigned long pmem_end_addr;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	loff_t offset = 0;

	pmem_end_addr = sbi->fc_journal_start + EXT4_NUM_FC_BLKS * sb->s_blocksize;
	offset = atomic64_fetch_add(len, &(sbi->fc_journal_valid_tail));
	pmem_kaddr = sbi->fc_journal_start + offset;

	if (pmem_kaddr + len >= pmem_end_addr) {
		return (u8 *) NULL;
	}

	return (u8 *) pmem_kaddr;
}

u8 *__ext4_alloc_fc_bytes_jbd2(struct super_block *sb, int len)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct buffer_head *bh;
	int bsize = sbi->s_journal->j_blocksize;
	int ret, off = sbi->s_fc_bytes % bsize;

	if (bsize - off - 1 > len) {
		if (!sbi->s_fc_bh) {
			ret = jbd2_map_fc_buf(EXT4_SB(sb)->s_journal, &bh);
			if (ret)
				return NULL;
			sbi->s_fc_bh = bh;
		}
		sbi->s_fc_bytes += len;
		return sbi->s_fc_bh->b_data + off;
	}
	BUG_ON(len > bsize - off - 1 && sbi->s_fc_bh == NULL);

	submit_fc_bh(sbi->s_fc_bh);
	sbi->s_fc_bh = NULL;
	ret = jbd2_map_fc_buf(EXT4_SB(sb)->s_journal, &bh);
	if (ret)
		return NULL;
	sbi->s_fc_bh = bh;
	sbi->s_fc_bytes = (sbi->s_fc_bytes / bsize + 1) * bsize;
	off = sbi->s_fc_bytes % bsize;
	BUG_ON(off != 0);
	sbi->s_fc_bytes += len;
	return sbi->s_fc_bh->b_data;
}

u8 *ext4_alloc_fc_bytes(struct super_block *sb, int len)
{
	if (test_opt2(sb, JOURNAL_FC_PMEM))
		return __ext4_alloc_fc_bytes_pmem(sb, len);
	return __ext4_alloc_fc_bytes_jbd2(sb, len);
}

void ext4_fc_memcpy(struct super_block *sb, void *dst, const void *src,
		   int len)
{
    int ret = 0;
	if (test_opt2(sb, JOURNAL_FC_PMEM)) {
		ret = __copy_from_user_inatomic_nocache(dst, src, len);
        BUG_ON(ret != 0);
    } else {
	    memcpy(dst, src, len);
    }

    return;
}


/*
 * Writes fast commit header and inode structure at memory
 * pointed to by start. Returns 0 on success, error on failure.
 * If successful, *last is upadated to point to the end of
 * inode that was copied.
 */
static int fc_write_hdr(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	int inode_len = EXT4_GOOD_OLD_INODE_SIZE;
	int ret;
	struct ext4_iloc iloc;
	u8 *cur;

	if (ext4_is_inode_fc_ineligible(inode))
		return -ECANCELED;

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	if (EXT4_INODE_SIZE(inode->i_sb) > EXT4_GOOD_OLD_INODE_SIZE)
		inode_len += ei->i_extra_isize;

	cur = ext4_alloc_fc_bytes(inode->i_sb, inode_len);
	if (!cur)
		return -ENOSPC;

	ext4_fc_memcpy(inode->i_sb, cur, ext4_raw_inode(&iloc), inode_len);

	return 0;
}

/*
 * Adds tag, length and value at memory pointed to by dst. Returns
 * true if tlv was added. Returns false if there's not enough space.
 * If successful also updates *dst to point to the end of this tlv.
 */
static bool fc_try_add_tlv(struct super_block *sb, u16 tag, u16 len, u8 *val)
{
	struct ext4_fc_tl tl;
	u8 *dst;

	dst = ext4_alloc_fc_bytes(sb, sizeof(tl) + len);
	if (!dst)
		return false;

	tl.fc_tag = cpu_to_le16(tag);
	tl.fc_len = cpu_to_le16(len);

	ext4_fc_memcpy(sb, dst, &tl, sizeof(tl));
	ext4_fc_memcpy(sb, dst + sizeof(tl), val, len);

	return true;
}

/* Same as above, but tries to add dentry tlv. */
static bool fc_try_add_dentry_info_tlv(struct super_block *sb, u16 tag,
				       int parent_ino, int ino, int dlen,
				       const unsigned char *dname)
{
	struct ext4_fc_dentry_info fcd;
	struct ext4_fc_tl tl;
	u8 *dst = ext4_alloc_fc_bytes(sb, sizeof(tl) + sizeof(fcd) + dlen);

	if (!dst)
		return false;

	fcd.fc_parent_ino = cpu_to_le32(parent_ino);
	fcd.fc_ino = cpu_to_le32(ino);
	tl.fc_tag = cpu_to_le16(tag);
	tl.fc_len = cpu_to_le16(sizeof(fcd) + dlen);
	ext4_fc_memcpy(sb, dst, &tl, sizeof(tl));
	dst += sizeof(tl);
	ext4_fc_memcpy(sb, dst, &fcd, sizeof(fcd));
	dst += sizeof(fcd);
	ext4_fc_memcpy(sb, dst, dname, dlen);
	dst += dlen;

	return true;
}

/*
 * Writes data tags (EXT4_FC_TAG_ADD_RANGE / EXT4_FC_TAG_DEL_RANGE)
 * at memory pointed to by start. Returns number of TLVs that were
 * added if successfully. Returns errors otherwise.
 */
static int fc_write_data(struct inode *inode)
{
	ext4_lblk_t old_blk_size, cur_lblk_off, new_blk_size;
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_map_blocks map;
	struct ext4_extent extent;
	struct ext4_fc_lrange lrange;
	int num_tlvs = 0;
	int ret;

	write_lock(&ei->i_fc_lock);
	old_blk_size = ei->i_fc_lblk_start;
	new_blk_size = ei->i_fc_lblk_end;
	ei->i_fc_lblk_start = ei->i_fc_lblk_end;
	write_unlock(&ei->i_fc_lock);

	cur_lblk_off = old_blk_size;
	jbd_debug(1, "%s: will try writing %ld to %ld for inode %ld\n",
		  __func__, cur_lblk_off, new_blk_size, inode->i_ino);
	while (cur_lblk_off <= new_blk_size) {
		map.m_lblk = cur_lblk_off;
		map.m_len = new_blk_size - cur_lblk_off + 1;
		ret = ext4_map_blocks(NULL, inode, &map, 0);
		if (ret < 0)
			return ret;
		if (map.m_len == 0)
			return -ECANCELED;
		if (map.m_flags & EXT4_MAP_UNWRITTEN)
			return -ECANCELED;

		cur_lblk_off += map.m_len;
		if (ret == 0) {
			lrange.fc_lblk = cpu_to_le32(map.m_lblk);
			lrange.fc_len = cpu_to_le32(map.m_len);
			if (!fc_try_add_tlv(inode->i_sb, EXT4_FC_TAG_DEL_RANGE,
				sizeof(lrange), (u8 *)&lrange))
				return -ENOSPC;

		} else {
			extent.ee_block = cpu_to_le32(map.m_lblk);
			extent.ee_len = cpu_to_le16(map.m_len);
			ext4_ext_store_pblock(&extent, map.m_pblk);
			ext4_ext_mark_initialized(&extent);
			if (!fc_try_add_tlv(inode->i_sb, EXT4_FC_TAG_ADD_RANGE,
				sizeof(struct ext4_extent), (u8 *)&extent))
				return -ENOSPC;
		}
		num_tlvs++;
	}

	return num_tlvs;
}

void ext4_submit_fc_bytes(struct super_block *sb, void *priv)
{
	struct buffer_head *bh = (struct buffer_head *) priv;

	submit_fc_bh(bh);
}

static int fc_commit_data_inode(journal_t *journal, struct inode *inode)
{
	int ret;

	ret = fc_write_hdr(inode);
	if (ret < 0)
		return ret;

	ret = fc_write_data(inode);
	if (ret < 0)
		return ret;

	return 1;
}

static int submit_all_inode_data(journal_t *journal)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *iter;
	struct list_head *pos;
	int ret = 0;

	spin_lock(&sbi->s_fc_lock);
	sbi->s_fc_q_locked = 1;
	list_for_each(pos, &sbi->s_fc_q) {
		iter = list_entry(pos, struct ext4_inode_info, i_fc_list);
		ext4_set_inode_state(&iter->vfs_inode,
				     EXT4_STATE_FC_COMMITTING);
		spin_unlock(&sbi->s_fc_lock);
		ret = jbd2_submit_inode_data(journal, iter->jinode);
		if (ret) {
			return ret;
		}
		spin_lock(&sbi->s_fc_lock);
	}
	spin_unlock(&sbi->s_fc_lock);

	return ret;
}

static int wait_all_inode_data(journal_t *journal)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *pos, *n;
	int ret = 0;


	spin_lock(&sbi->s_fc_lock);
	list_for_each_entry_safe(pos, n, &sbi->s_fc_q, i_fc_list) {
		if (!ext4_test_inode_state(&pos->vfs_inode,
					   EXT4_STATE_FC_COMMITTING))
			continue;
		spin_unlock(&sbi->s_fc_lock);

		ret = jbd2_wait_inode_data(journal, pos->jinode);
		if (ret) {
			return ret;
		}
		spin_lock(&sbi->s_fc_lock);
	}
	spin_unlock(&sbi->s_fc_lock);

	return 0;
}

/*
 * Commits all the dentry updates and respective inodes till and
 * including "last".
 */
static int fc_commit_dentry_updates(journal_t *journal,
				    struct ext4_fc_dentry_update *last)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_fc_dentry_update *fc_dentry;
	struct inode *inode;
	struct list_head *pos, *n;
	struct ext4_inode_info *iter;
	int ret;
	int nblks = 0;
	int num_tlvs = 0;
	bool is_last;

	spin_lock(&sbi->s_fc_lock);
	if (list_empty(&sbi->s_fc_dentry_q)) {
		spin_unlock(&sbi->s_fc_lock);
		return 0;
	}

	while (!list_empty(&sbi->s_fc_dentry_q)) {
		fc_dentry = list_first_entry(
			&sbi->s_fc_dentry_q, struct ext4_fc_dentry_update,
			fcd_list);
		list_del_init(&fc_dentry->fcd_list);
		spin_unlock(&sbi->s_fc_lock);
		if (!fc_try_add_dentry_info_tlv(
						sb, fc_dentry->fcd_op,
						fc_dentry->fcd_parent, fc_dentry->fcd_ino,
						fc_dentry->fcd_name.len,
						fc_dentry->fcd_name.name)) {
			kmem_cache_free(ext4_fc_dentry_cachep, fc_dentry);
			return -ENOSPC;
		}
		num_tlvs++;
		/*
		 * If this was the last metadata update for this inode, clear
		 * since we are going to handle it now.
		 */
		if (fc_dentry != last &&
		    fc_dentry->fcd_op != EXT4_FC_TAG_CREAT_DENTRY) {
			kmem_cache_free(ext4_fc_dentry_cachep, fc_dentry);
			spin_lock(&sbi->s_fc_lock);
			continue;
		}

		inode = NULL;
		spin_lock(&sbi->s_fc_lock);
		list_for_each_safe(pos, n, &sbi->s_fc_q) {
			iter = list_entry(pos, struct ext4_inode_info, i_fc_list);
			if (iter->vfs_inode.i_ino == fc_dentry->fcd_ino) {
				inode = &iter->vfs_inode;
				break;
			}
		}
		spin_unlock(&sbi->s_fc_lock);
		is_last = (fc_dentry == last);
		kmem_cache_free(ext4_fc_dentry_cachep, fc_dentry);
		if (IS_ERR_OR_NULL(inode)) {
			/*
			 * Inode got evicted from memory for some
			 * reason. it's possible that someone deleted
			 * the inode after we started fast commit.
			 * We just abort fast commits in this case.
			 */
			if (is_last)
				nblks++;

			spin_lock(&sbi->s_fc_lock);
			continue;
		}

		ret = fc_write_hdr(inode);
		if (ret < 0)
			return ret;

		if (inode->i_nlink) {
			ret = fc_write_data(inode);
			if (ret < 0)
				return ret;
		}
		nblks++;
		spin_lock(&sbi->s_fc_lock);
		if (!ext4_test_inode_state(inode,
				EXT4_STATE_FC_COMMITTING)) {
			ext4_set_inode_state(inode,
					     EXT4_STATE_FC_COMMITTING);
			// BUG_ON(list_empty(&EXT4_I(inode)->i_fc_list));
			spin_unlock(&sbi->s_fc_lock);
			ret = jbd2_submit_inode_data(
				journal, EXT4_I(inode)->jinode);
			if (ret < 0)
				return ret;
			spin_lock(&sbi->s_fc_lock);
		}
		spin_unlock(&sbi->s_fc_lock);
		if (is_last)
			goto skip_unlock;
		spin_lock(&sbi->s_fc_lock);
	}

	spin_unlock(&sbi->s_fc_lock);
skip_unlock:
	return nblks;
}

static void ext4_journal_fc_cleanup_cb(journal_t *journal)
{
	struct super_block *sb = journal->j_private;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *iter;
	struct ext4_fc_dentry_update *fc_dentry;
	struct list_head *pos, *n;

	if (sbi->s_fc_bh)
		brelse(sbi->s_fc_bh);

	spin_lock(&sbi->s_fc_lock);
	sbi->s_fc_q_locked = 0;

	if (test_opt2(sb, JOURNAL_FC_PMEM))
		atomic64_set(&(sbi->fc_journal_valid_tail), 0);

	list_for_each_safe(pos, n, &sbi->s_fc_q) {
		iter = list_entry(pos, struct ext4_inode_info, i_fc_list);
		list_del_init(&iter->i_fc_list);
		ext4_clear_inode_state(&iter->vfs_inode,
				       EXT4_STATE_FC_COMMITTING);
		/* Make sure DATA_SUBMIT bit is set */
		smp_mb();
#if (BITS_PER_LONG < 64)
		wake_up_bit(&iter->i_state_flags, EXT4_STATE_FC_COMMITTING);
#else
		wake_up_bit(&iter->i_flags, EXT4_STATE_FC_COMMITTING);
#endif
	}
	list_for_each_safe(pos, n, &sbi->s_fc_staging_q) {
		iter = list_entry(pos, struct ext4_inode_info, i_fc_list);
		list_del_init(&iter->i_fc_list);
		ext4_clear_inode_state(&iter->vfs_inode,
				       EXT4_STATE_FC_COMMITTING);
		/* Make sure DATA_SUBMIT bit is set */
		smp_mb();
#if (BITS_PER_LONG < 64)
		wake_up_bit(&iter->i_state_flags, EXT4_STATE_FC_COMMITTING);
#else
		wake_up_bit(&iter->i_flags, EXT4_STATE_FC_COMMITTING);
#endif
	}
	while (!list_empty(&sbi->s_fc_dentry_q)) {
		fc_dentry = list_first_entry(&sbi->s_fc_dentry_q,
					     struct ext4_fc_dentry_update,
					     fcd_list);
		list_del_init(&fc_dentry->fcd_list);
		spin_unlock(&sbi->s_fc_lock);

		if (fc_dentry->fcd_name.name &&
			fc_dentry->fcd_name.len > DNAME_INLINE_LEN)
			kfree(fc_dentry->fcd_name.name);
		kmem_cache_free(ext4_fc_dentry_cachep, fc_dentry);
		spin_lock(&sbi->s_fc_lock);
	}
	while (!list_empty(&sbi->s_fc_staging_q)) {
		iter = list_first_entry(&sbi->s_fc_staging_q,
					struct ext4_inode_info,
					i_fc_list);
		list_del_init(&iter->i_fc_list);
		list_add_tail(&iter->i_fc_list, &sbi->s_fc_q);
	}
	INIT_LIST_HEAD(&sbi->s_fc_dentry_q);
	sbi->s_mount_state &= ~EXT4_FC_INELIGIBLE;
	sbi->s_fc_bytes = 0;
	spin_unlock(&sbi->s_fc_lock);
	trace_ext4_journal_fc_stats(sb);
}

int ext4_fc_perform_hard_commit(journal_t *journal)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *iter;
	struct list_head *pos;
	struct inode *inode;
	int ret = 0, nblks = 0;

	ret = submit_all_inode_data(journal);
	if (ret < 0) {
		return ret;
	}

	spin_lock(&sbi->s_fc_lock);
	if (!list_empty(&EXT4_SB(sb)->s_fc_dentry_q)) {
		spin_unlock(&sbi->s_fc_lock);

		ret = fc_commit_dentry_updates(
			journal, list_last_entry(
				&EXT4_SB(sb)->s_fc_dentry_q,
				struct ext4_fc_dentry_update,
				fcd_list));
		if (ret < 0) {
			return ret;
		}
		nblks = ret;
		spin_lock(&sbi->s_fc_lock);
	}

	list_for_each(pos, &sbi->s_fc_q) {
		iter = list_entry(pos, struct ext4_inode_info, i_fc_list);
		inode = &iter->vfs_inode;
		if (!ext4_test_inode_state(
			    inode, EXT4_STATE_FC_COMMITTING))
			continue;

		spin_unlock(&sbi->s_fc_lock);
		ret = fc_commit_data_inode(journal, inode);
		if (ret < 0) {
			return ret;
        }
		nblks += ret;
		spin_lock(&sbi->s_fc_lock);
	}
	spin_unlock(&sbi->s_fc_lock);

	if (sbi->s_fc_bh) {
		submit_fc_bh(sbi->s_fc_bh);
		sbi->s_fc_bh = NULL;
	}

	ret = wait_all_inode_data(journal);
	if (ret < 0) {
		return ret;
    }

	return nblks;
}

int ext4_fc_async_commit_inode(journal_t *journal, tid_t commit_tid,
			       struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	int nblks = 0, ret;
	int start_jiffies;

	trace_ext4_journal_fc_commit_cb_start(sb);
	start_jiffies = jiffies;

	if (!test_opt2(sb, JOURNAL_FAST_COMMIT) ||
	    (sbi->s_mount_state & EXT4_FC_INELIGIBLE)) {
		spin_lock(&sbi->s_fc_lock);
		sbi->s_fc_stats.fc_ineligible_commits++;
		spin_unlock(&sbi->s_fc_lock);
		trace_ext4_journal_fc_commit_cb_stop(sb, 0, "disabled");
		trace_ext4_journal_fc_stats(sb);
		return jbd2_complete_transaction(journal, commit_tid);
	}

	if (ext4_is_inode_fc_ineligible(inode)) {
		spin_lock(&sbi->s_fc_lock);
		sbi->s_fc_stats.fc_ineligible_commits++;
		spin_unlock(&sbi->s_fc_lock);
		trace_ext4_journal_fc_commit_cb_stop(sb, 0, "ineligible");
		trace_ext4_journal_fc_stats(sb);
		return jbd2_complete_transaction(journal, commit_tid);
	}

	/*
	 * In case of soft consistency mode, we wait for any parallel
	 * fast commits to complete. In case of hard consistency, if a
	 * parallel fast commit is ongoing, it is going to take care
	 * of us as well, so we don't wait.
	 */
	ret = jbd2_start_async_fc_wait(journal, commit_tid);

	if (ret == -EALREADY) {
		trace_ext4_journal_fc_commit_cb_stop(sb, 0, "already");
		trace_ext4_journal_fc_stats(sb);
		return 0;
	}

	if (ret) {
		spin_lock(&sbi->s_fc_lock);
		sbi->s_fc_stats.fc_ineligible_commits++;
		spin_unlock(&sbi->s_fc_lock);
		trace_ext4_journal_fc_commit_cb_stop(sb, 0, "start");
		trace_ext4_journal_fc_stats(sb);
		return jbd2_complete_transaction(journal, commit_tid);
	}

	if (ext4_test_inode_state(inode, EXT4_STATE_FC_COMMITTING)) {
		jbd2_stop_async_fc(journal, commit_tid);
		trace_ext4_journal_fc_commit_cb_stop(sb, 0, "committed");
		trace_ext4_journal_fc_stats(sb);
		return 0;
	}

	ret = ext4_fc_perform_hard_commit(journal);
	nblks = ret;

	if (ret < 0) {
		spin_lock(&sbi->s_fc_lock);
		sbi->s_fc_stats.fc_ineligible_commits++;
		spin_unlock(&sbi->s_fc_lock);
		trace_ext4_journal_fc_commit_cb_stop(sb, 0, "fail1");
		jbd2_stop_async_fc(journal, commit_tid);
		trace_ext4_journal_fc_stats(sb);
		sbi->s_mount_state &= ~EXT4_FC_REPLAY;
		return jbd2_complete_transaction(journal, commit_tid);
	}
	jbd2_wait_on_fc_bufs(journal, sbi->s_fc_bytes / journal->j_blocksize);
	jbd2_stop_async_fc(journal, commit_tid);

	spin_lock(&sbi->s_fc_lock);
	EXT4_SB(sb)->s_fc_stats.fc_num_commits++;
	EXT4_SB(sb)->s_fc_stats.fc_numblks += nblks;
	spin_unlock(&sbi->s_fc_lock);
	trace_ext4_journal_fc_commit_cb_stop(sb,
					     nblks < 0 ? 0 : nblks,
					     nblks >= 0 ? "success" : "fail2");
	trace_ext4_journal_fc_stats(sb);
	sbi->s_mount_state &= ~EXT4_FC_REPLAY;
	return 0;
}

void ext4_init_fast_commit(struct super_block *sb, journal_t *journal)
{
	ext4_fsblk_t pblock = 0;
	sector_t sector = 0;
	pgoff_t pgoff;
	size_t size, map_len;
	void *kaddr;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	int ret;
	struct dax_device *dax_dev = NULL;
	pfn_t __pfn_t;

	size = EXT4_NUM_FC_BLKS * PAGE_SIZE;

	/*
	 * We set replay callback even if fast commit disabled because we may
	 * could still have fast commit blocks that need to be replayed even if
	 * fast commit has now been turned off.
	 */
	//journal->j_fc_replay_callback = ext4_journal_fc_replay_cb;
	if (!test_opt2(sb, JOURNAL_FAST_COMMIT))
		return;
	journal->j_fc_cleanup_callback = ext4_journal_fc_cleanup_cb;
	if (jbd2_init_fast_commit(journal, EXT4_NUM_FC_BLKS)) {
		pr_warn("Error while enabling fast commits, turning off.");
		ext4_clear_feature_fast_commit(sb);
	}

	if (test_opt2(sb, JOURNAL_FC_PMEM)) {

		jbd2_journal_bmap(journal, journal->j_first_fc, &pblock);

		sector = pblock << 3;

		dax_dev = fs_dax_get_by_host(sb->s_bdev->bd_disk->disk_name);
		BUG_ON(dax_dev == NULL);

		ret = bdev_dax_pgoff(sb->s_bdev, sector, size, &pgoff);
		BUG_ON(ret != 0);

		map_len = dax_direct_access(dax_dev, pgoff, PHYS_PFN(size),
					    &kaddr, &__pfn_t);
		BUG_ON(map_len < 0);

		sbi->fc_journal_start = (unsigned long) kaddr;
		atomic64_set(&(sbi->fc_journal_valid_tail), 0);

		printk(KERN_INFO "%s: Journal start = 0x%lx. Tail pointer = %ld\n",
		       __func__, sbi->fc_journal_start, sbi->fc_journal_valid_tail.counter);
	}
}

int __init ext4_init_fc_dentry_cache(void)
{
	ext4_fc_dentry_cachep = KMEM_CACHE(ext4_fc_dentry_update,
					   SLAB_RECLAIM_ACCOUNT);

	if (ext4_fc_dentry_cachep == NULL)
		return -ENOMEM;

	return 0;
}
