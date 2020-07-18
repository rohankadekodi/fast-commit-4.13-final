/*
 * BRIEF DESCRIPTION
 *
 * XIP operations.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include "pmfs.h"
#include "xip.h"
#include "inode.h"

static ssize_t
do_xip_mapping_read(struct address_space *mapping,
		    struct file_ra_state *_ra,
		    struct file *filp,
		    char __user *buf,
		    size_t len,
		    loff_t *ppos)
{
	struct inode *inode = mapping->host;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	timing_t memcpy_time;

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_SHIFT;
	do {
		unsigned long nr, left;
		void *xip_mem;
		unsigned long xip_pfn;
		int zero = 0;

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		error = pmfs_get_xip_mem(mapping, index, 1, 0,
					&xip_mem, &xip_pfn);
		if (unlikely(error < 0)) {
			if (error == -ENODATA) {
				/* sparse */
				zero = 1;
			} else
				goto out;
		}

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			/* address based flush */ ;

		/*
		 * Ok, we have the mem, so now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		PMFS_START_TIMING(memcpy_r_t, memcpy_time);
		if (!zero)
			left = __copy_to_user(buf+copied, xip_mem+offset, nr);
		else
			left = __clear_user(buf + copied, nr);
		PMFS_END_TIMING(memcpy_r_t, memcpy_time);

		if (left) {
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	return (copied ? copied : error);
}

ssize_t
xip_file_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	if (!access_ok(VERIFY_WRITE, buf, len))
		return -EFAULT;

	return do_xip_mapping_read(filp->f_mapping, &filp->f_ra, filp,
			    buf, len, ppos);
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * i_mutex.
 */
ssize_t pmfs_xip_file_read(struct file *filp, char __user *buf,
			    size_t len, loff_t *ppos)
{
	ssize_t res;
	timing_t xip_read_time;

	PMFS_START_TIMING(xip_read_t, xip_read_time);
//	rcu_read_lock();
	res = xip_file_read(filp, buf, len, ppos);
//	rcu_read_unlock();
	PMFS_END_TIMING(xip_read_t, xip_read_time);
	return res;
}

static inline void pmfs_flush_edge_cachelines(loff_t pos, ssize_t len,
	void *start_addr)
{
	if (unlikely(pos & 0x7))
		pmfs_flush_buffer(start_addr, 1, false);
	if (unlikely(((pos + len) & 0x7) && ((pos & (CACHELINE_SIZE - 1)) !=
			((pos + len) & (CACHELINE_SIZE - 1)))))
		pmfs_flush_buffer(start_addr + len, 1, false);
}

static inline size_t memcpy_to_nvmm(char *kmem, loff_t offset,
	const char __user *buf, size_t bytes)
{
	size_t copied;

	if (support_clwb) {
		copied = bytes - __copy_from_user(kmem + offset, buf, bytes);
		pmfs_flush_buffer(kmem + offset, copied, 0);
	} else {
		copied = bytes - __copy_from_user_inatomic_nocache(kmem +
						offset, buf, bytes);
	}

	return copied;
}

static ssize_t
__pmfs_xip_file_write(struct address_space *mapping, const char __user *buf,
          size_t count, loff_t pos, loff_t *ppos)
{
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	long        status = 0;
	size_t      bytes;
	ssize_t     written = 0;
	struct pmfs_inode *pi;
	timing_t memcpy_time, write_time;

	PMFS_START_TIMING(internal_write_t, write_time);
	pi = pmfs_get_inode(sb, inode->i_ino);
	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		void *xmem;
		unsigned long xpfn;

		offset = (pos & (sb->s_blocksize - 1)); /* Within page */
		index = pos >> sb->s_blocksize_bits;
		bytes = sb->s_blocksize - offset;
		if (bytes > count)
			bytes = count;

		status = pmfs_get_xip_mem(mapping, index, 1, 1, &xmem, &xpfn);
		if (status < 0) {
			break;
		}

		PMFS_START_TIMING(memcpy_w_t, memcpy_time);
		pmfs_xip_mem_protect(sb, xmem + offset, bytes, 1);
		copied = memcpy_to_nvmm((char *)xmem, offset, buf, bytes);
		pmfs_xip_mem_protect(sb, xmem + offset, bytes, 0);
		PMFS_END_TIMING(memcpy_w_t, memcpy_time);

		/* if start or end dest address is not 8 byte aligned, 
	 	 * __copy_from_user_inatomic_nocache uses cacheable instructions
	 	 * (instead of movnti) to write. So flush those cachelines. */
		pmfs_flush_edge_cachelines(pos, copied, xmem + offset);

        	if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
				buf += status;
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;
	} while (count);
	*ppos = pos;
	/*
 	* No need to use i_size_read() here, the i_size
 	* cannot change under us because we hold i_mutex.
 	*/
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		pmfs_update_isize(inode, pi);
	}

	PMFS_END_TIMING(internal_write_t, write_time);
	return written ? written : status;
}

/* optimized path for file write that doesn't require a transaction. In this
 * path we don't need to allocate any new data blocks. So the only meta-data
 * modified in path is inode's i_size, i_ctime, and i_mtime fields */
static ssize_t pmfs_file_write_fast(struct super_block *sb, struct inode *inode,
	struct pmfs_inode *pi, const char __user *buf, size_t count, loff_t pos,
	loff_t *ppos, u64 block)
{
	void *xmem = pmfs_get_block(sb, block);
	size_t copied, ret = 0, offset;
	timing_t memcpy_time;

	offset = pos & (sb->s_blocksize - 1);

	PMFS_START_TIMING(memcpy_w_t, memcpy_time);
	pmfs_xip_mem_protect(sb, xmem + offset, count, 1);
	copied = memcpy_to_nvmm((char *)xmem, offset, buf, count);
	pmfs_xip_mem_protect(sb, xmem + offset, count, 0);
	PMFS_END_TIMING(memcpy_w_t, memcpy_time);

	pmfs_flush_edge_cachelines(pos, copied, xmem + offset);

	if (likely(copied > 0)) {
		pos += copied;
		ret = copied;
	}
	if (unlikely(copied != count && copied == 0))
		ret = -EFAULT;
	*ppos = pos;
	inode->i_ctime = inode->i_mtime = current_time(inode);
	if (pos > inode->i_size) {
		/* make sure written data is persistent before updating
	 	* time and size */
		PERSISTENT_MARK();
		i_size_write(inode, pos);
		PERSISTENT_BARRIER();
		pmfs_memunlock_inode(sb, pi);
		pmfs_update_time_and_size(inode, pi);
		pmfs_memlock_inode(sb, pi);
	} else {
		u64 c_m_time;
		/* update c_time and m_time atomically. We don't need to make the data
		 * persistent because the expectation is that the close() or an explicit
		 * fsync will do that. */
		c_m_time = (inode->i_ctime.tv_sec & 0xFFFFFFFF);
		c_m_time = c_m_time | (c_m_time << 32);
		pmfs_memunlock_inode(sb, pi);
		pmfs_memcpy_atomic(&pi->i_ctime, &c_m_time, 8);
		pmfs_memlock_inode(sb, pi);
	}
	pmfs_flush_buffer(pi, 1, false);
	return ret;
}

/*
 * blk_off is used in different ways depending on whether the edge block is
 * at the beginning or end of the write. If it is at the beginning, we zero from
 * start-of-block to 'blk_off'. If it is the end block, we zero from 'blk_off' to
 * end-of-block
 */
static inline void pmfs_clear_edge_blk (struct super_block *sb, struct
	pmfs_inode *pi, bool new_blk, unsigned long block, size_t blk_off,
	bool is_end_blk)
{
	void *ptr;
	size_t count;
	unsigned long blknr;
	u64 bp = 0;

	if (new_blk) {
		blknr = block >> (pmfs_inode_blk_shift(pi) -
			sb->s_blocksize_bits);
		__pmfs_find_data_blocks(sb, pi, blknr, &bp, 1);
		ptr = pmfs_get_block(sb, bp);
		if (ptr != NULL) {
			if (is_end_blk) {
				ptr = ptr + blk_off - (blk_off % 8);
				count = pmfs_inode_blk_size(pi) -
					blk_off + (blk_off % 8);
			} else
				count = blk_off + (8 - (blk_off % 8));
			pmfs_memunlock_range(sb, ptr,  pmfs_inode_blk_size(pi));
			memset_nt(ptr, 0, count);
			pmfs_memlock_range(sb, ptr,  pmfs_inode_blk_size(pi));
		}
	}
}

ssize_t pmfs_xip_file_write(struct file *filp, const char __user *buf,
          size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	pmfs_transaction_t *trans;
	struct pmfs_inode *pi;
	ssize_t     written = 0;
	loff_t pos;
	u64 block;
	bool new_sblk = false, new_eblk = false;
	size_t count, offset, eblk_offset, ret;
	unsigned long start_blk, end_blk, num_blocks, max_logentries;
	bool same_block;
	timing_t xip_write_time, xip_write_fast_time;
	int num_blocks_found = 0;

	PMFS_START_TIMING(xip_write_t, xip_write_time);

	sb_start_write(inode->i_sb);
	inode_lock(inode);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;
	count = len;
	if (count == 0) {
		ret = 0;
		goto out;
	}

	pi = pmfs_get_inode(sb, inode->i_ino);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (pmfs_inode_blk_size(pi) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	num_blocks_found = pmfs_find_data_blocks(inode, start_blk, &block, 1);

	/* Referring to the inode's block size, not 4K */
	same_block = (((count + offset - 1) >>
			pmfs_inode_blk_shift(pi)) == 0) ? 1 : 0;
	if (block && same_block) {
		PMFS_START_TIMING(xip_write_fast_t, xip_write_fast_time);
		ret = pmfs_file_write_fast(sb, inode, pi, buf, count, pos,
			ppos, block);
		PMFS_END_TIMING(xip_write_fast_t, xip_write_fast_time);
		goto out;
	}
	max_logentries = num_blocks / MAX_PTRS_PER_LENTRY + 2;
	if (max_logentries > MAX_METABLOCK_LENTRIES)
		max_logentries = MAX_METABLOCK_LENTRIES;

	trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES + max_logentries);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}
	pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	ret = file_remove_privs(filp);
	if (ret) {
		pmfs_abort_transaction(sb, trans);
		goto out;
	}
	inode->i_ctime = inode->i_mtime = current_time(inode);
	pmfs_update_time(inode, pi);

	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway */
	if (offset != 0) {
		pmfs_find_data_blocks(inode, start_blk, &block, 1);
		if (block == 0)
		    new_sblk = true;
	}

	eblk_offset = (pos + count) & (pmfs_inode_blk_size(pi) - 1);
	if (eblk_offset != 0) {
		pmfs_find_data_blocks(inode, end_blk, &block, 1);
		if (block == 0)
			new_eblk = true;
	}

	/* don't zero-out the allocated blocks */
	pmfs_alloc_blocks(trans, inode, start_blk, num_blocks, false, ANY_CPU);

	/* now zero out the edge blocks which will be partially written */
	pmfs_clear_edge_blk(sb, pi, new_sblk, start_blk, offset, false);
	pmfs_clear_edge_blk(sb, pi, new_eblk, end_blk, eblk_offset, true);

	written = __pmfs_xip_file_write(mapping, buf, count, pos, ppos);
	if (written < 0 || written != count)
		pmfs_dbg_verbose("write incomplete/failed: written %ld len %ld"
				 " pos %llx start_blk %lx num_blocks %lx\n",
				 written, count, pos, start_blk, num_blocks);

	pmfs_commit_transaction(sb, trans);
	ret = written;
out:
	inode_unlock(inode);
	sb_end_write(inode->i_sb);
	PMFS_END_TIMING(xip_write_t, xip_write_time);

	return ret;
}

static int pmfs_find_and_alloc_blocks(struct inode *inode,
				      sector_t iblock,
				      unsigned long max_blocks,
				      u64 *bno,
				      int create)
{
	int err = -EIO;
	u64 block;
	pmfs_transaction_t *trans;
	struct pmfs_inode *pi;
	unsigned long blocks_found = 0;
	int allocated = 0;

	blocks_found = pmfs_find_data_blocks(inode, iblock, &block, max_blocks);

	if (!block) {
		struct super_block *sb = inode->i_sb;
		if (!create) {
			err = -ENODATA;
			goto err;
		}

		pi = pmfs_get_inode(sb, inode->i_ino);
		trans = pmfs_current_transaction();
		if (trans) {
			allocated = pmfs_alloc_blocks(trans, inode, iblock,
						      max_blocks, true, ANY_CPU);

			if (allocated < 0) {
				pmfs_dbg_verbose("[%s:%d] Alloc failed!\n",
					__func__, __LINE__);
				goto err;
			}
		} else {
			/* 1 lentry for inode, 1 lentry for inode's b-tree */
			trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES);
			if (IS_ERR(trans)) {
				err = PTR_ERR(trans);
				goto err;
			}

			rcu_read_unlock();
			inode_lock(inode);

			pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY,
				LE_DATA);
			allocated = pmfs_alloc_blocks(trans, inode, iblock,
						max_blocks, true, ANY_CPU);

			pmfs_commit_transaction(sb, trans);

			inode_unlock(inode);
			rcu_read_lock();
			if (allocated < 0) {
				pmfs_dbg_verbose("[%s:%d] Alloc failed!\n",
					__func__, __LINE__);
				goto err;
			}
		}

		blocks_found = pmfs_find_data_blocks(inode, iblock, &block, max_blocks);

		if (!block) {
			pmfs_dbg("[%s:%d] But alloc didn't fail!\n",
				  __func__, __LINE__);
			err = -ENODATA;
			goto err;
		}
	}

	pmfs_dbg_verbose("iblock 0x%lx allocated_block 0x%llx\n", iblock,
			 block);

	*bno = block;
	err = 0;

err:
	return blocks_found;
}

/* OOM err return with xip file fault handlers doesn't mean anything.
 * It would just cause the OS to go an unnecessary killing spree !
 */
static int __pmfs_xip_file_fault(struct vm_area_struct *vma,
				  struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	pgoff_t size;
	void *xip_mem;
	unsigned long xip_pfn;
	int err;

	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size) {
		pmfs_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx), size 0x%lx\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->address, size);
		return VM_FAULT_SIGBUS;
	}

	err = pmfs_get_xip_mem(mapping, vmf->pgoff, 1, 1, &xip_mem, &xip_pfn);
	if (unlikely(err < 0)) {
		pmfs_dbg("[%s:%d] get_xip_mem failed(OOM). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->address);
		return VM_FAULT_SIGBUS;
	}

	pmfs_dbg_mmapv("[%s:%d] vm_start(0x%lx), vm_end(0x%lx), pgoff(0x%lx), "
			"BlockSz(0x%lx), VA(0x%lx)->PA(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end, vmf->pgoff,
			PAGE_SIZE, (unsigned long)vmf->address,
			(unsigned long)xip_pfn << PAGE_SHIFT);

	err = vm_insert_mixed(vma, (unsigned long)vmf->address,
			pfn_to_pfn_t(xip_pfn));

	if (err == -ENOMEM)
		return VM_FAULT_SIGBUS;
	/*
	 * err == -EBUSY is fine, we've raced against another thread
	 * that faulted-in the same page
	 */
	if (err != -EBUSY)
		BUG_ON(err);
	return VM_FAULT_NOPAGE;
}

int pmfs_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
	unsigned int flags, struct iomap *iomap, bool taking_lock)
{
	struct pmfs_sb_info *sbi = PMFS_SB(inode->i_sb);
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	unsigned long max_blocks = (length + (1 << blkbits) - 1) >> blkbits;
	bool new = false, boundary = false;
	u64 bno;
	int ret;

	pmfs_dbg_verbose("%s: calling find_and_alloc_blocks. first_block = %lu "
			 "max_blocks = %lu. length = %lld\n", __func__,
			 first_block, max_blocks, length);

	ret = pmfs_find_and_alloc_blocks(inode,
				   first_block,
				   max_blocks,
				   &bno,
				   flags & IOMAP_WRITE);

	if (ret < 0) {
		pmfs_dbg("%s: pmfs_dax_get_blocks failed %d", __func__, ret);
		pmfs_dbg("%s: returning %d\n", __func__, ret);
		return ret;
	}

	iomap->flags = 0;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->dax_dev = sbi->s_dax_dev;
	iomap->offset = (u64)first_block << blkbits;

	if (ret == 0) {
		iomap->type = IOMAP_HOLE;
		iomap->blkno = IOMAP_NULL_BLOCK;
		iomap->length = 1 << blkbits;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->blkno = (sector_t)(bno >> 9);//<< (blkbits - 9));
		iomap->length = (u64)ret << blkbits;
		iomap->flags |= IOMAP_F_MERGED;
	}

	if (new)
		iomap->flags |= IOMAP_F_NEW;

	pmfs_dbg_verbose("%s: iomap->flags %d, iomap->offset %lld, iomap->blkno %lu, "
			 "iomap->length %llu\n", __func__, iomap->flags, iomap->offset,
			 iomap->blkno, iomap->length);

	return 0;
}


int pmfs_iomap_end(struct inode *inode, loff_t offset, loff_t length,
	ssize_t written, unsigned int flags, struct iomap *iomap)
{
	if (iomap->type == IOMAP_MAPPED &&
			written < length &&
			(flags & IOMAP_WRITE))
		truncate_pagecache(inode, inode->i_size);
	return 0;
}


static int pmfs_iomap_begin_lock(struct inode *inode, loff_t offset,
	loff_t length, unsigned int flags, struct iomap *iomap)
{
	return pmfs_iomap_begin(inode, offset, length, flags, iomap, true);
}

static struct iomap_ops pmfs_iomap_ops_lock = {
	.iomap_begin	= pmfs_iomap_begin_lock,
	.iomap_end	= pmfs_iomap_end,
};

static inline int __pmfs_get_block(struct inode *inode, pgoff_t pgoff,
				   unsigned long max_blocks, int create, u64 *result)
{
	int rc = 0;

	rc = pmfs_find_and_alloc_blocks(inode, (sector_t)pgoff, max_blocks, result,
					 create);
	return rc;
}

static int pmfs_dax_pfn_mkwrite(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	loff_t size;
	int ret = 0;
	timing_t fault_time;

	inode_lock(inode);
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size)
		ret = VM_FAULT_SIGBUS;
	else
		ret = dax_pfn_mkwrite(vmf);
	inode_unlock(inode);

	return ret;
}

int pmfs_get_xip_mem(struct address_space *mapping, pgoff_t pgoff,
		     unsigned long max_blocks, int create,
		      void **kmem, unsigned long *pfn)
{
	int rc;
	u64 block = 0;
	struct inode *inode = mapping->host;

	rc = __pmfs_get_block(inode, pgoff, max_blocks, create, &block);
	if (rc < 0) {
		pmfs_dbg1("[%s:%d] rc(%d), sb->physaddr(0x%llx), block(0x%llx),"
			" pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__,
			__LINE__, rc, PMFS_SB(inode->i_sb)->phys_addr,
			block, pgoff, create, *pfn);
		return rc;
	}

	*kmem = pmfs_get_block(inode->i_sb, block);
	*pfn = pmfs_get_pfn(inode->i_sb, block);

	pmfs_dbg_mmapvv("[%s:%d] sb->physaddr(0x%llx), block(0x%llx),"
		" pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__, __LINE__,
		PMFS_SB(inode->i_sb)->phys_addr, block, pgoff, create, *pfn);
	return rc;
}

static int pmfs_xip_huge_file_fault(struct vm_fault *vmf,
				    enum page_entry_size pe_size)
{
	int ret;
	int error = 0;
	pfn_t pfn;
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	pmfs_dbg_verbose("%s: inode %lu, pgoff %lu, pe_size %d\n",
			 __func__, inode->i_ino, vmf->pgoff, pe_size);

	if (vmf->flags & FAULT_FLAG_WRITE)
		file_update_time(vmf->vma->vm_file);

	ret = dax_iomap_fault(vmf, pe_size, &pmfs_iomap_ops_lock);

	return ret;

}

static int pmfs_xip_file_fault(struct vm_fault *vmf)
{
	int ret = 0;
	timing_t fault_time;

	/*
	pmfs_dbg("%s: got a 4K fault\n", __func__);
	return pmfs_xip_huge_file_fault(vmf, PE_SIZE_PTE);
	*/
	PMFS_START_TIMING(mmap_fault_t, fault_time);
	rcu_read_lock();
	ret = __pmfs_xip_file_fault(vmf->vma, vmf);
	rcu_read_unlock();
	PMFS_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static inline int pmfs_rbtree_compare_vma(struct vma_item *curr,
	struct vm_area_struct *vma)
{
	if (vma < curr->vma)
		return -1;
	if (vma > curr->vma)
		return 1;

	return 0;
}

int pmfs_insert_write_vma(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long flags = VM_SHARED | VM_WRITE;
	struct vma_item *item, *curr;
	struct rb_node **temp, *parent;
	int compVal;
	int insert = 0;
	int ret;
	timing_t insert_vma_time;


	if ((vma->vm_flags & flags) != flags)
		return 0;

	item = pmfs_alloc_vma_item(sb);
	if (!item) {
		return -ENOMEM;
	}

	item->vma = vma;

	pmfs_dbg_verbose("Inode %lu insert vma %p, start 0x%lx, end 0x%lx, pgoff %lu\n",
			 inode->i_ino, vma, vma->vm_start, vma->vm_end,
			 vma->vm_pgoff);

	inode_lock(inode);

	temp = &(sih->vma_tree.rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct vma_item, node);
		compVal = pmfs_rbtree_compare_vma(curr, vma);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			pmfs_dbg("%s: vma %p already exists\n",
				__func__, vma);
			kfree(item);
			goto out;
		}
	}

	rb_link_node(&item->node, parent, temp);
	rb_insert_color(&item->node, &sih->vma_tree);

	sih->num_vmas++;
	if (sih->num_vmas == 1)
		insert = 1;

out:
	inode_unlock(inode);

	return ret;
}

static int pmfs_remove_write_vma(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct vma_item *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int found = 0;
	int remove = 0;
	timing_t remove_vma_time;

	inode_lock(inode);

	temp = sih->vma_tree.rb_node;
	while (temp) {
		curr = container_of(temp, struct vma_item, node);
		compVal = pmfs_rbtree_compare_vma(curr, vma);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			rb_erase(&curr->node, &sih->vma_tree);
			found = 1;
			break;
		}
	}

	if (found) {
		sih->num_vmas--;
		if (sih->num_vmas == 0)
			remove = 1;
	}

	inode_unlock(inode);

	if (found) {
		pmfs_dbg_verbose("Inode %lu remove vma %p, start 0x%lx, end 0x%lx, pgoff %lu\n",
				 inode->i_ino,	curr->vma, curr->vma->vm_start,
				 curr->vma->vm_end, curr->vma->vm_pgoff);
		pmfs_free_vma_item(sb, curr);
	}

	return 0;
}

static void pmfs_vma_open(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	pmfs_dbg_mmap4k("[%s:%d] inode %lu, MMAP 4KPAGE vm_start(0x%lx), vm_end(0x%lx), vm pgoff %lu, %lu blocks, vm_flags(0x%lx), vm_page_prot(0x%lx)\n",
			__func__, __LINE__,
			inode->i_ino, vma->vm_start, vma->vm_end,
			vma->vm_pgoff,
			(vma->vm_end - vma->vm_start) >> PAGE_SHIFT,
			vma->vm_flags,
			pgprot_val(vma->vm_page_prot));

	pmfs_insert_write_vma(vma);
}

static void pmfs_vma_close(struct vm_area_struct *vma)
{
	pmfs_dbg_verbose("[%s:%d] MMAP 4KPAGE vm_start(0x%lx), vm_end(0x%lx), vm_flags(0x%lx), vm_page_prot(0x%lx)\n",
		  __func__, __LINE__, vma->vm_start, vma->vm_end,
		  vma->vm_flags, pgprot_val(vma->vm_page_prot));

	vma->original_write = 0;
	pmfs_remove_write_vma(vma);
}

static const struct vm_operations_struct pmfs_xip_vm_ops = {
	.fault	= pmfs_xip_file_fault,
	.huge_fault = pmfs_xip_huge_file_fault,
	.page_mkwrite = pmfs_xip_file_fault,
	.pfn_mkwrite = pmfs_dax_pfn_mkwrite,
	.open = pmfs_vma_open,
	.close = pmfs_vma_close,
};

int pmfs_xip_file_mmap(struct file *file, struct vm_area_struct *vma)
{
//	BUG_ON(!file->f_mapping->a_ops->get_xip_mem);

	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;

	vma->vm_ops = &pmfs_xip_vm_ops;

	pmfs_insert_write_vma(vma);

	pmfs_dbg_mmap4k("[%s:%d] MMAP 4KPAGE vm_start(0x%lx),"
			" vm_end(0x%lx), vm_flags(0x%lx), "
			"vm_page_prot(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end,
			vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}
