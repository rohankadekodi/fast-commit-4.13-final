#ifndef __PMFS_INODE_H
#define __PMFS_INODE_H

/*
 * Structure of an inode in PMFS. Things to keep in mind when modifying it.
 * 1) Keep the inode size to within 96 bytes if possible. This is because
 *    a 64 byte log-entry can store 48 bytes of data and we would like
 *    to log an inode using only 2 log-entries
 * 2) root must be immediately after the qw containing height because we update
 *    root and height atomically using cmpxchg16b in pmfs_decrease_btree_height 
 * 3) i_size, i_ctime, and i_mtime must be in that order and i_size must be at
 *    16 byte aligned offset from the start of the inode. We use cmpxchg16b to
 *    update these three fields atomically.
 */
struct pmfs_inode {
	/* first 48 bytes */
	__le16	i_rsvd;         /* reserved. used to be checksum */
	u8	    height;         /* height of data b-tree; max 3 for now */
	u8	    i_blk_type;     /* data block size this inode uses */
	__le32	i_flags;            /* Inode flags */
	__le64	root;               /* btree root. must be below qw w/ height */
	__le64	i_size;             /* Size of data in bytes */
	__le32	i_ctime;            /* Inode modification time */
	__le32	i_mtime;            /* Inode b-tree Modification time */
	__le32	i_dtime;            /* Deletion Time */
	__le16	i_mode;             /* File mode */
	__le16	i_links_count;      /* Links count */
	__le64	i_blocks;           /* Blocks count */

	/* second 48 bytes */
	__le64	i_xattr;            /* Extended attribute block */
	__le32	i_uid;              /* Owner Uid */
	__le32	i_gid;              /* Group Id */
	__le32	i_generation;       /* File version (for NFS) */
	__le32	i_atime;            /* Access time */

	struct {
		__le32 rdev;    /* major/minor # */
	} dev;              /* device inode */
	__le32 padding;     /* pad to ensure truncate_item starts 8-byte aligned */
};

/*
 * PMFS-specific inode state kept in DRAM
 */
struct pmfs_inode_info_header {
	struct rb_root rb_tree;         /* RB tree for directory */
	unsigned short i_mode;
	unsigned int i_flags;
	unsigned long i_size;
	unsigned long i_blocks;
	unsigned long ino;
	unsigned long pi_addr;
	u8 i_blk_type;
};

/* This is a per-inode structure and follows immediately after the 
 * struct pmfs_inode. It is used to implement the truncate linked list and is 
 * by pmfs_truncate_add(), pmfs_truncate_del(), and pmfs_recover_truncate_list()
 * functions to manage the truncate list */
struct pmfs_inode_truncate_item {
	__le64	i_truncatesize;     /* Size of truncated inode */
	__le64  i_next_truncate;    /* inode num of the next truncated inode */
};

struct pmfs_inode_info {
	__u32   i_dir_start_lookup;
	struct list_head i_truncated;
	struct pmfs_inode_info_header header;
	struct inode	vfs_inode;
};

static inline unsigned int pmfs_inode_blk_shift (struct pmfs_inode *pi)
{
	return blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t pmfs_inode_blk_size (struct pmfs_inode *pi)
{
	return blk_type_to_size[pi->i_blk_type];
}

static inline u64
pmfs_get_addr_off(struct pmfs_sb_info *sbi, void *addr)
{
	PMFS_ASSERT((addr >= sbi->virt_addr) &&
			(addr < (sbi->virt_addr + sbi->initsize)));
	return (u64)(addr - sbi->virt_addr);
}

static inline u64 __pmfs_find_data_block(struct super_block *sb,
		struct pmfs_inode *pi, unsigned long blocknr)
{
	__le64 *level_ptr;
	u64 bp = 0;
	u32 height, bit_shift;
	unsigned int idx;

	height = pi->height;
	bp = le64_to_cpu(pi->root);

	while (height > 0) {
		level_ptr = pmfs_get_block(sb, bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;
		bp = le64_to_cpu(level_ptr[idx]);
		if (bp == 0)
			return 0;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}
	return bp;
}

/* If this is part of a read-modify-write of the inode metadata,
 * pmfs_memunlock_inode() before calling! */
static inline struct pmfs_inode *pmfs_get_inode(struct super_block *sb,
						  u64	ino)
{
	struct pmfs_super_block *ps = pmfs_get_super(sb);
	struct pmfs_inode *inode_table = pmfs_get_inode_table(sb);
	u64 bp, block, ino_offset;

	if (ino == 0)
		return NULL;

	block = ino >> pmfs_inode_blk_shift(inode_table);
	bp = __pmfs_find_data_block(sb, inode_table, block);

	if (bp == 0)
		return NULL;
	ino_offset = (ino & (pmfs_inode_blk_size(inode_table) - 1));
	return (struct pmfs_inode *)((void *)ps + bp + ino_offset);
}


static inline struct pmfs_inode_info *PMFS_I(struct inode *inode)
{
	return container_of(inode, struct pmfs_inode_info, vfs_inode);
}

static inline struct pmfs_inode_truncate_item * pmfs_get_truncate_item (struct 
		super_block *sb, u64 ino)
{
	struct pmfs_inode *pi = pmfs_get_inode(sb, ino);
	return (struct pmfs_inode_truncate_item *)(pi + 1);
}

static inline struct pmfs_inode_truncate_item * pmfs_get_truncate_list_head (
		struct super_block *sb)
{
	struct pmfs_inode *pi = pmfs_get_inode_table(sb);
	return (struct pmfs_inode_truncate_item *)(pi + 1);
}

static inline void check_eof_blocks(struct super_block *sb, 
		struct pmfs_inode *pi, loff_t size)
{
	if ((pi->i_flags & cpu_to_le32(PMFS_EOFBLOCKS_FL)) &&
		(size + sb->s_blocksize) > (le64_to_cpu(pi->i_blocks)
			<< sb->s_blocksize_bits))
		pi->i_flags &= cpu_to_le32(~PMFS_EOFBLOCKS_FL);
}

static inline void pmfs_update_time_and_size(struct inode *inode,
	struct pmfs_inode *pi)
{
	__le32 words[2];
	__le64 new_pi_size = cpu_to_le64(i_size_read(inode));

	/* pi->i_size, pi->i_ctime, and pi->i_mtime need to be atomically updated.
 	* So use cmpxchg16b here. */
	words[0] = cpu_to_le32(inode->i_ctime.tv_sec);
	words[1] = cpu_to_le32(inode->i_mtime.tv_sec);
	/* TODO: the following function assumes cmpxchg16b instruction writes
 	* 16 bytes atomically. Confirm if it is really true. */
	cmpxchg_double_local(&pi->i_size, (u64 *)&pi->i_ctime, pi->i_size,
		*(u64 *)&pi->i_ctime, new_pi_size, *(u64 *)words);
}

extern unsigned int pmfs_free_inode_subtree(struct super_block *sb,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr);
extern int __pmfs_alloc_blocks(pmfs_transaction_t *trans,
		struct super_block *sb, struct pmfs_inode *pi,
		unsigned long file_blocknr, unsigned int num, bool zero);
extern int pmfs_init_inode_table(struct super_block *sb);
extern int pmfs_alloc_blocks(pmfs_transaction_t *trans, struct inode *inode,
		unsigned long file_blocknr, unsigned int num, bool zero);
extern u64 pmfs_find_data_block(struct inode *inode,
	unsigned long file_blocknr);
int pmfs_set_blocksize_hint(struct super_block *sb, struct pmfs_inode *pi,
		loff_t new_size);
void pmfs_setsize(struct inode *inode, loff_t newsize);

extern struct inode *pmfs_iget(struct super_block *sb, unsigned long ino);
extern void pmfs_put_inode(struct inode *inode);
extern void pmfs_evict_inode(struct inode *inode);
extern struct inode *pmfs_new_inode(pmfs_transaction_t *trans,
	struct inode *dir, umode_t mode, const struct qstr *qstr);
extern void pmfs_update_isize(struct inode *inode, struct pmfs_inode *pi);
extern void pmfs_update_nlink(struct inode *inode, struct pmfs_inode *pi);
extern void pmfs_update_time(struct inode *inode, struct pmfs_inode *pi);
extern int pmfs_write_inode(struct inode *inode, struct writeback_control *wbc);
extern void pmfs_dirty_inode(struct inode *inode, int flags);
extern int pmfs_notify_change(struct dentry *dentry, struct iattr *attr);
int pmfs_getattr(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int flags);
extern void pmfs_set_inode_flags(struct inode *inode, struct pmfs_inode *pi);
extern void pmfs_get_inode_flags(struct inode *inode, struct pmfs_inode *pi);
extern unsigned long pmfs_find_region(struct inode *inode, loff_t *offset,
		int hole);
extern void pmfs_truncate_del(struct inode *inode);
extern void pmfs_truncate_add(struct inode *inode, u64 truncate_size);


#endif