/*-
 * Copyright (c) 2014-present MongoDB, Inc.
 * Copyright (c) 2008-2014 WiredTiger, Inc.
 *	All rights reserved.
 *
 * See the file LICENSE for redistribution information.
 */

#pragma once

/*
 * WiredTiger's block manager interface.
 * 这是WiredTiger块管理器的核心接口定义，负责底层文件空间的分配、释放、检查点等操作。
 */

/*
 * The file's description is written into the first block of the file, which means we can use an
 * offset of 0 as an invalid offset.
 * 文件描述信息写在第一个块，offset为0表示无效偏移，用于标记空指针或未初始化状态。
 */
#define WT_BLOCK_INVALID_OFFSET 0

/*
 * The block manager maintains three per-checkpoint extent lists:
 *	alloc:	 the extents allocated in this checkpoint
 *	avail:	 the extents available for allocation
 *	discard: the extents freed in this checkpoint
 *
 * 块管理器每个检查点维护三个extent列表：
 * alloc：本次检查点分配的空间块
 * avail：当前可分配的空闲块
 * discard：本次检查点释放的空间块
 *
 * An extent list is based on two skiplists: first, a by-offset list linking
 * WT_EXT elements and sorted by file offset (low-to-high), second, a by-size
 * list linking WT_SIZE elements and sorted by chunk size (low-to-high).
 *
 * extent列表由两个跳表组成：按offset排序的WT_EXT跳表和按size排序的WT_SIZE跳表。
 *
 * Additionally, each WT_SIZE element on the by-size has a skiplist of its own,
 * linking WT_EXT elements and sorted by file offset (low-to-high).  This list
 * has an entry for extents of a particular size.
 *
 * 每个WT_SIZE节点还维护一个按offset排序的WT_EXT跳表，用于管理同一size的所有extent。
 *
 * The trickiness is each individual WT_EXT element appears on two skiplists.
 * In order to minimize allocation calls, we allocate a single array of WT_EXT
 * pointers at the end of the WT_EXT structure, for both skiplists, and store
 * the depth of the skiplist in the WT_EXT structure.  The skiplist entries for
 * the offset skiplist start at WT_EXT.next[0] and the entries for the size
 * skiplist start at WT_EXT.next[WT_EXT.depth].
 *
 * 每个WT_EXT节点同时出现在两个跳表中，通过next数组和depth字段区分offset和size跳表的指针。
 *
 * One final complication: we only maintain the per-size skiplist for the avail
 * list, the alloc and discard extent lists are not searched based on size.
 *
 * 只有avail列表维护size跳表，alloc和discard列表只用offset跳表。
 */

/*
 * WT_EXTLIST --
 *	An extent list.
 * extent列表结构，管理一组空闲或已分配空间块，支持按offset和size两种跳表。
 */
struct __wt_extlist {
    char *name; /* Name 名称，用于调试和日志 */

    uint64_t bytes;   /* Byte count 总字节数 */
    uint32_t entries; /* Entry count 块数量 */

    uint32_t objectid; /* Written object ID 写入时的对象ID */
    wt_off_t offset;   /* Written extent offset 写入时的偏移 */
    uint32_t checksum; /* Written extent checksum 校验和 */
    uint32_t size;     /* Written extent size 写入时的大小 */

    bool track_size; /* Maintain per-size skiplist 是否维护size跳表 */

    WT_EXT *last; /* Cached last element 缓存最后一个块，加速追加 */

    WT_EXT *off[WT_SKIP_MAXDEPTH]; /* Size/offset skiplists offset跳表头指针 */
    WT_SIZE *sz[WT_SKIP_MAXDEPTH]; /* size跳表头指针 */
};

/*
 * WT_EXT --
 *	Encapsulation of an extent, either allocated or freed within the
 * checkpoint.
 * extent结构，表示一个空间块，可能是已分配或已释放。
 */
struct __wt_ext {
    wt_off_t off;  /* Extent's file offset 块起始偏移 */
    wt_off_t size; /* Extent's Size 块大小 */

    uint8_t depth; /* Skip list depth 跳表层数（用于随机化加速查找） */

    /*
     * Variable-length array, sized by the number of skiplist elements. The first depth array
     * entries are the address skiplist elements, the second depth array entries are the size
     * skiplist.
     * next数组用于跳表指针，前depth个用于offset跳表，后depth个用于size跳表。
     */
    WT_EXT *next[0]; /* Offset, size skiplists */
};

/*
 * WT_SIZE --
 *	Encapsulation of a block size skiplist entry.
 * size分桶跳表节点，管理同一size的所有extent。
 */
struct __wt_size {
    wt_off_t size; /* Size 当前桶的块大小 */

    uint8_t depth; /* Skip list depth 跳表层数 */

    WT_EXT *off[WT_SKIP_MAXDEPTH]; /* Per-size offset skiplist 按offset排序的extent跳表 */

    /*
     * We don't use a variable-length array for the size skiplist, we want to be able to use any
     * cached WT_SIZE structure as the head of a list, and we don't know the related WT_EXT
     * structure's depth.
     * size跳表用固定数组，便于作为跳表头节点。
     */
    WT_SIZE *next[WT_SKIP_MAXDEPTH]; /* Size skiplist */
};

/*
 * Per session handle cached block manager information.
 * 每个session缓存的块管理器结构，加速WT_EXT和WT_SIZE对象的分配与复用。
 */
typedef struct {
    WT_EXT *ext_cache;   /* List of WT_EXT handles WT_EXT对象缓存链表 */
    u_int ext_cache_cnt; /* Count 缓存数量 */

    WT_SIZE *sz_cache;  /* List of WT_SIZE handles WT_SIZE对象缓存链表 */
    u_int sz_cache_cnt; /* Count 缓存数量 */
} WT_BLOCK_MGR_SESSION;

/*
 * WT_EXT_FOREACH --
 *	Walk a block manager skiplist.
 * 遍历offset跳表的宏，skip为遍历指针，head为跳表头。
 * WT_EXT_FOREACH_OFF --
 *	Walk a block manager skiplist where the WT_EXT.next entries are offset
 * by the depth.
 * 遍历size跳表的宏，next指针偏移depth。
 */
#define WT_EXT_FOREACH(skip, head) \
    for ((skip) = (head)[0]; (skip) != NULL; (skip) = (skip)->next[0])
#define WT_EXT_FOREACH_OFF(skip, head) \
    for ((skip) = (head)[0]; (skip) != NULL; (skip) = (skip)->next[(skip)->depth])

/*
 * WT_EXT_FOREACH_FROM_OFFSET_INCL --
 *	Walk a by-offset skiplist from the given offset, starting with the extent that contains the
 * given offset if available.
 * 从指定offset开始遍历offset跳表，包含该offset的extent优先。
 */
#define WT_EXT_FOREACH_FROM_OFFSET_INCL(skip, el, start)                        \
    for ((skip) = __wt_block_off_srch_inclusive((el), (start)); (skip) != NULL; \
         (skip) = (skip)->next[0])

/*
 * Checkpoint cookie: carries a version number as I don't want to rev the schema
 * file version should the default block manager checkpoint format change.
 *
 * Version #1 checkpoint cookie format:
 *	[1] [root addr] [alloc addr] [avail addr] [discard addr]
 *	    [file size] [checkpoint size] [write generation]
 * 检查点cookie格式，包含版本号和各类空间块信息。
 */
#define WT_BM_CHECKPOINT_VERSION 1   /* Checkpoint format version */
#define WT_BLOCK_EXTLIST_MAGIC 71002 /* Identify a list 魔数，标识extent列表 */

/*
 * There are two versions of the extent list blocks: the original, and a second version where
 * current checkpoint information is appended to the avail extent list.
 * extent列表块有两种版本，第二种支持将当前检查点信息追加到avail列表。
 */
#define WT_BLOCK_EXTLIST_VERSION_ORIG 0 /* Original version */
#define WT_BLOCK_EXTLIST_VERSION_CKPT 1 /* Checkpoint in avail output */

/*
 * Maximum buffer required to store a checkpoint: 1 version byte followed by
 * 14 packed 8B values.
 * 存储一个检查点所需的最大缓冲区大小。
 */
#define WT_BLOCK_CHECKPOINT_BUFFER (1 + 14 * WT_INTPACK64_MAXSIZE)

/*
 * __wt_block_ckpt --
 * 检查点结构，记录空间分配、释放、可用等信息。
 * 
三个变量的关系
  1. 分配空间：
  2. 从 avail 列表中查找合适的块，分配后将其从 avail 移动到 alloc。
释放空间：
    将释放的块从 alloc 移动到 discard。
回收空间：
    在某些情况下（如检查点完成后），将 discard 列表中的块合并到 avail 列表中。

举例说明
场景 1：分配空间
1.  初始状态：
    avail 列表：[10, 20), [30, 40), [50, 60)
    alloc 列表：空
    discard 列表：空
2.  操作：
    分配一个大小为 10 的空间块。
3.  结果：
    从 avail 中移除 [10, 20)，并将其加入 alloc。
    avail 列表：[30, 40), [50, 60)
    alloc 列表：[10, 20)
    discard 列表：空


场景 2：释放空间
1.  初始状态：
    avail 列表：[30, 40), [50, 60)
    alloc 列表：[10, 20)
    discard 列表：空
2.  操作：
    释放 [10, 20)。
3.  结果：
    从 alloc 中移除 [10, 20)，并将其加入 discard。
    avail 列表：[30, 40), [50, 60)
    alloc 列表：空
    discard 列表：[10, 20)


场景 3：回收空间
1.  初始状态：
    avail 列表：[30, 40), [50, 60)
    alloc 列表：空
    discard 列表：[10, 20)
2.  操作：
    将 discard 列表中的块合并到 avail。
3.  结果：
    从 discard 中移除 [10, 20)，并将其加入 avail。
    avail 列表：[10, 20), [30, 40), [50, 60)
    alloc 列表：空
    discard 列表：空
 */
struct __wt_block_ckpt {
    uint8_t version; /* Version 版本号 */

    uint32_t root_objectid;
    wt_off_t root_offset; /* The root 根节点偏移 */
    uint32_t root_checksum, root_size;

    WT_EXTLIST alloc;   /* Extents allocated 本次分配的空间块 */
    WT_EXTLIST avail;   /* Extents available 当前可分配空间块 */
    WT_EXTLIST discard; /* Extents discarded 本次释放的空间块 */

    //赋值参考__ckpt_update， 也就是block->size，也就是做checkpoint时候的文件大小
    wt_off_t file_size; /* Checkpoint file size 检查点时文件大小 */
    //ckpt_size实际上就是真实ext数据空间=file_size - avail空间(也就是磁盘碎片)
    uint64_t ckpt_size; /* Checkpoint byte count 检查点字节数，反映检查点的存储占用 */

    WT_EXTLIST ckpt_avail; /* Checkpoint free'd extents 检查点期间释放的空间块 */
    /*
     * Checkpoint archive: the block manager may potentially free a lot of memory from the
     * allocation and discard extent lists when checkpoint completes. Put it off until the
     * checkpoint resolves, that lets the upper btree layer continue eviction sooner.
     * 检查点归档，延迟释放空间块，提升eviction性能。
     */
    WT_EXTLIST ckpt_alloc;   /* Checkpoint archive 分配归档 */
    WT_EXTLIST ckpt_discard; /* Checkpoint archive 释放归档 */
};

/*
 * WT_BM --
 *	Block manager handle, references a single checkpoint in a btree.
 * 块管理器句柄，引用一个btree的检查点，包含所有块管理操作方法。
 */
struct __wt_bm {
    /* Methods 块管理器操作方法，函数指针接口 */
    int (*addr_invalid)(WT_BM *, WT_SESSION_IMPL *, const uint8_t *, size_t);
    int (*addr_string)(WT_BM *, WT_SESSION_IMPL *, WT_ITEM *, const uint8_t *, size_t);
    u_int (*block_header)(WT_BM *);
    int (*checkpoint)(WT_BM *, WT_SESSION_IMPL *, WT_ITEM *, WT_CKPT *, bool);
    int (*checkpoint_last)(WT_BM *, WT_SESSION_IMPL *, char **, char **, WT_ITEM *);
    int (*checkpoint_load)(
      WT_BM *, WT_SESSION_IMPL *, const uint8_t *, size_t, uint8_t *, size_t *, bool);
    int (*checkpoint_resolve)(WT_BM *, WT_SESSION_IMPL *, bool);
    int (*checkpoint_start)(WT_BM *, WT_SESSION_IMPL *);
    int (*checkpoint_unload)(WT_BM *, WT_SESSION_IMPL *);
    int (*close)(WT_BM *, WT_SESSION_IMPL *);
    int (*compact_end)(WT_BM *, WT_SESSION_IMPL *);
    int (*compact_page_rewrite)(WT_BM *, WT_SESSION_IMPL *, uint8_t *, size_t *, bool *);
    int (*compact_page_skip)(WT_BM *, WT_SESSION_IMPL *, const uint8_t *, size_t, bool *);
    int (*compact_skip)(WT_BM *, WT_SESSION_IMPL *, bool *);
    void (*compact_progress)(WT_BM *, WT_SESSION_IMPL *);
    int (*compact_start)(WT_BM *, WT_SESSION_IMPL *);
    int (*corrupt)(WT_BM *, WT_SESSION_IMPL *, const uint8_t *, size_t);
    int (*free)(WT_BM *, WT_SESSION_IMPL *, const uint8_t *, size_t);
    bool (*is_mapped)(WT_BM *, WT_SESSION_IMPL *);
    int (*map_discard)(WT_BM *, WT_SESSION_IMPL *, void *, size_t);
    int (*read)(WT_BM *, WT_SESSION_IMPL *, WT_ITEM *, const uint8_t *, size_t);
    int (*salvage_end)(WT_BM *, WT_SESSION_IMPL *);
    int (*salvage_next)(WT_BM *, WT_SESSION_IMPL *, uint8_t *, size_t *, bool *);
    int (*salvage_start)(WT_BM *, WT_SESSION_IMPL *);
    int (*salvage_valid)(WT_BM *, WT_SESSION_IMPL *, uint8_t *, size_t, bool);
    int (*size)(WT_BM *, WT_SESSION_IMPL *, wt_off_t *);
    int (*stat)(WT_BM *, WT_SESSION_IMPL *, WT_DSRC_STATS *stats);
    int (*switch_object)(WT_BM *, WT_SESSION_IMPL *, uint32_t);
    int (*switch_object_end)(WT_BM *, WT_SESSION_IMPL *, uint32_t);
    int (*sync)(WT_BM *, WT_SESSION_IMPL *, bool);
    int (*verify_addr)(WT_BM *, WT_SESSION_IMPL *, const uint8_t *, size_t);
    int (*verify_end)(WT_BM *, WT_SESSION_IMPL *);
    int (*verify_start)(WT_BM *, WT_SESSION_IMPL *, WT_CKPT *, const char *[]);
    int (*write)(WT_BM *, WT_SESSION_IMPL *, WT_ITEM *, uint8_t *, size_t *, bool, bool);
    int (*write_size)(WT_BM *, WT_SESSION_IMPL *, size_t *);

    WT_BLOCK *block; /* Underlying file. For a multi-handle tree this will be the writable file. */
    WT_BLOCK *next_block; /* If doing a tier switch, this is going to be the new file. */
    WT_BLOCK *prev_block; /* If a tier switch was done, this was the old file. */

    void *map; /* Mapped region 文件映射指针 */
    size_t maplen; /* 映射长度 */
    void *mapped_cookie; /* 映射相关cookie */

    /*
     * For trees, such as tiered tables, that are allowed to have more than one backing file or
     * object, we maintain an array of the block handles used by the tree. We use a reader-writer
     * mutex to protect the array. We lock it for reading when looking for a handle in the array and
     * lock it for writing when adding or removing handles in the array.
     * 支持多文件/对象场景，维护块句柄数组，读写锁保护并发访问。
     */
    bool is_multi_handle;
    WT_BLOCK **handle_array;       /* Array of block handles 块句柄数组 */
    size_t handle_array_allocated; /* Size of handle array 数组分配大小 */
    WT_RWLOCK handle_array_lock;   /* Lock for block handle array 读写锁 */
    u_int handle_array_next;       /* Next open slot 下一个可用槽位 */
    uint32_t max_flushed_objectid; /* Local objects at or below this id should be closed 最大已刷盘对象ID */

    /*
     * There's only a single block manager handle that can be written, all others are checkpoints.
     * 只有一个块管理器句柄可写，其余为只读检查点。
     */
    bool is_live; /* The live system 是否为可写系统 */
};

/*
 * WT_BLOCK --
 *	Block manager handle, references a single file.
 * 块管理器句柄，管理一个底层文件的所有空间分配、回收、检查点等操作。
 */
struct __wt_block {
    const char *name;  /* Name 文件名 */
    uint32_t objectid; /* Object id 文件对象ID（支持多对象场景） */
    uint32_t ref;      /* References 引用计数 */

    TAILQ_ENTRY(__wt_block) q;     /* Linked list of handles 块管理器链表节点 */
    TAILQ_ENTRY(__wt_block) hashq; /* Hashed list of handles 哈希链表节点 */

    WT_FH *fh;            /* Backing file handle 文件句柄 */
    wt_off_t size;        /* File size 当前文件大小 */
    wt_off_t extend_size; /* File extended size 文件扩展后的大小 */
    wt_off_t extend_len;  /* File extend chunk size 扩展块大小 */

    bool created_during_backup; /* Created during incremental backup 增量备份期间创建 */
    bool sync_on_checkpoint;    /* fsync the handle after the next checkpoint 检查点后需要fsync */
    bool remote;                /* Handle references non-local object 是否远程对象 */
    bool readonly;              /* Underlying file was opened only for reading 是否只读 */

    /* Configuration information, set when the file is opened. */
    wt_shared uint32_t allocfirst; /* Allocation is first-fit 是否采用first-fit分配策略 */
    uint32_t allocsize;            /* Allocation size 块分配的最小单位 */
    size_t os_cache;               /* System buffer cache flush max 系统缓存刷新阈值 */
    size_t os_cache_max;           /* 系统缓存最大值 */
    size_t os_cache_dirty_max;     /* 系统缓存脏页最大值 */

    u_int block_header; /* Header length 块头长度 */

    /*
     * There is only a single checkpoint in a file that can be written; stored here, only accessed
     * by one WT_BM handle.
     * 只允许一个可写检查点，live只被一个块管理器句柄访问。
     */
    WT_SPINLOCK live_lock; /* Live checkpoint lock 活动检查点锁 */
    WT_BLOCK_CKPT live;    /* Live checkpoint 活动检查点结构，管理空间分配/回收等 */
    bool live_open;        /* Live system is open 活动系统是否打开 */
    enum {                 /* Live checkpoint status 活动检查点状态 */
        WT_CKPT_NONE = 0,
        WT_CKPT_INPROGRESS,
        WT_CKPT_PANIC_ON_FAILURE,
        WT_CKPT_SALVAGE
    } ckpt_state;

    WT_CKPT *final_ckpt; /* Final live checkpoint write 最终检查点写入结构 */

    /* Compaction support 压缩相关统计与配置 */
    bool compact_estimated;                    /* If compaction work has been estimated 是否已估算压缩工作量 */
    int compact_pct_tenths;                    /* Percent to compact 压缩比例（十分之一为单位） */
    uint64_t compact_bytes_reviewed;           /* Bytes reviewed 已检查字节数 */
    uint64_t compact_bytes_rewritten;          /* Bytes rewritten 已重写字节数 */
    uint64_t compact_bytes_rewritten_expected; /* The expected number of bytes to rewrite 预期重写字节数 */
    uint64_t compact_internal_pages_reviewed;  /* Internal pages reviewed 已检查内部页数 */
    uint64_t compact_pages_reviewed;           /* Pages reviewed 已检查页数 */
    uint64_t compact_pages_rewritten;          /* Pages rewritten 已重写页数 */
    uint64_t compact_pages_rewritten_expected; /* The expected number of pages to rewrite 预期重写页数 */
    uint64_t compact_pages_skipped;            /* Pages skipped 跳过页数 */
    uint64_t compact_prev_pages_rewritten;     /* Pages rewritten during the previous iteration 上次迭代重写页数 */
    wt_off_t compact_prev_size;                /* File size at the start of a compaction pass 压缩前文件大小 */
    uint32_t compact_session_id;               /* Session compacting 压缩会话ID */

    /* Salvage support 文件修复相关 */
    wt_off_t slvg_off; /* Salvage file offset 修复时的文件偏移 */

    /* Verification support 校验相关配置与统计 */
    bool verify;             /* If performing verification 是否正在校验 */
    bool verify_layout;      /* Print out file layout information 是否打印文件布局 */
    bool dump_tree_shape;    /* Print out tree shape 是否打印树形结构 */
    bool verify_strict;      /* Fail hard on any error 是否严格校验 */
    wt_off_t verify_size;    /* Checkpoint's file size 检查点时文件大小 */
    WT_EXTLIST verify_alloc; /* Verification allocation list 校验时分配列表 */
    uint64_t frags;          /* Maximum frags in the file 文件最大碎片数 */
    uint8_t *fragfile;       /* Per-file frag tracking list 文件级碎片跟踪 */
    uint8_t *fragckpt;       /* Per-checkpoint frag tracking list 检查点级碎片跟踪 */

    /* Multi-file support 多文件支持相关 */
    wt_shared uint32_t read_count; /* Count of active read requests using this block handle 当前块句柄的活跃读请求数 */
};

/*
 * WT_BLOCK_DESC --
 *	The file's description.
 * 文件描述结构，存储在文件头部，包含魔数、版本、校验和等元数据。
 */
struct __wt_block_desc {
#define WT_BLOCK_MAGIC 120897
    uint32_t magic; /* 00-03: Magic number 魔数，用于识别文件类型 */
#define WT_BLOCK_MAJOR_VERSION 1
    uint16_t majorv; /* 04-05: Major version 主版本号 */
#define WT_BLOCK_MINOR_VERSION 0
    uint16_t minorv; /* 06-07: Minor version 次版本号 */

    uint32_t checksum; /* 08-11: Description block checksum 文件头校验和 */

    uint32_t unused; /* 12-15: Padding 填充字节，保证结构对齐 */
};
/*
 * WT_BLOCK_DESC_SIZE is the expected structure size -- we verify the build to ensure the compiler
 * hasn't inserted padding (padding won't cause failure, we reserve the first allocation-size block
 * of the file for this information, but it would be worth investigation, regardless).
 * 文件描述结构的预期大小，编译时校验防止结构体被填充。
 */
#define WT_BLOCK_DESC_SIZE 16

/*
 * __wt_block_desc_byteswap --
 *     Handle big- and little-endian transformation of a description block.
 * 处理文件描述结构的字节序转换（大端/小端），保证跨平台兼容。
 */
static WT_INLINE void
__wt_block_desc_byteswap(WT_BLOCK_DESC *desc)
{
#ifdef WORDS_BIGENDIAN
    desc->magic = __wt_bswap32(desc->magic);
    desc->majorv = __wt_bswap16(desc->majorv);
    desc->minorv = __wt_bswap16(desc->minorv);
    desc->checksum = __wt_bswap32(desc->checksum);
#else
    WT_UNUSED(desc);
#endif
}

/*
 * WT_BLOCK_HEADER --
 *	Blocks have a common header, a WT_PAGE_HEADER structure followed by a
 * block-manager specific structure: WT_BLOCK_HEADER is WiredTiger's default.
 * 块头结构，紧跟在WT_PAGE_HEADER之后，包含块大小、校验和、标志等元数据。
 */
struct __wt_block_header {
    /*
     * We write the page size in the on-disk page header because it makes salvage easier. (If we
     * don't know the expected page length, we'd have to read increasingly larger chunks from the
     * file until we find one that checksums, and that's going to be harsh given WiredTiger's
     * potentially large page sizes.)
     * 块头中记录页面大小，便于修复时快速定位块边界。
     */
    uint32_t disk_size; /* 00-03: on-disk page size 块实际大小 */

    /*
     * Page checksums are stored in two places. First, the page checksum is written within the
     * internal page that references it as part of the address cookie. This is done to improve the
     * chances of detecting not only disk corruption but other bugs (for example, overwriting a page
     * with another valid page image). Second, a page's checksum is stored in the disk header. This
     * is for salvage, so salvage knows it has found a page that may be useful.
     * 校验和既存于地址cookie，也存于块头，提升数据完整性和修复能力。
     */
    uint32_t checksum; /* 04-07: checksum 块校验和 */

/*
 * No automatic generation: flag values cannot change, they're written to disk.
 */
#define WT_BLOCK_DATA_CKSUM 0x1u /* Block data is part of the checksum 块数据参与校验和计算 */
    uint8_t flags;               /* 08: flags 标志位 */

    /*
     * End the structure with 3 bytes of padding: it wastes space, but it leaves the structure
     * 32-bit aligned and having a few bytes to play with in the future can't hurt.
     * 结构末尾填充3字节，保证32位对齐，便于未来扩展。
     */
    uint8_t unused[3]; /* 09-11: unused padding 未使用填充 */
};
/*
 * WT_BLOCK_HEADER_SIZE is the number of bytes we allocate for the structure: if the compiler
 * inserts padding it will break the world.
 * 块头结构的实际分配字节数，编译时校验防止结构体被填充。
 */
#define WT_BLOCK_HEADER_SIZE 12

/*
 * __wt_block_header_byteswap_copy --
 *     Handle big- and little-endian transformation of a header block, copying from a source to a
 *     target.
 * 块头结构的字节序转换（大端/小端），支持拷贝转换。
 */
static WT_INLINE void
__wt_block_header_byteswap_copy(WT_BLOCK_HEADER *from, WT_BLOCK_HEADER *to)
{
    *to = *from;
#ifdef WORDS_BIGENDIAN
    to->disk_size = __wt_bswap32(from->disk_size);
    to->checksum = __wt_bswap32(from->checksum);
#endif
}

/*
 * __wt_block_header_byteswap --
 *     Handle big- and little-endian transformation of a header block.
 * 块头结构的原地字节序转换（大端/小端）。
 */
static WT_INLINE void
__wt_block_header_byteswap(WT_BLOCK_HEADER *blk)
{
#ifdef WORDS_BIGENDIAN
    __wt_block_header_byteswap_copy(blk, blk);
#else
    WT_UNUSED(blk);
#endif
}

/*
 * WT_BLOCK_HEADER_BYTE
 * WT_BLOCK_HEADER_BYTE_SIZE --
 *	The first usable data byte on the block (past the combined headers).
 * 块中首个可用数据字节（跳过WT_PAGE_HEADER和WT_BLOCK_HEADER）。
 */
#define WT_BLOCK_HEADER_BYTE_SIZE (WT_PAGE_HEADER_SIZE + WT_BLOCK_HEADER_SIZE)
#define WT_BLOCK_HEADER_BYTE(dsk) ((void *)((uint8_t *)(dsk) + WT_BLOCK_HEADER_BYTE_SIZE))

/*
 * We don't compress or encrypt the block's WT_PAGE_HEADER or WT_BLOCK_HEADER structures because we
 * need both available with decompression or decryption. We use the WT_BLOCK_HEADER checksum and
 * on-disk size during salvage to figure out where the blocks are, and we use the WT_PAGE_HEADER
 * in-memory size during decompression and decryption to know how large a target buffer to allocate.
 * We can only skip the header information when doing encryption, but we skip the first 64B when
 * doing compression; a 64B boundary may offer better alignment for the underlying compression
 * engine, and skipping 64B shouldn't make any difference in terms of compression efficiency.
 * 块头和页头不参与压缩/加密，保证修复、解密、解压时能正确定位和分配缓冲区。
 */
#define WT_BLOCK_COMPRESS_SKIP 64
#define WT_BLOCK_ENCRYPT_SKIP WT_BLOCK_HEADER_BYTE_SIZE

/*
 * __wt_block_header --
 *     Return the size of the block-specific header.
 * 返回块头结构的字节数。
 */
static WT_INLINE u_int
__wt_block_header(WT_BLOCK *block)
{
    WT_UNUSED(block);

    return ((u_int)WT_BLOCK_HEADER_SIZE);
}

/*
 * __wt_block_eligible_for_sweep --
 *     Return true if the block meets requirements for sweeping. The check that read reference count
 *     is zero is made elsewhere.
 * 判断块是否满足清理（sweep）条件，主要用于后台空间回收。
 */
static WT_INLINE bool
__wt_block_eligible_for_sweep(WT_BM *bm, WT_BLOCK *block)
{
    return (!block->remote && block->objectid <= bm->max_flushed_objectid);
}