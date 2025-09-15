/*-
 * Copyright (c) 2014-present MongoDB, Inc.
 * Copyright (c) 2008-2014 WiredTiger, Inc.
 *	All rights reserved.
 *
 * See the file LICENSE for redistribution information.
 */

#include "wt_internal.h"

/*
 * __wti_block_truncate --
 *     截断底层文件到指定长度，更新内存中的文件大小信息，并在非备份期间尝试实际文件截断。
 *     主要用于释放文件尾部空间，节省磁盘空间。即使底层系统调用失败，也会更新内存状态。
 */
int
__wti_block_truncate(WT_SESSION_IMPL *session, WT_BLOCK *block, wt_off_t len)
{
    WT_CONNECTION_IMPL *conn;
    WT_DECL_RET;

    conn = S2C(session);

    // 打印截断操作日志，便于调试和追踪
    __wt_verbose(
      session, WT_VERB_BLOCK, "truncate file %s to %" PRIuMAX, block->name, (uintmax_t)len);

    /*
     * Truncate requires serialization, we depend on our caller for that.
     *
     * Truncation isn't a requirement of the block manager, it's only used to conserve disk space.
     * Regardless of the underlying file system call's result, the in-memory understanding of the
     * file size changes.
     */
    // 无论系统调用结果如何，先更新内存中的文件大小
    block->size = block->extend_size = len;

    /*
     * Backups are done by copying files outside of WiredTiger, potentially by system utilities. We
     * cannot truncate the file during the backup window, we might surprise an application.
     *
     * This affects files that aren't involved in the backup (for example, doing incremental
     * backups, which only copies log files, or targeted backups, stops all block truncation
     * unnecessarily). We may want a more targeted solution at some point.
     */
    // 备份期间禁止截断文件，防止影响备份一致性
    if (__wt_atomic_load64(&conn->hot_backup_start) == 0)
        WT_WITH_HOTBACKUP_READ_LOCK(session, ret = __wt_ftruncate(session, block->fh, len), NULL);
        __wt_verbose(
      session, WT_VERB_BLOCK, "yang test end: truncate file %s to %" PRIuMAX, block->name, (uintmax_t)len);
    /*
     * The truncate may fail temporarily or permanently (for example, there may be a file mapping if
     * there's an open checkpoint on the file on a POSIX system, in which case the underlying
     * function returns EBUSY). It's OK, we don't have to be able to truncate files.
     */
    // 截断失败（如EBUSY/ENOTSUP）时不报错，返回0，保证系统健壮性
    return (ret == EBUSY || ret == ENOTSUP ? 0 : ret);
}

/*
 * __wti_block_discard --
 *     控制文件在系统缓冲区中的占用，防止缓存过大影响系统性能。
 *     当累计写入量超过阈值时，调用底层fh_advise接口通知操作系统丢弃缓存。
 *     如果文件句柄不支持或未配置丢弃操作，则直接返回。
 */
int
__wti_block_discard(WT_SESSION_IMPL *session, WT_BLOCK *block, size_t added_size)
{
    WT_DECL_RET;
    WT_FILE_HANDLE *handle;

    /* The file may not support this call. */
    // 检查文件句柄是否支持fh_advise（即是否能丢弃缓存），不支持则直接返回
    handle = block->fh->handle;
    if (handle->fh_advise == NULL)
        return (0);

    /* The call may not be configured. */
    // 若未配置os_cache_max（最大缓存阈值），则不做丢弃操作
    if (block->os_cache_max == 0)
        return (0);

    /*
     * We're racing on the addition, but I'm not willing to serialize on it in the standard read
     * path without evidence it's needed.
     */
    // 累加本次写入量到os_cache，若未超过阈值则直接返回
    if ((block->os_cache += added_size) <= block->os_cache_max)
        return (0);

    // 超过阈值，重置os_cache计数，并调用fh_advise通知操作系统丢弃缓存
    block->os_cache = 0;
    ret = handle->fh_advise(
      handle, (WT_SESSION *)session, (wt_off_t)0, (wt_off_t)0, WT_FILE_HANDLE_DONTNEED);
    // 对于EBUSY/ENOTSUP等错误，认为丢弃失败但不报错，保证健壮性
    return (ret == EBUSY || ret == ENOTSUP ? 0 : ret);
}

/*
 * __block_extend --
 *     扩展底层文件的大小，确保后续写入有足够空间。
 *     只有配置了extend_len时才会触发扩展，且只允许一个线程实际扩展文件。
 *     支持有锁和无锁两种扩展方式，扩展前可释放锁以避免长时间持锁。
 *     扩展失败（如EBUSY/ENOTSUP）时不报错，保证系统健壮性。
 */
static WT_INLINE int
__block_extend(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_FH *fh, wt_off_t offset,
  size_t align_size, bool *release_lockp)
{
    WT_DECL_RET;
    WT_FILE_HANDLE *handle;

    WT_ASSERT_SPINLOCK_OWNED(session, &block->live_lock);

    /*
     * The locking in this function is messy: by definition, the live system is locked when we're
     * called, but that lock may have been acquired by our caller or our caller's caller. If our
     * caller's lock, release_lock comes in set and this function can unlock it before returning (so
     * it isn't held while extending the file). If it is our caller's caller, then release_lock
     * comes in not set, indicating it cannot be released here.
     *
     * If we unlock here, we clear release_lock.
     */

    /* If not configured to extend the file, we're done. */
    // 未配置扩展长度则直接返回
    if (block->extend_len == 0)
        return (0);

    /*
     * Extend the file in chunks. We want to limit the number of threads extending the file at the
     * same time, so choose the one thread that's crossing the extended boundary. We don't extend
     * newly created files, and it's theoretically possible we might wait so long our extension of
     * the file is passed by another thread writing single blocks, that's why there's a check in
     * case the extended file size becomes too small: if the file size catches up, every thread
     * tries to extend it.
     */
    // 只允许在特定条件下扩展文件，避免多线程同时扩展
    if (block->extend_size > block->size &&
      (offset > block->extend_size ||
        offset + block->extend_len + (wt_off_t)align_size < block->extend_size))
        return (0);

    /*
     * File extension may require locking: some variants of the system call used to extend the file
     * initialize the extended space. If a writing thread races with the extending thread, the
     * extending thread might overwrite already written data, and that would be very, very bad.
     */
    // 检查文件句柄是否支持扩展操作
    handle = fh->handle;
    if (handle->fh_extend == NULL && handle->fh_extend_nolock == NULL)
        return (0);

    /*
     * Set the extend_size before releasing the lock, I don't want to read and manipulate multiple
     * values without holding a lock.
     *
     * There's a race between the calculation and doing the extension, but it should err on the side
     * of extend_size being smaller than the actual file size, and that's OK, we simply may do
     * another extension sooner than otherwise.
     */
    // 计算新的扩展目标大小，提前更新，保证并发安全
    block->extend_size = block->size + block->extend_len * 2;

    /*
     * Release any locally acquired lock if not needed to extend the file, extending the file may
     * require updating on-disk file's metadata, which can be slow. (It may be a bad idea to
     * configure for file extension on systems that require locking over the extend call.)
     */
    // 支持无锁扩展时可提前释放锁，避免长时间阻塞
    if (handle->fh_extend_nolock != NULL && *release_lockp) {
        *release_lockp = false;
        __wt_spin_unlock(session, &block->live_lock);
    }

    /*
     * The extend might fail (for example, the file is mapped into memory or a backup is in
     * progress), or discover file extension isn't supported; both are OK.
     */
    // 非备份期间尝试实际扩展文件，扩展失败不报错
    if (__wt_atomic_load64(&S2C(session)->hot_backup_start) == 0)
        WT_WITH_HOTBACKUP_READ_LOCK(
          session, ret = __wt_fextend(session, fh, block->extend_size), NULL);
    return (ret == EBUSY || ret == ENOTSUP ? 0 : ret);
}

/*
 * __wt_block_write_size --
 *     计算写入一个块所需的缓冲区大小，并进行对齐和合法性检查。
 *     限制最大写入块为(4GB-1KB)，防止溢出和异常情况。
 */
int
__wt_block_write_size(WT_SESSION_IMPL *session, WT_BLOCK *block, size_t *sizep)
{
    WT_UNUSED(session);

    /*
     * We write the page size, in bytes, into the block's header as a 4B unsigned value, and it's
     * possible for the engine to accept an item we can't write. For example, a huge key/value where
     * the allocation size has been set to something large will overflow 4B when it tries to align
     * the write. We could make this work (for example, writing the page size in units of allocation
     * size or something else), but it's not worth the effort, writing 4GB objects into a btree
     * makes no sense. Limit the writes to (4GB - 1KB), it gives us potential mode bits, and I'm not
     * interested in debugging corner cases anyway.
     */
    // 块写入需要包含块头，且按allocsize对齐
    *sizep = (size_t)WT_ALIGN(*sizep + WT_BLOCK_HEADER_BYTE_SIZE, block->allocsize);
    // 限制最大块大小，防止溢出
    if (*sizep > UINT32_MAX - 1024)
        WT_RET_MSG(session, EINVAL, "requested block size is too large");
    return (0);
}

/*
 * __wt_block_write --
 *     将缓冲区写入块文件，并返回块的地址cookie（包含objectid、offset、size、checksum）。
 *     支持数据校验和和检查点写入，最终通过__wt_block_addr_pack编码地址信息。
 */
int
__wt_block_write(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_ITEM *buf, uint8_t *addr,
  size_t *addr_sizep, bool data_checksum, bool checkpoint_io)
{
    wt_off_t offset;
    uint32_t checksum, size;
    uint8_t *endp;

    // 实际写入数据到文件，获取offset、size、checksum
    WT_RET(__wti_block_write_off(
      session, block, buf, &offset, &size, &checksum, data_checksum, checkpoint_io, false));

    // 将块地址信息编码到addr中，返回地址长度
    endp = addr;
    WT_RET(__wt_block_addr_pack(block, &endp, block->objectid, offset, size, checksum));
    *addr_sizep = WT_PTRDIFF(endp, addr);

    return (0);
}

/*
 * __block_write_off --
 *     将缓冲区写入块文件，返回块的offset、size和checksum。
 *     负责分配空间、扩展文件、写入数据、计算校验和、更新统计和缓存、处理异常回收空间等。
 *     支持数据校验和和检查点写入，保证写入块的完整性和一致性。
 */
static int
__block_write_off(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_ITEM *buf, wt_off_t *offsetp,
  uint32_t *sizep, uint32_t *checksump, bool data_checksum, bool checkpoint_io, bool caller_locked)
{
    WT_BLOCK_HEADER *blk;
    WT_DECL_RET;
    WT_FH *fh;
    wt_off_t offset;
    size_t align_size;
    uint32_t checksum;
    uint8_t *file_sizep;
    bool local_locked;

    // 初始化返回参数，防止未初始化警告
    *offsetp = 0;   /* -Werror=maybe-uninitialized */
    *sizep = 0;     /* -Werror=maybe-uninitialized */
    *checksump = 0; /* -Werror=maybe-uninitialized */

    fh = block->fh;

    /* Buffers should be aligned for writing. */
    // 检查写入缓冲区是否对齐，必须满足direct I/O要求
    if (!F_ISSET(buf, WT_ITEM_ALIGNED)) {
        WT_ASSERT(session, F_ISSET(buf, WT_ITEM_ALIGNED));
        WT_RET_MSG(session, EINVAL, "direct I/O check: write buffer incorrectly allocated");
    }

    /*
     * File checkpoint/recovery magic: done before sizing the buffer as it may grow the buffer.
     */
    // 检查是否为最终检查点写入，必要时调整缓冲区内容
    if (block->final_ckpt != NULL)
        WT_RET(__wti_block_checkpoint_final(session, block, buf, &file_sizep));

    /*
     * Align the size to an allocation unit.
     *
     * The buffer must be big enough for us to zero to the next allocsize boundary, this is one of
     * the reasons the btree layer must find out from the block-manager layer the maximum size of
     * the eventual write.
     */
    // 计算写入对齐后的大小，保证块分配对齐
    align_size = WT_ALIGN(buf->size, block->allocsize);
    if (align_size > buf->memsize) {
        WT_ASSERT(session, align_size <= buf->memsize);
        WT_RET_MSG(session, EINVAL, "buffer size check: write buffer incorrectly allocated");
    }
    if (align_size > UINT32_MAX) {
        WT_ASSERT(session, align_size <= UINT32_MAX);
        WT_RET_MSG(session, EINVAL, "buffer size check: write buffer too large to write");
    }

    /* Pre-allocate some number of extension structures. */
    // 预分配空间管理结构，提升后续分配效率
    WT_RET(__wti_block_ext_prealloc(session, 5));

    /*
     * Acquire a lock, if we don't already hold one. Allocate space for the write, and optionally
     * extend the file (note the block-extend function may release the lock). Release any locally
     * acquired lock.
     */
    // 获取live_lock锁，分配空间并扩展文件，保证并发安全
    local_locked = false;
    if (!caller_locked) {
        __wt_spin_lock(session, &block->live_lock);
        local_locked = true;
    }
    ret = __wti_block_alloc(session, block, &offset, (wt_off_t)align_size);
    if (ret == 0)
        ret = __block_extend(session, block, fh, offset, align_size, &local_locked);
    if (local_locked)
        __wt_spin_unlock(session, &block->live_lock);
    WT_RET(ret);

    /*
     * The file has finished changing size. If this is the final write in a checkpoint, update the
     * checkpoint's information inline.
     */
    // 检查点写入时，更新文件大小信息到缓冲区
    if (block->final_ckpt != NULL)
        WT_RET(__wt_vpack_uint(&file_sizep, 0, (uint64_t)block->size));

    /* Zero out any unused bytes at the end of the buffer. */
    // 对齐后多余空间填0，保证块内容一致性
    memset((uint8_t *)buf->mem + buf->size, 0, align_size - buf->size);

    /*
     * Clear the block header to ensure all of it is initialized, even the unused fields.
     */
    // 初始化块头结构，保证所有字段有效
    blk = WT_BLOCK_HEADER_REF(buf->mem);
    memset(blk, 0, sizeof(*blk));

    /*
     * Set the disk size so we don't have to incrementally read blocks during salvage.
     */
    // 设置块头中的磁盘大小字段，便于修复时定位块边界
    blk->disk_size = WT_STORE_SIZE(align_size);

    /*
     * Update the block's checksum: checksum the complete data if our caller specifies, otherwise
     * checksum the leading WT_BLOCK_COMPRESS_SKIP bytes. Applications with a compression or
     * encryption engine that includes checksums won't need a separate checksum. However, if the
     * block was too small for compression, or compression failed to shrink the block, the block
     * wasn't compressed, in which case our caller will tell us to checksum the data. If skipping
     * checksums because of compression or encryption, we still need to checksum the first
     * WT_BLOCK_COMPRESS_SKIP bytes because they're not compressed or encrypted, both to give
     * salvage a quick test of whether a block is useful and to give us a test so we don't lose the
     * first WT_BLOCK_COMPRESS_SKIP bytes without noticing.
     *
     * Checksum a little-endian version of the header, and write everything in little-endian format.
     * The checksum is (potentially) returned in a big-endian format, swap it into place in a
     * separate step.
     */
    // 计算块的校验和，支持全块或部分校验，保证数据完整性
    blk->flags = 0;
    if (data_checksum)
        F_SET(blk, WT_BLOCK_DATA_CKSUM);
    blk->checksum = 0;
    __wt_block_header_byteswap(blk);
    blk->checksum = checksum =
      __wt_checksum(buf->mem, data_checksum ? align_size : WT_BLOCK_COMPRESS_SKIP);
#ifdef WORDS_BIGENDIAN
    blk->checksum = __wt_bswap32(blk->checksum);
#endif

    /* Write the block. */
    // 实际写入数据到文件，写入失败时回收空间
    if ((ret = __wt_write(session, fh, offset, align_size, buf->mem)) != 0) {
        if (!caller_locked)
            __wt_spin_lock(session, &block->live_lock);
        WT_TRET(
          __wti_block_off_free(session, block, block->objectid, offset, (wt_off_t)align_size));
        if (!caller_locked)
            __wt_spin_unlock(session, &block->live_lock);
        WT_RET(ret);
    }

    /*
     * Optionally schedule writes for dirty pages in the system buffer cache, but only if the
     * current session can wait.
     */
    // 若系统缓存脏页超过阈值且当前session可等待，则触发fsync写回
    if (block->os_cache_dirty_max != 0 && fh->written > block->os_cache_dirty_max &&
      __wt_session_can_wait(session)) {
        fh->written = 0;
        if ((ret = __wt_fsync(session, fh, false)) != 0) {
            /*
             * Ignore ENOTSUP, but don't try again.
             */
            if (ret != ENOTSUP)
                return (ret);
            block->os_cache_dirty_max = 0;
        }
    }

    /* Optionally discard blocks from the buffer cache. */
    // 写入后尝试丢弃系统缓存，释放内存资源
    WT_RET(__wti_block_discard(session, block, align_size));

    // 更新统计信息
    WT_STAT_CONN_INCR(session, block_write);
    WT_STAT_CONN_INCRV(session, block_byte_write, align_size);
    if (checkpoint_io)
        WT_STAT_CONN_INCRV(session, block_byte_write_checkpoint, align_size);

    // 打印调试日志
    __wt_verbose_debug2(session, WT_VERB_WRITE,
      "off %" PRIuMAX ", size %" PRIuMAX ", checksum %#" PRIx32, (uintmax_t)offset,
      (uintmax_t)align_size, checksum);

    // 返回写入块的offset、size和checksum
    *offsetp = offset;
    *sizep = WT_STORE_SIZE(align_size);
    *checksump = checksum;

    return (0);
}

/*
 * __wti_block_write_off --
 *     将缓冲区写入块文件，返回块的offset、size和checksum。
 *     负责处理页头字节序转换，保证写入和返回内容一致性。
 */
int
__wti_block_write_off(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_ITEM *buf, wt_off_t *offsetp,
  uint32_t *sizep, uint32_t *checksump, bool data_checksum, bool checkpoint_io, bool caller_locked)
{
    WT_DECL_RET;

    /*
     * Ensure the page header is in little endian order; this doesn't belong here, but it's the best
     * place to catch all callers. After the write, swap values back to native order so callers
     * never see anything other than their original content.
     */
    // 写入前将页头转换为小端字节序，写入后恢复原字节序，保证跨平台一致性
    __wt_page_header_byteswap(buf->mem);
    ret = __block_write_off(
      session, block, buf, offsetp, sizep, checksump, data_checksum, checkpoint_io, caller_locked);
    __wt_page_header_byteswap(buf->mem);
    return (ret);
}
