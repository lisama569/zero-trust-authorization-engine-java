package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/**
 * 审计记录持久化存储抽象。
 *
 * <p>实现需保证：单条 {@link #appendRecord} 在返回前已持久化（fsync/flush 落盘），
 * 进程重启后 {@link #recover()} 能把历史记录整体读回，并通过检查点与逐行哈希
 * 复核发现被篡改、插入、删除或截断的本地记录。</p>
 */
public interface AuditStore {

    /** 持久化一条已入链的审计记录（阻塞至落盘） */
    void appendRecord(AuditRecord record);

    /**
     * 启动恢复：读回全部历史记录并与检查点比对。
     *
     * @throws AuditPersistenceException 本地文件被改过/插入/删除/截断，或无法解析时
     */
    AuditRecovery recover();

    /** 持久化检查点（记录总数 + 末条哈希），在追加成功后更新 */
    void checkpoint(int recordCount, String lastHash);
}
