package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/**
 * 审计记录持久化存储。
 * append 与 rewrite 均由 {@link AuditLog} 持锁串行调用，实现无需再加锁。
 */
public interface AuditStore {

    /** 启动时一次性读取全部持久化记录（按文件顺序），坏行/截断通过结果标记 */
    StoredRecords readAll();

    /** 追加一条已封签记录（含 currentHash），必须落盘后才返回 */
    void append(AuditRecord record);

    /**
     * 发现损坏后：把原文件隔离（重命名），仅用最长完好前缀重建新文件，
     * 之后新记录继续追加在完好链尾。
     */
    void quarantineAndRewrite(List<AuditRecord> intactPrefix);

    /**
     * 无检查点但数据文件自带一条完好哈希链（老版本数据升级）时，
     * 以重放确认的记录数与末条哈希自举建立旁路基线。
     */
    void commitCheckpoint(int count, String lastHash);

    /**
     * 确保“首次使用”现场就绪：数据文件与空基线存在、追加通道可用。
     * 内存存储无需动作。供启动重放与不可恢复后显式重置时调用。
     */
    default void ensureInitialized() {
    }

    /** 存储位置的可读描述（日志/排查用） */
    String location();
}
