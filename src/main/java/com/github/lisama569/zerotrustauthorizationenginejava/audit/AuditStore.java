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
     * 之后新记录继续追加在完好链尾。封签水位同步重写到完好前缀。
     */
    void quarantineAndRewrite(List<AuditRecord> intactPrefix);

    /**
     * 重放确认 {@code intactPrefix} 为完整健康历史后，把带外封签水位
     * （条数 + 末条 currentHash）写到与之一致。用于给没有封签的旧版本文件补建，
     * 以及文件中记录数超过旧水位（上次写入在两盘之间崩溃）时把水位追上。
     */
    void commitWatermark(List<AuditRecord> intactPrefix);

    /**
     * 历史整体丢失、经运维显式确认后：把残留（数据文件/封签）作为证据隔离，
     * 重置为空存储并建立“全新历史”的初始封签，之后记录从 seq=0 重新开始。
     */
    void resetForFreshHistory();

    /** 存储位置的可读描述（日志/排查用） */
    String location();
}
