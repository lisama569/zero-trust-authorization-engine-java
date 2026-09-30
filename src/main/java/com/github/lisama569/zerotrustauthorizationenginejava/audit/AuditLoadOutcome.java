package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/**
 * 启动时持久化审计记录的加载结果。
 * records 为通过哈希链校验的最长完好前缀；
 * corrupted 表示文件被改过/插入/删除/截断（含尾部整段缺失，可隔离前缀后恢复续写）；
 * brokenAtSequence 为首个断裂位置（尾部缺失时为缺失起点的序列号）；
 * unrecoverable 表示历史整体丢失（曾有记录但数据文件消失），无法复核也不能安全续写，
 *   必须由运维显式处置后重新初始化。
 */
public record AuditLoadOutcome(List<AuditRecord> records, boolean corrupted,
                               Long brokenAtSequence, String detail, int rawLineCount,
                               boolean unrecoverable) {

    public AuditLoadOutcome(List<AuditRecord> records, boolean corrupted,
                            Long brokenAtSequence, String detail, int rawLineCount) {
        this(records, corrupted, brokenAtSequence, detail, rawLineCount, false);
    }
}
