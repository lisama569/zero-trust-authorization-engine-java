package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/**
 * 启动时持久化审计记录的加载结果。
 * records 为通过哈希链校验的最长完好前缀；
 * corrupted 表示文件被改过/插入/删除/截断，或与带外封签水位不一致；
 * brokenAtSequence 为首个断裂位置；historyLost 表示此前确认过的历史整体缺失
 * （与“首次使用、尚无历史”区分），此时不允许继续追加，必须显式恢复。
 */
public record AuditLoadOutcome(List<AuditRecord> records, boolean corrupted,
                               Long brokenAtSequence, String detail, int rawLineCount,
                               boolean historyLost) {

    public AuditLoadOutcome(List<AuditRecord> records, boolean corrupted,
                            Long brokenAtSequence, String detail, int rawLineCount) {
        this(records, corrupted, brokenAtSequence, detail, rawLineCount, false);
    }
}
