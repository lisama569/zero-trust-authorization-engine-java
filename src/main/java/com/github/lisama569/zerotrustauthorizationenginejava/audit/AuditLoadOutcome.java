package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/**
 * 启动时持久化审计记录的加载结果。
 * records 为通过哈希链校验的最长完好前缀；
 * corrupted 表示文件被改过/插入/删除/截断；brokenAtSequence 为首个断裂位置。
 */
public record AuditLoadOutcome(List<AuditRecord> records, boolean corrupted,
                               Long brokenAtSequence, String detail, int rawLineCount) {
}
