package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/**
 * 存储层原始读取结果。
 * records：成功解析的记录；rawLineCount：文件中非空行总数；
 * malformed：存在无法解析的行（典型为文件被截断）。
 */
public record StoredRecords(List<AuditRecord> records, int rawLineCount,
                            boolean malformed, String detail) {
}
