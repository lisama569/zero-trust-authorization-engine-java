package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/**
 * 存储层原始读取结果。
 * records：成功解析的记录；rawLineCount：文件中非空行总数；
 * malformed：存在无法解析的行（典型为文件被截断）。
 *
 * historyExists：带外封签是否表明“此前确实产生过历史”（封签条数 &gt; 0）。
 * 用于区分“首次使用、尚无历史”与“历史整体丢失”。
 * committedCount / committedLastHash：最后一次已确认落盘的封签水位
 * （记录条数与末条 currentHash），用于发现整行尾部删除与末条替换。
 */
public record StoredRecords(List<AuditRecord> records, int rawLineCount,
                            boolean malformed, String detail,
                            boolean historyExists, long committedCount,
                            String committedLastHash) {

    /** 无带外封签信息时的兼容构造器（如纯内存存储/旧版本文件） */
    public StoredRecords(List<AuditRecord> records, int rawLineCount,
                         boolean malformed, String detail) {
        this(records, rawLineCount, malformed, detail, false, records.size(),
                AuditHasher.GENESIS_HASH);
    }
}
