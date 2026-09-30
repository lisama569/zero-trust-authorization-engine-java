package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/**
 * 存储层原始读取结果。
 * records：成功解析的记录；rawLineCount：文件中非空行总数；
 * malformed：存在无法解析的行（典型为文件被截断）。
 * anchor：旁路基线（检查点）信息，用于识别“尾部整段删除”与“历史文件整体丢失”，
 *         这两种情况哈希链前缀仍然自洽，仅靠链本身无法发现。
 */
public record StoredRecords(List<AuditRecord> records, int rawLineCount,
                            boolean malformed, String detail, CheckpointState anchor) {

    public StoredRecords(List<AuditRecord> records, int rawLineCount,
                         boolean malformed, String detail) {
        this(records, rawLineCount, malformed, detail, CheckpointState.absent());
    }

    /**
     * 旁路检查点（锚点）状态：
     * - present=false：无检查点。dataExists=false 表示首次使用（空历史）；
     *   dataExists=true 表示老版本数据升级（链校验通过后自举建立检查点）。
     * - present=true 且 valid=true：检查点记录了上一次持久化确认的记录数与末条哈希，
     *   作为外部基线；expectedCount=0 且数据文件缺失属于合法的空历史。
     * - present=true 且 valid=false：检查点本身损坏/被改写，无法信任。
     */
    public record CheckpointState(boolean present, boolean valid, boolean dataExists,
                                  int expectedCount, String lastHash, String detail) {

        public static CheckpointState absent(boolean dataExists) {
            return new CheckpointState(false, false, dataExists, 0, "", "");
        }

        /** 无检查点且没有任何历史载体（内存存储或尚未触及存储） */
        public static CheckpointState absent() {
            return absent(false);
        }

        public static CheckpointState valid(boolean dataExists, int expectedCount,
                                            String lastHash) {
            return new CheckpointState(true, true, dataExists, expectedCount,
                    lastHash == null ? "" : lastHash, "");
        }

        public static CheckpointState invalid(String detail) {
            return new CheckpointState(true, false, true, 0, "", detail);
        }
    }
}
