package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * 审计文件的旁路基线（检查点）。
 *
 * 检查点与 JSONL 审计文件分开存放（{@code <audit文件>.checkpoint}），
 * 记录“上一次持久化已确认的记录总数”与“末条记录的 currentHash”，
 * 外加一份防误改校验码。仅靠哈希链无法发现两种破坏：
 * 1) 文件尾部整段删除（剩余前缀依然自洽）；
 * 2) 曾写入记录后整份历史文件被删（空文件与“首次使用”无法区分）。
 * 检查点提供链外基线，使这两种情况都可被识别。
 *
 * 崩溃安全：写顺序固定为“先追加审计记录并 force，再原子替换检查点”。
 * 任意时刻崩溃，最坏结果是检查点落后数据文件至多 1 条（下链哈希一致时补齐），
 * 不会出现检查点领先于已确认数据的情况。
 */
public final class AuditCheckpoint {

    static final int FORMAT_VERSION = 1;
    private static final String CHECKSUM_SALT = "zero-trust-audit-checkpoint-v1";

    private final ObjectMapper mapper = new ObjectMapper();
    private final Path file;

    public AuditCheckpoint(Path checkpointFile) {
        this.file = checkpointFile;
    }

    /** 检查点文件路径 */
    public Path path() {
        return file;
    }

    public boolean exists() {
        return Files.exists(file);
    }

    /**
     * 读取并校验检查点。
     * @return 解析与校验结果（valid=false 且 detail 说明原因）；文件不存在返回 null
     */
    public Snapshot read() {
        if (Files.notExists(file)) {
            return null;
        }
        try {
            JsonNode n = mapper.readTree(Files.readString(file, StandardCharsets.UTF_8));
            int version = n.path("version").asInt(0);
            if (version != FORMAT_VERSION) {
                return Snapshot.invalid("检查点版本不受支持: " + version);
            }
            JsonNode countNode = n.get("count");
            JsonNode hashNode = n.get("lastHash");
            JsonNode sumNode = n.get("checksum");
            if (countNode == null || !countNode.canConvertToInt()) {
                return Snapshot.invalid("检查点缺少合法的 count 字段");
            }
            int count = countNode.asInt();
            String lastHash = hashNode == null || hashNode.isNull() ? "" : hashNode.asText();
            String checksum = sumNode == null || sumNode.isNull() ? "" : sumNode.asText();
            if (count < 0) {
                return Snapshot.invalid("检查点 count 非法: " + count);
            }
            if (!checksumFor(count, lastHash).equals(checksum)) {
                return Snapshot.invalid("检查点校验码不匹配，检查点可能被篡改或损坏");
            }
            return Snapshot.valid(count, lastHash);
        } catch (IOException e) {
            return Snapshot.invalid("检查点无法读取: " + e.getMessage());
        }
    }

    /** 原子写入检查点（临时文件 + 原子移动，失败回退普通替换） */
    public void write(int count, String lastHash) {
        try {
            var n = mapper.createObjectNode();
            n.put("version", FORMAT_VERSION);
            n.put("count", count);
            n.put("lastHash", lastHash == null ? "" : lastHash);
            n.put("checksum", checksumFor(count, lastHash));
            byte[] payload = (mapper.writeValueAsString(n) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp-"
                    + System.nanoTime());
            Files.write(tmp, payload, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicNotSupported) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("写入审计检查点失败: " + file, e);
        }
    }

    private static String checksumFor(int count, String lastHash) {
        return AuditHasher.hash(CHECKSUM_SALT + "|" + count + "|" + (lastHash == null ? "" : lastHash));
    }

    /** 检查点解析结果 */
    public record Snapshot(boolean valid, int count, String lastHash, String detail) {
        static Snapshot valid(int count, String lastHash) {
            return new Snapshot(true, count, lastHash, "");
        }

        static Snapshot invalid(String detail) {
            return new Snapshot(false, 0, "", detail);
        }
    }
}
