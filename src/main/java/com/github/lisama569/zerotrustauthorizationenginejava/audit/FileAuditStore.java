package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * 基于本地 JSONL 文件的审计存储。
 *
 * - 每行一条已封签记录，追加时立即强制落盘，进程崩溃/重启不丢已确认记录；
 * - {@link #readAll()} 逐行解析，坏行（如被截断的半行、插入的垃圾内容）
 *   通过 {@link StoredRecords#malformed()} 上报；
 * - {@link #quarantineAndRewrite(List)} 把可疑原文件重命名隔离，
 *   仅用哈希链最长完好前缀重建，后续记录继续接在完好链尾。
 *
 * 带外封签（checkpoint）：数据文件旁边维护 {@code <审计文件>.checkpoint.json}，
 * 记录最近一次已确认落盘的记录条数与末条 currentHash。它独立于数据内容，
 * 因而能发现两类“链自检无法发现”的破坏：
 * - 删掉文件末尾一整行/连续几整行：剩余行仍是自洽哈希链，但条数少于封签，
 *   重放判为损坏并定位到缺失起点；
 * - 数据文件在产生过记录后被整体删除：读到空历史但封签显示曾有记录，
 *   判为“历史整体丢失”，与首次使用（无数据文件也无封签）区分。
 */
public class FileAuditStore implements AuditStore {

    private static final Logger log = LoggerFactory.getLogger(FileAuditStore.class);

    private final Path file;
    private final Path checkpointFile;
    private final ObjectMapper mapper = new ObjectMapper();
    /** 追加通道：append + dsync，保证写一行持久一行；懒打开，文件被删后可重建 */
    private java.nio.channels.FileChannel channel;

    public FileAuditStore(Path file) {
        this.file = file;
        this.checkpointFile = file.resolveSibling(file.getFileName() + ".checkpoint.json");
        try {
            // 只确保目录存在；数据文件不在构造期创建，否则“文件被删”会被立刻掩盖
            Files.createDirectories(file.toAbsolutePath().getParent());
            this.channel = Files.exists(file)
                    ? java.nio.channels.FileChannel.open(file,
                            StandardOpenOption.WRITE, StandardOpenOption.APPEND)
                    : null;
        } catch (IOException e) {
            throw new UncheckedIOException("无法初始化审计文件: " + file, e);
        }
    }

    @Override
    public StoredRecords readAll() {
        List<AuditRecord> parsed = new ArrayList<>();
        int nonBlank = 0;
        boolean malformed = false;
        String firstError = null;
        if (Files.exists(file)) {
            List<String> lines;
            try {
                lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException("读取审计文件失败: " + file, e);
            }
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                if (line.isBlank()) {
                    continue;
                }
                nonBlank++;
                try {
                    parsed.add(deserialize(mapper.readTree(line)));
                } catch (Exception e) {
                    malformed = true;
                    if (firstError == null) {
                        firstError = "第 " + (i + 1) + " 行无法解析（疑似截断或被插入垃圾内容）: "
                                + e.getMessage();
                    }
                }
            }
        }

        Checkpoint cp = readCheckpoint();
        boolean historyExists = cp != null && cp.recordCount() > 0;
        long committedCount = cp == null ? 0 : cp.recordCount();
        String committedLastHash = cp == null ? AuditHasher.GENESIS_HASH : cp.lastHash();
        return new StoredRecords(parsed, nonBlank, malformed,
                firstError == null ? "" : firstError,
                historyExists, committedCount, committedLastHash);
    }

    @Override
    public void append(AuditRecord record) {
        try {
            byte[] payload = (mapper.writeValueAsString(toNode(record)) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            synchronized (this) {
                ensureChannelOpen();
                channel.write(java.nio.ByteBuffer.wrap(payload));
                channel.force(true);
                // 数据先于封签落盘：崩溃时最多留下“数据多、封签旧”，少记录绝不会被判完整
                writeCheckpoint(new Checkpoint(record.getSequence() + 1,
                        record.getCurrentHash(), System.currentTimeMillis()));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("审计记录落盘失败: " + file, e);
        }
    }

    @Override
    public void quarantineAndRewrite(List<AuditRecord> intactPrefix) {
        synchronized (this) {
            try {
                long quarantineStamp = System.currentTimeMillis();
                Path quarantined = null;
                if (channel != null) {
                    channel.close();
                    channel = null;
                }
                if (Files.exists(file)) {
                    quarantined = file.resolveSibling(
                            file.getFileName() + ".corrupt-" + quarantineStamp);
                    Files.move(file, quarantined, StandardCopyOption.REPLACE_EXISTING);
                }
                // 旧封签一并留证（它记录了“本该有多少条”），再按完好前缀重写
                if (Files.exists(checkpointFile)) {
                    Path quarantinedCp = checkpointFile.resolveSibling(
                            checkpointFile.getFileName() + ".corrupt-" + quarantineStamp);
                    Files.move(checkpointFile, quarantinedCp,
                            StandardCopyOption.REPLACE_EXISTING);
                }
                Files.createFile(file);
                this.channel = java.nio.channels.FileChannel.open(file,
                        StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                for (AuditRecord r : intactPrefix) {
                    byte[] payload = (mapper.writeValueAsString(toNode(r)) + "\n")
                            .getBytes(StandardCharsets.UTF_8);
                    channel.write(java.nio.ByteBuffer.wrap(payload));
                }
                channel.force(true);
                writeCheckpoint(watermark(intactPrefix));
                log.warn("检测到审计文件损坏，已隔离原文件到 {}，仅恢复 {} 条完好记录",
                        quarantined, intactPrefix.size());
            } catch (IOException e) {
                throw new UncheckedIOException("隔离/重建审计文件失败: " + file, e);
            }
        }
    }

    @Override
    public void commitWatermark(List<AuditRecord> intactPrefix) {
        synchronized (this) {
            try {
                writeCheckpoint(watermark(intactPrefix));
            } catch (IOException e) {
                throw new UncheckedIOException("写入审计封签失败: " + checkpointFile, e);
            }
        }
    }

    @Override
    public void resetForFreshHistory() {
        synchronized (this) {
            try {
                long stamp = System.currentTimeMillis();
                if (channel != null) {
                    channel.close();
                    channel = null;
                }
                // 残留数据（含全空/只有坏行的情况）作为证据隔离，不直接删除
                if (Files.exists(file)) {
                    Path quarantined = quarantinePath(file, ".lost-");
                    Files.move(file, quarantined, StandardCopyOption.REPLACE_EXISTING);
                }
                if (Files.exists(checkpointFile)) {
                    Path quarantinedCp = quarantinePath(checkpointFile, ".lost-");
                    Files.move(checkpointFile, quarantinedCp, StandardCopyOption.REPLACE_EXISTING);
                }
                Files.createFile(file);
                this.channel = java.nio.channels.FileChannel.open(file,
                        StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                // 建立“全新历史”的初始封签（条数 0），与首次使用形态一致
                writeCheckpoint(new Checkpoint(0, AuditHasher.GENESIS_HASH,
                        System.currentTimeMillis()));
                log.warn("已确认历史整体丢失并重置：残留已隔离（时间戳 {}），从空历史重新开始", stamp);
            } catch (IOException e) {
                throw new UncheckedIOException("重置审计历史失败: " + file, e);
            }
        }
    }

    @Override
    public String location() {
        return file.toAbsolutePath().toString();
    }

    private void ensureChannelOpen() throws IOException {
        if (channel == null || !channel.isOpen()) {
            Files.createDirectories(file.toAbsolutePath().getParent());
            if (Files.notExists(file)) {
                Files.createFile(file);
            }
            channel = java.nio.channels.FileChannel.open(file,
                    StandardOpenOption.WRITE, StandardOpenOption.APPEND);
        }
    }

    private Checkpoint watermark(List<AuditRecord> intactPrefix) {
        String lastHash = intactPrefix.isEmpty()
                ? AuditHasher.GENESIS_HASH
                : intactPrefix.get(intactPrefix.size() - 1).getCurrentHash();
        return new Checkpoint(intactPrefix.size(), lastHash, System.currentTimeMillis());
    }

    private Path quarantinePath(Path source, String infix) {
        return source.resolveSibling(source.getFileName() + infix + System.currentTimeMillis());
    }

    private Checkpoint readCheckpoint() {
        if (Files.notExists(checkpointFile)) {
            return null;
        }
        try {
            JsonNode n = mapper.readTree(Files.readString(checkpointFile, StandardCharsets.UTF_8));
            JsonNode countNode = n.get("recordCount");
            JsonNode hashNode = n.get("lastHash");
            if (countNode == null || countNode.isNull() || hashNode == null || hashNode.isNull()) {
                log.warn("审计封签字段缺失，按无封签处理: {}", checkpointFile);
                return null;
            }
            return new Checkpoint(countNode.asLong(), hashNode.asText(), 0L);
        } catch (Exception e) {
            // 封签自身损坏时不能盲目当作“无历史”，也无法作为可信水位：交由上层按无封签处理
            log.warn("审计封签无法解析，按无封签处理: {} : {}", checkpointFile, e.getMessage());
            return null;
        }
    }

    /** 临时文件 + 原子替换，避免崩溃时留下半个封签 */
    private void writeCheckpoint(Checkpoint cp) throws IOException {
        var n = mapper.createObjectNode();
        n.put("recordCount", cp.recordCount());
        n.put("lastHash", cp.lastHash());
        n.put("updatedAt", cp.updatedAt());
        Path tmp = checkpointFile.resolveSibling(checkpointFile.getFileName() + ".tmp");
        Files.writeString(tmp, mapper.writeValueAsString(n) + "\n", StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        try {
            Files.move(tmp, checkpointFile, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException atomicUnsupported) {
            Files.move(tmp, checkpointFile, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** 手工序列化，避免给领域模型绑定 Jackson 注解 */
    private JsonNode toNode(AuditRecord r) {
        var n = mapper.createObjectNode();
        n.put("sequence", r.getSequence());
        n.put("auditId", nz(r.getAuditId()));
        n.put("timestamp", r.getTimestamp());
        n.put("subjectId", nz(r.getSubjectId()));
        n.put("action", nz(r.getAction()));
        n.put("resourceId", nz(r.getResourceId()));
        if (r.getResourceSensitivity() == null) {
            n.putNull("resourceSensitivity");
        } else {
            n.put("resourceSensitivity", r.getResourceSensitivity());
        }
        n.put("contextSummary", nz(r.getContextSummary()));
        n.put("decision", r.getDecision() == null ? "" : r.getDecision().name());
        n.put("matchedRuleId", nz(r.getMatchedRuleId()));
        n.put("policyVersion", nz(r.getPolicyVersion()));
        n.put("attributeConditionBasis", nz(r.getAttributeConditionBasis()));
        n.put("previousHash", nz(r.getPreviousHash()));
        n.put("currentHash", nz(r.getCurrentHash()));
        return n;
    }

    private AuditRecord deserialize(JsonNode n) {
        JsonNode sens = n.get("resourceSensitivity");
        Integer sensitivity = sens == null || sens.isNull() ? null : sens.asInt();
        String decisionText = text(n, "decision");
        Decision decision = decisionText.isBlank() ? null : Decision.valueOf(decisionText);
        return new AuditRecord(
                requiredLong(n, "sequence"),
                text(n, "auditId"),
                requiredLong(n, "timestamp"),
                text(n, "subjectId"),
                text(n, "action"),
                text(n, "resourceId"),
                sensitivity,
                text(n, "contextSummary"),
                decision,
                text(n, "matchedRuleId"),
                text(n, "policyVersion"),
                text(n, "attributeConditionBasis"),
                text(n, "previousHash"),
                text(n, "currentHash"));
    }

    private static long requiredLong(JsonNode n, String field) {
        JsonNode v = n.get(field);
        if (v == null || v.isNull()) {
            throw new IllegalArgumentException("缺少字段 " + field);
        }
        return v.asLong();
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() ? "" : v.asText();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    /** 带外封签水位：已确认记录条数与末条 currentHash */
    private record Checkpoint(long recordCount, String lastHash, long updatedAt) {
    }
}
