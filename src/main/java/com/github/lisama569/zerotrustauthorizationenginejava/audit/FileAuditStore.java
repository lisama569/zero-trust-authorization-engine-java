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
 * - 配套旁路基线文件 {@code <审计文件>.checkpoint}（记录数 + 末条哈希 + 校验码），
 *   用于识别哈希链自身无法发现的“尾部整段删除”与“历史文件整体丢失”；
 * - {@link #quarantineAndRewrite(List)} 把可疑原文件重命名隔离，
 *   仅用哈希链最长完好前缀重建并同步基线，后续记录继续接在完好链尾。
 */
public class FileAuditStore implements AuditStore {

    private static final Logger log = LoggerFactory.getLogger(FileAuditStore.class);

    private final Path file;
    private final AuditCheckpoint checkpoint;
    private final ObjectMapper mapper = new ObjectMapper();
    /** 追加通道：append + dsync，保证写一行持久一行；数据文件缺失时延迟打开 */
    private java.nio.channels.FileChannel channel;

    public FileAuditStore(Path file) {
        this.file = file;
        this.checkpoint = new AuditCheckpoint(file.resolveSibling(
                file.getFileName() + ".checkpoint"));
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            if (Files.notExists(file)) {
                if (!checkpoint.exists()) {
                    // 数据文件与基线同时不存在：首次使用，建立空基线
                    Files.createFile(file);
                    checkpoint.write(0, AuditHasher.GENESIS_HASH);
                }
                // 基线存在而数据文件缺失：历史可能整体丢失，保持现场，
                // 不立即补建空文件，由 AuditLog 重放时判定。
            }
            this.channel = openChannelIfDataExists();
        } catch (IOException e) {
            throw new UncheckedIOException("无法初始化审计文件: " + file, e);
        }
    }

    private java.nio.channels.FileChannel openChannelIfDataExists() throws IOException {
        if (Files.notExists(file)) {
            return null;
        }
        return java.nio.channels.FileChannel.open(file,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND);
    }

    private java.nio.channels.FileChannel ensureChannel() throws IOException {
        if (channel == null || !channel.isOpen()) {
            channel = java.nio.channels.FileChannel.open(file,
                    StandardOpenOption.WRITE, StandardOpenOption.APPEND);
        }
        return channel;
    }

    @Override
    public StoredRecords readAll() {
        boolean dataExists = Files.exists(file);
        List<String> lines;
        if (dataExists) {
            try {
                lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException("读取审计文件失败: " + file, e);
            }
        } else {
            lines = List.of();
        }
        List<AuditRecord> parsed = new ArrayList<>();
        int nonBlank = 0;
        boolean malformed = false;
        String firstError = null;
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
        return new StoredRecords(parsed, nonBlank, malformed,
                firstError == null ? "" : firstError, readAnchor(dataExists));
    }

    private StoredRecords.CheckpointState readAnchor(boolean dataExists) {
        AuditCheckpoint.Snapshot snap = checkpoint.read();
        if (snap == null) {
            return StoredRecords.CheckpointState.absent(dataExists);
        }
        if (!snap.valid()) {
            return StoredRecords.CheckpointState.invalid(snap.detail());
        }
        return StoredRecords.CheckpointState.valid(dataExists, snap.count(), snap.lastHash());
    }

    @Override
    public void append(AuditRecord record) {
        try {
            byte[] payload = (mapper.writeValueAsString(toNode(record)) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            synchronized (this) {
                ensureChannel().write(java.nio.ByteBuffer.wrap(payload));
                channel.force(true);
                // 数据落盘成功后再推进基线；序列号从 0 起连续，条数=末序号+1
                checkpoint.write((int) record.getSequence() + 1, record.getCurrentHash());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("审计记录落盘失败: " + file, e);
        }
    }

    @Override
    public void commitCheckpoint(int count, String lastHash) {
        checkpoint.write(count, lastHash == null ? "" : lastHash);
    }

    @Override
    public void ensureInitialized() {
        synchronized (this) {
            try {
                Files.createDirectories(file.toAbsolutePath().getParent());
                if (Files.notExists(file)) {
                    Files.createFile(file);
                }
                if (!checkpoint.exists()) {
                    checkpoint.write(0, AuditHasher.GENESIS_HASH);
                }
                if (channel == null || !channel.isOpen()) {
                    channel = java.nio.channels.FileChannel.open(file,
                            StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                }
            } catch (IOException e) {
                throw new UncheckedIOException("初始化审计文件失败: " + file, e);
            }
        }
    }

    @Override
    public void quarantineAndRewrite(List<AuditRecord> intactPrefix) {
        synchronized (this) {
            try {
                if (channel != null && channel.isOpen()) {
                    channel.close();
                }
                Path quarantined = file.resolveSibling(
                        file.getFileName() + ".corrupt-" + System.currentTimeMillis());
                if (Files.exists(file)) {
                    Files.move(file, quarantined, StandardCopyOption.REPLACE_EXISTING);
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
                // 以恢复出的完好前缀重建旁路基线
                String lastHash = intactPrefix.isEmpty()
                        ? AuditHasher.GENESIS_HASH
                        : intactPrefix.get(intactPrefix.size() - 1).getCurrentHash();
                checkpoint.write(intactPrefix.size(), lastHash);
                log.warn("检测到审计文件损坏，已隔离原文件到 {}，仅恢复 {} 条完好记录",
                        quarantined, intactPrefix.size());
            } catch (IOException e) {
                throw new UncheckedIOException("隔离/重建审计文件失败: " + file, e);
            }
        }
    }

    @Override
    public String location() {
        return file.toAbsolutePath().toString();
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
}
