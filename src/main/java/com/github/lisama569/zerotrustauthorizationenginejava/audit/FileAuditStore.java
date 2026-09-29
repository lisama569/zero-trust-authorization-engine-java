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
 */
public class FileAuditStore implements AuditStore {

    private static final Logger log = LoggerFactory.getLogger(FileAuditStore.class);

    private final Path file;
    private final ObjectMapper mapper = new ObjectMapper();
    /** 追加通道：append + dsync，保证写一行持久一行 */
    private java.nio.channels.FileChannel channel;

    public FileAuditStore(Path file) {
        this.file = file;
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            if (Files.notExists(file)) {
                Files.createFile(file);
            }
            this.channel = java.nio.channels.FileChannel.open(file,
                    StandardOpenOption.WRITE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("无法初始化审计文件: " + file, e);
        }
    }

    @Override
    public StoredRecords readAll() {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("读取审计文件失败: " + file, e);
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
        return new StoredRecords(parsed, nonBlank, malformed, firstError == null ? "" : firstError);
    }

    @Override
    public void append(AuditRecord record) {
        try {
            byte[] payload = (mapper.writeValueAsString(toNode(record)) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            synchronized (this) {
                channel.write(java.nio.ByteBuffer.wrap(payload));
                channel.force(true);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("审计记录落盘失败: " + file, e);
        }
    }

    @Override
    public void quarantineAndRewrite(List<AuditRecord> intactPrefix) {
        synchronized (this) {
            try {
                channel.close();
                Path quarantined = file.resolveSibling(
                        file.getFileName() + ".corrupt-" + System.currentTimeMillis());
                Files.move(file, quarantined, StandardCopyOption.REPLACE_EXISTING);
                Files.createFile(file);
                this.channel = java.nio.channels.FileChannel.open(file,
                        StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                for (AuditRecord r : intactPrefix) {
                    byte[] payload = (mapper.writeValueAsString(toNode(r)) + "\n")
                            .getBytes(StandardCharsets.UTF_8);
                    channel.write(java.nio.ByteBuffer.wrap(payload));
                }
                channel.force(true);
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
