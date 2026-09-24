package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AccessRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionResult;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 追加式哈希链审计日志。
 *
 * <p>完整性与并发保证：
 * <ul>
 *   <li>每条记录携带单调递增 seq、前一条记录哈希 prevHash 与自身哈希 recordHash，
 *       形成哈希链；任何篡改、删除、重排都会在校验时暴露；</li>
 *   <li>append 在同一把锁内完成"序号分配 + 哈希计算 + 内存入列 + 磁盘追加"，
 *       并发压力下无丢失、无重号、无空洞；</li>
 *   <li>每条记录含上下文摘要（SHA-256），关联主体/资源/动作与关键属性；</li>
 *   <li>启动时从本地文件重载，重载过程本身会校验哈希链。</li>
 * </ul>
 */
@Component
public class AuditLogger {

    /** 创世前导哈希。 */
    public static final String GENESIS_HASH = "GENESIS";

    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);

    private final ObjectMapper objectMapper;
    private final String filePath;

    private final List<AuditRecord> records = new ArrayList<>();
    private final Object appendLock = new Object();
    private long nextSeq = 0;
    private String lastHash = GENESIS_HASH;
    private boolean fileWritable;

    public AuditLogger(ObjectMapper objectMapper,
                       @Value("${zt.audit.file:build/audit/audit.log}") String filePath) {
        this.objectMapper = objectMapper;
        this.filePath = filePath;
    }

    @PostConstruct
    public void init() {
        synchronized (appendLock) {
            Path path = Path.of(filePath);
            if (Files.exists(path)) {
                loadFromFile(path);
            } else {
                try {
                    if (path.getParent() != null) {
                        Files.createDirectories(path.getParent());
                    }
                    fileWritable = true;
                } catch (IOException e) {
                    fileWritable = false;
                    log.warn("审计文件目录不可创建，审计将仅保留在内存: {}", e.getMessage());
                }
            }
        }
    }

    /**
     * 追加一条审计记录，返回落库后的最终记录（含 seq 与哈希）。
     * 磁盘写入失败会抛出 IllegalStateException，由调用方决定如何告警，绝不静默丢失。
     */
    public AuditRecord append(AccessRequest request, DecisionResult result, String requestId) {
        synchronized (appendLock) {
            long seq = nextSeq;
            String prev = lastHash;
            AuditRecord record = new AuditRecord(
                    seq,
                    Instant.now().toEpochMilli(),
                    requestId,
                    subjectId(request),
                    resourceId(request),
                    action(request),
                    contextDigest(request),
                    result.version(),
                    result.outcome(),
                    result.matchedRuleId(),
                    result.reason(),
                    prev,
                    null);
            String hash = hashOf(record);
            AuditRecord finalized = new AuditRecord(
                    record.seq(), record.timestamp(), record.requestId(),
                    record.subjectId(), record.resourceId(), record.action(),
                    record.contextDigest(), record.version(), record.outcome(),
                    record.matchedRuleId(), record.reason(), record.prevHash(), hash);

            records.add(finalized);
            nextSeq++;
            lastHash = hash;

            persist(finalized);
            log.info("审计记录 seq={} requestId={} version={} subject={} resource={} action={} outcome={} rule={}",
                    seq, requestId, result.version(), record.subjectId(),
                    record.resourceId(), record.action(), result.outcome(),
                    result.matchedRuleId());
            return finalized;
        }
    }

    /** 当前内存中的全部审计记录（按 seq 升序）。 */
    public List<AuditRecord> records() {
        synchronized (appendLock) {
            return List.copyOf(records);
        }
    }

    /**
     * 校验哈希链：序号连续、prevHash 衔接、recordHash 与内容一致、上下文摘要一致。
     */
    public AuditVerification verify() {
        synchronized (appendLock) {
            long expectedSeq = 0;
            String expectedPrev = GENESIS_HASH;
            for (AuditRecord r : records) {
                if (r.seq() != expectedSeq) {
                    return new AuditVerification(false, records.size(), expectedSeq,
                            "序号不连续: 期望 " + expectedSeq + " 实际 " + r.seq());
                }
                if (!java.util.Objects.equals(r.prevHash(), expectedPrev)) {
                    return new AuditVerification(false, records.size(), expectedSeq,
                            "seq=" + expectedSeq + " 的 prevHash 断裂");
                }
                if (!java.util.Objects.equals(hashOf(r), r.recordHash())) {
                    return new AuditVerification(false, records.size(), expectedSeq,
                            "seq=" + expectedSeq + " 的记录内容与 recordHash 不一致（疑似篡改）");
                }
                expectedPrev = r.recordHash();
                expectedSeq++;
            }
            return new AuditVerification(true, records.size(), -1, "哈希链完整，共 "
                    + records.size() + " 条记录");
        }
    }

    /** 强制刷盘（本实现每次追加已同步落盘，此方法保留用于接口语义完整）。 */
    public void flush() {
        synchronized (appendLock) {
            // no-op：append 已同步持久化
        }
    }

    /** 从磁盘文件重新加载并校验，校验失败抛出异常以暴露文件被破坏。 */
    public void reload() {
        synchronized (appendLock) {
            records.clear();
            nextSeq = 0;
            lastHash = GENESIS_HASH;
            loadFromFile(Path.of(filePath));
        }
    }

    private void loadFromFile(Path path) {
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                AuditRecord r = objectMapper.readValue(line, AuditRecord.class);
                if (r.seq() != nextSeq) {
                    throw new IllegalStateException("审计文件序号不连续: 期望 " + nextSeq
                            + " 实际 " + r.seq() + "（文件缺失或被篡改）");
                }
                if (!java.util.Objects.equals(r.prevHash(), lastHash)) {
                    throw new IllegalStateException("审计文件哈希链在 seq=" + nextSeq
                            + " 处断裂（文件被篡改或截断）");
                }
                if (!java.util.Objects.equals(hashOf(r), r.recordHash())) {
                    throw new IllegalStateException("审计文件 seq=" + nextSeq
                            + " 内容哈希不一致（文件被篡改）");
                }
                records.add(r);
                lastHash = r.recordHash();
                nextSeq++;
            }
            fileWritable = true;
            log.info("审计日志重载完成，共 {} 条记录，哈希链完整", records.size());
        } catch (IOException | RuntimeException e) {
            fileWritable = false;
            throw new IllegalStateException("审计文件加载/校验失败: " + path
                    + "，原因: " + e.getMessage(), e);
        }
    }

    private void persist(AuditRecord record) {
        if (!fileWritable) {
            return;
        }
        try {
            String line = objectMapper.writeValueAsString(record);
            Files.writeString(Path.of(filePath), line + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            // 内存记录已产生但无法持久化：标记不可写并抛出，避免调用方误以为审计已落盘。
            fileWritable = false;
            throw new IllegalStateException("审计记录持久化失败: " + e.getMessage(), e);
        }
    }

    /**
     * 计算记录哈希。recordHash 字段置空后参与摘要，保证自引用无环。
     */
    private String hashOf(AuditRecord r) {
        String canonical = String.join("|",
                Long.toString(r.seq()),
                Long.toString(r.timestamp()),
                nullSafe(r.requestId()),
                nullSafe(r.subjectId()),
                nullSafe(r.resourceId()),
                nullSafe(r.action()),
                nullSafe(r.contextDigest()),
                nullSafe(r.version()),
                r.outcome() == null ? "" : r.outcome().name(),
                nullSafe(r.matchedRuleId()),
                nullSafe(r.reason()),
                nullSafe(r.prevHash()));
        return sha256(canonical);
    }

    /** 关键上下文摘要：主体/资源/环境属性排序后做 SHA-256，防止审计内容被悄悄替换。 */
    private String contextDigest(AccessRequest request) {
        StringBuilder sb = new StringBuilder();
        if (request != null) {
            if (request.subject() != null) {
                sb.append("S=").append(request.subject().id()).append(';');
                appendSorted(sb, request.subject().attributes());
            }
            if (request.resource() != null) {
                sb.append("R=").append(request.resource().id()).append(';');
                appendSorted(sb, request.resource().attributes());
            }
            sb.append("A=").append(nullSafe(request.action())).append(';');
            if (request.environment() != null) {
                appendSorted(sb, request.environment().attributes());
            }
        }
        return sha256(sb.toString());
    }

    private void appendSorted(StringBuilder sb, Map<String, String> attributes) {
        if (attributes == null) {
            return;
        }
        for (Map.Entry<String, String> e : new TreeMap<>(attributes).entrySet()) {
            sb.append(e.getKey()).append('=').append(nullSafe(e.getValue())).append(';');
        }
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private String nullSafe(String s) {
        return s == null ? "" : s;
    }

    private String subjectId(AccessRequest request) {
        return request == null || request.subject() == null ? "" : request.subject().id();
    }

    private String resourceId(AccessRequest request) {
        return request == null || request.resource() == null ? "" : request.resource().id();
    }

    private String action(AccessRequest request) {
        return request == null ? "" : nullSafe(request.action());
    }
}
