package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * 基于本地 JSONL 文件的审计持久化存储。
 *
 * <p>每条审计记录序列化为一行 JSON 追加到记录文件（append + fsync，返回前已落盘）；
 * 旁路检查点文件记录“记录总数 + 末条 currentHash”。</p>
 *
 * <p>启动 {@link #recover()} 时逐行读回并复核：</p>
 * <ul>
 *   <li>某行无法解析/含未知字段 -> 指出出问题的行号（插入/损坏）；</li>
 *   <li>记录数少于检查点 -> 文件被截断，指出截断位置；</li>
 *   <li>记录数多于检查点 -> 存在未纳入检查点的追加（插入/不一致）；</li>
 *   <li>末条哈希与检查点不符 -> 内容被改过；</li>
 *   <li>随后再由 {@link AuditLog#recoverFromStore()} 重算整条哈希链，
 *       定位序列号、前驱或内容哈希断裂的具体位置。</li>
 * </ul>
 */
public class FileAuditStore implements AuditStore {

    private static final Logger log = LoggerFactory.getLogger(FileAuditStore.class);

    private final Path recordFile;
    private final Path checkpointFile;
    private final ObjectMapper mapper;
    private final Object fileLock = new Object();

    public FileAuditStore(Path recordFile, Path checkpointFile) {
        this.recordFile = recordFile;
        this.checkpointFile = checkpointFile;
        this.mapper = new ObjectMapper()
                // 持久化文件同样不接受夹塞未知字段：本地文件被插入伪造字段必须被发现
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
    }

    @Override
    public void appendRecord(AuditRecord record) {
        synchronized (fileLock) {
            try {
                ensureParent();
                String line = mapper.writeValueAsString(record);
                Files.writeString(recordFile, line + System.lineSeparator(),
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                        StandardOpenOption.APPEND);
                fsync(recordFile);
            } catch (IOException e) {
                throw new AuditPersistenceException("seq=" + record.getSequence(),
                        "审计记录落盘失败", e);
            }
        }
    }

    @Override
    public AuditRecovery recover() {
        synchronized (fileLock) {
            ensureParent();
            if (Files.notExists(recordFile)) {
                if (Files.exists(checkpointFile)) {
                    throw new AuditPersistenceException("record-file",
                            "检查点存在但审计记录文件缺失，记录可能被删除");
                }
                return new AuditRecovery(List.of());
            }

            List<AuditRecord> records = new ArrayList<>();
            long lineNo = 0;
            try (BufferedReader reader = Files.newBufferedReader(recordFile, StandardCharsets.UTF_8)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lineNo++;
                    if (line.isBlank()) {
                        // 非文件结尾的空行属于结构损坏；结尾换行 readLine 不会返回空串
                        throw new AuditPersistenceException("line=" + lineNo,
                                "审计记录文件存在空行，文件可能被截断或插入");
                    }
                    AuditRecord r;
                    try {
                        r = mapper.readValue(line, AuditRecord.class);
                    } catch (Exception e) {
                        throw new AuditPersistenceException("line=" + lineNo,
                                "审计记录无法解析（内容被改过或插入伪造记录）: "
                                        + safeMessage(e), e);
                    }
                    if (r.getSequence() != records.size()) {
                        throw new AuditPersistenceException("line=" + lineNo,
                                "审计序列号不连续，期望 " + records.size()
                                        + " 实际 " + r.getSequence() + "，记录可能被插入或删除");
                    }
                    records.add(r);
                }
            } catch (AuditPersistenceException e) {
                throw e;
            } catch (IOException e) {
                throw new AuditPersistenceException("record-file", "审计记录文件读取失败", e);
            }

            // 检查点交叉复核（首启时无检查点，跳过）
            if (Files.exists(checkpointFile)) {
                Checkpoint cp = readCheckpoint();
                if (cp.recordCount != records.size()) {
                    String where = cp.recordCount > records.size()
                            ? "after-seq=" + (records.isEmpty() ? 0 : records.size() - 1)
                            : "line=" + (records.size() + 1);
                    throw new AuditPersistenceException(where,
                            "审计记录数与检查点不一致：检查点记录 " + cp.recordCount
                                    + " 条，实际 " + records.size()
                                    + " 条，文件可能被截断或插入");
                }
                String actualLast = records.isEmpty()
                        ? AuditHasher.GENESIS_HASH
                        : records.get(records.size() - 1).getCurrentHash();
                if (!cp.lastHash.equals(actualLast)) {
                    throw new AuditPersistenceException("seq=" + (records.size() - 1),
                            "末条记录哈希与检查点不符，记录内容被篡改");
                }
            } else if (!records.isEmpty()) {
                log.info("未发现审计检查点，仅有 {} 条历史记录，按记录链直接恢复", records.size());
            }
            return new AuditRecovery(records);
        }
    }

    @Override
    public void checkpoint(int recordCount, String lastHash) {
        synchronized (fileLock) {
            try {
                ensureParent();
                Checkpoint cp = new Checkpoint(recordCount, lastHash);
                Files.writeString(checkpointFile, mapper.writeValueAsString(cp),
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING);
                fsync(checkpointFile);
            } catch (IOException e) {
                throw new AuditPersistenceException("checkpoint", "审计检查点落盘失败", e);
            }
        }
    }

    private Checkpoint readCheckpoint() {
        try {
            String json = Files.readString(checkpointFile, StandardCharsets.UTF_8);
            if (json.isBlank()) {
                throw new AuditPersistenceException("checkpoint",
                        "审计检查点为空，文件可能被截断");
            }
            Checkpoint cp = mapper.readValue(json, Checkpoint.class);
            if (cp.recordCount < 0 || cp.lastHash == null || cp.lastHash.isBlank()) {
                throw new AuditPersistenceException("checkpoint",
                        "审计检查点内容不合法，文件可能被改过");
            }
            return cp;
        } catch (AuditPersistenceException e) {
            throw e;
        } catch (Exception e) {
            throw new AuditPersistenceException("checkpoint",
                    "审计检查点无法解析，文件可能被改过: " + safeMessage(e), e);
        }
    }

    private void ensureParent() {
        try {
            Path parent = recordFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void fsync(Path path) throws IOException {
        // RandomAccessFile 强制把该文件的数据刷到磁盘，降低宕机丢记录概率
        try (RandomAccessFile raf = new RandomAccessFile(path.toFile(), "rw")) {
            raf.getFD().sync();
        }
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        return m == null ? "格式错误" : m;
    }

    /** 检查点载荷 */
    public static final class Checkpoint {
        public int recordCount;
        public String lastHash;

        public Checkpoint() {
        }

        public Checkpoint(int recordCount, String lastHash) {
            this.recordCount = recordCount;
            this.lastHash = lastHash;
        }
    }
}
