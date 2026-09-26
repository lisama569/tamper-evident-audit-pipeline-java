package com.github.lisama569.tamperevidentauditpipelinejava.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.CanonicalJson;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

/**
 * 清除操作凭证日志（只追加、带 HMAC、整体重写但永不删除历史条目）。
 *
 * <p>它回答“记录为什么不存在”：每条凭证记录清除依据、被阻止的法律保留项、
 * 压实前后链端哈希；任何对凭证本身的篡改都会在启动校验时被发现。
 */
@Component
public class CompactionJournal {

    private record Snapshot(List<CompactionEntry> entries, String signature) {
    }

    private final Path file;
    private final Path tmp;
    private final ObjectMapper mapper;
    private final HmacSigner signer;
    private final List<CompactionEntry> entries = new ArrayList<>();

    public CompactionJournal(Path storageDir, ObjectMapper mapper, HmacSigner signer) {
        this.file = storageDir.resolve("compaction-journal.json");
        this.tmp = storageDir.resolve("compaction-journal.json.tmp");
        this.mapper = mapper;
        this.signer = signer;
    }

    public void initialize() throws IOException {
        Files.createDirectories(file.getParent());
        if (!Files.exists(file)) {
            persist();
            return;
        }
        Snapshot snap = mapper.readValue(Files.readString(file), Snapshot.class);
        if (snap.entries() != null) {
            for (CompactionEntry e : snap.entries()) {
                if (!signer.verify(canonical(e), e.signature())) {
                    throw new IllegalStateException("压实凭证签名无效：凭证 " + e.id() + " 可能被篡改");
                }
                entries.add(e);
            }
        }
    }

    /** 追加一条已签名的清除凭证（signature 字段可先为空，由本方法补签）。 */
    public synchronized CompactionEntry append(CompactionEntry unsigned) {
        String sig = signer.sign(canonical(unsigned));
        CompactionEntry signed = new CompactionEntry(
                unsigned.id(), unsigned.at(), unsigned.mode(), unsigned.reason(),
                unsigned.requestedBy(), unsigned.removedSeqs(), unsigned.blockedSeqs(),
                unsigned.prevLastSeq(), unsigned.prevLastHash(),
                unsigned.newLastSeq(), unsigned.newLastHash(), sig);
        entries.add(signed);
        persist();
        return signed;
    }

    public synchronized List<CompactionEntry> entries() {
        return List.copyOf(entries);
    }

    private String canonical(CompactionEntry e) {
        TreeMap<String, Object> m = new TreeMap<>();
        m.put("id", e.id());
        m.put("at", e.at());
        m.put("mode", e.mode());
        m.put("reason", e.reason());
        m.put("requestedBy", e.requestedBy());
        m.put("removedSeqs", e.removedSeqs());
        m.put("blockedSeqs", e.blockedSeqs());
        m.put("prevLastSeq", e.prevLastSeq());
        m.put("prevLastHash", e.prevLastHash());
        m.put("newLastSeq", e.newLastSeq());
        m.put("newLastHash", e.newLastHash());
        return CanonicalJson.write(m);
    }

    private void persist() {
        try {
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(new Snapshot(entries, ""));
            // signature 字段在 Snapshot 中留空：逐条目签名已覆盖；这里不做整文件签名
            Files.write(tmp, json.getBytes(StandardCharsets.UTF_8));
            try (FileChannel ch = FileChannel.open(tmp, java.nio.file.StandardOpenOption.WRITE)) {
                ch.force(true);
            }
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("压实凭证持久化失败", e);
        }
    }
}
