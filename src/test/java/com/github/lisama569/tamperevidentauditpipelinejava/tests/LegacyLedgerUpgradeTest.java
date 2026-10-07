package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.CompatibilityReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.ByteBuffer;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.zip.CRC32;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 老数据目录（v1：DATA 帧无 eventTime、PURGE 帧无 source/requestId、无 anchor/format）
 * 用新版本打开：全链通过后原地升级，可继续追加/核验，给出明确兼容范围，不报错不静默降级。
 */
class LegacyLedgerUpgradeTest {

    private static final Logger LOG = Logger.getLogger(LegacyLedgerUpgradeTest.class.getName());
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private @TempDir Path dir;

    private byte[] hmac(byte[] key, String input) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
    }

    private String hex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte b : d) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private String encrypt(byte[] dek, String plain) throws Exception {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    private void appendV1Frame(Path ledgerFile, ObjectNode frame) throws Exception {
        byte[] bytes = (MAPPER.writeValueAsString(frame) + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(ledgerFile, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ch.write(ByteBuffer.wrap(bytes));
            ch.force(true);
        }
    }

    /** 用旧版本帧格式造一个含 2 条 DATA + 1 条 v1 PURGE 的账本（没有 keys/format.json）。 */
    private void buildV1Ledger() throws Exception {
        Path keys = dir.resolve("keys");
        Files.createDirectories(keys);
        byte[] hkey = new byte[32];
        RANDOM.nextBytes(hkey);
        Files.write(keys.resolve("hmac.key"), hkey);

        Path ledger = dir.resolve("ledger.log");
        String prev = "";
        long[][] seqs = {{1, 5000L}, {2, 6000L}};
        for (long[] s : seqs) {
            long seq = s[0], stored = s[1];
            byte[] dek = newDek();
            String body = encrypt(dek, "{\"v\":" + seq + "}");
            Files.write(keys.resolve(seq + ".key"), dek);
            long crc = new CRC32() {{
                update(body.getBytes(StandardCharsets.UTF_8));
            }}.getValue();
            // v1 HMAC 串：pos|DATA|seq|key|stored|body|crc|prev （无 eventTime）
            String hash = hex(hmac(hkey, seq + "|DATA|" + seq + "|key-" + seq + "|" + stored + "|"
                    + body + "|" + crc + "|" + prev));
            ObjectNode f = MAPPER.createObjectNode();
            f.put("pos", seq);
            f.put("seq", seq);
            f.put("kind", "DATA");
            f.put("key", "key-" + seq);
            f.put("stored", stored);
            f.put("prev", prev);
            f.put("hash", hash);
            f.put("body", body);
            f.put("crc", crc);
            appendV1Frame(ledger, f);
            prev = hash;
        }
        // v1 PURGE 帧（清除 seq1）：HMAC 串 pos| PURGE|seq|reason|stored|prev，无 source/requestId
        long pos = 3, pstored = 7000L;
        String phash = hex(hmac(hkey, pos + "|PURGE|1|RETENTION|" + pstored + "|" + prev));
        ObjectNode p = MAPPER.createObjectNode();
        p.put("pos", pos);
        p.put("kind", "PURGE");
        p.put("dataSeq", 1L);
        p.put("reason", "RETENTION");
        p.put("stored", pstored);
        p.put("prev", prev);
        p.put("hash", phash);
        appendV1Frame(ledger, p);
        Files.deleteIfExists(keys.resolve("1.key"));
        // 明确不创建 format.json / anchor.json / checkpoints
    }

    private byte[] newDek() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey().getEncoded();
    }

    @Test
    void v1DirectoryUpgradesAndContinuesToWork(TestInfo info) throws Exception {
        buildV1Ledger();
        AppendOnlyLedger l = new AppendOnlyLedger(dir.resolve("ledger.log"));

        // 兼容结论明确
        CompatibilityReport report = l.compatibilityReport();
        assertNotNull(report);
        assertTrue(report.legacy());
        assertEquals("1", report.ledgerVersion());
        assertFalse(report.capabilities().isEmpty());
        assertFalse(report.limitations().isEmpty());

        // 数据可继续读取：seq1 已清（v1 PURGE 兼容标注为 EXPIRY），seq2 明文可解
        assertTrue(l.at(1).orElseThrow().purged());
        assertEquals(com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeSource.EXPIRY,
                l.at(1).orElseThrow().purgeSource());
        assertEquals("{\"v\":2}", l.at(2).orElseThrow().payloadJson());

        // 可继续追加与核验
        l.append("key-3", "{\"v\":3}", 8000L);
        assertTrue(l.verifyFull().healthy());
        // v2 元数据已就位
        assertTrue(Files.exists(dir.resolve("keys/format.json")));
        assertTrue(Files.exists(dir.resolve("keys/anchor.json")));

        // 再重开一次：不再是 legacy，结论稳定（原生 v2 目录无需兼容报告）
        AppendOnlyLedger l2 = new AppendOnlyLedger(dir.resolve("ledger.log"));
        assertFalse(l2.isClosed());
        assertTrue(l2.compatibilityReport() == null || !l2.compatibilityReport().legacy(),
                "升级后第二次打开不再报 legacy");
        assertEquals(4L, l2.nextSequence());
        assertTrue(l2.verifyFull().healthy());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=v1目录(2 DATA+1 v1 PURGE)"
                + " 判定依据=全链按旧HMAC串重放通过后原地升级 报告能力=" + report.capabilities().size()
                + " 条/限制=" + report.limitations().size() + " 条"
                + " 最终状态=seq1按EXPIRY兼容标注, seq2可读, seq3新追加, 两次打开均健康");
    }

    @Test
    void v1DirectoryWithTailDeletionStillDetectedAfterUpgrade(TestInfo info) throws Exception {
        buildV1Ledger();
        // 升级前删掉末尾 v1 PURGE 帧：升级时全链重放会发现链尾对不上（无锚点可追溯升级前整删，
        // 但链内 HMAC/prev 已足以暴露），明确判破坏，不“悄悄升级”
        List<String> ls = Files.readAllLines(dir.resolve("ledger.log"));
        Files.write(dir.resolve("ledger.log"), ls.subList(0, 2));
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(dir.resolve("ledger.log"));
        assertTrue(bad.isClosed());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=v1目录删尾帧后升级打开"
                + " 判定依据=链尾hash不连续 最终状态=拒绝静默升级 closed seq="
                + bad.firstTamperedSequence());
    }
}
