package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.VerifyResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.zip.CRC32;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 上一轮版本（v1）写过数据的老目录，用新版本打开：
 * 不被误判为损坏、可继续追加与核验、兼容边界可解释；旧格式 PURGE 帧仍能验证。
 */
class LegacyLedgerUpgradeTest {

    private static final Logger LOG = Logger.getLogger(LegacyLedgerUpgradeTest.class.getName());
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private @TempDir Path dir;

    private Path ledgerFile() {
        return dir.resolve("ledger.log");
    }

    /** 用 v1 格式手工写 N 条 DATA（无 CHECKPOINT、无锚点）。 */
    private void writeLegacyData(int n, byte[] hmacKey) throws Exception {
        Path keys = dir.resolve("keys");
        Files.createDirectories(keys);
        Files.write(keys.resolve("hmac.key"), hmacKey);
        String prev = "";
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i <= n; i++) {
            byte[] dek = newDek();
            String body = encrypt(dek, ("{\"v\":" + i + "}").getBytes(StandardCharsets.UTF_8));
            Files.write(keys.resolve(i + ".key"), dek);
            long crc = crc32(body.getBytes(StandardCharsets.UTF_8));
            long pos = i;
            String hash = hmac(hmacKey, pos + "|DATA|" + i + "|legacy-key-" + i + "|" + (1000L + i)
                    + "|" + (1000L + i) + "|" + body + "|" + crc + "|" + prev);
            ObjectNode f = MAPPER.createObjectNode();
            f.put("pos", pos);
            f.put("seq", i);
            f.put("kind", "DATA");
            f.put("key", "legacy-key-" + i);
            f.put("stored", 1000L + i);
            f.put("eventTime", 1000L + i);
            f.put("prev", prev);
            f.put("hash", hash);
            f.put("body", body);
            f.put("crc", crc);
            sb.append(f).append('\n');
            prev = hash;
        }
        Files.write(ledgerFile(), sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** 再用 v1 格式追加一条 PURGE（旧公式：pos|PURGE|seq|RETENTION|stored|prev，无 source/requestId）。 */
    private void writeLegacyPurge(long dataSeq, long pos, long stored, String prevHash, byte[] hmacKey) throws Exception {
        String hash = hmac(hmacKey, pos + "|PURGE|" + dataSeq + "|RETENTION|" + stored + "|" + prevHash);
        ObjectNode f = MAPPER.createObjectNode();
        f.put("pos", pos);
        f.put("kind", "PURGE");
        f.put("dataSeq", dataSeq);
        f.put("reason", "RETENTION");
        f.put("stored", stored);
        f.put("prev", prevHash);
        f.put("hash", hash);
        java.nio.file.Files.write(ledgerFile(),
                (MAPPER.writeValueAsString(f) + "\n").getBytes(StandardCharsets.UTF_8),
                java.nio.file.StandardOpenOption.APPEND);
        Files.deleteIfExists(dir.resolve("keys").resolve(dataSeq + ".key"));
    }

    @Test
    void legacyDirectoryUpgradesAndContinuesToWork(TestInfo info) throws Exception {
        byte[] hmacKey = new byte[32];
        RANDOM.nextBytes(hmacKey);
        writeLegacyData(5, hmacKey);

        // 新版本打开：不抛异常、可继续追加、可核验
        AppendOnlyLedger ledger = new AppendOnlyLedger(ledgerFile());
        assertTrue(ledger.legacyMode(), "老目录应被识别为兼容升级模式");
        assertEquals(5L, ledger.legacyBoundaryDataSeq(), "兼容边界=升级时已有的数据序号5");
        assertEquals(-1L, ledger.verify(), "老数据不得因新增核验信息被当成损坏");
        assertEquals("{\"v\":3}", ledger.at(3).orElseThrow().payloadJson(), "老记录明文可懒解密");

        StoredEvent next = ledger.append("new-key-6", "{\"v\":6}", 2000L);
        assertEquals(6L, next.sequence());
        assertEquals(-1L, ledger.verify());

        // 重启：升级结论与后续追加依然成立
        AppendOnlyLedger reopened = new AppendOnlyLedger(ledgerFile());
        assertTrue(reopened.legacyMode());
        assertEquals(5L, reopened.legacyBoundaryDataSeq());
        assertEquals(7L, reopened.append("new-key-7", "{\"v\":7}", 2001L).sequence());
        assertEquals(-1L, reopened.verify());
        assertTrue(Files.exists(dir.resolve("ledger.log.anchor")), "升级后锚点文件应存在");

        LOG.info(() -> "[CASE " + info.getDisplayName()
                + "] 输入=v1目录5条 判定依据=legacyMode=true boundary=5 升级后追加6/7且verify=-1"
                + " 最终状态=老目录平滑升级、继续追加与核验正常");
    }

    @Test
    void legacyPurgeFrameStillVerifiesAndMarksErased(TestInfo info) throws Exception {
        byte[] hmacKey = new byte[32];
        RANDOM.nextBytes(hmacKey);
        writeLegacyData(3, hmacKey);
        // 取第3条 hash 作为 prev（v1 PURGE 占 pos=4）
        String lastHash;
        try (java.util.stream.Stream<String> st = Files.lines(ledgerFile())) {
            String last = st.reduce((a, b) -> b).orElseThrow();
            lastHash = MAPPER.readTree(last).path("hash").asText();
        }
        writeLegacyPurge(2L, 4L, 5000L, lastHash, hmacKey);

        AppendOnlyLedger ledger = new AppendOnlyLedger(ledgerFile());
        assertEquals(-1L, ledger.verify(), "旧格式 PURGE 帧必须按旧公式兼容校验");
        assertTrue(ledger.at(2).orElseThrow().purged());
        assertNull(ledger.at(2).orElseThrow().payloadJson());
        assertEquals("RETENTION", ledger.purgeMark(2L).orElseThrow().source());
        LOG.info(() -> "[CASE " + info.getDisplayName()
                + "] 输入=v1 DATA3条+v1 PURGE(seq2) 判定依据=旧HMAC公式兼容 verify=-1 最终状态=清除状态与来源正确");
    }

    @Test
    void emptyLegacyDirectoryGetsFullV2Capability(TestInfo info) throws Exception {
        // 空目录：不存在老数据，首次打开直接具备 v2 能力，不算 legacy
        Files.createDirectories(dir);
        AppendOnlyLedger ledger = new AppendOnlyLedger(ledgerFile());
        assertFalse(ledger.legacyMode());
        assertEquals(0L, ledger.legacyBoundaryDataSeq());
        assertTrue(Files.exists(dir.resolve("ledger.log.anchor")));
        ledger.append("k1", "{}", 1L);
        // 空账本创建后删末尾记录必须可检出（v2 能力自始具备）
        java.util.List<String> ls = Files.readAllLines(ledgerFile());
        Files.write(ledgerFile(), new byte[0]);
        assertThrows(com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException.class,
                () -> new AppendOnlyLedger(ledgerFile()));
        LOG.info(() -> "[CASE " + info.getDisplayName()
                + "] 输入=空目录新建账本再清空 判定依据=非legacy且锚点对账发现空缺 最终状态=新目录全能力");
    }

    private static byte[] newDek() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey().getEncoded();
    }

    private static String encrypt(byte[] dek, byte[] plain) throws Exception {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plain);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    private static long crc32(byte[] b) {
        CRC32 c = new CRC32();
        c.update(b);
        return c.getValue();
    }

    private static String hmac(byte[] key, String in) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] d = m.doFinal(in.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
