package com.github.lisama569.tamperevidentauditpipelinejava.domain;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * HMAC-SHA256 鉴权工具。
 *
 * <p>两条用途：
 * <ol>
 *   <li>{@link #chainHash} —— 记录内容的哈希链链接（SHA-256，前链 + 规范载荷）；</li>
 *   <li>{@link #sign}/{@link #verify} —— 对帧和清单做 HMAC 鉴权，
 *       使“有写权限的篡改”同样可被检测。</li>
 * </ol>
 */
public final class HmacSigner {

    /** 创世记录的前驱哈希（全 0），保证链有确定起点。 */
    public static final String GENESIS_PREV = "0".repeat(64);

    private final byte[] secret;

    public HmacSigner(String secret) {
        this.secret = (secret == null || secret.isBlank()
                ? "local-dev-hmac-secret-change-me" : secret).getBytes(StandardCharsets.UTF_8);
    }

    /** 计算链接哈希：sha256(prevHash || canonicalPayload)，返回小写十六进制。 */
    public String chainHash(String prevHash, String canonicalPayload) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(prevHash.getBytes(StandardCharsets.UTF_8));
            md.update((byte) '\n');
            md.update(canonicalPayload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** 对任意文本计算 HMAC-SHA256，返回小写十六进制。 */
    public String sign(String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(content.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /** 常数时间校验 HMAC。 */
    public boolean verify(String content, String signature) {
        if (signature == null || signature.isEmpty()) {
            return false;
        }
        return MessageDigest.isEqual(
                sign(content).getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8));
    }
}
