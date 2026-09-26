package com.github.lisama569.tamperevidentauditpipelinejava.storage;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * 长度分帧 + HMAC 鉴权的帧编解码器。
 *
 * <p>帧格式（大端）：
 * <pre>
 * [4 字节 payload 长度 N][N 字节 payload][32 字节 HMAC(payload)]
 * </pre>
 * payload 为一整条记录的 JSON 字节。长度前缀保证崩溃时只会在帧尾留下
 * 可识别、可截断的半截帧，绝不会让半条记录被当作有效记录读出。
 */
public final class FrameCodec {

    public static final int LENGTH_PREFIX = 4;
    public static final int SIGNATURE_BYTES = 32;

    private final HmacSigner signer;

    public FrameCodec(HmacSigner signer) {
        this.signer = signer;
    }

    /** 把一条 JSON 记录编码为完整帧。 */
    public byte[] encode(String jsonPayload) {
        byte[] payload = jsonPayload.getBytes(StandardCharsets.UTF_8);
        byte[] sig = hmacBytes(payload);
        ByteBuffer buf = ByteBuffer.allocate(LENGTH_PREFIX + payload.length + SIGNATURE_BYTES);
        buf.putInt(payload.length);
        buf.put(payload);
        buf.put(sig);
        return buf.array();
    }

    /** 读取 payload 的原始字节（不含长度前缀与签名）。 */
    public static byte[] payloadOf(byte[] frame, int offset, int length) {
        byte[] out = new byte[length];
        System.arraycopy(frame, offset + LENGTH_PREFIX, out, 0, length);
        return out;
    }

    /** 常数时间校验帧签名，防伪造/篡改。 */
    public boolean verify(byte[] frame, int offset, int payloadLength) {
        byte[] payload = payloadOf(frame, offset, payloadLength);
        byte[] actual = new byte[SIGNATURE_BYTES];
        System.arraycopy(frame, offset + LENGTH_PREFIX + payloadLength, actual, 0, SIGNATURE_BYTES);
        return java.security.MessageDigest.isEqual(hmacBytes(payload), actual);
    }

    private byte[] hmacBytes(byte[] payload) {
        String hex = signer.sign(new String(payload, StandardCharsets.UTF_8));
        return HexFormat.of().parseHex(hex);
    }
}
