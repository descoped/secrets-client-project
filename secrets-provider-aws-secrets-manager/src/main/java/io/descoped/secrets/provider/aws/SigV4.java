package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.crypto.Sha256;
import io.descoped.secrets.api.http.Codec;
import io.descoped.secrets.api.http.Http;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * AWS Signature Version 4 for a JSON 1.1 {@code POST /} request, on guarded memory. What is secret never leaves it:
 *
 * <ul>
 *     <li>the signing key is derived from the secret access key ({@code AWS4} + key, then the date, the region, the
 *     service and {@code aws4_request}) by HMAC-SHA256 in guarded memory, a new derivation per request;</li>
 *     <li>the canonical request includes the session token (it is a signed header), so it is built and hashed in
 *     guarded memory;</li>
 *     <li>the body, which may carry a secret value, is hashed in place.</li>
 * </ul>
 *
 * <p>The results are not secret: the hashes, the string to sign and the signature. The session token is sent as a
 * {@link Http.SecretHeader}.
 */
final class SigV4 {

    static final String ALGORITHM = "AWS4-HMAC-SHA256";
    static final String CONTENT_TYPE = "application/x-amz-json-1.1";

    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] AWS4 = "AWS4".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TOKEN_HEADER = "x-amz-security-token:".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LF = {'\n'};

    private final SecretMemory memory;
    private final String region;
    private final String service;

    SigV4(SecretMemory memory, String region, String service) {
        this.memory = memory;
        this.region = region;
        this.service = service;
    }

    /**
     * The headers of a signed request.
     *
     * @param headers      header lines that are not secret, {@code Authorization} included
     * @param sessionToken the session token to send as {@code X-Amz-Security-Token}, or {@code null}
     */
    record Signed(List<String> headers, Secret sessionToken) {

        /** Builds the request in guarded memory, the session token written from inside its own callback. */
        Secret request(SecretMemory memory, Http.Target target, MemorySegment body) {
            if (sessionToken == null) {
                return Http.request(memory, target, "POST", "/", headers, List.of(), body);
            }
            return sessionToken.withSegment(token -> Http.request(memory, target, "POST", "/", headers,
                    List.of(new Http.SecretHeader("X-Amz-Security-Token", "", token)), body));
        }
    }

    /**
     * Signs {@code POST /} to {@code host} with {@code X-Amz-Target: target} and {@code body}. The returned session
     * token is {@code credentials}' own: build the request before they are released.
     *
     * @param credentials the credentials
     * @param host        the {@code Host} header's value
     * @param target      the operation, such as {@code secretsmanager.GetSecretValue}
     * @param body        the body, in guarded memory
     * @param now         the signing time
     * @return the headers to send
     */
    Signed sign(Credentials credentials, String host, String target, MemorySegment body, Instant now) {
        String timestamp = TIMESTAMP.format(now);
        String date = timestamp.substring(0, 8);
        String scope = date + "/" + region + "/" + service + "/aws4_request";
        Secret token = credentials.sessionToken();
        String signedHeaders = "content-type;host;x-amz-date;" + (token == null ? "" : "x-amz-security-token;")
                + "x-amz-target";
        String canonicalHash = canonicalRequestHash(host, target, timestamp, token, signedHeaders, body);
        String stringToSign = ALGORITHM + "\n" + timestamp + "\n" + scope + "\n" + canonicalHash;
        String signature = signature(credentials.secretAccessKey(), date, stringToSign);
        List<String> headers = new ArrayList<>(List.of(
                "Content-Type: " + CONTENT_TYPE,
                "X-Amz-Date: " + timestamp,
                "X-Amz-Target: " + target,
                "Authorization: " + ALGORITHM + " Credential=" + credentials.accessKeyId() + "/" + scope
                        + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature));
        return new Signed(List.copyOf(headers), token);
    }

    /** The hex SHA-256 of the canonical request, which is built in guarded memory around the session token. */
    private String canonicalRequestHash(String host, String target, String timestamp, Secret token,
                                        String signedHeaders, MemorySegment body) {
        byte[] head = ("POST\n/\n\ncontent-type:" + CONTENT_TYPE + "\nhost:" + host + "\nx-amz-date:" + timestamp
                + "\n").getBytes(StandardCharsets.US_ASCII);
        byte[] tail = ("x-amz-target:" + target + "\n\n" + signedHeaders + "\n" + hex(digest(body)))
                .getBytes(StandardCharsets.US_ASCII);
        if (token == null) {
            byte[] canonical = new byte[head.length + tail.length];
            System.arraycopy(head, 0, canonical, 0, head.length);
            System.arraycopy(tail, 0, canonical, head.length, tail.length);
            return hex(digest(MemorySegment.ofArray(canonical)));
        }
        return token.withSegment(t -> {
            long length = head.length + TOKEN_HEADER.length + t.byteSize() + LF.length + tail.length;
            try (Secret canonical = memory.allocate(length, out -> {
                long pos = Codec.putBytes(out, 0, head);
                pos = Codec.putBytes(out, pos, TOKEN_HEADER);
                pos = Codec.putSegment(out, pos, t);
                pos = Codec.putBytes(out, pos, LF);
                Codec.putBytes(out, pos, tail);
            })) {
                return hex(canonical.withSegment(SigV4::digest));
            }
        });
    }

    /** {@code HMAC(kSigning, stringToSign)}, with the signing key derived in guarded memory. */
    private String signature(Secret secretAccessKey, String date, String stringToSign) {
        byte[] signature = new byte[Sha256.LENGTH];
        secretAccessKey.withSegment(key -> {
            // kSecret ("AWS4" + key), then two 32-byte keys that each HMAC step alternates between.
            long length = AWS4.length + key.byteSize() + 2L * Sha256.LENGTH;
            try (Secret scratch = memory.allocate(length, work -> {
                long secretLength = AWS4.length + key.byteSize();
                MemorySegment kSecret = work.asSlice(0, secretLength);
                MemorySegment a = work.asSlice(secretLength, Sha256.LENGTH);
                MemorySegment b = work.asSlice(secretLength + Sha256.LENGTH, Sha256.LENGTH);
                Codec.putSegment(kSecret, Codec.putBytes(kSecret, 0, AWS4), key);
                Sha256.hmac(kSecret, ascii(date), a);
                Sha256.hmac(a, ascii(region), b);
                Sha256.hmac(b, ascii(service), a);
                Sha256.hmac(a, ascii("aws4_request"), b);
                Sha256.hmac(b, ascii(stringToSign), MemorySegment.ofArray(signature));
            })) {
                return scratch.length();
            }
        });
        return hex(signature);
    }

    private static MemorySegment ascii(String text) {
        return MemorySegment.ofArray(text.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] digest(MemorySegment message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(Sha256.LENGTH);
            Sha256.digest(message, out);
            return out.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    private static String hex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }
}
