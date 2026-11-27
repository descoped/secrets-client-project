package io.descoped.secrets.provider.aws.test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Signature Version 4 with the JDK, written from AWS's description, for checking the provider's signatures in
 * {@link FakeAws}. Test code only: it holds keys on the heap. Its own correctness is shown against AWS's examples in
 * {@link SigV4ReferenceTest}.
 */
final class SigV4Reference {

    private static final HexFormat HEX = HexFormat.of();

    private SigV4Reference() {
    }

    static String sha256Hex(byte[] data) {
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] signingKey(String secretAccessKey, String date, String region, String service) {
        byte[] key = hmac(("AWS4" + secretAccessKey).getBytes(StandardCharsets.UTF_8), date);
        key = hmac(key, region);
        key = hmac(key, service);
        return hmac(key, "aws4_request");
    }

    /**
     * The canonical request for a request with an empty query string.
     *
     * @param headers the signed headers, by lower-case name
     */
    static String canonicalRequest(String method, String path, Map<String, String> headers, byte[] body) {
        SortedMap<String, String> sorted = new TreeMap<>(headers);
        String canonicalHeaders = sorted.entrySet().stream()
                .map(e -> e.getKey() + ":" + e.getValue().strip().replaceAll(" +", " ") + "\n")
                .collect(Collectors.joining());
        return method + "\n" + path + "\n\n" + canonicalHeaders + "\n" + String.join(";", sorted.keySet()) + "\n"
                + sha256Hex(body);
    }

    static String signature(String secretAccessKey, String timestamp, String region, String service,
                            String canonicalRequest) {
        String date = timestamp.substring(0, 8);
        String stringToSign = "AWS4-HMAC-SHA256\n" + timestamp + "\n" + date + "/" + region + "/" + service
                + "/aws4_request\n" + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        return HEX.formatHex(hmac(signingKey(secretAccessKey, date, region, service), stringToSign));
    }
}
