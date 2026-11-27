package io.descoped.secrets.api.test;

import io.descoped.secrets.api.crypto.Sha256;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** {@link Sha256} (OpenSSL) against published test vectors and against the JDK. */
class Sha256Test {

    private static final HexFormat HEX = HexFormat.of();

    private static String digest(byte[] message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(Sha256.LENGTH);
            Sha256.digest(arena.allocateFrom(ValueLayout.JAVA_BYTE, message), out);
            return HEX.formatHex(out.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    private static String hmac(byte[] key, byte[] message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(Sha256.LENGTH);
            Sha256.hmac(arena.allocateFrom(ValueLayout.JAVA_BYTE, key),
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, message), out);
            return HEX.formatHex(out.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    /** FIPS 180-4 examples (NIST CSRC). */
    @ParameterizedTest
    @CsvSource({
            "'', e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "abc, ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq, "
                    + "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"})
    void sha256MatchesFips180(String message, String expected) {
        assertEquals(expected, digest(ascii(message)));
    }

    /** RFC 4231 test cases 1 to 4, 6 and 7 (case 5 is a truncated output). */
    @ParameterizedTest
    @CsvSource({
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b, 4869205468657265, "
                    + "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "4a656665, 7768617420646f2079612077616e7420666f72206e6f7468696e673f, "
                    + "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, "
                    + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd, "
                    + "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "0102030405060708090a0b0c0d0e0f10111213141516171819, "
                    + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd, "
                    + "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"})
    void hmacMatchesRfc4231(String key, String message, String expected) {
        assertEquals(expected, hmac(HEX.parseHex(key), HEX.parseHex(message)));
    }

    /** Keys longer than the block size are hashed first (RFC 4231 cases 6 and 7). */
    @Test
    void aKeyLongerThanABlockMatchesRfc4231() {
        byte[] key = new byte[131];
        java.util.Arrays.fill(key, (byte) 0xaa);
        assertEquals("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                hmac(key, ascii("Test Using Larger Than Block-Size Key - Hash Key First")));
        assertEquals("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                hmac(key, ascii("This is a test using a larger than block-size key and a larger than block-size data."
                        + " The key needs to be hashed before being used by the HMAC algorithm.")));
    }

    @Test
    void randomInputsMatchTheJdk() throws GeneralSecurityException {
        Random random = new Random(7);
        for (int i = 0; i < 200; i++) {
            byte[] key = new byte[random.nextInt(1, 200)];
            byte[] message = new byte[random.nextInt(0, 5000)];
            random.nextBytes(key);
            random.nextBytes(message);
            assertEquals(HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(message)), digest(message));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            assertEquals(HEX.formatHex(mac.doFinal(message)), hmac(key, message));
        }
    }

    /** What is not secret may be on the heap; the output may be too. */
    @Test
    void heapSegmentsAreAccepted() {
        byte[] out = new byte[Sha256.LENGTH];
        Sha256.hmac(MemorySegment.ofArray(ascii("key")), MemorySegment.ofArray(ascii("message")),
                MemorySegment.ofArray(out));
        assertEquals(hmac(ascii("key"), ascii("message")), HEX.formatHex(out));
        byte[] digest = new byte[Sha256.LENGTH + 8];
        Sha256.digest(MemorySegment.ofArray(ascii("abc")), MemorySegment.ofArray(digest));
        assertArrayEquals(HEX.parseHex(digest(ascii("abc"))), java.util.Arrays.copyOf(digest, Sha256.LENGTH));
    }

    @Test
    void misuseIsReported() {
        MemorySegment message = MemorySegment.ofArray(ascii("m"));
        MemorySegment small = MemorySegment.ofArray(new byte[Sha256.LENGTH - 1]);
        assertThrows(IllegalArgumentException.class, () -> Sha256.digest(message, small));
        MemorySegment readOnly = MemorySegment.ofArray(new byte[Sha256.LENGTH]).asReadOnly();
        assertThrows(IllegalArgumentException.class, () -> Sha256.hmac(message, message, readOnly));
        MemorySegment out = MemorySegment.ofArray(new byte[Sha256.LENGTH]);
        assertThrows(NullPointerException.class, () -> Sha256.hmac(null, message, out));
        assertThrows(NullPointerException.class, () -> Sha256.digest(message, null));
    }
}
