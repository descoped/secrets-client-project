package io.descoped.secrets.test.support;

import com.sun.management.HotSpotDiagnosticMXBean;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.zip.CRC32C;

/**
 * The child JVM's side of {@link HeapCanary}. A subject's {@code main} gets the canary file as {@code args[0]} and the
 * dump file as {@code args[1]}; it reads the canary only through the code under test, reports a checksum of what it
 * read with {@link #checksum(MemorySegment)}, and ends with {@link #dump(Path)}.
 *
 * <p>Neither method copies the value to the heap: the checksum is computed over a direct buffer, which {@link CRC32C}
 * reads in place.
 */
public final class HeapDump {

    /** The line that reports the checksum, followed by eight hex digits. */
    static final String CHECKSUM = "CHECKSUM ";
    /** The line that reports a finished dump. */
    static final String DUMPED = "DUMPED";

    private HeapDump() {
    }

    /**
     * Prints the CRC32C of {@code value}, so that {@link HeapCanary} knows the subject really read the canary. The
     * value is read in place.
     *
     * @param value the value the subject read, native memory
     */
    public static void checksum(MemorySegment value) {
        if (!value.isNative()) {
            throw new IllegalArgumentException("Not native memory: the checksum must not read from the heap");
        }
        CRC32C crc = new CRC32C();
        crc.update(value.asByteBuffer());
        print(crc.getValue());
    }

    /**
     * Prints the CRC32C of {@code value}, a direct buffer, read in place from its position to its limit.
     *
     * @param value the value the subject read
     */
    public static void checksum(ByteBuffer value) {
        if (!value.isDirect()) {
            throw new IllegalArgumentException("Not a direct buffer: the checksum must not read from the heap");
        }
        CRC32C crc = new CRC32C();
        crc.update(value.duplicate());
        print(crc.getValue());
    }

    /** Standard output is how the subject reports to {@link HeapCanary}, which reads it. */
    @SuppressWarnings("java:S106")
    private static void print(long crc) {
        System.out.println(CHECKSUM + HexFormat.of().toHexDigits((int) crc));
    }

    /**
     * Dumps the whole heap to {@code file}, unreachable objects included: a stray copy is garbage, and a collection
     * may not have run yet. Then prints {@value #DUMPED}.
     *
     * @param file the dump file, which must not exist
     * @throws IOException if the dump cannot be written
     */
    @SuppressWarnings("java:S106")
    public static void dump(Path file) throws IOException {
        HotSpotDiagnosticMXBean bean = ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class);
        bean.dumpHeap(file.toString(), false);
        System.out.println(DUMPED);
    }
}
