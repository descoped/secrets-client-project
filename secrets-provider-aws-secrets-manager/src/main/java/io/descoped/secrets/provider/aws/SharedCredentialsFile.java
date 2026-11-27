package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Static keys from the AWS shared credentials file ({@code ~/.aws/credentials}, INI): {@code aws_access_key_id},
 * {@code aws_secret_access_key} and, for temporary keys, {@code aws_session_token}, in the section named after the
 * profile. The file is read into guarded memory and parsed there: section and key names are compared in place, and
 * the secret values are copied from the file's memory straight into their own guarded memory. Only the access key
 * ID becomes a {@code String}. For development: on AWS, a role is the better source.
 */
final class SharedCredentialsFile implements CredentialsProvider.Source {

    /** Larger than any credentials file. */
    static final long MAX_LENGTH = 1024L * 1024;

    private static final byte[] ACCESS_KEY_ID = ascii("aws_access_key_id");
    private static final byte[] SECRET_ACCESS_KEY = ascii("aws_secret_access_key");
    private static final byte[] SESSION_TOKEN = ascii("aws_session_token");

    private final SecretMemory memory;
    private final Path file;
    private final String profile;
    private final byte[] section;

    SharedCredentialsFile(SecretMemory memory, Path file, String profile) {
        this.memory = memory;
        this.file = file;
        this.profile = profile;
        this.section = ascii(profile);
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public Credentials fetch() {
        try (FileChannel channel = FileChannel.open(file); Secret content = memory.read(channel, MAX_LENGTH)) {
            return content.withSegment(this::parse);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read the AWS credentials file " + file + ": "
                    + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * Finds the profile's section and the spans of its three values ({start, end}, or {-1, -1} when absent), and
     * copies the secret ones into their own guarded memory.
     */
    private Credentials parse(MemorySegment text) {
        long[] id = {-1, -1};
        long[] key = {-1, -1};
        long[] token = {-1, -1};
        boolean inSection = false;
        boolean found = false;
        long size = text.byteSize();
        long lineStart = 0;
        while (lineStart < size) {
            long lineEnd = lineStart;
            while (lineEnd < size && at(text, lineEnd) != '\n') {
                lineEnd++;
            }
            long start = skipSpace(text, lineStart, lineEnd);
            long end = trimEnd(text, start, lineEnd);
            if (start < end && at(text, start) == '[') {
                inSection = end - start >= 2 && at(text, end - 1) == ']'
                        && equalsAt(text, skipSpace(text, start + 1, end - 1), trimEnd(text, start + 1, end - 1),
                        section);
                found |= inSection;
            } else if (inSection && start < end && at(text, start) != '#' && at(text, start) != ';') {
                assign(text, start, end, id, key, token);
            }
            lineStart = lineEnd + 1;
        }
        if (!found) {
            throw new SecretManagerException("The AWS credentials file " + file + " has no profile '" + profile + "'");
        }
        if (id[0] < 0 || key[0] < 0) {
            throw new SecretManagerException("The profile '" + profile + "' in the AWS credentials file " + file
                    + " has no aws_access_key_id and aws_secret_access_key");
        }
        String accessKeyId = new String(text.asSlice(id[0], id[1] - id[0]).toArray(ValueLayout.JAVA_BYTE),
                StandardCharsets.US_ASCII);
        Secret secretAccessKey = copy(text, key);
        try {
            Secret sessionToken = token[0] < 0 ? null : copy(text, token);
            return new Credentials(accessKeyId, secretAccessKey, sessionToken, null);
        } catch (RuntimeException e) {
            secretAccessKey.close();
            throw e;
        }
    }

    /** {@code name = value}: records the value's span if the name is one of the three. */
    private static void assign(MemorySegment text, long start, long end, long[] id, long[] key, long[] token) {
        long eq = start;
        while (eq < end && at(text, eq) != '=') {
            eq++;
        }
        if (eq == end) {
            return;
        }
        long nameEnd = trimEnd(text, start, eq);
        long valueStart = skipSpace(text, eq + 1, end);
        long[] target = null;
        if (equalsAt(text, start, nameEnd, ACCESS_KEY_ID)) {
            target = id;
        } else if (equalsAt(text, start, nameEnd, SECRET_ACCESS_KEY)) {
            target = key;
        } else if (equalsAt(text, start, nameEnd, SESSION_TOKEN)) {
            target = token;
        }
        if (target != null && valueStart < end) {
            target[0] = valueStart;
            target[1] = end;
        }
    }

    private Secret copy(MemorySegment text, long[] span) {
        MemorySegment value = text.asSlice(span[0], span[1] - span[0]);
        return memory.allocate(value.byteSize(), out -> out.copyFrom(value));
    }

    private static byte at(MemorySegment text, long index) {
        return text.get(ValueLayout.JAVA_BYTE, index);
    }

    private static boolean isSpace(byte b) {
        return b == ' ' || b == '\t' || b == '\r';
    }

    private static long skipSpace(MemorySegment text, long from, long to) {
        long i = from;
        while (i < to && isSpace(at(text, i))) {
            i++;
        }
        return i;
    }

    private static long trimEnd(MemorySegment text, long from, long to) {
        long i = to;
        while (i > from && isSpace(at(text, i - 1))) {
            i--;
        }
        return i;
    }

    private static boolean equalsAt(MemorySegment text, long start, long end, byte[] expected) {
        if (end - start != expected.length) {
            return false;
        }
        for (int i = 0; i < expected.length; i++) {
            if (at(text, start + i) != expected[i]) {
                return false;
            }
        }
        return true;
    }
}
