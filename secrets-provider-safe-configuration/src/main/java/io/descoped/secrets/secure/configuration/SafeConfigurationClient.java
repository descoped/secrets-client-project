package io.descoped.secrets.secure.configuration;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A client that reads secrets from a local {@code key=value} file and keeps the values as byte arrays,
 * wiped on {@link #close()}.
 */
public class SafeConfigurationClient implements SecretManagerClient {

    static final Logger LOG = LoggerFactory.getLogger(SafeConfigurationClient.class);
    private final Map<String, byte[]> secureMap = new ConcurrentHashMap<>();
    private final Path resourcePath;
    private final Object lock = new Object();
    private final AtomicBoolean closed = new AtomicBoolean();

    /**
     * Reads the secrets from a file.
     *
     * @param propertyResourcePath the path of the secrets file
     */
    public SafeConfigurationClient(String propertyResourcePath) {
        Objects.requireNonNull(propertyResourcePath);
        resourcePath = Paths.get(propertyResourcePath);
        if (!Files.isReadable(resourcePath)) {
            throw new SecretManagerException("The file " + propertyResourcePath + " is not readable");
        }
        loadResource(resourcePath);
    }

    private void loadResource(Path resourcePath) {
        byte[] bytes = new byte[0];
        char[] chars = new char[0];
        try {
            bytes = Files.readAllBytes(resourcePath);
            CharBuffer buffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
            chars = new char[buffer.remaining()];
            buffer.get(chars);
            buffer.clear();

            int pos = 0;

            while (pos < chars.length) {
                Map.Entry<Integer, Integer> endOfLIne = findEndOfLine(chars, pos);

                // skip comment lines
                if (chars[pos] == '#') {
                    pos = endOfLIne.getValue() + 1;
                    continue;
                }

                // split property pair
                int equalPos = findEqualCharacter(chars, pos);
                if (equalPos == -1) {
                    pos = endOfLIne.getValue() + 1;
                    continue;
                }
                if (equalPos > endOfLIne.getValue()) {
                    pos = endOfLIne.getValue() + 1;
                    continue;
                }
                char[] value = new char[0];
                CharBuffer valueCharBuffer = null;
                ByteBuffer valueByteBuffer = null;
                try {
                    String key = new String(chars, pos, equalPos - pos);
                    value = Arrays.copyOfRange(chars, equalPos + 1, endOfLIne.getKey());
                    valueCharBuffer = CharBuffer.wrap(value);
                    valueByteBuffer = StandardCharsets.UTF_8.encode(valueCharBuffer);
                    byte[] valueBytes = new byte[valueByteBuffer.remaining()];
                    valueByteBuffer.get(valueBytes);
                    secureMap.put(key, valueBytes);
                } finally {
                    if (valueCharBuffer != null) valueCharBuffer.clear();
                    if (valueByteBuffer != null) valueByteBuffer.clear();
                    Arrays.fill(value, '\u0000');
                }

                pos = (endOfLIne.getValue() < chars.length && chars[endOfLIne.getValue()] == '\n') ? endOfLIne.getValue() + 1 : endOfLIne.getValue();
            }

        } catch (IOException e) {
            throw new SecretManagerException("Cannot read " + resourcePath, e);
        } finally {
            Arrays.fill(bytes, (byte) 0);
            Arrays.fill(chars, '\u0000');
        }
    }

    private Integer findEqualCharacter(char[] chars, int pos) {
        for (int i = pos; i < chars.length; i++) {
            if (chars[i] == '=') {
                return i;
            }
        }
        return -1;
    }

    private Map.Entry<Integer, Integer> findEndOfLine(char[] chars, int pos) {
        int cr = -1; // \r
        int lf = -1; // \n

        for (int i = pos; i < chars.length; i++) {
            if (chars[i] == '\n') {
                lf = i;
                if ((i - 1 > -1) && (chars[i - 1] == '\r')) {
                    cr = i - 1;
                }
                break;
            }
        }

        if (cr > -1) {
            return Map.entry(cr, lf);

        } else if (lf == -1) {
            return Map.entry(chars.length, chars.length);

        } else {
            return Map.entry(lf, lf);
        }
    }

    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        if (closed.get()) {
            throw new IllegalStateException("Client is closed!");
        }
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        byte[] previous = secureMap.put(secretName, secretValue.clone());
        if (previous != null) {
            Arrays.fill(previous, (byte) 0);
        }
        if (!Files.isWritable(resourcePath)) {
            LOG.warn("Secret configuration is NOT writable: {}", resourcePath.normalize().toAbsolutePath());
            return "latest";
        }
        synchronized (lock) {
            try {
                String secretResources = Files.readString(resourcePath);
                Properties props = new Properties();
                props.load(new StringReader(secretResources));
                props.put(secretName, new String(secretValue, StandardCharsets.UTF_8));
                try (FileOutputStream out = new FileOutputStream(resourcePath.toFile())) {
                    props.store(out, null);
                }
            } catch (IOException e) {
                throw new SecretManagerException("Cannot write secret '" + secretName + "' to " + resourcePath, e);
            }
        }
        return "latest";
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        if (closed.get()) {
            throw new IllegalStateException("Client is closed!");
        }
        Objects.requireNonNull(secretName, "secretName");
        byte[] value = secureMap.get(secretName);
        if (value == null) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        return value.clone();
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            for (Map.Entry<String, byte[]> entry : secureMap.entrySet()) {
                Arrays.fill(entry.getValue(), (byte) 0);
            }
            secureMap.clear();
        }
    }
}
