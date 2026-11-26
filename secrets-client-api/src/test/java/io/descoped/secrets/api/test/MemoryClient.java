package io.descoped.secrets.api.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implements only the abstract methods, so the tests exercise the API's default methods. It remembers every array it
 * handed out or was handed, so the tests can check that the default methods wipe them.
 */
final class MemoryClient implements SecretManagerClient {

    final Map<String, List<byte[]>> versions = new ConcurrentHashMap<>();
    final List<byte[]> returned = new ArrayList<>();
    final List<byte[]> received = new ArrayList<>();
    private final SecretMemory memory = SecretMemory.create(Map.of(SecretMemory.GUARD_KEY, "off"));

    @Override
    public Secret read(String secretName, String secretVersion) {
        return memory.fromBytes(readBytes(secretName, secretVersion));
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        Objects.requireNonNull(secretName, "secretName");
        List<byte[]> list = versions.get(secretName);
        if (list == null) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        int index = secretVersion == null ? list.size() - 1 : Integer.parseInt(secretVersion) - 1;
        if (index < 0 || index >= list.size()) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        byte[] copy = list.get(index).clone();
        returned.add(copy);
        return copy;
    }

    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        received.add(secretValue);
        List<byte[]> list = versions.computeIfAbsent(secretName, k -> new ArrayList<>());
        list.add(secretValue.clone());
        return String.valueOf(list.size());
    }

    @Override
    public void close() {
        // The versions stay readable to the test after close.
        memory.close();
    }
}
