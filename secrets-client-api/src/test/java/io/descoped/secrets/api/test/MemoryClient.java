package io.descoped.secrets.api.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/** Implements only the abstract methods, so the tests exercise the API's default methods. */
final class MemoryClient implements SecretManagerClient {

    final Map<String, List<Secret>> versions = new ConcurrentHashMap<>();
    private final SecretMemory memory = SecretMemory.create(Map.of(SecretMemory.GUARD_KEY, "off"));

    @Override
    public Secret read(String secretName, String secretVersion) {
        Objects.requireNonNull(secretName, "secretName");
        List<Secret> list = versions.get(secretName);
        if (list == null) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        int index = secretVersion == null ? list.size() - 1 : Integer.parseInt(secretVersion) - 1;
        if (index < 0 || index >= list.size()) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        return copy(list.get(index));
    }

    @Override
    public String addVersion(String secretName, Secret secretValue) {
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        List<Secret> list = versions.computeIfAbsent(secretName, k -> new ArrayList<>());
        list.add(copy(secretValue));
        return String.valueOf(list.size());
    }

    private Secret copy(Secret value) {
        return value.withSegment(from -> memory.allocate(from.byteSize(),
                to -> MemorySegment.copy(from, 0, to, 0, from.byteSize())));
    }

    @Override
    public void close() {
        memory.close();
    }
}
