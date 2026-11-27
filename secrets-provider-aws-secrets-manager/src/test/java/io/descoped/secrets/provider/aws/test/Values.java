package io.descoped.secrets.provider.aws.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretMemory;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** The tests' way to read a value as text or bytes and to write one, through {@link Secret} only. */
final class Values {

    private Values() {
    }

    static String text(SecretManagerClient client, String name) {
        return text(client, name, null);
    }

    static String text(SecretManagerClient client, String name, String version) {
        try (Secret secret = client.read(name, version)) {
            return secret.withChars(String::new);
        }
    }

    static char[] chars(SecretManagerClient client, String name) {
        try (Secret secret = client.read(name)) {
            return secret.withChars(char[]::clone);
        }
    }

    static byte[] bytes(SecretManagerClient client, String name) {
        return bytes(client, name, null);
    }

    static byte[] bytes(SecretManagerClient client, String name, String version) {
        try (Secret secret = client.read(name, version)) {
            return secret.withSegment(segment -> segment.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    static String add(SecretManagerClient client, String name, Secret value) {
        return client.addVersion(name, value);
    }

    static String add(SecretManagerClient client, String name, String value) {
        return add(client, name, value.getBytes(StandardCharsets.UTF_8));
    }

    static String add(SecretManagerClient client, String name, char[] value) {
        try (SecretMemory memory = SecretMemory.create(Map.of());
             Secret secret = memory.fromChars(value.clone())) {
            return client.addVersion(name, secret);
        }
    }

    static String add(SecretManagerClient client, String name, byte[] value) {
        try (SecretMemory memory = SecretMemory.create(Map.of());
             Secret secret = memory.fromBytes(value.clone())) {
            return client.addVersion(name, secret);
        }
    }
}
