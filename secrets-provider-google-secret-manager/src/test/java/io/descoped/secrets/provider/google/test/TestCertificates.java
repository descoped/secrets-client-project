package io.descoped.secrets.provider.google.test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Certificates made by keytool for FakeGoogle on https, and a PKCS12 trust store that trusts them, as an application
 * would add a private CA. The password is a test constant, not a secret.
 */
final class TestCertificates {

    static final String PASSWORD = "changeit";
    static final String TRUST_STORE = "trust.p12";

    private TestCertificates() {
    }

    /** The trust store in {@code keys} that {@link #server} adds each certificate to. */
    static Path trustStore(Path keys) {
        return keys.resolve(TRUST_STORE);
    }

    /**
     * A server context with a new EC key and a self-signed certificate for {@code san} (such as
     * {@code SAN=ip:127.0.0.1}), which is added to the trust store in {@code keys}.
     */
    static SSLContext server(Path keys, String alias, String san)
            throws IOException, InterruptedException, GeneralSecurityException {
        Path store = keys.resolve(alias + ".p12");
        Path certificate = keys.resolve(alias + ".pem");
        keytool("-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + alias,
                "-ext", san, "-validity", "2", "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD);
        keytool("-exportcert", "-rfc", "-alias", alias, "-keystore", store.toString(), "-storepass", PASSWORD,
                "-file", certificate.toString());
        keytool("-importcert", "-noprompt", "-alias", alias, "-file", certificate.toString(),
                "-keystore", trustStore(keys).toString(), "-storetype", "PKCS12", "-storepass", PASSWORD);
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(KeyStore.getInstance(store.toFile(), PASSWORD.toCharArray()), PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), null, null);
        return context;
    }

    /** Makes the JDK trust {@code trustStore} for every TLS context created from now on. */
    static void trust(Path trustStore) {
        System.setProperty("javax.net.ssl.trustStore", trustStore.toString());
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
    }

    /** Back to the JDK's own trust store. */
    static void forget() {
        System.clearProperty("javax.net.ssl.trustStore");
        System.clearProperty("javax.net.ssl.trustStorePassword");
        System.clearProperty("javax.net.ssl.trustStoreType");
    }

    private static void keytool(String... arguments) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "keytool finishes");
        assertEquals(0, process.exitValue(), output);
    }
}
