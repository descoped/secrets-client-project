package io.descoped.secrets.provider.aws.test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Certificates made by keytool for FakeAws on https (the JDK's TLS on the server side), and a PEM file of the
 * trusted ones, which the client is given as {@code secrets.tls.ca-file}, as an application would trust a private
 * CA. The password is a test constant, not a secret.
 */
final class TestCertificates {

    static final String PASSWORD = "changeit";
    static final String TRUSTED = "trusted.pem";

    private TestCertificates() {
    }

    /** The PEM file in {@code keys} that {@link #server} adds each trusted certificate to. */
    static Path trusted(Path keys) {
        return keys.resolve(TRUSTED);
    }

    /**
     * A server context with a new EC key and a self-signed certificate for {@code san} (such as
     * {@code SAN=ip:127.0.0.1}), which is added to the trusted file in {@code keys}.
     */
    static SSLContext server(Path keys, String alias, String san)
            throws IOException, InterruptedException, GeneralSecurityException {
        return server(keys, alias, san, true);
    }

    /**
     * A server context as {@link #server(Path, String, String)}, trusted or not, with more {@code keytool
     * -genkeypair} options (such as {@code -startdate}).
     */
    static SSLContext server(Path keys, String alias, String san, boolean trusted, String... options)
            throws IOException, InterruptedException, GeneralSecurityException {
        Path store = keys.resolve(alias + ".p12");
        Path certificate = keys.resolve(alias + ".pem");
        List<String> generate = new ArrayList<>(List.of("-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname",
                "secp256r1", "-dname", "CN=" + alias, "-ext", san, "-keystore", store.toString(), "-storetype",
                "PKCS12", "-storepass", PASSWORD));
        if (options.length == 0) {
            generate.addAll(List.of("-validity", "2"));
        } else {
            generate.addAll(List.of(options));
        }
        keytool(generate.toArray(String[]::new));
        keytool("-exportcert", "-rfc", "-alias", alias, "-keystore", store.toString(), "-storepass", PASSWORD,
                "-file", certificate.toString());
        if (trusted) {
            Files.writeString(trusted(keys), Files.readString(certificate, StandardCharsets.US_ASCII),
                    StandardCharsets.US_ASCII, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(KeyStore.getInstance(store.toFile(), PASSWORD.toCharArray()), PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), null, null);
        return context;
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
