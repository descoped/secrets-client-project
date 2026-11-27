package io.descoped.secrets.api.internal;

import io.descoped.secrets.api.SecretManagerException;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * The OpenSSL 3 calls TLS and the digests need, through the Foreign Function &amp; Memory API, from the system's {@code libssl} and
 * {@code libcrypto}: {@code libssl.so.3} on Linux, Homebrew's {@code openssl@3} on macOS. Nothing is bundled.
 *
 * <p>OpenSSL's error queue is per thread. A virtual thread can move to another carrier between two calls, so an
 * error read from the queue may be missing; it is used for messages only, and a failure is reported either way.
 */
@SuppressWarnings("restricted")
public final class OpenSsl {

    public static final int SSL_ERROR_NONE = 0;
    public static final int SSL_ERROR_WANT_READ = 2;
    public static final int SSL_ERROR_WANT_WRITE = 3;
    public static final int SSL_ERROR_ZERO_RETURN = 6;

    public static final int SSL_VERIFY_PEER = 1;
    public static final int SSL_CTRL_MODE = 33;
    public static final int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
    public static final int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
    public static final int SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
    public static final long SSL_MODE_RELEASE_BUFFERS = 0x10;
    /** Clear decrypted data once it is handed over, and on {@code SSL_free} (OpenSSL 3.0). */
    public static final long SSL_OP_CLEANSE_PLAINTEXT = 1L << 1;
    public static final long SSL_OP_NO_COMPRESSION = 1L << 17;
    public static final long SSL_OP_NO_RENEGOTIATION = 1L << 30;
    public static final long TLS1_2_VERSION = 0x0303;
    public static final long TLS1_3_VERSION = 0x0304;
    public static final long TLSEXT_NAMETYPE_HOST_NAME = 0;
    public static final long X509_V_OK = 0;
    private static final long OPENSSL_3 = 0x30000000L;

    public final MethodHandle tlsClientMethod;
    public final MethodHandle ctxNew;
    public final MethodHandle ctxFree;
    public final MethodHandle ctxCtrl;
    public final MethodHandle ctxSetOptions;
    public final MethodHandle ctxSetCiphersuites;
    public final MethodHandle ctxSetCipherList;
    public final MethodHandle ctxSetVerify;
    public final MethodHandle ctxSetDefaultVerifyPaths;
    public final MethodHandle ctxLoadVerifyLocations;
    public final MethodHandle sslNew;
    public final MethodHandle sslFree;
    public final MethodHandle sslCtrl;
    public final MethodHandle sslSet1Host;
    public final MethodHandle sslGet0Param;
    public final MethodHandle paramSet1IpAsc;
    public final MethodHandle bioSMem;
    public final MethodHandle bioNew;
    public final MethodHandle bioFree;
    public final MethodHandle sslSetBio;
    public final MethodHandle bioWrite;
    public final MethodHandle bioRead;
    public final MethodHandle bioCtrlPending;
    public final MethodHandle sslSetConnectState;
    public final MethodHandle sslDoHandshake;
    public final MethodHandle sslReadEx;
    public final MethodHandle sslWriteEx;
    public final MethodHandle sslGetError;
    public final MethodHandle sslPending;
    public final MethodHandle sslGetVerifyResult;
    public final MethodHandle verifyErrorString;
    public final MethodHandle sslGet0PeerCertificate;
    public final MethodHandle sslShutdown;
    public final MethodHandle evpSha256;
    public final MethodHandle evpDigest;
    public final MethodHandle hmac;
    public final MethodHandle errGetError;
    public final MethodHandle errErrorStringN;
    public final MethodHandle errClearError;

    private static final class Holder {
        static final OpenSsl INSTANCE = new OpenSsl();
    }

    /**
     * The bound calls, loaded on first use.
     *
     * @throws SecretManagerException if OpenSSL 3 is not found
     */
    public static OpenSsl get() {
        try {
            return Holder.INSTANCE;
        } catch (ExceptionInInitializerError e) {
            if (e.getCause() instanceof SecretManagerException s) {
                throw s;
            }
            throw e;
        } catch (NoClassDefFoundError e) {
            // A second use after the first one failed.
            throw new SecretManagerException("OpenSSL 3 could not be loaded; see the first failure", e);
        }
    }

    private OpenSsl() {
        SymbolLookup lookup = load();
        Linker linker = Linker.nativeLinker();
        Binder b = new Binder(linker, lookup);
        MethodHandle versionNum = b.bind("OpenSSL_version_num", FunctionDescriptor.of(JAVA_LONG));
        long version = call(() -> (long) versionNum.invokeExact());
        if (Long.compareUnsigned(version, OPENSSL_3) < 0) {
            throw new SecretManagerException("TLS and request signing need OpenSSL 3, found version 0x" + Long.toHexString(version));
        }
        tlsClientMethod = b.bind("TLS_client_method", FunctionDescriptor.of(ADDRESS));
        ctxNew = b.bind("SSL_CTX_new", FunctionDescriptor.of(ADDRESS, ADDRESS));
        ctxFree = b.bind("SSL_CTX_free", FunctionDescriptor.ofVoid(ADDRESS));
        ctxCtrl = b.bind("SSL_CTX_ctrl", FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_INT, JAVA_LONG, ADDRESS));
        ctxSetOptions = b.bind("SSL_CTX_set_options", FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_LONG));
        ctxSetCiphersuites = b.bind("SSL_CTX_set_ciphersuites", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        ctxSetCipherList = b.bind("SSL_CTX_set_cipher_list", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        ctxSetVerify = b.bind("SSL_CTX_set_verify", FunctionDescriptor.ofVoid(ADDRESS, JAVA_INT, ADDRESS));
        ctxSetDefaultVerifyPaths = b.bind("SSL_CTX_set_default_verify_paths",
                FunctionDescriptor.of(JAVA_INT, ADDRESS));
        ctxLoadVerifyLocations = b.bind("SSL_CTX_load_verify_locations",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        sslNew = b.bind("SSL_new", FunctionDescriptor.of(ADDRESS, ADDRESS));
        sslFree = b.bind("SSL_free", FunctionDescriptor.ofVoid(ADDRESS));
        sslCtrl = b.bind("SSL_ctrl", FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_INT, JAVA_LONG, ADDRESS));
        sslSet1Host = b.bind("SSL_set1_host", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        sslGet0Param = b.bind("SSL_get0_param", FunctionDescriptor.of(ADDRESS, ADDRESS));
        paramSet1IpAsc = b.bind("X509_VERIFY_PARAM_set1_ip_asc", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        bioSMem = b.bind("BIO_s_mem", FunctionDescriptor.of(ADDRESS));
        bioNew = b.bind("BIO_new", FunctionDescriptor.of(ADDRESS, ADDRESS));
        bioFree = b.bind("BIO_free", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        sslSetBio = b.bind("SSL_set_bio", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS));
        bioWrite = b.bind("BIO_write", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        bioRead = b.bind("BIO_read", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        bioCtrlPending = b.bind("BIO_ctrl_pending", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
        sslSetConnectState = b.bind("SSL_set_connect_state", FunctionDescriptor.ofVoid(ADDRESS));
        sslDoHandshake = b.bind("SSL_do_handshake", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        sslReadEx = b.bind("SSL_read_ex", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        sslWriteEx = b.bind("SSL_write_ex", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        sslGetError = b.bind("SSL_get_error", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
        sslPending = b.bind("SSL_pending", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        sslGetVerifyResult = b.bind("SSL_get_verify_result", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
        verifyErrorString = b.bind("X509_verify_cert_error_string", FunctionDescriptor.of(ADDRESS, JAVA_LONG));
        sslGet0PeerCertificate = b.bind("SSL_get0_peer_certificate", FunctionDescriptor.of(ADDRESS, ADDRESS));
        sslShutdown = b.bind("SSL_shutdown", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        evpSha256 = b.bind("EVP_sha256", FunctionDescriptor.of(ADDRESS));
        // Short, never blocking and never calling back: critical, so that inputs that are not secret may be on the
        // heap.
        evpDigest = b.critical("EVP_Digest",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        hmac = b.critical("HMAC",
                FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
        errGetError = b.bind("ERR_get_error", FunctionDescriptor.of(JAVA_LONG));
        errErrorStringN = b.bind("ERR_error_string_n", FunctionDescriptor.ofVoid(JAVA_LONG, ADDRESS, JAVA_LONG));
        errClearError = b.bind("ERR_clear_error", FunctionDescriptor.ofVoid());
    }

    /** {@code libssl} and {@code libcrypto}, from the first place that has both. */
    private static SymbolLookup load() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        List<String> tried = new ArrayList<>();
        Arena global = Arena.global();
        if (os.startsWith("mac")) {
            for (String dir : List.of("/opt/homebrew/opt/openssl@3/lib", "/usr/local/opt/openssl@3/lib")) {
                Path ssl = Path.of(dir, "libssl.3.dylib");
                Path crypto = Path.of(dir, "libcrypto.3.dylib");
                tried.add(ssl.toString());
                if (Files.exists(ssl) && Files.exists(crypto)) {
                    return SymbolLookup.libraryLookup(ssl, global).or(SymbolLookup.libraryLookup(crypto, global));
                }
            }
            throw missing(tried, "install it with 'brew install openssl@3'");
        }
        if (!os.startsWith("linux")) {
            throw new SecretManagerException("OpenSSL (TLS and request signing) is supported on Linux and macOS, not on "
                    + System.getProperty("os.name"));
        }
        tried.add("libssl.so.3");
        try {
            return SymbolLookup.libraryLookup("libssl.so.3", global)
                    .or(SymbolLookup.libraryLookup("libcrypto.so.3", global));
        } catch (IllegalArgumentException _) {
            throw missing(tried, "install OpenSSL 3 (on Debian and Ubuntu, the libssl3 package)");
        }
    }

    private static SecretManagerException missing(List<String> tried, String advice) {
        return new SecretManagerException("TLS and request signing need OpenSSL 3 (libssl), which was not found (tried " + tried + "); "
                + advice);
    }

    /** The messages in this thread's OpenSSL error queue, which is emptied; "no details" if it is empty. */
    public String errors() {
        StringBuilder messages = new StringBuilder();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buffer = arena.allocate(256);
            long code;
            while ((code = call(() -> (long) errGetError.invokeExact())) != 0) {
                long error = code;
                call(() -> {
                    errErrorStringN.invokeExact(error, buffer, buffer.byteSize());
                    return null;
                });
                if (!messages.isEmpty()) {
                    messages.append("; ");
                }
                messages.append(buffer.getString(0));
            }
        }
        return messages.isEmpty() ? "no details" : messages.toString();
    }

    /** Empties this thread's error queue, so that what is read after a call is that call's. */
    public void clearErrors() {
        call(() -> {
            errClearError.invokeExact();
            return null;
        });
    }

    /** A native call: {@code MethodHandle.invokeExact} is declared to throw {@code Throwable}. */
    @FunctionalInterface
    @SuppressWarnings("java:S112")
    public interface Call<T> {
        T run() throws Throwable;
    }

    public static <T> T call(Call<T> call) {
        try {
            return call.run();
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("A native OpenSSL call failed", e);
        }
    }

    private record Binder(Linker linker, SymbolLookup lookup) {

        MethodHandle bind(String name, FunctionDescriptor descriptor) {
            MemorySegment symbol = lookup.find(name).orElseThrow(
                    () -> new SecretManagerException("OpenSSL has no " + name + ": not OpenSSL 3?"));
            return linker.downcallHandle(symbol, descriptor);
        }

        /** A call that may be given heap segments ({@link Linker.Option#critical(boolean)}). */
        MethodHandle critical(String name, FunctionDescriptor descriptor) {
            MemorySegment symbol = lookup.find(name).orElseThrow(
                    () -> new SecretManagerException("OpenSSL has no " + name + ": not OpenSSL 3?"));
            return linker.downcallHandle(symbol, descriptor, Linker.Option.critical(true));
        }
    }
}
