/**
 * The {@code google-secret-manager} secrets provider. See
 * {@link io.descoped.secrets.provider.google.GoogleSecretManagerClientInitializer}.
 */
module io.descoped.secrets.provider.google {
    requires transitive io.descoped.secrets.api;
    requires java.net.http;
    requires com.google.auth;
    requires com.google.auth.oauth2;
    // google-auth and google-http-client are automatic modules: they read every module but cannot make a named module
    // resolve. These named modules are what they use at run time (Guava brings failureaccess with it), so this module
    // requires them; without that, the provider fails on the module path with NoClassDefFoundError.
    requires com.google.common;
    requires com.google.gson;
    requires com.fasterxml.jackson.core;

    exports io.descoped.secrets.provider.google;

    provides io.descoped.secrets.api.SecretManagerClientInitializer with
            io.descoped.secrets.provider.google.GoogleSecretManagerClientInitializer;
}
