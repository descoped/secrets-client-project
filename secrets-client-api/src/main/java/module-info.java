/**
 * The secrets client API. Start with {@link io.descoped.secrets.api.SecretManagerClient}; providers implement
 * {@link io.descoped.secrets.api.SecretManagerClientInitializer}.
 *
 * <p>The module declares {@code uses} for the provider service, so a provider module on the module path is resolved
 * at startup without the application requiring it.
 */
// "module": the providers named in qualified exports are not there when this module is compiled.
@SuppressWarnings("module")
module io.descoped.secrets.api {
    requires transitive io.descoped.service.provider.api;

    exports io.descoped.secrets.api;
    // TLS through OpenSSL, for the providers that talk to a server; not part of the API.
    exports io.descoped.secrets.api.tls to io.descoped.secrets.provider.google, io.descoped.secrets.api.test;
    exports io.descoped.secrets.api.http to io.descoped.secrets.provider.google;

    uses io.descoped.secrets.api.SecretManagerClientInitializer;
}
