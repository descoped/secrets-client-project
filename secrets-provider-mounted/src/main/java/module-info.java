/**
 * The {@code mounted} secrets provider: secrets that the platform mounts as files. See
 * {@link io.descoped.secrets.provider.mounted.MountedClientInitializer}.
 */
module io.descoped.secrets.provider.mounted {
    requires transitive io.descoped.secrets.api;

    exports io.descoped.secrets.provider.mounted;

    provides io.descoped.secrets.api.SecretManagerClientInitializer with
            io.descoped.secrets.provider.mounted.MountedClientInitializer;
}
