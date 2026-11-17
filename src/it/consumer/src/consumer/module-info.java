/**
 * An application that requires only the API: no provider module is required and there is no {@code uses}, so the
 * providers are found through the API module's {@code uses} and service binding.
 */
module consumer {
    requires io.descoped.secrets.api;
}
