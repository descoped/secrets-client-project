# Writing a provider

A provider adds a backend to `SecretManagerClient.create`. It is a named module that depends on `secrets-client-api`
(see [The API](api.md)).

A provider is two classes in a named module:

1. A `SecretManagerClient` implementation. Implement `readBytes(String, String)`, `addVersion(String, byte[])` and
   `close()`; the other methods are defaults built on these. Follow [the contract](api.md#the-contract) exactly; the
   default methods rely on it. In particular, `close()` may run while other threads are inside a call: read the
   client's state once per call (into a local, or under a lock) so such a call finishes or throws
   `IllegalStateException`, never a `NullPointerException`.
2. A `SecretManagerClientInitializer`, with a public no-argument constructor, annotated with
   `@ProviderName("my-provider")`:

```java
@ProviderName("my-provider")
public final class MyClientInitializer implements SecretManagerClientInitializer {

    public MyClientInitializer() {
    }

    @Override
    public Set<String> configurationKeys() {
        return Set.of("secrets.my-provider.url");   // required keys; create() fails without them
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        return new MyClient(configuration.get("secrets.my-provider.url"));
    }
}
```

Register it twice, so it works on the module path and on the class path:

```java
module com.example.secrets.myprovider {
    requires transitive io.descoped.secrets.api;
    provides io.descoped.secrets.api.SecretManagerClientInitializer
            with com.example.secrets.myprovider.MyClientInitializer;
}
```

and a file `META-INF/services/io.descoped.secrets.api.SecretManagerClientInitializer` containing the class name.

Keep the client class package-private; only the initializer needs to be public. Test it as an application would:
through `SecretManagerClient.create` from a separate test module, not from the provider's own package.
