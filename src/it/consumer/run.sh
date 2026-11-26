#!/usr/bin/env bash
# JPMS consumer smoke test. Builds the jars and copies the runtime dependencies, then runs an application module
# that requires only io.descoped.secrets.api (no provider module, no `uses`) against every provider:
#
# - on the module path, where the API module's `uses` and service binding resolve the provider modules, with
#   google-auth and its dependencies as automatic modules;
# - on the class path, where META-INF/services registers the providers.
#
# It also prints each module descriptor and checks with jdeps that the modules with only named dependencies declare
# exactly the `requires` they need.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
it="$root/src/it/consumer"
out="$root/target/it-consumer"
cd "$root"
# The baseline release, as CI and the POM use it.
release=$(cat .java-version)

rm -rf "$out"
mkdir -p "$out/lib" "$out/classes"

# One build, so the reactor resolves the modules' own jars: package them, then copy every runtime dependency.
./mvnw --batch-mode --no-transfer-progress --quiet package -DskipTests \
    dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory="$out/lib"
version=$(sed -n 's/^version=//p' secrets-client-api/target/maven-archiver/pom.properties)
for module in secrets-client-api secrets-provider-safe-configuration secrets-provider-dynamic-configuration \
    secrets-provider-google-secret-manager; do
    cp "$module/target/$module-$version.jar" "$out/lib/"
done

javac --release "$release" -Xlint:all -Werror --module-path "$out/lib" --module-source-path "$it/src" \
    -d "$out/classes" $(find "$it/src" -name '*.java')

echo "== module descriptors"
for module in secrets-client-api secrets-provider-safe-configuration secrets-provider-dynamic-configuration \
    secrets-provider-google-secret-manager; do
    jar --describe-module --file "$out/lib/$module-$version.jar" | head -1
done

echo "== jdeps: requires that are missing or unused"
jdeps --multi-release "$release" --module-path "$out/lib" --check \
    io.descoped.secrets.api,io.descoped.secrets.provider.safe,io.descoped.secrets.provider.dynamic

# Guarded memory (safe-configuration, and every provider's read) needs native access for the API module.
echo "== module path"
java --enable-native-access=io.descoped.secrets.api --module-path "$out/lib:$out/classes" \
    --module consumer/consumer.Main module

echo "== class path"
java --enable-native-access=ALL-UNNAMED --class-path "$out/lib/*:$out/classes/consumer" consumer.Main classpath
