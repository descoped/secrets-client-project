# secrets-client-project development recipes. Run `just` to list them.
#
# Everything here only builds, tests or reads. What publishes or changes something outside the working tree (push,
# pull request, merge, comment, release) is not a recipe.

set shell := ["bash", "-euo", "pipefail", "-c"]
set quiet

# The JDK of the version in .java-version: the first of JAVA_HOME, macOS's java_home, Homebrew's openjdk@<version>
# and the usual Linux paths that is that version; JAVA_HOME as it is if none is. Every recipe that builds checks it
# against .java-version first (_jdk).
export JAVA_HOME := `v=$(cat .java-version); for h in "${JAVA_HOME:-}" "$(/usr/libexec/java_home -v "$v" 2>/dev/null)" "/opt/homebrew/opt/openjdk@$v/libexec/openjdk.jdk/Contents/Home" "/usr/lib/jvm/temurin-$v-jdk" "/usr/lib/jvm/java-$v-openjdk-amd64" "/usr/lib/jvm/java-$v-openjdk-arm64"; do [ -n "$h" ] && [ -x "$h/bin/java" ] && [ "$("$h/bin/java" -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java.specification.version = //p')" = "$v" ] && { echo "$h"; exit 0; }; done; echo "${JAVA_HOME:-}"`
# Its tools first on the PATH: the smoke test runs javac, jar and jdeps.
export PATH := if JAVA_HOME == "" { env("PATH") } else { JAVA_HOME + "/bin:" + env("PATH") }

# The SonarCloud project, one for the whole reactor.
sonar_project := "descoped_secrets-client-project"
# Where recipes keep their logs.
logs := "target/just"

default:
    just --list --unsorted

# ---------------------------------------------------------------- Build and test

# Compile with -Xlint:all -Werror and run every test
build: _jdk
    ./mvnw -B verify

# Everything CI checks: build, tests, Javadoc with doclint, and the JPMS smoke test
check: _jdk
    ./mvnw -B verify javadoc:javadoc
    src/it/consumer/run.sh

# Tests of one module and what it needs, optionally one test pattern. Usage: just test secrets-provider-mounted [Mounted*]
test module tests="": _jdk
    ./mvnw -B verify -pl {{module}} -am -Djacoco.skip=true \
        {{ if tests == "" { "" } else { "-Dsurefire.failIfNoSpecifiedTests=false -Dtest='" + tests + "'" } }}

# Run a test pattern N times; one result per run, tests:failures+errors (flakiness). Usage: just repeat <module> <pattern> [n]
repeat module tests times="10": _jdk
    mkdir -p {{logs}}
    ./mvnw -B -q install -pl {{module}} -am -DskipTests > {{logs}}/install.log 2>&1 || { cat {{logs}}/install.log; exit 1; }
    for i in $(seq 1 {{times}}); do \
        ./mvnw -B -o verify -pl {{module}} -Djacoco.skip=true -Dsurefire.failIfNoSpecifiedTests=false \
            -Dtest='{{tests}}' > {{logs}}/repeat.log 2>&1 || true; \
        grep -E 'Tests run:.*in ' {{logs}}/repeat.log | sed -E 's/.*Tests run: ([0-9]+), Failures: ([0-9]+), Errors: ([0-9]+).*/\1:\2+\3/' \
            | tr '\n' ' ' || printf 'build-failed '; \
    done; echo

# JaCoCo coverage per module (<module>/target/site/jacoco); with a module, its line and branch totals and each class
coverage module="": _jdk
    ./mvnw -B -q verify -P coverage
    if [ -n "{{module}}" ]; then \
        awk -F, 'NR>1 {l+=$9; L+=$8+$9; b+=$7; B+=$6+$7; printf "  %s: lines %d/%d branches %d/%d\n", $3, $9, $8+$9, $7, $6+$7} \
            END {printf "{{module}}: lines %d/%d (%.1f%%) branches %d/%d (%.1f%%)\n", l, L, L ? 100*l/L : 0, b, B, B ? 100*b/B : 0}' \
            {{module}}/target/site/jacoco/jacoco.csv; \
    fi

# The JPMS smoke test: every provider on the module path and the class path, and jdeps
smoke: _jdk
    src/it/consumer/run.sh

# Tests on Linux in Docker, where memfd_secret is in use, with the pinned Maven. Usage: just linux [modules] [tests]
linux modules="secrets-client-api,secrets-test-support,secrets-provider-safe-configuration,secrets-provider-mounted,secrets-provider-google-secret-manager" tests="":
    # The wrapper needs unzip: without it, it downloads the .tar.gz and checks it against the .zip's checksum.
    docker run --rm -v "$PWD":/src:ro -v secrets-client-m2:/root/.m2 maven:3-eclipse-temurin-25 bash -c \
        'set -o pipefail; (apt-get update -qq && apt-get install -y -qq unzip) >/dev/null 2>&1; \
        cp -r /src /w && cd /w && rm -rf */target target; \
        ./mvnw -B verify -pl {{modules}} -Djacoco.skip=true \
        {{ if tests == "" { "" } else { "-Dsurefire.failIfNoSpecifiedTests=false -Dtest=" + tests } }} > /tmp/build.log 2>&1; rc=$?; \
        grep -E "Tests run:.*in |FAIL|ERROR\]|BUILD" /tmp/build.log; exit $rc'

# Remove build output
clean:
    ./mvnw -B -q clean
    rm -rf target/it-consumer {{logs}}

# Fails unless the JDK in use is the baseline in .java-version
_jdk:
    want=$(cat .java-version); \
    have=$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java.specification.version = //p'); \
    [ "$have" = "$want" ] || { echo "JDK $want is needed (.java-version), not '${have:-none}': set JAVA_HOME"; exit 1; }

# ---------------------------------------------------------------- Live tests (not in CI)

# The Google live test against a real project (SECRETS_GOOGLE_TEST_PROJECT; credentials as the test documents)
live-google: _jdk
    : "${SECRETS_GOOGLE_TEST_PROJECT:?set SECRETS_GOOGLE_TEST_PROJECT}"
    ./mvnw -B verify -pl secrets-provider-google-secret-manager -am -Djacoco.skip=true \
        -Dsurefire.failIfNoSpecifiedTests=false -Dtest=GoogleSecretManagerLiveTest

# The AWS live test against a real account (SECRETS_AWS_TEST_REGION; SECRETS_AWS_TEST_PROFILE names the profile)
live-aws: _jdk
    : "${SECRETS_AWS_TEST_REGION:?set SECRETS_AWS_TEST_REGION}"
    ./mvnw -B verify -pl secrets-provider-aws-secrets-manager -am -Djacoco.skip=true \
        -Dsurefire.failIfNoSpecifiedTests=false -Dtest=AwsSecretsManagerLiveTest

# ---------------------------------------------------------------- Pull requests (read only)

# A pull request's checks
checks pr:
    gh pr checks {{pr}} || true

# Wait until no check of a pull request is pending (at most 30 minutes), then show them
wait pr:
    for i in $(seq 1 60); do \
        out=$(gh pr checks {{pr}} 2>&1 || true); \
        if [ "$i" -ge 6 ] && grep -q "no checks reported" <<< "$out"; then echo "$out"; exit 0; fi; \
        if ! grep -q "no checks reported" <<< "$out" && ! grep -qE "\s(pending|queued|in_progress)\s" <<< "$out"; then \
            cut -f1,2 <<< "$out"; exit 0; \
        fi; \
        sleep 30; \
    done; echo "Still pending after 30 minutes"; gh pr checks {{pr}} | cut -f1,2 || true; exit 1

# The Claude review on a pull request
review pr:
    gh pr view {{pr}} --json comments -q '.comments[] | select(.author.login=="claude") | .body'

# SonarCloud on a pull request: the quality gate and the open issues (the token from ~/.sonar-token, never on a command line)
sonar pr:
    mkdir -p {{logs}}
    code=$(printf 'user = "%s:"\n' "$(< ~/.sonar-token)" | curl -s -K - -o {{logs}}/gate.json -w '%{http_code}' \
        "https://sonarcloud.io/api/qualitygates/project_status?projectKey={{sonar_project}}&pullRequest={{pr}}"); \
    case "$code" in \
        200) ;; \
        401|403) echo "SonarCloud refused the token in ~/.sonar-token (HTTP $code)"; exit 1 ;; \
        404) echo "No SonarCloud analysis for pull request {{pr}} (a docs-only change runs no CI)"; exit 1 ;; \
        *) echo "SonarCloud answered HTTP $code"; exit 1 ;; \
    esac
    python3 -c "import json; d=json.load(open('{{logs}}/gate.json'))['projectStatus']; print('gate', d['status'], [(c['metricKey'], c.get('actualValue')) for c in d['conditions'] if c['status'] != 'OK' or 'coverage' in c['metricKey']])"
    printf 'user = "%s:"\n' "$(< ~/.sonar-token)" | curl -sf -K - -o {{logs}}/issues.json \
        "https://sonarcloud.io/api/issues/search?componentKeys={{sonar_project}}&pullRequest={{pr}}&resolved=false&ps=100"
    python3 -c "import json; d=json.load(open('{{logs}}/issues.json')); print('issues', d['total']); [print(' ', i['severity'], i['component'].split('/')[-1] + ':' + str(i.get('line')), i['rule'], i['message']) for i in d['issues']]"

# The failing lines of a CI run's log. Usage: just ci-log <run id>
ci-log run:
    gh run view {{run}} --log-failed | grep -E "ERROR|FAIL|Tests run:.*Fail|expected" | head -40 || true
