# secrets-client-project development recipes. Run `just` to list them.
#
# Everything here only builds, tests or reads. What publishes or changes something outside the working tree (push,
# pull request, merge, comment, release) is not a recipe: it is run by hand, and Claude Code asks first
# (.claude/settings.json).

set shell := ["bash", "-euo", "pipefail", "-c"]
set quiet

# The JDK of the baseline (.java-version): from JAVA_HOME if set, else macOS's java_home, else the java on the PATH.
export JAVA_HOME := env("JAVA_HOME", `/usr/libexec/java_home -v "$(cat .java-version)" 2>/dev/null || true`)
# Its tools first on the PATH: the smoke test runs javac, jar and jdeps.
export PATH := JAVA_HOME + "/bin:" + env("PATH")

# The SonarCloud project, one for the whole reactor.
sonar_project := "descoped_secrets-client-project"

default:
    @just --list --unsorted

# ---------------------------------------------------------------- Build and test

# Compile with -Xlint:all -Werror and run every test
build:
    ./mvnw -B verify

# Everything CI checks: build, tests, Javadoc with doclint, and the JPMS smoke test
check:
    ./mvnw -B verify javadoc:javadoc
    src/it/consumer/run.sh

# Tests of one module and what it needs, optionally one test pattern. Usage: just test secrets-provider-mounted [Mounted*]
test module tests="":
    ./mvnw -B verify -pl {{module}} -am -Djacoco.skip=true \
        {{ if tests == "" { "" } else { "-Dsurefire.failIfNoSpecifiedTests=false -Dtest='" + tests + "'" } }}

# Run a test pattern N times in a row and print one result per run (flakiness). Usage: just repeat secrets-provider-mounted 'MountedClientTest' 10
repeat module tests times="10":
    ./mvnw -B -q install -pl {{module}} -am -DskipTests >/dev/null
    for i in $(seq 1 {{times}}); do \
        ./mvnw -B -o verify -pl {{module}} -Djacoco.skip=true -Dsurefire.failIfNoSpecifiedTests=false \
            -Dtest='{{tests}}' 2>&1 | grep -E 'Tests run:.*in ' | sed -E 's/.*Tests run: ([0-9]+), Failures: ([0-9]+), Errors: ([0-9]+).*/\1:\2\3/' \
            | tr '\n' ' '; \
    done; echo

# JaCoCo coverage per module (target/site/jacoco), with a line and branch summary of one module if given
coverage module="":
    ./mvnw -B -q verify -P coverage
    if [ -n "{{module}}" ]; then \
        awk -F, 'NR>1 {printf "%s: lines %d/%d branches %d/%d\n", $3, $9, $8+$9, $7, $6+$7}' {{module}}/target/site/jacoco/jacoco.csv; \
    fi

# The JPMS smoke test: every provider on the module path and the class path, and jdeps
smoke:
    src/it/consumer/run.sh

# Tests on Linux in Docker, where memfd_secret is in use (the repository is mounted read-only). Usage: just linux [modules] [tests]
linux modules="secrets-client-api,secrets-test-support,secrets-provider-safe-configuration,secrets-provider-mounted,secrets-provider-google-secret-manager" tests="":
    docker run --rm -v "$PWD":/src:ro -v secrets-client-m2:/root/.m2 maven:3-eclipse-temurin-25 bash -c \
        'cp -r /src /w && cd /w && rm -rf */target target && mvn -B verify -pl {{modules}} -Djacoco.skip=true \
        {{ if tests == "" { "" } else { "-Dsurefire.failIfNoSpecifiedTests=false -Dtest=" + tests } }} 2>&1 \
        | grep -E "Tests run:.*in |FAIL|ERROR\]|BUILD"'

# Remove build output
clean:
    ./mvnw -B -q clean
    rm -rf target/it-consumer

# ---------------------------------------------------------------- Live tests (not in CI)

# The Google live test against a real project: SECRETS_GOOGLE_TEST_PROJECT and SECRETS_GOOGLE_TEST_CREDENTIALS_PATH set
live-google:
    : "${SECRETS_GOOGLE_TEST_PROJECT:?set SECRETS_GOOGLE_TEST_PROJECT}"
    : "${SECRETS_GOOGLE_TEST_CREDENTIALS_PATH:?set SECRETS_GOOGLE_TEST_CREDENTIALS_PATH (an authorized_user file)}"
    ./mvnw -B verify -pl secrets-provider-google-secret-manager -am -Djacoco.skip=true \
        -Dsurefire.failIfNoSpecifiedTests=false -Dtest=GoogleSecretManagerLiveTest

# ---------------------------------------------------------------- Pull requests (read only)

# A pull request's checks
checks pr:
    gh pr checks {{pr}}

# Wait until a pull request's checks are done (the review included), then show them
wait pr:
    until gh pr checks {{pr}} 2>/dev/null | grep -qE "^review\s+(pass|fail)" \
        && ! gh pr checks {{pr}} | grep -q pending; do sleep 30; done
    gh pr checks {{pr}} | cut -f1,2

# The Claude review on a pull request
review pr:
    gh pr view {{pr}} --json comments -q '.comments[] | select(.author.login=="claude") | .body'

# SonarCloud on a pull request: the quality gate and the open issues (token from ~/.sonar-token, never printed)
sonar pr:
    @curl -sf -o /dev/null -u "$(cat ~/.sonar-token):" "https://sonarcloud.io/api/qualitygates/project_status?projectKey={{sonar_project}}&pullRequest={{pr}}" \
        || { echo "No SonarCloud analysis for pull request {{pr}} (a docs-only change runs no CI)"; exit 1; }
    curl -sf -u "$(cat ~/.sonar-token):" "https://sonarcloud.io/api/qualitygates/project_status?projectKey={{sonar_project}}&pullRequest={{pr}}" \
        | python3 -c "import json,sys; d=json.load(sys.stdin)['projectStatus']; print('gate', d['status'], [(c['metricKey'], c.get('actualValue')) for c in d['conditions'] if c['status'] != 'OK' or 'coverage' in c['metricKey']])"
    curl -sf -u "$(cat ~/.sonar-token):" "https://sonarcloud.io/api/issues/search?componentKeys={{sonar_project}}&pullRequest={{pr}}&resolved=false&ps=100" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print('issues', d['total']); [print(' ', i['severity'], i['component'].split('/')[-1] + ':' + str(i.get('line')), i['rule'], i['message']) for i in d['issues']]"

# The failing steps of a CI run's log. Usage: just ci-log <run id>
ci-log run:
    gh run view {{run}} --log-failed | grep -E "ERROR|FAIL|Tests run:.*Fail|expected" | head -40
