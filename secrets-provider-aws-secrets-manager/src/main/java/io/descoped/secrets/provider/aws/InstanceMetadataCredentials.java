package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.http.Http;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Temporary credentials of the EC2 instance profile, from instance metadata with IMDSv2 only: a session token from
 * {@code PUT /latest/api/token}, kept in guarded memory and sent from there, then the role's name and its
 * credentials, parsed in guarded memory ({@link CredentialsDocument}). IMDSv1, without a token, is never used.
 */
final class InstanceMetadataCredentials implements CredentialsProvider.Source {

    static final String SOURCE = "EC2 instance metadata";

    private static final String TOKEN_PATH = "/latest/api/token";
    private static final String ROLES_PATH = "/latest/meta-data/iam/security-credentials/";
    private static final String TOKEN_HEADER = "X-aws-ec2-metadata-token";
    /** Six hours, the most IMDS allows; a token is used for one fetch only. */
    private static final String TOKEN_TTL = "X-aws-ec2-metadata-token-ttl-seconds: 21600";
    private static final Pattern ROLE = Pattern.compile("[\\w+=,.@-]{1,128}");

    private final SecretMemory memory;
    private final Http.Target target;
    private final Http.Timeouts timeouts;

    InstanceMetadataCredentials(SecretMemory memory, Http.Target target, Http.Timeouts timeouts) {
        this.memory = memory;
        this.target = target;
        this.timeouts = timeouts;
    }

    @Override
    public Credentials fetch() {
        try (Secret put = Http.request(memory, target, "PUT", TOKEN_PATH, List.of(TOKEN_TTL), List.of(), null);
             Http.Response token = exchange(put, "the session token")) {
            String role = role(token.body());
            try (Http.Response credentials = get(token.body(), ROLES_PATH + role, "the role's credentials")) {
                return CredentialsDocument.parse(memory, credentials.body(), SOURCE);
            }
        }
    }

    /** The instance profile's role: the first line of the list. */
    private String role(Secret token) {
        try (Http.Response roles = get(token, ROLES_PATH, "the role")) {
            String list = roles.body().withSegment(segment -> new String(segment.toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8));
            String role = list.lines().findFirst().orElse("").strip();
            if (!ROLE.matcher(role).matches()) {
                throw new SecretManagerException(SOURCE + " has no instance profile role");
            }
            return role;
        }
    }

    /** {@code GET path} with the session token. */
    private Http.Response get(Secret token, String path, String what) {
        Secret request = token.withSegment(t -> Http.request(memory, target, "GET", path, List.of(),
                List.of(new Http.SecretHeader(TOKEN_HEADER, "", t)), null));
        try (request) {
            return exchange(request, what);
        }
    }

    private Http.Response exchange(Secret request, String what) {
        Http.Response response;
        try {
            response = Http.exchange(target, request, timeouts, memory);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot reach " + SOURCE + " for " + what + ": "
                    + e.getClass().getSimpleName(), e);
        }
        if (response.status() != 200) {
            response.close();
            throw new SecretManagerException(SOURCE + " returned HTTP " + response.status() + " for " + what);
        }
        return response;
    }
}
