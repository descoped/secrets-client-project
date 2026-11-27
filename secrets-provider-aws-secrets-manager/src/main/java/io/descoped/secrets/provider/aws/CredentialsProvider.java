package io.descoped.secrets.provider.aws;

import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;

/**
 * Holds the current credentials from one source, fetched on first use and again when temporary ones have less than
 * five minutes left. The credentials are used under a read lock, so that a refresh never wipes them while a request
 * is being signed.
 */
final class CredentialsProvider implements AutoCloseable {

    /** A place AWS credentials come from. */
    @FunctionalInterface
    interface Source {

        /**
         * Fetches credentials; the caller owns and closes them.
         *
         * @return the credentials
         */
        Credentials fetch();
    }

    static final Duration REFRESH_MARGIN = Duration.ofMinutes(5);

    private final Source source;
    private final Clock clock;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private Credentials current;
    private boolean closed;

    CredentialsProvider(Source source, Clock clock) {
        this.source = source;
        this.clock = clock;
    }

    /** Runs {@code action} with valid credentials; they must not be kept after it returns. */
    <R> R withCredentials(Function<Credentials, R> action) {
        lock.readLock().lock();
        try {
            if (isUsable()) {
                return action.apply(current);
            }
        } finally {
            lock.readLock().unlock();
        }
        lock.writeLock().lock();
        try {
            if (closed) {
                throw new IllegalStateException("Client is closed");
            }
            if (!isUsable()) {
                Credentials fresh = source.fetch();
                if (current != null) {
                    current.close();
                }
                current = fresh;
            }
            // Downgrade, so that other threads can sign with the same credentials meanwhile.
            lock.readLock().lock();
        } finally {
            lock.writeLock().unlock();
        }
        try {
            return action.apply(current);
        } finally {
            lock.readLock().unlock();
        }
    }

    private boolean isUsable() {
        return !closed && current != null && !current.expiresWithin(REFRESH_MARGIN, clock.instant());
    }

    /** Wipes the credentials, after the signing in other threads. Idempotent. */
    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            closed = true;
            if (current != null) {
                current.close();
                current = null;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
}
