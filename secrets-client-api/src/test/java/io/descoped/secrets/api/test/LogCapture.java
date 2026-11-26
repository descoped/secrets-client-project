package io.descoped.secrets.api.test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Collects what one logger logs, through {@code java.util.logging} (the default backend of {@code System.Logger}).
 */
final class LogCapture extends Handler implements AutoCloseable {

    private final Logger logger;
    private final List<String> messages = new CopyOnWriteArrayList<>();

    LogCapture(Class<?> type) {
        this.logger = Logger.getLogger(type.getName());
        logger.addHandler(this);
    }

    @Override
    public void publish(LogRecord logRecord) {
        synchronized (messages) {
            messages.add(logRecord.getMessage());
            messages.notifyAll();
        }
    }

    @Override
    public void flush() {
        // Nothing is buffered.
    }

    @Override
    public void close() {
        logger.removeHandler(this);
    }

    List<String> messages() {
        return List.copyOf(messages);
    }

    /**
     * Runs the garbage collector until something is logged, at most {@code seconds}, and returns what was logged.
     * Cleaners log after a collection has found their object unreachable.
     */
    List<String> collectUntilLogged(int seconds) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        synchronized (messages) {
            while (messages.isEmpty() && System.nanoTime() < deadline) {
                System.gc();
                messages.wait(20);
            }
        }
        return messages();
    }
}
