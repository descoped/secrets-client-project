package io.descoped.secrets.api.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretMemory;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Map;

/**
 * Run in a child JVM by {@link GuardPageTest}: reads memory it should not be able to read, through raw addresses, and
 * prints {@code READ <byte>} if that worked or {@code FAULT <exception>} if the JVM turned the fault into one. A
 * fault the JVM does not survive ends the process instead.
 */
public final class GuardProbe {

    private GuardProbe() {
    }

    @SuppressWarnings("restricted")
    public static void main(String[] args) {
        String mode = args[0];
        if (mode.equals("create")) {
            create(args.length > 1 ? args[1] : "required");
            return;
        }
        try (SecretMemory memory = SecretMemory.create(Map.of());
             Secret secret = memory.fromBytes(new byte[]{42, 42, 42, 42})) {
            long address = secret.withSegment(MemorySegment::address);
            long target = switch (mode) {
                // In bounds, while the secret is read: must work, so the probe itself is known to work.
                case "control" -> address;
                // The byte before the first block of the first slab: the guard page in front of it.
                case "before" -> address - 1;
                // The value itself, after the callback returned: the page is no longer accessible.
                case "after" -> address;
                default -> throw new IllegalArgumentException(mode);
            };
            byte value;
            if (mode.equals("control")) {
                value = secret.withSegment(s -> MemorySegment.ofAddress(target).reinterpret(1)
                        .get(ValueLayout.JAVA_BYTE, 0));
            } else {
                value = MemorySegment.ofAddress(target).reinterpret(1).get(ValueLayout.JAVA_BYTE, 0);
            }
            System.out.println("READ " + value);
        } catch (Throwable e) {
            System.out.println("FAULT " + e.getClass().getName());
        }
    }

    /** Creates guarded memory with {@code lock} as {@value SecretMemory#LOCK_KEY}, and prints what happened. */
    private static void create(String lock) {
        try (SecretMemory memory = SecretMemory.create(Map.of(SecretMemory.LOCK_KEY, lock));
             Secret secret = memory.fromBytes(new byte[]{1})) {
            System.out.println("CREATED locked=" + memory.isLocked() + " length=" + secret.length());
        } catch (RuntimeException e) {
            System.out.println("REFUSED " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}
