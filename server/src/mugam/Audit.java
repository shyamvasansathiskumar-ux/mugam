package mugam;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Security log: every sign-in, failure, new device, revocation and recovery, as a chain in which
 * each line holds an HMAC-SHA256 of the line before (the same design as Pathivu, with a key).
 * Append-only file.
 *
 * The key is derived from the pepper. Someone who can edit the log file but doesn't have the
 * pepper can't forge a valid chain. Someone who has both can, which is why the pepper should be
 * kept away from the data (see SECURITY.md). Cutting lines off the end is caught at runtime (the
 * file is shorter than the server's memory) and, across restarts, by comparing the head hash with
 * a copy kept somewhere else.
 *
 * Privacy: the log never stores a username. It stores a "subject", an HMAC of the account key
 * (username plus creation time), so a later account with the same username never sees the
 * earlier one's events, and deleting an account leaves no readable name behind.
 */
public final class Audit {

    public record Event(long seq, long at, String subject, String type, String detail, String prev, String hash) {
        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("seq", (double) seq); m.put("at", (double) at); m.put("subject", subject);
            m.put("type", type); m.put("detail", detail); m.put("prev", prev); m.put("hash", hash);
            return m;
        }
    }

    public static final String GENESIS = "0".repeat(64);

    private final Path file;
    private final String pepper;
    private final List<Event> events = new ArrayList<>();

    private final byte[] key;

    public Audit(Path file, String pepper) throws IOException {
        this.file = file;
        this.pepper = pepper;
        this.key = Crypto.sha256Hex("mugam-audit-key|" + pepper).getBytes(StandardCharsets.UTF_8);
        events.addAll(read());
    }

    private List<Event> read() throws IOException {
        List<Event> out = new ArrayList<>();
        if (!Files.exists(file)) return out;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            Map<String, Object> m;
            try { m = Json.object(line); } catch (IllegalArgumentException e) { out.add(new Event(out.size() + 1, 0, "?", "UNREADABLE", "", "", "")); continue; }
            out.add(new Event(((Double) m.get("seq")).longValue(), ((Double) m.get("at")).longValue(),
                (String) m.get("subject"), (String) m.get("type"), (String) m.get("detail"),
                (String) m.get("prev"), (String) m.get("hash")));
        }
        return out;
    }

    public String subject(String accountKey) { return Crypto.hmacHex(key, "subject|" + accountKey).substring(0, 32); }

    String hash(String prev, long seq, long at, String subject, String type, String detail) {
        return Crypto.hmacHex(key, String.join("|", prev, Long.toString(seq), Long.toString(at), subject, type, detail));
    }

    public synchronized Event append(String username, String type, String detail, long now) {
        String subject = username == null ? "-" : subject(username);
        String prev = events.isEmpty() ? GENESIS : events.get(events.size() - 1).hash();
        long seq = events.size() + 1;
        String clean = detail == null ? "" : detail.replaceAll("[\\p{Cntrl}]", " ");
        if (clean.length() > 200) clean = clean.substring(0, 200);
        Event e = new Event(seq, now, subject, type, clean, prev, hash(prev, seq, now, subject, type, clean));
        events.add(e);
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            Files.writeString(file, Json.write(e.toMap()) + "\n", StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.SYNC);
        } catch (IOException x) { throw new IllegalStateException("could not write the security log", x); }
        return e;
    }

    /**
     * Re-reads the file and re-walks the whole chain. Returns the first broken sequence number,
     * or 0 if it is intact. A file shorter than what this server has written counts as broken
     * at the first missing line; a line that differs from memory counts as broken there.
     */
    public synchronized long firstBroken() {
        List<Event> disk;
        try { disk = read(); } catch (IOException e) { return 1; }
        long chain = walk(disk);
        if (chain != 0) return chain;
        if (disk.size() < events.size()) return disk.size() + 1;
        for (int k = 0; k < events.size(); k++) if (!events.get(k).hash().equals(disk.get(k).hash())) return k + 1;
        return walk(events);
    }

    private long walk(List<Event> list) {
        String prev = GENESIS;
        for (Event e : list) {
            if (!e.prev().equals(prev) || !e.hash().equals(hash(e.prev(), e.seq(), e.at(), e.subject(), e.type(), e.detail())))
                return e.seq();
            prev = e.hash();
        }
        return 0;
    }

    public synchronized String head() { return events.isEmpty() ? GENESIS : events.get(events.size() - 1).hash(); }
    public synchronized int size() { return events.size(); }

    public synchronized List<Map<String, Object>> forUser(String username, int limit) {
        String s = subject(username);
        List<Map<String, Object>> out = new ArrayList<>();
        for (int k = events.size() - 1; k >= 0 && out.size() < limit; k--)
            if (events.get(k).subject().equals(s)) out.add(events.get(k).toMap());
        return out;
    }

    /** For tests: lets a test tamper with history the way someone with disk access could. */
    synchronized void tamperForTest(int index, String newDetail) {
        Event e = events.get(index);
        events.set(index, new Event(e.seq(), e.at(), e.subject(), e.type(), newDetail, e.prev(), e.hash()));
    }
}
