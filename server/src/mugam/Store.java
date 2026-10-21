package mugam;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Accounts and their devices, kept in memory and saved to one JSON file after every change
 * (written to a temp file, then moved into place, so a crash never leaves half a file).
 *
 * What is stored about a person: a username, a display name, each device's PUBLIC key,
 * and hashes of their recovery codes. No face, no face template, no password. The face
 * never leaves the person's device.
 */
public final class Store {

    public static final class Device {
        public final String id, name;
        public final Map<String, Object> jwk;     // public key only
        public final long created;
        public long lastUsed, revokedAt;           // 0 = never / not revoked
        public long recoveredAt;                   // when a recovery code added this device; 0 = it didn't
        Device(String id, String name, Map<String, Object> jwk, long created) {
            this.id = id; this.name = name; this.jwk = jwk; this.created = created;
        }
        public boolean active() { return revokedAt == 0; }
    }

    public static final class User {
        public final String username;
        public String displayName;
        public final long created;
        public final List<Device> devices = new ArrayList<>();
        public String codeSalt = "";
        public final List<String> codeHashes = new ArrayList<>();   // "" once used
        User(String username, String displayName, long created) {
            this.username = username; this.displayName = displayName; this.created = created;
        }
        public Device device(String id) {
            for (Device d : devices) if (d.id.equals(id)) return d;
            return null;
        }
        public long activeDevices() { return devices.stream().filter(Device::active).count(); }
        public long codesLeft() { return codeHashes.stream().filter(h -> !h.isEmpty()).count(); }
    }

    private final Path file;
    private final Map<String, User> users = new LinkedHashMap<>();

    public Store(Path file) throws IOException {
        this.file = file;
        if (Files.exists(file)) load();
    }

    public synchronized User get(String username) { return users.get(username); }
    public synchronized boolean exists(String username) { return users.containsKey(username); }
    public synchronized int count() { return users.size(); }

    public synchronized User create(String username, String displayName, long now) {
        if (users.containsKey(username)) throw new IllegalStateException("taken");
        User u = new User(username, displayName, now);
        users.put(username, u);
        return u;
    }

    public synchronized Device addDevice(User u, String name, Map<String, Object> jwk, long now) {
        Device d = new Device(Crypto.randomToken(12), name, jwk, now);
        u.devices.add(d);
        return d;
    }

    public synchronized void delete(String username) { users.remove(username); }

    /** Saves everything. Called by Auth after each change, inside its lock. */
    public synchronized void save() {
        List<Object> list = new ArrayList<>();
        for (User u : users.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("username", u.username);
            m.put("displayName", u.displayName);
            m.put("created", (double) u.created);
            m.put("codeSalt", u.codeSalt);
            m.put("codeHashes", new ArrayList<Object>(u.codeHashes));
            List<Object> ds = new ArrayList<>();
            for (Device d : u.devices) {
                Map<String, Object> dm = new LinkedHashMap<>();
                dm.put("id", d.id); dm.put("name", d.name); dm.put("jwk", d.jwk);
                dm.put("created", (double) d.created); dm.put("lastUsed", (double) d.lastUsed); dm.put("revokedAt", (double) d.revokedAt);
                dm.put("recoveredAt", (double) d.recoveredAt);
                ds.add(dm);
            }
            m.put("devices", ds);
            list.add(m);
        }
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", 1.0);
        root.put("users", list);
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, Json.write(root), StandardCharsets.UTF_8);
            try { Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------")); }
            catch (UnsupportedOperationException ignored) { }     // Windows
            try { Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
            catch (AtomicMoveNotSupportedException e) { Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING); }
        } catch (IOException e) { throw new IllegalStateException("could not save accounts", e); }
    }

    @SuppressWarnings("unchecked")
    private void load() throws IOException {
        Map<String, Object> root = Json.object(Files.readString(file, StandardCharsets.UTF_8));
        for (Object o : (List<Object>) root.get("users")) {
            Map<String, Object> m = (Map<String, Object>) o;
            User u = new User((String) m.get("username"), (String) m.get("displayName"), ((Double) m.get("created")).longValue());
            u.codeSalt = (String) m.get("codeSalt");
            for (Object h : (List<Object>) m.get("codeHashes")) u.codeHashes.add((String) h);
            for (Object od : (List<Object>) m.get("devices")) {
                Map<String, Object> dm = (Map<String, Object>) od;
                Device d = new Device((String) dm.get("id"), (String) dm.get("name"), (Map<String, Object>) dm.get("jwk"),
                                      ((Double) dm.get("created")).longValue());
                d.lastUsed = ((Double) dm.get("lastUsed")).longValue();
                d.revokedAt = ((Double) dm.get("revokedAt")).longValue();
                Object rec = dm.get("recoveredAt");
                d.recoveredAt = rec instanceof Double x ? x.longValue() : 0;
                u.devices.add(d);
            }
            users.put(u.username, u);
        }
    }
}
