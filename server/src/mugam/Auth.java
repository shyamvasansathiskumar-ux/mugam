package mugam;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The whole sign-in protocol, with no HTTP in it, so every rule can be tested directly.
 *
 *   1. The browser asks for a challenge (begin).
 *   2. On the person's device, Mugam checks their face (match + liveness). Only then does it
 *      use the device's private key, which can't be exported, to sign
 *      clientData = {type, challenge, origin, username, deviceId, face}.
 *   3. The server checks the challenge (one use, 2 minutes, right type, right user), the origin,
 *      and the signature against that device's PUBLIC key (finish).
 *
 * The server never receives a face, a template or a secret it would have to protect. Someone
 * who steals the whole database gets public keys, which sign nothing.
 */
public final class Auth {

    public static final class AuthError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final int status;
        public AuthError(int status, String message) { super(message); this.status = status; }
    }

    public static final long CHALLENGE_TTL_MS = 120_000;
    public static final long SESSION_IDLE_MS = 15 * 60_000;
    public static final long SESSION_MAX_MS = 12 * 60 * 60_000;
    public static final long STEP_UP_MS = 5 * 60_000;           // sensitive actions need a sign-in this recent
    public static final int MAX_FAILURES = 5;
    public static final long FAILURE_WINDOW_MS = 15 * 60_000;
    public static final int MAX_DEVICES = 10;
    public static final int RECOVERY_CODES = 10;
    /** For this long after a recovery code adds a device, that device can't remove others or replace codes. */
    public static final long RECOVERY_HOLD_MS = 24 * 60 * 60_000;
    static final String GENERIC = "Sign-in didn't work. Try again.";

    record Challenge(String id, String type, String username, String value, long expires) { }

    public record Session(String token, String username, String deviceId, long created, long signedInAt, long[] lastSeen) { }

    private final Store store;
    private final Audit audit;
    private final String origin;
    private final Clock clock;
    private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> failures = new HashMap<>();

    public Auth(Store store, Audit audit, String origin, Clock clock) {
        this.store = store; this.audit = audit; this.origin = origin; this.clock = clock;
    }

    long now() { return clock.millis(); }

    // ------------------------------------------------------------------ validation

    public static String username(Object raw) {
        if (!(raw instanceof String s)) throw new AuthError(400, "Enter a username.");
        String u = s.trim().toLowerCase();
        if (!u.matches("[a-z0-9][a-z0-9._-]{2,31}"))
            throw new AuthError(400, "Usernames are 3–32 characters: letters, numbers, dot, dash or underscore.");
        return u;
    }

    static String label(Object raw, String what, int max) {
        if (!(raw instanceof String s)) throw new AuthError(400, "Enter a " + what + ".");
        String t = s.replaceAll("[\\p{Cntrl}\\p{Cf}]", "").trim();     // no control or invisible format characters
        if (t.isEmpty() || t.length() > max) throw new AuthError(400, "The " + what + " must be 1–" + max + " characters.");
        return t;
    }

    // ------------------------------------------------------------------ challenges

    private Map<String, Object> issue(String type, String username) {
        purge();
        if (challenges.size() > 50_000) throw new AuthError(503, "Busy. Try again in a minute.");
        Challenge c = new Challenge(Crypto.randomToken(16), type, username, Crypto.randomToken(32), now() + CHALLENGE_TTL_MS);
        challenges.put(c.id(), c);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("challengeId", c.id());
        out.put("username", c.username());          // the exact (normalised) name the device must sign
        out.put("challenge", c.value());
        out.put("origin", origin);
        out.put("expiresInMs", (double) CHALLENGE_TTL_MS);
        return out;
    }

    private void purge() {
        long t = now();
        challenges.values().removeIf(c -> c.expires() < t);
        sessions.values().removeIf(s -> expired(s, t));
    }

    /** Takes a challenge out (single use, even if the rest fails) and checks the signed clientData against it. */
    private Map<String, Object> consume(Map<String, Object> body, String type, String expectedUser) {
        String id = Json.str(body, "challengeId", 64);
        Challenge c = challenges.remove(id);
        if (c == null || c.expires() < now() || !c.type().equals(type)) throw new AuthError(401, GENERIC);
        if (expectedUser != null && !expectedUser.equals(c.username())) throw new AuthError(401, GENERIC);
        String clientData = Json.str(body, "clientData", 4096);
        Map<String, Object> cd;
        try { cd = Json.object(clientData); } catch (IllegalArgumentException e) { throw new AuthError(400, GENERIC); }
        if (!type.equals(cd.get("type")) || !Crypto.same(c.value(), String.valueOf(cd.get("challenge")))
            || !origin.equals(cd.get("origin")) || !c.username().equals(cd.get("username")))
            throw new AuthError(401, GENERIC);
        Map<String, Object> out = new HashMap<>(cd);
        out.put("_challenge", c);
        out.put("_raw", clientData);
        return out;
    }

    private static boolean signed(PublicKey key, Map<String, Object> cd, Map<String, Object> body) {
        byte[] sig;
        try { sig = Crypto.unb64(Json.str(body, "signature", 200)); } catch (IllegalArgumentException e) { return false; }
        return Crypto.verify(key, ((String) cd.get("_raw")).getBytes(StandardCharsets.UTF_8), sig);
    }

    // ------------------------------------------------------------------ lockout
    //
    // Only wrong RECOVERY CODES count toward the lockout, because a code is the one secret here
    // that could be guessed. A device signature can't be guessed, so failed sign-ins are logged
    // but never lock anyone out: otherwise anyone could lock any user out with no secret at all.

    private synchronized boolean locked(String username) {
        Deque<Long> d = failures.get(username);
        if (d == null) return false;
        long cutoff = now() - FAILURE_WINDOW_MS;
        while (!d.isEmpty() && d.peekFirst() < cutoff) d.pollFirst();
        return d.size() >= MAX_FAILURES;
    }

    private synchronized void fail(String username, String why) {
        failures.computeIfAbsent(username, k -> new ArrayDeque<>()).addLast(now());
        if (failures.size() > 100_000) failures.clear();         // bounded memory; codes stay slow to guess
        Store.User user = store.get(username);
        if (user != null) audit.append(key(user), "RECOVERY_FAILED", why, now());
    }

    private void logFailedSignIn(String username, String why) {
        Store.User user = store.get(username);
        if (user != null) audit.append(key(user), "SIGN_IN_FAILED", why, now());
    }

    /** The log's account key: the username plus the moment the account was made, so a later
     *  account with the same name never sees the old one's history. */
    static String key(Store.User u) { return u.username + "#" + u.created; }

    // ------------------------------------------------------------------ registration

    public Map<String, Object> registerBegin(Map<String, Object> body) {
        String u = username(body.get("username"));
        if (store.exists(u)) throw new AuthError(409, "That username is taken.");
        return issue("mugam.register", u);
    }

    public synchronized Map<String, Object> registerFinish(Map<String, Object> body) {
        Map<String, Object> cd = consume(body, "mugam.register", null);
        Challenge c = (Challenge) cd.get("_challenge");
        String display = label(body.get("displayName"), "name", 60);
        String deviceName = label(body.get("deviceName"), "device name", 40);
        Map<String, Object> jwk = Json.obj(body, "publicKey");
        PublicKey key;
        try { key = Crypto.publicKeyFromJwk(jwk); } catch (IllegalArgumentException e) { throw new AuthError(400, e.getMessage()); }
        if (!signed(key, cd, body)) throw new AuthError(401, GENERIC);           // proves the device holds the private key
        if (store.exists(c.username())) throw new AuthError(409, "That username is taken.");
        Store.User user = store.create(c.username(), display, now());
        Store.Device d = store.addDevice(user, deviceName, publicOnly(jwk), now());
        List<Object> codes = newCodes(user);
        store.save();
        audit.append(key(user), "ACCOUNT_CREATED", "device " + d.id + " (" + d.name + ")", now());
        Map<String, Object> out = session(user, d);
        out.put("recoveryCodes", codes);
        return out;
    }

    private static Map<String, Object> publicOnly(Map<String, Object> jwk) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kty", "EC"); m.put("crv", "P-256"); m.put("x", jwk.get("x")); m.put("y", jwk.get("y"));
        return m;
    }

    private List<Object> newCodes(Store.User user) {
        byte[] salt = new byte[16];
        Crypto.RANDOM.nextBytes(salt);
        user.codeSalt = Crypto.b64(salt);
        user.codeHashes.clear();
        List<Object> codes = new ArrayList<>();
        for (int k = 0; k < RECOVERY_CODES; k++) {
            String code = Crypto.newRecoveryCode();
            codes.add(code);
            user.codeHashes.add(Crypto.hashCode(Crypto.normaliseCode(code), salt));
        }
        return codes;
    }

    // ------------------------------------------------------------------ sign-in

    /**
     * Unknown usernames get a challenge too, so this endpoint doesn't reveal who has an account.
     * A locked username gets the same "too many attempts" answer whether or not it exists.
     */
    public Map<String, Object> loginBegin(Map<String, Object> body) {
        String u = username(body.get("username"));
        return issue("mugam.login", u);       // the browser already knows its own device id
    }

    public synchronized Map<String, Object> loginFinish(Map<String, Object> body) {
        Map<String, Object> cd = consume(body, "mugam.login", null);
        Challenge c = (Challenge) cd.get("_challenge");
        String u = c.username();
        Store.User user = store.get(u);
        String deviceId = String.valueOf(cd.get("deviceId"));
        Store.Device d = user == null ? null : user.device(deviceId);
        if (d == null || !d.active()) { logFailedSignIn(u, "unknown or removed device"); throw new AuthError(401, GENERIC); }
        if (!signed(Crypto.publicKeyFromJwk(d.jwk), cd, body)) { logFailedSignIn(u, "bad signature from device " + d.id); throw new AuthError(401, GENERIC); }
        d.lastUsed = now();
        store.save();
        audit.append(key(user), "SIGNED_IN", "device " + d.id + " (" + d.name + ")" + faceNote(cd), now());
        return session(user, d);
    }

    private static String faceNote(Map<String, Object> cd) {
        Object f = cd.get("face");
        if (!(f instanceof Map<?, ?> m)) return "";
        Object steps = m.get("steps");
        return steps == null ? "" : "; liveness " + steps;    // reported by the device; logged, never trusted
    }

    // ------------------------------------------------------------------ recovery

    public Map<String, Object> recoverBegin(Map<String, Object> body) {
        String u = username(body.get("username"));
        if (locked(u)) throw new AuthError(429, "Too many attempts. Wait 15 minutes and try again.");
        return issue("mugam.recover", u);
    }

    private static final byte[] DUMMY_SALT = new byte[16];

    /**
     * A recovery code adds THIS device as a new one. Each code works once.
     * The slow hash runs outside the lock (so recovery attempts can't stall every sign-in),
     * and runs for unknown usernames too (so timing doesn't reveal who has an account).
     */
    public Map<String, Object> recoverFinish(Map<String, Object> body) {
        Map<String, Object> cd = consume(body, "mugam.recover", null);
        Challenge c = (Challenge) cd.get("_challenge");
        String u = c.username();
        if (locked(u)) throw new AuthError(429, "Too many attempts. Wait 15 minutes and try again.");
        String code = Crypto.normaliseCode(Json.str(body, "recoveryCode", 40));
        Store.User peek = store.get(u);
        String salt = peek == null ? null : peek.codeSalt;
        String h = Crypto.hashCode(code.length() == 12 ? code : "XXXXXXXXXXXX", salt == null ? DUMMY_SALT : Crypto.unb64(salt));
        return recoverCommit(u, code, salt, h, cd, body);
    }

    private synchronized Map<String, Object> recoverCommit(String u, String code, String salt, String h,
                                                            Map<String, Object> cd, Map<String, Object> body) {
        Store.User user = store.get(u);
        if (user == null || code.length() != 12 || !user.codeSalt.equals(salt)) { fail(u, "bad recovery code"); throw new AuthError(401, "That recovery code didn't work."); }
        int hit = -1;
        for (int k = 0; k < user.codeHashes.size(); k++) if (!user.codeHashes.get(k).isEmpty() && Crypto.same(user.codeHashes.get(k), h)) hit = k;
        if (hit < 0) { fail(u, "bad recovery code"); throw new AuthError(401, "That recovery code didn't work."); }
        Map<String, Object> jwk = Json.obj(body, "publicKey");
        PublicKey key;
        try { key = Crypto.publicKeyFromJwk(jwk); } catch (IllegalArgumentException e) { throw new AuthError(400, e.getMessage()); }
        if (!signed(key, cd, body)) { fail(u, "bad signature during recovery"); throw new AuthError(401, GENERIC); }
        if (user.activeDevices() >= MAX_DEVICES) throw new AuthError(409, "This account already has " + MAX_DEVICES + " devices. Remove one first.");
        user.codeHashes.set(hit, "");                       // burnt, whatever happens next
        Store.Device d = store.addDevice(user, label(body.get("deviceName"), "device name", 40), publicOnly(jwk), now());
        d.recoveredAt = now();
        store.save();
        failures.remove(u);
        audit.append(key(user), "RECOVERY_CODE_USED", "new device " + d.id + " (" + d.name + "); " + user.codesLeft() + " codes left", now());
        return session(user, d);
    }

    // ------------------------------------------------------------------ sessions

    private Map<String, Object> session(Store.User user, Store.Device d) {
        long t = now();
        Session s = new Session(Crypto.randomToken(32), user.username, d.id, t, t, new long[]{t});
        sessions.put(s.token(), s);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("session", s.token());
        out.put("username", user.username);
        out.put("displayName", user.displayName);
        out.put("deviceId", d.id);
        return out;
    }

    private static boolean expired(Session s, long t) {
        return t - s.lastSeen()[0] > SESSION_IDLE_MS || t - s.created() > SESSION_MAX_MS;
    }

    /** The signed-in session for a token, or 401. A removed device ends its sessions at once. */
    public Session session(String token) {
        Session s = token == null ? null : sessions.get(token);
        long t = now();
        if (s == null || expired(s, t)) { if (s != null) sessions.remove(token); throw new AuthError(401, "Please sign in."); }
        Store.User u = store.get(s.username());
        Store.Device d = u == null ? null : u.device(s.deviceId());
        if (d == null || !d.active()) { sessions.remove(token); throw new AuthError(401, "Please sign in."); }
        s.lastSeen()[0] = t;
        return s;
    }

    private void stepUp(Session s) {
        if (now() - s.signedInAt() > STEP_UP_MS) throw new AuthError(403, "For this, sign in with your face again first.");
    }

    /**
     * Removing devices, replacing recovery codes and deleting the account also need a device that
     * wasn't added by a recovery code in the last 24 hours. A stolen code then can't lock the
     * owner out at once: the owner sees "Recovery code used" in their log and can remove the
     * new device first.
     */
    private void owner(Session s) {
        stepUp(s);
        Store.User u = store.get(s.username());
        Store.Device d = u == null ? null : u.device(s.deviceId());
        if (d != null && d.recoveredAt > 0 && now() - d.recoveredAt < RECOVERY_HOLD_MS && u.activeDevices() > 1)
            throw new AuthError(403, "This device was added with a recovery code less than 24 hours ago. "
                + "Use one of your other devices, or wait until the 24 hours have passed.");
    }

    public void logout(String token) {
        Session s = token == null ? null : sessions.remove(token);
        Store.User u = s == null ? null : store.get(s.username());
        if (u != null) audit.append(key(u), "SIGNED_OUT", "device " + s.deviceId(), now());
    }

    public Map<String, Object> me(Session s) {
        Store.User u = store.get(s.username());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("username", u.username);
        out.put("displayName", u.displayName);
        out.put("currentDevice", s.deviceId());
        out.put("recoveryCodesLeft", (double) u.codesLeft());
        List<Object> ds = new ArrayList<>();
        for (Store.Device d : u.devices) {
            if (!d.active()) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", d.id); m.put("name", d.name); m.put("created", (double) d.created); m.put("lastUsed", (double) d.lastUsed);
            ds.add(m);
        }
        out.put("devices", ds);
        out.put("log", audit.forUser(key(u), 30));
        out.put("logIntact", audit.firstBroken() == 0);
        out.put("logHead", audit.head());
        return out;
    }

    public synchronized void revokeDevice(Session s, Map<String, Object> body) {
        owner(s);
        Store.User u = store.get(s.username());
        Store.Device d = u.device(Json.str(body, "deviceId", 64));
        if (d == null || !d.active()) throw new AuthError(404, "No such device.");
        if (u.activeDevices() == 1 && u.codesLeft() == 0)
            throw new AuthError(409, "This is your last device and you have no recovery codes left. Make new codes first.");
        d.revokedAt = now();
        store.save();
        sessions.values().removeIf(x -> x.username().equals(u.username) && x.deviceId().equals(d.id));
        audit.append(key(u), "DEVICE_REMOVED", "device " + d.id + " (" + d.name + ") removed from device " + s.deviceId(), now());
    }

    public synchronized Map<String, Object> newRecoveryCodes(Session s) {
        owner(s);
        Store.User u = store.get(s.username());
        List<Object> codes = newCodes(u);
        store.save();
        audit.append(key(u), "RECOVERY_CODES_REPLACED", "old codes no longer work", now());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("recoveryCodes", codes);
        return out;
    }

    /** Records that the face was set up again on this device (the template itself never leaves it). */
    public void faceRenewed(Session s) {
        stepUp(s);
        Store.User u = store.get(s.username());
        audit.append(key(u), "FACE_SET_UP_AGAIN", "device " + s.deviceId(), now());
    }

    /** Deletes the account and every session. The security log keeps only pseudonymous lines. */
    public synchronized void deleteAccount(Session s) {
        owner(s);
        String u = s.username();
        audit.append(key(store.get(u)), "ACCOUNT_DELETED", "all devices and recovery codes erased", now());
        store.delete(u);
        store.save();
        sessions.values().removeIf(x -> x.username().equals(u));
    }

    // ------------------------------------------------------------------ for tests and the server

    public int liveChallenges() { purge(); return challenges.size(); }
    public Audit audit() { return audit; }
    public String origin() { return origin; }
}
