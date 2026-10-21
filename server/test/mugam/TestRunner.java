package mugam;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Plain-Java tests (no JUnit). Part 1 checks the pieces, part 2 the protocol with a fake
 * device (a Java key pair standing in for the browser's WebCrypto key), part 3 attacks it,
 * part 4 runs the real HTTP server.
 */
public class TestRunner {

    static int passed, failed;
    static final List<String> failures = new ArrayList<>();
    interface Body { void run() throws Exception; }

    static void test(String name, Body b) {
        try { b.run(); passed++; System.out.println("  PASS  " + name); }
        catch (Throwable t) { failed++; failures.add(name + " -> " + t); System.out.println("  FAIL  " + name + "\n        " + t); }
    }
    static void check(boolean ok, String msg) { if (!ok) throw new AssertionError(msg); }
    static Auth.AuthError refused(Body b) {
        try { b.run(); } catch (Auth.AuthError e) { return e; } catch (Exception e) { throw new AssertionError("wrong exception " + e); }
        throw new AssertionError("was accepted");
    }

    /** A clock the tests can move forward. */
    static final class TestClock extends Clock {
        long t = Instant.parse("2026-10-21T06:00:00Z").toEpochMilli();
        void plus(long ms) { t += ms; }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId z) { return this; }
        @Override public long millis() { return t; }
        @Override public Instant instant() { return Instant.ofEpochMilli(t); }
    }

    /** Stands in for the browser: a P-256 key pair and WebCrypto-style signing. */
    static final class FakeDevice {
        final KeyPair kp;
        String id;
        FakeDevice() throws Exception {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            kp = g.generateKeyPair();
        }
        Map<String, Object> jwk() {
            ECPublicKey k = (ECPublicKey) kp.getPublic();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kty", "EC"); m.put("crv", "P-256");
            m.put("x", Crypto.b64(fixed(k.getW().getAffineX().toByteArray())));
            m.put("y", Crypto.b64(fixed(k.getW().getAffineY().toByteArray())));
            return m;
        }
        static byte[] fixed(byte[] b) {   // BigInteger bytes -> exactly 32
            byte[] out = new byte[32];
            int n = Math.min(32, b.length);
            System.arraycopy(b, b.length - n, out, 32 - n, n);
            return out;
        }
        String sign(String data) throws Exception {
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initSign(kp.getPrivate());
            s.update(data.getBytes(StandardCharsets.UTF_8));
            return Crypto.b64(s.sign());
        }
    }

    static final String ORIGIN = "https://mugam.test";

    static String clientData(String type, Map<String, Object> ch, String user, String deviceId) {
        Map<String, Object> cd = new LinkedHashMap<>();
        cd.put("type", type); cd.put("challenge", ch.get("challenge")); cd.put("origin", ORIGIN); cd.put("username", user);
        if (deviceId != null) cd.put("deviceId", deviceId);
        Map<String, Object> face = new LinkedHashMap<>();
        face.put("steps", "turnLeft,blink"); face.put("distance", 0.31);
        cd.put("face", face);
        return Json.write(cd);
    }

    static Map<String, Object> body(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int k = 0; k < kv.length; k += 2) m.put((String) kv[k], kv[k + 1]);
        return m;
    }

    static Map<String, Object> register(Auth a, String user, FakeDevice d) throws Exception {
        Map<String, Object> ch = a.registerBegin(body("username", user));
        String cd = clientData("mugam.register", ch, user, null);
        Map<String, Object> r = a.registerFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", d.sign(cd),
            "publicKey", d.jwk(), "displayName", "Shyam Kumar", "deviceName", "MacBook Air"));
        d.id = (String) r.get("deviceId");
        return r;
    }

    static Map<String, Object> login(Auth a, String user, FakeDevice d) throws Exception {
        Map<String, Object> ch = a.loginBegin(body("username", user));
        String cd = clientData("mugam.login", ch, (String) ch.get("username"), d.id);
        return a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", d.sign(cd)));
    }

    static Auth fresh(TestClock clock, Path dir) throws Exception {
        Store store = new Store(dir.resolve("accounts.json"));
        return new Auth(store, new Audit(dir.resolve("log.jsonl"), "pepper-for-tests"), ORIGIN, clock);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("\nPart 1: pieces");
        pieces();
        System.out.println("\nPart 2: protocol");
        protocol();
        System.out.println("\nPart 3: attacks");
        attacks();
        System.out.println("\nPart 4: the real HTTP server");
        http();
        System.out.println("\n" + passed + " passed, " + failed + " failed");
        failures.forEach(f -> System.out.println("  - " + f));
        System.exit(failed == 0 ? 0 : 1);
    }

    // ------------------------------------------------------------------ Part 1

    static void pieces() throws Exception {
        test("JSON: reads and writes, escaping < so a reply can't become HTML", () -> {
            Map<String, Object> m = Json.object("{\"a\":\"x<script>\",\"n\":3,\"l\":[true,null]}");
            check(Json.write(m).equals("{\"a\":\"x\\u003cscript>\",\"n\":3,\"l\":[true,null]}"), Json.write(m));
        });
        test("JSON: refuses duplicate keys (two parsers could read them differently)", () -> {
            try { Json.object("{\"a\":1,\"a\":2}"); throw new AssertionError("accepted"); } catch (IllegalArgumentException e) { }
        });
        test("JSON: refuses deep nesting, trailing junk and raw control characters", () -> {
            for (String bad : List.of("[".repeat(40) + "]".repeat(40), "{} x", "{\"a\":\"\u0001\"}", "{\"a\":\"\\u-001\"}", "{\"a\":\"\\u+0041\"}")) {
                try { Json.parse(bad); throw new AssertionError("accepted " + bad); } catch (IllegalArgumentException e) { }
            }
        });
        test("Keys: a JWK carrying a private part is refused", () -> {
            Map<String, Object> jwk = new FakeDevice().jwk();
            jwk.put("d", "AAAA");
            try { Crypto.publicKeyFromJwk(jwk); throw new AssertionError("accepted"); } catch (IllegalArgumentException e) { }
        });
        test("Keys: a point that is not on the P-256 curve is refused (invalid-curve attack)", () -> {
            Map<String, Object> jwk = new FakeDevice().jwk();
            jwk.put("y", Crypto.b64(new byte[32]));
            try { Crypto.publicKeyFromJwk(jwk); throw new AssertionError("accepted"); } catch (IllegalArgumentException e) { }
        });
        test("Signatures: right key verifies, wrong key or changed message does not", () -> {
            FakeDevice a = new FakeDevice(), b = new FakeDevice();
            byte[] sig = Crypto.unb64(a.sign("hello"));
            check(Crypto.verify(Crypto.publicKeyFromJwk(a.jwk()), "hello".getBytes(StandardCharsets.UTF_8), sig), "own key");
            check(!Crypto.verify(Crypto.publicKeyFromJwk(b.jwk()), "hello".getBytes(StandardCharsets.UTF_8), sig), "other key");
            check(!Crypto.verify(Crypto.publicKeyFromJwk(a.jwk()), "hellO".getBytes(StandardCharsets.UTF_8), sig), "changed message");
        });
        test("Recovery codes: 12 characters, no look-alike letters, typed loosely still works", () -> {
            String c = Crypto.newRecoveryCode();
            check(c.matches("[2-9A-HJKMNP-Z]{4}-[2-9A-HJKMNP-Z]{4}-[2-9A-HJKMNP-Z]{4}"), c);
            check(Crypto.normaliseCode(" " + c.toLowerCase().replace("-", " ") + " ").equals(c.replace("-", "")), "normalise");
        });
    }

    // ------------------------------------------------------------------ Part 2

    static void protocol() throws Exception {
        TestClock clock = new TestClock();
        Path dir = Files.createTempDirectory("mugam");
        Auth a = fresh(clock, dir);
        FakeDevice mac = new FakeDevice();

        test("register: new account, device key proven, 10 recovery codes, session", () -> {
            Map<String, Object> r = register(a, "shyam", mac);
            check(((List<?>) r.get("recoveryCodes")).size() == 10, "codes");
            check(r.get("session") != null && mac.id != null, "session/device");
        });
        test("the server stores no face, no template and no secret: only public keys and code hashes", () -> {
            String saved = Files.readString(dir.resolve("accounts.json"));
            for (String word : List.of("face", "template", "descriptor", "\"d\"", "image"))
                check(!saved.contains(word), "found " + word);
            check(saved.contains("\"kty\":\"EC\""), "public key missing");
        });
        test("sign in with the device key", () -> check(login(a, "shyam", mac).get("session") != null, "no session"));
        test("usernames are case-insensitive and validated", () -> {
            check(login(a, "SHYAM", mac).get("username").equals("shyam"), "case");
            check(refused(() -> a.loginBegin(body("username", "a b"))).status == 400, "bad name accepted");
        });
        test("a taken username can't be registered again", () -> check(refused(() -> register(a, "shyam", new FakeDevice())).status == 409, "status"));
        test("names lose control and invisible characters (no spoofing with RTL marks)", () -> {
            check(Auth.label("Kavya‮\u0007 R", "name", 60).equals("Kavya R"), Auth.label("Kavya‮\u0007 R", "name", 60));
        });
        test("me(): devices and the person's own security log, chain intact", () -> {
            Map<String, Object> me = a.me(a.session((String) login(a, "shyam", mac).get("session")));
            check(((List<?>) me.get("devices")).size() == 1 && Boolean.TRUE.equals(me.get("logIntact")), Json.write(me));
            check(!((List<?>) me.get("log")).isEmpty(), "log empty");
        });
        test("the security log never contains a username (pseudonymous subjects)", () -> {
            check(!Files.readString(dir.resolve("log.jsonl")).contains("shyam"), "username in log");
        });
        test("recovery: a code adds this device once; the same code never works again", () -> {
            FakeDevice phone = new FakeDevice();
            String code = (String) ((List<?>) a.newRecoveryCodes(a.session((String) login(a, "shyam", mac).get("session"))).get("recoveryCodes")).get(0);
            Map<String, Object> r = recover(a, "shyam", code.toLowerCase().replace("-", " "), phone);
            phone.id = (String) r.get("deviceId");
            check(phone.id != null, "no device");
            check(refused(() -> recover(a, "shyam", code, new FakeDevice())).status == 401, "reused");
            check(login(a, "shyam", phone).get("session") != null, "new device can't sign in");
        });
        test("removing a device ends its sessions at once", () -> {
            FakeDevice old = new FakeDevice();
            String code = (String) ((List<?>) a.newRecoveryCodes(a.session((String) login(a, "shyam", mac).get("session"))).get("recoveryCodes")).get(1);
            old.id = (String) recover(a, "shyam", code, old).get("deviceId");
            String oldSession = (String) login(a, "shyam", old).get("session");
            a.revokeDevice(a.session((String) login(a, "shyam", mac).get("session")), body("deviceId", old.id));
            check(refused(() -> a.session(oldSession)).status == 401, "session survived");
            check(refused(() -> login(a, "shyam", old)).status == 401, "removed device signed in");
        });
        test("sessions expire after 15 idle minutes", () -> {
            String s = (String) login(a, "shyam", mac).get("session");
            clock.plus(Auth.SESSION_IDLE_MS + 1);
            check(refused(() -> a.session(s)).status == 401, "still valid");
        });
        test("sensitive actions need a sign-in from the last 5 minutes", () -> {
            Auth.Session s = a.session((String) login(a, "shyam", mac).get("session"));
            clock.plus(Auth.STEP_UP_MS + 1000);
            Auth.Session again = a.session(s.token());
            check(refused(() -> a.newRecoveryCodes(again)).status == 403, "no step-up");
        });
        test("deleting the account removes it; the log keeps only pseudonymous lines", () -> {
            FakeDevice d = new FakeDevice();
            register(a, "kavya", d);
            a.deleteAccount(a.session((String) login(a, "kavya", d).get("session")));
            check(refused(() -> login(a, "kavya", d)).status == 401, "still signs in");
            check(!Files.readString(dir.resolve("accounts.json")).contains("kavya"), "account still saved");
            check(!Files.readString(dir.resolve("log.jsonl")).contains("kavya"), "name in log");
        });
        test("accounts survive a restart (saved to disk, read back)", () -> {
            Auth b = fresh(clock, dir);
            check(login(b, "shyam", mac).get("session") != null, "lost after restart");
        });
    }

    static Map<String, Object> recover(Auth a, String user, String code, FakeDevice d) throws Exception {
        Map<String, Object> ch = a.recoverBegin(body("username", user));
        String cd = clientData("mugam.recover", ch, user, null);
        return a.recoverFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", d.sign(cd),
            "publicKey", d.jwk(), "recoveryCode", code, "deviceName", "Phone"));
    }

    // ------------------------------------------------------------------ Part 3

    static void attacks() throws Exception {
        TestClock clock = new TestClock();
        Path dir = Files.createTempDirectory("mugam");
        Auth a = fresh(clock, dir);
        FakeDevice mac = new FakeDevice(), thief = new FakeDevice();
        register(a, "shyam", mac);
        register(a, "meera", thief);

        test("replay: a captured sign-in can't be sent twice", () -> {
            Map<String, Object> ch = a.loginBegin(body("username", "shyam"));
            String cd = clientData("mugam.login", ch, "shyam", mac.id);
            Map<String, Object> b = body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", mac.sign(cd));
            a.loginFinish(new LinkedHashMap<>(b));
            check(refused(() -> a.loginFinish(new LinkedHashMap<>(b))).status == 401, "replayed");
        });
        test("a challenge expires after 2 minutes", () -> {
            Map<String, Object> ch = a.loginBegin(body("username", "shyam"));
            String cd = clientData("mugam.login", ch, "shyam", mac.id);
            clock.plus(Auth.CHALLENGE_TTL_MS + 1);
            check(refused(() -> a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", mac.sign(cd)))).status == 401, "late");
        });
        test("phishing: a signature made for another website's origin is refused", () -> {
            Map<String, Object> ch = a.loginBegin(body("username", "shyam"));
            String cd = clientData("mugam.login", ch, "shyam", mac.id).replace(ORIGIN, "https://mugarn.test");
            check(refused(() -> a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", mac.sign(cd)))).status == 401, "phish");
        });
        test("a registration challenge can't be used to sign in (type confusion)", () -> {
            Map<String, Object> ch = a.registerBegin(body("username", "newperson"));
            String cd = clientData("mugam.login", ch, "newperson", mac.id);
            check(refused(() -> a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", mac.sign(cd)))).status == 401, "confused");
        });
        test("a challenge issued for one user can't sign in another (username swap)", () -> {
            Map<String, Object> ch = a.loginBegin(body("username", "meera"));
            String cd = clientData("mugam.login", ch, "shyam", mac.id);
            check(refused(() -> a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", mac.sign(cd)))).status == 401, "swapped");
        });
        test("someone else's device key can't sign in to my account", () -> {
            Map<String, Object> ch = a.loginBegin(body("username", "shyam"));
            String cd = clientData("mugam.login", ch, "shyam", mac.id);
            check(refused(() -> a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", thief.sign(cd)))).status == 401, "stolen");
        });
        test("changing one character of the signed data breaks the signature", () -> {
            Map<String, Object> ch = a.loginBegin(body("username", "shyam"));
            String cd = clientData("mugam.login", ch, "shyam", mac.id);
            String sig = mac.sign(cd);
            String changed = cd.replace("turnLeft", "turnLefT");
            check(refused(() -> a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", changed, "signature", sig))).status == 401, "tamper");
        });
        test("failed sign-ins never lock the owner out (no secret-free lockout)", () -> {
            for (int k = 0; k < 8; k++) {                       // an attacker sends junk for "meera" with no key of hers
                Map<String, Object> ch = a.loginBegin(body("username", "meera"));
                String cd = clientData("mugam.login", ch, "meera", "nope");
                refused(() -> a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", mac.sign(cd))));
            }
            check(login(a, "meera", thief).get("session") != null, "the real owner was locked out");
        });
        test("5 wrong recovery codes lock recovery for 15 minutes", () -> {
            TestClock c2 = new TestClock();
            Auth b = fresh(c2, Files.createTempDirectory("mugam"));
            FakeDevice dev = new FakeDevice();
            register(b, "kiran", dev);
            for (int k = 0; k < 5; k++) refused(() -> recover(b, "kiran", "AAAA-BBBB-CCCC", new FakeDevice()));
            check(refused(() -> b.recoverBegin(body("username", "kiran"))).status == 429, "not locked");
            check(login(b, "kiran", dev).get("session") != null, "sign-in should still work");
            c2.plus(Auth.FAILURE_WINDOW_MS + 1);
            check(b.recoverBegin(body("username", "kiran")).get("challenge") != null, "still locked after 15 min");
        });
        test("a device added by a recovery code can't remove the owner's devices for 24 hours", () -> {
            TestClock c2 = new TestClock();
            Auth b = fresh(c2, Files.createTempDirectory("mugam"));
            FakeDevice owner = new FakeDevice(), thief2 = new FakeDevice();
            List<?> codes = (List<?>) register(b, "anu", owner).get("recoveryCodes");
            thief2.id = (String) recover(b, "anu", (String) codes.get(0), thief2).get("deviceId");
            Auth.Session ts = b.session((String) login(b, "anu", thief2).get("session"));
            check(refused(() -> b.revokeDevice(ts, body("deviceId", owner.id))).status == 403, "thief removed the owner");
            check(refused(() -> b.newRecoveryCodes(ts)).status == 403, "thief replaced the codes");
            check(refused(() -> b.deleteAccount(ts)).status == 403, "thief deleted the account");
            Auth.Session os = b.session((String) login(b, "anu", owner).get("session"));
            b.revokeDevice(os, body("deviceId", thief2.id));               // the owner can act at once
            check(refused(() -> b.session(ts.token())).status == 401, "thief's session survived");
        });
        test("a new account with a reused username can't see the old account's log", () -> {
            TestClock c2 = new TestClock();
            Auth b = fresh(c2, Files.createTempDirectory("mugam"));
            FakeDevice first = new FakeDevice(), second = new FakeDevice();
            register(b, "reuse", first);
            b.deleteAccount(b.session((String) login(b, "reuse", first).get("session")));
            c2.plus(1000);
            register(b, "reuse", second);
            Map<String, Object> me = b.me(b.session((String) login(b, "reuse", second).get("session")));
            for (Object e : (List<?>) me.get("log"))
                check(!String.valueOf(((Map<?, ?>) e).get("type")).equals("ACCOUNT_DELETED"), "saw the old account's events");
        });
        test("unknown usernames still get a challenge (the API doesn't reveal who has an account)", () -> {
            Map<String, Object> ch = a.loginBegin(body("username", "nobody-here"));
            check(ch.get("challenge") != null, "no challenge");
            String cd = clientData("mugam.login", ch, "nobody-here", "x");
            Auth.AuthError e = refused(() -> a.loginFinish(body("challengeId", ch.get("challengeId"), "clientData", cd, "signature", mac.sign(cd))));
            check(e.getMessage().equals(Auth.GENERIC), e.getMessage());
        });
        test("a wrong recovery code is refused and counts toward the lockout", () -> {
            Auth.AuthError e = refused(() -> recover(a, "shyam", "AAAA-BBBB-CCCC", new FakeDevice()));
            check(e.status == 401, "status");
        });
        test("can't remove your last device when no recovery codes are left", () -> {
            TestClock c2 = new TestClock();
            Auth b = fresh(c2, Files.createTempDirectory("mugam"));
            FakeDevice only = new FakeDevice();
            Map<String, Object> r = register(b, "solo", only);
            List<?> codes = (List<?>) r.get("recoveryCodes");
            for (Object code : codes) {                                   // burn all 10, removing each new device again
                String id = (String) recover(b, "solo", (String) code, new FakeDevice()).get("deviceId");
                b.revokeDevice(b.session((String) login(b, "solo", only).get("session")), body("deviceId", id));
            }
            Auth.Session s = b.session((String) login(b, "solo", only).get("session"));
            check(refused(() -> b.revokeDevice(s, body("deviceId", only.id))).status == 409, "allowed lock-out");
        });
        test("someone with disk access who edits one log line is caught", () -> {
            Audit log = a.audit();
            check(log.firstBroken() == 0, "broken before");
            log.tamperForTest(1, "nothing happened");
            check(log.firstBroken() == 2, "not caught: " + log.firstBroken());
        });
        test("editing or cutting the log FILE is caught while the server runs", () -> {
            Path ldir = Files.createTempDirectory("mugam");
            TestClock c2 = new TestClock();
            Auth b = fresh(c2, ldir);
            FakeDevice d = new FakeDevice();
            register(b, "logcheck", d);
            login(b, "logcheck", d);
            login(b, "logcheck", d);
            Path f = ldir.resolve("log.jsonl");
            List<String> lines = Files.readAllLines(f);
            check(b.audit().firstBroken() == 0, "broken before");
            Files.write(f, lines.subList(0, lines.size() - 1));          // cut the last line off
            check(b.audit().firstBroken() == lines.size(), "truncation missed: " + b.audit().firstBroken());
            List<String> edited = new ArrayList<>(lines);
            edited.set(1, edited.get(1).replace("SIGNED_IN", "SIGNED_OUT"));
            Files.write(f, edited);
            check(b.audit().firstBroken() == 2, "edit missed: " + b.audit().firstBroken());
        });
    }

    // ------------------------------------------------------------------ Part 4

    static void http() throws Exception {
        Path dir = Files.createTempDirectory("mugam-http"), web = Files.createTempDirectory("mugam-web");
        Files.writeString(web.resolve("index.html"), "<!doctype html><title>Mugam</title>");
        Files.writeString(dir.resolve("secret.txt"), "do not serve");
        Files.writeString(web.resolve("notes.md"), "unknown type");
        int port;
        try (var sock = new java.net.ServerSocket(0)) { port = sock.getLocalPort(); }
        String origin = "http://127.0.0.1:" + port;
        Server s = Server.create(dir, web, origin, Clock.systemUTC());
        com.sun.net.httpserver.HttpServer http = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", port), 16);
        http.createContext("/", s::handle);
        http.start();
        HttpClient c = HttpClient.newBuilder().proxy(java.net.ProxySelector.of(null)).build();
        try {
            test("every page carries strict security headers", () -> {
                HttpResponse<String> r = c.send(HttpRequest.newBuilder(URI.create(origin + "/")).build(), HttpResponse.BodyHandlers.ofString());
                check(r.statusCode() == 200, "status " + r.statusCode());
                String csp = r.headers().firstValue("Content-Security-Policy").orElse("");
                check(csp.contains("frame-ancestors 'none'") && csp.contains("default-src 'self'") && !csp.contains("unsafe-inline"), csp);
                check(r.headers().firstValue("X-Frame-Options").orElse("").equals("DENY"), "XFO");
                check(r.headers().firstValue("Permissions-Policy").orElse("").contains("camera=(self)"), "camera policy");
            });
            test("path traversal can't read files outside the web folder", () -> {
                for (String p : List.of("/../" + dir.getFileName() + "/secret.txt", "/%2e%2e/%2e%2e/etc/passwd", "/..%2f..%2fetc%2fpasswd")) {
                    HttpResponse<String> r = c.send(HttpRequest.newBuilder(URI.create(origin + p)).build(), HttpResponse.BodyHandlers.ofString());
                    check(r.statusCode() >= 400 && !r.body().contains("do not serve") && !r.body().contains("root:"), p + " -> " + r.statusCode());
                }
            });
            test("only known file types are served", () -> {
                HttpResponse<String> r = c.send(HttpRequest.newBuilder(URI.create(origin + "/notes.md")).build(), HttpResponse.BodyHandlers.ofString());
                check(r.statusCode() == 404, "served .md");
            });
            test("a POST from another origin is refused (CSRF)", () -> {
                HttpResponse<String> r = post(c, origin, "/api/login/begin", "{\"username\":\"x\"}", "https://evil.example", "application/json");
                check(r.statusCode() == 403, "status " + r.statusCode());
            });
            test("a POST that isn't JSON is refused (no form-based CSRF)", () -> {
                HttpResponse<String> r = post(c, origin, "/api/login/begin", "username=x", origin, "application/x-www-form-urlencoded");
                check(r.statusCode() == 415, "status " + r.statusCode());
            });
            test("oversized bodies are refused", () -> {
                HttpResponse<String> r = post(c, origin, "/api/login/begin", "{\"username\":\"" + "a".repeat(20000) + "\"}", origin, "application/json");
                check(r.statusCode() == 413, "status " + r.statusCode());
            });
            test("full sign-up over HTTP: the session is an HttpOnly SameSite cookie, never in the JSON", () -> {
                FakeDevice d = new FakeDevice();
                Map<String, Object> ch = Json.object(post(c, origin, "/api/register/begin", "{\"username\":\"webuser\"}", origin, "application/json").body());
                Map<String, Object> cd = new LinkedHashMap<>();
                cd.put("type", "mugam.register"); cd.put("challenge", ch.get("challenge")); cd.put("origin", origin); cd.put("username", "webuser");
                String cds = Json.write(cd);
                String b = Json.write(body("challengeId", ch.get("challengeId"), "clientData", cds, "signature", d.sign(cds),
                    "publicKey", d.jwk(), "displayName", "Web User", "deviceName", "Chrome"));
                HttpResponse<String> r = post(c, origin, "/api/register/finish", b, origin, "application/json");
                check(r.statusCode() == 200, r.body());
                String cookie = r.headers().firstValue("Set-Cookie").orElse("");
                check(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"), cookie);
                check(!r.body().contains("\"session\""), "token leaked into JSON");
                String token = cookie.substring(0, cookie.indexOf(';'));
                HttpResponse<String> me = c.send(HttpRequest.newBuilder(URI.create(origin + "/api/me")).header("Cookie", token).build(), HttpResponse.BodyHandlers.ofString());
                check(me.statusCode() == 200 && me.body().contains("webuser"), me.body());
                check(me.headers().firstValue("Cache-Control").orElse("").equals("no-store"), "cacheable API");
            });
            test("an error never leaks a stack trace", () -> {
                HttpResponse<String> r = post(c, origin, "/api/login/finish", "{\"challengeId\":\"x\"}", origin, "application/json");
                check(r.statusCode() >= 400 && !r.body().contains("Exception") && !r.body().contains("at mugam."), r.body());
            });
            test("more than 60 API calls a minute from one address are slowed down", () -> {
                int last = 0;
                for (int k = 0; k < 70; k++)
                    last = c.send(HttpRequest.newBuilder(URI.create(origin + "/api/health")).build(), HttpResponse.BodyHandlers.ofString()).statusCode();
                check(last == 429, "last status " + last);
            });
        } finally { http.stop(0); }
    }

    static HttpResponse<String> post(HttpClient c, String origin, String path, String body, String fromOrigin, String type) throws Exception {
        return c.send(HttpRequest.newBuilder(URI.create(origin + path)).header("Origin", fromOrigin).header("Content-Type", type)
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
