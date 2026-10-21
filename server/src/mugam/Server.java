package mugam;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/**
 * Mugam's web server: the JDK's built-in HTTP server, no framework, no dependencies.
 *
 *   java -cp out mugam.Server --port 8080 --origin http://localhost:8080 --data data --web docs
 *
 * It serves the web app and a small JSON API. Every response carries strict security
 * headers; every API write must be same-origin JSON; the session lives in an HttpOnly,
 * SameSite=Strict cookie that page scripts can't read.
 */
public final class Server {

    static final int MAX_BODY = 16 * 1024;
    static final int PER_IP_PER_MINUTE = 60;
    static final int REGISTRATIONS_PER_IP_PER_HOUR = 5;

    final Auth auth;
    final Path web;
    final boolean secure;
    final String cookieName;
    private final Map<String, Deque<Long>> hits = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> registrations = new ConcurrentHashMap<>();
    private final Clock clock;
    /** Set when Mugam runs behind a reverse proxy at this address: the client is then read
     *  from the right-most X-Forwarded-For entry, the one the proxy itself added. */
    String trustedProxy;
    private long lastPrune;

    Server(Auth auth, Path web, Clock clock) {
        this.auth = auth;
        this.web = web.toAbsolutePath().normalize();
        this.clock = clock;
        this.secure = auth.origin().startsWith("https://");
        this.cookieName = secure ? "__Host-mugam" : "mugam_session";   // __Host- needs HTTPS
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> a = new HashMap<>();
        for (int k = 0; k + 1 < args.length; k += 2) a.put(args[k], args[k + 1]);
        int port = Integer.parseInt(a.getOrDefault("--port", "8080"));
        String origin = a.getOrDefault("--origin", "http://localhost:" + port);
        Path data = Path.of(a.getOrDefault("--data", "data"));
        Path web = Path.of(a.getOrDefault("--web", "docs"));
        Path pepper = Path.of(a.getOrDefault("--pepper", data.resolve("pepper").toString()));
        Server s = create(data, web, origin, Clock.systemUTC(), pepper);
        s.trustedProxy = a.get("--trusted-proxy");
        HttpServer http = HttpServer.create(new InetSocketAddress(a.getOrDefault("--bind", "127.0.0.1"), port), 64);
        http.createContext("/", s::handle);
        http.setExecutor(Executors.newFixedThreadPool(8));
        http.start();
        System.out.println("Mugam on " + origin + "  (data: " + data.toAbsolutePath() + ")");
    }

    static Server create(Path data, Path web, String origin, Clock clock) throws IOException {
        return create(data, web, origin, clock, data.resolve("pepper"));
    }

    static Server create(Path data, Path web, String origin, Clock clock, Path pepperFile) throws IOException {
        Files.createDirectories(data);
        if (pepperFile.toAbsolutePath().getParent() != null) Files.createDirectories(pepperFile.toAbsolutePath().getParent());
        if (!Files.exists(pepperFile)) {
            Files.writeString(pepperFile, Crypto.randomToken(32));
            try { Files.setPosixFilePermissions(pepperFile, PosixFilePermissions.fromString("rw-------")); }
            catch (UnsupportedOperationException ignored) { }
        }
        Store store = new Store(data.resolve("accounts.json"));
        Audit audit = new Audit(data.resolve("security-log.jsonl"), Files.readString(pepperFile).trim());
        return new Server(new Auth(store, audit, origin, clock), web, clock);
    }

    // ------------------------------------------------------------------ routing

    void handle(HttpExchange ex) throws IOException {
        try {
            headers(ex.getResponseHeaders());
            String path = ex.getRequestURI().getRawPath();
            if (path.startsWith("/api/")) api(ex, path);
            else file(ex, path);
        } catch (Auth.AuthError e) {
            json(ex, e.status, err(e.getMessage()));
        } catch (IllegalArgumentException e) {
            json(ex, 400, err("That request wasn't valid."));
        } catch (Exception e) {
            json(ex, 500, err("Something went wrong on the server."));
        } finally {
            ex.close();
        }
    }

    static Map<String, Object> err(String m) { Map<String, Object> o = new LinkedHashMap<>(); o.put("error", m); return o; }

    /** Strict headers on every response, page or API. */
    static void headers(Headers h) {
        h.set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
            + "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; worker-src 'self' blob:; "
            + "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
        h.set("X-Content-Type-Options", "nosniff");
        h.set("Referrer-Policy", "no-referrer");
        h.set("Permissions-Policy", "camera=(self), microphone=(), geolocation=(), payment=(), usb=()");
        h.set("Cross-Origin-Opener-Policy", "same-origin");
        h.set("Cross-Origin-Resource-Policy", "same-origin");
        h.set("X-Frame-Options", "DENY");
    }

    private void api(HttpExchange ex, String path) throws IOException {
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        String ip = clientIp(ex);
        prune();
        if (!allow(hits, ip, PER_IP_PER_MINUTE, 60_000)) throw new Auth.AuthError(429, "Too many requests. Slow down.");
        String method = ex.getRequestMethod();

        if (method.equals("GET") && path.equals("/api/me")) { json(ex, 200, auth.me(auth.session(cookie(ex)))); return; }
        if (method.equals("GET") && path.equals("/api/health")) { Map<String, Object> o = new LinkedHashMap<>(); o.put("ok", true); json(ex, 200, o); return; }
        if (!method.equals("POST")) throw new Auth.AuthError(405, "Method not allowed.");

        // Cross-site request forgery: a POST must come from our own origin and be JSON.
        String origin = ex.getRequestHeaders().getFirst("Origin");
        if (origin == null || !origin.equals(auth.origin())) throw new Auth.AuthError(403, "Wrong origin.");
        String ct = ex.getRequestHeaders().getFirst("Content-Type");
        if (ct == null || !ct.toLowerCase().startsWith("application/json")) throw new Auth.AuthError(415, "Send JSON.");
        Map<String, Object> body = Json.object(read(ex.getRequestBody()));

        switch (path) {
            case "/api/register/begin" -> {
                if (!allow(registrations, ip, REGISTRATIONS_PER_IP_PER_HOUR, 3_600_000)) throw new Auth.AuthError(429, "Too many new accounts from here. Try later.");
                json(ex, 200, auth.registerBegin(body));
            }
            case "/api/register/finish" -> signIn(ex, auth.registerFinish(body));
            case "/api/login/begin" -> json(ex, 200, auth.loginBegin(body));
            case "/api/login/finish" -> signIn(ex, auth.loginFinish(body));
            case "/api/recover/begin" -> json(ex, 200, auth.recoverBegin(body));
            case "/api/recover/finish" -> signIn(ex, auth.recoverFinish(body));
            case "/api/face/renewed" -> { auth.faceRenewed(auth.session(cookie(ex))); json(ex, 200, ok()); }
            case "/api/device/remove" -> { auth.revokeDevice(auth.session(cookie(ex)), body); json(ex, 200, ok()); }
            case "/api/recovery/new" -> json(ex, 200, auth.newRecoveryCodes(auth.session(cookie(ex))));
            case "/api/logout" -> { auth.logout(cookie(ex)); clear(ex); json(ex, 200, ok()); }
            case "/api/account/delete" -> { auth.deleteAccount(auth.session(cookie(ex))); clear(ex); json(ex, 200, ok()); }
            default -> throw new Auth.AuthError(404, "Not found.");
        }
    }

    private static Map<String, Object> ok() { Map<String, Object> o = new LinkedHashMap<>(); o.put("ok", true); return o; }

    /** Moves the session token from the JSON reply into an HttpOnly cookie. */
    private void signIn(HttpExchange ex, Map<String, Object> result) throws IOException {
        String token = (String) result.remove("session");
        ex.getResponseHeaders().add("Set-Cookie", cookieName + "=" + token + "; Path=/; HttpOnly; SameSite=Strict"
            + (secure ? "; Secure" : "") + "; Max-Age=" + (Auth.SESSION_MAX_MS / 1000));
        json(ex, 200, result);
    }

    String clientIp(HttpExchange ex) {
        String peer = ex.getRemoteAddress().getAddress().getHostAddress();
        if (trustedProxy == null || !trustedProxy.equals(peer)) return peer;     // headers from anyone else are ignored
        String xff = ex.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xff == null || xff.isBlank()) return peer;
        String[] parts = xff.split(",");
        String last = parts[parts.length - 1].trim();
        return last.matches("[0-9A-Fa-f:.]{2,45}") ? last : peer;
    }

    /** Drops rate-limit entries whose window has passed, so memory can't grow without limit. */
    private void prune() {
        long t = clock.millis();
        if (t - lastPrune < 60_000) return;
        lastPrune = t;
        hits.entrySet().removeIf(e -> { synchronized (e.getValue()) { return e.getValue().isEmpty() || e.getValue().peekLast() < t - 60_000; } });
        registrations.entrySet().removeIf(e -> { synchronized (e.getValue()) { return e.getValue().isEmpty() || e.getValue().peekLast() < t - 3_600_000; } });
    }

    private void clear(HttpExchange ex) {
        ex.getResponseHeaders().add("Set-Cookie", cookieName + "=; Path=/; HttpOnly; SameSite=Strict" + (secure ? "; Secure" : "") + "; Max-Age=0");
    }

    String cookie(HttpExchange ex) {
        String all = ex.getRequestHeaders().getFirst("Cookie");
        if (all == null) return null;
        for (String part : all.split(";")) {
            String p = part.trim();
            if (p.startsWith(cookieName + "=")) return p.substring(cookieName.length() + 1);
        }
        return null;
    }

    private boolean allow(Map<String, Deque<Long>> book, String key, int max, long windowMs) {
        long t = clock.millis();
        Deque<Long> d = book.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (d) {
            while (!d.isEmpty() && d.peekFirst() < t - windowMs) d.pollFirst();
            if (d.size() >= max) return false;
            d.addLast(t);
            return true;
        }
    }

    static String read(InputStream in) throws IOException {
        byte[] b = in.readNBytes(MAX_BODY + 1);
        if (b.length > MAX_BODY) throw new Auth.AuthError(413, "Request too large.");
        return new String(b, StandardCharsets.UTF_8);
    }

    static void json(HttpExchange ex, int status, Object body) throws IOException {
        byte[] b = Json.write(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }

    // ------------------------------------------------------------------ static files

    static final Map<String, String> TYPES = Map.ofEntries(
        Map.entry("html", "text/html; charset=utf-8"), Map.entry("js", "text/javascript; charset=utf-8"),
        Map.entry("css", "text/css; charset=utf-8"), Map.entry("json", "application/json"),
        Map.entry("svg", "image/svg+xml"), Map.entry("png", "image/png"), Map.entry("jpg", "image/jpeg"),
        Map.entry("webp", "image/webp"), Map.entry("woff2", "font/woff2"), Map.entry("bin", "application/octet-stream"),
        Map.entry("txt", "text/plain; charset=utf-8"), Map.entry("ico", "image/x-icon"));

    private void file(HttpExchange ex, String rawPath) throws IOException {
        String method = ex.getRequestMethod();
        if (!method.equals("GET") && !method.equals("HEAD")) { ex.sendResponseHeaders(405, -1); return; }
        String p = URI.create(rawPath).getPath();                      // decodes %2e%2e etc. before we check
        if (p == null || p.contains("\0") || p.contains("\\")) { ex.sendResponseHeaders(400, -1); return; }
        if (p.endsWith("/")) p += "index.html";
        Path f = web.resolve(p.substring(1)).normalize();
        if (!f.startsWith(web) || !Files.isRegularFile(f) || Files.isHidden(f)) { notFound(ex); return; }
        String name = f.getFileName().toString();
        String ext = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1).toLowerCase() : "";
        String type = TYPES.get(ext);
        if (type == null) { notFound(ex); return; }                     // only known file types are served
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", type);
        h.set("Cache-Control", ext.equals("bin") ? "public, max-age=604800, immutable" : "no-cache");
        long len = Files.size(f);
        if (method.equals("HEAD")) { ex.sendResponseHeaders(200, -1); return; }
        ex.sendResponseHeaders(200, len);
        try (OutputStream o = ex.getResponseBody()) { Files.copy(f, o); }
    }

    private static void notFound(HttpExchange ex) throws IOException {
        byte[] b = "Not found".getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(404, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }
}
