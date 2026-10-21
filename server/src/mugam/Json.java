package mugam;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small, strict JSON reader and writer, so the server has no dependencies.
 * Objects become LinkedHashMap, arrays ArrayList, numbers Double, plus String,
 * Boolean and null. Input is limited in size and nesting depth, because the
 * parser reads untrusted request bodies.
 */
public final class Json {
    public static final int MAX_DEPTH = 16;
    public static final int MAX_LENGTH = 64 * 1024;

    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    public static Object parse(String text) {
        if (text == null) throw new IllegalArgumentException("empty JSON");
        if (text.length() > MAX_LENGTH) throw new IllegalArgumentException("JSON too large");
        Json p = new Json(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != p.s.length()) throw p.err("trailing characters");
        return v;
    }

    /** Parses and insists on an object at the top. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) throw new IllegalArgumentException("expected a JSON object");
        return (Map<String, Object>) v;
    }

    private IllegalArgumentException err(String m) { return new IllegalArgumentException("bad JSON at " + i + ": " + m); }

    private void ws() { while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) i++; }

    private Object value(int depth) {
        if (depth > MAX_DEPTH) throw err("too deeply nested");
        if (i >= s.length()) throw err("unexpected end");
        char c = s.charAt(i);
        switch (c) {
            case '{': return obj(depth);
            case '[': return arr(depth);
            case '"': return str();
            case 't': lit("true"); return Boolean.TRUE;
            case 'f': lit("false"); return Boolean.FALSE;
            case 'n': lit("null"); return null;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return num();
                throw err("unexpected '" + c + "'");
        }
    }

    private void lit(String w) {
        if (!s.startsWith(w, i)) throw err("expected " + w);
        i += w.length();
    }

    private Map<String, Object> obj(int depth) {
        Map<String, Object> m = new LinkedHashMap<>();
        i++; ws();
        if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
        while (true) {
            ws();
            if (i >= s.length() || s.charAt(i) != '"') throw err("expected a key");
            String k = str();
            ws();
            if (i >= s.length() || s.charAt(i) != ':') throw err("expected ':'");
            i++; ws();
            if (m.containsKey(k)) throw err("duplicate key " + k);   // ambiguity is a classic parser-differential bug
            m.put(k, value(depth + 1));
            ws();
            if (i >= s.length()) throw err("unexpected end");
            char c = s.charAt(i++);
            if (c == '}') return m;
            if (c != ',') throw err("expected ',' or '}'");
        }
    }

    private List<Object> arr(int depth) {
        List<Object> a = new ArrayList<>();
        i++; ws();
        if (i < s.length() && s.charAt(i) == ']') { i++; return a; }
        while (true) {
            ws();
            a.add(value(depth + 1));
            ws();
            if (i >= s.length()) throw err("unexpected end");
            char c = s.charAt(i++);
            if (c == ']') return a;
            if (c != ',') throw err("expected ',' or ']'");
        }
    }

    private String str() {
        StringBuilder b = new StringBuilder();
        i++;
        while (true) {
            if (i >= s.length()) throw err("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return b.toString();
            if (c < 0x20) throw err("control character in string");
            if (c != '\\') { b.append(c); continue; }
            if (i >= s.length()) throw err("bad escape");
            char e = s.charAt(i++);
            switch (e) {
                case '"': b.append('"'); break;
                case '\\': b.append('\\'); break;
                case '/': b.append('/'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'n': b.append('\n'); break;
                case 'r': b.append('\r'); break;
                case 't': b.append('\t'); break;
                case 'u':
                    if (i + 4 > s.length() || !s.substring(i, i + 4).matches("[0-9A-Fa-f]{4}")) throw err("bad \\u escape");
                    try { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); }
                    catch (NumberFormatException x) { throw err("bad \\u escape"); }
                    i += 4; break;
                default: throw err("bad escape \\" + e);
            }
        }
    }

    private Double num() {
        int start = i;
        if (s.charAt(i) == '-') i++;
        while (i < s.length() && "0123456789.eE+-".indexOf(s.charAt(i)) >= 0) i++;
        try { return Double.valueOf(s.substring(start, i)); }
        catch (NumberFormatException x) { throw err("bad number"); }
    }

    // ------------------------------------------------------------------ writing

    public static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v);
        return b.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder b, Object v) {
        if (v == null) b.append("null");
        else if (v instanceof String str) quote(b, str);
        else if (v instanceof Boolean bo) b.append(bo);
        else if (v instanceof Double d && d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 1e15) b.append(d.longValue());
        else if (v instanceof Number n) b.append(n);
        else if (v instanceof Map<?, ?> m) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) b.append(',');
                first = false;
                quote(b, String.valueOf(e.getKey()));
                b.append(':');
                write(b, e.getValue());
            }
            b.append('}');
        } else if (v instanceof List<?> l) {
            b.append('[');
            for (int k = 0; k < l.size(); k++) { if (k > 0) b.append(','); write(b, l.get(k)); }
            b.append(']');
        } else quote(b, String.valueOf(v));
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '<': b.append("\\u003c"); break;   // safe even if a JSON reply is ever shown inside HTML
                default:
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append('"');
    }

    // ------------------------------------------------------------------ typed getters

    public static String str(Map<String, Object> m, String k, int maxLen) {
        Object v = m.get(k);
        if (!(v instanceof String s)) throw new IllegalArgumentException(k + " is required");
        if (s.length() > maxLen) throw new IllegalArgumentException(k + " is too long");
        return s;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (!(v instanceof Map)) throw new IllegalArgumentException(k + " must be an object");
        return (Map<String, Object>) v;
    }
}
