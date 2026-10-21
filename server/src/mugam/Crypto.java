package mugam;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Everything cryptographic, in one place, all from the JDK. */
public final class Crypto {
    private Crypto() { }

    public static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    public static String b64(byte[] b) { return B64.encodeToString(b); }

    public static byte[] unb64(String s) {
        if (s == null || !s.matches("[A-Za-z0-9_-]*")) throw new IllegalArgumentException("not base64url");
        return B64D.decode(s);
    }

    public static String randomToken(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return b64(b);
    }

    public static String sha256Hex(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    /** Constant-time string compare (for tokens and hashes). */
    public static boolean same(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------------ device keys (P-256)

    private static final ECParameterSpec P256;
    static {
        try {
            AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
            p.init(new ECGenParameterSpec("secp256r1"));
            P256 = p.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }

    /**
     * Reads a public key in the JWK form WebCrypto exports: {kty:"EC", crv:"P-256", x, y}.
     * Only P-256 public keys are accepted; anything carrying a private part ("d") is refused,
     * because a client that sends its private key has already lost it.
     */
    public static PublicKey publicKeyFromJwk(Map<String, Object> jwk) {
        if (!"EC".equals(jwk.get("kty")) || !"P-256".equals(jwk.get("crv")))
            throw new IllegalArgumentException("device key must be an EC P-256 public key");
        if (jwk.containsKey("d")) throw new IllegalArgumentException("never send a private key");
        byte[] x = unb64(Json.str(jwk, "x", 64)), y = unb64(Json.str(jwk, "y", 64));
        if (x.length != 32 || y.length != 32) throw new IllegalArgumentException("bad P-256 coordinates");
        BigInteger bx = new BigInteger(1, x), by = new BigInteger(1, y);
        // The JDK's KeyFactory does NOT check that the point lies on the curve (a test caught
        // this). An off-curve point is the start of an invalid-curve attack, so check it here:
        // y^2 = x^3 + ax + b (mod p), with 0 <= x, y < p.
        BigInteger p = ((java.security.spec.ECFieldFp) P256.getCurve().getField()).getP();
        if (bx.compareTo(p) >= 0 || by.compareTo(p) >= 0) throw new IllegalArgumentException("device key is not a valid P-256 point");
        BigInteger lhs = by.modPow(BigInteger.TWO, p);
        BigInteger rhs = bx.pow(3).add(P256.getCurve().getA().multiply(bx)).add(P256.getCurve().getB()).mod(p);
        if (!lhs.equals(rhs)) throw new IllegalArgumentException("device key is not a valid P-256 point");
        try {
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(bx, by), P256));
        } catch (Exception e) { throw new IllegalArgumentException("device key is not a valid P-256 point"); }
    }

    /**
     * Verifies a WebCrypto ECDSA P-256 / SHA-256 signature. WebCrypto produces the raw
     * 64-byte r||s form (IEEE P1363), which the JDK reads with the "inP1363Format" name.
     */
    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        if (signature.length != 64) return false;
        try {
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initVerify(key);
            s.update(message);
            return s.verify(signature);
        } catch (Exception e) { return false; }
    }

    // ------------------------------------------------------------------ recovery codes

    public static final int PBKDF2_ITERATIONS = 210_000;

    public static String hashCode(String code, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(code.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
        try {
            return HexFormat.of().formatHex(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded());
        } catch (Exception e) { throw new IllegalStateException(e); }
        finally { spec.clearPassword(); }
    }

    /** "K7Q2-9XMD-4TPA": 12 characters from an alphabet with no look-alikes (no 0/O, 1/I/L). About 60 bits. */
    public static String newRecoveryCode() {
        String alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
        StringBuilder b = new StringBuilder();
        for (int k = 0; k < 12; k++) {
            if (k > 0 && k % 4 == 0) b.append('-');
            b.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        }
        return b.toString();
    }

    /** Uppercase and remove spaces and dashes, so "k7q2 9xmd-4tpa" still works. */
    public static String normaliseCode(String c) { return c.toUpperCase().replaceAll("[\\s-]", ""); }

    /** HMAC-SHA256 as lowercase hex. */
    public static String hmacHex(byte[] key, String data) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            byte[] out = mac.doFinal(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (byte x : out) b.append(String.format("%02x", x));
            return b.toString();
        } catch (java.security.GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
}
