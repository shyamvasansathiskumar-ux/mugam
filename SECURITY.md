# Mugam security notes and threat model

This file says plainly what Mugam protects against and what it doesn't. A login system that overstates itself is worse than one that's honest about its limits.

## What is stored, and where

| Where | What | What it's worth to a thief |
|---|---|---|
| Server, `accounts.json` | username, display name, each device's **public** P-256 key, PBKDF2-SHA256 hashes of recovery codes (210,000 iterations, per-account salt) | Public keys sign nothing. Recovery codes have about 60 bits of entropy and a slow hash. |
| Server, `security-log.jsonl` | events chained with HMAC-SHA256, keyed by a pseudonym (an HMAC of the username and the account's creation time) | No usernames, no faces. A later account that reuses a username can't see the earlier one's events. |
| Server, `pepper` | 32 random bytes, file mode 600 | The log's key, and the link from pseudonyms back to accounts. Keep it **away from the data**: `--pepper /somewhere/else/pepper`. Never put it in the repo. |
| Device, IndexedDB | the P-256 key pair (private half **non-extractable**), an AES-GCM key (**non-extractable**), the rotated template and its seed (both AES-GCM encrypted, bound to the username) | Scripts can't read the key bytes. The template can't be compared to anything without the seed, and the seed can't be read without the browser's key. |

**No photo, video frame, raw descriptor or template is ever sent to the server or written to disk unencrypted.**

## Attacks, and what stops them

| Attack | Defence | Tested |
|---|---|---|
| Hold up a printed photo or a phone picture | Liveness: two random movements, a time limit on each, one face only, no jumps | e2e: a still photo of the enrolled face fails |
| Replay a captured sign-in | Challenges are single-use, expire in 2 minutes, and are removed even when verification fails | Java |
| Phishing: a look-alike site relays the challenge | The device signs `origin = location.origin`, and the server checks it against its own origin | Java and demo |
| Steal the server's database | It holds only public keys and slow hashes | Java: no face data in the saved file |
| Steal the template from the device | It is encrypted with a non-extractable key; even decrypted, it's rotated by a secret; re-enrolling cancels it | Node: cancelability |
| Use someone else's device key | The signature is checked against **this account's** registered device | Java |
| Swap usernames or challenge types | `clientData` must match the challenge's type and user exactly | Java |
| Invalid-curve key | Points are checked on P-256 (the JDK doesn't do this by itself; a test caught it) | Java |
| Guess recovery codes | 60-bit codes, slow hash, 5 wrong codes in 15 minutes lock **recovery** for that username, per-IP rate limit | Java |
| Lock someone out with no secret | Failed sign-ins are logged but never lock anyone out: a device signature can't be guessed, so locking sign-in would only help an attacker. Only wrong recovery codes count, and they lock recovery, never sign-in | Java |
| Take over with a stolen recovery code | The code adds a device, and the owner sees "Recovery code used" in their log. For 24 hours that new device can't remove other devices, replace the codes or delete the account; the owner's devices can remove it at once | Java |
| Swap in a different face at an unlocked computer | Setting up the face again first needs a full face sign-in against the current template, and the change is logged | e2e (flow), log event |
| Find out which usernames exist | Sign-in and recovery start the same way for unknown names, and recovery runs the slow hash for unknown names too, so timing doesn't tell. **Sign-up does reveal it:** "That username is taken" is unavoidable, so it is rate-limited (5 an hour per address) | Java |
| Cross-site request forgery | POST needs `Origin` equal to the site and `Content-Type: application/json`; cookie is `SameSite=Strict` | Java (HTTP) |
| Steal the session with injected script | The session is an `HttpOnly` cookie; CSP has no inline script; user text is set with `textContent`, never HTML | Java (HTTP), e2e |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` | Java (HTTP) |
| Read files off the server | Static paths are decoded, normalised and kept inside `docs/`; only known file types are served | Java (HTTP) |
| A lost device | Remove it from another device (its sessions end at once), or use a recovery code on a new one | Java |
| Lock yourself out | You can't remove your last device while you have no recovery codes left | Java |
| Quietly edit the security log | Each line carries an HMAC of the line before, keyed from the pepper. The file is re-read and re-checked on every account view, so an edited or cut-off file shows "Chain broken" while the server runs. Someone with **both** the log and the pepper can rewrite it, so keep the pepper elsewhere and copy the head hash (shown on the account screen) somewhere outside the server | Java |
| Rate limits shared by everyone behind a proxy | Start with `--trusted-proxy <proxy address>`: the client address is then taken from the right-most `X-Forwarded-For` entry, and only when the request really comes from that proxy. Old rate-limit entries are pruned every minute | (manual) |

## What Mugam does NOT protect against (honest limits)

1. **A webcam sees no depth.** Apple's Face ID uses an infrared dot projector and dedicated hardware. Mugam uses an ordinary camera, so a skilled video deepfake or a good 3D mask could pass liveness. That is why the face only unlocks a key **on this device**: an attacker needs your device as well as your face.
2. **Malware on the device wins.** Browser JavaScript can't prove to the server that the face check really ran. Code running inside a compromised browser could call the signing key without a face. Every software authenticator has this limit; hardware passkeys (WebAuthn with a secure enclave) are stronger. Mugam suits devices with no built-in biometrics.
3. **The face check happens on the device and is reported, not proven.** The `face` field in `clientData` (which movements, match distance) is logged for the record, but the server doesn't trust it.
4. **Face models are not equally accurate for everyone.** Public research, including NIST's face recognition tests, shows error rates differ across groups. Mugam's match threshold is stricter than the model's default (0.5 against 0.6), and recovery codes mean nobody is ever locked out by the model. Accuracy across groups has not been measured for this project.
5. **The rotation is not encryption.** Without the AES layer, someone who obtains both the template and its seed can undo the rotation. The AES key's non-extractability is the real protection.
6. **The GitHub Pages demo protects nothing.** Its "server" runs in the same browser, so the person at the keyboard can change it. It follows the same protocol, but its lockout counter resets on reload and its log uses a plain hash. It shows how the system behaves; it isn't a deployment.
7. **The server keeps sessions in memory.** Restarting it signs everyone out. That is safe, but it doesn't scale beyond one machine as it stands.
8. **Losing your only device still means a 24-hour wait** before the device you add with a recovery code can remove the lost one. The lost device is useless without your face, so this trades a little convenience for protection against a stolen code.

## Privacy

- **Consent.** Before the camera turns on, the user sees a plain notice (what, where, why, how to stop) and must agree.
- **Erasure.** "Remove face data from this device" deletes the template and the device key. "Delete account" deletes the account; the log keeps only pseudonymous lines.
- **India's DPDP Act** treats face data as personal data that needs notice and consent. Mugam is designed so the operator never holds it at all. This is a summary, not legal advice.

## Reporting a problem

Open a GitHub issue with no exploit details, and ask for a private contact.
