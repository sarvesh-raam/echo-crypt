# Security model

EchoCrypt is a portfolio and learning project. It has not been independently audited. Don't rely on it where your safety depends on it; use Signal for that.

## Goals

1. A party who controls the server or the database cannot read message contents.
2. That party cannot forge or modify messages without detection.
3. That party cannot silently swap a contact's keys (man-in-the-middle) once you have talked to that contact before.
4. A stolen database does not hand out passwords, working logins or private keys.

## Primitives

All from the Web Crypto API; no custom cryptography.

| Purpose | Algorithm |
| --- | --- |
| Password stretching | PBKDF2-HMAC-SHA256, 600,000 iterations, 128-bit random salt |
| Key separation | HKDF-SHA256 (`echocrypt/v1/auth`, `echocrypt/v1/wrap`) |
| Server-side auth hash | scrypt (N=2^15, r=8, p=1) over the client's auth key |
| Private-key storage | AES-256-GCM under a random 256-bit account key, with a per-key label as AAD |
| Key slots | The account key, AES-256-GCM-sealed under each unlock method's key, with the slot kind as AAD |
| Recovery key | 24 Crockford base32 characters (120 bits) → HKDF-SHA256 → auth key + wrap key |
| Passkeys | WebAuthn (ES256/RS256, user verification required; origin and RP ID checked by `@simplewebauthn/server`); PRF extension output → HKDF-SHA256 → slot key |
| Email codes | 6 random digits, kept as SHA-256 in Redis for 10 minutes, single use, burned after 5 wrong guesses |
| Google / GitHub | OAuth 2.0 authorization code flow with PKCE (S256) and a signed, short-lived state cookie; a new user's provider identity waits in a signed 15-minute cookie until the browser has created the account's keys |
| Key agreement | ECDH P-256, with a fresh ephemeral key per message and recipient |
| Message key wrapping | HKDF-SHA256 over the ECDH secret, bound to conversation, message id, recipient and ephemeral key; then AES-256-GCM |
| Content encryption | AES-256-GCM with a one-time 256-bit key; AAD binds conversation, sender and message id |
| Signatures | ECDSA P-256 / SHA-256 over a length-prefixed encoding of every envelope field |
| Safety numbers | SHA-512 iterated 1,024 times over each party's public keys; 30 digits per party |

## What is protected

- **Message contents** are encrypted before they leave the browser. The server stores only envelopes (`server/src/models/Message.ts` has no plaintext field). An integration test asserts that the stored documents contain no plaintext.
- **Integrity and authenticity.** The client verifies the sender's signature before decrypting. A changed ciphertext, key list, conversation id, message id or sender, or a message signed by anyone other than the claimed sender, is rejected. The server also verifies signatures, but only to reject garbage early; clients never rely on that check.
- **The password** never leaves the browser. The server receives `authKey = HKDF(PBKDF2(password), "auth")`, which cannot be turned into the wrap key, and stores only `scrypt(authKey)`.
- **Private keys** live on the server only as AES-GCM ciphertext under the account key. The account key is stored only inside key slots, which need the password, the recovery code or a passkey's PRF output to open. In the browser they are imported as **non-extractable** `CryptoKey`s and kept in IndexedDB, so page scripts can use them but cannot read their bytes.
- **Sign-in methods cannot weaken encryption.** Google, GitHub and email codes only create a session; none of them yields a key that opens a slot. A passkey's PRF output and the recovery code never leave the browser (only an HKDF-derived auth key, hashed again with scrypt, reaches the server). Passkey challenges are single-use and kept in Redis, so a replay fails on every instance.
- **Key substitution** after first contact. Contacts' key fingerprints are pinned (trust on first use). If the server later returns different keys, the UI warns, marks the safety number as changed, and blocks sending until the user re-verifies.
- **Group membership changes.** The server rejects envelopes that do not carry a key for exactly the current members, so a client can't quietly leave someone out, and nobody gets keys to messages from before they joined.
- **Account enumeration** through the KDF-parameter endpoint: unknown usernames get a stable decoy salt. Login failures look the same for unknown users and wrong passwords.
- **Brute force:** login and sign-up are rate-limited per IP (and per username for login), with the counters shared across instances in Redis.

## What is not protected

- **Metadata:** usernames, display names, group names, conversation membership, message timing and approximate size are visible to the server.
- **Forward secrecy and post-compromise security.** Someone who obtains a member's password and the encrypted key blob, or the unlocked keys from their device, can decrypt that member's past messages. A Double Ratchet would be required.
- **First contact.** Trust on first use cannot detect a key substitution that happens before you first see a contact. Compare safety numbers out of band.
- **Malicious client code.** The server serves the web app, so a compromised server could ship JavaScript that leaks keys. This is inherent to browser-delivered E2EE.
- **Compromised endpoints:** malware or a malicious browser extension on a user's device.
- **Session theft.** Sessions are 7-day JWTs in an `HttpOnly`, `Secure` (in production), `SameSite=Strict` cookie. There is no server-side revocation list, so a stolen token stays valid until it expires. A stolen session cannot decrypt anything without the keys.
- **Messages sent to the demo bot.** The bot is a regular participant whose private keys live on the server, so the server can read what is sent *to it*, by design. It cannot read any other conversation. Set `DEMO=false` to turn the bot and guest accounts off.
- **Takeover of a linked Google/GitHub account or email inbox** gives an attacker a session, not your messages. With a session they could remove your passkeys or recovery key, or link accounts of their own (these settings do not ask for re-confirmation). That is an availability risk, not a confidentiality one.
- **The recovery key is as powerful as the password.** Anyone with it and your username can reset the password and read your messages. Keep it offline.
- **Denial of service** beyond basic rate limiting.

## Reporting

Please open a GitHub issue, or email sarveshraam5@gmail.com for anything sensitive.
