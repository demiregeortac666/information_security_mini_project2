# SecureShield - Project Report

**Mini Project II - Role-Based Access Control API**
Team: _<fill in>_ &nbsp;&nbsp;|&nbsp;&nbsp; Members: _<fill in>_

---

## 1. Why salting is necessary to prevent Rainbow Table attacks

A *rainbow table* is a precomputed lookup structure that maps the hashes
of common (or even all) plaintext passwords to the passwords themselves.
With modern storage and GPUs, an attacker can build (or download) such a
table containing trillions of entries for fast hash families like MD5,
SHA-1, or even unsalted SHA-256. If a database of unsalted password
hashes is leaked, the attacker simply looks up each hash in the table
and recovers most passwords almost instantly - no brute-force is needed.

A *salt* is a sufficiently long random value generated **per user** at
registration time and concatenated with the password before hashing:

```
hash = bcrypt(salt || password)
```

Salting defeats rainbow tables for three reasons:

1. **Per-user uniqueness** - Two users who happen to choose the same
   password produce completely different hashes. The attacker can no
   longer identify popular passwords by spotting hash collisions across
   the leaked database.
2. **Precomputation becomes infeasible** - To use a rainbow table on
   salted hashes, the attacker would have to build a separate table for
   *every* possible salt. With bcrypt's 128-bit (16-byte) random salt,
   that means 2^128 tables. The storage and time cost are physically
   impossible.
3. **Forces per-account brute force** - The only remaining attack is to
   try candidate passwords one-by-one against each user's salt+hash
   pair. Combined with bcrypt's deliberately slow, tunable work factor
   (we use the default of 12, ~250 ms per hash), even a moderately
   strong password resists offline cracking for years on commodity
   hardware.

In SecureShield this is handled automatically by `flask_bcrypt`. The
call `bcrypt.generate_password_hash(password)` produces a string of the
form `$2b$12$<22-char-salt><31-char-hash>` where the algorithm version,
cost factor, and salt are all embedded alongside the hash. Verification
re-extracts the salt from the stored value, making the system fully
self-contained while still defeating rainbow-table attacks.

---

## 2. Risks of storing sensitive data inside a JWT payload

A common misconception is that JWTs are encrypted. They are **not**.
The JWS form used everywhere in practice (and used in this project)
simply *signs* the payload - it does not hide it. Anyone holding the
token can paste it into <https://jwt.io> and read every claim
verbatim. Treating the JWT body as a confidential channel therefore
introduces several concrete risks:

1. **Information disclosure to anyone who sees the token.**
   Tokens routinely live in browser `localStorage`, cookies, mobile
   crash reports, server access logs, proxy logs, and `Referer`
   headers. Any sensitive value placed in the payload (full name,
   national ID, e-mail, phone, role/permission lists, internal
   database IDs, billing information, the user's password) leaks
   wherever the token leaks.
2. **Inability to revoke disclosed information.**
   JWTs are designed to be stateless. Once issued, the data inside is
   "in the wild" until the token expires. If a sensitive claim turns
   out to be wrong or compromised, you cannot rewrite tokens that have
   already been handed out.
3. **Long lifetime amplifies exposure.**
   A token typically lives 15 minutes to several hours. Any data
   embedded in it remains visible for that entire window, on every
   device that holds a copy.
4. **Token bloat and replay impact.**
   The token is sent on every authenticated request. Stuffing it with
   PII inflates request size and increases the surface area exposed to
   anyone capable of replaying or sniffing requests.
5. **False sense of security from base64.**
   `eyJhbGciOi...` looks opaque but is just `base64url`. Developers
   sometimes assume it is encrypted and place secrets there - this is
   a frequent finding in real-world penetration tests.

**What we *do* put in the SecureShield JWT** (see `auth.generate_token`):

| Claim | Why it is safe to include |
|-------|---------------------------|
| `sub` (username) | Public identifier already known to the user |
| `role`           | Needed for authorization decisions, low sensitivity |
| `jti`            | Random UUID; only meaningful with our blacklist |
| `iat`, `exp`     | Metadata, no secret content |

Notably absent: the password, the password hash, the user's e-mail,
internal numeric IDs, or any PII. The payload is the **minimum** needed
to make an authorization decision; any further user data is fetched
from the server using the token as an opaque reference.

**Mitigations when sensitive data really must travel inside a token.**

If a use-case truly requires confidential claims, the correct tool is
**JWE (JSON Web Encryption)**, which encrypts the payload with the
recipient's key. JWE introduces key-management complexity that is rarely
worth it - the safer pattern is to keep the JWT minimal and look up
sensitive data on the server, behind the access-control checks the JWT
authorizes.

---

### Summary

SecureShield combines two deliberately conservative choices:
*bcrypt with per-user salts* makes a leaked database resistant to
rainbow tables and slow to brute-force, while a *minimal, signed-only
JWT* avoids leaking sensitive information through a token that is, by
design, only base64-encoded. Together with the role-checking
decorators and the in-memory `jti` blacklist, these mechanisms
implement the Principle of Least Privilege end-to-end.
