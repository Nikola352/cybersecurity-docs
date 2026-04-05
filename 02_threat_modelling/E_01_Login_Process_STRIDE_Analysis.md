# E. Threat and Mitigation Analysis: Login Process

## Processes

### Authenticate

Verifies the identity of the user by checking submitted credentials against the User Accounts DB.

#### S - Spoofing
**Title:** Rogue Service Impersonation
**Description:** A rogue internal service impersonates the Authenticate process, intercepting
credentials before they reach the legitimate authenticator.

**Mitigations:**
- Mutual TLS or signed service-to-service tokens between internal processes
- Deploy pipeline signing and integrity checks on service binaries

#### T - Tampering
**Title:** Authentication Logic Tampering
**Description:** The authentication logic is modified (e.g. via a compromised deployment) to skip
credential verification or accept any input as valid.

**Mitigations:**
- Code integrity checks and signed deployments
- Immutable infrastructure - services run from read-only images

#### R - Repudiation
**Title:** Missing Authentication Audit Trail
**Description:** Authentication events (successful logins, failed attempts) are not recorded,
making it impossible to prove or dispute that a login occurred.

**Mitigations:**
- Mandatory structured logging of every authentication attempt (success and failure) to the Audit/Session Log
- Logs must include timestamp, user identifier, source IP, and outcome

#### I - Information Disclosure
**Title:** Username Enumeration
**Description:** The authenticator leaks whether a username exists by returning distinct responses
for "unknown username" vs. "wrong password" (username enumeration).

**Mitigations:**
- Return identical error messages and HTTP status codes for all failed login attempts
- Use constant-time string comparison to prevent timing-based enumeration

#### D - Denial of Service
**Title:** Credential Stuffing / Brute Force
**Description:** An attacker floods the authentication endpoint with credential attempts, exhausting
resources and preventing legitimate users from logging in (brute force / credential stuffing).

**Mitigations:**
- Rate limiting per IP and per account
- Progressive account lockout with notification to the account owner
- CAPTCHA after a threshold of failed attempts
- IP reputation and blocklist integration

#### E - Elevation of Privilege
**Title:** Authentication Bypass
**Description:** An attacker bypasses the authentication step entirely - e.g. via a logic flaw,
token forgery, or forced browsing - and reaches the Authorize process as an authenticated identity.

**Mitigations:**
- Defense in depth: the Authorize process independently validates the identity claim rather than
  trusting it implicitly
- Authentication result must be a cryptographically signed token, not a plain flag

---

### Authorize

Receives a verified identity from Authenticate and determines what rights the user holds.
Records the login event to the Audit/Session Log.

#### S - Spoofing
**Title:** Forged Identity Token
**Description:** An attacker forges or replays an identity token to make the Authorize process
believe it received a legitimate identity from the Authenticate process.

**Mitigations:**
- Sign identity tokens (e.g. HMAC-signed JWT) so the Authorize process can verify origin
- Short token lifetime; bind tokens to the session context

#### T - Tampering
**Title:** Rights Manipulation
**Description:** The rights or permissions associated with a user are manipulated in transit or
at rest, granting the user access they are not entitled to.

**Mitigations:**
- Rights must be fetched directly from the authoritative store (database), never derived solely
  from a client-supplied token
- Sign and integrity-protect any internal rights claims

#### R - Repudiation
**Title:** Unlogged Authorization Decisions
**Description:** Authorization decisions (which rights were granted, which were denied) are not
logged, making it impossible to audit privilege grants after the fact.

**Mitigations:**
- Log every authorization decision to the Audit/Session Log, including granted rights and timestamp
- Retain logs for a period consistent with regulatory requirements

#### I - Information Disclosure
**Title:** Rights Information Leakage
**Description:** The Authorize process leaks role or rights information to unauthorized parties -
e.g. through verbose error messages or insecure internal API responses.

**Mitigations:**
- Return only the minimum necessary rights information to downstream processes
- Suppress internal role names and permission details from any externally visible error responses

#### D - Denial of Service
**Title:** Authorization Endpoint Flood
**Description:** The authorization service is flooded with requests, or its dependency on the
Audit/Session Log is exploited to exhaust log storage and halt writes, blocking all logins.

**Mitigations:**
- Rate limiting on the authorization endpoint
- Decouple log writes from the critical path where possible (async logging with circuit breaker)
- Monitor and alert on log storage utilization

#### E - Elevation of Privilege
**Title:** Privilege Escalation via Authorization Flow
**Description:** A lower-privileged user manipulates the authorization flow to obtain a rights set
beyond what they are entitled to (privilege escalation).

**Mitigations:**
- Enforce least privilege: rights are loaded server-side from the database, not from user-supplied input
- Re-validate rights on every request, not only at login time

---

### Login Processing

Creates a session for the authenticated and authorized user and issues a session token back to the client.

#### S - Spoofing
**Title:** Session Hijacking
**Description:** An attacker steals a valid session token and uses it to impersonate the legitimate
user (session hijacking).

**Mitigations:**
- Set `HttpOnly` and `Secure` flags on session cookies to prevent JavaScript access and cleartext transmission
- Set `SameSite=Strict` to prevent cross-site request forgery using the session cookie
- Bind sessions to additional context (e.g. User-Agent) where feasible
- Short session TTL with re-authentication for sensitive operations

#### T - Tampering
**Title:** Session Fixation
**Description:** An attacker forces a known session ID onto the user before login (session fixation),
then hijacks the session after the user authenticates.

**Mitigations:**
- Regenerate the session ID immediately upon successful authentication
- Invalidate any pre-authentication session identifier

#### R - Repudiation
**Title:** Unlinked Session Activity
**Description:** Session activity is not linked to the audit log, allowing a user to deny actions
performed during their session.

**Mitigations:**
- Associate all significant actions within a session to the authenticated user identity in the Audit/Session Log
- Log session creation and termination events with timestamps and source IP

#### I - Information Disclosure
**Title:** Session Token Exposure
**Description:** The session token is exposed in a URL, HTTP Referer header, or server logs,
allowing it to be harvested by a third party.

**Mitigations:**
- Never include session tokens in URLs or query parameters
- Transmit tokens exclusively via `Set-Cookie` headers with `Secure` flag
- Ensure logs redact or omit session token values

#### D - Denial of Service
**Title:** Session Table Exhaustion
**Description:** An attacker creates a large number of sessions without completing authentication,
exhausting server-side session storage and preventing new logins.

**Mitigations:**
- Limit the number of concurrent unvalidated (pre-auth) sessions per IP
- Enforce server-side session expiry and garbage collection
- Monitor and alert on session table utilization

#### E - Elevation of Privilege
**Title:** Unauthenticated Session Acquisition
**Description:** An unauthenticated request bypasses Login Processing and obtains a session with
valid rights - e.g. by directly calling a downstream endpoint that trusts a session parameter.

**Mitigations:**
- All session tokens must be validated server-side on every request before any access is granted
- Downstream processes must not accept an unauthenticated identity from a session parameter

---

## Data Stores

### User Accounts DB

Stores user credentials (hashed passwords) and account information.

#### T - Tampering
**Title:** Credential Record Tampering
**Description:** An attacker modifies stored credential hashes or account data, either to take over
accounts or to corrupt the integrity of the user base (e.g. via SQL injection).

**Mitigations:**
- Use parameterized queries / prepared statements exclusively - no string-concatenated SQL
- Restrict DB write access to only the processes that require it (least privilege DB accounts)
- Enable DB-level audit logging for all write operations

#### R - Repudiation
**Title:** Missing Database Audit Trail
**Description:** There is no audit trail of who accessed or modified account records, making it
impossible to detect unauthorized access or attribute data changes.

**Mitigations:**
- Enable database audit logging for all reads and writes to account tables
- Retain audit logs in a separate, append-only store

#### I - Information Disclosure
**Title:** Credential Database Exfiltration
**Description:** Credential records are exfiltrated via SQL injection, an insider threat, or a
database breach, exposing usernames and password hashes.

**Mitigations:**
- Store passwords using a strong adaptive hashing algorithm (bcrypt, Argon2, scrypt) - never plaintext or MD5/SHA1
- Encrypt sensitive columns (e.g. PII) at rest
- Restrict network access to the DB to authorized services only; no direct external access

#### D - Denial of Service
**Title:** Database Unavailability
**Description:** The User Accounts DB is made unavailable through resource exhaustion, a destructive
query, or infrastructure failure, preventing all authentication.

**Mitigations:**
- DB replicas and automated failover
- Regular backups with tested restore procedures
- Connection pooling to prevent exhaustion from burst traffic

---

### Audit / Session Log

Append-only store recording login events, authorization decisions, and session lifecycle.

#### T - Tampering
**Title:** Log Tampering / Deletion
**Description:** An attacker modifies or deletes log entries to cover tracks after a compromise,
undermining forensic investigation and compliance.

**Mitigations:**
- Implement the log store as append-only; deny UPDATE and DELETE at the storage/DB layer
- Apply cryptographic integrity checksums (e.g. hash chaining) to log entries
- Ship logs in near-real-time to an external SIEM or log aggregator that the application cannot modify

#### R - Repudiation
**Title:** Insufficient Log Detail
**Description:** Logs contain insufficient detail (missing user identity, timestamp, or action) to
prove that a specific user performed a specific action.

**Mitigations:**
- Define and enforce a minimum log schema: timestamp, user ID, source IP, action, outcome
- Logs must be written synchronously for security-critical events (login, logout, privilege change)

#### I - Information Disclosure
**Title:** Secrets Written to Logs
**Description:** Raw session tokens, passwords, or other secrets are written into the log, making
the log itself a high-value target.

**Mitigations:**
- Redact or omit session token values, passwords, and PII from log entries
- Apply access controls to the log store - only security tooling and auditors should have read access

#### D - Denial of Service
**Title:** Log Storage Exhaustion
**Description:** Log storage is exhausted (intentionally or through log flooding), causing the
application to halt writes and potentially block logins if logging is on the critical path.

**Mitigations:**
- Set storage quotas and alerts on log volume
- Implement log rotation and archival
- Decouple log writes from the critical login path using an async queue with a circuit breaker

---

## Data Flows

### Identity / Account Info - Authenticate <-> User Accounts DB

Bidirectional flow: Authenticate queries the User Accounts DB with the submitted identity; the DB returns account data and stored credentials for verification.

#### T - Tampering
**Title:** Query Result Manipulation
**Description:** An attacker with access to the internal network modifies the DB response in transit (e.g. substituting a different account's credential hash) causing Authenticate to verify against thewrong record.

**Mitigations:**
- Use a direct, trusted connection to the DB (no intermediary proxies on the query path)
- Validate response integrity with signed DB responses or mTLS between the process and DB

#### I - Information Disclosure
**Title:** Credential Data Interception
**Description:** The account data returned by the DB (including credential hashes and user attributes)
is intercepted by an unauthorized process observing internal traffic.

**Mitigations:**
- Encrypt the connection between Authenticate and the DB (TLS or mTLS)
- Restrict network access to the DB to authorized services only; no lateral reachability from other hosts

#### D - Denial of Service
**Title:** DB Query Channel Disruption
**Description:** The connection between Authenticate and the User Accounts DB is severed or flooded,
making credential lookups impossible and blocking all authentication.

**Mitigations:**
- Connection pooling with health checks and automatic reconnection
- DB replicas with failover so a single node failure does not halt authentication
- Circuit breaker on the DB client to fail fast and surface errors clearly

---

### Login Credentials - User -> Authenticate

Carries the username and password from the client to the Authenticate process.

#### T - Tampering
**Title:** Man-in-the-Middle Credential Modification
**Description:** A man-in-the-middle modifies the credential payload in transit - e.g. substituting
a different username - before it reaches the Authenticate process.

**Mitigations:**
- TLS with certificate pinning on mobile clients
- Validate the integrity of the login request server-side (CSRF token tied to session)

#### I - Information Disclosure
**Title:** Credential Eavesdropping
**Description:** Credentials are transmitted in cleartext or logged, allowing an eavesdropper or
log reader to harvest them.

**Mitigations:**
- TLS mandatory on all connections; no HTTP fallback
- Never log raw credentials at any layer
- Do not include credentials in URLs or query parameters

#### D - Denial of Service
**Title:** Credential Flow Interruption
**Description:** An attacker disrupts the channel carrying credentials to the Authenticate process 
(e.g. via a volumetric attack or TCP reset injection) preventing login requests from reaching the server.

**Mitigations:**
- DDoS protection and traffic scrubbing at the network edge
- Connection rate limiting per source IP
- Redundant ingress paths and load balancing

---

### Identity - Authenticate -> Authorize

Carries the verified identity claim from the Authenticate process to the Authorize process.

#### T - Tampering
**Title:** Identity Claim Modification
**Description:** The identity claim is modified in transit - e.g. changing the user ID to that of
an administrator.

**Mitigations:**
- Signed tokens make tampering detectable; reject any token with an invalid signature
- Use encrypted internal channels (mTLS) between processes

#### I - Information Disclosure
**Title:** Identity Token Interception
**Description:** The identity claim (user ID, roles) is intercepted by an unauthorized process
observing internal traffic.

**Mitigations:**
- Encrypt internal service-to-service communication (mTLS or TLS on internal network)
- Minimize the data carried in the identity token - include only what Authorize needs

#### D - Denial of Service
**Title:** Internal Identity Flow Disruption
**Description:** The internal channel between Authenticate and Authorize is flooded or severed,
preventing verified identities from reaching the Authorize process and blocking all logins.

**Mitigations:**
- Health checks and circuit breakers on the internal communication path
- Process co-location or in-process calls to eliminate network hops where feasible
- Redundant internal routing

---

### Login Event + Rights - Authorize -> Audit/Session Log

Records the authorization decision and granted rights to the audit log.

#### T - Tampering
**Title:** Log Entry Modification in Transit
**Description:** A log entry is modified in transit before being written, altering the recorded
rights or outcome.

**Mitigations:**
- Use a direct, trusted internal write path to the log store with no intermediary that could modify entries
- Apply per-entry checksums at write time

#### I - Information Disclosure
**Title:** Authorization Data Interception
**Description:** The rights and login event data transmitted to the log store are intercepted by an
unauthorized process observing internal traffic, exposing user roles and session context.

**Mitigations:**
- Encrypt the internal channel to the log store (TLS or mTLS)
- Restrict network access to the log store to authorized services only

#### D - Denial of Service
**Title:** Log Write Channel Disruption
**Description:** The channel between Authorize and the Audit/Session Log is severed or flooded,
causing log writes to fail and potentially blocking the login flow if logging is synchronous.

**Mitigations:**
- Use an async write queue with a circuit breaker so log failures do not block authentication
- Alert on sustained log write failures
- Ensure the log store has dedicated, isolated network resources

---

### Session / Page - Login Processing -> User

Delivers the session token and initial page back to the client after successful login.

#### T - Tampering
**Title:** Session Token Forgery
**Description:** The session token value is modified by the client in an attempt to forge a
different user's session.

**Mitigations:**
- Session tokens must be cryptographically random and server-validated - the server must look up
  the token in its session store, not decode user identity from it directly
- Signed tokens (if stateless) must have their signature verified on every request

#### I - Information Disclosure
**Title:** Session Token Leakage via Response
**Description:** The session token is exposed in the HTTP response body, a redirect URL, or a
Referer header, allowing it to be captured by a third-party script or server.

**Mitigations:**
- Deliver the session token exclusively via a `Set-Cookie` header, never in the response body or URL
- Set `Referrer-Policy: no-referrer` or `strict-origin` to prevent token leakage via Referer

#### D - Denial of Service
**Title:** Response Channel Disruption
**Description:** An attacker disrupts the response channel (e.g. via connection exhaustion or
RST injection), preventing session tokens and pages from reaching the client after successful login.

**Mitigations:**
- Connection timeout and retry handling on the client side
- Load balancer health checks to reroute around degraded nodes
- DDoS protection at the network edge

---

### Identity Request / Confirm - Authorize <-> Login Processing

Bidirectional flow: Authorize passes the verified identity and granted rights to Login Processing; Login Processing confirms receipt before issuing the session token.

#### T - Tampering
**Title:** Identity Handoff Manipulation
**Description:** The identity and rights payload passed from Authorize to Login Processing is modified
in transit, causing Login Processing to issue a session with incorrect or elevated privileges.

**Mitigations:**
- Sign the internal handoff payload so Login Processing can detect modification before acting on it
- Use encrypted internal channels (mTLS) between Authorize and Login Processing

#### I - Information Disclosure
**Title:** Internal Identity Handoff Interception
**Description:** The identity and rights data passed between Authorize and Login Processing is
intercepted by an unauthorized process on the internal network, exposing user roles and session context.

**Mitigations:**
- Encrypt the internal channel (mTLS or TLS on the internal network)
- Restrict network reachability between processes to only the required service pairs

#### D - Denial of Service
**Title:** Authorize–LoginProcessing Channel Disruption
**Description:** The channel between Authorize and Login Processing is severed or flooded, preventing
session tokens from being issued even after successful authentication and authorization.

**Mitigations:**
- Health checks and circuit breakers on the internal communication path
- Process co-location or in-process calls to eliminate network hops where feasible
- Redundant internal routing

---

## External Entities

### User (Web / Mobile Client)

The human end-user accessing MegaTravel via a browser or mobile application.

#### S - Spoofing
**Title:** Account Impersonation via Stolen Credentials
**Description:** An attacker obtains a user's credentials (phishing, credential stuffing, brute
force) and authenticates as that user, fully impersonating them.

**Mitigations:**
- Multi-factor authentication (MFA) as a second factor independent of the password
- Anomaly detection on login patterns (unusual location, device, time)
- Notify users of new logins via email/SMS so they can detect impersonation

#### R - Repudiation
**Title:** Denial of Performed Actions
**Description:** A user denies having performed an action (e.g. a booking or payment) made during
their authenticated session, claiming their account was compromised.

**Mitigations:**
- Non-repudiation through signed, tamper-evident audit log entries recording user ID, timestamp,
  source IP, and the specific action taken
- Retain session logs for a period aligned with legal and business requirements
