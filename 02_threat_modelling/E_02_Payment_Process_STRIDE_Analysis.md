# E. Threat and Mitigation Analysis: Payment Process

## Processes

### Client authentication and authorization

Authenticates and authorizes clients before any booking or payment is processed. Sends
identification records to the Log. Described in previous file!

### B2B/B2C booking service

Checks if the desired hotel is available and procceed further.

#### S - Spoofing

**Title:** Fake Availability Response Injection

**Description:** A malicious actor impersonates the B2B/B2C external system and returns a fabricated "available" response to the Booking Service, causing the platform to proceed with payment for a property that is not actually free or does not exist.

**Mitigations:**

- Verify the B2B/B2C System's identity via mTLS or signed API responses; reject responses without a valid signature or from an untrusted certificate.
- Pin the TLS certificate or CA of each registered B2B partner endpoint; alert on certificate changes.

#### T - Tampering

**Title:** Availability Response Manipulation

**Description:** A man-in-the-middle intercepts and modifies the availability response in transit - e.g. changing "unavailable" to "available", altering booking dates, or modifying pricing data - before it reaches the Booking Service.

**Mitigations:**

- Require HMAC or digital signature over the full availability response payload; the Booking Service validates the signature before acting on it.
- Re-validate critical booking parameters (dates, property ID, price) server-side against internal configuration before passing them to the payment process.

#### R - Repudiation

**Title:** No Record of Availability Check

**Description:** Availability check requests and responses are not logged, making it impossible to prove what availability data was returned at the time of booking - critical for dispute resolution when a client arrives at a property that is already occupied.

**Mitigations:**

- Log every availability request and response with timestamp, property ID, requested dates, B2B partner identity, and the raw response outcome.

#### I - Information Disclosure

**Title:** Property or Pricing Data Leakage

**Description:** Internal property data, partner pricing structures, or availability patterns are leaked - e.g. through verbose error messages from the Booking Service, unauthenticated API endpoints, or unencrypted responses from the B2B system.

**Mitigations:**

- Return only the minimum necessary availability data to downstream processes (available: yes/no, booking reference); do not expose partner internal pricing structures or inventory levels.

#### D - Denial of Service

**Title:** Booking Service DoS or B2B Dependency Failure
**Description:** An attacker floods the Booking Service with availability check requests, exhausting its capacity. Alternatively, the external B2B/B2C System becomes unavailable, causing all availability checks - and therefore all bookings - to fail.

**Mitigations:**

- Rate limit availability check requests per authenticated client session.
- CAPTCHA after a threshold of failed attempts

#### E - Elevation of Privilege

**Title:** Booking Without Valid Authentication
**Description:** An attacker bypasses the Client Authentication process and calls the Booking Service directly, querying property availability or injecting a fake "confirmed available" signal into the payment flow without a valid authenticated session.

**Mitigations:**

- The Booking Service must validate a signed session token issued by the Client Authentication process on every request; reject unauthenticated or unsigned requests.

---

### Electronic payment service

Main service of payment system that communicate with core banking system and notifies the user if the booking is done successfully.

#### S - Spoofing

**Title:** Forged Payment Instruction

**Description:** An attacker forges or replays a payment instruction — e.g. a manipulated booking confirmation or payment details message — to trigger an unauthorized payment or redirect funds to a different account.

**Mitigations:**

- Sign all inter-process payment instructions with HMAC or asymmetric keys; reject instructions with invalid or missing signatures.
- Include a nonce or message ID in each payment instruction and reject replays.
- Bind payment instructions to a specific session and booking reference.

#### T - Tampering

**Title:** Payment Amount or Destination Tampering

**Description:** A man-in-the-middle or compromised internal service modifies the payment amount, currency, or destination account number in transit between the Client Auth process and the Electronic Payment process before the charge is submitted to the Core Banking System.

**Mitigations:**

- Encrypt all internal service-to-service communication with mTLS.
- Include a cryptographic HMAC over the full payment payload; the Electronic Payment process verifies the HMAC before processing.
- Fetch payment parameters (amount, recipient) from a server-side trusted source rather than relying solely on the incoming message.

#### R - Repudiation

**Title:** Payment Event Not Logged

**Description:** Payment processing events — initiation, gateway authorization, success, or failure — are not written to the Log Record, making it impossible to audit transactions, dispute chargebacks, or satisfy PCI-DSS audit requirements.

**Mitigations:**

- Log every payment event with transaction ID, booking reference, amount, currency, timestamp, and outcome.
- Retain payment logs for a period consistent with PCI-DSS and local financial regulatory requirements.
- Use an append-only Log Record store and forward to an external SIEM in near real-time.

#### I - Information Disclosure

**Title:** Card Data or Payment Details Exposure

**Description:** Full card numbers, CVVs, or bank account details are exposed in transit, in logs, or in error responses — violating PCI-DSS and enabling downstream payment fraud.

**Mitigations:**

- Never store, log, or transmit raw card numbers or CVVs; use a PCI-DSS compliant tokenization service.
- Transmit card data only over TLS 1.2+ connections; reject cleartext payment channels.
- Mask card numbers in all log output (show only last 4 digits).

#### D - Denial of Service

**Title:** Payment Endpoint Flood or Core Banking Dependency Failure

**Description:** An attacker floods the Electronic Payment process with requests, exhausting its capacity and preventing legitimate clients from completing bookings. Alternatively, the Core Banking System becomes unavailable, causing all payment processing to fail.

**Mitigations:**

- Rate limit payment requests per authenticated client session and per booking reference.
- Circuit breaker on the Core Banking System connection: fail fast with a clear error rather than hanging.
- Async payment queue with backpressure to decouple receipt of payment requests from actual processing.

#### E - Elevation of Privilege

**Title:** Unauthorized Payment Initiation

**Description:** A lower-privileged or unauthenticated caller bypasses the Client Authentication process and invokes the Electronic Payment process directly, initiating payments without a valid booking or authenticated identity.

**Mitigations:**

- The Electronic Payment process must verify a valid signed session and booking token on every request; reject unauthenticated or unsigned calls.
- Enforce a strict state machine: payment can only be initiated after a confirmed, logged availability result from the Booking Service.
- Network-level isolation: the Electronic Payment process is not reachable from untrusted network segments or directly from the internet.

## Data Stores

### User Accounts DB

Stores user credentials (hashed passwords) and account information. Described in the previous file.

### Client identification / payment logs

Append-only store recording client identification and payments accross our app.

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
