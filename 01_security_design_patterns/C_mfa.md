# Multi-Factor Authentication in Web Applications

## Table of Contents

1. [Introduction](#introduction)
2. [Types of MFA](#types-of-mfa)
3. [Chosen Factors: Password and TOTP](#chosen-factors)
4. [Implementation: Password-Based Authentication](#implementation-password)
5. [Implementation: TOTP](#implementation-totp)
6. [Common Mistakes and Security Vulnerabilities](#common-mistakes)
7. [References](#references)

---

## 1. Introduction

Multi-Factor Authentication (MFA) is a security mechanism that requires users to verify their identity using two or more independent factors before gaining access to a system. The core principle is that even if one factor is compromised, an attacker cannot gain access without the others. MFA significantly reduces the risk of unauthorized access caused by stolen credentials, phishing, or brute-force attacks.

According to Microsoft's research, MFA can block over 99.9% of account compromise attacks. Despite this, many web applications either do not implement MFA at all, or implement it incorrectly — introducing new vulnerabilities in the process.

---

## 2. Types of MFA

Authentication factors are grouped into three broad categories, often referred to as the **three pillars of authentication**:

### 2.1 Something You Know (Knowledge Factors)

These are secrets that only the legitimate user should know. Examples include:

- **Passwords** — the most widely used knowledge factor
- **PINs** — short numeric codes
- **Security questions** — largely considered insecure today due to predictability

Knowledge factors are convenient but vulnerable to phishing, credential stuffing, keylogging, and database breaches.

### 2.2 Something You Have (Possession Factors)

These rely on a physical or digital object in the user's possession. Examples include:

- **TOTP apps** (e.g., Google Authenticator, Authy) — generate time-based codes
- **Hardware security keys** (e.g., YubiKey) — physical USB/NFC devices implementing FIDO2/WebAuthn
- **SMS one-time passwords** — codes sent via text message
- **Email OTPs** — codes sent to a verified email address
- **Smart cards** — common in enterprise and government settings

Possession factors are stronger than knowledge factors alone, but SMS and email OTPs are considered weaker due to SIM-swapping attacks and account takeover via email.

### 2.3 Something You Are (Inherence Factors)

These are biometric characteristics unique to the user. Examples include:

- **Fingerprint recognition**
- **Facial recognition**
- **Voice recognition**
- **Iris scanning**

Biometrics offer strong usability and security but raise significant privacy concerns, cannot be changed if compromised, and require dedicated hardware on the client side.

### 2.4 Additional Factor Categories

Beyond the three main categories, some frameworks define additional factors:

- **Somewhere you are (Location factors)** — verification based on IP address, GPS, or network geolocation
- **Something you do (Behavioral factors)** — typing rhythm, mouse movement patterns

NIST SP 800-63B is the primary authoritative reference for classifying and evaluating authenticator types, defining three Authenticator Assurance Levels (AAL1, AAL2, AAL3) based on factor strength and combination.

---

## 3. Chosen Factors

This document focuses on the combination of two factors:

1. **Password** — a knowledge factor (AAL1)
2. **TOTP (Time-based One-Time Password)** — a possession factor (AAL2 when properly implemented)

This combination is one of the most widely adopted MFA setups in web applications today, used by services such as GitHub, Google, AWS, and many others. It balances security, usability, and ease of implementation. Under NIST SP 800-63B, this combination satisfies **AAL2** requirements.

---

## 4. Implementation: Password-Based Authentication

### 4.1 Password Storage

Passwords must **never** be stored in plaintext. The correct approach is to store a one-way hash of the password using a purpose-built, slow hashing algorithm. The three recommended algorithms are:

- **bcrypt** — widely supported, includes a built-in salt, adjustable cost factor
- **Argon2id** — winner of the Password Hashing Competition (2015), recommended by OWASP as the first choice
- **scrypt** — memory-hard algorithm, good resistance to GPU-based attacks

Example using Argon2id (Python, using the `argon2-cffi` library):

```python
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=2,       # number of iterations
    memory_cost=65536, # 64 MB
    parallelism=2
)

# Hashing
hashed = ph.hash("user_password")

# Verification
try:
    ph.verify(hashed, "user_password")  # returns True
except Exception:
    pass  # verification failed
```

### 4.2 Password Policies

OWASP recommends the following password policy guidelines:

- Minimum length of **8 characters**, with a recommended minimum of **12**
- Maximum length of at least **64 characters** (to support passphrases)
- Allow all printable ASCII characters and Unicode
- **Do not require** character complexity rules (uppercase, numbers, symbols) — they reduce usability without significantly improving security
- **Check passwords against known breached databases** (e.g., using the [Have I Been Pwned API](https://haveibeenpwned.com/API/v3))
- Do not force periodic password rotation unless there is evidence of compromise

### 4.3 Secure Transmission

Passwords must only be transmitted over **HTTPS (TLS 1.2 or higher)**. The application should:

- Redirect all HTTP traffic to HTTPS
- Set `Strict-Transport-Security` (HSTS) headers
- Never log passwords, even partially

### 4.4 Brute-Force Protection

To prevent automated attacks against the login endpoint:

- Implement **account lockout** or **exponential backoff** after repeated failed attempts
- Use **CAPTCHA** or similar challenges after a threshold of failures
- Rate-limit login endpoints per IP and per account
- Monitor and alert on unusual login patterns

---

## 5. Implementation: TOTP

### 5.1 How TOTP Works

TOTP is defined in **RFC 6238** and is built on top of HOTP (HMAC-based One-Time Password, RFC 4226). The algorithm works as follows:

1. A **shared secret** (a random byte sequence, typically 20 bytes) is generated during setup and shared between the server and the user's authenticator app, usually via a QR code.
2. The current **time step** is calculated as:  
   `T = floor(current_unix_time / 30)`  
   (by default, TOTP uses 30-second time steps)
3. An HMAC-SHA1 of the secret and the time step is computed.
4. The result is **truncated** to produce a 6- or 8-digit code.

Because both the server and the authenticator app share the same secret and use the same time, they independently produce the same code at any given moment — no network communication is required to generate the code.

### 5.2 Enrollment (Setup)

During enrollment, the server must:

1. **Generate a cryptographically random secret** — at least 160 bits (20 bytes). Do not use weak or predictable sources of randomness.

```python
import pyotp
import os

# Generate a random base32-encoded secret
secret = pyotp.random_base32()  # internally uses os.urandom()
```

2. **Present the secret to the user** via a QR code encoding a `otpauth://` URI:

```
otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp
```

Libraries like `qrcode` (Python) or `qrcode.js` (JS) can generate the QR image.

3. **Verify that enrollment was successful** by asking the user to enter one valid code before activating TOTP on their account. This confirms the secret was correctly scanned.

4. **Securely store the secret** — encrypt it at rest using AES-256 or equivalent. Do not store it in plaintext in the database.

5. **Generate and store backup codes** — typically 8–10 single-use codes. Hash them before storing (use bcrypt or Argon2id, same as passwords).

### 5.3 Verification

When a user logs in:

1. The user provides their password (first factor — verified first).
2. If the password is correct, the user is prompted for their TOTP code.
3. The server computes the expected TOTP for the current time window.

```python
import pyotp

totp = pyotp.TOTP(user_secret)

# Allow 1 window of drift (±30 seconds) to account for clock skew
if totp.verify(user_provided_code, valid_window=1):
    # success
    pass
else:
    # failure
    pass
```

4. **Check the code against a used-codes store** — to prevent replay attacks within the same time window, keep track of recently used codes and reject duplicates.

### 5.4 Renewal and Recovery

Users must be able to recover access if they lose their TOTP device:

- **Backup codes** — single-use codes provided at enrollment. Each code should be invalidated immediately after use.
- **Re-enrollment flow** — allow users to set up a new TOTP device after verifying identity through a secondary mechanism (e.g., email link + knowledge question, or identity verification).
- **Admin override** — support staff should be able to disable TOTP and trigger a re-enrollment, after identity verification.

The re-enrollment or recovery process must itself be protected with a strong identity verification step — otherwise it becomes the weakest link in the MFA chain.

### 5.5 Disabling TOTP

If a user wants to disable TOTP:

- Require them to first authenticate successfully with both factors
- Consider a confirmation step (e.g., email notification) to alert the user in case this was triggered by an attacker who has temporary access

---

## 6. Common Mistakes and Security Vulnerabilities

### 6.1 TOTP-Specific Issues

#### Time Synchronization Problems

TOTP relies on both the server and the client having accurate clocks. If the server clock drifts significantly, valid codes will be rejected. Solutions:

- Sync the server clock using **NTP** (Network Time Protocol)
- Allow a tolerance window of ±1 or ±2 time steps (30–60 seconds drift)
- Do not set the window too large — a window of more than ±2 steps significantly increases the attack surface

#### Replay Attacks

A TOTP code is valid for the duration of its time window (30 seconds by default). An attacker who intercepts a code in transit can reuse it within that window.

**Mitigation:** Maintain a server-side cache of recently used codes and reject any code that has already been used, even within the same time window.

#### Weak or Predictable Secrets

Using `random.random()`, time-based seeds, or other non-cryptographic random number generators to produce TOTP secrets is a critical vulnerability.

**Mitigation:** Always use a cryptographically secure random number generator (`os.urandom()` in Python, `crypto.randomBytes()` in Node.js).

#### Secret Storage in Plaintext

Storing TOTP secrets unencrypted in the database means that a database breach immediately exposes all TOTP secrets, completely defeating the purpose of MFA.

**Mitigation:** Encrypt secrets at rest using a key stored separately from the database (e.g., in an HSM or secrets manager like AWS Secrets Manager or HashiCorp Vault).

#### Backup Code Vulnerabilities

- **Storing backup codes in plaintext** — an attacker with database access can read all backup codes.
- **Brute-forcing backup codes** — if backup codes are short (e.g., 6 digits), they are vulnerable to brute force.
- **Codes not invalidated after use** — a backup code that can be reused is not a one-time code.

**Mitigation:** Generate backup codes with at least 64 bits of entropy, hash them before storage, and invalidate each code immediately upon use.

### 6.2 Password-Specific Issues

#### Insufficient Hashing

Using MD5, SHA-1, or even SHA-256 for password hashing is insecure because these are fast algorithms — an attacker with the hash can test billions of guesses per second on commodity hardware.

**Mitigation:** Use Argon2id, bcrypt, or scrypt with appropriate cost parameters.

#### No Salt

Without a per-user salt, identical passwords produce identical hashes. This enables rainbow table attacks and reveals when multiple users share the same password.

**Mitigation:** All recommended algorithms (Argon2id, bcrypt, scrypt) include automatic salting. Never implement password hashing manually.

#### Insufficient Brute-Force Protection

An unprotected login endpoint allows an attacker to test millions of password combinations with no consequence.

**Mitigation:** Implement rate limiting, account lockout, and CAPTCHA as described in Section 4.4.

### 6.3 MFA Flow-Level Issues

#### MFA Bypass via Password Reset

If the password reset flow does not require MFA re-enrollment, an attacker who gains access to a user's email can reset the password and log in without the TOTP device.

**Mitigation:** After a password reset, either require TOTP verification before completing the reset, or force re-enrollment of TOTP.

#### Step-Up Authentication Not Enforced

Some implementations check MFA at login but do not require it again for sensitive actions (e.g., changing email, withdrawing funds).

**Mitigation:** Implement step-up authentication — re-prompt for MFA before high-risk operations.

#### Phishing and Real-Time Phishing Proxies

Sophisticated phishing attacks use reverse proxies (e.g., Evilginx2) to relay credentials and TOTP codes in real time to the legitimate site, obtaining a valid session for the attacker.

**Mitigation:** TOTP does not protect against this. The only effective defense is a **phishing-resistant factor** such as FIDO2/WebAuthn (hardware security keys or passkeys), which binds the credential to the origin.

#### MFA Fatigue (Push Notification Bombing)

When MFA is implemented via push notifications (not TOTP), attackers can spam approval requests hoping the user approves one by accident.

**Mitigation:** This does not apply to TOTP specifically, but is worth noting when choosing MFA type. TOTP requires the attacker to have the code, so fatigue attacks are not possible.

#### Insecure Fallback Mechanisms

Offering a fallback to SMS OTP when TOTP is unavailable can undermine the entire MFA setup, since SMS is vulnerable to SIM-swapping.

**Mitigation:** Choose fallback mechanisms carefully and document their security tradeoffs. Backup codes are generally preferable to SMS as a fallback.

---

## 7. References

All references listed below are primary, authoritative sources.

1. **OWASP Multi-Factor Authentication Cheat Sheet**  
   https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html  
   *Comprehensive guide to MFA types, implementation, and common mistakes.*

2. **OWASP Authentication Cheat Sheet**  
   https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html  
   *Covers password storage, brute-force protection, and secure session management.*

3. **OWASP Password Storage Cheat Sheet**  
   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html  
   *Details on algorithm selection, cost parameters, and migration strategies.*

4. **NIST Special Publication 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management**  
   https://pages.nist.gov/800-63-3/sp800-63b.html  
   *The US federal standard for authentication; defines AAL1/AAL2/AAL3 and authenticator types.*

5. **RFC 6238 — TOTP: Time-Based One-Time Password Algorithm**  
   https://datatracker.ietf.org/doc/html/rfc6238  
   *The official TOTP specification.*

6. **RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm**  
   https://datatracker.ietf.org/doc/html/rfc4226  
   *The HOTP specification on which TOTP is based.*

7. **RFC 3986 — Key Uri Format for OTP (otpauth URI scheme)**  
   https://github.com/google/google-authenticator/wiki/Key-Uri-Format  
   *Documents the `otpauth://` URI format used in QR code enrollment.*

8. **pyotp — Python TOTP/HOTP Library**  
   https://pyauth.github.io/pyotp/  
   *Reference implementation of TOTP in Python, useful for understanding the algorithm.*
