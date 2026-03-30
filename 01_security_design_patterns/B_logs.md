# Logiggin and auditing in systems

## Table of contents
- [Logiggin and auditing in systems](#logiggin-and-auditing-in-systems)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Log structure](#log-structure)
  - [Log types](#log-types)

## Introduction
Log files are only useful if you can learn from them. Without normalization and centralization, logs become noise instead of answers. It is of crucial importance to have a well structured log records, implying exact events in a system, user actions, time of their origin, etc.

A well-designed logging mechanism is the backbone of system observability and security. It must go beyond simply writing events to a local file—it needs to guarantee data integrity so actions cannot be denied (non-repudiation), automatically redact sensitive user information, and ensure high availability so crucial diagnostic data is never lost during a system outage.

Troubleshooting thru logs becomes faster. Logs show exactly what happened, when, and what triggered it, so you yourself may trace the root cause without guessing.

## Log structure

Anatomy of a high-quality log record should contain three categories of data: When, Where, and What.
1. The "When" (Temporal Metadata) 
   
   - Timestamp: High-precision (ISO 8601 format) including milliseconds and timezone offset.
2. The "Where" (Contextual Metadata)
   - Service Name: Which microservice generated this? (e.g., auth-service).
   - Environment: Is this production, staging, or development?
   - Host/Container ID: The specific server or Docker container name.
   - Trace ID / Correlation ID: A unique ID that follows a single user request across multiple services. This is the "holy grail" of troubleshooting.
3. The "What" (The Payload)
   - Level: The severity (e.g., INFO, WARN, ERROR, FATAL).
   - Actor/User ID: Who performed the action? (Crucial for non-repudiation).
   - Action: What happened? (e.g., login_attempt, file_upload).
   - Status: Was it a success or failure?
   - Message: A short, human-readable summary. Note: Do not put dynamic variables here; put them in separate fields.

All the sections and subsections mentioned above, make logs indexable in a system, so they are easily discoverable, searchable, and interpretable.

If logs contain user sensitive data, it should, at best, be ommited. Log record's structure should strive to be flat, rather than nested. This is because nesting maxes indexing more cumbersome.

## Log types

While all logs should follow the structured anatomy mentioned above, they generally fall into four functional categories:

- Audit logs: Track admin actions and config changes for compliance.
- Access logs: Show who accessed what, when, and from where—helpful for user behavior analysis.
- Transaction logs: Used in databases and financial systems to trace query history or payment events.
- Security Logs (WAF/Auth): Records of login attempts, firewall blocks, or suspicious API calls. These are the primary source for threat detection and incident response.