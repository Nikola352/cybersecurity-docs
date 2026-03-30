# Logiggin and auditing in systems

## Table of contents

- [Logiggin and auditing in systems](#logiggin-and-auditing-in-systems)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Log structure](#log-structure)
  - [Log types](#log-types)
  - [High-availability (HA) logging service](#high-availability-ha-logging-service)
  - [Log rotation](#log-rotation)
    - [LogRotate](#logrotate)
    - [Known Attacks](#known-attacks)
      - [The Exploit](#the-exploit)
      - [The Result](#the-result)
      - [Mitigations](#mitigations)
    - [Docker log rotation](#docker-log-rotation)
  - [ELK Stack - Elastic Search, LogStash, Kibana](#elk-stack---elastic-search-logstash-kibana)
      - [LogStash](#logstash)
      - [Elastic Search hierarchy](#elastic-search-hierarchy)
      - [Kibana](#kibana)
  - [References](#references)

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

While all logs should follow the structured anatomy mentioned above, they generally fall into these functional categories:

- System Logs: Logs that record foundational system-level events, such as kernel activities and hardware errors, to help administrators monitor the overall health and stability of the operating system.

- Application Logs: Generated directly by specific software applications, containing contextual information and severity levels to aid debugging errors and understand software behavior.

- Security Logs: Specifically track security-focused events—such as authentication attempts, access controls and intrusion detection alerts.

- Audit Logs: High-integrity evidence for compliance and forensic analysis, these logs provide tracking of user actions, data access, and system configuration changes.

- Event Logs: Acting as a comprehensive timeline, these logs track state changes across the operating system, security mechanisms, and applications to provide a high-level overview.


## High-availability (HA) logging service

HA logging system ensures continuous, uninterrupted log collection and storage by eliminating single points of failure through redundancy, load balancing, and failover mechanisms. Key architectures include clustered deployments (e.g., Graylog with Elasticsearch) and active-passive or active-active setups. If a network connection or logging endpoint becomes temporarily unavailable, the application has to attempt resource-intensive retry logic to resume log streaming, which could impact overall performance.

If there's a persistent outage, the logs could be dropped and lost forever which could impact the troubleshooting process, ability to comply with regulations, or even conduct security investigations.

## Log rotation
Usually we rotate logs, so that log file can be archived, and later zipped with multiple archived log files and transported to a different system or a service for processing. It involves declaring a policy where after a certain amount of times, logs are rotated to allow easier processing or free up space. Enourmous log files can be prevented by archiving them per intervals, allowing easier processing later when they are passed to a different service that will process them.
### LogRotate

LogRotate is a service for log rotation on Linux. 

It decouples the log generation process from the log transmission process, seperating concerns so application does not need to focus on log transimission. Instead system is to rely on the log forwarder to handle the complexities of log delivery.

Rotation Process:
1. Rename - current active log is renamd to archived name
2. Create new - new empty log file is created to continue logging
3. Compression, old files are compressed to .gz, saving space
4. Cleanup- logs exceeding retention count are deleted, set in /etc/logrotate.conf — the log rotation configuration file

### Known Attacks
Log injection - Abusing race condition to elevate privledges 

Preconditions are:
- Logrotate must be root user
- unprivledged user has to control logdir path
- conf file should have directives for file creation

Attacker submits malicious data, written to a log file. If log rotate moves the file, it may processes injected entries.

A race condition exists if logrotate gets executed with the “create” option. Known vulnerable directives are  prerotate, postrotate.

#### The Exploit
The race-condition can be exploited by setting a inotify-hook at the logfile. As soon as logrotate hits the logfile, the exploit gets notified and exchanges the log directory by a symbolic link to /etc/bash_completion.d. 

#### The Result
Logrotate will then create the new logfile into /etc/bash_completion.d as root and will adjust the owner and permissions of that file afterwards. The new logfile will be writable if logrotate is configured to set the owner of the file to the uid of the malicious user.

Therefore the attacker can write a payload for a reverse shell into this file. As soon as root logs in, the reverse shell will be executed and spawns a root shell for the attacker.

#### Mitigations

To prevent these attacks, a secure logging design should incorporate:

- Strict Permissions: Ensure that log directories are owned by root and are not writable by unprivileged users.

- Use su Directive: Always using su (switch user) directive in the LogRotate config to rotate logs using the specific user/group of the application rather than root.

- Move to Data Streams: Stream logs directly to stdout/stderr (Docker) or a remote socket, bypassing the need for local file rotation entirely.

### Docker log rotation

In Docker, primarily, there are two types of log files.

- Docker daemon logs - These logs are generated by the Docker daemon and located on the host. It provides insights into the state of the Docker platform.

- Docker container logs - Docker container logs cover all the logs related to a particular application running in a container.

Docker does not impose a size restriction on logging files. Hence they will inevitably increase over time and consume storage if left unchecked.

Docker uses "Logging Drivers" to handle data.
Global rotation policy can be defined in 
deamon.json (/etc/docker/) 

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

If intent is to limit logs for a specific service (like a high-traffic web server), it can be defined in docker-compose.yml:
```yml
services:
  web-app:
    image: my-app:latest
    logging:
      driver: "json-file"
      options:
        max-size: "10m",
        max-file: "5"
```


## ELK Stack - Elastic Search, LogStash, Kibana

Based on three components, each handling one concern: 
- ElasticSearch - full text search and analasys engine, based on Lucene, here logs are stored and indexed.

- LogStash - log aggregator, processign engine, normalizes data so its consistent. Collects data from various sources and filters it so its readable.

- Kibana - vizualization layer, charts, exploration

#### LogStash

Logs from app, can be dumpted into an bucket  (S3) or any data stream to move the logs, logstash picks them up, processes them, then dumps them to ElasticSearch for indexing, and later search and filtering.

#### Elastic Search hierarchy
ElasticSearch stores logs using a specific structure that balances speed with storage efficiency, following the heirarchy:

Indices: Documents are grouped into Indices (e.g., waf-logs-2026-03-24). Index is used as a table in a database.

Shards: To handle massive amounts of data, an index is split into Shards. This allows ElasticSearch to spread one index across multiple servers.

Segments: Inside each shard, data is stored in Lucene Segments. These are immutable files that are compressed and optimized for fast searching.

Confguration:

A. Index Templates

- Settings: Number of shards and replicas.

- Mappings: Defines field types (e.g., "client_ip" is an ip type, not just a string).
    
    
B. Mappings (The Schema)

This is very important step in configuration. If ElasticSearch is to guess wrong and thinks a numeric ID is a "date," searches will break.

- Keyword vs. Text: Use keyword for IDs, Status Codes, and IPs (exact matches). Use text for log messages (searchable phrases).

- Geo-point: Specifically map your latitude/longitude fields so you can use Kibana's map features.

C. Index Lifecycle Management (ILM)

- Hot Phase: Logs from today (high-speed SSDs, fast searching).

- Warm Phase: Logs from last week (cheaper storage, slower searching).

- Delete Phase: Automatically delete logs older than 30 or 90 days to save money.

D. Data Streams

For logging, it is advisable to use Data Streams. They act as a single "virtual" index (e.g., logs-waf-prod) that automatically handles the creation of new hidden indices automatically. It makes managing time-series data much simpler.

#### Kibana
Visualization layer that allows users to transform raw logs into intelligence through several key features:

- Dashboards: Centralized views containing time filters, global search bars, and data tables.

- Visualizations: Drag-and-drop tools for creating heatmaps, pie charts and coordinate maps.

- KQL (Kibana Query Language): A simple syntax for filtering logs in real-time. Examples:
    - event.action: "login_failure" AND user.id: 552

    - http.response.status_code >= 500

System using these 3 components becomes performant, cost-effective and secure.

## References
1. **Logs Data Model** https://opentelemetry.io/docs/specs/otel/logs/data-model/
2. **Exploring Various Log Types and Formats for Better Log Management** https://edgedelta.com/company/blog/log-types-and-formats
3. **Graylog** https://go2docs.graylog.org/5-0/what_is_graylog/what_is_graylog.htm?tocpath=What%20Is%20Graylog%253F%7C_____0
4. **What is log rotation** https://www.crowdstrike.com/en-us/cybersecurity-101/next-gen-siem/log-rotation/
5. **LogRotate** https://linux.die.net/man/8/logrotate
6. **Details of a logrotate race-condition** https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition
7. **Docker Log Rotation Configuration Guide** https://signoz.io/blog/docker-log-rotation/
8. **The Complete Guide to the ELK Stack** https://logz.io/learn/complete-guide-elk-stack/
9. **ELK Stack Comprehensive Guide** https://dev.to/kaustubhyerkade/elk-stack-a-comprehensive-guide-to-installing-and-configuring-the-elk-stack-el7