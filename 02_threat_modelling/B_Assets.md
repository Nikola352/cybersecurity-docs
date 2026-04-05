# Sensitive Assets — _MegaTravel_

## Introduction

Asset identification is a prerequisite for meaningful risk assessment: without knowing what needs protection, it is impossible to prioritize security investment [[OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process), [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)]. Following ISO 27001 Annex A.8, assets are inventoried and classified by their value, sensitivity, and criticality [[ISO 27001 Annex A.8](https://hightable.io/iso-27001-annex-a-5-9-inventory-of-information-and-other-associated-assets/)]. For each asset, three properties from the **CIA triad** [[Fortinet](https://www.fortinet.com/resources/cyberglossary/cia-triad), [Splunk](https://www.splunk.com/en_us/blog/learn/cia-triad-confidentiality-integrity-availability.html)] are evaluated:

- **C — Confidentiality**: only authorized parties can read the asset
- **I — Integrity**: the asset cannot be altered without authorization
- **A — Availability**: the asset is accessible when needed

Each property is rated **H**, **M**, or **L** based on the impact of a compromise, following [NIST SP 800-30 Rev. 1](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-30r1.pdf) guidance on impact levels:

| Level | Meaning |
|---|---|
| **H** — High | Severe or catastrophic impact: significant financial loss, regulatory penalty, safety risk, or operational failure |
| **M** — Medium | Serious but contained impact: meaningful disruption, limited data exposure, or elevated risk requiring prompt attention |
| **L** — Low | Limited impact: minor inconvenience, low data sensitivity, or easily recoverable harm |

The threat actors identified in [Task A](./01_Threat_Actors.md) directly inform which assets are sensitive and why — their goals determine what is worth attacking.

---

## Asset Categories

### 1. Customer Personal Data

MegaTravel processes personal data of over 100 million customers across jurisdictions subject to strict privacy regulation. Travel companies routinely collect terabytes of sensitive customer data: passport numbers, credit/debit card information, and PII (Personally Identifiable Information) [[Managed Outsource Solutions](https://www.managedoutsource.com/blog/significance-of-data-privacy-and-security-in-the-travel-and-tourism-industry/)].

| Asset | Exposure | C | I | A | Impact if Compromised |
|---|---|---|---|---|---|
| Full name, address, email, phone number | Customers (self), customer-facing staff, marketing systems | H | M | L | GDPR/CCPA breach notification obligations; fines up to €20M or 4% of global turnover; reputational damage |
| Passport and travel document data | Customers (self), booking agents, partner airlines/hotels | H | M | L | Identity theft; regulatory fine; potential safety risk for high-profile individuals |
| Date of birth and nationality | Customers (self), booking agents | H | L | L | Identity theft; GDPR violation |
| Travel history and past itineraries | Customers (self), internal analysts, partner systems | H | M | L | Profiling; enables targeted phishing or social engineering against customers |
| **Future booking and itinerary data (high-profile individuals)** | Customers (self), booking agents, partner airlines/hotels | H | M | M | APT espionage target — compromises physical security of diplomats, executives, military officials; parallels Marriott breach which exposed diplomat data |
| Loyalty and rewards program data | Customers (self), loyalty platform, partner systems | H | H | M | Point theft is a documented fraud vector in travel industry; financial and reputational damage |
| Account login credentials (hashed passwords, MFA configs) | Authentication system only | H | H | L | Account takeover; enables all downstream fraud against customer data |
| Session tokens and authentication cookies | Client browser, web application | H | M | M | Session hijacking; impersonation of customers; if session store is down, users cannot access the platform |
| Customer communication history (support chat, email logs) | Customer service staff, internal systems | H | L | L | Privacy violation; social engineering material; GDPR scope |

> **Threat actor relevance:** Career Cybercriminals are the primary threat — they target PII for phishing campaigns, resale, and identity fraud. State-Sponsored Actors (APTs) specifically target **future itinerary data** of high-profile passengers to track diplomatic and military movement (see geographic breakdown: Hong Kong APT41/APT27, London political espionage). Insiders (customer service staff) have direct access and may leak celebrity or political data for personal gain.

---

### 2. Payment & Financial Data

Payment data is among the most directly monetizable assets. The British Airways Magecart attack (2018) demonstrated that injecting malicious JavaScript into a payment page is sufficient to steal 380,000 card records — resulting in a £20M ICO fine and the largest personal data group action in UK history [[Huntress](https://www.huntress.com/threat-library/data-breach/british-airways-data-breach), [SecurityWeek](https://www.securityweek.com/british-airways-settles-class-action-over-2018-data-breach/)]. The Orbitz/Expedia breach (2016–17) separately compromised 880,000 payment cards [[Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/880000-payment-cards-data-breached-in-orbitz-security-incident)].

| Asset | Exposure | C | I | A | Impact if Compromised |
|---|---|---|---|---|---|
| Credit/debit card numbers, CVVs, expiry dates | Payment processor, PCI-DSS scoped systems only | H | H | L | Direct financial fraud; PCI-DSS violation; fines, loss of card processing ability |
| Bank account details (for refunds/direct debit) | Finance team, payment processor | H | H | L | Direct financial fraud; misdirected funds; regulatory breach |
| Transaction history | Finance team, fraud detection system, auditors | H | H | M | Enables fraud pattern analysis by attackers; privacy violation; fraud detection depends on near-real-time access |
| Refund records | Finance team, customer service | M | H | M | Exploited by Organized Crime for money laundering via bulk refund abuse |
| Revenue and financial reporting data | Finance leadership, auditors, executives | H | H | M | Competitive intelligence; stock manipulation if publicly listed |
| Promotional codes and discount configurations | Marketing team, e-commerce platform | L | H | M | Insiders or external attackers can generate unauthorized discounts; revenue loss |

> **Threat actor relevance:** Career Cybercriminals are the dominant threat — direct card theft and fraud. Organized Crime Groups exploit refund flows for money laundering (fake bookings, mass cancellations for clean refunds). Insiders with access to promo code systems can manipulate discounts for personal benefit.

---

### 3. Business & Operational Data

| Asset | Exposure | C | I | A | Impact if Compromised |
|---|---|---|---|---|---|
| Fraud detection rules and thresholds | Security team, fraud analysts | H | H | M | Exposure allows attackers to craft transactions that evade detection; directly undermines all financial security controls [[OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)] |
| Internal business intelligence and analytics | Analysts, executives | H | M | L | Competitive intelligence; reveals customer segments and strategic priorities |
| Employee records (HR data, roles, access levels, salaries) | HR team, payroll, managers | H | M | L | Privacy violation; enables targeted social engineering; access level data aids privilege escalation planning |
| Internal communications (email, messaging platforms) | Staff (role-based) | H | L | L | Insider threat investigation material; business intelligence for competitors |
| Marketing strategies and campaign data | Marketing team | M | L | L | Competitive intelligence |

> **Threat actor relevance:** State-Sponsored Actors target **algorithms and source code** as Intelectual Property (IP) theft (Boston division explicitly identified in Task A). Career Cybercriminals and Insiders target employee records for social engineering. Compromising **fraud detection rules** is a prerequisite for the money laundering flows described for Organized Crime Groups.

---

### 4. Partner & Third-Party Integration Data

The Prestige Software breach (2013–2020) is the canonical example: a misconfigured AWS S3 bucket exposed seven years of customer records aggregated from Booking.com, Expedia, Agoda, Amadeus, Hotels.com, and Hotelbeds — including credit cards, CVV codes, names, reservation details, and ID numbers [[Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/hotel-reservation-platform-leaks-7-years-worth-of-customer-records-exposes-millions-to-fraud-and-extortion)]. Third-party integrations dramatically expand the attack surface [[Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/online-privacy/pii-leaks-and-other-risks-from-unsecure-e-commerce-apis)].

| Asset | Exposure | C | I | A | Impact if Compromised |
|---|---|---|---|---|---|
| API credentials for airline partners | Integration layer, DevOps | H | H | M | Unauthorized access to flight inventory; data exfiltration from partner systems; lateral movement |
| API credentials for hotel/accommodation partners | Integration layer, DevOps | H | H | M | Enables fraudulent booking creation; data theft from partner systems |
| API credentials for car rental and tour operators | Integration layer, DevOps | H | H | M | Fraudulent reservations; data theft from partner systems |
| **GDS (Global Distribution System) access credentials** (e.g., Amadeus, Sabre) | Integration layer, booking engine | H | H | H | GDS compromise gives read/write access to global travel inventory across hundreds of airlines and thousands of hotels; catastrophic blast radius |
| Partner contracts, SLAs, and pricing agreements | Executives, legal, procurement | H | H | L | Competitive intelligence; enables contract fraud; legal liability if tampered |
| Partner data received via API (co-mingled customer records) | Internal data pipelines | H | H | L | Breach liability extends to partner customers; multiplies regulatory scope |

> **Threat actor relevance:** State-Sponsored Actors use third-party vendor compromise as a backdoor (supply chain attack) to avoid direct detection — explicitly noted in Task A. GDS credential theft in particular would be a high-value APT target. Script Kiddies scanning for exposed API keys (misconfigured S3 buckets, public repos) are a lower-sophistication but realistic risk.

---

### 5. Authentication & Cryptographic Material

| Asset | Exposure | C | I | A | Impact if Compromised |
|---|---|---|---|---|---|
| Admin account credentials | System administrators only | H | H | M | Full system compromise; enables all other attacks |
| Employee directory credentials (SSO/Active Directory) | All employees (own credentials) | H | H | M | Lateral movement; privilege escalation; impersonation |
| Service account credentials | DevOps, CI/CD pipelines | H | H | H | Persistent unauthorized system access; services break if credentials are revoked or corrupted |
| Database encryption keys | Key management system, DBAs | H | H | M | Decryption of entire customer and financial database |
| TLS/SSL certificates and private keys | Web servers, load balancers | H | H | H | Man-in-the-middle attacks; impersonation of MegaTravel services; expiry causes service unavailability |
| JWT signing secrets and OAuth tokens | Authentication service | H | H | M | Token forgery; complete authentication bypass for any user |
| Secrets in config stores (web app config, worker config) | Application runtime, DevOps | H | M | M | Exposure of all downstream credentials and API keys stored as configuration |

> **Threat actor relevance:** Insiders with elevated access are the primary threat — a disgruntled developer with access to service account credentials or JWT signing secrets can cause catastrophic damage while being difficult to detect. Hacktivists targeting admin accounts to perform defacement (Task A) also fall here. Career Cybercriminals seek credentials for account takeover at scale.

---

### 6. Infrastructure & Technical Assets

| Asset | Exposure | C | I | A | Impact if Compromised |
|---|---|---|---|---|---|
| Booking platform web application | Internet-facing (all users) | L | H | H | Core business function; downtime = direct revenue loss; tampering = defacement or fraud |
| Payment processing pipeline | Payment processor integration | L | H | H | Transaction failure = revenue loss; integrity failure = financial fraud |
| Background worker process (order processing) | Internal network only | L | H | H | Failure blocks order fulfillment; compromise enables order manipulation |
| Database servers (customer, booking, financial data) | Application layer only | H | H | H | Full breach of all data assets; ransomware target |
| Message queue | Internal services | L | H | H | Manipulation of queued orders; DoS against worker processes |
| Web/application servers | Internet-facing | L | M | H | DDoS target; downtime during peak booking season = significant revenue loss |
| Authentication and IAM system | All authenticated users | M | H | H | Auth bypass; outage locks out all users and staff; cascading failure across all services |
| Config stores (web app config and worker config) | Application runtime | H | H | M | Contain secrets; tampering redirects traffic or alters application behavior |
| Internal network infrastructure (VPNs, firewalls) | IT/network team | M | H | H | Compromise enables unrestricted internal access; routing attacks |
| Employee endpoints (laptops, mobile devices) | Individual employees | H | M | M | Entry point for phishing-delivered malware; insider threat vector |
| **Source code repositories (intellectual property)** | Engineering team | H | H | M | IP theft (state-sponsored); backdoor injection; Boston-specific risk per Task A |
| CI/CD pipelines | DevOps team | M | H | M | Supply chain attack vector; malicious code injection into production deployments |
| Backup systems and disaster recovery infrastructure | IT/DR team | M | M | H | Ransomware specifically targets backups to prevent recovery without paying |

> **Threat actor relevance:** Hacktivists and Script Kiddies target **platform availability** via DDoS — particularly during peak travel seasons to maximize damage. Ransomware groups (Career Cybercriminals) target **databases and backups** simultaneously. State-Sponsored Actors target **source code and CI/CD pipelines** for IP theft and supply chain compromise. Insiders planting logic bombs target **worker processes and application servers**.

---

### 7. Audit & Compliance Records

| Asset | Exposure | C | I | A | Impact if Compromised |
|---|---|---|---|---|---|
| System access and activity logs | Security team, auditors, SIEM | M | H | H | Tampering conceals attacks and hinders incident response; unavailability delays forensics |
| Payment audit trails | Finance team, auditors, PCI-DSS assessors | M | H | H | PCI-DSS requires audit trail integrity; loss may trigger non-compliance finding |
| Data processing records (GDPR Article 30) | DPO, legal, auditors | M | H | H | GDPR requires records of processing activities; loss = regulatory non-compliance |
| Incident response records | Security team, legal | H | H | M | Confidentiality from adversaries; integrity required for legal proceedings |
| **Compliance certifications and audit evidence** (PCI-DSS, ISO 27001, SOC 2) | Executives, compliance team, regulators | M | H | H | Loss of PCI-DSS certification = inability to process credit cards; operational shutdown of payment business |

> **Threat actor relevance:** Log tampering is a post-exploitation step common to **all sophisticated threat actors** (Insiders, APTs, Career Cybercriminals) — they destroy audit trails to hide their presence and extend dwell time. The Marriott attackers remained undetected for four years partly due to inadequate monitoring [[Huntress](https://www.huntress.com/threat-library/data-breach/marriott-data-breach)].

---

### 8. Reputational & Legal Standing

These assets are less tangible but directly affect MegaTravel's ability to operate. The travel industry ranks third in cyberattack incidents [[SRM Solutions](https://www.srm-solutions.com/blog/why-is-the-travel-industry-such-a-popular-target-for-hackers/)], and research shows major travel companies continued to have hundreds of security vulnerabilities even after high-profile breaches [[Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/travel-industry-giants-failed-to-secure-their-websites-despite-high-profile-data-breaches-new-research-shows)].

| Asset | Exposure | C | I | A | Impact if Compromised |
|---|---|---|---|---|---|
| Brand reputation and customer trust (100M+ returning customers) | Public | L | H | H | A single large breach or sustained outage can trigger customer churn at scale; hard to recover |
| Partner and supplier relationships | Partners, procurement | M | H | M | Public breach damages partner confidence; non-compliance with partner security requirements may void contracts |
| Regulatory compliance status (GDPR, CCPA, PCI-DSS, PDPO) | Regulators, auditors | L | H | M | Violation triggers fines, operational restrictions, mandatory public disclosure |
| Platform service availability (SLA commitment) | Customers, partners | L | L | H | Sustained downtime breaches SLAs; contractual penalties; revenue loss |

> **Threat actor relevance:** Hacktivists explicitly target **brand reputation** through defacement and service disruption (Extinction Rebellion example in London, Task A). Terrorist Groups aim to spread propaganda through platform compromise. Any successful attack by any actor class ultimately harms reputational standing.

---

## Regulatory Cross-Reference

| Regulation | Jurisdiction | Assets Covered | Key Requirement | Penalty for Violation |
|---|---|---|---|---|
| **GDPR** [[europa.eu](https://europa.eu/youreurope/business/dealing-with-customers/data-protection/data-protection-gdpr/index_en.htm), [GEP](https://www.gep.com/blog/mind/gdpr-and-its-implications-for-corporate-travel)] | EU / UK — London division | Customer PII, passport data, itineraries, communication history, processing records | 72-hour breach notification; lawful basis for processing; data minimization; DPO appointment | Up to €20M or 4% of global annual turnover [[AltexSoft](https://www.altexsoft.com/blog/how-to-comply-with-gdpr-recommendations-for-travel-industry/)] |
| **CCPA** [[oag.ca.gov](https://oag.ca.gov/privacy/ccpa), [Inside Privacy](https://www.insideprivacy.com/state-privacy/california-finalizes-updates-to-existing-ccpa-regulations/)] | California, USA — Boston division | Customer PII, behavioral data, purchase history | Consumer right to know, delete, and opt out of data sale; mandatory opt-out confirmation (2026 updates) | Up to $7,500 per intentional violation |
| **PDPO** [[PCPD](https://www.pcpd.org.hk/english/data_privacy_law/ordinance_at_a_Glance/ordinance.html), [Captain Compliance](https://captaincompliance.com/education/hong-kong-pdpo/)] | Hong Kong division | Customer PII, travel data, employee data | Six data protection principles; 2021 amendments cover doxxing | Fines and imprisonment for serious violations |
| **PCI-DSS** [[PCI SSC](https://www.pcisecuritystandards.org/standards/)] | Global — all card processing | Payment card numbers, CVVs, expiry dates, cardholder names, transaction data | Secure storage, processing, and transmission of cardholder data; annual QSA audit | Loss of card processing ability; fines from card schemes |
| **DOT Air Consumer Privacy** [[transportation.gov](https://www.transportation.gov/individuals/aviation-consumer-protection/privacy)] | USA | Passenger name, DOB, frequent flyer numbers, flight itineraries | Fairness and accuracy in handling passenger personal information | DOT enforcement action |
| **IATA Data Protection Standards** [[iata.org](https://www.iata.org/en/programs/passenger/data-protection-privacy/)] | International | Passenger data exchanged with airlines via GDS/NDC | Compliance with passenger data sharing protocols | Exclusion from IATA programs; partner liability |

---

## References

### Breach Case Studies
- Marriott/Starwood breach (2018) — 383M records, passport and payment data: [Huntress](https://www.huntress.com/threat-library/data-breach/marriott-data-breach) | [Insurance Journal — $52M settlement](https://www.insurancejournal.com/news/national/2024/10/10/796585.htm)
- British Airways breach (2018) — 380K payment cards, Magecart attack: [Huntress](https://www.huntress.com/threat-library/data-breach/british-airways-data-breach) | [Source Defense — GDPR case study](https://sourcedefense.com/resources/blog/british-airways-a-case-study-in-gdpr-compliance-failure) | [SecurityWeek — class action](https://www.securityweek.com/british-airways-settles-class-action-over-2018-data-breach/)
- Orbitz/Expedia breach (2016–17) — 880K cards: [Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/880000-payment-cards-data-breached-in-orbitz-security-incident)
- Prestige Software breach (2013–2020) — 7 years of multi-platform records via misconfigured S3: [Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/hotel-reservation-platform-leaks-7-years-worth-of-customer-records-exposes-millions-to-fraud-and-extortion)

### Industry Research
- Travel industry cyberattack prevalence: [SRM Solutions](https://www.srm-solutions.com/blog/why-is-the-travel-industry-such-a-popular-target-for-hackers/)
- Persistent security gaps post-breach: [Bitdefender research](https://www.bitdefender.com/en-us/blog/hotforsecurity/travel-industry-giants-failed-to-secure-their-websites-despite-high-profile-data-breaches-new-research-shows) | [CPO Magazine](https://www.cpomagazine.com/cyber-security/in-spite-experiencing-some-of-the-biggest-data-breaches-in-recent-years-the-travel-industry-is-still-full-of-security-holes/)
- PII risks from insecure travel/e-commerce APIs: [Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/online-privacy/pii-leaks-and-other-risks-from-unsecure-e-commerce-apis)
- Data privacy significance in travel and tourism: [Managed Outsource Solutions](https://www.managedoutsource.com/blog/significance-of-data-privacy-and-security-in-the-travel-and-tourism-industry/)

### Standards and Frameworks
- OWASP Threat Modeling Process: [owasp.org](https://owasp.org/www-community/Threat_Modeling_Process)
- OWASP Threat Modeling Cheat Sheet: [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- OWASP Risk Rating Methodology: [owasp.org](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- ISO 27001 Annex A.8 — Asset Inventory: [hightable.io](https://hightable.io/iso-27001-annex-a-5-9-inventory-of-information-and-other-associated-assets/)
- NIST SP 800-30 Rev. 1 — Impact level guidance (H/M/L): [nvlpubs.nist.gov](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-30r1.pdf)
- CIA Triad: [Fortinet](https://www.fortinet.com/resources/cyberglossary/cia-triad) | [Splunk](https://www.splunk.com/en_us/blog/learn/cia-triad-confidentiality-integrity-availability.html)
- PCI-DSS: [pcisecuritystandards.org](https://www.pcisecuritystandards.org/standards/)

### Regulatory Sources
- GDPR official text: [gdpr.eu](https://gdpr.eu/what-is-gdpr/)
- GDPR for travel industry: [AltexSoft](https://www.altexsoft.com/blog/how-to-comply-with-gdpr-recommendations-for-travel-industry/) | [GEP](https://www.gep.com/blog/mind/gdpr-and-its-implications-for-corporate-travel)
- GDPR applicability for businesses: [europa.eu](https://europa.eu/youreurope/business/dealing-with-customers/data-protection/data-protection-gdpr/index_en.htm)
- CCPA: [California AG](https://oag.ca.gov/privacy/ccpa) | [2026 regulatory updates](https://www.insideprivacy.com/state-privacy/california-finalizes-updates-to-existing-ccpa-regulations/)
- PDPO (Hong Kong): [PCPD](https://www.pcpd.org.hk/english/data_privacy_law/ordinance_at_a_Glance/ordinance.html) | [Captain Compliance](https://captaincompliance.com/education/hong-kong-pdpo/)
- DOT Air Consumer Privacy: [transportation.gov](https://www.transportation.gov/individuals/aviation-consumer-protection/privacy)
- IATA Data Protection: [iata.org](https://www.iata.org/en/programs/passenger/data-protection-privacy/)
