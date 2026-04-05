# Attack Surface - _MegaTravel_

**Attack surface** is a set of all **entry points** through which the users and external systems interact with the system, and are thus entrypoints for malicious parties.

## Users

Each user has to interact with the system through one or multiple entry points, so identifying all the users helps systematically cover all entry points. The following user categories were identified (including both humans and external systems):

| User | Type | Description |
|---|---|---|
| Customer | Human | Uses web/mobile app to explore and book trips |
| Customer support agent | Human | Uses internal CRM to look up accounts and handle customer calls |
| Business Expert | Human | Uses analytics data to make business decisions and marketing campaigns |
| System administrator | Human | Manages server infrastructure and deploys updates |
| Payment provider | External System | Handles payments |
| Accomodation Partner(s) | External system | Manages hotel bookings for our clients |
| Transportation Partner(s) | External system | Manages transport tickets for our clients |
| Tour guide/Car rental Partner(s) | External system | Manages tours for our clients |
| Maps API | External system | Provides geolocation information |

## Entry points



| Entry Point | Interface Type | Exposed To | User(s) | Why It Matters |
|---|---|---|---|---|
| REST API (unautenticated endpoints) | REST API over HTTPS | Public Internet | Customers | Enumeration, scraping, injection target, DDoS |
| REST API (authenticated endpoints) | REST API over HTTPS | Public Internet (authenticated) | Customers | Handles customer data; Token forgery, User impersonation |
| Payment API | REST API over HTTPS + payment processor call | Public Internet (authenticated) | Customers | High impact |
| Customer support CRM Portal | Internal web app | VPN/Internal network | Customer support agent | Access to customer support account, phishing
| Analytics dashboard | Internal web app | VPN/Internal network | Business expert | Access to BI info, USB malware |
| Admin management interface | SSH | VPN/Internal network | System admin, CI/CD pipelines | Privilege escalation, full system compromise |
| Payment provider webhook callback | HTTPS webhook | Public Internet | Payment provider | Webhook/payment provider compromise |
| Maps/geolocation API | REST API (outbound) | Internet (outbound) | Maps API provider | fake/poisoned data |
| Accomodation Partner(s) API | REST API (outbound) | Internet (outbound) | Accomodation partner(s) | fake/poisoned data; MITM |
| Transportation Partner(s) API | REST API (outbound) | Internet (outbound) | Transportation partner(s) | fake/poisoned data; MITM |
| Tour guide/Car rental Partner(s) API | REST API (outbound) | Internet (outbound) | Tour guide/Car rental partner(s) | fake/poisoned data; MITM |
| Email | Email | Public internet | All users | phishing attacks |
