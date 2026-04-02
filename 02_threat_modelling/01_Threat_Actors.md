# Threat Actors - *MegaTravel* attackers


## Introduction
When having a large public system, often it comes to wonder who might be a not so nice individual to threaten the safety of the system itself, or the users using it. To discuss the topic, we will present an imaginary multi-national company that provides services to organize trips and holidays, and what mallitious inidividuals pose a threat to such a system.

## Threat Actor Classification
Generally speaking, in cybersecurity there are a few categories which classify the attackers by their motives and behaviour. A threat actor can be a single person inside or outside of the organization. It can be a group, opposing organization, or even a country that desires to execute a targeted cyber attack. Threat actor is a key driver who participates in a malicious action that will create a negative impact on company's security posture.

### Career Cybercriminals
 Most common type of threat actors. Attacks are intended to steal data for financial gain. Often times they will make data innacessible to the victim, until they pay a ransom. Driving factor for them is money. Their attack arsenal is made up of phishing attacks, ransomware, malware, social engineering, and other techniques.

 Specifically for *MegaTravel* system, they may spoof the connections to get sensitive user data. They would most likely steal user credit card data, send phishing emails thru leaked emails, bribe users for money, counduct fraud with stolen data, forge fake domains for users to log onto, exploit weak input validation to punch into the backend. Even if the ransom is paid, severe reputational and financial damage to the platform has already occurred.

### Hacktivists
Threat actors driven by political, social or ideological motives. Hacktivists are not primarily motivated by money, rather by a need to publicize misdeeds of an organization, or to be a part of political or social movement. Usually targeting organizations, webites or systems to promote their belifes or statemets.

For a company like *MegaTravel*, hacktivists are a realistic threat. If hacktivists are able to compromise administrative user accounts, or elevate their privilages, they could execute defacement attack. In other words they would replace legitimate pages with ther own political messaging, post data regarding their political or sociological subjects as travel data. They are highly likely to utilize DDoS (Distributed Denial of Service) attacks to exhaust backend resources and take the booking platform offline during peak seasons. This would cause financial damage to company and disrupt company's business, even tho they are not aiming to gain money at all from their acctions.

### State-sponsored Actors - APTs (Advanced persistant threat)
These are government-backed entities that conduct cyber espionage, sabotage, or other offensive activities to advance their nation's interests. They often possess advanced capabilities and significant resources.

It is likely that this kind of actors would indulge in espionage of high-profile pessangers (diplomats, military officals, CEOs). *MegaTravel* itselfs may not be a direct target, they could compromise smaller vendors that provide APIs for the platform itself, getting a backdoor. Even more wild is the idea of discriptiong flight services, leaving targeted individuals stranded in other countries, away from their seat of power.

### Insiders
Insiders are individuals within a business. They may abuse their close access to systems, data, or information for personal gain, espionage, or sabotage. An insider can be an employee, third-party contractor, or partner who wants to get at organizational data or compromise key processes.

Threat from within to *MegaTravel* may be an employee seeking to sabotage a system, commit fraud, or plant a logic bomb, motive being resentment towards the company. Attacks like these often include injecting a backdoor in backed services, allowing them to bypass authentification mechanism to alter data at will. Some may not be developers. Non-techincal staff, like customer service agents, may leak information themselves about celebrities, politicians, ex-partners; Or even manipule discount prices on promocodes for thier friends.

### “Script Kiddies”
 Typically inexperienced individuals who use existing hacking tools and techniques without a deep understanding of the underlying technology. They may engage in cyberattacks out of entertainment.

Usage of automated tools to scan *MegaTravels* public facing servers for common misconfigurations, open ports, outdated plugins. Launching a small scale DDoS strike is a viable option, to take it down for a few minutes out of fun. Generally speaking, these would be low capability attacks, just to harrass or cause annoyance.

### Organized Crime Groups
 Criminal organizations may use cyberattacks as part of their broader criminal activities, such as drug trafficking or money laundering.

 These groups could use the MegaTravel booking system to "clean" illicit funds. By making thousands of high-value, refundable hotel and flight bookings using "dirty" money and then canceling them for a clean refund, they turn the platform into a massive laundering machine. May as well create "ghost" bookings that help move individuals or illicit goods across borders without triggering red flags in traditional law enforcement databases.

### Terrorist Groups
 Some terrorist organizations may use cyber-attacks as a means of furthering their goals, disrupting services, or causing fear. 

Same as hacktivists, they may want to exploit vulnerabilities to spread propaganda, or even gain insight on flight data to plan their attacks as act of terrors or targeted attacks on specific individuals.

## Threats based on grahpic location

1. Boston, USA
   
    Boston is the primary target for attackers looking for the "Big Score" in monetary value.

    Primary Actors: State-sponsored APTs (China/Russia) and Organized Crime Syndicates.

    Specific Threats:

   - Ransomware: US companies are the number one target for ransomware because they are viewed as having the highest "willingness to pay."

   - IP Theft: Since Boston is a tech and biotech hub, state actors may target the Boston center to steal *MegaTravel’s* .

   - Class Action Risk: A breach here triggers massive US legal liabilities (CCPA/State laws), making it a favorite for Extortionists.
  
2. London, UK

    Global crossroads for diplomacy and is governed by the world’s strictest data privacy laws (UK GDPR).

    Primary Actors: Hacktivists and European-focused APTs (Iran/Russia).

    Specific Threats:

    - GDPR Extortion: Cybercriminals target the London hub specifically to leak personal information. They know that the fines for a GDPR breach can reach 4% of global turnover, so they use that strict regulations to demand higher ransoms.

    - Political Espionage: London is a hub for international diplomats and NATO-aligned officials. State actors will target the London booking systems to track the movement of UK and EU government officials.

    - Hacktivism: London is a center for climate activism. Groups like "Extinction Rebellion" or similar hacktivists might target this center to disrupt travel services as a protest against the  carbon footprint.
3. Hong Kong
    
    Hong Kong is in a unique and volatile position, serving as the gateway between Western markets and mainland China.

    Primary Actors: Regional State Actors (APT41/APT27) and Money Laundering Syndicates.

    Specific Threats:

   - Surveillance & Monitoring: Because of the National Security Law and regional tensions, the Hong Kong center is under constant threat from state actors wanting access to the passenger data of travelers entering or leaving Asia. They want to know who is meeting whom.

   - Financial Laundering: As Hong kong is a major global financial hub with complex banking, Organized Crime Groups target the center to exploit the "travel" and "reservation" systems for high-volume money laundering (booking/canceling expensive trips).

   - Infrastructure Sabotage: In the event of regional political instability, the Hong Kong node is at the highest risk for Kinetic Sabotage. In other words, taking down local transport APIs to paralyze regional travel.