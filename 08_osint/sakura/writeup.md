# Sakura - Try hack me

## Introduction

Sakura room on Try Hack me is designed to introduce a learner to basic OSINT tehniques, as per introduction statement:

```
Room is designed to test a wide variety of different  techniques. With a bit of research, most beginner  practitioners should be able to complete these challenges. This room will take you through a sample  investigation in which you will be asked to identify a number of identifiers and other pieces of information in order to help catch a cybercriminal. 
```

So we are going to go on a hunt for a suspected cybercriminal, putting us in shoes of an investigator that plays cat and mouse game with a perpetrator.

## 1. *Tip off*

Task states:

```
The  Dojo recently found themselves the victim of a cyber attack. It seems that there is no major damage, and there does not appear to be any other significant indicators of compromise on any of our systems. However during forensic analysis our admins found an image left behind by the cybercriminals. Perhaps it contains some clues that could allow us to determine who the attackers were?
```

We are provided with a [link](https://tryhackme.com/room/sakura) to an image someone had left us:

![alt](screenshots/image.png)

Attacker left us a nice image telling us we have been hacked. On the first glance, there is a binary code embedded in the image, as well `aria-label` tag. When decoded into text, it reads: `Image is worth a 1000 words, but metadata is worth far more` (what a waste of time...). Checking the metadata, our pepetrator was a bit hasty, living a full path to an image on their computer. It reads `/home/SakuraSnowAngelAiko/Desktop/pwnedletter.png`.

So our cyber criminal goes by the artistic name `SakuraSnowAngelAiko`.

## 2. *Reconnaissance*

We are now going to gather some information about our subject, as stated by the task text:
```
It appears that our attacker made a fatal mistake in their operational security. They seem to have reused their username across other social media platforms as well. This should make it far easier for us to gather additional information on them by locating their other social media accounts. 
```

Googling the username, it led us to the github account.

![alt](screenshots/image1.png)

Long story short, in search for any credentials we found a repository named `PGP`. It has a singular file called `publikey` containing a `PGP` style key.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
23pRnPKc+41cwL3oq8yb/Fhj+biohgIp
=grbk
-----END PGP PUBLIC KEY BLOCK-----
```

Saving the file and then running `gpg --list-keys publickey.key` we get the following:

![alt](screenshots/image2.png)

So, attackers email is `SakuraSnowAngel83@protonmain.com`.

Searching the username on the internet we get her full name, as revealed on `LinkedIn`. She is `Aiko Abe`.


## 3. *Unveil*

```
It seems the cybercriminal is aware that we are on to them. As we were investigating into their Github account we observed indicators that the account owner had already begun editing and deleting information in order to throw us off their trail. It is likely that they were removing this information because it contained some sort of data that would add to our investigation. Perhaps there is a way to retrieve the original information that they provided?
```

Taks instructs us to checkout out her crypto currency transactions to gain some insight.

We went into search, going thru her Github repositories. As far as we are able to see trhu the repositry content, she is very much interested in crypto and crypto mining.

But one particular repository comes to our attention, the `ETH`.

![alt](screenshots/image3.png)

File content reads `stratum://ethwallet.workerid:password@miningpool:port`. But if we look into commit history, we can see she leaked another address (or whatever you call this), `stratum://0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef.Aiko:pswd@eu1.ethermine.org:4444`.

We searched for the hex hash on the internet, and it led us to a website that lists all the transactions made by the account.

![alt](screenshots/image4.png)

So the wallet is for `Ethereum` crypto currency.

Address of the wallet is `0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef`.

Thru filtering the transactions by date, specifically for the day 23rd of January, 2021, we can see that mining pool used was `Ethermine`.

Scrolling thru transactions we can see that miss attacker made some transactions `Tether` crypto currency, mostly leading to something resembling gambling webistes.


## 4. *Taunt*

```
Just as we thought, the cybercriminal is fully aware that we are gathering information about them after their attack. They were even so brazen as to message the  Dojo on Twitter and taunt us for our efforts. The Twitter account which they used appears to use a different username than what we were previously tracking, maybe there is some additional information we can locate to get an idea of where they are heading to next?
```
We've taken a screenshot of the message sent to us by the attacker, you can view it in your browser [here](https://raw.githubusercontent.com/OsintDojo/public/main/taunt.png).

The task asks us to find the alternate twitter account of the attacker. A quick google search by the old username reveals the current account with the username: `SakuraLoverAiko`.

![alt](screenshots/image5.png)
![alt](screenshots/image6.png)

The latest post hints that they might have pasted their wifi passwords on a website called DeepPaste on the dark web, under the key of `b2b37b3c106eb3f86e2340a3050968e2`. Spinning up a TOR window in the Brave browser and doing a quick search, lands us on that website and we can see the contents that they have pasted.

![alt](screenshots/image7.png)

We can see that their home wifi SSID is `DK1F-G`.

There exist a service called [wigle](https://wigle.net/) that has a large database of Wifi device information. There, we can search by SSID to find the BSSID.

![alt](screenshots/image8.png)

We find that the BSSID is `84:AF:EC:34:FC:F8`.


## 5. *Homebound*

```
Based on their tweets, it appears our cybercriminal is indeed heading home as they claimed. Their Twitter account seems to have plenty of photos which should allow us to piece together their route back home. If we follow the trail of breadcrumbs they left behind, we should be able to track their movements from one location to the next back all the way to their final destination. Once we can identify their final stops, we can identify which law enforcement organization we should forward our findings to.
```

We explore the pictures they posted on Twitter in chronological order.

![alt](screenshots/image8.png)

The first photo shows a beautiful cherry blossom, which indicates that this might be somewhere in Japan, because that is what it is famous for. However, upon closer inspection of the photo, while looking for more characteristic landmarks in order to discover the exact location, we observe a characteristic monument in the background. 

A quick google search reveals that this is the Washington Monument in Washington D.C. From there, we find that the closest airport to that monument is Ronald Reagan Washington National Airport. Its international airport code is `DCA`.

![alt](screenshots/image9.png)
![alt](screenshots/image10.png)
![alt](screenshots/image11.png)

The second photo is from an airport launge. By reading the signs we can see that it states "First Class Launge, Sacura Launge", by the Japan Airlines. Again, a quick google search lands us on the Japan Airlines website that showcases a Sakura launge at the Tokyo International Airport (Haneda). Its international airport code is `HND`.

![alt](screenshots/image12.png)

The next picture from the twitter account shows an airplane view or a satelite image over a lake.

![alt](screenshots/image13.png)

Since we now that the flight is from Tokyo, we try to find it on Google Maps. We quickly find out that they are flying over `Lake Inawashiro`.

![alt](screenshots/image14.png)

The final piece of the puzzle is finding out what city they call home. We now that they are flying from Tokyo over Lake Inawashiro, so we have a rough geographical sense that it is in the north of Japan. If we recall their paste from the DeepPaste website on the dark web, there was a wifi entry with SSID `HIROSAKI_FREE_WI-FI`. This hints that the attacker frequently connects to a public wifi in their home city. By checking on the map once again, we can clearly find the city of `Hirasaki`.