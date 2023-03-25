---
title: Another Phishing Tool - noVNC and Docker
author: powerseb
date: 2023-03-22 00:00:00 +0800
categories: [Phishing, RedTeam]
tags: [Infrastructure, Phishing, Setup]
render_with_liquid: false
img_path: /assets/img/2023-03-22/
---

In this article I would like to introduce you to a tool / template I created, which can be used to phish credentials and even handle MFA. This work is heavily based on the initial article of [mrd0x](https://mrd0x.com/bypass-2fa-using-novnc/).

## Basic Concept

So, we all know and love phishing. From my experience there are two kinds of phishing attacks:

- Phishing for credentials - you want to lure a user to a website where the user should logon and you can harvest the credentials.
- Phishing with a payload - the user should (download and) execute a payload - the famous iPhone.exe which is attached to a mail.

Both scenarios come with their own problems and possible solutions - in this article we focus on the phishing for credentials. So when it comes to this kind of attack the main enemy (or best defense) is `Multi-Factor-Authentication`. Even when an attacker gains access to valid credentials, a logon without this factor is not possible. Therefore, this attack vector is highly depended on the site, which should be phished and the individual user setup - which negatively impacts the success rate of such an attack.

That is until the article of [mrd0x](https://mrd0x.com/bypass-2fa-using-novnc/) changed the perspective on this topic - the basic idea is to lure the user to click a link, which connects to a machine where the desktop is presented within the browser, by use of `noVNC`. But instead of a regular desktop the attacker presents a fullscreen browser with the real target website. The big advantage of this technique is that the attacker has full control over the machine (with the vnc connection) and therefore has full control over the browser and sessions within it. When the user now logs on the real website - the attacker gains access to all relevant session information, which are required to impersonate the user. An additional advantage, from an attacker perspective, is that the real website is shown. This means the user interacts with the real target website and therefore the user experience for the victim is nearly the same.

This was just a short overview so please read the full article of [mrd0x](https://mrd0x.com/bypass-2fa-using-novnc/) to get more details.

Because it is the real website and the user performs a real logon to it, the `Multi-Factor-Authentication` can be performed and the attacker has still 100 % control over the session of the user.

Ultimately this provides an attacker with multiple possible further attacks - e.g., export of the session cookies and logon with those, extraction of data by use of a keylogger on the noVNC machine, manipulation of the network traffic to prevent a logout and then takeover the session ... etc.

With this concept established let's see what a noob as I can add to that. The basic concept is easy to understand but, if I wanted to setup such a phishing infrastructure, I was confronted with a lot of questions. So started my adventure to build an  `easy` setup, which works out-of-the-box (like `Evilgnix`). As a result I prepared a tool / template, which should help others to easily setup a scalable `noVNC` based phishing infrastructure and can easily be used in real world scenarios - so let's start.

![Make it easy!](easy.jpg)

## How to make it scalable?

So with the basic concept established maybe you see already a little issue - a vnc session means that the user controls the provided machine. If you now send the same link to two different users, they both connect to the same machine and therefore see each other’s actions (or fight over the control of the mouse). This situation (although funny) will be very awkward and should be avoided. Therefore, a requirement for our setup is that each user, which we want to phis, requires a separate vnc session.

To accomplish this we could start as many vnc sessions on our phishing host as we want - than we require a little bit of power under the hood (so no ec2 small :( ). Next and an additional disadvantage is that we need to open the corresponding vnc port for each session - this can be a little overhead. Ideally, we want just one url, which then redirects to the separate vnc sessions and makes the network setup very simple - just open port 80 / 443.

Before we cover this distribution problem, we may focus on our initial problem one user one vnc machine - and keep it small (and ideally cheap). Let's talk about docker.

![How I talk now about Docker](docker.jpg)

During this thought process I also stumbled across this article from [fhlipzero](https://fhlipzero.io/blogs/6_noVNC/noVNC.html) - which also inspired (and helped) to build the setup.

### Docker

So the setup sounds like the typical use case of docker - we want to run a small process (a browser on a machine with novnc) and scale it with the amount of users.

My personal experience with docker was zero - so after a lot of reading, trial and error, tears and considering a carrier as baker I found a working noVNC setup, with a browser and how to use it for my purpose.

The base docker image is [accetto/ubuntu-vnc-xfce-firefox-g3](https://hub.docker.com/r/accetto/ubuntu-vnc-xfce-firefox-g3) - there we adjust a few things:

Adjustments to noVNC:
- Within the vnc.html file the same adjustments were made as [fhlipzero](https://fhlipzero.io/blogs/6_noVNC/noVNC.html) and [mrd0x](https://mrd0x.com/bypass-2fa-using-noVNC/) suggested - to ensure no controls are shown and the transition to the vnc connection is blank
- Renaming of the adjusted vnc.html to conn.html (to not be suspicious)
- Within the ui.js the page title was changed to ensure it does not look to phishy

Adjustments to the container:
- Adjust the xfce4 config to ensure just a blank white screen is shown

So this ensures our container is ready to lure a user. But this is only one container for one user - we need to create one container for every user. Therefore, those steps and adjustments are ideally put in to the dockerfile - and there we have a reproduceable `noVNC` container, which can be reliably spawned and used for phishing.

But alright I know this is all old stuff - so this makes `noVNC` scaleable but there was this thing with connections, ports etc.

### Reverse Proxy

Ok, before we talk about my stunning new discoveries with apache, lets establish first what is a reverse proxy and why we need one. Please consider the following abstract is my understanding and I read many different interpretations and just want to ensure we are all on the same page.

A reverse proxy is an instance, which accepts client requests and forwards them to instances in the backend. The answers of the backend are then forwarded to the reverse proxy and from there to the client. This means the client never knows that it is talking to a backend instance - all communication is tunneled through the reverse proxy.

Because of this circumstance a reverse proxy is an ideal enhancement of our setup - we can spawn as many VNC instances as we want and the reverse proxy does all the handling of the different user requests. This will save us many open ports and it makes the detection of potential other noVNC instances harder. Alright so how we can set one up?

![When you google reverse-proxy](revproxy.jpg)

Because I am a noob in webserver technology, I tried my luck with `Apache`. Here it was quite easy to use `VirtualHosts` within the `000-default.conf`. Here an example of a config I generated:

```html
NameVirtualHost *
<VirtualHost *:80>
		<Location /5b6fefd758e9f1fd8dcf0fe2cc6c>
		ProxyPass http://172.17.0.2:6901
		ProxyPassReverse http://172.17.0.2:6901
		</Location>
		<Location /5b6fefd758e9f1fd8dcf0fe2cc6c/websockify>
		ProxyPass ws://172.17.0.2:6901/websockify
		ProxyPassReverse ws://172.17.0.2:6901/websockify
		</Location>
</VirtualHost>
```

You will notice that instead of subdomains - I chose to use subdirectories within the reverse proxy. This ensures that our setup just requires one hostname and every subdirectory redirects to one noVNC container. The intention was to save work and DNS entries.

But we require more than just a redirect to the correct container - because `noVNC` connections rely on websockets and therefore we also need to forward those connections also - this is done by the entry `ws://172.17.0.2:6901/websockify`.

That is basically all the reverse proxy setup requires which is awesome because it is very simple and easy to understand (which was very important because I needed to understand it).

![How I felt](apache.jpg)

Alright so we have all together - within Apache we use the proxy modules to achieve the required forwarding. We adjust the `000-default.conf` to forward our connections accordingly to our VNC containers and we are done.

Further also this configuration can be applied and easily to a docker container, which is the perfect segway to the tool / script I wrote as a learning experience.

## NoPhish - the tool / setup

So combining all the things together - I present you [NoPhish](https://github.com/powerseb/NoPhish.git). Basically, it is a complete phishing setup based on docker which uses `noVNC`.

![All comes together now](together.jpg)

We have a docker image for our noVNC containers, which will be started for every user we want to phis and one reverse proxy container, which will handle all the incoming requests and distribute them to the different containers.

Further the setup will pull out all gathered cookies (and sessions cookies) from the started noVNC containers - this is done every 60 Seconds. The result of this are cookies.json files (for handy import to the extension you like).

So that is the rough overview of the setup and mechanisms - now a short overview of how to use it.

### Installation

To setup the tool the following basic requirements need to be fulfilled:

- Docker needs to be installed
- the python modules lz4 and json are required for the cookie export

When those requirements are given clone the [repo](https://github.com/powerseb/NoPhish) and run the `setup.sh`:

```console
setup.sh install
```

So under the hood of this magic bash script the docker images will be generated (based on the provided dockerfiles). Then we are good to go.

### Run it

When the setup is completed (or you want to start a new engagement) - you can start up the whole infrastructure with the `setup.sh` script.

Here a short overview of the parameters:


```console
Usage: ./setup.sh -u No. Users -d Domain -t Target
         -u Number of users - please note for every user a container is spawned so don't go crazy
         -d Domain which is used for phishing
         -t Target website which should be displayed for the user
         -e Export format
         -s true / false if ssl is required - if ssl is set crt and key file are needed
         -c Full path to the crt file of the ssl certificate
         -k Full path to the key file of the ssl certificate
```

So, everything is clear - then we can start it:

```console
./setup.sh -u 4 -t https://accounts.google.com -d hello.local
```


This will start 4 VNC docker containers (one for every user), will target the url https://accounts.google.com under the domain hello.local (yeah not the best choice but it is a test).

The setup also supports SSL you just need to provide the certificate and the key, then it will run on with HTTPS on port 443. If not provided the setup runs with HTTP on port 80.

When the setup starts it will show you the following output:

```console
./setup.sh -u 4 -t https://accounts.google.com -d hello.local       
[+] Configuration file generated
[-] Starting containers
[+] VNC Containers started                          
[-] Starting reverse proxy
[+] Reverse proxy running
[+] Setup completed
[+] Use the following URLs:
http://hello.local/f325a55604e4d31f5a469d591e2c/conn.html?path=/f325a55604e4d31f5a469d591e2c/websockify&password=f325a55604e4d31f5a469d591e2c&autoconnect=true&resize=remote
http://hello.local/25fcc33508ad8abecac8259223a7/conn.html?path=/25fcc33508ad8abecac8259223a7/websockify&password=25fcc33508ad8abecac8259223a7&autoconnect=true&resize=remote
http://hello.local/7eb3f7dd95feb93ff5ad653e6920/conn.html?path=/7eb3f7dd95feb93ff5ad653e6920/websockify&password=7eb3f7dd95feb93ff5ad653e6920&autoconnect=true&resize=remote
http://hello.local/695ad1ff254ee7806b06835d6b3d/conn.html?path=/695ad1ff254ee7806b06835d6b3d/websockify&password=695ad1ff254ee7806b06835d6b3d&autoconnect=true&resize=remote
[-] Starting Loop to collect sessions and cookies from containers
    Every 60 Seconds Cookies and Sessions are exported - Press [CTRL+C] to stop..
^C
[-] Import stealed session and cookie JSON to impersonate user
[-] VNC and Rev-Proxy container will be removed
[+] Done!
```


The displayed Phishing URLs contain some random strings (in this example f325a55604e4d31f5a469d591e2c) - this should provide some randomness to the URL (to lure the user), hide the vnc connections from scanners and randomize the vnc password.

Next the script will start it's loop to gather cookies and session cookies. To not dive here into too much details (because this was the part of this whole endeavor which drove me near madness) - the loop contains the following steps:

- Copy of the `recovery.jsonlz4` and the `cookies.sqlite` of every noVNC container
- Extraction of the session and cookie information of those files
- Import of the information to the phis.db (- currently this only done to document the gathered information and to enable others to create custom output)
- Creation of two .json files - one for sessions and one for cookies

Alright maybe a little insight - here my own stubbornness came into play. The `noVNC` container uses Firefox as a browser. Firefox handles session cookies and regular cookies different. Regular cookies are saved to a `cookies.sqlite` file - easy to read and understand. Session cookies are saved in memory (better secured but not so good for our purpose). So the first reaction would be to use chromium (which handles cookies and session cookies different than Firefox) - but I wanted to find a way with Firefox. After a lot of googling (and reevaluation of life choices) I stumbled across the file `recovery.jsonlz4`. This file is created by Firefox to save the current state of the browser to ensure it can restore this state in case of an crash - and it contains also the session cookies :).

This is the reason why there are two scripts within the setup which take care of different parts of the user session information. Each script will create a separate JSON file (cookies.json and session.json) - the format of both files is the same.

Regarding the format of the JSON files - the setup offers the possibility to create a simple `cookies.json` file with the option `-e simple` (good to be used with the extension [CookieBro](https://chrome.google.com/webstore/detail/cookiebro/lpmockibcakojclnfmhchibmdpmollgn?hl=de)). By default the script will generate a custom `cookies.json`-format which is compatible with the [Cookie Quick Manager](https://addons.mozilla.org/de/firefox/addon/cookie-quick-manager/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search) for Firefox.

And that's it - this is how you can run the tool.

### Stop it!

Ok so you did your awesome phishing test - got domain admin etc. but what to do to stop and remove the infrastructure?

During the execution if you hit `ctrl` + `c` the script will stop and remove all created docker containers. If you now want to completely remove the docker images just run `./setup.sh cleanup` - here the script will attempt to delete the containers again and further removes all the docker images. Be aware before you can use the setup again you need to install it again.

## Conclusion

I hope I could provide you some insight into this phishing setup, provide more understanding how to use noVNC within a phishing campaign. Please feel free to let me know if the tool / setup helped you in any way, what could be done better and @my-future-self I hope you remembered again how your own tool works.
