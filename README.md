ProxyCheck
==========

Supybot's plugin for ip/hostmask check against various Domain Name System Blacklists

it uses system calls on dig, the DIG utility (domain information groper) is a unix tool, which can be used to gather information from the Domain Name System servers. It is part of the ISC bind nameserver software package.
If you want to learn more about dig, here is the Linux dig man page : http://www.kloth.net/services/dig-man.php 

Currently supported :

- http://www.spamhaus.org/
- https://dnsbl.tornevall.org/
- http://www.sorbs.net/
- https://www.spamcop.net/
- https://www.projecthoneypot.org/
- http://efnetrbl.org/

At this time, the plugin has 2 command :

    !proxychannel [<channel>] returns all users who are listed on DNSBLS configured
    !proxyuser <nick|ip|hostmask> check against dnsbls configured

It can also check users on join, and announce those who are listed on configured DNSBLS in another channel:

    !config channel #mychannel supybot.plugins.ProxyCheck.logChannel #mychannel-ops

Configuration
========

You can configure DNSBLS you want to use per channel :

    !config supybot.plugins.ProxyCheck.dnsbls 'spamhaus','tornevall','sorbs','spamcop','efnet','honeypot'
    !config channel #mychannel supybot.plugins.ProxyCheck.dnsbls 'honeypot'

For "honeypot" you must use a key api, available under your account on http://www.projecthoneypot.org/

    !config supybot.plugins.ProxyCheck.honeypotKey ""
    
Tips
========
I'm open for idea/features request on github or /query <niko> on freenode.
