###
# Copyright (c) 2014, Nicolas Coevoet
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

###

import supybot.utils as utils
from supybot.commands import *
import supybot.plugins as plugins
import supybot.ircutils as ircutils
import supybot.callbacks as callbacks
import supybot.ircmsgs as ircmsgs
import subprocess
import socket
from math import floor

try:
	from supybot.i18n import PluginInternationalization
	_ = PluginInternationalization('ProxyCheck')
except:
	# Placeholder that allows to run the plugin on a bot
	# without the i18n module
	_ = lambda x:x

class ProxyCheck(callbacks.Plugin):
	"""Dns query on dnsbls"""
	threaded = True

	def __init__(self, irc):
		self.__parent = super(ProxyCheck, self)
		self.__parent.__init__(irc)
		self._resolved = utils.structures.CacheDict(4000)
		self._count = 0

	def proxychannel (self,irc,msg,args,channel):
		"""[<channel>]
		
		Checks all users against DNSBLs and returns those who
		have an entry"""
		hs = []
		r = []
		for n in list(irc.state.channels[channel].users):
			hs.append(irc.state.nickToHostmask(n))
		irc.reply(_('please wait, %s users to check') % len(hs))
		for hostmask in hs:
			(n,i,h) = ircutils.splitHostmask(hostmask)
			check = self.check(h,channel)
			if check:
				r.append(format(_('%s (%L)'), n, check))
		irc.replies(r)
	proxychannel = wrap(proxychannel,['op','channel'])

	def proxyuser (self,irc,msg,args,nick):
		"""<nick|ip>

		Checks <nick|ip> against configured DNSBLS"""
		if ircutils.isUserHostmask(nick):
			h = irc.state.nickToHostmask(nick)
			(n,i,h) = ircutils.splitHostmask(h)
		else:
			h = nick
		check = self.check(h,'')
		if check:
			irc.replies(check)
		else:
			irc.reply(_('%s is clean') % nick)
	proxyuser = wrap(proxyuser,['owner','text'])

	def count (self,irc,msg,args):
		"""takes no arguments

		Return the number of dig calls since plugin has been loaded"""
		irc.reply(_('dig has been called %s') % self._count)
	count = wrap(count,['owner'])

	def doJoin(self,irc,msg):
		(n,i,h) = ircutils.splitHostmask(msg.prefix)
		channels = msg.args[0].split(',')
		for channel in channels:
			logChannel = self.registryValue('logChannel',channel=channel)
			if logChannel in irc.state.channels:
				check = self.check(h,channel)
				if check:
					irc.queueMsg(ircmsgs.privmsg(logChannel,'[%s] %s (%s)' % (channel,msg.prefix,', '.join(check))))

	def check (self,ip,channel):
		real = ip
		if ip in self._resolved:
			real = self._resolved[ip]
		else:
			try:
				r = socket.getaddrinfo(ip,None)
				if r != None:
					u = {}
					L = []
					for item in r:
						if not item[4][0] in u:
							u[item[4][0]] = item[4][0]
							L.append(item[4][0])
					self.log.debug('%s --> %s' % (ip,', '.join(L)))
					if len(L) == 1:
						self._resolved[ip] = real = L[0]
			except:
				self._resolved[ip] = ip
		ip = real
		if ip.find('ip.') != -1:
			ip = ip.split('ip.')[1]
		if utils.net.isIPV4(ip):
			h = '.'.join(ip.split('.')[::-1])
			r = []
			for entry in self.registryValue('dnsbls',channel=channel):
				m = None
				if entry == 'spamhaus':
					m = self.spamhaus(h)
				elif entry == 'tornevall':
					m = self.tornevall(h)
				elif entry == 'sorbs':
					m = self.sorbs(h)
				elif entry == 'spamcop':
					m = self.spamcop(h)
				elif entry == 'honeypot':
					m = self.honeypot(h)
				elif entry == 'efnet':
					m = self.efnet(h)
				if m:
					r.append(m)
			return r

	def honeypot (self,h):
		if len(self.registryValue('honeypotKey')) == 0:
			return []
		h = self.registryValue('honeypotKey') + '.' + h + '.dnsbl.httpbl.org'
		m = self.dig(['dig','+short',h])
		if m:
			for entry in m.split('\n'):
				msgs = entry.split('.')
				if msgs[0] != '127':
					continue
				days = msgs[1]
				score = floor(100 * float(msgs[2])/float(255))
				type = ''
				if msgs[3] == '0':
					type = _('SearchEngine')
				elif msgs[3] == '1':
					type = _('Suspicious')
				elif msgs[3] == '2':
					type = _('Harvest')
				elif msgs[3] == '3':
					type = _('Suspicious & Harvester')
				elif msgs[3] == '4':
					type = _('Comment spammer')
				elif msgs[3] == '5':
					type = _('Suspicious & Comment Spammer')
				elif msgs[3] == '6':
					type = _('Harvester & Comment Spammer')
				elif msgs[3] == '7':
					type = _('Suspicious & Harvester & Comment Spammer')
				return _('honeypot|%s with a score of %s%%, updated %s day(s) ago') % (type,score,days)

	def efnet (self,h):
		h = h + '.rbl.efnetrbl.org'
		m = self.dig(['dig','+short',h])
		if m:
			for entry in m.split('\n'):
				if entry == '127.0.0.1':
					return _('efnet|Open Proxy')
				elif entry == '127.0.0.2':
					return _('efnet|Spreading virus and trojans')
				elif entry == '127.0.0.3':
					return _('efnet|Virus and trojans known to self-spread')
				elif entry == '127.0.0.4':
					return _('efnet|tor')
				elif entry == '127.0.0.5':
					return _('efnet|Drones/Flooding')
		return None

	def sorbs(self,h):
		h = h + '.dnsbl.sorbs.net'
		m = self.dig(['dig','+short',h])
		if m:
			for entry in m.split('\n'):
				if entry == '127.0.0.2':
					return _('sorbs|Open HTTP Proxy')
				elif entry == '127.0.0.3':
					return _('sorbs|Open Socket Proxy')
				elif entry == '127.0.0.4':
					return _('sorbs|Open Proxy')
				elif entry == '127.0.0.5':
					return _('sorbs|Open SMTP relay')
				elif entry == '127.0.0.7':
					return _('sorbs|abusable vulnerabilities')
				elif entry == '127.0.0.9':
					return _('sorbs|Zombie')
		return None

	def spamcop (self,h):
		h = h + '.bl.spamcop.net'
		m = self.dig(['dig','+short',h])
		if m:
			for entry in m.split('\n'):
				if entry == '127.0.0.2':
					return _('spamcop|listed')
		return None

	def tornevall (self,h):
		h = h + '.dnsbl.tornevall.org'
		m = self.dig(['dig','+short',h])
		if m:
			for entry in m.split('\n'):
				if entry == '127.0.0.1':
					return _('tornevall|Proxy has been scanned' )
				elif entry == '127.0.0.2':
					return _('tornevall|Proxy is working')
				elif entry == '127.0.0.8':
					return _('tornevall|Proxy tested but timeout')
				elif entry == '127.0.0.32':
					return _('tornevall|Proxy has different ip')
				elif entry == '127.0.0.64':
					return _('tornevall|Abusive ip')
				elif entry == '127.0.0.128':
					return _('tornevall|Anonymous proxy')
		return None

	def spamhaus (self,h):
		h = h + '.zen.spamhaus.org'
		m = self.dig(['dig','+short',h])
		if m:
			SBL = False
			SBLCSS = False
			CBL = False
			PBL = False
			for entry in m.split('\n'):
				if entry == '127.0.0.2':
					SBL = True
				elif entry == '127.0.0.3':
					SBLCSS = True
				elif entry == '127.0.0.4' or entry == '127.0.0.5' or entry == '127.0.0.6' or entry == '127.0.0.7':
					CBL = True
				elif entry == '127.0.0.10' or entry == '127.0.0.11':
					PBL = True
			if SBL:
				return _('SpamHaus|SBL')
			elif SBLCSS:
				return _('SpamHaus|SBLCSS')
			elif CBL:
				return _('SpamHaus|CBL')
			elif PBL:
				return _('SpamHaus|PBL')
			else:
				return _('SpamHaus|Unknown : %s') % m
		return None

	def dronebl (self,h):
		h = h + '.dnsbl.dronebl.org'
		m = self.dig(['dig','+short',h])
		if m:
			for entry in m.split('\n'):
				if entry == '127.0.0.3':
					return _('dronebl|Irc Drone')
				elif entry == '127.0.0.5':
					return _('dronebl|Bottler')
				elif entry == '127.0.0.6':
					return _('dronebl|Unknown spambot or drone')
				elif entry == '127.0.0.7':
					return _('dronebl|DDOS Drone')
				elif entry == '127.0.0.8':
					return _('dronebl|Sock Proxy')
				elif entry == '127.0.0.9':
					return _('dronebl|Http Proxy')
				elif entry == '127.0.0.10':
					return _('dronebl|ProxyChain')
				elif entry == '127.0.0.13':
					return _('dronebl|Brute force attackers')
				elif entry == '127.0.0.14':
					return _('dronebl|Open Wingate Proxy')
				elif entry == '127.0.0.15':
					return _('dronebl|Compromised router / gateway')
				elif entry == '127.0.0.17':
					return _('dronebl|Automatically determined botnet IPs (experimental)')
		return None

Class = ProxyCheck


# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
