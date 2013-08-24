# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from twisted.internet.defer import Deferred
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.protocol import ClientFactory
from twisted.internet.task import react
from twisted.words.protocols.irc import IRCClient
from twisted.protocols.policies import SpewingFactory

from txsocksx.client import SOCKS5ClientEndpoint


class TorIRC(IRCClient):
    nickname = 'txsocksx-tor-irc'
    nickservPassword = ''

    def connectionMade(self):
        self.sendLine('CAP REQ :sasl')
        self.deferred = Deferred()
        IRCClient.connectionMade(self)

    def irc_CAP(self, prefix, params):
        if params[1] != 'ACK' or params[2].split() != ['sasl']:
            print 'sasl not available'
            self.quit('')
        sasl = ('{0}\0{0}\0{1}'.format(self.nickname, self.nickservPassword)).encode('base64').strip()
        self.sendLine('AUTHENTICATE PLAIN')
        self.sendLine('AUTHENTICATE ' + sasl)

    def irc_903(self, prefix, params):
        self.sendLine('CAP END')

    def irc_904(self, prefix, params):
        print 'sasl auth failed', params
        self.quit('')
    irc_905 = irc_904

    def connectionLost(self, reason):
        self.deferred.errback(reason)

    def signedOn(self):
        print 'signed on successfully'
        self.quit('')


class TorIRCFactory(ClientFactory):
    protocol = TorIRC


def main(reactor):
    torEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
    # freenode's tor endpoint
    ircEndpoint = SOCKS5ClientEndpoint('lgttsalmpw3qo4no.onion', 6667, torEndpoint)
    d = ircEndpoint.connect(SpewingFactory(TorIRCFactory()))
    d.addCallback(lambda proto: proto.wrappedProtocol.deferred)
    return d

react(main, [])
