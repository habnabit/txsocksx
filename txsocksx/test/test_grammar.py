# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

import unittest

from parsley import makeGrammar, ParseError

from txsocksx.grammar import grammarSource, bindings


grammar = makeGrammar(grammarSource, bindings)

def stringParserFromRule(rule):
    def parseString(s):
        return getattr(grammar(s), rule)()
    return parseString


class TestGrammar(unittest.TestCase):
    def test_SOCKS4aHostUser(self):
        parse = stringParserFromRule('SOCKS4aHostUser')
        self.assertEqual(parse('\x7f\x00\x00\x01spam\x00'), ('127.0.0.1', 'spam'))
        self.assertEqual(parse('\x00\x00\x00\x00egggs\x00'), ('0.0.0.0', 'egggs'))
        self.assertEqual(parse('\x00\x00\x00\x01spam\x00example.com\x00'),
                         ('example.com', 'spam'))

    def test_SOCKS4Command(self):
        parse = stringParserFromRule('SOCKS4Command')
        self.assertEqual(parse('\x01'), 'tcp-connect')
        self.assertEqual(parse('\x02'), 'tcp-bind')
        self.assertRaises(ParseError, parse, '\x00')
        self.assertRaises(ParseError, parse, '\x03')

    def test_SOCKS4Request(self):
        parse = stringParserFromRule('SOCKS4Request')
        self.assertEqual(parse('\x04\x01\x01\x00\x7f\x00\x00\x01spam\x00'),
                         ('tcp-connect', 256, '127.0.0.1', 'spam'))
        self.assertEqual(parse('\x04\x02\x00\xff\x00\x00\x00\x01spam\x00eggs.com\x00'),
                         ('tcp-bind', 255, 'eggs.com', 'spam'))

    def test_SOCKS4Response(self):
        parse = stringParserFromRule('SOCKS4Response')
        self.assertEqual(parse('\x00' * 8), (0, '0.0.0.0', 0))
        self.assertEqual(parse('\x00\x01' + '\x00' * 6), (1, '0.0.0.0', 0))
        self.assertEqual(parse('\x00\x01' + '\xff' * 6), (1, '255.255.255.255', 65535))

    def test_SOCKS5Command(self):
        parse = stringParserFromRule('SOCKS5Command')
        self.assertEqual(parse('\x01'), 'tcp-connect')
        self.assertEqual(parse('\x02'), 'tcp-bind')
        self.assertEqual(parse('\x03'), 'udp-associate')
        self.assertRaises(ParseError, parse, '\x00')
        self.assertRaises(ParseError, parse, '\x04')

    def test_SOCKS5Address(self):
        parse = stringParserFromRule('SOCKS5Address')
        self.assertEqual(parse('\x01\x00\x00\x00\x00'), '0.0.0.0')
        self.assertEqual(parse('\x01\x7f\x00\x00\x01'), '127.0.0.1')
        self.assertEqual(parse('\x01\xff\xff\xff\xff'), '255.255.255.255')
        self.assertEqual(parse('\x03\x00'), '')
        self.assertEqual(parse('\x03\x0bexample.com'), 'example.com')
        self.assertEqual(parse('\x04' + '\x00' * 16), '::')
        self.assertEqual(parse('\x04' + '\x00' * 15 + '\x01'), '::1')
        self.assertEqual(parse('\x04\xfe\x80' + '\x00' * 14), 'fe80::')
        self.assertEqual(parse('\x04\xfe\x80' + '\x00' * 13 + '\x01'), 'fe80::1')

    def test_SOCKS5ServerAuthSelection(self):
        parse = stringParserFromRule('SOCKS5ServerAuthSelection')
        self.assertEqual(parse('\x05\x00'), '\x00')
        self.assertEqual(parse('\x05\x01'), '\x01')
        self.assertEqual(parse('\x05\xff'), '\xff')

    def test_SOCKS5ServerLoginResponse(self):
        parse = stringParserFromRule('SOCKS5ServerLoginResponse')
        self.assertEqual(parse('\x00\x00'), True)
        self.assertEqual(parse('\x00\x01'), False)
        self.assertEqual(parse('\x01\x00'), True)
        self.assertEqual(parse('\x01\x01'), False)

    def test_SOCKS5ServerResponse(self):
        parse = stringParserFromRule('SOCKS5ServerResponse')
        self.assertEqual(parse('\x05\x00\x00\x03\x00\x00\x00'), (0, '', 0))
        self.assertEqual(parse('\x05\x01\x00\x01\x7f\x00\x00\x01\x01\x00'),
                         (1, '127.0.0.1', 256))
        self.assertEqual(parse('\x05\x02\x00\x04' + '\x00' * 15 + '\x01\x00\xff'),
                         (2, '::1', 255))

    def test_SOCKS5ClientGreeting(self):
        parse = stringParserFromRule('SOCKS5ClientGreeting')
        self.assertEqual(parse('\x05\x00'), [])
        self.assertEqual(parse('\x05\x01\x01'), [1])
        self.assertEqual(parse('\x05\x02\x00\x02'), [0, 2])
