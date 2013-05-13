from twisted.internet import defer
from txsocksx.errors import SOCKSError

class Anonymous(object):
    method = '\x00'

    def negotiate(self, proto):
        return defer.succeed(None)

class UsernamePasswordAuthFailed(SOCKSError):
    pass

class UsernamePassword(object):
    method = '\x02'

    def __init__(self, uname, passwd):
        self.uname = uname
        self.passwd = passwd

    @defer.inlineCallbacks
    def negotiate(self, proto):
        proto.transport.write(
            '\x01'
            + chr(len(self.uname)) + self.uname
            + chr(len(self.passwd)) + self.passwd)
        resp, = yield proto.unpack('!xB')
        if resp != 0:
            raise UsernamePasswordAuthFailed(resp)
