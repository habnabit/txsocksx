# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from twisted.internet import defer
from twisted.protocols import policies
from twisted.python import failure
from twisted.test import proto_helpers
from twisted.trial import unittest


class FakeEndpoint(object):
    def __init__(self, failure=None):
        self.failure = failure
        self.deferred = None

    def connect(self, fac):
        self.factory = fac
        if self.deferred:
            return self.deferred
        if self.failure:
            return defer.fail(self.failure)
        self.proto = fac.buildProtocol(None)
        transport = proto_helpers.StringTransport()
        self.aborted = []
        transport.abortConnection = lambda: self.aborted.append(True)
        self.tlsStarts = []
        transport.startTLS = lambda ctx: self.tlsStarts.append(ctx)
        self.proto.makeConnection(transport)
        self.transport = transport
        return defer.succeed(self.proto)


class UppercaseWrapperProtocol(policies.ProtocolWrapper):
    def dataReceived(self, data):
        policies.ProtocolWrapper.dataReceived(self, data.upper())

    def write(self, data):
        policies.ProtocolWrapper.write(self, data.upper())

    def writeSequence(self, seq):
        for data in seq:
            self.write(data)

class UppercaseWrapperFactory(policies.WrappingFactory):
    protocol = UppercaseWrapperProtocol

    def __init__(self, context, ign, factory):
        self.context = context
        policies.WrappingFactory.__init__(self, factory)


class SyncDeferredsTestCase(unittest.TestCase):
    def successResultOf(self, deferred):
        """
        Return the current success result of C{deferred} or raise
        C{self.failException}.

        @param deferred: A L{Deferred<twisted.internet.defer.Deferred>} which
            has a success result.  This means
            L{Deferred.callback<twisted.internet.defer.Deferred.callback>} or
            L{Deferred.errback<twisted.internet.defer.Deferred.errback>} has
            been called on it and it has reached the end of its callback chain
            and the last callback or errback returned a non-L{failure.Failure}.
        @type deferred: L{Deferred<twisted.internet.defer.Deferred>}

        @raise SynchronousTestCase.failureException: If the
            L{Deferred<twisted.internet.defer.Deferred>} has no result or has a
            failure result.

        @return: The result of C{deferred}.
        """
        result = []
        deferred.addBoth(result.append)
        if not result:
            self.fail(
                "Success result expected on %r, found no result instead" % (
                    deferred,))
        elif isinstance(result[0], failure.Failure):
            self.fail(
                "Success result expected on %r, "
                "found failure result instead:\n%s" % (
                    deferred, result[0].getTraceback()))
        else:
            return result[0]



    def failureResultOf(self, deferred, *expectedExceptionTypes):
        """
        Return the current failure result of C{deferred} or raise
        C{self.failException}.

        @param deferred: A L{Deferred<twisted.internet.defer.Deferred>} which
            has a failure result.  This means
            L{Deferred.callback<twisted.internet.defer.Deferred.callback>} or
            L{Deferred.errback<twisted.internet.defer.Deferred.errback>} has
            been called on it and it has reached the end of its callback chain
            and the last callback or errback raised an exception or returned a
            L{failure.Failure}.
        @type deferred: L{Deferred<twisted.internet.defer.Deferred>}

        @param expectedExceptionTypes: Exception types to expect - if
            provided, and the the exception wrapped by the failure result is
            not one of the types provided, then this test will fail.

        @raise SynchronousTestCase.failureException: If the
            L{Deferred<twisted.internet.defer.Deferred>} has no result, has a
            success result, or has an unexpected failure result.

        @return: The failure result of C{deferred}.
        @rtype: L{failure.Failure}
        """
        result = []
        deferred.addBoth(result.append)
        if not result:
            self.fail(
                "Failure result expected on %r, found no result instead" % (
                    deferred,))
        elif not isinstance(result[0], failure.Failure):
            self.fail(
                "Failure result expected on %r, "
                "found success result (%r) instead" % (deferred, result[0]))
        elif (expectedExceptionTypes and
              not result[0].check(*expectedExceptionTypes)):
            expectedString = " or ".join([
                '.'.join((t.__module__, t.__name__)) for t in
                expectedExceptionTypes])

            self.fail(
                "Failure of type (%s) expected on %r, "
                "found type %r instead: %s" % (
                    expectedString, deferred, result[0].type,
                    result[0].getTraceback()))
        else:
            return result[0]



    def assertNoResult(self, deferred):
        """
        Assert that C{deferred} does not have a result at this point.

        If the assertion succeeds, then the result of C{deferred} is left
        unchanged. Otherwise, any L{failure.Failure} result is swallowed.

        @param deferred: A L{Deferred<twisted.internet.defer.Deferred>} without
            a result.  This means that neither
            L{Deferred.callback<twisted.internet.defer.Deferred.callback>} nor
            L{Deferred.errback<twisted.internet.defer.Deferred.errback>} has
            been called, or that the
            L{Deferred<twisted.internet.defer.Deferred>} is waiting on another
            L{Deferred<twisted.internet.defer.Deferred>} for a result.
        @type deferred: L{Deferred<twisted.internet.defer.Deferred>}

        @raise SynchronousTestCase.failureException: If the
            L{Deferred<twisted.internet.defer.Deferred>} has a result.
        """
        result = []
        def cb(res):
            result.append(res)
            return res
        deferred.addBoth(cb)
        if result:
            # If there is already a failure, the self.fail below will
            # report it, so swallow it in the deferred
            deferred.addErrback(lambda _: None)
            self.fail(
                "No result expected on %r, found %r instead" % (
                    deferred, result[0]))
