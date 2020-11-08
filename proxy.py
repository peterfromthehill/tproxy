#!/usr/bin/python
"""A basic transparent HTTP proxy"""

__author__ = "Erik Johansson"
__email__  = "erik@ejohansson.se"
__license__= """
Copyright (c) 2012 Erik Johansson <erik@ejohansson.se>
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

import os
from pprint import pformat
from twisted.python.log import err
from twisted.web import http
from twisted.internet import reactor, protocol, ssl
from twisted.python import log
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol
from twisted.web.client import ProxyAgent, readBody
from twisted.web.http_headers import Headers
from twisted.internet.defer import succeed
from twisted.web.iweb import IBodyProducer
from zope.interface import implementer
import re
import sys

log.startLogging(sys.stdout)

@implementer(IBodyProducer)
class BytesProducer(object):
    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass        

class ProxyRequest(http.Request):
    def __init__(self, channel, queued, reactor=reactor):
        http.Request.__init__(self, channel, queued)
        self.reactor = reactor

    def process(self):
        host = self.getHeader('Host')
        if not host:
            log.err("No host header given")
            self.setResponseCode(400)
            self.finish()
            return

        port = 80
        if self.isSecure() == True:
            port = 443
        if ':' in host:
            host, port = host.split(':')
            port = int(port)

        log.msg("self: %s" % (self))
        log.msg("host:port: %s:%s" % (host, port))
        self.setHost(host, port)

        self.content.seek(0, 0)
        postData = self.content.read()
        endpoint = TCP4ClientEndpoint(self.reactor, os.environ.get("PROXY_HOST"), int(os.environ.get("PROXY_PORT")))
        agent = ProxyAgent(endpoint)
        scheme = b"http"
        if self.isSecure() == True:
            scheme = b"https"
        userpw = None
        url = scheme + b"://" + str.encode(host)  + b":" + str.encode(str(port)) + self.uri
        if self.getUser() != None and self.getPassword() != None:
            userpw = self.getUser() + b":" + self.getPassword()
            url = scheme + b"://" + userpw + b"@" + str.encode(host)  + b":" + str.encode(str(port)) + self.uri
        log.msg("URL: %s" % (url))
        d = Deferred()
        log.msg("Method: %s" % (self.method))
        if self.method == b"POST" or self.method == b"PUT":
            log.msg("POST Data: %s" % (postData))
            body = BytesProducer(postData)
            d = agent.request(self.method, url, self.requestHeaders, body)
        else:
            d = agent.request(self.method, url, self.requestHeaders)
        d.addCallback(self.forwardToClient)

    def processResponse(self, data):
        return data

    def forwardToClient(self, response):
        print("Received response")
        print('Response version:', response.version)
        print('Response code:', response.code)
        print('Response phrase:', response.phrase)
        print('Response headers:')
        print(pformat(list(response.headers.getAllRawHeaders())))

        self.setResponseCode(response.code)
        self.responseHeaders = response.headers

        finished = Deferred()
        finished = readBody(response)
        finished.addCallback(self.forwardBodyToClient)
        return finished

    def forwardBodyToClient(self, body):
        print('Reponse body:')
        print(len(body))
        self.write(body)
        self.finish()

class TransparentProxy(http.HTTPChannel):
    requestFactory = ProxyRequest
 
class ProxyFactory(http.HTTPFactory):
    protocol = TransparentProxy
 
if __name__ == "__main__":
    env = ["HTTP_PORT", "HTTPS_PORT", "SSLKEY_FILE", "SSLCERT_FILE", "PROXY_HOST", "PROXY_PORT"]
    for e in env:
        if os.environ.get(e) == None:
            log.err("Variable %s not set" % (e))
            sys.exit(-1)
    reactor.listenTCP(int(os.environ.get("HTTP_PORT")), ProxyFactory())
    # https://github.com/philmayers/txsslmitm/blob/master/mitm.py
    reactor.listenSSL(int(os.environ.get("HTTPS_PORT")), ProxyFactory(), ssl.DefaultOpenSSLContextFactory(os.environ.get("SSLKEY_FILE"), os.environ.get("SSLCERT_FILE")))
    reactor.run()
