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
import re
import sys
import tempfile
import struct
import string
import hashlib
import socket
socket.SO_ORIGINAL_DST = 80
import ssl as pyssl
import pprint
import glob

from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol
from twisted.internet import ssl, reactor, protocol, defer, utils, threads
from twisted.internet.defer import succeed
from twisted.internet import reactor, protocol, ssl, task
from twisted.protocols import tls
from twisted.python import log
from twisted.python.log import err
from twisted.web import http
from twisted.web.client import ProxyAgent, readBody
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer

from twisted.internet.ssl import ContextFactory
from OpenSSL.SSL import Context,TLSv1_METHOD
#import ssl
from OpenSSL import SSL

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from zope.interface import implementer

log.startLogging(sys.stdout)

@defer.inlineCallbacks
def certMaker(cert):
    print(cert)
    if cert['subject'][-1][0][0]!='commonName':
        raise Exception('tip of subject is not commonName')

    hostname = cert['subject'][-1][0][1]
    OU = cert['issuer'][1][0][1]
    O = cert['issuer'][2][0][1]
    chash = cert['hash']

    keyfile =  '%s/%s-key.pem' % (os.environ.get("SSLCACHE_DIR"), chash,)
    csrfile = '%s/%s-csr.pem' % (os.environ.get("SSLCACHE_DIR"), chash,)
    certfile = '%s/%s-crt.pem' % (os.environ.get("SSLCACHE_DIR"), chash,)
    log.msg("keyfile %s" % (keyfile))
    log.msg("csrfile %s" % (csrfile))
    try:
        # check for a cert already on-disk
        # with the same sha1 hash of binary blob
        os.stat(certfile)
    except:
        print("making new fake cert")
    else:
        print("using fake cert from disk")
        # file already exists on-disk
        # assume key is present too
        r = {
                'name': hostname,
                'cert': certfile,
                'key': keyfile,
                }
        defer.returnValue(r)


    # Is this sufficient? Maybe we want to copy whole DN?
    # Or read the 2nd & subsequent bits of the DN from our CA cert?
    subj = '/CN=%s/OU=%s/O=%s' % (
            hostname,
            OU,
            O
            )

    # FIXME: key filenames by host/port combo, or maybe "real" cert hash?
    # FIXME: make the CA configurable?
    res = yield utils.getProcessOutputAndValue('/usr/bin/openssl',
        ('req','-newkey','rsa:2048','-nodes','-subj',subj,'-keyout',keyfile,'-out',csrfile),
        )
    out, err, code = res
    if code!=0:
        raise Exception('error generating csr '+ err + " out:" + out)

    fd, tmpname = tempfile.mkstemp()
    try:
        ext = os.fdopen(fd, 'w')

        # write the subjectAltName extension into a temp .cnf file
        dns = []
        if 'subjectAltName' in cert:
            for san in cert['subjectAltName']:
                if san[0]!='DNS':
                    continue
                dns.append('DNS:'+san[1])
        if dns:
            ext.write("subjectAltName=" + ','.join(dns))

        # FIXME: copy other extensions? eku?
        ext.close()

        # process the .csr with our CA cert to generate a signed cert
        res = yield utils.getProcessOutputAndValue('/usr/bin/openssl',
            ('x509','-req','-days','365','-in',csrfile,'-CA',os.environ.get("SSLCERT_FILE"),'-CAkey',os.environ.get("SSLKEY_FILE"),'-set_serial','0','-extfile',tmpname,'-out',certfile),
            )
    finally:
        # remove temp file
        os.unlink(tmpname)

    out, err, code = res
    if code==0:
        r = {
                'name': hostname,
                'cert': certfile,
                'key': keyfile,
                }
        defer.returnValue(r)

    raise Exception('failed to generate cert '+err)

# The twisted SSL client API is a bit of a pain
# we use the normal python socket/ssl API via a
# deferToThread
def _ssl_cert_chain(host, port):

    # FIXME: use getaddrinfo, not IPv6-safe here
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # FIXME: configurable timeout?
    s.settimeout(5)
    s.connect((host, port))

    sec = pyssl.wrap_socket(
            s,
            # NOTE: it seems that, unless we do verification,
            # python doesn't expose the peer cert to us.
            # This means we need to supply a CA bundle, so
            # this code doesn't support self-signed certs.
            #
            # It might be possible to do better with an explicit
            # context & verify callback?
            cert_reqs=pyssl.CERT_REQUIRED,
            ca_certs='/etc/ssl/certs/ca-certificates.crt',
            )
    # should be redundant, in theory...
    sec.do_handshake()

    # get peer certs
    rv = sec.getpeercert()
    log.msg("RV: %s" % (rv))
    bin = sec.getpeercert(binary_form=True)
    log.msg("bin: %s" % (bin))
    rv['hash'] = hashlib.sha1(bin).hexdigest()
    log.msg("hash: %s" % (rv['hash']))

    sec.close()
    del sec
    del s
    return rv

def ssl_cert_chain(host, port):
    return threads.deferToThread(_ssl_cert_chain, host, port)

class CertCache:
    def __init__(self):
        self._cache = {}
        for cert in glob.glob(os.environ.get("SSLCACHE_DIR")+"/*-crt.pem"):
            key = cert.replace("-crt.pem", "-key.pem")
            log.msg("%s" % (str.encode(open(cert).read())))
            _cert = x509.load_pem_x509_certificate(str.encode(open(cert).read()), default_backend())
            domain = _cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            sni = []
            try: 
                sni = _cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
            except:
                pass
            if domain not in sni:
                sni.append(domain)
            for domain in sni:
                self._cache[str.encode(domain), 443] = {
                    'name': domain,
                    'cert': cert,
                    'key': key,
                }

    def printCache(self):
        log.msg(pprint.pformat(self._cache))

    @defer.inlineCallbacks
    def checkSSL(self, host, port):

        log.msg("search for %s:%d" % (host, port))
        if (host, port) in self._cache:
            log.msg("find %s:%d" % (host, port))
            defer.returnValue(self._cache[host, port])

        # get the cert on that ip/port combp
        cert = yield ssl_cert_chain(host, port)

        # make a fake
        log.msg("Cert %s" % (cert))
        fake = yield certMaker(cert)

        # add to cache
        self._cache[host, port] = fake

        # done
        defer.returnValue(fake)

cache = None

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

        headers = {};
        for key, values in self.requestHeaders.getAllRawHeaders():
            if key.lower() == "connection":
                headers[key] = ['close']
            elif key.lower() == 'keep-alive':
                next
            else:
                headers[key] = values

        if self.method == b"POST" or self.method == b"PUT":
            log.msg("POST Data: %s" % (postData))
            body = BytesProducer(postData)
            d = agent.request(self.method, url, Headers(headers), body)
        else:
            d = agent.request(self.method, url, Headers(headers))
        d.addCallback(self.forwardToClient)

    def processResponse(self, data):
        return data

    def forwardToClient(self, response):
        print("Received response")
        print('Response version:', response.version)
        print('Response code:', response.code)
        print('Response phrase:', response.phrase)
        print('Response headers:')
        print(pprint.pformat(list(response.headers.getAllRawHeaders())))

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

class SSLFactory(ContextFactory):

    def convert_version2method(self, protocol_version):
        """
        Convert internal protocol version ID to OpenSSL method.

        :param Integer protocol_version: Version ID
        :return: OpenSSL method or None if not found
        :rtype: OpenSSL method or None
        """
        log.msg(protocol_version)
        if protocol_version == "TLSv1":
            return SSL.TLSv1_METHOD
        if protocol_version == "TLSv1.1":
            return SSL.TLSv1_1_METHOD
        if protocol_version == "TLSv1.2":
            return SSL.TLSv1_2_METHOD
        return None     

    def __call__(self,connection):
        log.msg(connection)
        log.msg("Servername: %s" % (connection.get_servername()))
        log.msg("TLS Version: %s" % (connection.get_protocol_version_name()))

        d = cache.checkSSL(connection.get_servername(), 443)
        d.addCallback(self._gotcert, connection, 443)
        d.addErrback(self._goterr, connection.get_servername(), 443)
        
        # new_context = Context(self.convert_version2method(connection.get_protocol_version_name()))
        # new_context.use_privatekey_file(self.certinfo['key'])
        # new_context.use_certificate_file(self.certinfo['cert'])
        # connection.set_context(new_context)

    def _goterr(self, fail, orighost, origport):
        log.msg('failed to get SSL cert for', orighost, origport, fail)
        log.err(fail)
        # FIX: how to close the connection in this state?

    def _gotcert(self, result, origconnection, origport):
        self.certinfo = result

        log.msg("conneccting to", origconnection.get_servername(), origport)
       
        new_context = Context(self.convert_version2method(origconnection.get_protocol_version_name()))
        new_context.use_privatekey_file(self.certinfo['key'])
        new_context.use_certificate_file(self.certinfo['cert'])
        origconnection.set_context(new_context)        
#        f = ForwardFactory()
#        f.other = self
#         
    def getContext(self):
#        log.msg(self.connection.get_protocol_version_name())
        server_context = Context(SSL.TLSv1_2_METHOD)
        server_context.set_tlsext_servername_callback(self)
        #server_context.sni_callback=self.server_name
        return server_context

def printCache():
    cache.printCache()

if __name__ == "__main__":
    env = ["HTTP_PORT", "HTTPS_PORT", "SSLCACHE_DIR", "SSLKEY_FILE", "SSLCERT_FILE", "PROXY_HOST", "PROXY_PORT"]
    for e in env:
        if os.environ.get(e) == None:
            log.err("Variable %s not set" % (e))
            sys.exit(-1)
    cache = CertCache()
    reactor.listenTCP(int(os.environ.get("HTTP_PORT")), ProxyFactory())
    # https://github.com/philmayers/txsslmitm/blob/master/mitm.py
    #reactor.listenSSL(int(os.environ.get("HTTPS_PORT")), ProxyFactory(), ssl.DefaultOpenSSLContextFactory(os.environ.get("SSLKEY_FILE"), os.environ.get("SSLCERT_FILE")))
    # factory = MitmFactory()
    reactor.listenSSL(int(os.environ.get("HTTPS_PORT")), ProxyFactory(), SSLFactory())
    l = task.LoopingCall(printCache)
    l.start(10.0) # call every second
    reactor.run()
