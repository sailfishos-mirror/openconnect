#!/usr/bin/env python3
#
# Copyright © 2021 Daniel Lenski
# Copyright © 2021 Tom Carroll
#
# This file is part of openconnect.
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#!/usr/bin/env python3

import sys
import ssl
from random import randint
import base64
import time
from json import dumps
from functools import wraps
from flask import Flask, request, abort, redirect, url_for, make_response, session
from werkzeug.serving import WSGIRequestHandler
from textwrap import dedent
import xmltodict
import OpenSSL, base64

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, SESSION_COOKIE_NAME='fake')

########################################

def cookify(jsonable):
    return base64.urlsafe_b64encode(dumps(jsonable).encode())

########################################

def generate_initial_request():
    request = dedent('''\
                      <?xml version="1.0" encoding="UTF-8"?>
                      <config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
                      <opaque is-for="sg">
                      <aggauth-handle>1234567890</aggauth-handle>
                      <auth-method>multiple-cert</auth-method>
                      <config-hash>1569257118741</config-hash>
                      </opaque>
                      <multiple-client-cert-request>
                      <hash-algorithm>sha256</hash-algorithm>
                      <hash-algorithm>sha384</hash-algorithm>
                      <hash-algorithm>sha512</hash-algorithm>
                      </multiple-client-cert-request>
                      <random>90639C8E4A5407D555520F4B0656CF745BA4C1674ADEDC30C015406333840B585AE74A4921DDFB7A500263ACB527953965A0D0FCC15E15BE7B0F73E617E36E9E</random>
                      <cert-authenticated></cert-authenticated>
                      </config-auth>''')
    return request

########################################

def is_ca_cert(cert):
    for ext in (cert.get_extension(i) for i in range(cert.get_extension_count())):
        if (ext.get_short_name() == b'basicConstraints' and str(ext).find('CA:TRUE') > -1):
            return True
    return False

########################################

def get_certs(p7):
    from OpenSSL.crypto import _lib, _ffi, X509

    """ client-cert is a PKCS7-encoded set of certificates.
        GnuTLS and OpenSSL order the certificates differently.
        GnuTLS provides the certificates in 'canonical order',
        while OpenSSL provides it in the order the programmer
        added it to the PKCS#7 structure."""

    """ Testing shows that Cisco can handle any order """

    if p7.type_is_signed():
        certs = p7._pkcs7.d.sign.cert
    elif p7.type_is_signedAndEnveloped():
        certs = p7._pkcs7.d.signed_and_enveloped.cert
    else:
        return ()

    usercert = None
    extracerts = []
    for i in range(_lib.sk_X509_num(certs)):
        cert = _lib.X509_dup(_lib.sk_X509_value(certs, i))
        pycert = X509._from_raw_x509_ptr(cert)
        if is_ca_cert(pycert):
            extracerts.append(pycert)
        else:
            assert usercert is None
            usercert = pycert
    assert usercert

    """ Now build a path from usercert to a root """
    path = [ usercert ]

    """ Check for duplicate certificates in the set """
    issuers = { }
    for c in extracerts:
        subject = c.get_subject().der()
        assert subject not in issuers
        issuers[subject] = c

    while True:
         issuer = issuers.pop(path[-1].get_issuer().der(), None)
         if issuer is None: break
         path.append(issuer)

    """ Ensure that there aren't any remaining certificates """
    assert len(issuers) == 0

    return tuple(path)

########################################

def verify_certs(certs, ca_certs):
    from OpenSSL.crypto import load_certificate, X509Store, X509StoreContext

    """ Initialize trust store with CA certificates """
    store = X509Store()
    for cert in ca_certs:
        store.add_cert(cert)

    """ Incrementally build up trust by first checking intermedaries """
    for cert in reversed(certs):
        store_ctx = X509StoreContext(store, cert)
        store_ctx.verify_certificate()
        """ Add intermediary to trust """
        store.add_cert(cert)

########################################

# Respond to initial auth request (XML/POST only, for now)
@app.route('/', methods=('POST',))
def initial_xmlpost(usergroup=None):
    dict_req = xmltodict.parse(request.data)
    assert 'config-auth' in dict_req
    assert '@client' in dict_req['config-auth'] and dict_req['config-auth']['@client'] == 'vpn'
    assert '@type' in dict_req['config-auth']

    def initial_request():
        assert dict_req['config-auth']['@type'] == 'init'
        assert dict_req['config-auth']['capabilities']['auth-method'] == 'multiple-cert'
        assert dict_req['config-auth']['group-access']

        """step is None iff config-auth/@type == init"""
        assert session.get('step', None) is None

        resp = generate_initial_request()
        return resp.format(**session)

    def auth_reply():
        assert dict_req['config-auth']['@type'] == 'auth-reply'
        assert 'client-cert-chain' in dict_req['config-auth']['auth']
        client_cert_chain = dict_req['config-auth']['auth']['client-cert-chain']
        assert client_cert_chain[0]['@cert-store'] == '1M'
        assert client_cert_chain[0]['client-cert-sent-via-protocol'] is None
        assert client_cert_chain[1]['@cert-store'] == '1U'
        assert client_cert_chain[1]['client-cert']['@cert-format'] == 'pkcs7'
        assert client_cert_chain[1]['client-cert']['#text']
        assert client_cert_chain[1]['client-cert-auth-signature']['@hash-algorithm-chosen'] in ('sha256', 'sha384', 'sha512',)
        assert client_cert_chain[1]['client-cert-auth-signature']['#text']

        """step == init iff config-auth/@type == auth-reply"""
        assert session.get('step', None) == 'init'

        certs = client_cert_chain[1]['client-cert']['#text']
        certs = OpenSSL.crypto.load_pkcs7_data(OpenSSL.crypto.FILETYPE_ASN1,
                                               base64.b64decode(certs))
        certs = get_certs(certs)
        assert len(certs) >= 1
        assert len(certs) <= 10

        sign = base64.b64decode(client_cert_chain[1]['client-cert-auth-signature']['#text'])

        digest = client_cert_chain[1]['client-cert-auth-signature']['@hash-algorithm-chosen']

        if app.config['ca_certs']:
            verify_certs(certs, app.config['ca_certs'])

        OpenSSL.crypto.verify(certs[0], sign,
                              generate_initial_request().encode('utf-8'),
                              digest)

        resp = dedent('''\
                      <?xml version="1.0" encoding="UTF-8"?>
                      <config-auth client="vpn" type="complete" aggregate-auth-version="2">
                      <session-id>123456789</session-id>
                      <session-token>1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD</session-token>
                      <auth id="success">
                      <message id="0" param1="" param2=""></message>
                      </auth>
                      <config/>
                      </config-auth>''')
        return resp.format(**session)

    step = dict_req['config-auth']['@type']
    dispatcher = { 'init': initial_request, 'auth-reply': auth_reply }

    assert step in dispatcher.keys()

    response = dispatcher[step]()
    session.update(step=step, authid='main')
    return response

@app.route('/+webvpn+/index.html', methods=('POST',))
def main_auth_post():
    auth_id = session.get('auth_id')

    # FIXME: check that the request XML looks like this
    # (at least the username and password fields must be present):
    # <config-auth client="vpn" type="auth-reply">
    #   <version who="vpn">v8.10-472-g3920a629-dirty</version>
    #   <device-id>linux-64</device-id>
    #   <auth><username>test</username><password>foo</password></auth>
    # </config-auth>

    session.update(step='main-auth-xmlpost', auth_id='success')
    webvpn = cookify(dict(session)).decode()
    session.update(webvpn=webvpn)

    return '''<config-auth type="complete"><session-token>{webvpn}</session-token><auth id="{auth_id}"/></config-auth>'''.format(
        **session)


# respond to 'CONNECT /CSCOSSLC/tunnel' with 401, what the real
# Cisco server returns when it doesn't like the webvpn cookie
@app.route('/CSCOSSLC/tunnel', methods=('CONNECT',))
def tunnel_connect():
    assert request.headers.get('X-CSTP-Version') == '1'

    # Can't actually check the value since standard HTTP cookies (including our 'fake' session cookie)
    # are not passed by OpenConnect on the CONNECT request:
    # assert request.cookies.get('webvpn') == session.get('webvpn')
    assert request.cookies.get('webvpn')

    abort(401)

def main(args):
    context = ssl.SSLContext()
    context.load_cert_chain(args.cert, args.key)

    """ Read cafile, parsing each certificate found """
    ca_certs = []
    if args.cafile:
        with open(args.cafile, 'r', encoding='utf-8') as f:
            root_cas_pem = f.read()

        delimiter = '-----BEGIN CERTIFICATE-----\n'
        offset = 0
        while True:
            offset = root_cas_pem.find(delimiter, offset)
            if offset < 0: break
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, root_cas_pem[offset:])
            ca_certs.append(cert)
            offset += len(delimiter)

        assert ca_certs

    app.config['ca_certs'] = ca_certs
    app.run(host=args.host, port=args.port, debug=True, ssl_context=context)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Cisco AnyConnect server stub')
    parser.add_argument('--enable-multicert', default=False, action='store_true',
                        help='Enable multiple-certificate authentication')
    parser.add_argument('--cafile', default=None, help='Path to CA file')
    parser.add_argument('host', help='Bind address')
    parser.add_argument('port', type=int, help='Bind port')
    parser.add_argument('cert')
    parser.add_argument('key', default=None, nargs='?')
    args = parser.parse_args()

    if not args.enable_multicert:
        print(dedent("""\
                This server stub is solely implemented to excerise
                multiple-certificate authentication."""), file=sys.stderr)
        sys.exit(1)

    main(args)
