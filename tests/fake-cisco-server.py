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

import argparse
import ssl
from base64 import b64decode
from flask import Flask, request, session
from textwrap import dedent
import xmltodict
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtensionOID


app = Flask(__name__)
app.config.update(SECRET_KEY=b"fake", DEBUG=True, SESSION_COOKIE_NAME="fake")


########################################


def is_ca_cert(cert):
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        return bc.value.ca
    except cx509.ExtensionNotFound:
        return False


def get_certs(cert_list):
    # cert_list is a list of cryptography x509.Certificate objects
    # from pkcs7.load_der_pkcs7_certificates().
    # GnuTLS and OpenSSL order the certificates differently.
    # GnuTLS provides the certificates in 'canonical order',
    # while OpenSSL provides it in the order the programmer
    # added it to the PKCS#7 structure.
    #
    # Testing shows that Cisco servers can handle any order

    # Ensure that we have exactly one usercert, and that
    # all the rest are (possibly-intermediate) CA certs
    usercert = None
    extracerts = []
    for cert in cert_list:
        if is_ca_cert(cert):
            extracerts.append(cert)
        else:
            assert usercert is None
            usercert = cert
    assert usercert

    # Build a path from the usercert to the root
    path = [usercert]

    # Verify that there are no duplicates in the set
    issuers = {}
    for c in extracerts:
        subject = c.subject.public_bytes()
        assert subject not in issuers
        issuers[subject] = c

    while True:
        try:
            path.append(issuers.pop(path[-1].issuer.public_bytes()))
        except KeyError:
            break

    # Verify that there are no remaining (unused) certificates
    assert len(issuers) == 0

    return tuple(path)


def verify_certs(certs, ca_certs):
    # Build a set of trusted subject DERs from CA certs
    trusted = {c.subject.public_bytes(): c for c in ca_certs}

    # Incrementally build up trust by first checking intermediaries
    for cert in reversed(certs):
        issuer_der = cert.issuer.public_bytes()
        assert issuer_der in trusted, (
            f"Certificate issuer not found in trust store: {cert.issuer}"
        )
        issuer = trusted[issuer_der]
        # Verify signature
        issuer.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        # Add to trusted so intermediaries can vouch for the next cert
        trusted[cert.subject.public_bytes()] = cert


########################################


ALLOWED_HASH_ALGORITHMS = ("sha256", "sha384", "sha512")

INITIAL_RESPONSE = dedent(
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <multiple-client-cert-request>{}</multiple-client-cert-request>
    <cert-authenticated></cert-authenticated>
    </config-auth>""".format(
        "".join(
            "<hash-algorithm>%s</hash-algorithm>" % algo
            for algo in ALLOWED_HASH_ALGORITHMS
        )
    )
)

AUTH_COMPLETE_RESPONSE = dedent("""
    <?xml version="1.0" encoding="UTF-8"?>
    <config-auth client="vpn" type="complete" aggregate-auth-version="2">
    <session-id>123456789</session-id>
    <session-token>1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD</session-token>
    <auth id="success"/>
    <config/>
    </config-auth>""")


# Respond to XML/POST auth requests
@app.route("/", methods=("POST",))
def handle_xmlpost(usergroup=None):
    dict_req = xmltodict.parse(request.data)
    assert "config-auth" in dict_req
    assert (
        "@client" in dict_req["config-auth"]
        and dict_req["config-auth"]["@client"] == "vpn"
    )
    assert "@type" in dict_req["config-auth"]

    step = dict_req["config-auth"]["@type"]
    session.update(step=step, authid="main")
    if step == "init":
        return initial_request(dict_req)
    elif step == "auth-reply":
        return auth_reply(dict_req)
    else:
        raise AssertionError("Unexpected config-auth/@type %r" % step)


def initial_request(dict_req):
    config_auth = dict_req["config-auth"]
    assert "multiple-cert" in config_auth["capabilities"]["auth-method"]
    return INITIAL_RESPONSE


def auth_reply(dict_req):
    config_auth = dict_req["config-auth"]
    assert "client-cert-chain" in config_auth["auth"]
    client_cert_chain = config_auth["auth"]["client-cert-chain"]
    assert client_cert_chain[0]["@cert-store"] == "1M"
    assert client_cert_chain[0]["client-cert-sent-via-protocol"] is None  # empty tag
    assert client_cert_chain[1]["@cert-store"] == "1U"
    assert client_cert_chain[1]["client-cert"]["@cert-format"] == "pkcs7"
    certs_pkcs7 = b64decode(client_cert_chain[1]["client-cert"]["#text"])
    signature = b64decode(client_cert_chain[1]["client-cert-auth-signature"]["#text"])
    algo = client_cert_chain[1]["client-cert-auth-signature"]["@hash-algorithm-chosen"]
    assert algo in ALLOWED_HASH_ALGORITHMS

    certs = get_certs(pkcs7.load_der_pkcs7_certificates(certs_pkcs7))
    assert 1 <= len(certs) <= 10

    if app.config["ca_certs"]:
        verify_certs(certs, app.config["ca_certs"])

    # Verify that the client has signed the INITIAL_RESPONSE using the private key
    # corresponding to the appropriate certificate, using the chosen hash algorithm.
    hash_algo = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }[algo]
    certs[0].public_key().verify(
        signature, INITIAL_RESPONSE.encode(), padding.PKCS1v15(), hash_algo
    )

    return AUTH_COMPLETE_RESPONSE


def main(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)

    ca_certs = []
    if args.cafile:
        with open(args.cafile, "rb") as f:
            pem_data = f.read()
        import re

        for m in re.finditer(
            b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            pem_data,
            re.DOTALL,
        ):
            ca_certs.append(cx509.load_pem_x509_certificate(m.group(0)))
        assert ca_certs

    app.config["ca_certs"] = ca_certs
    app.run(
        host=args.host,
        port=args.port,
        debug=True,
        ssl_context=context,
        use_reloader=False,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cisco AnyConnect server stub")
    parser.add_argument(
        "--enable-multicert",
        action="store_true",
        help="Enable multiple-certificate authentication",
    )
    parser.add_argument("--cafile", help="Path to CA file")
    parser.add_argument("host", help="Bind address")
    parser.add_argument("port", type=int, help="Bind port")
    parser.add_argument("cert", help="TLS user certificate to validate")
    parser.add_argument(
        "key", nargs="?", help="Key of TLS user certificate to validate"
    )
    args = parser.parse_args()

    if not args.enable_multicert:
        parser.error(
            "This server stub is solely implemented to exercise "
            "multiple-certificate authentication."
        )

    main(args)
