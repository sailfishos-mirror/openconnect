#!/usr/bin/env python3
#
# Copyright © 2021 Daniel Lenski
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

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext()
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, HOST=host, PORT=int(port), SESSION_COOKIE_NAME='fake')

########################################

def cookify(jsonable):
    return base64.urlsafe_b64encode(dumps(jsonable).encode())

########################################

# Respond to initial auth request (XML/POST only, for now)
@app.route('/', methods=('POST',))
def initial_xmlpost(usergroup=None):
    request.data

    # FIXME: check that the request XML looks like this:
    # <config-auth client="vpn" type="init">
    #   <version who="vpn">v8.10-472-g3920a629-dirty</version>
    #   <device-id>linux-64</device-id>
    #   <group-access>https://localhost:4443/</group-access>
    # </config-auth>

    session.update(step='initial-xmlpost', auth_id='main')
    return '''<config-auth><auth id="{auth_id}">
<title>Fake server</title><banner>This isn't a real server</banner>
<message>Please enter your username and password for this FAKE server</messaage>
<form method="post" action="/+webvpn+/index.html">
<input type="text" name="username" label="Username:" />
<input type="password" name="password" label="Password:" />
</form></auth></config-auth>'''.format(**session)


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


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=True, ssl_context=context)
