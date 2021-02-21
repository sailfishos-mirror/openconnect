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

########################################
# This program emulates the authentication-phase behavior of a F5
# server enough to test OpenConnect's authentication behavior against it.
# Specifically, it emulates the following requests:
#
#    GET /
#    GET /my.policy
#    POST /my.policy
#
# It does not actually validate the credentials in any way, but attempts to
# verify their consistency from one request to the next, by saving their
# values via a (cookie-based) session.
########################################

import sys
import ssl
import random
import base64
import time
from json import dumps
from functools import wraps
from flask import Flask, request, abort, redirect, url_for, make_response, session

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext()
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, HOST=host, PORT=int(port), SESSION_COOKIE_NAME='fake')

########################################

def cookify(jsonable):
    return base64.urlsafe_b64encode(dumps(jsonable).encode())

def require_MRHSession(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not request.cookies.get('MRHSession'):
            session.clear()
            return redirect(url_for('get_policy'))
        return fn(*args, **kwargs)
    return wrapped

def check_form_against_session(*fields, use_query=False):
    def inner(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            source = request.args if use_query else request.form
            source_name = 'args' if use_query else 'form'
            for f in fields:
                assert session.get(f) == source.get(f), \
                    f'at step {session.get("step")}: {source_name} {f!r} {source.get(f)!r} != session {f!r} {session.get(f)!r}'
            return fn(*args, **kwargs)
        return wrapped
    return inner

########################################

# Respond to initial 'GET /' with a redirect to '/my.policy'
@app.route('/')
def root():
    session.update(step='initial-GET')
    # print(session)
    return redirect(url_for('get_policy'))


# Respond to 'GET /my.policy with a placeholder stub (since OpenConnect doesn't even try to parse the form)
@app.route('/my.policy')
def get_policy():
    session.update(step='GET-login-form')
    return 'login page'


# Respond to 'POST /my.policy with an empty response containing MRHSession and F5_ST
# cookies (OpenConnect uses the combination of the two to detect successful authentication)
@app.route('/my.policy', methods=['POST'])
def post_policy():
    session.update(step='POST-login', username=request.form.get('username'), credential=request.form.get('password'))
    # print(session)

    resp = make_response('')
    resp.set_cookie('MRHSession', cookify(dict(session)))
    resp.set_cookie('F5_ST', '1z1z1z%dz%d' % (time.time(), 3600))
    return resp


# Respond to 'GET /remote/logout' by clearing session and MRHSession
@app.route('/remote/logout')
@require_MRHSession
def logout():
    assert request.args == {'hangup_error': '1'}
    session.clear()
    resp = make_response('successful logout')
    resp.set_cookie('MRHSession', '')
    return resp


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'],
        ssl_context=context, use_debugger=False)
