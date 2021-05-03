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

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext()
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, HOST=host, PORT=int(port), SESSION_COOKIE_NAME='fake')

########################################

def cookify(jsonable):
    return base64.urlsafe_b64encode(dumps(jsonable).encode())

def check_form_against_session(*fields, use_query=False, on_failure=None):
    def inner(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            source = request.args if use_query else request.form
            source_name = 'args' if use_query else 'form'
            for f in fields:
                fs = f.replace('_', '-')
                if on_failure:
                    if session.get(f) != source.get(fs):
                        return on_failure
                else:
                    assert session.get(f) == source.get(fs), \
                        f'at step {session.get("step")}: {source_name} {f!r} {source.get(fs)!r} != session {f!r} {session.get(f)!r}'
            return fn(*args, **kwargs)
        return wrapped
    return inner

########################################


# Get parameters into the initial session setup in order to configure gateways, 2FA requirement
@app.route('/global-protect/testconfig.esp', methods=('GET','POST',))
@app.route('/ssl-vpn/testconfig.esp', methods=('GET','POST',))
def testconfig():
    gateways, portal_2fa, gw_2fa = request.args.get('gateways'), request.args.get('portal_2fa'), request.args.get('gw_2fa')
    session.update(gateways=gateways and gateways.split(','),
                   portal_2fa=portal_2fa and bool(portal_2fa), gw_2fa=gw_2fa and bool(gw_2fa))
    prelogin = '/'.join(request.path.split('/')[:-1] + ['prelogin.esp'])
    return redirect(prelogin)


# Respond to initial prelogin requests
@app.route('/global-protect/prelogin.esp', methods=('GET','POST',))
@app.route('/ssl-vpn/prelogin.esp', methods=('GET','POST',))
def prelogin():
    session.update(step='%s-prelogin' % ('portal' if 'global-protect' in request.path else 'gateway'))
    return '''
<prelogin-response>
<status>Success</status>
<ccusername/>
<autosubmit>false</autosubmit>
<msg/>
<newmsg/>
<authentication-message>Please login to this fake VPN</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>
<region>EARTH</region>
</prelogin-response>'''.format(request.path)


def challenge_2fa(where):
    # select a random inputStr of 4 hex digits, and randomly return challenge in either XML or Javascript-y form
    inputStr = '%04x' % randint(0x1000, 0xffff)
    session.update(step='%s-2FA' % where, inputStr=inputStr)
    if randint(1, 2) == 1:
        tmpl = '<challenge><respmsg>2FA challenge from %s</respmsg><inputstr>%s</inputstr></challenge>'
    else:
        tmpl = ('var respStatus = "Challenge";\n'
                'var respMsg = "2FA challenge from %s";\n'
                'thisForm.inputStr.value = "%s";\n')
    return tmpl % (where, inputStr)


# Respond to portal getconfig request
@app.route('/global-protect/getconfig.esp', methods=('POST',))
def portal_config():
    portal_2fa = session.get('portal_2fa')
    inputStr = request.form.get('inputStr') or None
    if portal_2fa and not inputStr:
        return challenge_2fa('portal')
    if not (request.form.get('user') and request.form.get('passwd') and inputStr == session.get('inputStr')):
        return 'Invalid username or password', 512

    session.update(step='portal-config', user=request.form.get('user'), passwd=request.form.get('passwd'), inputStr=None)
    gateways = session.get('gateways') or ('Default gateway',)
    gwlist = ''.join('<entry name="{}:{}"><description>{}</description></entry>'.format(app.config['HOST'], app.config['PORT'], gw)
                     for gw in gateways)

    return '''<?xml version="1.0" encoding="UTF-8" ?>
    <policy><gateways><external><list>{}</list></external></gateways>
    <hip-collection><hip-report-interval>600</hip-report-interval></hip-collection>
    </policy>'''.format(gwlist)


# Respond to gateway login request
@app.route('/ssl-vpn/login.esp', methods=('POST',))
def gateway_login():
    gw_2fa = session.get('gw_2fa')
    inputStr = request.form.get('inputStr') or None
    if gw_2fa and not inputStr:
        return challenge_2fa('gateway')
    if not (request.form.get('user') and request.form.get('passwd') and inputStr == session.get('inputStr')):
        return 'Invalid username or password', 512
    session.update(step='gateway-login', user=request.form.get('user'), passwd=request.form.get('passwd'), inputStr=None)

    for k, v in (('jnlpReady', 'jnlpReady'), ('ok', 'Login'), ('direct', 'yes'), ('clientVer', '4100'), ('prot', 'https:')):
        if request.form.get(k) != v:
            abort(500)
    for k in ('clientos', 'os-version', 'server', 'computer'):
        if not request.form.get(k):
            abort(500)

    portal = 'Portal%d' % randint(1, 10)
    auth = 'Auth%d' % randint(1, 10)
    domain = 'Domain%d' % randint(1, 10)
    preferred_ip = request.form.get('preferred-ip') or '192.168.%d.%d' % (randint(2, 254), randint(2, 254))
    if request.form.get('ipv6-support') == 'yes':
        preferred_ipv6 = request.form.get('preferred-ipv6') or 'fd00::%x' % randint(0x1000, 0xffff)
    else:
        preferred_ipv6 = None
    session.update(preferred_ip=preferred_ip, portal=portal, auth=auth, domain=domain, computer=request.form.get('computer'),
                   ipv6_support=request.form.get('ipv6-support'), preferred_ipv6=preferred_ipv6)
    session['authcookie'] = cookify(dict(session)).decode()

    return '''<?xml version="1.0" encoding="utf-8"?> <jnlp> <application-desc>
        <argument>(null)</argument>
            <argument>{authcookie}</argument>
            <argument>PersistentCookie</argument>
            <argument>{portal}</argument>
            <argument>{user}</argument>
            <argument>TestAuth</argument>
            <argument>vsys1</argument>
            <argument>{domain}</argument>
            <argument>(null)</argument>
            <argument/>
            <argument></argument>
            <argument></argument>
            <argument>tunnel</argument>
            <argument>-1</argument>
            <argument>4100</argument>
            <argument>{preferred_ip}</argument>
            <argument/>
            <argument/>
            <argument>{ipv6}</argument>
            </application-desc></jnlp>'''.format(ipv6=preferred_ipv6 or '', **session)


# Respond to gateway getconfig request
@app.route('/ssl-vpn/getconfig.esp', methods=('POST',))
@check_form_against_session('user', 'portal', 'domain', 'authcookie', 'preferred_ip', 'preferred_ipv6', 'ipv6_support', on_failure="errors getting SSL/VPN config")
def getconfig():
    session.update(step='gateway-config')
    addrs = '<ip-address>{}</ip-address>'.format(session['preferred_ip'])
    if session['ipv6_support'] == 'yes':
        addrs += '<ip-address-v6>{}</ip-address-v6>'.format(session['preferred_ipv6'])
    return '''<response>{}<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>'''.format(addrs)


# Respond to gateway getconfig request
@app.route('/ssl-vpn/hipreportcheck.esp', methods=('POST',))
@check_form_against_session('user', 'portal', 'domain', 'authcookie', 'computer')
def hipcheck():
    session.update(step='gateway-config')
    return '''<response><hip-report-needed>no</hip-report-needed></response>'''


# Respond to faux-CONNECT GET-tunnel with 502
# (what the real GP server responds with when it doesn't like the cookie, intended
# to trigger "cookie rejected" error in OpenConnect)
@app.route('/ssl-tunnel-connect.sslvpn')
# Can't use because OpenConnect doesn't send headers here
# @check_form_against_session('user', 'authcookie', use_query=True)
def tunnel():
    assert 'user' in request.args and 'authcookie' in request.args
    session.update(step='GET-tunnel')
    abort(502)


# Respond to 'GET /ssl-vpn/logout.esp' by clearing session and MRHSession
@app.route('/ssl-vpn/logout.esp')
# XX: real server really requires all these fields; see auth-globalprotect.c
@check_form_against_session('authcookie', 'portal', 'user', 'computer')
def logout():
    return '<response status="success"/>'


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=True, ssl_context=context)
