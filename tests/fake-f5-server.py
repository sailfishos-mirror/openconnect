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
from flask import Flask, request, redirect, url_for, make_response, session

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
# [Save list of domains/authgroups in the session for use later]
@app.route('/')
def root():
    domains, mock_dtls, no_html_login_form = request.args.get('domains'), request.args.get('mock_dtls'), request.args.get('no_html_login_form')
    assert not (domains and no_html_login_form), \
        f'combination of domains and no_html_login_form is not allow specified'
    session.update(step='initial-GET', domains=domains and domains.split(','),
                   mock_dtls=mock_dtls and bool(mock_dtls),
                   no_html_login_form = no_html_login_form and bool(no_html_login_form))
    # print(session)
    return redirect(url_for('get_policy'))


# Respond to 'GET /my.policy with a login form
@app.route('/my.policy')
def get_policy():
    session.update(step='GET-login-form')
    no_html_login_form = session.get('no_html_login_form')
    if no_html_login_form:
        return '''<html><body>It would be nice if F5 login pages consistently used actual HTML forms</body></html>'''

    domains = session.get('domains')
    sel = ''
    if domains:
        sel = '<select name="domain">%s</select>' % ''.join(
            '<option value="%d">%s</option>' % nv for nv in enumerate(domains))

    return '''
<html><body><form id="auth_form" method="post">
<input type="text" name="username"/>
<input type="password" name="password"/>
%s</form></body></html>''' % sel


# Respond to 'POST /my.policy with a redirect response containing MRHSession and F5_ST
# cookies (OpenConnect uses the combination of the two to detect successful authentication)
@app.route('/my.policy', methods=['POST'])
def post_policy():
    domains = session.get('domains')
    if domains:
        assert 0 <= int(request.form.get('domain', -1)) < len(domains)
    session.update(step='POST-login', username=request.form.get('username'),
                   credential=request.form.get('password'),
                   domain=request.form.get('domain'))
    # print(session)

    resp = redirect(url_for('webtop'))
    resp.set_cookie('MRHSession', cookify(dict(session)))
    resp.set_cookie('F5_ST', '1z1z1z%dz%d' % (time.time(), 3600))
    return resp


@app.route('/vdesk/webtop.eui')
def webtop():
    session.update(step='POST-login-webtop')
    # print(session)

    return 'some junk HTML webtop'


# Respond to 'GET /vdesk/vpn/index.php3?outform=xml&client_version=2.0 with an XML config
# [Save VPN resource name in the session for verification of client state later]
@app.route('/vdesk/vpn/index.php3')
@require_MRHSession
def profile_params():
    print(request.args)
    assert request.args.get('outform') == 'xml' and request.args.get('client_version') == '2.0'
    vpn_name = 'demo%d_vpn_resource' % random.randint(1, 100)
    session.update(step='GET-profile-params', resourcename='/Common/'+vpn_name)
    # print(session)

    return (f'''
            <?xml version="1.0" encoding="utf-8"?>
            <favorites type="VPN" limited="YES">
              <favorite id="/Common/{vpn_name}">
                <caption>{vpn_name}</caption>
                <name>/Common/{vpn_name}</name>
                <params>resourcename=/Common/{vpn_name}</params>
              </favorite>
            </favorites>''',
            {'content-type': 'application/xml'})

# Respond to 'GET /vdesk/vpn/connect.php3?outform=xml&client_version=2.0&resourcename=RESOURCENAME
# with an ugliest-XML-you've-ever-seen config.
# [Save random HDLC flag and ur_Z for verification later.]
@app.route('/vdesk/vpn/connect.php3')
@require_MRHSession
@check_form_against_session('resourcename', use_query=True)
def options():
    assert request.args.get('outform') == 'xml' and request.args.get('client_version') == '2.0'
    session.update(hdlc_framing=['no', 'yes'][random.randint(0, 1)],
                   Z=session['resourcename'] + str(random.randint(1, 100)),
                   ipv4='yes', ipv6=['no', 'yes'][random.randint(0, 1)],
                   sess=request.cookies['MRHSession'] + str(random.randint(1, 100)))

    return (f'''
            <?xml version="1.0" encoding="UTF-8" ?><favorite>
            <object ID="ur_Host" CLASSID="CLSID:CC85ACDF-B277-486F-8C70-2C9B2ED2A4E7"
             CODEBASE="https://{app.config['HOST']}:{app.config['PORT']}/vdesk/terminal/urxshost.cab"
             WIDTH="320" HEIGHT="240">
                <ur_Z>{session['Z']}</ur_Z>
                <Session_ID>{session['sess']}</Session_ID>
                <ur_name>{session['resourcename']}</ur_name>
                <host0>{app.config['HOST']}</host0>
                <port0>{app.config['PORT']}</port0>
                <tunnel_host0>{app.config['HOST']}</tunnel_host0>
                <tunnel_port0>{app.config['PORT']}</tunnel_port0>
                <tunnel_protocol0>https</tunnel_protocol0>
                <idle_session_timeout>900</idle_session_timeout>
                <IPV4_0>{int(session['ipv4']=='yes')}</IPV4_0>
                <IPV6_0>{int(session['ipv6']=='yes')}</IPV6_0>
                <tunnel_dtls>{int(session['mock_dtls'] or 0)}</tunnel_dtls>
                <tunnel_port_dtls>{app.config['PORT']}</tunnel_port_dtls>

                <DNS0>1.1.1.1</DNS0>
                <DNS1>8.8.8.8</DNS1>
                <DNS6_0>2606:4700:4700::1111</DNS6_0>
                <DNS6_1>2001:4860:4860::8888</DNS6_1>
                <WINS0></WINS0>
                <DNSSuffix0>foo.com</DNSSuffix0>
                <SplitTunneling0>2</SplitTunneling0>
                <LAN0>10.11.10.10/32 10.11.1.0/24</LAN0>
                <LAN6_0>::/1 8000::/1</LAN6_0>

                <DNS_SPLIT0>*</DNS_SPLIT0>

                <hdlc_framing>{session['hdlc_framing']}</hdlc_framing>
            </object>
            </favorite>''',
            {'content-type': 'application/xml'})


# Respond to faux-CONNECT 'GET /myvpn' with 504 Gateway Timeout
# (what the real F5 server responds with when it doesn't like the parameters, intended
# to trigger "cookie rejected" error in OpenConnect)
@app.route('/myvpn')
# Can't use because OpenConnect doesn't send cookies here (see f5.c for why)
# @check_form_against_session('sess', 'hdlc_framing', 'ipv4', 'ipv6', 'Z', use_query=True)
def tunnel():
    try:
        base64.urlsafe_b64decode(request.args.get('hostname') or None)
    except (ValueError, TypeError):
        raise AssertionError('Hostname is not a base64 string')
    return make_response('', 504, {'X-VPN-Client-IP': '10.11.1.2', 'X-VPN-Client-IPv6': '2601::f00f:1234'})


# Respond to 'GET /remote/logout' by clearing session and MRHSession
@app.route('/vdesk/hangup.php3')
@require_MRHSession
def logout():
    assert request.args.get('hangup_error') == '1'
    session.clear()
    resp = make_response('successful logout')
    resp.set_cookie('MRHSession', '')
    return resp


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'],
        ssl_context=context, use_debugger=False)
