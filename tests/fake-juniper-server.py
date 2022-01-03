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
# This program emulates the authentication-phase behavior of a Juniper
# server enough to test OpenConnect's authentication behavior against it.
########################################

import sys
import ssl
import base64
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


def require_DSID(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not request.cookies.get('DSID'):
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

# Respond to initial 'GET /' with a redirect to '/dana-na/auth/url_default/welcome.cgi'
# [Save in the session for use later:
#   list of realms,
#   session confirmation requirement,
#   token/2FA form name (can be frmLogin, for 2-password-in-one-form option)]
@app.route('/')
def root():
    # We don't support the Junos/Pulse protocol (which starts with this request)
    if request.headers.get('Upgrade') == 'IF-T/TLS 1.0' and request.headers.get('Content-Type') == 'EAP':
        return abort(501)

    realms = request.args.get('realms')
    roles = request.args.get('roles')
    confirm = bool(request.args.get('confirm'))
    token_form = request.args.get('token_form')
    session.update(step='initial-GET', realms=realms and realms.split(','),
                   roles=roles and roles.split(','),
                   confirm=confirm, token_form=token_form)
    # print(session)
    return redirect(url_for('frmLogin'))


# frmLogin
@app.route('/dana-na/auth/url_default/welcome.cgi')
def frmLogin():
    session.update(step='GET-frmLogin')
    realms = session.get('realms')
    token_form = session.get('token_form')
    sel = token = ''
    if realms:
        sel = '<select name="realm">%s</select>' % ''.join(
            '<option value="%d">%s</option>' % nv for nv in enumerate(realms))
    if token_form == 'frmLogin':
        token = '<input type="password" name="token_as_second_password"/>'

    return '''
<html><body><form name="frmLogin" method="post" action="%s">
<input type="text" name="username"/>
<input type="password" name="password"/>
%s<input type="submit" value="Sign In" name="btnSubmit"/>
%s</form></body></html>''' % (url_for('frmLogin_post'), token, sel)


# frmLogin POST-response
# This either yields a successful DSID cookie, or redirects to a confirmation page,
# depending on session['confirm']
@app.route('/dana-na/auth/url_default/login.cgi', methods=['POST'])
def frmLogin_post():
    realms = session.get('realms')
    confirm = session.get('confirm')
    token_form = session.get('token_form')
    roles = session.get('roles')
    if realms:
        assert 0 <= int(request.form.get('realm', -1)) < len(realms)
    session.update(step='POST-login', username=request.form.get('username'),
                   password=request.form.get('password'),
                   realm=request.form.get('realm'))
    # print(session)

    need_confirm = need_token = False
    got_confirm = got_token = None
    if confirm:
        need_confirm = request.form.get('btnContinue') is None
        got_confirm = not need_confirm
    if token_form:
        need_token = request.form.get('btnAction') is None and request.form.get('totpactionEnter') is None and request.form.get('token_as_second_password') is None
        got_token = not need_token
    session.update(got_token=got_token, got_confirm=got_confirm)

    if need_token and not got_confirm:
        return redirect(url_for('frm2FA'))
    elif need_confirm:
        return redirect(url_for('frmConfirmation'))
    elif roles:
        return redirect(url_for('frmSelectRoles'))
    else:
        resp = redirect(url_for('webtop'))
        resp.set_cookie('DSID', cookify(dict(session)))
        return resp


# frmSelectRoles
# This is some insane post-login realm-ish select-y thing
@app.route('/dana-na/auth/url_default/select_role.cgi')
def frmSelectRoles():
    session.update(step='GET-frmSelectRoles')
    roles = session.get('roles')
    dest = url_for('frmSelectRoles_AFTER')
    roles = '\n'.join('<tr><td><a href="%s?role=%d">%s</a></td></tr>' % (dest, nn, role) for (nn, role) in enumerate(roles))
    return '''
<html><body><form name="frmSelectRoles">
<table id="TABLE_SelectRole_1">
<tr><td>You have access to the following roles:</td></tr>
%s
<tr><td>Each role allows you to access certain resources.  Click on the role you want to join for this session.  Please contact your administrator if you need help choosing a role.</td></tr>
</table>
</form></body></form>''' % roles


# Note the URL is shared with the frmLogin POST URL... so weird
@app.route('/dana-na/auth/url_default/login.cgi', methods=['GET'])
def frmSelectRoles_AFTER():
    roles = session.get('roles')
    assert roles
    assert 0 <= int(request.args.get('role', -1)) < len(roles)
    session.update(step='AFTER-frmSelectRoles', role=request.form.get('role'))
    resp = redirect(url_for('webtop'))
    resp.set_cookie('DSID', cookify(dict(session)))
    return resp


# 2FA forms (frmDefender, frmNextToken, or frmTotpToken)
# This redirects back to frmLogin_POST
@app.route('/dana-na/auth/url_default/token.cgi')
def frm2FA():
    token_form = session.get('token_form')
    submit_button = ('totpactionEnter' if token_form == 'frmTotpToken' else 'btnAction')
    session.update(step='GET-frmConfirm')
    return '''
<html><body><form name="%s" method="post" action="%s">
Enter your 2FA token code.
<input type="hidden" name="username" value="%s"/>
<input type="password" name="token_code"/>
<input type="hidden" name="realm" value="%s"/>
<input type="submit" name="%s" value="Sign In"/>
</form></body></html>''' % (
    token_form,
    url_for('frmLogin_post'), session.get('username'), session.get('realm'),
    submit_button
)


# frmConfirmation
# This redirects back to frmLogin_POST
@app.route('/dana-na/auth/url_default/confirm.cgi')
def frmConfirmation():
    session.update(step='GET-frmConfirm')
    return '''
<html><body><form name="frmConfirmation" method="post" action="%s">
Confirm your login for whatever reason.
<input type="hidden" name="username" value="%s"/>
<input type="hidden" name="password" value="%s"/>
<input type="hidden" name="realm" value="%s"/>
<input type="submit" name="btnContinue" value="Confirm Login"/>
</form></body></html>''' % (
    url_for('frmLogin_post'), session.get('username'), session.get('password'),
    session.get('realm'))


# stand-in for the "webtop" UI if logged in through a browser
@app.route('/dana/home/starter0.cgi')
def webtop():
    session.update(step='POST-login-webtop')
    # print(session)

    return 'some junk HTML webtop'


# respond to faux-CONNECT 'POST /dana/na?prot=1&svc=4' with 401
@app.route('/dana/js', methods=['POST'])
@require_DSID
def tunnel_post():
    session.update(step='POST-tunnel')
    assert request.args.get('prot') == '1' and request.args.get('svc') == '4'
    assert request.headers['Connection'].lower().strip() == 'close'
    abort(401)


# Respond to 'GET /dana-na/auth/logout.cgi' by clearing session and DSID
@app.route('/dana-na/auth/logout.cgi')
@require_DSID
def logout():
    session.clear()
    resp = make_response('successful logout')
    resp.set_cookie('DSID', '')
    return resp


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'],
        ssl_context=context, use_debugger=False)
