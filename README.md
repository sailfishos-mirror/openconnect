# OpenConnect

OpenConnect is an SSL VPN client initially created to support [Cisco's AnyConnect SSL VPN](http://www.cisco.com/go/asm).
It has since been ported to support the Juniper SSL VPN (which is now known as [Pulse Connect Secure](https://www.pulsesecure.net/products/connect-secure/)),
and the [Palo Alto Networks GlobalProtect SSL VPN](https://www.paloaltonetworks.com/features/vpn).

An openconnect VPN server (ocserv), which implements an improved version of the Cisco AnyConnect protocol, has also been written.
You can find it on Gitlab at [https://gitlab.com/openconnect/ocserv](https://gitlab.com/openconnect/ocserv).

If you're looking for the standard `vpnc-script`, which is invoked by OpenConnect for routing and DNS setup,
you can find it on Gitlab at [https://gitlab.com/openconnect/vpnc-script](https://gitlab.com/openconnect/vpnc-script).

## Licence

OpenConnect is released under the [GNU Lesser Public License, version 2.1](https://openconnect.gitlab.io/openconnect/licence.html).

## Documentation

Documentation for OpenConnect is built from the `www/` directory in this repository, and lives in rendered form at [https://openconnect.gitlab.io/openconnect](https://openconnect.gitlab.io/openconnect).

Commonly-sought documentation:

* [Manual](https://openconnect.gitlab.io/openconnect/manual.html)
* [Getting Started / Building](https://openconnect.gitlab.io/openconnect/building.html) (includes build instructions)
* [Contribute](https://openconnect.gitlab.io/openconnect/contribute.html)
* [Mailing list / Help](https://openconnect.gitlab.io/openconnect/mail.html)
* [GUIs / Front Ends](https://openconnect.gitlab.io/openconnect/gui.html)
* [VPN Server / ocserv](http://ocserv.gitlab.io/www)
