## usage

In your socket/request/api code

```
var ipac = require('node-ip-ac/node-ip-ac.js');

var ip_ac = ipac.init();

// set authorization status for an IP
// to allowed
ipac.modify_auth(ip_ac, true, '127.0.0.1');

// test authorization status for an IP
// this needs to be called every time there is a new IP connection
var status = ipac.test_ip_allowed(ip_ac, '127.0.0.1');

// test if you should warn users from an IP
var ip_ac_test = ip_ac.allowed_ips['127.0.0.1'];
var warn = false;
if (typeof(ip_ac_test) == 'object') {
	warn = true;
}
```

## default options

Set these in the object {} passed as the first argument to `ipac.init();`

```
// default configurable options

// how many seconds between each iteration of the cleanup loop
o.cleanup_loop_seconds = 60;

// how many seconds to block an IP for
o.block_ip_for_seconds = 60 * 60 * 24;

// warn after N attempts
// requests from these IP addresses should
// display a denial of service warning for the IP
// in the user interface
o.warn_after_attempts = 100;

// block after N attempts
o.block_after_attempts = 1500;

// send this object to send an email when an IP is blocked
// {nodemailer_smtpTransport: nodemailer.createTransport({}), from: 'user@domain.tld', to: 'user@domain.tls', domain: 'domain or ip address'}
o.mail = null;
```

## firewall support

In this module there exists support for `iptables` on Linux.

There is structure for supporting any OS and firewall that NodeJS supports.

There is also structure for supporting API calls to network or hosting providers, like AWS.

## license

Code is licensed MIT

Copyright 2022 Andrew Hodel
