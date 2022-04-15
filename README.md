## usage

In your socket/request/api code

```javascript
var ipac = require('node-ip-ac/node-ip-ac.js');

var ip_ac = ipac.init();

// set authorization status for an IP
// reset (use this on invalid authorization attempts)
ipac.modify_auth(ip_ac, undefined, '127.0.0.1');
// failed/unauthorized (use this on valid logouts)
ipac.modify_auth(ip_ac, false, '127.0.0.1');
// authorized (use this on valid logins)
ipac.modify_auth(ip_ac, true, '127.0.0.1');

// test authorization status for an IP
// this needs to be called every time there is a new IP connection
var status = ipac.test_ip_allowed(ip_ac, '127.0.0.1');

// test if you should warn users from an IP
var warn = ipac.test_ip_warn(ip_ac, '127.0.0.1');

// return details for a specific ip address
var ip_details = ipac.ip_details(ip_ac, '127.0.0.1');
```

## default options

Set these in the object {} passed as the first argument to `ipac.init();` if you want to change the defaults shown here.

```javascript
// default configurable options

// how many seconds between each iteration of the cleanup loop
o.cleanup_loop_seconds = 60;

// how many seconds to block an IP for
o.block_ip_for_seconds = 60 * 60 * 24;

// warn after N unauthorized new connections
// requests from these IP addresses should
// display a denial of service warning for the IP
// in the user interface
o.warn_after_new_connections = 80;

// block after N unauthorized new connections
o.block_after_new_connections = 600;

// block after N invalid authorization attempts
// this prevents login guessing many times from the same IP address
o.block_after_unauthed_attempts = 5;

// notify after N absurd auth attempts
// failed authorization attempts after the IP has been authorized
o.notify_after_absurd_auth_attempts = 20;

// send this object to send an email when an IP is blocked
// or the absurd_auth_attempts limit is breached
// {nodemailer_smtpTransport: nodemailer.createTransport({}), from: 'user@domain.tld', to: 'user@domain.tls', domain: 'domain or ip address'}
o.mail = null;
```

## counts

You may want the total counts.

```javascript
// count of IP Addresses that have connected in the last ip_ac.block_ip_for_seconds
ip_ac.total_count;

// count of IP Addresses that are blocked
ip_ac.blocked_count;

// count of IP Addresses that are warned
ip_ac.warn_count;
```

## firewall support

In this module there exists support for `iptables` on Linux.

There is structure for supporting any OS and firewall that NodeJS supports.

There is also structure for supporting API calls to network or hosting providers, like AWS.

## license

Code is licensed MIT

Copyright 2022 Andrew Hodel
