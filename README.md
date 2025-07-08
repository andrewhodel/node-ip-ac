## usage

In your socket/request/api code

```javascript
var ipac = require('node-ip-ac/node-ip-ac.js');

var ip_ac = ipac.init();

// set authorization status of an IP
// logout
ipac.modify_auth(ip_ac, 'logout', '127.0.0.1');
// invalid login credentials
ipac.modify_auth(ip_ac, 'invalid_login', '127.0.0.1');
// authorized (valid login credentials)
ipac.modify_auth(ip_ac, 'valid_login', '127.0.0.1');

// test authorization status of an IP
// this can be called every time there is a new IP connection
// if you want to block the IP connection in the application, it is not required if you are using iptables/ip6tables
var status = ipac.test_ip_allowed(ip_ac, '127.0.0.1');

// test if you should warn users from an IP
// this must be called if you want to warn connections from the application that more requests forces a block
var warn = ipac.test_ip_warn(ip_ac, '127.0.0.1');

// return details of a specific ip address
var ip_details = ipac.ip_details(ip_ac, '127.0.0.1');
```

## default options

Set these in the object {} passed as the first argument to `ipac.init();` if you want to change the defaults shown here.

```javascript
// default configurable options

// how many seconds between each iteration of the cleanup loop
o.cleanup_loop_seconds = 60;

// how many seconds to ban/block entities for
o.block_for_seconds = 60 * 60;

// maximum depth to classify IPv6 is
// 64 bits of a network prefix and 64 bits of an interface identifier
// 64 bits is 4 groups that are 16 bits each
o.block_ipv6_subnets_group_depth = 4;

// the number of IP bans within a subnet group required for a subnet group to be blocked
o.block_ipv6_subnets_breach = 40;
// number of lowest level subnets to block
// multiplied by itself for each step back
//
// example values: depth 4 and breach 40
// example ip: 2404:3c00:c140:b3c0:5d43:d92e:7b4f:5d52
//
// 2404* blocked at 40*40*40*40 ips
// 2404:3c00* blocked at 40*40*40 ips
// 2404:3c00:c140* blocked at 40*40 ips
// 2404:3c00:c140:b3c0* blocked at 40 ips

// warn after N unauthorized new connections
// requests from these IP addresses should
// display a denial of service warning to the IP
// in the user interface
o.warn_after_new_connections = 80;

// block after N unauthorized new connections
o.block_after_new_connections = 600;

// block after N invalid authorization attempts
// this prevents login guessing many times from the same IP address
o.block_after_unauthed_attempts = 30;

// notify after N absurd auth attempts
// failed authorization attempts after the IP has been authorized
o.notify_after_absurd_auth_attempts = 20;

// event notification callback
o.notify_cb = function(event, info, ips)
// event is a string of ips_blocked, ips_exceeded_absurd_auth_attempts or subnet_blocked
// info is a string about the event
// ips is a list of ip addresses related to the event

// never block, to disable the firewall
o.never_block = false;
```

## counts

You may want the total counts.

```javascript
// count of IP Addresses that have connected in the last ip_ac.block_for_seconds
ip_ac.total_count;

// count of IP Addresses that are blocked
ip_ac.blocked_count;

// count of IP Addresses that are warned
ip_ac.warn_count;

// count of subnets that are blocked
ip_ac.blocked_subnet_count;
```

## firewall support

In this module there exists support of `iptables` and `ip6tables` in Linux.

There is structure to support any OS and firewall that NodeJS supports.

There is also structure to support API calls to network or hosting providers, like AWS.

## license

Code is licensed MIT

Copyright 2022 Andrew Hodel
