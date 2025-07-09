/*
Copyright 2022 Andrew Hodel
	andrewhodel@gmail.com

LICENSE MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// read this for how node modules work
// https://gist.github.com/andrewhodel/780f21c748cc570d96bd92e2655d9e39

var os = require('os');
var cp = require('child_process');
var net = require('net');
var process = require('process');

exports.init = function(opts={}) {

	// remove existing firewall rules created by node-ip-ac
	if (os.platform() == 'linux') {

		// flush the nodeipac chain
		cp.exec('iptables -F nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('iptables -X nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('iptables -N nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('iptables -D INPUT -j nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('iptables -A INPUT -j nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});

		// add nodeipac to ip6tables
		cp.exec('ip6tables -F nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('ip6tables -X nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('ip6tables -N nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('ip6tables -D INPUT -j nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('ip6tables -A INPUT -j nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});

	}

	var o = {};

	// default configurable options
	// explained in README.md
	o.cleanup_loop_seconds = 60;
	o.block_for_seconds = 60 * 60;
	o.block_ipv6_subnets_group_depth = 4;
	o.block_ipv6_subnets_breach = 40;
	o.warn_after_new_connections = 80;
	o.warn_after_unauthed_attempts = 5;
	o.block_after_new_connections = 600;
	o.block_after_unauthed_attempts = 30;
	o.notify_after_absurd_auth_attempts = 20;
	o.last_notify_absurd = (Date.now() / 1000) - o.block_for_seconds;
	o.notify_cb = null;
	o.purge = false;
	o.never_block = false;

	if (opts.notify_cb !== undefined) {
		if (typeof(opts.notify_cb) !== 'function') {
			console.log('node-ip-ac init(opts), opts.notify_cb must be a function or undefined.');
			process.exit(1);
		}
	}

	// update default configurable options passed
	// as the first argument to the init() function
	for (var n in opts) {
		if (typeof(o[n]) != 'undefined') {
			// update the default option
			// because it is a default option
			o[n] = opts[n];
		}
	}

	// set non configurable key/value pairs
	o.next_notify_blocked_ips = [];
	o.next_notify_absurd_ips = [];
	o.ips = {};
	o.ipv6_subnets = {};

	// counts updated in the cleanup loop
	o.total_count = 0;
	o.blocked_count = 0;
	o.warn_count = 0;
	o.blocked_subnet_count = 0;

	// start the cleanup routine
	o.last_cleanup = Date.now();
	var cleanup = setInterval(function() {

		// print everything about this node-ip-ac object
		//console.log(o);

		// consider the time since the last interval as that is when the last_cleanup value was set
		var seconds_since_last_cleanup = (Date.now() - o.last_cleanup) / 1000;

		var expire_older_than = o.block_for_seconds - seconds_since_last_cleanup;

		var ctotal = 0;
		var cblocked = 0;
		var cwarn = 0;
		var cblocked_subnet = 0;

		if (o.purge === true) {
			// clear ips
			o.ips = {};
		}

		// clear expired ips
		for (var key in o.ips) {

			// the age of this ip in seconds
			var age_of_ip = (Date.now() - o.ips[key].original_access)/1000;

			// print each IP and it's age
			//console.log("expire_older_than=" + expire_older_than, "age_of_ip=" + age_of_ip);
			//console.log(key, o.ips[key]);

			if (age_of_ip > expire_older_than) {

				if (o.ips[key].blocked === true) {
					// unblock the IP at the OS level
					modify_ip_block_os(false, key);
				}

				delete o.ips[key];

			} else {

				// this ip was not deleted, count it
				ctotal++;
				if (o.ips[key].blocked) {
					cblocked++;
				}
				if (o.ips[key].warn) {
					cwarn++;
				}

			}

		}

		// update the ipac object
		o.total_count = ctotal;
		o.blocked_count = cblocked;
		o.warn_count = cwarn;

		if (o.purge === true) {
			// clear subnets
			o.ipv6_subnets = {};
		}

		// handle subnet group blocks with
		for (s in o.ipv6_subnets) {

			if (o.ipv6_subnets[s].blockedMs !== undefined) {
				// this subnet group is blocked
				// test if the block should expire

				var age_of_block = (Date.now() - o.ipv6_subnets[s].blockedMs)/1000;

				if (age_of_block > expire_older_than) {
					// unblock this subnet group
					ipv6_modify_subnet_block_os(false, s);
					delete o.ipv6_subnets[s];
				} else {
					// increment the blocked subnet count for this cleanup() loop
					cblocked_subnet++;
				}

				continue;

			}

			// calculate the number of banned ips required for this prefix to be blocked
			// block_ipv6_subnets_group_depth = 4
			// block_ipv6_subnets_breach = 40
			// pow(40, 4 - num_of_groups + 1)
			// ffff = pow(40, 4)
			// ffff:ffff = pow(40, 3)
			// ffff:ffff:ffff = pow(40, 2)
			// ffff:ffff:ffff:ffff = pow(40, 1)
			var ip_count_to_breach_subnet = Math.pow(o.block_ipv6_subnets_breach, o.block_ipv6_subnets_group_depth - s.split(':').length + 1)

			if (o.ipv6_subnets[s].ip_bans >= ip_count_to_breach_subnet) {

				// this subnet group has breached the limit
				// block it
				ipv6_modify_subnet_block_os(true, s);
				o.ipv6_subnets[s].blockedMs = Date.now();

				// increment the blocked subnet count for this cleanup() loop
				cblocked_subnet++;

				if (o.notify_cb !== null) {

					// send notification
					o.notify_cb('subnet_blocked', 'IPv6 subnet blocked.', [s]);

				}

			}

		}

		// update the ipac object
		o.blocked_subnet_count = cblocked_subnet;

		if (o.purge === true) {
			// reset o.purge
			o.purge = false;
		}

		if (o.notify_cb !== null) {

			if (o.next_notify_blocked_ips.length > 0) {

				// send notification
				o.notify_cb('ips_blocked', 'IP addresses blocked.', o.next_notify_blocked_ips);

				// reset it
				o.next_notify_blocked_ips = [];

			}

			if (o.next_notify_absurd_ips.length > 0 && Date.now() / 1000 < o.last_notify_absurd - o.block_for_seconds) {

				// send notification
				o.notify_cb('ips_exceeded_absurd_auth_attempts', 'Too many failed login attempts from IP Addresses that are already authenticated.', o.next_notify_absurd_ips);

				// reset it
				o.next_notify_absurd_ips = [];

				// set last notify absurd timestamp
				o.last_notify_absurd = Date.now() / 1000;

			}

		}

		// update the last cleanup
		o.last_cleanup = Date.now();

	}, o.cleanup_loop_seconds * 1000);

	// return the object
	return o;

}

// this is a default entry
// for new (first time connections or logins)
var default_entry = function() {

	return {authed: false, warn: false, blocked: false, original_access: Date.now(), last_access: Date.now(), last_auth: Date.now(), unauthed_new_connections: 0, unauthed_attempts: 0, absurd_auth_attempts: 0};

}

var ipv6_get_ranked_groups = function(o, addr_string) {

	// get each ranked group after o.block_ipv6_subnets_group_depth
	// if addr_string is aaaa:bbbb:cccc:dddd:eeee:ffff:gggg:hhhh
	// and o.block_ipv6_subnets_group_depth is 4
	// return
	// aaaa:bbbb:cccc:dddd
	// aaaa:bbbb:cccc:dddd:eeee
	// aaaa:bbbb:cccc:dddd:eeee:ffff
	// aaaa:bbbb:cccc:dddd:eeee:ffff:gggg
	// to match by these prefixes as ipv6 subnets quickly

	var groups = addr_string.split(':');

	// make full length IPv6 address

	// an address with repeating 0000 groups can replace the series of repeating groups with :: once
	// Original: 2041:0000:140F:0000:0000:0000:875B:131B (8)
	// Short: 2041:0000:140F::875B:131B (6)
	var g = 0;
	while (g < groups.length) {
		if (groups[g].length === 0) {
			// set the empty group to 0000
			groups[g] = '0000';
			// get the number of new zero groups
			var number_of_new_zero_groups = 8-groups.length;
			// add the new groups
			var p = 0;
			while (p < number_of_new_zero_groups) {
				groups.splice(g, 0, '0000');
				p++;
			}
			break
		}
		g++;
	}

	// one group of 4 zeroes can be replaced with only a 0
	// Short: 2041:0000:140F::875B:131B
	// Shorter: 2041:0:140F::875B:131B
	var g = 0;
	while (g < groups.length) {
		if (groups[g] === '0') {
			groups[g] = '0000';
		}
		g++;
	}

	// leading zeroes in each group can also be removed
	// Original: 2001:0001:0002:0003:0004:0005:0006:0007
	// Short: 2001:1:2:3:4:5:6:7
	var g = 0;
	while (g < groups.length) {
		if (groups[g].length < 4) {
			var number_of_prefix_zeroes = 4-groups[g].length;
			var prefix = '';
			var p = 0;
			while (p < number_of_prefix_zeroes) {
				prefix += '0';
				p++;
			}
			groups[g] = prefix + groups[g];
		}
		g++;
	}

	var ranked_groups = [];

	var g = 0;
	while (g < 8-o.block_ipv6_subnets_group_depth) {

		var prefix = ""
		var a = 0;
		while (a < 8-o.block_ipv6_subnets_group_depth+g) {
			prefix += groups[a] + ":"
			a++;
		}

		// remove the last :
		prefix = prefix.slice(0, prefix.length-1);

		// add to ranked_groups
		ranked_groups.push(prefix);

		g++;

	}

	return ranked_groups;

}

var ipv6_modify_subnet_block_os = function(block, subnet_string) {
	// block or unblock the subnet at the OS level

	// make 'ffff' or 'ffff:ffff' be a full ipv6 subnet specificed with zeroes instead of CIDR
	// ffff:0000:0000:0000:0000:0000:0000:0000
	// ffff:ffff:0000:0000:0000:0000:0000:0000
	var groups = subnet_string.split(':');

	var total = 8;
	var c = 0;
	var iptables_subnet_string = '';
	while (c < total) {

		if (typeof(groups[c]) == 'undefined') {
			iptables_subnet_string += '0000:';
		} else {
			iptables_subnet_string += groups[c] + ':';
		}

		c++;

	}

	// remove the last :
	iptables_subnet_string = iptables_subnet_string.substring(0, iptables_subnet_string.length-1);

	if (block) {

		// block the subnet
		if (os.platform() == 'linux') {
			cp.exec('ip6tables -I nodeipac -s "' + iptables_subnet_string + '" -j DROP', {}, function(error, stdout, stderr) {
				if (stderr !== '') {console.log(stderr);}
			});
		}

	} else {

		// unblock the subnet
		if (os.platform() == 'linux') {
			cp.exec('ip6tables -D nodeipac -s "' + iptables_subnet_string + '" -j DROP', {}, function(error, stdout, stderr) {
				if (stderr !== '') {console.log(stderr);}
			});
		}

	}

}

var modify_ip_block_os = function(block, addr_string) {
	// block or unblock the IP at the OS level

	if (block) {

		// block the IP address
		if (os.platform() == 'linux') {
			if (addr_string.indexOf(':') > -1) {
				cp.exec('ip6tables -I nodeipac -s "' + addr_string + '" -j DROP', {}, function(error, stdout, stderr) {
					if (stderr !== '') {console.log(stderr);}
				});
			} else {
				cp.exec('iptables -I nodeipac -s "' + addr_string + '" -j DROP', {}, function(error, stdout, stderr) {
					if (stderr !== '') {console.log(stderr);}
				});
			}
		}

	} else {

		// unblock the IP address
		if (os.platform() == 'linux') {
			if (addr_string.indexOf(':') > -1) {
				cp.exec('ip6tables -D nodeipac -s "' + addr_string + '" -j DROP', {}, function(error, stdout, stderr) {
					if (stderr !== '') {console.log(stderr);}
				});
			} else {
				cp.exec('iptables -D nodeipac -s "' + addr_string + '" -j DROP', {}, function(error, stdout, stderr) {
					if (stderr !== '') {console.log(stderr);}
				});
			}
		}

	}

}

var clean_ip_string = function(a) {

	if (a.indexOf('::ffff:') === 0) {
		// remove ::ffff: and return string
		// node makes ipv4 addresses this way
		return a.slice(7);
	} else {
		return a;
	}

}

exports.ip_details = function(o, addr_string) {

	if (addr_string === undefined) {
		// nodejs has a bug in the net module that allows a request object to have an undefined remoteAddress field
		// but they have blocked @andrewhodel from https://github.com/nodejs/node
		// to prevent me from helping
		return;
	}

	addr_string = clean_ip_string(addr_string);

	var i = default_entry();

	if (typeof(o.ips[addr_string]) == 'object') {
		i = o.ips[addr_string];
	}

	return i;

}

exports.test_ip_warn = function(o, addr_string) {

	if (addr_string === undefined) {
		// nodejs has a bug in the net module that allows a request object to have an undefined remoteAddress field
		// but they have blocked @andrewhodel from https://github.com/nodejs/node
		// to prevent me from helping
		return true;
	}

	addr_string = clean_ip_string(addr_string);

	var warn = false;

	if (typeof(o.ips[addr_string]) == 'object') {
		warn = o.ips[addr_string].warn;
	}

	return warn;

}

exports.test_ip_allowed = function(o, addr_string) {

	if (addr_string === undefined) {
		// nodejs has a bug in the net module that allows a request object to have an undefined remoteAddress field
		// but they have blocked @andrewhodel from https://github.com/nodejs/node
		// to prevent me from helping
		return false;
	}

	if (o.never_block === true) {
		// firewall is disabled
		return true;
	}

	addr_string = clean_ip_string(addr_string);

	// this must be called every time there is a new IP connection, it accounts for the number of connections

	// returns false if the IP address has made too many unauthenticated requests and is not allowed
	// returns true is the connection is allowed

	if (o.ips[addr_string] !== undefined) {

		// a matching ip address has been found
		var entry = o.ips[addr_string];

		if (entry.authed === false) {
			// increment the number of unauthed connections for this IP address
			entry.unauthed_new_connections++;
		}

		// warn this IP address if required
		if (entry.unauthed_new_connections >= o.warn_after_new_connections && entry.warn === false) {
			// made too many unauthed connections
			entry.warn = true;
		} else if (entry.unauthed_attempts >= o.warn_after_unauthed_attempts && entry.warn === false) {
			// made too many invalid authorization attempts
			entry.warn = true;
		}

		// block this IP address if it has made too many unauthed connections
		// or invalid authorization attempts
		if ((entry.unauthed_new_connections >= o.block_after_new_connections || entry.unauthed_attempts >= o.block_after_unauthed_attempts) && entry.blocked === false) {

			// set the IP address to blocked
			entry.blocked = true;

			// update the entry in memory
			o.ips[addr_string] = entry;

			// block this IP at the OS level
			modify_ip_block_os(true, addr_string);

			if (o.notify_cb !== null) {

				// add to next notify
				o.next_notify_blocked_ips.push(addr_string);

			}

			// get ip address as bytes
			if (net.isIPv4(addr_string)) {

			} else if (net.isIPv6(addr_string)) {

				var ranked_groups = ipv6_get_ranked_groups(o, addr_string);

				// add the ranked_groups to the subnet classifications
				var a = 0;
				while (a < ranked_groups.length) {

					if (o.ipv6_subnets[ranked_groups[a]] !== undefined) {
						// add one to the counter for this subnet group
						o.ipv6_subnets[ranked_groups[a]].ip_bans++;
					} else {
						// it's new
						o.ipv6_subnets[ranked_groups[a]] = {ip_bans: 1};
					}

					a++;

				}

			}

		} else if (entry.absurd_auth_attempts >= o.notify_after_absurd_auth_attempts) {

			// too many auth attempts while the IP has an authenticated session

			if (o.notify_cb !== null) {

				if (o.next_notify_absurd_ips.includes(addr_string) === false) {
					// add unique ip address to next notify absurd list
					o.next_notify_absurd_ips.push(addr_string);
				}

			}

		}

		// update the entry in memory
		o.ips[addr_string] = entry;

	} else {

		// this IP address is new
		o.ips[addr_string] = default_entry();

	}

	// set the last_access attempt time
	o.ips[addr_string].last_access = Date.now();

	if (o.ips[addr_string].blocked) {
		return false;
	} else {
		return true;
	}

}

exports.purge = function(o) {

	// clear all ips
	o.purge = true;

	if (os.platform() == 'linux') {
		// flush the nodeipac chain
		cp.exec('iptables -F nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
		cp.exec('ip6tables -F nodeipac', {}, function(error, stdout, stderr) {
			if (stderr !== '') {console.log(stderr);}
		});
	}

	var o = {};

}

exports.modify_auth = function(o, authed, addr_string) {

	if (addr_string === undefined) {
		// nodejs has a bug in the net module that allows a request object to have an undefined remoteAddress field
		// but they have blocked @andrewhodel from https://github.com/nodejs/node
		// to prevent me from helping
		return;
	}

	if (o.never_block === true) {
		// firewall is disabled
		return true;
	}

	addr_string = clean_ip_string(addr_string);

	if (o.purge === true) {
		// do not allow modification while purging
		return;
	}

	// modify the authorization status
	// via the authed argument for the IP address in addr_string

	if (o.ips[addr_string] === undefined) {
		// this IP address is new to the access control system
		o.ips[addr_string] = default_entry();
	}

	// get the IP address
	var entry = o.ips[addr_string];

	// get a current timestamp
	var now = Date.now();

	if (entry.authed === true && authed === "invalid_login") {
		// an IP address is authorized but invalid authorizations are happening from the IP
		// perhaps someone else at the location is abusing the authed IP address and trying to guess
		// logins or logout the valid user
		// as node-ip-ac will not deauth an IP without specific instruction to do so
		//
		// modify_auth() should be passed undefined as the authed argument when there is a valid logout
		//
		// increment absurd_auth_attempts
		// to notify the admin and allow the valid user to continue normally

		entry.absurd_auth_attempts++;

	} else if (authed === "valid_login") {

		// authorized
		entry.blocked = false;
		entry.warn = false;
		entry.authed = true;

	} else if (authed === "invalid_login") {

		// not authorized, not expired

		// increment the invalid authorization attempts counter for the IP address
		entry.unauthed_attempts++;

	} else if (authed === "logout") {

		// this is a valid logout attempt that was authenticated
		entry.authed = false;

	} else {

		console.log("ipac.ModifyAuth called with invalid authed string.  Only logout, invalid_login and valid_login are allowed.");
		process.exit(1)

	}

	// set the last_auth attempt time
	entry.last_auth = Date.now();

	// update the entry in memory
	o.ips[addr_string] = entry;

}
