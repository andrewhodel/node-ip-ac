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

exports.init = function(opts={}) {

	// remove existing firewall rules created by node-ip-ac
	if (os.platform() == 'linux') {
		// first flush the nodeipac chain (error is not relevant)
		cp.exec('sudo iptables -F nodeipac', {}, function(error, stdout, stderr) {

			// then delete the chain (error is not relevant)
			cp.exec('sudo iptables -X nodeipac', {}, function(error, stdout, stderr) {

				// then add the chain
				cp.exec('sudo iptables -N nodeipac', {}, function(error, stdout, stderr) {
				});
			});
		});
	}

	var o = {};

	// default configurable options
	// explained in README.md
	o.cleanup_loop_seconds = 60;
	o.block_for_seconds = 60 * 60 * 24;
	o.block_ipv6_subnets_group_depth = 4;
	o.block_ipv6_subnets_breach = 40;
	o.warn_after_new_connections = 80;
	o.warn_after_unauthed_attempts = 5;
	o.block_after_new_connections = 600;
	o.block_after_unauthed_attempts = 30;
	o.notify_after_absurd_auth_attempts = 20;
	o.mail = null;
	o.purge = false;
	o.never_block = false;

	if (typeof(opts.mail) == 'object') {
		// make sure the object is valid
		if (typeof(opts.mail.nodemailer_smtpTransport) == 'undefined' || typeof(opts.mail.from) == 'undefined' || typeof(opts.mail.to) == 'undefined' || typeof(opts.mail.domain) == 'undefined') {
			console.log('node-ip-ac init() function first argument\'s mail object requires 4 fields:\n\tnodemailer_smtpTransport: nodemailer.createTransport({})\n\tfrom: "user@domain.tld"\n\tto: "user@domain.tld"\n\tdomain: "domain or ip address"');
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
	o.next_email_blocked_ips = [];
	o.next_email_absurd_ips = [];
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

			// the age of this ip's last access in seconds
			var age_of_ip = (Date.now() - o.ips[key].last_access)/1000;

			// print each IP and it's age
			//console.log("expire_older_than=" + expire_older_than, "age_of_ip=" + age_of_ip);
			//console.log(key, o.ips[key]);

			if (age_of_ip > expire_older_than) {

				// unblock the IP at the OS level
				modify_ip_block_os(false, key);

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

				if (o.mail !== null) {

					// send notification
					o.mail.nodemailer_smtpTransport.sendMail({
						from: "ISPApp <" + o.mail.from + ">", // sender address
						to: o.mail.to,
						subject: 'node-ip-ac blocked subnet group ' + s + ' on ' + o.mail.domain,
						html: '<p>This subnet group was blocked.</p><br /><p>' + s + '</p>'
					}, function(error, response) {
						if (error) {
							log_with_date('error sending email', error);
						} else {
							//log_with_date("Message sent: " + response.message);
						}
					});

				}

			}

		}

		// update the ipac object
		o.blocked_subnet_count = cblocked_subnet;

		if (o.purge === true) {
			// reset o.purge
			o.purge = false;
		}

		if (o.mail !== null) {

			// send notifications via email

			if (o.next_email_blocked_ips.length > 0) {

				// generate the string of IPs for the email body
				var s = '';
				var n = 0;
				while (n < o.next_email_blocked_ips.length) {
					s += o.next_email_blocked_ips[n] + ', ';
					n++;
				}
				s = s.substring(0, s.length-2);

				// send notification
				o.mail.nodemailer_smtpTransport.sendMail({
					from: "ISPApp <" + o.mail.from + ">", // sender address
					to: o.mail.to,
					subject: 'node-ip-ac blocked ' + o.next_email_blocked_ips.length + ' IP(s) on ' + o.mail.domain,
					html: '<p>These IP addresses were blocked.</p><br /><p>' + s + '</p>'
				}, function(error, response) {
					if (error) {
						log_with_date('error sending email', error);
					} else {
						//log_with_date("Message sent: " + response.message);
					}
				});

				// reset it
				o.next_email_blocked_ips = [];

			}

			if (o.next_email_absurd_ips.length > 0) {

				// generate the string of IPs for the email body
				var s = '';
				var n = 0;
				while (n < o.next_email_absurd_ips.length) {
					s += o.next_email_absurd_ips[n] + ', ';
					n++;
				}
				s = s.substring(0, s.length-2);

				// send notification
				o.mail.nodemailer_smtpTransport.sendMail({
					from: "ISPApp <" + o.mail.from + ">", // sender address
					to: o.mail.to,
					subject: 'node-ip-ac is reporting ' + o.next_email_absurd_ips.length + ' absurd authorization attempt(s) on ' + o.mail.domain,
					html: '<p>These IP addresses tried to brute force or guess a login while there was an authenticated connection from the same IP.  It may be a malicious user or a malicious NAT (RFC1918) network.</p><p><strong>The IP is not blocked</strong> because there is an authenticated IP connection from the same IP address.</p><br /><p>' + s + '</p>'
				}, function(error, response) {
					if (error) {
						log_with_date('error sending email', error);
					} else {
						//log_with_date("Message sent: " + response.message);
					}
				});

				// reset it
				o.next_email_absurd_ips = [];

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

	return {authed: false, warn: false, blocked: false, last_access: Date.now(), last_auth: Date.now(), unauthed_new_connections: 0, unauthed_attempts: 0, absurd_auth_attempts: 0};

}

var ipv6_get_ranked_groups = function(o, addr_string) {

	// get each ranked group after o.BlockIpv6SubnetsGroupDepth
	// if addr is ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
	// and o.BlockIpv6SubnetsGroupDepth is 4
	// return
	// ffff:ffff:ffff:ffff
	// ffff:ffff:ffff:ffff:ffff
	// ffff:ffff:ffff:ffff:ffff:ffff
	// ffff:ffff:ffff:ffff:ffff:ffff:ffff
	// to match by these prefixes as ipv6 subnets quickly

	// split groups
	var groups = addr_string.split(':');

	// create ranked groups
	var ranked_groups = [];

	var at = 0;
	var g = 0;

	while (g < o.block_ipv6_subnets_group_depth) {

		var prefix = '';

		var l = 0;
		while (l < o.block_ipv6_subnets_group_depth) {
			// add first to `o.BlockIpv6SubnetsGroupDepth` strings of `groups`
			prefix += groups[l] + ':';
			l++;
		}

		// remove the last :
		prefix = prefix.slice(0, prefix.length-1);

		l = 0;
		while (l < at) {
			// then `o.BlockIpv6SubnetsGroupDepth` to `o.BlockIpv6SubnetsGroupDepth+at` strings of `groups`
			prefix += groups[l + o.block_ipv6_subnets_group_depth] + ':';
			l++;
		}

		// remove the last :
		prefix = prefix.slice(0, prefix.length-1);

		// add to ranked_groups
		ranked_groups.push(prefix);

		// increment at
		at++;

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
			cp.exec('sudo iptables -I nodeipac -s "' + iptables_subnet_string + '" -j DROP', {}, function(error, stdout, stderr) {
			});
		}

	} else {

		// unblock the subnet
		if (os.platform() == 'linux') {
			cp.exec('sudo iptables -D nodeipac -s "' + iptables_subnet_string + '" -j DROP', {}, function(error, stdout, stderr) {
			});
		}

	}

}

var modify_ip_block_os = function(block, addr_string) {
	// block or unblock the IP at the OS level

	if (block) {

		// block the IP address
		if (os.platform() == 'linux') {
			cp.exec('sudo iptables -I nodeipac -s "' + addr_string + '" -j DROP', {}, function(error, stdout, stderr) {
			});
		}

	} else {

		// unblock the IP address
		if (os.platform() == 'linux') {
			cp.exec('sudo iptables -D nodeipac -s "' + addr_string + '" -j DROP', {}, function(error, stdout, stderr) {
			});
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

	// always ran at the start of any request
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

			if (o.mail !== null) {

				// add to next email
				o.next_email_blocked_ips.push(addr_string);

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

		} else if (entry.absurd_auth_attempts === o.notify_after_absurd_auth_attempts) {

			// too many auth attempts while the IP has an authenticated session, send an email

			if (o.mail !== null) {

				// add to next email
				o.next_email_absurd_ips.push(addr_string);

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
		cp.exec('sudo iptables -F nodeipac', {}, function(error, stdout, stderr) {
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

	if (entry.authed === true && authed === false) {
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

	} else if ((now - entry.last_access)/1000 > o.block_for_seconds || authed === true) {

		// authorized or expired
		// reset the object keys

		// removes the requirement for waiting until the next cleanup iteration

		entry.blocked = false;
		entry.warn = false;

		if (authed) {
			// authorized
			entry.authed = true;
		} else {
			// expired
			// only reset these counters when modify_auth is resetting an expired IP address
			entry.unauthed_attempts = 0;
			entry.unauthed_new_connections = 0;
			entry.absurd_auth_attempts = 0;
		}

	} else if (authed === false) {

		// not authorized, not expired

		// increment the invalid authorization attempts counter for the IP address
		entry.unauthed_attempts++;

	} else if (authed === undefined) {

		// this is a valid logout attempt that was authenticated
		entry.authed = false;

	}

	// set the last_auth attempt time
	entry.last_auth = Date.now();

	// update the entry in memory
	o.ips[addr_string] = entry;

}
