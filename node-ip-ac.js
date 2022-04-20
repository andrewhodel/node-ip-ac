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

// this is a default entry
// for new (first time connections or logins)
var default_entry = function() {

	return {authed: false, warn: false, blocked: false, last_access: Date.now(), last_auth: Date.now(), unauthed_new_connections: 0, unauthed_attempts: 0, absurd_auth_attempts: 0};

}

var get_ranked_groups_ipv6 = function(o, addr_string) {

	// split groups
	var groups = addr_string.split(':');

	var all = [];
	for (var g in groups) {
		all.push(groups[g]);
	}

	//console.log('all', all);

	// create ranked groups
	var ranked_groups = [];

	var at = 0;

	var g = 0;
	while (g < all.length) {
		ranked_groups.push(all[at]);

		if (g === o.block_ipv6_subnets_group_depth-1) {
			// what size to classify groups by
			break;
		}

		g++;

	}

	//console.log('ranked_groups', ranked_groups);

	var a = 0;
	while (a < all.length) {

		if (a === o.block_ipv6_subnets_group_depth) {
			// what size to classify groups by
			break;
		}

		at++;
		var gl = 0;
		while (gl < all.length) {

			if (gl === o.block_ipv6_subnets_group_depth) {
				// what size to classify groups by
				break;
			}

			if (gl < at) {
				gl++;
				continue;
			}

			ranked_groups[gl] += ':' + all[at];

			gl++;

		}

		a++;

	}

	return ranked_groups;

}

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

	// how many seconds between each iteration of the cleanup loop
	o.cleanup_loop_seconds = 60;

	// how many seconds to block an IP for
	o.block_ip_for_seconds = 60 * 60 * 24;

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
	// {nodemailer_smtpTransport: nodemailer.createTransport({}), from: 'user@domain.tld', to: 'user@domain.tls', domain: 'domain or ip address'}
	o.mail = null;
	o.next_email_blocked_ips = [];
	o.next_email_absurd_ips = [];

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
	o.ips = {};

	o.ipv6_subnets = {};

	// store the counts updated in the cleanup loop
	o.total_count = 0;
	o.blocked_count = 0;
	o.warn_count = 0;

	// start the cleanup routine
	o.last_cleanup = Date.now();
	var cleanup = setInterval(function() {

		// consider the time since the last interval as that is when the last_cleanup value was set
		var seconds_since_last_cleanup = (Date.now() - o.last_cleanup) / 1000;

		var expire_older_than = o.block_ip_for_seconds - seconds_since_last_cleanup;

		var ctotal = 0;
		var cblocked = 0;
		var cwarn = 0;

		// clear expired ips
		for (var key in o.ips) {

			// the age of this ip's last access in seconds
			var age_of_ip = (Date.now() - o.ips[key].last_access)/1000;

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

		// handle subnet group blocks with
		//
		// o.ipv6_subnets
		// o.block_ipv6_subnets_group_depth
		// o.block_ipv6_subnets_breach
		for (s in o.ipv6_subnets) {

			if (o.ipv6_subnets[s].blockedMs !== undefined) {
				// this subnet group is blocked
				// test if the block should expire

				var age_of_block = (Date.now() - o.ipv6_subnets[s].blockedMs)/1000;

				if (age_of_block > expire_older_than) {
					// unblock this subnet group
					delete o.ipv6_subnets[s];
				}

				continue;

			}

			var groups = s.split(':');

			var group_breach = o.block_ipv6_subnets_breach * (o.block_ipv6_subnets_group_depth + 1 - groups.length);

			if (o.ipv6_subnets[s].ip_bans === group_breach) {

				// this subnet group has breached the limit
				// block it
				o.ipv6_subnets[s].blockedMs = Date.now();

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

		if (o.mail !== null) {

			// send notifications via email

			if (o.next_email_blocked_ips.length > 0) {

				// generate the string of IPs for the email body
				var s = '';
				for (var n in o.next_email_blocked_ips) {
					s += o.next_email_blocked_ips[n] + ', ';
				}
				s = s.substring(0, s.length-2);

				// send notification
				o.mail.nodemailer_smtpTransport.sendMail({
					from: "ISPApp <" + o.mail.from + ">", // sender address
					to: o.mail.to,
					subject: 'node-ip-ac blocked ' + o.next_email_blocked_ips.length + ' IP(s) on ' + o.mail.domain,
					html: '<p>These IP address were blocked.</p><br /><p>' + s + '</p>'
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
				for (var n in o.next_email_absurd_ips) {
					s += o.next_email_absurd_ips[n] + ', ';
				}
				s = s.substring(0, s.length-2);

				// send notification
				o.mail.nodemailer_smtpTransport.sendMail({
					from: "ISPApp <" + o.mail.from + ">", // sender address
					to: o.mail.to,
					subject: 'node-ip-ac is reporting ' + o.next_email_absurd_ips.length + ' absurd authorization attempt(s) on ' + o.mail.domain,
					html: '<p>These IP address tried to brute force or guess a login while there was an authenticated connection from the same IP.  It may be a malicious user or a malicious NAT (RFC1918) network.  They are not blocked.</p><br /><p>' + s + '</p>'
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

exports.ip_details = function(o, addr_string) {

	var i = default_entry();

	if (typeof(o.ips[addr_string]) == 'object') {
		i = o.ips[addr_string];
	}

	return i;

}

exports.test_ip_warn = function(o, addr_string) {

	var warn = false;

	if (typeof(o.ips[addr_string]) == 'object') {
		warn = o.ips[addr_string].warn;
	}

	return warn;

}

exports.test_ip_allowed = function(o, addr_string) {
	// always ran at the start of any request
	// returns false if the IP address has made too many unauthenticated requests and is not allowed
	// returns true is the connection is allowed

	// test if the subnet is blocked
	if (net.isIPv4(addr_string)) {
	} else if (net.isIPv6(addr_string)) {

		var ranked_groups = get_ranked_groups_ipv6(o, addr_string);

		for (var s in ranked_groups) {
			if (o.ipv6_subnets[s] !== undefined) {
				if (o.ipv6_subnets[s].blockedMs !== undefined) {
					// this subnet group is blocked
					return false;
				}
			}
		}

	}

	if (o.ips[addr_string] !== undefined) {

		// a matching ip address has been found
		var entry = o.ips[addr_string];

		if (entry.authed === false) {
			// increment the number of unauthed connections for this IP address
			entry.unauthed_new_connections++;
		}

		// warn this IP address if it has made too many unauthed connections
		if (entry.unauthed_new_connections >= o.warn_after_new_connections && entry.warn === false) {
			entry.warn = true;
		}

		// block this IP address if it has made too many unauthed connections
		// or invalid authorization attempts
		if ((entry.unauthed_new_connections >= o.block_after_new_connections || entry.unauthed_attempts >= o.block_after_unauthed_attempts) && entry.blocked === false) {

			// set the IP address to blocked
			entry.blocked = true;

			// block this IP at the OS level
			modify_ip_block_os(true, addr_string);

			if (o.mail !== null) {

				// add to next email
				o.next_email_blocked_ips.push(addr_string);

			}

			// get ip address as bytes
			if (net.isIPv4(addr_string)) {

			} else if (net.isIPv6(addr_string)) {

				var ranked_groups = get_ranked_groups_ipv6(o, addr_string);

				// add the ranked_groups to the subnet classifications
				var a = 0;
				while (a < ranked_groups.length) {

					if (ipv6_subnets[ranked_groups[a]] !== undefined) {
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

			// this will only happen once as it is === not >

			if (o.mail !== null) {

				// add to next email
				o.next_email_absurd_ips.push(addr_string);

			}

		}

		// update the entry in memory
		o.ips[addr_string] = entry;

	} else {

		// this IP address is new to the access control system
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

exports.modify_auth = function(o, authed, addr_string) {

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

	} else if ((now - entry.last_access)/1000 > o.block_ip_for_seconds || authed === true) {
		// authorized or expired
		// reset the object keys
		// this removes the requirement for waiting until the next cleanup iteration
		// as the whole functionality may be executed during that time
		// and an authorized attempt must reset that possibility
		entry.unauthed_attempts = 0;
		entry.unauthed_new_connections = 0;
		entry.absurd_auth_attempts = 0;
		entry.blocked = false;
		entry.warn = false;

		if (authed) {
			entry.authed = true;
		}

	} else if (authed === false) {

		// not authorized or expired

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
