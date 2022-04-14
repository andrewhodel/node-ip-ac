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

	return {authed: false, warn: false, blocked: false, last_access: Date.now(), last_auth: Date.now(), unauthed_new_connections: 0, unauthed_attempts: 0};

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

	// send this object to send an email when an IP is blocked
	// {nodemailer_smtpTransport: nodemailer.createTransport({}), from: 'user@domain.tld', to: 'user@domain.tls', domain: 'domain or ip address'}
	o.mail = null;

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
	o.allowed_ips = {};

	// start the cleanup routine
	o.last_cleanup = Date.now();
	var cleanup = setInterval(function() {

		// consider the time since the last interval as that is when the last_cleanup value was set
		var seconds_since_last_cleanup = (Date.now() - o.last_cleanup) / 1000;

		var expire_older_than = this.o.block_ip_for_seconds - seconds_since_last_cleanup;

		// clear expired allowed_ips
		for (var key in this.o.allowed_ips) {

			// the age of this ip's last access in seconds
			var age_of_ip = (Date.now() - this.o.allowed_ips[key].last_access)/1000;

			//console.log("expire_older_than=" + expire_older_than, "age_of_ip=" + age_of_ip);
			//console.log(key, this.o.allowed_ips[key]);

			if (age_of_ip > expire_older_than) {

				// unblock the IP at the OS level
				modify_ip_block_os(false, key);

				delete this.o.allowed_ips[key];
			}
		}

		// update the last cleanup
		o.last_cleanup = Date.now();

	}.bind({o: o}), o.cleanup_loop_seconds * 1000);

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

	if (typeof(o.allowed_ips[addr_string]) == 'object') {
		i = o.allowed_ips[addr_string];
	}

	return i;

}

exports.test_ip_warn = function(o, addr_string) {

	var warn = false;

	if (typeof(o.allowed_ips[addr_string]) == 'object') {
		warn = o.allowed_ips[addr_string].warn;
	}

	return warn;

}

exports.test_ip_allowed = function(o, addr_string) {
	// always ran at the start of any request
	// returns false if the IP address has made too many unauthenticated requests and is not allowed
	// returns true is the connection is allowed

	if (o.allowed_ips[addr_string] !== undefined) {

		// a matching ip address has been found
		var entry = o.allowed_ips[addr_string];

		if (entry.authed === false) {
			// increment the number of unauthed connections for this IP address
			entry.unauthed_new_connections++;
		}

		// warn this IP address if it has made too many unauthed connections
		if (entry.unauthed_new_connections > o.warn_after_new_connections && entry.warn === false) {
			entry.warn = true;
		}

		// block this IP address if it has made too many unauthed connections
		// or invalid authorization attempts
		if ((entry.unauthed_new_connections > o.block_after_new_connections || entry.unauthed_attempts > o.block_after_unauthed_attempts) && entry.blocked === false) {

			// set the IP address to blocked
			entry.blocked = true;

			// block this IP at the OS level
			modify_ip_block_os(true, addr_string);

			if (o.mail !== null) {

				// email the initial admin the list of expired accounts that were removed
				o.mail.nodemailer_smtpTransport.sendMail({
					from: "ISPApp <" + o.mail.from + ">", // sender address
					to: o.mail.to,
					subject: 'node-ip-ac blocked ' + addr_string + ' on ' + o.mail.domain + ' after ' + o.block_after_new_connections + ' new unauthed connections',
					html: '<p>The IP address ' + addr_string + ' was blocked and will be allowed in ' + o.block_ip_for_seconds + ' seconds.</p><br /><p>' + JSON.stringify(entry) + '</p><br /><br /><a href="https://github.com/andrewhodel/node-ip-ac">node-ip-ac</a>'
				}, function(error, response) {
					if (error) {
						log_with_date('error sending email', error);
					} else {
						//log_with_date("Message sent: " + response.message);
					}
				});

			}

		}

		// update the entry in memory
		o.allowed_ips[addr_string] = entry;

	} else {

		// this IP address is new to the access control system
		o.allowed_ips[addr_string] = default_entry();

	}

	// set the last_access attempt time
	o.allowed_ips[addr_string].last_access = Date.now();

	if (o.allowed_ips[addr_string].blocked) {
		return false;
	} else {
		return true;
	}

}

exports.modify_auth = function(o, authed, addr_string) {
	// modify the authorization status
	// via the authed argument for the IP address in addr_string

	if (o.allowed_ips[addr_string] === undefined) {
		// this IP address is new to the access control system
		o.allowed_ips[addr_string] = default_entry();
	}

	// get the IP address
	var entry = o.allowed_ips[addr_string];

	// get a current timestamp
	var now = Date.now();

	if ((now - entry.last_access)/1000 > o.block_ip_for_seconds || authed) {
		// authorized or expired
		// reset the object keys
		// this removes the requirement for waiting until the next cleanup iteration
		// as the whole functionality may be executed during that time
		// and an authorized attempt must reset that possibility
		entry.unauthed_attempts = 0;
		entry.unauthed_new_connections = 0;
		entry.blocked = false;
		entry.warn = false;

		if (authed) {
			entry.authed = true;
		}

	} else {

		// not authorized or expired

		// increment the invalid authorization attempts counter for the IP address
		entry.unauthed_attempts += 1;
	}

	// set the last_auth attempt time
	entry.last_auth = Date.now();

	// update the entry in memory
	o.allowed_ips[addr_string] = entry;

}
