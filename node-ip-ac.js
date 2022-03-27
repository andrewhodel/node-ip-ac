/*
Copyright 2016 Andrew Hodel
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

		var seconds_since_last_cleanup = (Date.now() - o.last_cleanup) / 1000;

		// clear expired allowed_ips
		for (var key in this.o.allowed_ips) {
			if ((Date.now() - this.o.allowed_ips[key].last_auth)/1000 > this.o.block_ip_for_seconds - seconds_since_last_cleanup) {

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

exports.test_ip_allowed = function(o, addr_string) {
	// always ran at the start of any request
	// returns false if the IP address has made too many unauthenticated requests and is not allowed
	// returns true is the connection is allowed

	if (typeof(o.allowed_ips[addr_string]) == 'object') {
		// a matching ip address has been found
		var entry = o.allowed_ips[addr_string];
		entry.unauthed_attempts++;

		// warn this IP address if there have been too many unauthed attempts
		if (entry.unauthed_attempts > o.warn_after_attempts && entry.warn == false) {
			entry.warn = true;
		}

		// block this IP address if there have been too many unauthed attempts
		if (entry.unauthed_attempts > o.block_after_attempts && entry.blocked == false) {
			entry.blocked = true;

			// block this IP at the OS level
			modify_ip_block_os(true, addr_string);

			if (o.mail != null) {

				// email the initial admin the list of expired accounts that were removed
				o.mail.nodemailer_smtpTransport.sendMail({
					from: "ISPApp <" + o.mail.from + ">", // sender address
					to: o.mail.to,
					subject: 'IP address blocked on ' + o.mail.domain + ' after ' + o.block_after_attempts + ' unauthed attempts',
					html: '<p>This IP address was blocked and will be allowed in ' + o.block_ip_for_seconds + ' seconds.</p><br /><p>' + JSON.stringify(entry) + '</p>'
				}, function(error, response) {
					if (error) {
						log_with_date('error sending email', error);
					} else {
						//log_with_date("Message sent: " + response.message);
					}
				});

			}

		}

		//console.log(entry, (Date.now()-entry.last_auth)/1000);

		if (entry.blocked) {
			return false;
		} else {
			return true;
		}
	} else {

		// this is the first call to this function for this ip address
		// add the address
		o.allowed_ips[addr_string] = {warn: false, blocked: false, last_auth: Date.now(), unauthed_attempts: 1};

		// return that the address is allowed
		return true;
	}
}

exports.modify_auth = function(o, authed, addr_string) {
	// modify the authorization status
	// via the authed argument for the IP address in addr_string

	var entry = o.allowed_ips[addr_string];
	var now = Date.now();

	if ((now - entry.last_auth)/1000 > o.block_ip_for_seconds) {
		// the last auth attempt was made more than o.block_ip_for_seconds ago

		// set these defaults as if it was the first
		// because denial of service has not been happening from this IP
		entry.blocked = false;
		entry.warn = false;

		// test the auth status
		if (!authed) {
			// this is the first attempt
			entry.unauthed_attempts = 1;
		} else {
			// this is no an unauthed attempt
			entry.unauthed_attempts = 0;
		}

	} else {

		// if the authed status is true
		// reset everything
		if (authed) {
			entry.blocked = false;
			entry.unauthed_attempts = 0;
			entry.warn = false;
		}
	}

	// remember the last_auth attempt time
	entry.last_auth = Date.now();

}
