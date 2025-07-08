var ipac = require('../node-ip-ac');

var ip_ac = ipac.init();

// event notification closure
ip_ac.notify_cb = function(event, info, ips) {

	// event is a string of ips_blocked, ips_exceeded_absurd_auth_attempts or subnet_blocked
	// info is a string about the event
	// ips is a list of ip addresses related to the event

}

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
console.log('test_ip_allowed 127.0.0.1:', status);

// test if you should warn users from an IP
// this must be called if you want to warn connections from the application that more requests forces a block
var warn = ipac.test_ip_warn(ip_ac, '127.0.0.1');
console.log('test_ip_warn 127.0.0.1:', warn);

// return details of a specific ip address
var ip_details = ipac.ip_details(ip_ac, '127.0.0.1');
console.log('ip_details 127.0.0.1:', ip_details);
