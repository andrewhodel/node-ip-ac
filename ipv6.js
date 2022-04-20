
// split groups
var groups = addr_string.split(':');

var all = [];
for (var g in groups) {
	// convert hexadecimal string to Number
	//all.push(parseInt(groups[g], 16));
	all.push(groups[g]);
}

//console.log('all', all);

// create ranked groups
var ranked_groups = [];
// maximum depth to classify IPv6 is
// 64 bits of a network prefix and 64 bits of an interface identifier
// 64 bits is 4 groups that are 16 bits each
var max_groups = 4;

var at = 0;

var g = 0;
while (g < all.length) {
	ranked_groups.push(all[at]);

	if (g === max_groups-1) {
		// what size to classify groups by
		break;
	}

	g++;

}

//console.log('ranked_groups', ranked_groups);

var a = 0;
while (a < all.length) {

	if (a === max_groups) {
		// what size to classify groups by
		break;
	}

	at++;
	var gl = 0;
	while (gl < all.length) {

		if (gl === max_groups) {
			// what size to classify groups by
			break;
		}

		if (gl < at) {
			gl++;
			continue;
		}

		ranked_groups[gl] += all[at];

		gl++;

	}

	a++;

}

// add the ranked_groups to the subnet classifications
var a = 0;
while (a < ranked_groups.length) {

	if (ipv6_subnets[ranked_groups[a]] !== undefined) {
		// add one to the counter for this subnet group
		ipv6_subnets[ranked_groups[a]]++;
	} else {
		// it's new
		ipv6_subnets[ranked_groups[a]]++;
	}

	a++;

}
