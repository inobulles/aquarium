#include <bob.h>

#define SOURCE "https://github.com/inobulles/bob-linux-images/releases/download/"
#define VERSION "amd64.ubuntu.focal"

int main(void) {
	bob_set_verbose(1);
	
	bob_vessel_t* vessel = bob_new_vessel("amd64.ubuntu.focal");
	BOB_SANITY_CHECK(vessel)

	setprogname(vessel->name);

	// options

	bob_vessel_sys(vessel, BOB_SYS_SYSTEMD);

	// install components

	bob_vessel_net_component(vessel, "base", SOURCE VERSION "/amd64.ubuntu.focal.txz");
	bob_vessel_component_extract(vessel, "base");

	bob_del_vessel(vessel);

	return 0;
}