#include <bob.h>

#define SOURCE "https://github.com/inobulles/bob-linux-images/releases/download/"
#define VERSION "amd64.ubuntu.focal"

int main(void) {
	bob_set_verbose(1);
	
	bob_aquarium_t* aquarium = bob_new_aquarium("amd64.ubuntu.focal");
	BOB_SANITY_CHECK(aquarium)

	setprogname(aquarium->name);

	// options

	bob_aquarium_sys(aquarium, BOB_SYS_SYSTEMD);

	// install components

	bob_aquarium_net_component(aquarium, "base", SOURCE VERSION "/amd64.ubuntu.focal.txz");
	bob_aquarium_component_extract(aquarium, "base");

	bob_del_aquarium(aquarium);

	return 0;
}