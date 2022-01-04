#include <bob.h>

#define SOURCE "https://github.com/inobulles/aquabsd-core/release/download/"
#define VERSION "v1221a-beta"

int main(void) {
	bob_set_verbose(1);
	
	bob_vessel_t* vessel = bob_new_vessel("aquabsd-example");
	BOB_SANITY_CHECK(vessel)

	// options

	bob_vessel_os(vessel, BOB_OS_FREEBSD);

	// install components

	bob_vessel_net_component(vessel, SOURCE VERSION "/kernel.txz");
	bob_vessel_net_component(vessel, SOURCE VERSION "/base.txz");
	// bob_vessel_local_component(vessel, "example.txz");

	// // specfic configuration

	// bob_vessel_hostname(vessel, vessel->name);
	// bob_vessel_pkg(vessel, "vim");

	// // create image components

	// bob_vessel_gen_fs(vessel, vessel->name);
	// bob_vessel_gen_esp(vessel, "AQUABSD ", "AQUABSD-EFI");

	// char* path = bob_vessel_assemble(vessel);
	// BOB_INFO("Final assembled image outputted at %s\n", path)

	bob_del_vessel(vessel);

	return 0;
}