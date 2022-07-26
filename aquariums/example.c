#include <bob.h>

#define SOURCE "https://github.com/inobulles/aquabsd-core/releases/download/"
#define VERSION "v0222a-beta"

int main(void) {
	bob_set_verbose(1);
	
	bob_aquarium_t* aquarium = bob_new_aquarium("aquabsd-example");
	BOB_SANITY_CHECK(aquarium)

	setprogname(aquarium->name);

	// options

	bob_aquarium_sys(aquarium, BOB_SYS_FREEBSD);

	// install components

	bob_aquarium_net_component(aquarium, "kernel", SOURCE VERSION "/kernel.txz");
	bob_aquarium_net_component(aquarium, "base",   SOURCE VERSION "/base.txz");
	// bob_aquarium_local_component(aquarium, "example.txz");

	bob_aquarium_component_extract(aquarium, "kernel");
	bob_aquarium_component_extract(aquarium, "base");

	// specfic configuration

	bob_aquarium_hostname(aquarium, aquarium->name);
	// bob_aquarium_pkg(aquarium, "vim");

	// create image components

	bob_aquarium_gen_fs(aquarium, aquarium->name);
	bob_aquarium_gen_esp(aquarium, "AQUABSD ", "AQUABSD-EFI");

	bob_aquarium_assemble(aquarium);
	BOB_INFO("Final assembled image outputted at %s\n", aquarium->assembled_path)

	bob_del_aquarium(aquarium);

	return 0;
}