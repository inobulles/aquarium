#include <bob.h>

#include <stdlib.h>

static unsigned bob_verbose = 0;

void bob_set_verbose(unsigned verbose) {
	bob_verbose = verbose;
}

bob_vessel_t* bob_new_vessel(const char* name) {
	BOB_INFO("Creating a new vessel (%s) ...\n", name)

	bob_vessel_t* vessel = calloc(1, sizeof *vessel);
	vessel->name = strdup(name);

	return vessel;
}

void bob_del_vessel(bob_vessel_t* vessel) {
	if (!vessel) {
		BOB_WARN("Attempting to delete a non-existant vessel\n")
		return;
	}
	
	if (vessel->name) {
		BOB_INFO("Deleting vessel (%s) ...\n", vessel->name)
		free(vessel->name);
	}
}