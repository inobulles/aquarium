#include <bob.h>

// TODO the two following headers are necessary for 'fetch.h' but are not included
//      most likely a bug, fix this

#include <sys/param.h>
#include <time.h>

#include <fetch.h>
#include <stdlib.h>

#define CHECK_VESSEL(vessel) \
	if (!(vessel)) { \
		BOB_WARN("Attempting to delete a non-existant vessel\n") \
		return; \
	}

// global settings functions

static unsigned bob_verbose = 0;

void bob_set_verbose(unsigned verbose) {
	bob_verbose = verbose;
}

// vessel creation/destruction functions

bob_vessel_t* bob_new_vessel(const char* name) {
	BOB_INFO("Creating a new vessel (%s) ...\n", name)

	bob_vessel_t* vessel = calloc(1, sizeof *vessel);
	vessel->name = strdup(name);

	return vessel;
}

void bob_del_vessel(bob_vessel_t* vessel) {
	CHECK_VESSEL(vessel)
	
	if (vessel->name) {
		BOB_INFO("Deleting vessel (%s) ...\n", vessel->name)
		free(vessel->name);
	}
}

// vessel settings functions

void bob_vessel_os(bob_vessel_t* vessel, bob_os_t os) {
	CHECK_VESSEL(vessel)

	vessel->os = os;
}

// vessel component functions

int bob_vessel_net_component(bob_vessel_t* vessel, const char* url) {
	BOB_FATAL("%s not yet implemented\n", __func__)
	return -1;
}