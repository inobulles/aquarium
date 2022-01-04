#include <bob.h>

// TODO the two following headers are necessary for 'fetch.h' but are not included
//      most likely a bug, fix this

#include <sys/param.h>
#include <time.h>

#include <fetch.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

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
	int rv = -1;
	
	BOB_INFO("Creating a new vessel (%s) ...\n", name)

	bob_vessel_t* vessel = calloc(1, sizeof *vessel);
	vessel->name = strdup(name);

	BOB_INFO("Creating temporary directory in which the vessel will be built ...\n")

	char _path[] = "/tmp/bob-vessel-XXXXXXX";
	char* path = mkdtemp(_path);

	if (!path) {
		BOB_FATAL("Failed to create temporary directory for vessel\n")
		goto error;
	}

	vessel->path = strdup(path);

	// success

	rv = 0;

done:

	return vessel;

error:

	bob_del_vessel(vessel);
	goto done;
}

void bob_del_vessel(bob_vessel_t* vessel) {
	CHECK_VESSEL(vessel)
	
	if (vessel->name) {
		BOB_INFO("Deleting vessel (%s) ...\n", vessel->name)
		free(vessel->name);
	}

	if (vessel->path) {
		if (rmdir(vessel->path) < 0) {
			BOB_FATAL("Failed to delete vessel directory (%s) (%s)\n", vessel->path, strerror(errno))
		}

		free(vessel->path);
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