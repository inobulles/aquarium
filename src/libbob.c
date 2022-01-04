#include <bob.h>

// TODO the two following headers are necessary for 'fetch.h' but are not included
//      most likely a bug, fix this

#include <sys/param.h>
#include <time.h>

#include <fetch.h>

#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define COMPONENT_PATH "components"

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

static unsigned bob_chunk_bytes = 4096;

void bob_set_chunk_bytes(unsigned chunk_bytes) {
	bob_chunk_bytes = chunk_bytes;
}

// vessel creation/destruction functions

bob_vessel_t* bob_new_vessel(const char* name) {
	BOB_INFO("Creating a new vessel (%s) ...\n", name)

	int rv = -1;

	bob_vessel_t* vessel = calloc(1, sizeof *vessel);
	vessel->name = strdup(name);

	char _path[] = "/tmp/bob-vessel-XXXXXXX";
	char* path = mkdtemp(_path);

	if (!path) {
		BOB_FATAL("Failed to create build directory for vessel\n")
		goto error;
	}

	vessel->path = strdup(path);

	if (chdir(vessel->path) < 0) {
		BOB_FATAL("Failed to enter vessel build directory (%s) (%s)\n", vessel->path, strerror(errno))
		goto error;
	}

	if (mkdir(COMPONENT_PATH, 0700) < 0) {
		BOB_FATAL("Failed to create component subdirectory (%s)\n", strerror(errno))
		goto error;
	}

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

int bob_vessel_net_component(bob_vessel_t* vessel, const char* name, const char* url) {
	BOB_INFO("Downloading net component (%s) ...\n", name)

	int rv = -1;
	uint8_t chunk[bob_chunk_bytes]; // initialization of VLA must come before any jumps

	// get component output path

	char* path = malloc(strlen(COMPONENT_PATH) + strlen(name) + 2);
	sprintf(path, "%s/%s", COMPONENT_PATH, name);

	FILE* out_fp = fopen(path, "w+");

	if (!out_fp) {
		BOB_FATAL("Failed to open %s for writing (%s)\n", path, strerror(errno))
		goto error_open_out;
	}

	// fetch the component itself

	FILE* fetch_fp = fetchGetURL(url, "");

	if (!fetch_fp) {
		BOB_FATAL("Failed to find %s component (%s)\n", name, url);
		goto error_open_fetch;
	}

	size_t bytes;

	while ((bytes = fread(chunk, 1, sizeof chunk, fetch_fp)) > 0) {
		if (fwrite(chunk, 1, bytes, out_fp) < bytes) {
			break;
		}
	}

	// success

	rv = 0;

error_open_fetch:

	fclose(out_fp);

error_open_out:

	free(path);

	return rv;
}