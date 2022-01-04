#include <bob.h>

// TODO the two following headers are necessary for 'fetch.h' but are not included
//      most likely a bug, fix this

#include <sys/param.h>
#include <time.h>

#include <fetch.h>
#include <archive.h>

#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define ROOTFS_PATH "rootfs"
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

	if (mkdir(ROOTFS_PATH, 0700) < 0) {
		BOB_FATAL("Failed to create rootfs subdirectory (%s)\n", strerror(errno))
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

	char* path = malloc(strlen(COMPONENT_PATH) + strlen(name) + 64);
	sprintf(path, COMPONENT_PATH "/%s", name);

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

int bob_vessel_component_extract(bob_vessel_t* vessel, const char* name) {
	int rv = -1;

	BOB_INFO("Extracting component %s ...\n", name)

	// "chroot" (really just changing directories) to the final root
	// don't forget to go back to the vessel's build directory, so 'bob_vessel_component_extract' is atomic
	// as per archive_write_disk(3)'s "BUGS" section, we mustn't call 'chdir' between opening and closing archive objects

	if (chdir(ROOTFS_PATH) < 0) {
		BOB_FATAL("Failed to chroot into " ROOTFS_PATH " to extract the %s component (%s)\n", name, strerror(errno))
		goto error_chdir;
	}

	// get component path

	char* path = malloc(strlen(COMPONENT_PATH) + strlen(name) + 64);
	sprintf(path, "../" COMPONENT_PATH "/%s", name);

	// open archive

	struct archive* archive = archive_read_new();

	archive_read_support_filter_all(archive);
	archive_read_support_format_all(archive);

	if (archive_read_open_filename(archive, path, bob_chunk_bytes) < 0) {
		BOB_FATAL("Failed to open the %s component (%s)\n", name, archive_error_string(archive))
		goto error_read;
	}

	// extract archive

	while (1) {
		struct archive_entry* entry;
		int res = archive_read_next_header(archive, &entry);

		if (res == ARCHIVE_OK) {
			// when multithreading, the 'ARCHIVE_EXTRACT_ACL' flag results in a bus error
			// it would seem as though there is a bug in 'libarchive', but unfortunately I have not yet had the time to resolve it

			res = archive_read_extract(archive, entry, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_OWNER | ARCHIVE_EXTRACT_PERM | /*ARCHIVE_EXTRACT_ACL |*/ ARCHIVE_EXTRACT_XATTR | ARCHIVE_EXTRACT_FFLAGS);
		}

		if (res == ARCHIVE_EOF) {
			break;
		}

		const char* error_string = archive_error_string(archive);
		unsigned useless_warning = error_string && strcmp(error_string, "Can't restore time") == 0;
		
		if (res != ARCHIVE_OK && !(res == ARCHIVE_WARN && useless_warning)) {
			BOB_FATAL("Failed to extract the %s component (%s)\n", name, error_string)
			goto error_extract;
		}
	}

	// reached success

	rv = 0;

error_extract:
error_read:

	archive_read_close(archive);
	archive_read_free(archive);

	// don't forget to change back to vessel build directory!

	if (chdir("..") < 0) {
		BOB_FATAL("Failed to change back into vessel build directory after component extraction (%s)\n", strerror(errno))
		rv = -1;
	}

error_chdir:

	return rv;
}