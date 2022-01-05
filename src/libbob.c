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

#define CHECK_VESSEL(vessel, rv) \
	if (!(vessel)) { \
		BOB_WARN("Using %s on a non-existant vessel\n", __func__) \
		return rv; \
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
	vessel->sys = BOB_SYS_AQUABSD;

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
	CHECK_VESSEL(vessel, )
	
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

int bob_vessel_sys(bob_vessel_t* vessel, bob_sys_t sys) {
	CHECK_VESSEL(vessel, -1)

	if ((unsigned) sys >= BOB_SYS_LEN) {
		BOB_WARN("Unknown system %d\n", sys)
		return -1;
	}

	vessel->sys = sys;
	return 0;
}

// vessel component functions

int bob_vessel_net_component(bob_vessel_t* vessel, const char* name, const char* url) {
	CHECK_VESSEL(vessel, -1)
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
	CHECK_VESSEL(vessel, -1)
	BOB_INFO("Extracting component %s ...\n", name)

	int rv = -1;

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
			// TODO when multithreading, the 'ARCHIVE_EXTRACT_ACL' flag results in a bus error
			//      it would seem as though there is a bug in 'libarchive', but unfortunately I have not yet had the time to resolve it

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

// vessel configuration functions

static int file_append(const char* path, const void* data, size_t len) {
	int rv = -1;

	FILE* fp = fopen(path, "a");

	if (!fp) {
		BOB_FATAL("Failed to open %s (%s)\n", path, strerror(errno))
		goto error_fopen;
	}

	fwrite(data, len, 1, fp);

	// success

	rv = 0;

	fclose(fp);

error_fopen:

	return rv;
}

static int file_append_str(const char* path, const char* str) {
	return file_append(path, str, strlen(str));
}

static int dummy_vessel_hostname(bob_vessel_t* vessel, const char* hostname) {
	BOB_FATAL("Setting hostname for system %d vessels is currently unsupported\n", vessel->sys)
	return -1;
}

static int freebsd_vessel_hostname(bob_vessel_t* vessel, const char* hostname) {
	char* ent = malloc(strlen(hostname) + 64);
	sprintf(ent, "hostname=%s\n", hostname);

	int rv = file_append_str(ROOTFS_PATH "/etc/rc.conf", ent);

	free(ent);

	return rv;
}

int bob_vessel_hostname(bob_vessel_t* vessel, const char* hostname) {
	CHECK_VESSEL(vessel, -1)
	BOB_INFO("Setting hostname to %s ...\n", hostname)

	int (*lut[BOB_SYS_LEN]) (bob_vessel_t* vessel, const char* hostname);

	for (int i = 0; i < sizeof(lut) / sizeof(*lut); i++) {
		lut[i] = dummy_vessel_hostname;
	}

	lut[BOB_SYS_FREEBSD] = freebsd_vessel_hostname;

	return lut[vessel->sys](vessel, hostname);
}