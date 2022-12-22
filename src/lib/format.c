// #include <aquarium.h>
#include "../aquarium.h"
#include <err.h>
#include <libgeom.h>
#include <stdlib.h>
#include <string.h>

static int create_gpt_table(aquarium_drive_t* drive) {
	struct gctl_req* const handle = gctl_get_handle();

	gctl_ro_param(handle, "class", -1, "PART");
	gctl_ro_param(handle, "verb", -1, "create");
	gctl_ro_param(handle, "scheme", -1, "gpt");
	gctl_ro_param(handle, "arg0", -1, drive->provider);

	char const* const err= gctl_issue(handle);

	if (err) {
		warnx("Failed to create GPT partition table: %s\n", err);

		gctl_free(handle);
		return -1;
	}

	gctl_free(handle);
	return 0;
}

static int destroy_table(aquarium_drive_t* drive) {
	struct gctl_req* const handle = gctl_get_handle();

	gctl_ro_param(handle, "class", -1, "PART"); // NOT to be confused with the drive's class
	gctl_ro_param(handle, "verb", -1, "destroy");
	gctl_ro_param(handle, "arg0", -1, drive->provider);

	int const forced = 1;
	gctl_ro_param(handle, "force", sizeof forced, &forced);

	char const* const err = gctl_issue(handle); // we don't care if this errors-out

	if (err) {
		warnx("Failed to destroy partition table: %s\n", err);

		gctl_free(handle);
		return -1;
	}

	gctl_free(handle);
	return 0;
}

int aquarium_format_new_table(aquarium_drive_t* drive) {
	char* const provider = drive->provider;

	if (strncmp(provider, "md", 2)) { // XXX to be removed when releasing obviously
		printf("Don't lol %s\n", provider);
		return -1;
	}

	int rv = -1;

	char* const provider_path = g_device_path(provider);

	if (!provider_path) {
		warnx("g_device_path(\"%s\") failed\n", provider);
		goto g_device_path_err;
	}

	// destroy previous partition table

	if (destroy_table(drive) < 0) {
		goto destroy_table_err;
	}

	// create new GPT partition table on the drive

	if (create_gpt_table(drive) < 0) {
		goto create_table_err;
	}

	// success

	rv = 0;

create_table_err:
destroy_table_err:

	free(provider_path);

g_device_path_err:

	return rv;
}
