// #include <aquarium.h>
#include "../aquarium.h"
#include <err.h>
#include <errno.h>
#include <libgeom.h>
#include <stdlib.h>
#include <string.h>

#define ESP_ALIGN 4096 // 4k boundary
#define ZFS_ALIGN (1024 * 1024) // 1m boundary

#define MIN_FAT32_CLUSTERS 66581

static uint64_t align(x, bound) {
	return x + bound - (x - 1) % bound - 1;
}

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

static int create_mesh(struct gmesh* mesh, struct ggeom** geom, char* provider) {
	if (geom_gettree(mesh) < 0) {
		warnx("Failed to get drive geometry mesh: %s\n", strerror(errno));
		return -1;
	}

	int rv = -1;

	struct gclass* class;

	LIST_FOREACH(class, &mesh->lg_class, lg_class) {
		if (!strcmp(class->lg_name, "PART")) {
			break;
		}
	}

	if (!class) {
		warnx("Failed to get partition class: %s\n", strerror(errno));
		goto err;
	}

	*geom = NULL;

	LIST_FOREACH(*geom, &class->lg_geom, lg_geom) {
		if (!strcmp((*geom)->lg_name, provider)) {
			break;
		}
	}

	if (!*geom) {
		fprintf(stderr, "Could not find geom: %s\n", provider);
		goto err;
	}

	rv = 0;

err:

	geom_deletetree(mesh);

	return rv;
}

static int add_esp_entry(aquarium_opts_t* opts, aquarium_drive_t* drive) {
	// create drive geometry mesh

	struct gmesh mesh;
	struct ggeom* geom;

	if (create_mesh(&mesh, &geom, drive->provider) < 0) {
		return -1;
	}

	uint64_t start = 40; // some sane default value if ever we can't find 'start'

	struct gconfig* config;

	LIST_FOREACH(config, &geom->lg_config, lg_config) {
		if (strcmp(config->lg_name, "first") == 0) {
			start = atoll(config->lg_val);
		}
	}

	// create an EFI system partition

	struct gctl_req* const gctl_handle = gctl_get_handle();

	gctl_ro_param(gctl_handle, "class", -1, "PART");
	gctl_ro_param(gctl_handle, "verb", -1, "add");
	gctl_ro_param(gctl_handle, "type", -1, "efi");
	gctl_ro_param(gctl_handle, "label", -1, opts->esp_label);
	gctl_ro_param(gctl_handle, "arg0", -1, drive->provider);

	start = align(start, ESP_ALIGN / drive->sector_size); // align to 4k boundaries
	uint64_t const esp_size = align(start + MIN_FAT32_CLUSTERS, ZFS_ALIGN / drive->sector_size) - start; // get minimum size our ESP can be, and align that to the start of the next partition (ZFS)

	char size_str[256];
	snprintf(size_str, sizeof size_str, "%lu", esp_size);

	gctl_ro_param(gctl_handle, "size", -1, size_str);

	char start_str[256];
	snprintf(start_str, sizeof start_str, "%lu", start);

	gctl_ro_param(gctl_handle, "start", -1, start_str);

	char const* const err = gctl_issue(gctl_handle);

	if (err) {
		warnx("Failed to create EFI system partition (ESP): %s\n", err);

		gctl_free(gctl_handle);
		return -1;
	}

	gctl_free(gctl_handle);
	return 0;
}

int aquarium_format_create_esp(aquarium_opts_t* opts, aquarium_drive_t* drive, char const* path) {
	// add entry to partition table

	if (add_esp_entry(opts, drive) < 0) {
		return -1;
	}

	return 0;
}
