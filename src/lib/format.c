// #include <aquarium.h>
#include "../aquarium.h"
#include <err.h>
#include <errno.h>
#include <geom/geom_ctl.h>
#include <libgeom.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mkfs_msdos.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>

#define ESP_ALIGN 4096 // 4k boundary
#define ZFS_ALIGN (1024 * 1024) // 1m boundary

#define MIN_FAT32_CLUSTERS 66581

static size_t align(size_t x, size_t bound) {
	return x + bound - (x - 1) % bound - 1;
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

static int format_create_part(aquarium_drive_t* drive, char const* type, char const* label, size_t start, size_t size) {
	struct gctl_req* const handle = gctl_get_handle();

	gctl_ro_param(handle, "class", -1, "PART");
	gctl_ro_param(handle, "verb", -1, "add");
	gctl_ro_param(handle, "type", -1, type);
	gctl_ro_param(handle, "label", -1, label);
	gctl_ro_param(handle, "arg0", -1, drive->provider);

	char size_str[256];
	snprintf(size_str, sizeof size_str, "%lu", size);
	gctl_ro_param(handle, "size", -1, size_str);

	char start_str[256];
	snprintf(start_str, sizeof start_str, "%lu", start);
	gctl_ro_param(handle, "start", -1, start_str);

	char const* const err = gctl_issue(handle);

	if (err) {
		warnx("Failed to create partition '%s' of type '%s' (start = %zu, size = %zu): %s", label, type, start, size, err);

		gctl_free(handle);
		return -1;
	}

	gctl_free(handle);
	return 0;
}

int aquarium_format_new_table(aquarium_opts_t* opts, aquarium_drive_t* drive) {
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

	// create drive geometry mesh

	struct gmesh mesh;
	struct ggeom* geom;

	if (create_mesh(&mesh, &geom, drive->provider) < 0) {
		goto create_mesh_err;
	}

	// how much space do we have to work with?

	size_t start = 40; // some sane default value if ever we can't find 'start'
	size_t end = drive->size / drive->sector_size - start;

	struct gconfig* config;

	LIST_FOREACH(config, &geom->lg_config, lg_config) {
		if (!strcmp(config->lg_name, "first")) {
			start = atoll(config->lg_val);
		}

		if (!strcmp(config->lg_name, "end")) {
			end = atoll(config->lg_val) + 1;
		}
	}

	// lay partitions out
	// ESP start: align to 4k boundaries
	// ZFS start: get minimum size our ESP can be, and align ZFS partition's start to that

	size_t const esp_start = align(start, ESP_ALIGN / drive->sector_size);
	size_t const zfs_start = align(esp_start + MIN_FAT32_CLUSTERS, ZFS_ALIGN / drive->sector_size);

	size_t const esp_size = zfs_start - esp_start;
	size_t const zfs_size = end - zfs_start;

	// create ESP

	if (format_create_part(drive, "efi", opts->esp_label, esp_start, esp_size) < 0) {
		goto esp_part_err;
	}

	// create rootfs (ZFS)

	if (format_create_part(drive, "freebsd-zfs", opts->rootfs_label, zfs_start, zfs_size) < 0) {
		goto zfs_part_err;
	}

	// success

	rv = 0;

zfs_part_err:
esp_part_err:

	geom_deletetree(&mesh);

create_mesh_err:
create_table_err:
destroy_table_err:

	free(provider_path);

g_device_path_err:

	return rv;
}

static char* part_name_from_i(aquarium_drive_t* drive, size_t want) {
	// create drive geometry mesh

	struct gmesh mesh;
	struct ggeom* geom;

	if (create_mesh(&mesh, &geom, drive->provider) < 0) {
		return NULL;
	}

	// look through providers

	struct gprovider* part;
	size_t i = 0;

	LIST_FOREACH(part, &geom->lg_provider, lg_provider) {
		if (i++ == want) {
			goto found;
		}
	}

	warnx("Couldn't find partition index %zu on drive '%s' ('%s')", want, drive->name, drive->provider);

	geom_deletetree(&mesh);
	return NULL;

found: {}

	char* const name = strdup(part->lg_name);
	geom_deletetree(&mesh);

	return name;
}

int aquarium_format_create_esp(aquarium_opts_t* opts, aquarium_drive_t* drive, char const* path) {
	int rv = -1;

	// ESP should be the first partition

	char* name = part_name_from_i(drive, 0);

	if (!name) {
		goto name_err;
	}

	// create FAT32 filesystem on the ESP

	struct msdos_options options = {
		.OEM_string = opts->esp_oem,
		.volume_label = opts->esp_vol_label,

		.fat_type = 32,

		// .create_size = esp_size * drive->sector_size,
		.sectors_per_cluster = 1,
	};

	char esp_dev_path[256];
	snprintf(esp_dev_path, sizeof esp_dev_path, "/dev/%s", name);

	if (mkfs_msdos(esp_dev_path, NULL, &options) < 0) {
		warnx("Failed to create FAT32 filesystem in ESP\n");
		goto mkfs_err;
	}

	// mount ESP

	char* mountpoint;
	if (asprintf(&mountpoint, "%s/boot/efi", path)) {}

	struct iovec iov[] = {
		__AQUARIUM_IOV("fstype", "msdosfs"),
		__AQUARIUM_IOV("fspath", mountpoint),
		__AQUARIUM_IOV("from", esp_dev_path),
		__AQUARIUM_IOV("longnames", ""),
	};

	if (nmount(iov, sizeof(iov) / sizeof(*iov), 0) < 0) {
		warnx("nmount(\"%s\", \"%s\"): %s\n", esp_dev_path, mountpoint, strerror(errno));
		goto mount_err;
	}

	// finally, populate the ESP

	if (aquarium_img_populate_esp(path, mountpoint) < 0) {
		goto populate_err;
	}

	rv = 0;

populate_err:

	if (unmount(mountpoint, 0) < 0) {
		warnx("unmount(\"%s\"): %s", mountpoint, strerror(errno));
	}

mount_err:

	free(mountpoint);

mkfs_err:

	free(name);

name_err:

	return rv;
}

int aquarium_format_create_zfs(aquarium_opts_t* opts, aquarium_drive_t* drive, char const* path) {
	return 0;
}
