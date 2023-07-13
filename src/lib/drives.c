// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2023 Aymeric Wibo

#include <aquarium.h>
#include <err.h>
#include <errno.h>
#include <libgeom.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

static aquarium_drive_kind_t drive_kind(char const* provider) {
	// not super super robust but whatever

	if (!strncmp(provider, "md", 2)) return AQUARIUM_DRIVE_KIND_MD;
	if (!strncmp(provider, "ad", 2)) return AQUARIUM_DRIVE_KIND_ADA;
	if (!strncmp(provider, "da", 2)) return AQUARIUM_DRIVE_KIND_DA;
	if (!strncmp(provider, "nv", 2)) return AQUARIUM_DRIVE_KIND_NVME;
	if (!strncmp(provider, "cd", 2)) return AQUARIUM_DRIVE_KIND_CD;

	return AQUARIUM_DRIVE_KIND_OTHER;
}

static int process_drive(aquarium_drive_t** drives_ref, size_t* drives_len_ref, struct ggeom* geom, struct gclass* class) {
	aquarium_drive_t* drives = *drives_ref;
	size_t drives_len = *drives_len_ref;

	if (LIST_EMPTY(&geom->lg_provider)) {
		return 0;
	}

	// find provider(s)

	struct gprovider* provider;

	LIST_FOREACH(provider, &geom->lg_provider, lg_provider) {
		drives = realloc(drives, ++drives_len * sizeof *drives);
		aquarium_drive_t* const drive = &drives[drives_len - 1];

		memset(drive, 0, sizeof *drive); // 'realloc' doesn't zero out anything unfortunately
		drive->kind = drive_kind(provider->lg_name);

		drive->provider = strdup(provider->lg_name); // TODO vs 'geom->lg_name'?
		drive->rank = geom->lg_rank;

		drive->sector_size = provider->lg_sectorsize;
		drive->size = provider->lg_mediasize;

		// find extra information on drive

		struct gconfig* config;

		LIST_FOREACH(config, &provider->lg_config, lg_config) {
			if (!strcmp(config->lg_name, "ident") && config->lg_val) {
				drive->ident = strdup(config->lg_val);
			}

			else if (!strcmp(config->lg_name, "descr") && config->lg_val) {
				drive->name = strdup(config->lg_val);
			}
			
			else if (!strcmp(config->lg_name, "label") && config->lg_val) {
				drive->label = strdup(config->lg_val);
			}
		}
	}

	// find potential label(s)

	struct ggeom* label_geom;

	LIST_FOREACH(label_geom, &class->lg_geom, lg_geom) {
		if (strcmp(label_geom->lg_name, geom->lg_name)) {
			continue;
		}

		// 'provider' already defined previously

		LIST_FOREACH(provider, &label_geom->lg_provider, lg_provider) {
			for (size_t i = 0; i < drives_len; i++) {
				aquarium_drive_t* drive = &drives[i];

				if (strcmp(drive->provider, provider->lg_name)) {
					continue;
				}

				drive->label = strdup(provider->lg_name);
				break;
			}
		}

		break;
	}

	// set references

	*drives_ref = drives;
	*drives_len_ref = drives_len;

	return 0;
}

static void free_drive(aquarium_drive_t* drive) {
	if (drive->provider) {
		free(drive->provider);
	}

	if (drive->ident) {
		free(drive->ident);
	}

	if (drive->name) {
		free(drive->name);
	}

	if (drive->label) {
		free(drive->label);
	}
}

static int process_class(aquarium_drive_t** drives_ref, size_t* drives_len_ref, struct gmesh* mesh, char const* name) {
	struct gclass* class;

	// find class we're interested in

	LIST_FOREACH(class, &mesh->lg_class, lg_class) {
		if (!strcmp(class->lg_name, name)) {
			break;
		}
	}

	if (!class) {
		warnx("Failed to find '%s' class\n", name);
		return -1;
	}

	// traverse through first layer of disk geometry (rank 1)

	struct ggeom* geom;

	LIST_FOREACH(geom, &class->lg_geom, lg_geom) {
		process_drive(drives_ref, drives_len_ref, geom, class);
	}
	
	return 0;
}

int aquarium_drives_read(aquarium_drive_t** drives_ref, size_t* drives_len_ref) {
	int rv = -1;

	// get drive geometry mesh

	struct gmesh mesh;

	if (geom_gettree(&mesh) < 0) {
		warnx("geom_gettree: %s\n", strerror(errno));
		goto err_gettree;
	}

	if (
		process_class(drives_ref, drives_len_ref, &mesh, "DISK" ) < 0 ||
		process_class(drives_ref, drives_len_ref, &mesh, "MD"   ) < 0 ||
		process_class(drives_ref, drives_len_ref, &mesh, "LABEL") < 0
	) {
		goto class_err;
	}

	// success

	rv = 0;

class_err:

	geom_deletetree(&mesh);

err_gettree:

	return rv;
}

void aquarium_drives_free(aquarium_drive_t* drives, size_t drives_len) {
	for (size_t i = 0; i < drives_len; i++) {
		aquarium_drive_t* const drive = &drives[i];
		free_drive(drive);
	}

	free(drives);
}

aquarium_drive_t* aquarium_drives_find(aquarium_drive_t* drives, size_t drives_len, char const* provider) {
	for (size_t i = 0; i < drives_len; i++) {
		aquarium_drive_t* const drive = &drives[i];

		if (!strcmp(drive->provider, provider)) {
			return drive;
		}
	}

	warnx("Couldn't find drive with provider '%s' (we tried our best 😟)", provider);
	return NULL;
}
