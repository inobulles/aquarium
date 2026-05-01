// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2023 Aymeric Wibo

#include <aquarium.h>
#include <err.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STONERS_GROUP "stoners"
#define BASE_PATH "/usr/local/aquarium"

// directory paths

#define TEMPLATES_PATH "tmpls"
#define KERNELS_PATH   "kerns"
#define OVERLAYS_PATH  "overlays"
#define AQUARIUMS_PATH "roots"

// file paths

#define SANCTIONED_PATH "tmpls.remote"
#define DB_PATH "db"

// image output & filesystem creation options

#define ROOTFS_LABEL  "freebsd-ufs"
#define ESP_LABEL     "efiboot0"
#define ESP_OEM       "BSD4.4  "
#define ESP_VOL_LABEL "FREEBSD-ESP"


aquarium_opts_t* aquarium_opts_create(void) {
	aquarium_opts_t* const opts = calloc(1, sizeof *opts);

	// setting the base path automatically sets all the others

	aquarium_opts_set_base_path(opts, BASE_PATH);

	// image output & filesystem creation options

	opts->rootfs_label  = strdup(ROOTFS_LABEL );
	opts->esp_label     = strdup(ESP_LABEL    );
	opts->esp_oem       = strdup(ESP_OEM      );
	opts->esp_vol_label = strdup(ESP_VOL_LABEL);

	// jail options

	opts->persist = false;
	opts->dhcp = false;
	opts->max_children = 0;
	opts->vnet_bridge = NULL;

	// skip this stuff if we're root
	// note that aquariums created as root won't be accessible by members of the stoners group

	opts->initial_uid = getuid();
	opts->initial_gid = getgid();

	if (!opts->initial_uid) {
		goto ok;
	}

	// make sure the $STONERS_GROUP group exists, and error if not

	struct group* const stoners_group = getgrnam(STONERS_GROUP);

	if (!stoners_group) {
		errx(EXIT_FAILURE, "Couldn't find \"" STONERS_GROUP "\" group");
	}

	opts->stoners_gid = stoners_group->gr_gid;
	endgrent();

	// make sure user is part of the $STONERS_GROUP group

	struct passwd* const passwd = getpwuid(opts->initial_uid);
	char** stoners = stoners_group->gr_mem;

	while (*stoners) {
		if (!strcmp(*stoners++, passwd->pw_name)) {
			goto ok;
		}
	}

	errx(EXIT_FAILURE, "%s is not part of the \"" STONERS_GROUP "\" group", passwd->pw_name);

ok:

	return opts;
}

void aquarium_opts_free(aquarium_opts_t* opts) {
	free(opts->base_path);

	// directory paths

	free(opts->templates_path);
	free(opts->kernels_path);
	free(opts->overlays_path);
	free(opts->aquariums_path);

	// file paths

	free(opts->sanctioned_path);
	free(opts->db_path);

	// image output & filesystem creation options

	free(opts->rootfs_label);
	free(opts->esp_label);
	free(opts->esp_oem);
	free(opts->esp_vol_label);

	// jailparams

	free(opts->jailparam_keys);
	free(opts->jailparam_vals);

	// devfs ruleset options

	free(opts->rulesets);

	free(opts);
}

void aquarium_opts_set_base_path(aquarium_opts_t* opts, char const* base_path) {
	free(opts->base_path);
	opts->base_path = strdup(base_path);

	// directory paths

	free(opts->templates_path);
	free(opts->kernels_path);
	free(opts->overlays_path);
	free(opts->aquariums_path);

	if (asprintf(&opts->templates_path, "%s/" TEMPLATES_PATH, opts->base_path)) {}
	if (asprintf(&opts->kernels_path,   "%s/" KERNELS_PATH,   opts->base_path)) {}
	if (asprintf(&opts->overlays_path,  "%s/" OVERLAYS_PATH,  opts->base_path)) {}
	if (asprintf(&opts->aquariums_path, "%s/" AQUARIUMS_PATH, opts->base_path)) {}

	// file paths

	free(opts->sanctioned_path);
	free(opts->db_path);

	if (asprintf(&opts->sanctioned_path, "%s/" SANCTIONED_PATH, opts->base_path)) {}
	if (asprintf(&opts->db_path,         "%s/" DB_PATH,         opts->base_path)) {}
}

void aquarium_opts_add_devfs_ruleset(aquarium_opts_t* opts, uint32_t ruleset) {
	opts->rulesets = realloc(opts->rulesets, ++opts->ruleset_count * sizeof *opts->rulesets);
	opts->rulesets[opts->ruleset_count - 1] = ruleset;
}

void aquarium_opts_add_jailparam(aquarium_opts_t* opts, char* key, char* val) {
	opts->jailparam_count++;

	opts->jailparam_keys = realloc(opts->jailparam_keys, opts->jailparam_count * sizeof *opts->jailparam_keys);
	opts->jailparam_vals = realloc(opts->jailparam_vals, opts->jailparam_count * sizeof *opts->jailparam_vals);

	opts->jailparam_keys[opts->jailparam_count - 1] = key;
	opts->jailparam_vals[opts->jailparam_count - 1] = val;
}
