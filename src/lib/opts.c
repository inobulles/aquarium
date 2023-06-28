#include <aquarium.h>
#include <err.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STONERS_GROUP "stoners"
#define BASE_PATH "/etc/aquariums"

// directory paths

#define TEMPLATES_PATH "templates"
#define KERNELS_PATH   "kernels"
#define AQUARIUMS_PATH "aquariums"

// file paths

#define SANCTIONED_PATH "templates_remote"
#define DB_PATH "aquarium_db"

// image output & filesystem creation options

#define ROOTFS_LABEL  "aquabsd-rootfs"
#define ESP_LABEL     "aquabsd-esp"
#define ESP_OEM       "AQUABSD "
#define ESP_VOL_LABEL "AQUABSD-ESP"

// useful macros

#define TRY_FREE(str) \
	if ((str)) { \
		free((str)); \
	}

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
	opts->vnet_disable = false;

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
	TRY_FREE(opts->base_path)

	// directory paths

	TRY_FREE(opts->templates_path)
	TRY_FREE(opts->kernels_path)
	TRY_FREE(opts->aquariums_path)

	// file paths

	TRY_FREE(opts->sanctioned_path)
	TRY_FREE(opts->db_path)

	// image output & filesystem creation options

	TRY_FREE(opts->rootfs_label)
	TRY_FREE(opts->esp_label)
	TRY_FREE(opts->esp_oem)
	TRY_FREE(opts->esp_vol_label)

	free(opts);
}

void aquarium_opts_set_base_path(aquarium_opts_t* opts, char const* base_path) {
	TRY_FREE(opts->base_path)
	opts->base_path = strdup(base_path);

	// directory paths

	TRY_FREE(opts->templates_path)
	TRY_FREE(opts->kernels_path)
	TRY_FREE(opts->aquariums_path)

	if (asprintf(&opts->templates_path, "%s/" TEMPLATES_PATH, opts->base_path)) {}
	if (asprintf(&opts->kernels_path,   "%s/" KERNELS_PATH,   opts->base_path)) {}
	if (asprintf(&opts->aquariums_path, "%s/" AQUARIUMS_PATH, opts->base_path)) {}

	// file paths

	TRY_FREE(opts->sanctioned_path)
	TRY_FREE(opts->db_path)

	if (asprintf(&opts->sanctioned_path, "%s/" SANCTIONED_PATH, opts->base_path)) {}
	if (asprintf(&opts->db_path,         "%s/" DB_PATH,         opts->base_path)) {}
}
