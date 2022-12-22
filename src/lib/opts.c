#include "../aquarium.h"
#include <err.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STONERS_GROUP "stoners"

#define BASE_PATH      "/etc/aquariums"
#define TEMPLATES_PATH "templates"
#define KERNELS_PATH   "kernels"
#define AQUARIUMS_PATH "aquariums"

#define SANCTIONED_PATH "templates_remote"
#define DB_PATH "aquarium_db"

aquarium_opts_t* aquarium_opts_create(void) {
	aquarium_opts_t* opts = calloc(1, sizeof *opts);

	// copy default paths

	opts->base_path       = strdup(BASE_PATH      );
	opts->templates_path  = strdup(TEMPLATES_PATH );
	opts->kernels_path    = strdup(KERNELS_PATH   );
	opts->aquariums_path  = strdup(AQUARIUMS_PATH );

	opts->sanctioned_path = strdup(KERNELS_PATH   );
	opts->db_path         = strdup(AQUARIUMS_PATH );

	// skip this stuff if we're root
	// note that aquariums created as root won't be accessible by members of the stoners group

	uid_t const uid = getuid();

	if (!uid) {
		goto ok;
	}

	// make sure the $STONERS_GROUP group exists, and error if not

	struct group* stoners_group = getgrnam(STONERS_GROUP);

	if (!stoners_group) {
		warnx("Couldn't find \"" STONERS_GROUP "\" group");
	}

	opts->stoners_gid = stoners_group->gr_gid;
	endgrent();

	// make sure user is part of the $STONERS_GROUP group

	struct passwd* passwd = getpwuid(uid);
	char** stoners = stoners_group->gr_mem;

	while (*stoners) {
		if (!strcmp(*stoners++, passwd->pw_name)) {
			goto ok;
		}
	}

	warnx("%s is not part of the \"" STONERS_GROUP "\" group", passwd->pw_name);

ok:

	return opts;
}

void aquarium_opts_free(aquarium_opts_t* opts) {
	if (opts->base_path) {
		free(opts->base_path);
	}

	if (opts->templates_path) {
		free(opts->templates_path);
	}

	if (opts->kernels_path) {
		free(opts->templates_path);
	}

	if (opts->aquariums_path) {
		free(opts->templates_path);
	}

	if (opts->sanctioned_path) {
		free(opts->sanctioned_path);
	}

	if (opts->db_path) {
		free(opts->db_path);
	}

	free(opts);
}
