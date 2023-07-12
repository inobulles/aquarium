#pragma once

#include <copyfile.h>
#include <err.h>
#include <errno.h>
#include <fts.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

// TODO make these FS utility functions a library et mettre en commun avec Bob

static void strfree(char* const* str_ref) {
	char* const str = *str_ref;

	if (!str) {
		return;
	}

	free(str);
}

#define CLEANUP_STR __attribute__((cleanup(strfree)))

static bool can_read_all(char* path) {
	char* const path_argv[] = { path, NULL };
	FTS* const fts = fts_open(path_argv, FTS_PHYSICAL | FTS_XDEV, NULL);

	if (fts == NULL) {
		warnx("fts_open(\"%s\"): %s", path, strerror(errno));
		return false;
	}

	bool accum = true;

	for (FTSENT* ent; (ent = fts_read(fts));) {
		char* const path = ent->fts_path; // shadow parent scope's 'path'

		switch (ent->fts_info) {
		case FTS_DP:

			break; // ignore directories being visited in postorder

		case FTS_DOT:

			warnx("fts_read: Read a '.' or '..' entry, which shouldn't happen as the 'FTS_SEEDOT' option was not passed to 'fts_open'");
			break;

		case FTS_DNR:
		case FTS_ERR:
		case FTS_NS:

			warnx("fts_read: Failed to read '%s': %s", path, strerror(errno));
			break;

		case FTS_SL:
		case FTS_SLNONE:
		case FTS_D:
		case FTS_DC:
		case FTS_F:
		case FTS_DEFAULT:
		default:

			if (access(path, R_OK) != 0) {
				goto err_access;
			}
		}
	}

	accum = true;

err_access:

	fts_close(fts);
	return accum;
}

static int mkdir_recursive(char const* _path) {
	int rv = -1;

	// we don't need to do anything if path is empty

	if (!*_path) {
		return 0;
	}

	char* const CLEANUP_STR orig_path = strdup(_path);
	char* path = orig_path;

	// remember previous working directory, because to make our lives easier, we'll be jumping around the place to create our subdirectories

	char* const CLEANUP_STR cwd = getcwd(NULL, 0);

	if (!cwd) {
		warnx("getcwd: %s", strerror(errno));
		goto err_cwd;
	}

	// if we're dealing with a path relative to $HOME, chdir to $HOME first

	if (*path == '~') {
		char* const home = getenv("HOME");

		// if $HOME isn't set, treat as an absolute directory

		if (!home) {
			*path = '/';
		}

		else if (chdir(home) < 0) {
			warnx("chdir($HOME): %s", strerror(errno));
			goto err_home;
		}
	}

	// if we're dealing with an absolute path, chdir to '/' and treat path as relative

	if (*path == '/' && chdir("/") < 0) {
		warnx("chdir(\"/\"): %s", strerror(errno));
		goto err_abs;
	}

	// parse the path itself

	char* bit;

	while ((bit = strsep(&path, "/"))) {
		// ignore if the bit is empty

		if (!bit || !*bit) {
			continue;
		}

		// ignore if the bit refers to the current directory

		if (!strcmp(bit, ".")) {
			continue;
		}

		// don't attempt to mkdir if we're going backwards, only chdir

		if (!strcmp(bit, "..")) {
			goto no_mkdir;
		}

		if (mkdir(bit, 0755) < 0 && errno != EEXIST) {
			warnx("mkdir(\"%s\"): %s", bit, strerror(errno));
			goto err_mkdir;
		}

	no_mkdir:

		if (chdir(bit) < 0) {
			warnx("chdir(\"%s\"): %s", bit, strerror(errno));
			goto err_chdir;
		}
	}

	// success

	rv = 0;

err_chdir:
err_mkdir:

	// move back to current directory once we're sure the output directory exists (or there's an error)

	if (chdir(cwd) < 0) {
		warnx("chdir(\"%s\"): %s", cwd, strerror(errno));
	}

err_abs:
err_home:
err_cwd:

	return rv;
}

static int copy_recursive(char* source, char* target) {
	char* const path_argv[] = { source, NULL };
	FTS* const fts = fts_open(path_argv, FTS_PHYSICAL | FTS_XDEV, NULL);

	if (fts == NULL) {
		warnx("fts_open(\"%s\"): %s", source, strerror(errno));
		return -1;
	}

	int rv = -1;

	for (FTSENT* ent; (ent = fts_read(fts));) {
		char* const path = ent->fts_path;
		char* path_end = path + strlen(source);

		if (*path_end == '\0') {
			path_end = strrchr(path, '/');

			if (path_end == NULL) {
				path_end = path;
			}
		}

		char* CLEANUP_STR abs_path = NULL;
		if (asprintf(&abs_path, "%s/%s", target, path_end)) {}

		switch (ent->fts_info) {
		case FTS_DP:

			break; // ignore directories being visited in postorder

		case FTS_DOT:

			warnx("fts_read: Read a '.' or '..' entry, which shouldn't happen as the 'FTS_SEEDOT' option was not passed to 'fts_open'");
			break;

		case FTS_DNR:
		case FTS_ERR:
		case FTS_NS:

			warnx("fts_read: Failed to read '%s': %s", path, strerror(errno));
			break;

		case FTS_D:
		case FTS_DC: {}

			if (mkdir_recursive(abs_path) < 0) {
				goto err_mkdir;
			} 

			break;

		case FTS_SL:
		case FTS_SLNONE:
		case FTS_F:
		case FTS_DEFAULT:
		default:

			if (copyfile(path, abs_path, 0, COPYFILE_ALL) < 0) {
				warnx("copyfile(\"%s\", \"%s\"): %s", path, abs_path, strerror(errno));
				goto err_copy;
			}
		}
	}

	// success 🎉

	rv = 0;

err_copy:
err_mkdir:

	fts_close(fts);
	return rv;
}

static int chown_recursive(char* path, uid_t uid, gid_t gid) {
	char* const path_argv[] = { path, NULL };
	FTS* const fts = fts_open(path_argv, FTS_PHYSICAL | FTS_XDEV, NULL);

	if (fts == NULL) {
		warnx("fts_open(\"%s\"): %s", path, strerror(errno));
		return -1;
	}

	for (FTSENT* ent; (ent = fts_read(fts));) {
		char* const path = ent->fts_path; // shadow parent scope's 'path'

		switch (ent->fts_info) {
		case FTS_DP:

			break; // ignore directories being visited in postorder

		case FTS_DOT:

			warnx("fts_read: Read a '.' or '..' entry, which shouldn't happen as the 'FTS_SEEDOT' option was not passed to 'fts_open'");
			break;

		case FTS_DNR:
		case FTS_ERR:
		case FTS_NS:

			warnx("fts_read: Failed to read '%s': %s", path, strerror(errno));
			break;

		case FTS_SL:
		case FTS_SLNONE:
		case FTS_D:
		case FTS_DC:
		case FTS_F:
		case FTS_DEFAULT:
		default:

			if (chown(path, uid, gid) < 0) {
				warnx("chown(\"%s\", %d, %d): %s", path, uid, gid, strerror(errno));
			}
		}
	}

	fts_close(fts);
	return 0;
}
