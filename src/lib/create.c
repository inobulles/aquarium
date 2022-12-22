// #include <aquarium.h>
#include "../aquarium.h"
#include "sanctioned.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <copyfile.h>

static int ensure_struct(aquarium_opts_t* opts) {
	int rv = -1;

	// build filestructure if it doesn't yet exist for convenience
	// also create a sanctioned templates file with some default and trusted entries

	uid_t const uid = getuid();

	if (setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		return -1;
	}

	// try making the directory structure 

	mode_t const MODE = 0770; // rwx for owner (root), rwx for group (stoners, execute access is required to list directory)

	#define SET_PERMS(path) \
		if (opts->stoners_gid && chown((path), 0, opts->stoners_gid) < 0) { \
			warnx("chown(\"%s\", 0, %d): %s", (path), opts->stoners_gid, strerror(errno)); \
			goto err; \
		} \
		\
		if (chmod((path), MODE) < 0) { \
			warnx("chmod(\"%s\", 0, 0%o): %s", (path), MODE, strerror(errno)); \
			goto err; \
		}

	#define TRY_MKDIR(path) \
		if (mkdir((path), MODE) < 0 && errno != EEXIST) { \
			warnx("mkdir(\"%s\", 0%o): %s", (path), MODE, strerror(errno)); \
			goto err; \
		} \
		\
		SET_PERMS((path))

	TRY_MKDIR(opts->base_path)
	TRY_MKDIR(opts->templates_path)
	TRY_MKDIR(opts->kernels_path)
	TRY_MKDIR(opts->aquariums_path)

	// try creating sanctioned templates file

	if (access(opts->sanctioned_path, R_OK) < 0) {
		FILE* const fp = fopen(opts->sanctioned_path, "wx");

		if (!fp) {
			warnx("fopen(\"%s\"): %s", opts->sanctioned_path, strerror(errno));
			goto err;
		}

		fprintf(fp, SANCTIONED);
		fclose(fp);
	}

	SET_PERMS(opts->sanctioned_path)

	// try creating aquarium database file

	if (access(opts->db_path, R_OK) < 0) {
		int const fd = creat(opts->db_path, MODE);

		if (!fd) {
			warnx("creat(\"%s\", 0%o): %s", opts->db_path, MODE, strerror(errno));
		}

		close(fd);
	}

	SET_PERMS(opts->db_path)

	// success

	rv = 0;

err:

	if (setuid(uid) < 0) {
		warnx("setuid(%d): %s", uid, strerror(errno));
		rv = -1;
	}

	return rv;
}

int create_aquarium(aquarium_opts_t* opts, char const* path, char const* template, char const* kernel_template) {
	int rv = -1;

	// make sure aquarium structure exists

	if (ensure_struct(opts) < 0) {
		return -1;
	}

	// make sure our template is legal

	if (*template == AQUARIUM_ILLEGAL_TEMPLATE_PREFIX) {
		return -1;
	}

	// remember our current working directory for later

	char* const cwd = getcwd(NULL, 0);

	if (!cwd) {
		warnx("getcwd: %s", strerror(errno));
		goto getcwd_err;
	}

	// generate final aquarium path

	char* _aquarium_path;
	if (asprintf(&_aquarium_path, "%s%s-XXXXXXX", opts->aquariums_path, template)) {}

	char* const aquarium_path = mkdtemp(_aquarium_path);
	free(_aquarium_path);

	if (!aquarium_path) {
		warnx("mkdtemp(\"%s\"): failed to create aquarium directory: %s", _aquarium_path, strerror(errno));
		goto mkdtemp_err;
	}

	// check that pointer file isn't already in the aquarium database
	// if it doesn't yet exist, the 'realpath' call will fail (which we don't want if 'flags & FLAGS_CREATE')
	// although it's cumbersome, I really wanna use realpath here to reduce points of failure
	// to be honest, I think it's a mistake not to have included a proper way of checking path hierarchy in POSIX
	// TODO haven't yet thought about how safe this'd be, but since the aquarium database also contains what the pointer file was supposed to point to, maybe it could be cool for this to automatically regenerate the pointer file instead of erroring?

	if (!access(path, F_OK)) {
		warnx("Pointer file %s already exists", path);
		goto pointer_file_exists_err;
	}

	int const fd = creat(path, 0 /* don't care about mode */);

	if (!fd) {
		warnx("creat(\"%s\"): %s", path, strerror(errno));
		goto creat_err;
	}

	char* const abs_path = realpath(path, NULL);

	close(fd);
	remove(path);

	if (!abs_path) {
		warnx("realpath(\"%s\"): %s", path, strerror(errno));
		goto abs_path_err;
	}

	FILE* const fp = fopen(opts->db_path, "r");

	if (!fp) {
		warnx("fopen: failed to open %s for reading: %s", opts->db_path, strerror(errno));
		goto db_read_err;
	}

	char buf[1024];
	aquarium_db_ent_t ent;

	while (aquarium_db_next_ent(opts, &ent, sizeof buf, buf, fp, true)) {
		if (!strcmp(ent.pointer_path, abs_path)) {
			warnx("Pointer file already exists in the aquarium database at %s (pointer file is supposed to reside at %s and point to %s)", opts->db_path, ent.pointer_path, ent.aquarium_path);
			goto pointer_file_exists_db_err;
		}
	}

	// setuid root

	uid_t const uid = getuid();

	if (setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		goto setuid_root_err;
	}

	// extract templates

	if (template && aquarium_extract_template(opts, aquarium_path, template, AQUARIUM_TEMPLATE_KIND_BASE) < 0) {
		goto extract_template_err;
	}

	if (kernel_template && aquarium_extract_template(opts, aquarium_path, kernel_template, AQUARIUM_TEMPLATE_KIND_KERNEL) < 0) {
		goto extract_template_err;
	}

	// copy over /etc/resolv.conf so we don't have to use DHCP when using the host's interface

	if (copyfile("/etc/resolv.conf", "etc/resolv.conf", 0, COPYFILE_ALL) < 0) {
		warnx("copyfile: %s", strerror(errno));
		goto resolv_copy_err;
	}

	// write info to aquarium database

	FILE* const db_fp = fopen(opts->db_path, "a");

	if (!db_fp) {
		warnx("fopen: failed to open %s for writing: %s", opts->db_path, strerror(errno));
		goto db_open_err;
	}

	fprintf(db_fp, "%s:%s\n", abs_path, aquarium_path);

	// finish writing pointer file as user

	if (setuid(uid) < 0) {
		warnx("setuid(%d): %s", uid, strerror(errno));
		goto setuid_user_err;
	}

	// change back to where we were & write to pointer file

	if (chdir(cwd) < 0) {
		warnx("chdir(\"%s\"): %s", cwd, strerror(errno));
	}

	FILE* pointer_fp = fopen(path, "wx");

	if (!pointer_fp) {
		warnx("fopen: failed to open %s for writing: %s", path, strerror(errno));
		goto pointer_open_err;
	}

	fprintf(pointer_fp, "%s", aquarium_path);

	// success

	rv = 0;

	fclose(pointer_fp);

pointer_open_err:
setuid_user_err:

	fclose(db_fp);

db_open_err:
resolv_copy_err:
extract_template_err:

	if (setuid(uid) < 0) {
		warnx("setuid(%d): %s", uid, strerror(errno));
		rv = -1;
	}

setuid_root_err:
pointer_file_exists_db_err:

	fclose(fp);

db_read_err:

	free(abs_path);

abs_path_err:
creat_err:
pointer_file_exists_err:

	free(aquarium_path);

mkdtemp_err:

	if (chdir(cwd) < 0) {
		warnx("chdir(\"%s\"): %s", cwd, strerror(errno));
	}

	free(cwd);

getcwd_err:

	return rv;
}
