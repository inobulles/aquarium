// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2023 Aymeric Wibo

#include <aquarium.h>
#include "sanctioned.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <copyfile.h>

int aquarium_create_struct(aquarium_opts_t* opts) {
	int rv = -1;

	// build filestructure if it doesn't yet exist for convenience
	// also create a sanctioned templates file with some default and trusted entries

	if (opts->initial_uid && setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		return -1;
	}

	// try making the directory structure 

	#define SET_PERMS(path, mode) { \
		struct stat sb; \
		\
		if (stat((path), &sb) < 0) { \
			warnx("stat(\"%s\"): %s", (path), strerror(errno)); \
			goto err; \
		} \
		\
		bool const owner_correct = sb.st_uid == 0 && sb.st_gid == opts->stoners_gid; \
		bool const mode_correct = (sb.st_mode & 0777) == (mode); \
		\
		if (!owner_correct && chown((path), 0, opts->stoners_gid) < 0) { \
			warnx("chown(\"%s\", 0, %d): %s", (path), opts->stoners_gid, strerror(errno)); \
			goto err; \
		} \
		\
		\
		if (!mode_correct && chmod((path), (mode)) < 0) { \
			warnx("chmod(\"%s\", 0, 0%o): %s", (path), (mode), strerror(errno)); \
			goto err; \
		} \
	}


	// 0770: execute access is required to list directory

	#define TRY_MKDIR(path) \
		if (mkdir((path), 0770) < 0 && errno != EEXIST) { \
			warnx("mkdir(\"%s\", 0%o): %s", (path), 0770, strerror(errno)); \
			goto err; \
		} \
		\
		SET_PERMS((path), 0770)

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

	SET_PERMS(opts->sanctioned_path, 0660)

	// try creating aquarium database file

	if (access(opts->db_path, R_OK) < 0) {
		int const fd = creat(opts->db_path, 0660);

		if (fd < 0) {
			warnx("creat(\"%s\", 0660): %s", opts->db_path, strerror(errno));
		}

		close(fd);
	}

	SET_PERMS(opts->db_path, 0660)

	// success

	rv = 0;

err:

	if (opts->initial_uid && setreuid(opts->initial_uid, 0) < 0) {
		warnx("setreuid(%d): %s", opts->initial_uid, strerror(errno));
		rv = -1;
	}

	return rv;
}

static char* setup_script_unix(char* hostname) {
	char* script;

	if (asprintf(&script,
		"#!/bin/sh\n"
		"set -e;"

		"hostname=%s;"

		"echo $hostname > /etc/hostname;"
		"echo 127.0.0.1 $hostname >> /etc/hosts;",
	hostname)) {}

	return script;
}

static char* setup_script_freebsd(char* hostname) {
	return setup_script_unix(hostname);
}

static char* setup_script_ubuntu(char* hostname) {
	char* const unix_script = setup_script_unix(hostname);
	char* script;

	if (asprintf(&script, "%s"
		// fix APT defaults

		"echo APT::Cache-Start \\\"100000000\\\"\\; >> /etc/apt/apt.conf.d/10cachestart;"
		"sed -i 's/$/\\ universe/' /etc/apt/sources.list;"

		// broken symlink (symbolic, not hard!) which needs to be fixed for the dynamic linker to work

		"ln -sf ../lib/x86_64-linux-gnu/ld-2.31.so /lib64/ld-linux-x86-64.so.2;",
	unix_script)) {}

	free(unix_script);
	return script;
}

static int setup_enter_cb(void* param) {
	char* script = param;

	execl("/bin/sh", "/bin/sh", "-c", script, NULL);
	_exit(EXIT_FAILURE);
}

static int config(aquarium_opts_t* opts, char* path) {
	// copy over /etc/resolv.conf so we don't have to use DHCP when using the host's interface

	if (copyfile("/etc/resolv.conf", "etc/resolv.conf", 0, COPYFILE_ALL) < 0) {
		warnx("copyfile: %s", strerror(errno));
		return -1;
	}

	int rv = -1;

	// enter the newly created aquarium to do a bit of configuration
	// we can't do this is all in C, because, well, there's a chance the template is not the operating system we're currently running
	// this does thus depend a lot on the platform we're running on
	// the solution here is to generate an initial setup script depending on the aquarium's OS, which we then run in the aquarium

	char* name = strrchr(path, '/');

	if (!name) {
		name = path;
	}

	// create OS-specific setup script
	// TODO we shouldn't be simply using the name of the aquarium as a hostname

	aquarium_os_t const os = aquarium_os_info(path);
	char* setup_script = NULL;

	if (os == AQUARIUM_OS_FREEBSD && !(setup_script = setup_script_freebsd(name))) {
		goto setup_script_err;
	}

	if (os == AQUARIUM_OS_UBUNTU && !(setup_script = setup_script_ubuntu(name))) {
		goto setup_script_err;
	}

	// if no setup script, just go to 'setup_script_err' successfully

	if (!setup_script) {
		rv = 0;
		goto setup_script_err;
	}

	// enter the jail in a separate process & run that script
	// TODO make sure there's nothing crazy in opts
	//      I guess it's always possible for the user to accidentally pass in e.g. -v to aquarium -c

	pid_t pid = fork();

	if (pid < 0) {
		warnx("fork: %s", strerror(errno));
		goto fork_err;
	}

	if (!pid) {
		if (aquarium_enter(opts, path, setup_enter_cb, setup_script) < 0) {
			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	int const child_rv = __aquarium_wait_for_process(pid);

	if (child_rv != EXIT_SUCCESS) {
		warnx("Child configuration process exited with error code %d", child_rv);
		goto enter_err;
	}

	// success

	rv = 0;

enter_err:
fork_err:

	free(setup_script);

setup_script_err:

	return rv;
}

int aquarium_create(aquarium_opts_t* opts, char const* pointer_path, char const* template, char const* kernel_template) {
	int rv = -1;

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

	char* _path;
	if (asprintf(&_path, "%s/%s-XXXXXXX", opts->aquariums_path, template)) {}

	char* const path = strdup(_path);

	if (!mkdtemp(path)) {
		warnx("mkdtemp(\"%s\"): failed to create aquarium directory: %s", _path, strerror(errno));
		goto mkdtemp_err;
	}

	// check that pointer file isn't already in the aquarium database
	// if it doesn't yet exist, the 'realpath' call will fail (which we don't want if 'flags & FLAGS_CREATE')
	// although it's cumbersome, I really wanna use realpath here to reduce points of failure
	// to be honest, I think it's a mistake not to have included a proper way of checking path hierarchy in POSIX
	// TODO haven't yet thought about how safe this'd be, but since the aquarium database also contains what the pointer file was supposed to point to, maybe it could be cool for this to automatically regenerate the pointer file instead of erroring?

	if (!access(pointer_path, F_OK)) {
		warnx("Pointer file %s already exists", pointer_path);
		goto pointer_file_exists_err;
	}

	int const fd = creat(pointer_path, 0 /* don't care about mode */);

	if (fd < 0) {
		warnx("creat(\"%s\"): %s", pointer_path, strerror(errno));
		goto creat_err;
	}

	char* const abs_path = realpath(pointer_path, NULL);

	close(fd);
	remove(pointer_path);

	if (!abs_path) {
		warnx("realpath(\"%s\"): %s", pointer_path, strerror(errno));
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

	if (opts->initial_uid && setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		goto setuid_root_err;
	}

	// extract templates

	if (template && aquarium_extract_template(opts, path, template, AQUARIUM_TEMPLATE_KIND_BASE) < 0) {
		goto extract_template_err;
	}

	if (kernel_template && aquarium_extract_template(opts, path, kernel_template, AQUARIUM_TEMPLATE_KIND_KERNEL) < 0) {
		goto extract_template_err;
	}

	// write info to aquarium database

	FILE* const db_fp = fopen(opts->db_path, "a");

	if (!db_fp) {
		warnx("fopen: failed to open %s for writing: %s", opts->db_path, strerror(errno));
		goto db_open_err;
	}

	fprintf(db_fp, "%s:%s\n", abs_path, path);

	// configure the newly created aquarium

	if (config(opts, path) < 0) {
		goto config_err;
	}

	// finish writing pointer file as user

	if (opts->initial_uid && setreuid(opts->initial_uid, 0) < 0) {
		warnx("setreuid(%d, 0): %s", opts->initial_uid, strerror(errno));
		goto setuid_user_err;
	}

	// change back to where we were & write to pointer file

	if (chdir(cwd) < 0) {
		warnx("chdir(\"%s\"): %s", cwd, strerror(errno));
	}

	FILE* const pointer_fp = fopen(pointer_path, "wx");

	if (!pointer_fp) {
		warnx("fopen: failed to open %s for writing: %s", pointer_path, strerror(errno));
		goto pointer_open_err;
	}

	fprintf(pointer_fp, "%s", path);

	// success

	rv = 0;

	fclose(pointer_fp);

	// try set ownership of pointer file to the user who's UID is the current real UID
	// we don't want to do this if the real UID is root (0), so check 'opts->stoners_gid' (which is 0 when root)

	if (opts->stoners_gid && chown(pointer_path, opts->initial_uid, opts->stoners_gid) < 0) {
		warnx("chown(\"%s\", %d, %d\"): %s", pointer_path, opts->initial_uid, opts->stoners_gid, strerror(errno));
		rv = -1;
	}

pointer_open_err:
setuid_user_err:
config_err:

	fclose(db_fp);

db_open_err:
extract_template_err:

	if (opts->initial_uid && setreuid(opts->initial_uid, 0) < 0) {
		warnx("setreuid(%d, 0): %s", opts->initial_uid, strerror(errno));
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

mkdtemp_err:

	free(path);
	free(_path);

	if (chdir(cwd) < 0) {
		warnx("chdir(\"%s\"): %s", cwd, strerror(errno));
	}

	free(cwd);

getcwd_err:

	return rv;
}
