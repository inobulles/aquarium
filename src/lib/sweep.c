// #include <aquarium.h>
#include "../aquarium.h"
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int remove_aquarium(char* path) {
	// first, make sure all possible mounted filesystems are unmounted
	// if this fails, try to remove things anyway

	aquarium_os_t const os = aquarium_os_info(path);
	int rv = aquarium_enter_setdown(path, os);

	// then, we remove all the aquarium files
	// the aquarium may have already been deleted (e.g. by a nosy user)
	// so we don't wanna do anything with the return value of '__aquarium_wait_for_process'
	// TODO I desperately need some easy API for removing files in the standard library on aquaBSD
	//      I'm not (I hope) dumb enough to do something like 'asprintf(&cmd, "rm -rf %s", ent.aquarium_path)', but I know damn well other developers would be tempted to do such a thing given no other alternative

	pid_t pid = fork();

	if (pid < 0) {
		warnx("fork: %s", strerror(errno));
		return -1;
	}

	if (!pid) {
		execl("/bin/rm", "/bin/rm", "-rf", path, NULL);
		_exit(EXIT_FAILURE);
	}

	__aquarium_wait_for_process(pid);
	return rv;
}

int aquarium_sweep(aquarium_opts_t* opts) {
	int rv = -1;

	// go through aquarium database

	FILE* const fp = fopen(opts->db_path, "rw");

	if (!fp) {
		warnx("fopen(\"%s\"): %s", opts->db_path, strerror(errno));
		goto open_err;
	}

	// list of database entries which survive the sweep

	size_t survivors_len = 0;
	aquarium_db_ent_t* survivors = NULL;

	char buf[1024];
	aquarium_db_ent_t ent;

	while (aquarium_db_next_ent(opts, &ent, sizeof buf, buf, fp, false)) {
		// if something went wrong reading an entry (e.g. it's malformed), simply discard it
		// there is a chance then that some aquariums or pointer files will be left behind, but eh rather that than risk deleting something we shouldn't
		// also, under normal operation, this kind of condition shouldn't occur

		if (!ent.pointer_path || !ent.aquarium_path) {
			continue;
		}

		// if we can't find pointer file, remove the aquarium and that entry from the aquarium database

		if (access(ent.pointer_path, F_OK) < 0) {
			remove_aquarium(ent.aquarium_path);

			// discard this entry obviously, we don't want nuffin to do with it no more 😡

			continue;
		}

		// if we can't find aquarium, remove the pointer file and that entry from the aquarium database
		// not sure under which circumstances this kind of stuff could happen, but handle it anyway

		if (access(ent.aquarium_path, F_OK) < 0) {
			// attempt to remove the pointer file
			// we don't care to do anything on error, because the file may very well have already been removed by the user

			remove(ent.pointer_path);

			// discard this entry &c &c

			continue;
		}

		// congratulations to the database entry! 🎉
		// it has survived unto the next sweep!

		survivors = realloc(survivors, (survivors_len + 1) * sizeof *survivors);
		aquarium_db_ent_t* const survivor = &survivors[survivors_len++];

		survivor->pointer_path  = strdup(ent.pointer_path);
		survivor->aquarium_path = strdup(ent.aquarium_path);
	}

	// keep things nice and clean is to go through everything under /etc/aquariums/aquariums and see which aquariums were never "recensés" (censused?)

	DIR* const dp = opendir(opts->aquariums_path);

	if (!dp) {
		warnx("opendir: %s", strerror(errno));
		goto opendir_err;
	}

	struct dirent* dir_ent;

	while ((dir_ent = readdir(dp))) {
		char* const name = dir_ent->d_name;

		if (!strcmp(name, ".") || !strcmp(name, "..")) {
			continue;
		}

		for (size_t i = 0; i < survivors_len; i++) {
			aquarium_db_ent_t* const survivor = &survivors[i];
			char* aquarium = strrchr(survivor->aquarium_path, '/');

			aquarium += !!*aquarium;

			if (!strcmp(aquarium, name)) {
				goto found;
			}
		}

		// ah! couldn't find the aquarium in the list of survivors! remove it!

		char* aquarium_path;
		asprintf(&aquarium_path, "%s/%s", opts->aquariums_path, name);

		remove_aquarium(aquarium_path);
		free(aquarium_path);

	found:

		continue; // need something after a label in C for some reason
	}

	// last thing to do is rebuild new aquarium database file with the entries that survived

	for (size_t i = 0; i < survivors_len; i++) {
		aquarium_db_ent_t* const survivor = &survivors[i];
		fprintf(fp, "%s:%s\n", survivor->pointer_path, survivor->aquarium_path);
	}

	// success

	rv = 0;

	closedir(dp);

opendir_err:

	for (size_t i = 0; i < survivors_len; i++) {
		aquarium_db_ent_t* const survivor = &survivors[i];

		free(survivor->pointer_path);
		free(survivor->aquarium_path);
	}

	if (survivors) {
		free(survivors);
	}

	fclose(fp);

open_err:

	return rv;
}
