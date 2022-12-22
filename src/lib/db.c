#include "../aquarium.h"

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool aquarium_db_next_ent(aquarium_opts_t* opts, aquarium_db_ent_t* ent, size_t buf_len, char buf[buf_len], FILE* fp, bool be_dramatic) {
	char* line = fgets(buf, buf_len, fp);

	if (!line) {
		return false;
	}

	// remove potential trailing newline

	size_t const end_i = strlen(line) - 1;

	if (line[end_i] == '\n') {
		line[end_i] = '\0';
	}

	// parse tokens

	char* const pointer_path  = strsep(&line, ":");
	char* const aquarium_path = strsep(&line, ":");

	if (be_dramatic && (!pointer_path || !aquarium_path)) {
		warnx("Aquarium database file %s has an invalid format", opts->db_path);
	}

	ent->pointer_path  = pointer_path;
	ent->aquarium_path = aquarium_path;

	return true;
}

char* aquarium_db_read_pointer_file(aquarium_opts_t* opts, char const* path) {
	// spaghetti code 🍝

	char* aquarium_path = NULL;

	// read the pointer file

	FILE* const fp = fopen(path, "r");

	if (!fp) {
		warnx("fopen: failed to open %s for reading: %s", path, strerror(errno));
		goto open_err;
	}

	fseek(fp, 0, SEEK_END);
	size_t const len = ftell(fp);

	rewind(fp);

	aquarium_path = malloc(len + 1);
	aquarium_path[len] = 0;

	if (fread(aquarium_path, 1, len, fp) != len) {
		warnx("fread: %s", strerror(errno));

		free(aquarium_path);
		aquarium_path = NULL;

		goto read_err;
	}

	// make sure the path of the pointer file is well the one contained in the relevant entry of the aquarium database

	char* const abs_path = realpath(path, NULL);

	if (!abs_path) {
		warnx("realpath(\"%s\"): %s", path, strerror(errno));

		free(aquarium_path);
		aquarium_path = NULL;

		goto realpath_err;
	}

	FILE* db_fp = fopen(opts->db_path, "r");

	if (!db_fp) {
		warnx("fopen: failed to open %s for reading: %s", opts->db_path, strerror(errno));

		free(aquarium_path);
		aquarium_path = NULL;

		goto db_open_err;
	}

	char buf[1024];
	aquarium_db_ent_t ent;

	while (aquarium_db_next_ent(opts, &ent, sizeof buf, buf, fp, true)) {
		if (strcmp(ent.pointer_path, abs_path)) {
			continue;
		}

		if (strcmp(ent.aquarium_path, aquarium_path)) {
			warnx("Found pointer file in the aquarium database, but it doesn't point to the correct aquarium (%s vs %s)", aquarium_path, ent.aquarium_path);

			free(aquarium_path);
			aquarium_path = NULL;

			goto wrong_pointer_err;
		}

		goto found;
	}

	warnx("Could not find pointer file %s in the aquarium database", abs_path);

	free(aquarium_path);
	aquarium_path = NULL;

found:

	fclose(db_fp);

wrong_pointer_err:
db_open_err:

	free(abs_path);

realpath_err:
read_err:

	fclose(fp);

open_err:

	return aquarium_path;
}
