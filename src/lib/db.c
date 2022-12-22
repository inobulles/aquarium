#include "../aquarium.h"

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

bool aquarium_next_db_ent(aquarium_opts_t* opts, aquarium_db_ent_t* ent, size_t buf_len, char buf[buf_len], FILE* fp, bool be_dramatic) {
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
