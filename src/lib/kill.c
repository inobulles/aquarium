// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2025 Aymeric Wibo

#include <aquarium.h>

#include <errno.h>
#include <jail.h>
#include <string.h>
#include <sys/jail.h>

int aquarium_kill(char const* path) {
	int rv = -1;

	// Find aquarium path hash.
	// This is what's used to refer to the aquarium's jail by name.

	char* const hash = __aquarium_hash(path);

	if (!hash) {
		warnx("Failed to hash '%s'", path);
		goto hash_err;
	}

	// Attempt to get the jail ID.

	int const jid = jail_getid(hash);

	if (jail_remove(jid) < 0) {
		warnx("jail_remove: %s", strerror(errno));
		goto jail_remove_err;
	}

	// TODO It would be very nice if we could also destroy the epair if we created one, but idk where we'd find that.

	rv = 0;

jail_remove_err:

	free(hash);

hash_err:

	return rv;
}
