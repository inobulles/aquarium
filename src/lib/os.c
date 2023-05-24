#include <aquarium.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/linker.h>

aquarium_os_t aquarium_os_info(char const* _path) {
	// this method of retrieving OS info relies on the existence of an '/etc/os-release' file on the installation
	// all officially supported OS' for aquariums should have this file, else they'll simply be reported as 'OS_GENERIC'
	// if 'path == NULL', assume we're already in the aquarium, and just use the relative path for '/etc/os-release'
	// TODO find a better way of detecting OS', because this isn't gonna cut it

	char* path = "etc/os-release";

	if (_path) {
		if (asprintf(&path, "%s/etc/os-release", _path)) {}
	}

	FILE* const fp = fopen(path, "r");

	if (_path) {
		free(path);
	}

	if (!fp) {
		return AQUARIUM_OS_FREEBSD; // AQUARIUM_OS_GENERIC;
	}

	char buf[1024];
	char* os = fgets(buf, sizeof buf, fp);

	os += strlen("NAME=\"");
	os[strlen(os) - 2] = '\0';

	fclose(fp);

	// match NAME with an OS we know of

	if (!strstr(os, "FreeBSD")) {
		return AQUARIUM_OS_FREEBSD;
	}

	if (!strstr(os, "Ubuntu")) {
		return AQUARIUM_OS_UBUNTU;
	}

	return AQUARIUM_OS_FREEBSD; // AQUARIUM_OS_GENERIC;
}

static int load_kmod(char const* name) {
	if (!kldload(name)) {
		return 0;
	}

	if (errno == EEXIST) {
		return 0;
	}

	// jammer, iets is fout gegaan

	if (errno == ENOEXEC) {
		warnx("kldload(\"%s\"): please check dmesg(8) for details (or don't, I'm not your mum)", name);
		return -1;
	}

	warnx("kldload(\"%s\"): %s", name, strerror(errno));
	return -1;
}

int aquarium_os_load_linux64_kmod(void) {
	return load_kmod("linux64");
}
