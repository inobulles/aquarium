// #include <aquarium.h>
#include "../aquarium.h" 
#include <stdlib.h>
#include <string.h>

aquarium_os_info_t aquarium_os_info(char const* _path) {
	// this method of retrieving OS info relies on the existence of an '/etc/os-release' file on the installation
	// all officially supported OS' for aquariums should have this file, else they'll simply be reported as 'OS_GENERIC'
	// if 'path == NULL', assume we're already in the aquarium, and just use the relative path for '/etc/os-release'

	char* path = "etc/os-release";

	if (_path) {
		if (asprintf(&path, "%s/etc/os-release", _path)) {}
	}

	FILE* const fp = fopen(path, "r");

	if (_path) {
		free(path);
	}

	if (!fp) {
		return AQUARIUM_OS_GENERIC;
	}

	char buf[1024];
	char* os = fgets(buf, sizeof buf, fp);

	os += strlen("NAME=\"");
	os[strlen(os) - 2] = '\0';

	fclose(fp);

	// match NAME with an OS we know of

	if (!strcmp(os, "FreeBSD")) {
		return AQUARIUM_OS_FBSD;
	}

	if (!strcmp(os, "Ubuntu")) {
		return AQUARIUM_OS_LINUX;
	}

	return AQUARIUM_OS_GENERIC;
}
