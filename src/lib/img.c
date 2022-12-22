// #include <aquarium.h>
#include "../aquarium.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENTROPY_BYTES 4096

static int update_fstab(aquarium_opts_t* opts, char const* _path) {
	int rv = -1;

	char* path;
	if (asprintf(&path, "%s/etc/fstab", _path)) {}

	FILE* fp = fopen(path, "w");

	if (!fp) {
		warnx("fopen(\"%s\"): %s", path, strerror(errno));
		goto err;
	}

	fprintf(fp, "/dev/gpt/%s / ufs ro,noatime 1 1\n", opts->rootfs_label);
	fprintf(fp, "/dev/gpt/%s /boot/efi msdosfs ro,noatime 0 0\n", opts->esp_label);

	fclose(fp);

	// success

	rv = 0;

err:

	free(path);

	return rv;
}

static int gen_entropy(char const* _path) {
	int rv = 0;

	// open random device

	int random_fd = open("/dev/random", O_RDONLY);

	if (random_fd < 0) {
		warnx("open(\"/dev/random\"): %s", strerror(errno));
		goto random_open_err;
	}

	// open entropy file

	char* path;
	asprintf(&path, "%s/boot/entropy", _path);

	int fd = open(path, O_CREAT | O_WRONLY, 0600 /* read/write by owner (root) */);

	if (fd < 0) {
		warnx("open(\"%s\"): %s", path, strerror(errno));
		goto entropy_open_err;
	}

	uint8_t entropy[ENTROPY_BYTES];

	if (read(random_fd, entropy, sizeof entropy) != sizeof entropy) {
		warnx("read: %s", strerror(errno));
		goto read_err;
	}

	if (write(fd, entropy, sizeof entropy) != sizeof entropy) {
		warnx("write: %s", strerror(errno));
		goto write_err;
	}

	// success

	rv = 0;

write_err:
read_err:

	close(fd);

entropy_open_err:

	close(random_fd);
	free(path);

random_open_err:

	return rv;
}

int aquarium_img_out(aquarium_opts_t* opts, char const* _path, char const* out) {
	char* const path = aquarium_db_read_pointer_file(opts, _path);

	if (!path) {
		return -1;
	}

	// TODO make sure aquarium is unmounted, once I've implemented all the entering stuff
	// TODO check the OS is actually supported

	// add necessary entries to fstab

	if (update_fstab(opts, path) < 0) {
		return -1;
	}

	// generate entropy

	if (gen_entropy(path) < 0) {
		return -1;
	}

	return 0;
}
