// #include <aquarium.h>
#include "../aquarium.h"
#include "copyfile.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENTROPY_BYTES 4096

static int update_fstab(aquarium_opts_t* opts, char const* _path) {
	int rv = -1;

	char* path;
	if (asprintf(&path, "%s/etc/fstab", _path)) {}

	FILE* const fp = fopen(path, "w");

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

	int const random_fd = open("/dev/random", O_RDONLY);

	if (random_fd < 0) {
		warnx("open(\"/dev/random\"): %s", strerror(errno));
		goto random_open_err;
	}

	// open entropy file

	char* path;
	asprintf(&path, "%s/boot/entropy", _path);

	int const fd = open(path, O_CREAT | O_WRONLY, 0600 /* read/write by owner (root) */);

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

int aquarium_img_populate_esp(char const* path, char const* stage) {
	int rv = -1;

	// create EFI directory structure

	char* stage_efi;
	if (asprintf(&stage_efi, "%s/EFI", stage)) {}

	if (mkdir(stage_efi, 0700) < 0) {
		warnx("mkdir(\"%s\", 0700): %s", stage_efi, strerror(errno));
		goto mkdir_stage_efi_err;
	}

	char* stage_efi_boot;
	if (asprintf(&stage_efi_boot, "%s/BOOT", stage_efi)) {}

	if (mkdir(stage_efi_boot, 0700) < 0) {
		warnx("mkdir(\"%s\", 0700): %s", stage_efi_boot, strerror(errno));
		goto mkdir_stage_efi_boot_err;
	}

	// copy over boot code

	char* loader;
	if (asprintf(&loader, "%s/boot/loader.efi", path)) {}

	int const loader_fd = open(loader, O_RDONLY);

	if (loader_fd < 0) {
		warnx("open(\"%s\"): %s", loader, strerror(errno));
		goto loader_open_err;
	}

	char* bootx64;
	if (asprintf(&bootx64, "%s/BOOTX64.EFI", stage_efi_boot)) {}

	int const bootx64_fd = creat(bootx64, 0660);

	if (bootx64_fd < 0) {
		warnx("create(\"%s\", 0660): %s", bootx64, strerror(errno));
		goto bootx64_open_err;
	}

	if (fcopyfile(loader_fd, bootx64_fd, 0, COPYFILE_ALL) < 0) {
		warnx("fcopyfile(\"%s\", \"%s\"): %s", loader, bootx64, strerror(errno));
		goto copy_err;
	}

	// success

	rv = 0;

copy_err:

	close(bootx64_fd);

bootx64_open_err:

	free(bootx64);
	close(loader_fd);

loader_open_err:

	free(loader);

mkdir_stage_efi_boot_err:

	free(stage_efi_boot);

mkdir_stage_efi_err:

	free(stage_efi);

	return rv;
}

static int create_esp(aquarium_opts_t* opts, char const* path) {
	int rv = -1;

	// create ESP stage

	char* stage = strdup("/tmp/aquarium-esp-stage-XXXXXXX");
	stage = mkdtemp(stage);

	if (!stage) {
		warnx("mkdtemp: failed to create ESP staging directory: %s", strerror(errno));
		goto mkdtemp_err;
	}

	// populate ESP

	if (aquarium_img_populate_esp(path, stage) < 0) {
		goto populate_err;
	}

	// create ESP image from stage

	pid_t pid = fork();

	if (!pid) {
		// child process
		// don't care about freeing anything in here

		char* oem_string_opt;
		if (asprintf(&oem_string_opt, "-oOEM_string=%s", opts->esp_oem)) {}

		char* label_opt;
		if (asprintf(&label_opt, "-ovolume_label=%s", opts->esp_vol_label)) {}

		execl(
			"/usr/sbin/makefs", "/usr/sbin/makefs",                // 'makefs' binary location
			"-tmsdos", "-ofat_type=12", "-osectors_per_cluster=1", // filesystem options
			"-s1m", oem_string_opt, label_opt,                     // more filesystem options
			"esp.img", stage,                                      // output/input paths
			NULL);

		_exit(EXIT_FAILURE);
	}

	int child_rv = __aquarium_wait_for_process(pid);

	if (child_rv < 0) {
		warnx("Child ESP image creation process exited with error code %d", child_rv);
		goto create_esp_err;
	}

	// success

	rv = 0;

create_esp_err:
populate_err:
mkdtemp_err:

	free(stage);

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

	// create ESP

	if (create_esp(opts, path) < 0) {
		return -1;
	}

	// TODO

	(void) out;

	return 0;
}
