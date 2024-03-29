// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2023 Aymeric Wibo

#include <aquarium.h>
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

	if (!mkdtemp(stage)) {
		warnx("mkdtemp: failed to create ESP staging directory: %s", strerror(errno));
		goto mkdtemp_err;
	}

	// populate ESP

	if (aquarium_img_populate_esp(path, stage) < 0) {
		goto populate_err;
	}

	// create ESP image from stage
	// use FAT12 - UEFI code seems to be fussy with FAT32 partitions generated by FreeBSD

	char const* const out = "esp.img";

	pid_t pid = fork();

	if (pid < 0) {
		warnx("fork: %s", strerror(errno));
		goto fork_err;
	}

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
			out, stage,                                            // output/input paths
			NULL);

		_exit(EXIT_FAILURE);
	}

	int const child_rv = __aquarium_wait_for_process(pid);

	if (child_rv != EXIT_SUCCESS) {
		warnx("Child ESP image creation process exited with error code %d", child_rv);
		goto create_esp_err;
	}

	if (chown(out, opts->initial_uid, opts->initial_gid) < 0) {
		warnx("chown(\"%s\", %d, %d): %s", out, opts->initial_uid, opts->initial_gid, strerror(errno));
		goto chown_err;
	}

	if (chmod(out, 0660) < 0) {
		warnx("chmod(\"%s\"): %s", out, strerror(errno));
		goto chmod_err;
	}

	// success

	rv = 0;

chmod_err:
chown_err:
create_esp_err:
fork_err:
populate_err:
mkdtemp_err:

	free(stage);

	return rv;
}

static int create_rootfs(aquarium_opts_t* opts, char const* path) {
	// create UFS2 rootfs image with the contents of the aquarium

	char const* const out = "rootfs.img";

	pid_t const pid = fork();

	if (pid < 0) {
		warnx("fork: %s", strerror(errno));
		return -1;
	}

	if (!pid) {
		// child process
		// don't care about freeing anything in here

		char* label_opt;
		if (asprintf(&label_opt, "-olabel=%s", opts->rootfs_label)) {}

		execl(
			"/usr/sbin/makefs", "/usr/sbin/makefs", // 'makefs' binary location
			"-ZBle", label_opt, "-oversion=2",      // filesystem options
			out, path,                              // output/input paths
			NULL);

		_exit(EXIT_FAILURE);
	}

	int child_rv = __aquarium_wait_for_process(pid);

	if (child_rv != EXIT_SUCCESS) {
		warnx("Child rootfs image creation process exited with error code %d", child_rv);
		return -1;
	}

	if (chown(out, opts->initial_uid, opts->initial_gid) < 0) {
		warnx("chown(\"%s\", %d, %d): %s", out, opts->initial_uid, opts->initial_gid, strerror(errno));
		return -1;
	}

	if (chmod(out, 0660) < 0) {
		warnx("chmod(\"%s\"): %s", out, strerror(errno));
		return -1;
	}

	return 0;
}

static int create_img(aquarium_opts_t* opts, char const* path, char const* out) {
	// combine 'esp.img' & 'rootfs.img' into a final bootable image

	pid_t const pid = fork();

	if (pid < 0) {
		warnx("fork: %s", strerror(errno));
		return -1;
	}

	if (!pid) {
		// child process
		// don't care about freeing anything in here

		char* pmbr;
		if (asprintf(&pmbr, "-b%s/boot/pmbr", path)) {}

		char* gptboot;
		if (asprintf(&gptboot, "-pfreebsd-boot/bootfs:=%s/boot/gptboot", path)) {}

		char* esp;
		if (asprintf(&esp, "-pefi/%s:=esp.img", opts->esp_label)) {}

		char* ufs;
		if (asprintf(&ufs, "-pfreebsd-ufs/%s:=rootfs.img", opts->rootfs_label)) {}

		execl(
			"/usr/bin/mkimg", "/usr/bin/mkimg", // 'mkimg' binary location
			"-sgpt", "-fraw",                   // partition table & image type options
			pmbr,                               // MBR bootcode (for legacy BIOS booting yeah)
			gptboot, esp, ufs,                  // different partitions
			"-o", out,                          // output path
			NULL);

		_exit(EXIT_FAILURE);
	}

	int child_rv = __aquarium_wait_for_process(pid);

	if (child_rv != EXIT_SUCCESS) {
		warnx("Child final bootable image creation process exited with error code %d", child_rv);
		return -1;
	}

	if (chown(out, opts->initial_uid, opts->initial_gid) < 0) {
		warnx("chown(\"%s\", %d, %d): %s", out, opts->initial_uid, opts->initial_gid, strerror(errno));
		return -1;
	}

	if (chmod(out, 0660) < 0) {
		warnx("chmod(\"%s\"): %s", out, strerror(errno));
		return -1;
	}

	return 0;
}

int aquarium_img_out(aquarium_opts_t* opts, char const* path, char const* out) {
	aquarium_os_t const os = aquarium_os_info(path);

	// check the OS is actually supported

	if (os != AQUARIUM_OS_FREEBSD) {
		warnx("Aquarium OS is unsupported (%d, only FreeBSD aquariums are currently supported)", os);
		// return -1;
	}

	// make sure everything is unmounted
	// this will (hopefully) fail if the aquarium is running (i.e. using the filesystems)

	if (aquarium_enter_setdown(path, os) < 0) {
		return -1;
	}

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

	// create rootfs

	if (create_rootfs(opts, path) < 0) {
		return -1;
	}

	// combine ESP & rootfs partitions into final bootable image

	if (create_img(opts, path, out) < 0) {
		return -1;
	}

	return 0;
}
