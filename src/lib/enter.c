// #include <aquarium.h>
#include "../aquarium.h" 
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fs/devfs/devfs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioccom.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <unistd.h>

static int devfs_ruleset(void) {
	int rv = -1;

	// we necessarily need to start by hiding everything for some reason

	int const devfs_fd = open("dev", O_RDONLY);

	if (devfs_fd < 0) {
		warnx("open(\"dev\"): %s", strerror(errno));
		goto open_err;
	}

	devfs_rsnum ruleset = 1; // devfsrules_hide_all

	if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &ruleset) < 0) {
		warnx("DEVFSIO_SAPPLY: %s", strerror(errno));
		goto devfsio_err;
	}

	ruleset = 2; // devfsrules_unhide_basic

	if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &ruleset) < 0) {
		warnx("DEVFSIO_SAPPLY: %s", strerror(errno));
		goto devfsio_err;
	}

	ruleset = 3; // devfsrules_unhide_login

	if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &ruleset) < 0) {
		warnx("DEVFSIO_SAPPLY: %s", strerror(errno));
		goto devfsio_err;
	}

	ruleset = 5; // devfsrules_jail_vnet

	if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &ruleset) < 0) {
		warnx("DEVFSIO_SAPPLY: %s", strerror(errno));
		goto devfsio_err;
	}

	// success

	rv = 0;

devfsio_err:

	close(devfs_fd);

open_err:

	return rv;
}

int aquarium_enter(aquarium_opts_t* opts, char const* path) {
	int rv = -1;

	// remember our current working directory for later

	char* const cwd = getcwd(NULL, 0);

	if (!cwd) {
		warnx("getcwd: %s", strerror(errno));
		goto getcwd_err;
	}

	// change into the aquarium directory

	if (chdir(path) < 0) {
		warnx("chdir(\"%s\"): %s", path, strerror(errno));
		goto chdir_err;
	}

	// setuid root

	uid_t const uid = getuid();

	if (setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		goto setuid_root_err;
	}

	// mount devfs filesystem

	struct iovec iov_dev[] = {
		__AQUARIUM_IOV("fstype", "devfs"),
		__AQUARIUM_IOV("fspath", "dev"),
	};

	if (nmount(iov_dev, sizeof(iov_dev) / sizeof(*iov_dev), 0) < 0) {
		warnx("nmount: failed to mount devfs: %s", strerror(errno));
		goto mount_devfs_err;
	}

	// set the correct ruleset for devfs

	if (devfs_ruleset() < 0) {
		goto devfs_ruleset_err;
	}

	// success

	rv = 0;

devfs_ruleset_err:

	if (unmount("dev", 0) < 0) {
		warnx("unmount(\"dev\"): %s", strerror(errno));
		rv = -1;
	}

mount_devfs_err:

	if (setuid(uid) < 0) {
		warnx("setuid(%d): %s", uid, strerror(errno));
		rv = -1;
	}

setuid_root_err:

	if (chdir(cwd) < 0) {
		warnx("chdir(\"%s\"): %s", cwd, strerror(errno));
		rv = -1;
	}

chdir_err:

	free(cwd);

getcwd_err:

	return rv;
}
