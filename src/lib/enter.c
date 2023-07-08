#include <aquarium.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <fs/devfs/devfs.h>
#include <jail.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioccom.h>
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/procctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <unistd.h>

#define TRY_UMOUNT(mountpoint) \
	if (!access((mountpoint), F_OK) && recursive_umount((mountpoint)) < 0) { \
		rv = -1; \
	}

#define JAILPARAM(key, val) \
	jailparam_init  (&args[args_len], (key)); \
	jailparam_import(&args[args_len], (val)); \
	\
	args_len++;

#define ILLEGAL_HOSTNAME_CHAR(h) ((h) == '.' || (h) == ' ' || (h) == '/')

static int is_mountpoint(char* path) {
	struct stat sb;

	// get the device id of the path

	if (stat(path, &sb) < 0) {
		warnx("stat(\"%s\"): %s", path, strerror(errno));
		return -1;
	}

	int const inside_id = sb.st_dev;

	// get the device id of the parent of that path

	char* parent;
	if (asprintf(&parent, "%s/..", path)) {}

	if (stat(parent, &sb) < 0) {
		warnx("stat(\"%s\"): %s", parent, strerror(errno));

		free(parent);
		return -1;
	}

	free(parent);
	int const outside_id = sb.st_dev;

	// if the id's are different, we have ourselves a mountpoint

	return inside_id != outside_id;
}

static int recursive_umount(char* path) {
	// loop, trying to unmount until we either get an error, or the path isn't a mountpoint anymore

	for (;;) {
		int const mountpoint = is_mountpoint(path);

		if (mountpoint < 0) {
			return -1;
		}

		if (!mountpoint) {
			return 0;
		}

		// XXX is there a reason I *shouldn't* be using 'MNT_FORCE'?

		if (unmount(path, MNT_FORCE) < 0) {
			warnx("unmount(\"%s\"): %s", path, strerror(errno));
			return -1;
		}
	}
}

static int devfs_ruleset(aquarium_opts_t* opts) {
	int rv = -1;

	int const devfs_fd = open("dev", O_RDONLY);

	if (devfs_fd < 0) {
		warnx("open(\"dev\"): %s", strerror(errno));
		goto open_err;
	}

	#define APPLY_RULESET(__ruleset) do { \
		devfs_rsnum const _ruleset = (__ruleset); \
		\
		if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &_ruleset) < 0) { \
			warnx("DEVFSIO_SAPPLY(%d): %s", _ruleset, strerror(errno)); \
			goto devfsio_err; \
		} \
	} while (0)

	// we necessarily need to start by hiding everything

	APPLY_RULESET(1); // devfsrules_hide_all

	for (size_t i = 0; i < opts->ruleset_count; i++) {
		uint32_t const ruleset = opts->rulesets[i];
		APPLY_RULESET(ruleset);
	}

	// success

	rv = 0;

devfsio_err:

	close(devfs_fd);

open_err:

	return rv;
}

// OS-specific setup functions

static int freebsd_setup(void) {
	// mount fdescfs
	// ignore ENOENT, because we may be prevented from mounting by the devfs ruleset

	struct iovec iov_fd[] = {
		__AQUARIUM_IOV("fstype", "fdescfs"),
		__AQUARIUM_IOV("fspath", "dev/fd"),
	};

	if (nmount(iov_fd, sizeof(iov_fd) / sizeof(*iov_fd), 0) < 0 && errno != ENOENT) {
		warnx("nmount: failed to mount fdescfs: %s", strerror(errno));
		goto mount_fd_err;
	}

	// mount procfs

	struct iovec iov_proc[] = {
		__AQUARIUM_IOV("fstype", "procfs"),
		__AQUARIUM_IOV("fspath", "proc"),
	};

	if (nmount(iov_proc, sizeof(iov_proc) / sizeof(*iov_proc), 0) < 0) {
		warnx("nmount: failed to mount procfs: %s", strerror(errno));
		goto mount_proc_err;
	}

	// success

	return 0;

	__attribute__((unused)) int rv; // dummy variable for TRY_UMOUNT macro
	TRY_UMOUNT("proc")

mount_proc_err:

	TRY_UMOUNT("dev/fd")

mount_fd_err:

	return -1;
}

static int linux_setup(void) {
	if (aquarium_os_load_linux64_kmod() < 0) {
		goto load_kmod_err;
	}

	// mount /dev/shm as tmpfs
	// on linux, this needs to have mode 1777
	// ignore ENOENT, because we may be prevented from mounting by the devfs ruleset

	struct iovec iov_shm[] = {
		__AQUARIUM_IOV("fstype", "tmpfs"),
		__AQUARIUM_IOV("fspath", "dev/shm"),
		__AQUARIUM_IOV("mode", "1777"),
	};

	if (nmount(iov_shm, sizeof(iov_shm) / sizeof(*iov_shm), 0) < 0 && errno != ENOENT) {
		warnx("nmount: failed to mount shm tmpfs: %s", strerror(errno));
		goto mount_shm_err;
	}

	// mount fdescfs (with linrdlnk)
	// ignore ENOENT, because we may be prevented from mounting by the devfs ruleset

	struct iovec iov_fd[] = {
		__AQUARIUM_IOV("fstype", "fdescfs"),
		__AQUARIUM_IOV("fspath", "dev/fd"),
		__AQUARIUM_IOV("linrdlnk", ""),
	};

	if (nmount(iov_fd, sizeof(iov_fd) / sizeof(*iov_fd), 0) < 0 && errno != ENOENT) {
		warnx("nmount: failed to mount fdescfs: %s", strerror(errno));
		goto mount_fd_err;
	}

	//

	// mount linprocfs

	struct iovec iov_proc[] = {
		__AQUARIUM_IOV("fstype", "linprocfs"),
		__AQUARIUM_IOV("fspath", "proc"),
	};

	if (nmount(iov_proc, sizeof(iov_proc) / sizeof(*iov_proc), 0) < 0) {
		warnx("nmount: failed to mount linprocfs: %s", strerror(errno));
		goto mount_proc_err;
	}

	// mount linsysfs

	struct iovec iov_sys[] = {
		__AQUARIUM_IOV("fstype", "linsysfs"),
		__AQUARIUM_IOV("fspath", "sys"),
	};

	if (nmount(iov_sys, sizeof(iov_sys) / sizeof(*iov_sys), 0) < 0) {
		warnx("nmount: failed to mount linsysfs: %s", strerror(errno));
		goto mount_sys_err;
	}

	// success

	return 0;

	__attribute__((unused)) int rv; // dummy variable for TRY_UMOUNT macro
	TRY_UMOUNT("sys")

mount_sys_err:

	TRY_UMOUNT("proc")

mount_proc_err:

	TRY_UMOUNT("dev/fd")

mount_fd_err:

	TRY_UMOUNT("dev/shm")

mount_shm_err:
load_kmod_err:

	return -1;
}

static int ubuntu_setup(void) {
	return linux_setup();
}

// OS-specific setdown (lol) functions

static int freebsd_setdown(void) {
	int rv = 0;

	TRY_UMOUNT("proc")
	TRY_UMOUNT("dev/fd")
	TRY_UMOUNT("dev")
	TRY_UMOUNT("tmp")

	return rv;
}

static int linux_setdown(void) {
	int rv = 0;

	TRY_UMOUNT("sys")
	TRY_UMOUNT("proc")
	TRY_UMOUNT("dev/fd")
	TRY_UMOUNT("dev/shm")
	TRY_UMOUNT("dev")
	TRY_UMOUNT("tmp")

	return rv;
}

static int ubuntu_setdown(void) {
	return linux_setdown();
}

int aquarium_enter_setdown(char const* path, aquarium_os_t os) {
	int rv = -1;

	// remember our current working directory

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

	if (os == AQUARIUM_OS_FREEBSD && freebsd_setdown() < 0) {
		goto setdown_err;
	}

	if (os == AQUARIUM_OS_UBUNTU && ubuntu_setdown() < 0) {
		goto setdown_err;
	}

	// success

	rv = 0;

setdown_err:

	if (chdir(cwd) < 0) {
		warnx("chdir(\"%s\"): %s", cwd, strerror(errno));
		rv = -1;
	}

chdir_err:

	free(cwd);

getcwd_err:

	return rv;
}

int aquarium_enter(aquarium_opts_t* opts, char const* path, aquarium_enter_cb_t cb, void* param) {
	int rv = -1;

	// remember our current working directory
	// this is in case there's an error before we can attach to the jail

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

	if (opts->initial_uid && setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		goto setuid_root_err;
	}

	// mount tmpfs filesystem for /tmp
	// we don't wanna overwrite anything potentially already inside of /tmp
	// to do that, the manual (nmount(2)) suggests we use the MNT_EMPTYDIR flag
	// there seem to be a few inconsistencies vis-à-vis the type of 'flags', so instead we can simply use the 'emptydir' iov (as can be seen in '/usr/include/sys/mount.h')

	struct iovec iov_tmp[] = {
		__AQUARIUM_IOV("fstype", "tmpfs"),
		__AQUARIUM_IOV("fspath", "tmp"),
		__AQUARIUM_IOV("emptydir", ""),
	};

	if (nmount(iov_tmp, sizeof(iov_tmp) / sizeof(*iov_tmp), 0) < 0 && errno != ENOTEMPTY) {
		warnx("nmount: failed to mount tmpfs for /tmp: %s", strerror(errno));
		goto mount_tmpfs_err;
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

	// OS-specific actions

	aquarium_os_t const os = aquarium_os_info(NULL);

	if (os == AQUARIUM_OS_FREEBSD && freebsd_setup() < 0) {
		goto os_setup_err;
	}

	if (os == AQUARIUM_OS_UBUNTU && ubuntu_setup() < 0) {
		goto os_setup_err;
	}

	// set the correct ruleset for devfs
	// this comes last, so any setup scripts still have full access to the devfs filesystem

	if (devfs_ruleset(opts) < 0) {
		goto devfs_ruleset_err;
	}

	// actually enter the aquarium
	// PROC_NO_NEW_PRIVS_ENABLE is only available in aquaBSD and FreeBSD-CURRENT: https://reviews.freebsd.org/D30939

#if __FreeBSD_version >= 1400026
	int flag = PROC_NO_NEW_PRIVS_ENABLE;

	if (procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_CTL, &flag) < 0) {
		warnx("procctl: %s", strerror(errno));
		goto procctl_err;
	}
#endif

	// find aquarium path hash
	// this is what's used to refer to the aquarium's jail by name

	char* const hash = __aquarium_hash(path);

	if (!hash) {
		warnx("Failed to hash '%s'", path);
		goto hash_err;
	}

	// attempt to get the jail ID
	// if found, we can skip the jail creation step & attach ourselves to it right away
	// this all happens in a child process, because jail_attach will steal our process

	pid_t const pid = fork();

	if (pid < 0) {
		warnx("fork: %s", strerror(errno));
		goto fork_err;
	}

	if (!pid) {
		int const jid = jail_getid(hash);

		struct jailparam args[16] = { 0 };
		size_t args_len = 0;

		if (jid >= 0) {
			if (jail_attach(jid) < 0) {
				warnx("jail_attach(%d): %s", jid, strerror(errno));
				_exit(EXIT_FAILURE);
			}

			goto inside;
		}

		// find a hostname for the jail
		// replace all illegal chars by dashes

		char* hostname = opts->hostname;

		if (!hostname) {
			hostname = strrchr(path, '/');
			hostname += !!hostname;
		}

		if (!hostname) {
			hostname = (void*) path; // TODO idk if it makes more sense to default to the path as the hostname or the name the user gave to the aquarium
		}

		hostname = strdup(hostname); // duplicate so that we don't also modify path (we don't concern ourselves with freeing)

		for (size_t i = 0; i < strlen(hostname); i++) {
			if (ILLEGAL_HOSTNAME_CHAR(hostname[i])) {
				hostname[i] = '-';
			}
		}

		// create the jail

		JAILPARAM("name", hash)
		JAILPARAM("path", path)
		JAILPARAM("host.hostname", hostname)
		JAILPARAM("allow.mount", "false")
		JAILPARAM("allow.mount.devfs", "false")
		JAILPARAM("allow.raw_sockets", "true") // to allow us to send ICMP packets (for ping)
		JAILPARAM("allow.socket_af", "true")

		if (!opts->vnet_disable) {
			JAILPARAM("vnet", NULL)
		}

		else {
			JAILPARAM("ip4", "inherit")
			JAILPARAM("ip6", "inherit")
		}

		if (opts->persist) {
			JAILPARAM("persist", NULL)
		}

		if (jailparam_set(args, args_len, JAIL_CREATE | JAIL_ATTACH) < 0) {
			warnx("jailparam_set: %s (%s)", strerror(errno), jail_errmsg);
			_exit(EXIT_FAILURE);
		}

		// we're now inside of the aquarium

	inside:

		// call the passed callback function

		if (!opts->persist && cb(param) < 0) {
			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	// wait for child process

	int const child_rv = __aquarium_wait_for_process(pid);

	if (child_rv != EXIT_SUCCESS) {
		warnx("Child enter process exited with error code %d", child_rv);
		goto child_err;
	}

	// success

	rv = 0;

child_err:
fork_err:

	free(hash);

hash_err:

#if __FreeBSD_version >= 1400026
procctl_err:
#endif

devfs_ruleset_err:

	if (aquarium_enter_setdown(path, os) < 0) {
		rv = -1;
	}

os_setup_err:

	TRY_UMOUNT("dev")

mount_devfs_err:

	TRY_UMOUNT("tmp")

mount_tmpfs_err:

	if (opts->initial_uid && setreuid(opts->initial_uid, 0) < 0) {
		warnx("setreuid(%d, 0): %s", opts->initial_uid, strerror(errno));
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
