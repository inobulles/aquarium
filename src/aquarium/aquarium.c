// #include <aquarium.h>
#include "../aquarium.h"

// includes

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <err.h>
#include <fcntl.h>
#include <grp.h>
#include <paths.h>
#include <pwd.h>

#include <sys/param.h>

#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/uio.h>

// TODO the two following headers are necessary for 'fetch.h' but are not included
//      most likely a bug, fix this

#include <sys/param.h>
#include <time.h>

#include <archive.h>
#include <archive_entry.h>
#include <copyfile.h>
#include <jail.h>
#include <fetch.h>

#include <fs/devfs/devfs.h>
#include <openssl/sha.h>

// defines

#define STONERS_GROUP "stoners"

#define DEFAULT_BASE_PATH "/etc/aquariums/"

#define TEMPLATES_PATH "templates/"
#define KERNELS_PATH   "kernels/"
#define AQUARIUMS_PATH "aquariums/"

#define ILLEGAL_TEMPLATE_PREFIX '.'

#define SANCTIONED_TEMPLATES "templates_remote"
#define AQUARIUM_DB_PATH     "aquarium_db"

#define PROGRESS_FREQUENCY  (1 << 22)
#define FETCH_CHUNK_BYTES   (1 << 16)
#define ARCHIVE_CHUNK_BYTES (1 << 16)

// macros

#define IOV(name, val) \
	(struct iovec) { .iov_base = (name), .iov_len = strlen((name)) + 1 }, \
	(struct iovec) { .iov_base = (val ), .iov_len = strlen((val )) + 1 }

#define JAILPARAM(key, val) \
	jailparam_init  (&args[args_len], (key)); \
	jailparam_import(&args[args_len], (val)); \
	\
	args_len++;

// options

static gid_t stoners_gid = 0;

static char** copy_args = NULL;
static size_t copy_args_len = 0;

static char* template = "amd64.aquabsd.0922a";
static char* kernel_template = NULL;

static char* out_path = NULL;
static char* path = NULL;

static bool persist = false;
static bool vnet_disable = false;

static void usage(void) {
	fprintf(stderr,
		"usage: %1$s [-r base]\n"
		"       %1$s [-r base] -c path [-t template] [-k kernel_template]\n"
		"       %1$s [-r base] -i path -o image\n"
		"       %1$s [-r base] [-pv] -e path\n"
		"       %1$s [-r base] -l\n"
		"       %1$s [-r base] -s\n"
		"       %1$s [-r base] -T path -o template\n"
		"       %1$s [-r base] -y path source_file ... target_directory\n",
	getprogname());

	exit(EXIT_FAILURE);
}

// utility functions

static inline char* __hash(char* str) { // djb2 algorithm
	uint64_t hash = 5381;

	while (*str) {
		hash = ((hash << 5) + hash) + *str++;
	}

	asprintf(&str, "aquarium-%lx", hash);
	return str;
}

typedef enum {
	OS_GENERIC,
	OS_FBSD,
	OS_LINUX,
} os_info_t;

static inline os_info_t __retrieve_os_info(const char* aquarium_path) {
	// this method of retrieving OS info relies on the existence of an '/etc/os-release' file on the installation
	// all officially supported OS' for aquariums should have this file, else they'll simply be reported as 'OS_GENERIC'
	// if 'aquarium_path == NULL', assume we're already in the aquarium, and just use the relative path for '/etc/os-release'

	char* path = "etc/os-release";

	if (aquarium_path) {
		asprintf(&path, "%s/etc/os-release", aquarium_path);
	}

	FILE* fp = fopen(path, "r");

	if (aquarium_path) {
		free(path);
	}

	if (!fp) {
		return OS_GENERIC;
	}

	char buf[1024];
	char* os = fgets(buf, sizeof buf, fp);

	os += strlen("NAME=\"");
	os[strlen(os) - 2] = '\0';

	fclose(fp);

	// match NAME with an OS we know of

	if (!strcmp(os, "FreeBSD")) {
		return OS_FBSD;
	}

	if (!strcmp(os, "Ubuntu")) {
		return OS_LINUX;
	}

	return OS_GENERIC;
}

static inline void __load_kmod(const char* name) {
	if (!kldload(name)) {
		return;
	}

	if (errno == EEXIST) {
		return;
	}

	// jammer, iets is fout gegaan

	if (errno == ENOEXEC) {
		errx(EXIT_FAILURE, "kldload(\"%s\"): please check dmesg(8) for details (or don't, I'm not your mum)", name);
	}

	errx(EXIT_FAILURE, "kldload(\"%s\"): %s", name, strerror(errno));
}

static void load_linux64_kmod(void) {
	__load_kmod("linux64");
}

static inline int __wait_for_process(pid_t pid) {
	int wstatus = 0;
	while (waitpid(pid, &wstatus, 0) > 0);

	if (WIFSIGNALED(wstatus)) {
		return -1;
	}

	if (WIFEXITED(wstatus)) {
		return WEXITSTATUS(wstatus);
	}

	return -1;
}

// actions

static int do_list(aquarium_opts_t* opts) {
	FILE* fp = fopen(opts->db_path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", opts->db_path, strerror(errno));
	}

	printf("POINTER\tAQUARIUM\n");

	char buf[1024];
	aquarium_db_ent_t ent;

	while (aquarium_db_next_ent(opts, &ent, sizeof buf, buf, fp, true)) {
		printf("%s\t%s\n", ent.pointer_path, ent.aquarium_path);
	}

	fclose(fp);

	return EXIT_SUCCESS;
}

static inline void __list_templates_dir(const char* path, const char* kind) {
	DIR* dp = opendir(path);

	if (!dp) {
		errx(EXIT_FAILURE, "opendir: failed to open template directory %s: %s", path, strerror(errno));
	}

	printf("ARCH\tOS\tVERS\t(%s)\n", kind);

	struct dirent* ent;

	while ((ent = readdir(dp))) {
		char* name = ent->d_name;

		if (!strcmp(name, ".") || !strcmp(name, "..")) {
			continue;
		}

		enum {
			ARCH, OS, VERS, SENTINEL
		} kind = 0;

		char* tok;

		while ((tok = strsep(&name, "."))) {
			printf("%s", tok);

			if (++kind >= SENTINEL) {
				break;
			}

			printf("\t");
		}

		printf("\n");
	}

	closedir(dp);
}

static int do_list_templates(aquarium_opts_t* opts) {
	__list_templates_dir(opts->templates_path, "BASE");
	__list_templates_dir(opts->kernels_path, "KERNEL");

	return EXIT_SUCCESS;
}

// creating aquariums (takes in a template name):
//  - check if template exists (and also kernel template if specified)
//  - open pointer file for writing
//  - setuid root
//  - extract template (and kernel template if specified) in the aquarium's directory if it exists
//  - if it doesn't (they don't), first download it (them), and compare SHA256 hash to a database of trusted templates (and kernel templates if specified) to make sure there isn't anything weird going on
//  - create user and stuff
//  - do any final setup (e.g. copying '/etc/resolv.conf' for networking)
//  - write path of pointer file & its associated aquarium to aquarium database (and give it some unique ID)
//  - setuid user (CHECK FOR ERRORS!)
//  - write unique ID to pointer file

static int do_create(aquarium_opts_t* opts) {
	if (!path) {
		usage();
	}

	if (*template == ILLEGAL_TEMPLATE_PREFIX) {
		errx(EXIT_FAILURE, "%s template is illegal (starts with ILLEGAL_TEMPLATE_PREFIX, '%c'). Someone may be trying to swindle you!", template, ILLEGAL_TEMPLATE_PREFIX);
	}

	// remember our current working directory for later

	char* cwd = getcwd(NULL, 0);

	if (!cwd) {
		errx(EXIT_FAILURE, "getcwd: %s", strerror(errno));
	}

	// generate final aquarium path

	char* aquarium_path; // don't care about freeing this (TODO: although I probably will if I factor this out into a libaquarium library)
	asprintf(&aquarium_path, "%s%s-XXXXXXX", opts->aquariums_path, template);

	aquarium_path = mkdtemp(aquarium_path);

	if (!aquarium_path) {
		errx(EXIT_FAILURE, "mkdtemp: failed to create aquarium directory: %s", strerror(errno));
	}

	// check that pointer file isn't already in the aquarium database
	// if it doesn't yet exist, the 'realpath' call will fail (which we don't want if 'flags & FLAGS_CREATE')
	// although it's cumbersome, I really wanna use realpath here to reduce points of failure
	// to be honest, I think it's a mistake not to have included a proper way of checking path hierarchy in POSIX

	// TODO haven't yet thought about how safe this'd be, but since the aquarium database also contains what the pointer file was supposed to point to, maybe it could be cool for this to automatically regenerate the pointer file instead of erroring?

	if (!access(path, F_OK)) {
		errx(EXIT_FAILURE, "Pointer file %s already exists", path);
	}

	int fd = creat(path, 0 /* don't care about mode */);

	if (!fd) {
		errx(EXIT_FAILURE, "creat(\"%s\"): %s", path, strerror(errno));
	}

	char* abs_path = realpath(path, NULL);

	close(fd);
	remove(path);

	if (!abs_path) {
		errx(EXIT_FAILURE, "realpath(\"%s\"): %s", path, strerror(errno));
	}

	FILE* fp = fopen(opts->db_path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", opts->db_path, strerror(errno));
	}

	char buf[1024];
	aquarium_db_ent_t ent;

	while (aquarium_db_next_ent(opts, &ent, sizeof buf, buf, fp, true)) {
		if (!strcmp(ent.pointer_path, abs_path)) {
			errx(EXIT_FAILURE, "Pointer file already exists in the aquarium database at %s (pointer file is supposed to reside at %s and point to %s)", opts->db_path, ent.pointer_path, ent.aquarium_path);
		}
	}

	fclose(fp);

	// setuid root

	uid_t uid = getuid();

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid(0): %s", strerror(errno));
	}

	// extract templates

	(void) (template && aquarium_extract_template(opts, aquarium_path, template, AQUARIUM_TEMPLATE_KIND_BASE) < 0);
	(void) (kernel_template && aquarium_extract_template(opts, aquarium_path, kernel_template, AQUARIUM_TEMPLATE_KIND_KERNEL) < 0);

	// copy over /etc/resolv.conf for networking to, well, work

	#define COPYFILE_DEBUG (1 << 31)

	if (copyfile("/etc/resolv.conf", "etc/resolv.conf", 0, COPYFILE_ALL) < 0) {
		errx(EXIT_FAILURE, "copyfile: %s", strerror(errno));
	}

	// write info to aquarium database

	/* FILE* */ fp = fopen(opts->db_path, "a");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", opts->db_path, strerror(errno));
	}

	fprintf(fp, "%s:%s\n", abs_path, aquarium_path);

	free(abs_path);
	fclose(fp);

	// enter the newly created aquarium to do a bit of configuration
	// we can't do this is all in C, because, well, there's a chance the template is not the operating system we're currently running
	// this does thus depend a lot on the platform we're running on
	// the solution here is to generate an initial setup script depending on the aquarium's OS, which we then run in the aquarium

	char* name = strrchr(path, '/');

	if (!name) {
		name = path;
	}

	struct passwd* passwd = getpwuid(uid);
	char* username = passwd->pw_name;

	os_info_t os = __retrieve_os_info(NULL);
	char* setup_script_fmt;

	#define SETUP_SCRIPT_HEADER \
		"#!/bin/sh\n" \
		"set -e;" \
		\
		"hostname=%s;" \
		\
		"echo $hostname > /etc/hostname;" \
		"echo 127.0.0.1 $hostname >> /etc/hosts;"

	if (os == OS_LINUX) {
		load_linux64_kmod();

		setup_script_fmt = SETUP_SCRIPT_HEADER
			// fix APT defaults

			"echo APT::Cache-Start \\\"100000000\\\"\\; >> /etc/apt/apt.conf.d/10cachestart;"
			"sed -i 's/$/\\ universe/' /etc/apt/sources.list;"

			// broken symlink (symbolic, not hard!) which needs to be fixed for the dynamic linker to work

			"ln -sf ../lib/x86_64-linux-gnu/ld-2.31.so /lib64/ld-linux-x86-64.so.2;";
	}

	else {
		setup_script_fmt = SETUP_SCRIPT_HEADER;
	}

	char* setup_script;
	asprintf(&setup_script, setup_script_fmt, username, uid, name);

	// create the jail for the aquarium
	// a few considerations here, because it seems appropriate to make these public:
	//  - the various keys you can use for jailparams can be found in 'usr.sbin/jail/config.c', and they are the ones *without* the 'PF_INTERNAL' flag
	//  - those which do have the 'PF_INTERNAL' flag (e.g. "mount.devfs" & "vnet.interface") are generally dished out to external commands (which can be found in 'usr.sbin/jail/command.c')
	//  - this is done in a separate process, because we still want to come back to the original CWD to create the pointer file

	// fork the process and actually create that jail and run that initial setup script
	// then, wait for it to finish parent-side (and check for errors blah blah)

	pid_t setup_pid = fork();

	if (!setup_pid) {
		// child process here

		struct jailparam args[16] = { 0 };
		size_t args_len = 0;

		JAILPARAM("name", __hash(aquarium_path)) // don't care about freeing
		JAILPARAM("path", aquarium_path)

		if (jailparam_set(args, args_len, JAIL_CREATE | JAIL_ATTACH) < 0) {
			errx(EXIT_FAILURE, "jailparam_set: %s (%s)", strerror(errno), jail_errmsg);
		}

		jailparam_free(args, args_len);

		execl("/bin/sh", "/bin/sh", "-c", setup_script, NULL);
		_exit(EXIT_FAILURE);
	}

	int child_rv = __wait_for_process(setup_pid);

	if (child_rv < 0) {
		errx(EXIT_FAILURE, "Child setup process exited with error code %d", child_rv);
	}

	// finish writing pointer file as user

	if (setuid(uid) < 0) {
		errx(EXIT_FAILURE, "setuid(%d): %s", uid, strerror(errno));
	}

	// change back to where we were and write to pointer file

	if (chdir(cwd) < 0) {
		errx(EXIT_FAILURE, "chdir(\"%s\"): %s", cwd, strerror(errno));
	}

	/* FILE* */ fp = fopen(path, "wx");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", path, strerror(errno));
	}

	fprintf(fp, "%s", aquarium_path);
	fclose(fp);

	return EXIT_SUCCESS;
}

// entering aquariums (takes in a pointer file):
//  - make sure the path of the pointer file is well the one contained in the relevant entry of the aquarium database
//  - mount necessary filesystems (linsysfs, linprocfs, &c)
//  - link (or bind mount) necessary directories (/dev, /tmp if specified, &c)
//  - actually enter the aquarium

static int do_enter(aquarium_opts_t* opts) {
	char* aquarium_path = aquarium_db_read_pointer_file(opts, path);

	// change into the aquarium directory

	if (chdir(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chdir: %s", strerror(errno));
	}

	// setuid root

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid(0): %s", strerror(errno));
	}

	// mount devfs filesystem

	struct iovec iov_dev[] = {
		IOV("fstype", "devfs"),
		IOV("fspath", "dev"),
	};

	if (nmount(iov_dev, sizeof(iov_dev) / sizeof(*iov_dev), 0) < 0) {
		errx(EXIT_FAILURE, "nmount: failed to mount devfs: %s", strerror(errno));
	}

	// set the correct ruleset for devfs
	// we necessarily need to start by hiding everything for some reason

	int devfs_fd = open("dev", O_RDONLY);

	if (devfs_fd < 0) {
		errx(EXIT_FAILURE, "open(\"dev\"): %s", strerror(errno));
	}

	devfs_rsnum ruleset = 1; // devfsrules_hide_all

	if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &ruleset) < 0) {
		errx(EXIT_FAILURE, "DEVFSIO_SAPPLY: %s", strerror(errno));
	}

	ruleset = 2; // devfsrules_unhide_basic

	if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &ruleset) < 0) {
		errx(EXIT_FAILURE, "DEVFSIO_SAPPLY: %s", strerror(errno));
	}

	ruleset = 3; // devfsrules_unhide_login

	if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &ruleset) < 0) {
		errx(EXIT_FAILURE, "DEVFSIO_SAPPLY: %s", strerror(errno));
	}

	ruleset = 5; // devfsrules_jail_vnet

	if (ioctl(devfs_fd, DEVFSIO_SAPPLY, &ruleset) < 0) {
		errx(EXIT_FAILURE, "DEVFSIO_SAPPLY: %s", strerror(errno));
	}

	close(devfs_fd);

	// mount tmpfs filesystem for /tmp
	// we don't wanna overwrite anything potentially already inside of /tmp
	// to do that, the manual (nmount(2)) suggests we use the MNT_EMPTYDIR flag
	// there seem to be a few inconsistencies vis-à-vis the type of 'flags', so instead we can simply use the 'emptydir' iov (as can be seen in '/usr/include/sys/mount.h')

	struct iovec iov_tmp[] = {
		IOV("fstype", "tmpfs"),
		IOV("fspath", "tmp"),
		IOV("emptydir", ""),
	};

	if (nmount(iov_tmp, sizeof(iov_tmp) / sizeof(*iov_tmp), 0) < 0 && errno != ENOTEMPTY) {
		errx(EXIT_FAILURE, "nmount: failed to mount nullfs for /tmp: %s", strerror(errno));
	}

	// OS-specific actions
	// treat OS_GENERIC OS' as the default (i.e. like their host OS)

	os_info_t os = __retrieve_os_info(NULL);

	if (os == OS_LINUX) {
		load_linux64_kmod();

		// mount /dev/shm as tmpfs
		// on linux, this needs to have mode 1777
		// ignore ENOENT, because we may be prevented from mounting by the devfs ruleset

		struct iovec iov_shm[] = {
			IOV("fstype", "tmpfs"),
			IOV("fspath", "dev/shm"),
			IOV("mode", "1777"),
		};

		if (nmount(iov_shm, sizeof(iov_shm) / sizeof(*iov_shm), 0) < 0 && errno != ENOENT) {
			errx(EXIT_FAILURE, "nmount: failed to mount shm tmpfs: %s", strerror(errno));
		}

		// mount fdescfs (with linrdlnk)
		// ignore ENOENT, because we may be prevented from mounting by the devfs ruleset

		struct iovec iov_fd[] = {
			IOV("fstype", "fdescfs"),
			IOV("fspath", "dev/fd"),
			IOV("linrdlnk", ""),
		};

		if (nmount(iov_fd, sizeof(iov_fd) / sizeof(*iov_fd), 0) < 0 && errno != ENOENT) {
			errx(EXIT_FAILURE, "nmount: failed to mount fdescfs: %s", strerror(errno));
		}

		// mount linprocfs

		struct iovec iov_proc[] = {
			IOV("fstype", "linprocfs"),
			IOV("fspath", "proc"),
		};

		if (nmount(iov_proc, sizeof(iov_proc) / sizeof(*iov_proc), 0) < 0) {
			errx(EXIT_FAILURE, "nmount: failed to mount linprocfs: %s", strerror(errno));
		}

		// mount linsysfs

		struct iovec iov_sys[] = {
			IOV("fstype", "linsysfs"),
			IOV("fspath", "sys"),
		};

		if (nmount(iov_sys, sizeof(iov_sys) / sizeof(*iov_sys), 0) < 0) {
			errx(EXIT_FAILURE, "nmount: failed to mount linsysfs: %s", strerror(errno));
		}
	}

	else {
		// mount fdescfs
		// ignore ENOENT, because we may be prevented from mounting by the devfs ruleset

		struct iovec iov_fd[] = {
			IOV("fstype", "fdescfs"),
			IOV("fspath", "dev/fd"),
		};

		if (nmount(iov_fd, sizeof(iov_fd) / sizeof(*iov_fd), 0) < 0 && errno != ENOENT) {
			errx(EXIT_FAILURE, "nmount: failed to mount fdescfs: %s", strerror(errno));
		}

		// mount procfs

		struct iovec iov_proc[] = {
			IOV("fstype", "procfs"),
			IOV("fspath", "proc"),
		};

		if (nmount(iov_proc, sizeof(iov_proc) / sizeof(*iov_proc), 0) < 0) {
			errx(EXIT_FAILURE, "nmount: failed to mount procfs: %s", strerror(errno));
		}
	}

	// actually enter aquarium
	// PROC_NO_NEW_PRIVS_ENABLE is only available in aquaBSD and FreeBSD-CURRENT: https://reviews.freebsd.org/D30939

#if __FreeBSD_version >= 1400026
	int flag = PROC_NO_NEW_PRIVS_ENABLE;

	if (procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_CTL, &flag) < 0) {
		errx(EXIT_FAILURE, "procctl: %s", strerror(errno));
	}
#endif

	char* hash = __hash(aquarium_path); // don't care about freeing
	int jid = jail_getid(hash);

	if (jid >= 0) {
		if (jail_attach(jid) < 0) {
			errx(EXIT_FAILURE, "jail_attach: %s", strerror(errno));
		}

		goto shell;
	}

	char* hostname = strrchr(path, '/');

	if (!hostname) {
		hostname = path;
	}

	struct jailparam args[16] = { 0 };
	size_t args_len = 0;

	JAILPARAM("name", __hash(aquarium_path))
	JAILPARAM("path", aquarium_path)
	JAILPARAM("host.hostname", hostname)
	JAILPARAM("allow.mount", "false")
	JAILPARAM("allow.mount.devfs", "false")
	JAILPARAM("allow.raw_sockets", "true") // allow for sending ICMP packets (for ping)
	JAILPARAM("allow.socket_af", "true")

	if (!vnet_disable) {
		JAILPARAM("vnet", NULL)
	}

	else {
		JAILPARAM("ip4", "inherit")
		JAILPARAM("ip6", "inherit")
	}

	if (persist) {
		JAILPARAM("persist", NULL)
	}

	if (jailparam_set(args, args_len, JAIL_CREATE | JAIL_ATTACH) < 0) {
		errx(EXIT_FAILURE, "jailparam_set: %s (%s)", strerror(errno), jail_errmsg);
	}

	jailparam_free(args, args_len);

shell:

	if (persist) {
		return EXIT_SUCCESS;
	}

	// unfortunately we kinda need to use execlp here
	// different OS' may have different locations for the 'env' binary
	// we use it instead of starting the shell directly to clear any environment variables that we shouldn't have access to (and which anyway isn't super relevant to us)

	return execlp("env", "env", "-i", "sh", NULL);
}

// sweeping aquariums (takes in nothing):
//  - go through aquarium database
//  - if a valid pointer file doesn't exist at the path in the database, we say the aquarium has been "orphaned"
//  - if an aquarium is orphaned, we can safely delete it and remove it from the aquarium database

static void __unmount_aquarium(char* aquarium_path) {
	#define GEN(prefix, name) \
		char* name; \
		asprintf(&name, "%s/" #name, prefix);

	GEN(aquarium_path, dev)
	GEN(dev, fd)
	GEN(dev, shm)

	GEN(aquarium_path, proc)
	GEN(aquarium_path, sys)
	GEN(aquarium_path, tmp)

	// we do as many iterations as we need, because some filesystems may be mounted over others

	do {
		while (!unmount(fd,  MNT_FORCE));
		while (!unmount(shm, MNT_FORCE));
	}   while (!unmount(dev, MNT_FORCE));

	while (!unmount(proc, MNT_FORCE));
	while (!unmount(sys,  MNT_FORCE));
	while (!unmount(tmp,  MNT_FORCE));

	#undef GEN

	free(dev);
	free(fd);
	free(shm);

	free(proc);
	free(sys);
	free(tmp);
}

static void __remove_aquarium(char* aquarium_path) {
	// first, make sure all possible mounted filesystems are unmounted

	__unmount_aquarium(aquarium_path);

	// then, we remove all the aquarium files
	// the aquarium may have already been deleted (e.g. by a nosy user)
	// so we don't wanna do anything with the return value of '__wait_for_process'
	// TODO I desperately need some easy API for removing files in the standard library on aquaBSD
	//      I'm not (I hope) dumb enough to do something like 'asprint(&cmd, "rm -rf %s", ent.aquarium_path)', but I know damn well other developers would be tempted to do such a thing given no other alternative

	pid_t rm_pid = fork();

	if (!rm_pid) {
		execl("/bin/rm", "/bin/rm", "-rf", aquarium_path, NULL);
		_exit(EXIT_FAILURE);
	}

	__wait_for_process(rm_pid);
}

static int do_sweep(aquarium_opts_t* opts) {
	// list of database entries which survive the sweep

	size_t survivors_len = 0;
	aquarium_db_ent_t* survivors = NULL;

	// go through aquarium database

	FILE* fp = fopen(opts->db_path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", opts->db_path, strerror(errno));
	}

	char buf[1024];
	aquarium_db_ent_t ent;

	while (aquarium_db_next_ent(opts, &ent, sizeof buf, buf, fp, false)) {
		// if something went wrong reading an entry (e.g. it's malformed), simply discard it
		// there is a chance then that some aquariums or pointer files will be left behind, but eh rather that than risk deleting something we shouldn't
		// also, under normal operation, this kind of condition shouldn't occur

		if (!ent.pointer_path || !ent.aquarium_path) {
			continue;
		}

		// if we can't find pointer file, remove the aquarium and that entry from the aquarium database

		if (access(ent.pointer_path, F_OK) < 0) {
			__remove_aquarium(ent.aquarium_path);

			// discard this entry obviously, we don't want nuffin to do with it no more 😡

			continue;
		}

		// if we can't find aquarium, remove the pointer file and that entry from the aquarium database
		// not sure under which circumstances this kind of stuff could happen, but handle it anyway

		if (access(ent.aquarium_path, F_OK) < 0) {
			// attempt to remove the pointer file
			// we don't care to do anything on error, because the file may very well have already been removed by the user

			remove(ent.pointer_path);

			// discard this entry &c &c

			continue;
		}

		// congratulations to the database entry! 🎉
		// it has survived unto the next sweep!

		survivors = realloc(survivors, (survivors_len + 1) * sizeof *survivors);
		aquarium_db_ent_t* survivor = &survivors[survivors_len++];

		survivor->pointer_path  = strdup(ent.pointer_path);
		survivor->aquarium_path = strdup(ent.aquarium_path);
	}

	fclose(fp);

	// keep things nice and clean is to go through everything under /etc/aquariums/aquariums and see which aquariums were never "recensés" (censused?)

	DIR* dp = opendir(opts->aquariums_path);

	if (!dp) {
		errx(EXIT_FAILURE, "opendir: %s", strerror(errno));
	}

	struct dirent* dir_ent;

	while ((dir_ent = readdir(dp))) {
		char* name = dir_ent->d_name;

		if (!strcmp(name, ".") || !strcmp(name, "..")) {
			continue;
		}

		for (size_t i = 0; i < survivors_len; i++) {
			aquarium_db_ent_t* survivor = &survivors[i];
			char* aquarium = strrchr(survivor->aquarium_path, '/');

			aquarium += !!*aquarium;

			if (!strcmp(aquarium, name)) {
				goto found;
			}
		}

		// ah! couldn't find the aquarium in the list of survivors! remove it!

		char* aquarium_path;
		asprintf(&aquarium_path, "%s/%s", opts->aquariums_path, name);

		__remove_aquarium(aquarium_path);
		free(aquarium_path);

	found:

		continue; // need something after a label in C for some reason
	}

	closedir(dp);

	// last thing to do is rebuild new aquarium database file with the entries that survived

	/* FILE* */ fp = fopen(opts->db_path, "w");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", opts->db_path, strerror(errno));
	}

	for (size_t i = 0; i < survivors_len; i++) {
		aquarium_db_ent_t* survivor = &survivors[i];

		fprintf(fp, "%s:%s\n", survivor->pointer_path, survivor->aquarium_path);

		free(survivor->pointer_path);
		free(survivor->aquarium_path);
	}

	fclose(fp);
	free(survivors);

	return 0;
}

// outputting aquariums (TODO: much of this code can be shared with do_enter)
//  - make sure the path of the pointer file is well the one contained in the relevant entry of the aquarium database
//  - walk the aquarium path and add files/directories to output archive

typedef struct {
	const char* out;
	int fd;
} do_out_state_t;

static int do_out_open_cb(__attribute__((unused)) struct archive* archive, void* _state) {
	do_out_state_t* state = _state;

	state->fd = open(state->out, O_WRONLY | O_CREAT, 0644);

	if (state->fd < 0) {
		warnx("open(\"%s\"): %s", state->out, strerror(errno));
		return ARCHIVE_FATAL;
	}

	return ARCHIVE_OK;
}

static la_ssize_t do_out_write_cb(__attribute__((unused)) struct archive* archive, void* _state, const void* buf, size_t len) {
	do_out_state_t* state = _state;
	return write(state->fd, buf, len);
}

static int do_out_close_cb(__attribute__((unused)) struct archive* archive, void* _state) {
	do_out_state_t* state = _state;

	if (state->fd >= 0) {
		close(state->fd);
	}

	return ARCHIVE_OK;
}

static int do_out(aquarium_opts_t* opts) {
	if (!out_path) {
		usage();
	}

	char* aquarium_path = aquarium_db_read_pointer_file(opts, path);
	__unmount_aquarium(aquarium_path);

	// create template

	char* abs_template;
	asprintf(&abs_template, "%s/%s", getcwd(NULL, 0), out_path); // don't care about freeing this for now

	if (chdir(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chdir: %s", strerror(errno));
	}

	struct archive* disk = archive_read_disk_new();

	archive_read_disk_set_standard_lookup(disk);
	archive_read_disk_set_behavior(disk, ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS);

	if (archive_read_disk_open(disk, ".") != ARCHIVE_OK) {
		errx(EXIT_FAILURE, "archive_read_disk_open: %s", archive_error_string(disk));
	}

	// try to deduce compression format to use based on file extension, and if that fails, default to XZ compression

	do_out_state_t state = {
		.out = abs_template
	};

	struct archive* archive = archive_write_new();

	archive_write_add_filter_xz   (archive); // archive_write_filter(3)
	archive_write_set_format_ustar(archive); // archive_write_format(3)

	archive_write_set_filter_option(archive, "xz", "compression-level", "9");
	archive_write_set_filter_option(archive, "xz", "threads", "0"); // fixed as of https://github.com/libarchive/libarchive/pull/1664

	if (archive_write_open(archive, &state, do_out_open_cb, do_out_write_cb, do_out_close_cb) < 0) {
		errx(EXIT_FAILURE, "archive_write_open: %s", archive_error_string(archive));
	}

	for (;;) {
		// read next file and write entry

		struct archive_entry* entry = archive_entry_new();
		int rv = archive_read_next_header2(disk, entry);

		if (rv == ARCHIVE_EOF) {
			break;
		}

		if (rv != ARCHIVE_OK) {
			errx(EXIT_FAILURE, "archive_read_next_header2: %s", archive_error_string(disk));
		}

		archive_read_disk_descend(disk);
		rv = archive_write_header(archive, entry);

		if (rv == ARCHIVE_FATAL) {
			errx(EXIT_FAILURE, "archive_write_header: %s", archive_error_string(archive));
		}

		if (rv < ARCHIVE_OK) {
			warnx("archive_write_header: %s", archive_error_string(archive));
		}

		if (rv <= ARCHIVE_FAILED) {
			goto finish_entry;
		}

		// write file content

		const char* path = archive_entry_sourcepath(entry);
		printf("%s\n", path + 2);

		int fd;

		if ((fd = open(path, O_RDONLY)) < 0) {
			warnx("open(\"%s\"): %s", path, strerror(errno));
			goto finish_entry;
		}

		ssize_t len;
		char buf[ARCHIVE_CHUNK_BYTES];

		while ((len = read(fd, buf, sizeof buf)) > 0) {
			archive_write_data(archive, buf, len);
		}

		close(fd);

	finish_entry:

		archive_entry_free(entry);
	}

	archive_read_close(disk);
	archive_read_free(disk);

	archive_write_close(archive);
	archive_write_free(archive);

	return EXIT_SUCCESS;
}

// outputting aquariums as images
//  - check the OS we're tryna create an image of is actually supported (i.e. is FreeBSD)
//  - make sure '/etc/fstab' is setup correctly to mount the rootfs & ESP (EFI System Partition)
//  - generate entropy
//  - create UFS2 rootfs image with the contents of the aquarium
//  - create ESP image (FAT12 - UEFI code seems to be fussy with FAT32 partitions generated by FreeBSD) with the EFI loader
//  - combine all that together into a final image, which uses the GPT partition scheme (and also installs gptboot(8) in the MBR boot sector for BIOS booting on legacy systems - something aquabsd-installer should be doing too!)
// TODO a lot of these things need to be added to aquabsd-installer

static int do_img_out(aquarium_opts_t* opts) {
	if (!out_path) {
		usage();
	}

	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	// check the OS is actually supported

	os_info_t os = __retrieve_os_info(aquarium_path);

	if (os != OS_FBSD) {
		errx(EXIT_FAILURE, "Aquarium OS is unsupported (%d, only FreeBSD aquariums are currently supported)", os);
	}

	// make sure all filesystems are unmounted

	__unmount_aquarium(aquarium_path);

	// finally, create image

	return aquarium_img_out(opts, path, out_path);
}

// copy files from outside of the aquarium

static int do_copy(aquarium_opts_t* opts) {
	if (!copy_args || copy_args_len < 2) {
		usage();
	}

	char* aquarium_path = aquarium_db_read_pointer_file(opts, path);

	// setuid root

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid(0): %s", strerror(errno));
	}

	// iterate through all files

	char* target = copy_args[--copy_args_len];

	while (copy_args_len --> 0) {
		char* source = copy_args[copy_args_len];

		// load target

		char* target_path;
		asprintf(&target_path, "%s/%s/%s", aquarium_path, target, strrchr(source, '/'));

		int target_fd = creat(target_path, 0660);
		free(target_path);

		if (target_fd < 0) {
			errx(EXIT_FAILURE, "creat(\"%s\"): %s", target_path, strerror(errno));
		}

		// load source

		int fd = open(source, O_RDONLY);

		if (fd < 0) {
			errx(EXIT_FAILURE, "open(\"%s\"): %s", source, strerror(errno));
		}

		// copy & close

		if (fcopyfile(fd, target_fd, 0, COPYFILE_ALL) < 0) {
			errx(EXIT_FAILURE, "fcopyfile(\"%s\", \"%s\"): %s", source, target_path, strerror(errno));
		}

		close(fd);
		close(target_fd);
	}

	return EXIT_SUCCESS;
}

// main function

typedef int (*action_t) (aquarium_opts_t* opts);

int main(int argc, char* argv[]) {
	action_t action = do_list;
	aquarium_opts_t* opts = aquarium_opts_create();

	// parse options

	int c;

	while ((c = getopt(argc, argv, "c:e:fi:k:lo:pr:st:T:vy:")) != -1) {
		// general options

		if (c == 'p') {
			persist = true;
		}

		else if (c == 'r') {
			opts->base_path = optarg;
		}

		else if (c == 'v') {
			vnet_disable = true;
		}

		// action options

		else if (c == 'c') {
			action = do_create;
			path = optarg;
		}

		else if (c == 'e') {
			action = do_enter;
			path = optarg;
		}

		else if (c == 'i') {
			action = do_img_out;
			path = optarg;
		}

		else if (c == 'l') {
			action = do_list_templates;
		}

		else if (c == 's') {
			action = do_sweep;
		}

		else if (c == 'T') {
			action = do_out;
			path = optarg;
		}

		else if (c == 'y') {
			action = do_copy;
			path = optarg;
		}

		// name-passing options

		else if (c == 'k') {
			kernel_template = optarg;
		}

		else if (c == 't') {
			template = optarg;
		}

		else if (c == 'o') {
			out_path = optarg;
		}

		else {
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (action == do_copy) {
		copy_args = argv;
		copy_args_len = argc;
	}

	else if (argc) {
		usage();
	}

	// generate various paths relative to the base path
	// we don't really care about freeing these
	// TODO there should really be facilities in libaquarium for this

	asprintf(&opts->templates_path,  "%s/" TEMPLATES_PATH,       opts->base_path);
	asprintf(&opts->kernels_path,    "%s/" KERNELS_PATH,         opts->base_path);
	asprintf(&opts->aquariums_path,  "%s/" AQUARIUMS_PATH,       opts->base_path);

	asprintf(&opts->sanctioned_path, "%s/" SANCTIONED_TEMPLATES, opts->base_path);
	asprintf(&opts->db_path,         "%s/" AQUARIUM_DB_PATH,     opts->base_path);

	// skip this stuff if we're root
	// note that aquariums created as root won't be accessible by members of the stoners group

	uid_t uid = getuid();

	if (!uid) {
		goto okay;
	}

	// make sure the $STONERS_GROUP group exists, and error if not

	struct group* stoners_group = getgrnam(STONERS_GROUP);

	if (!stoners_group) {
		errx(EXIT_FAILURE, "Couldn't find \"" STONERS_GROUP "\" group");
	}

	stoners_gid = stoners_group->gr_gid;
	endgrent();

	// make sure user is part of the $STONERS_GROUP group

	struct passwd* passwd = getpwuid(uid);
	char** stoners = stoners_group->gr_mem;

	while (*stoners) {
		if (!strcmp(*stoners++, passwd->pw_name)) {
			goto okay;
		}
	}

	errx(EXIT_FAILURE, "%s is not part of the \"" STONERS_GROUP "\" group", passwd->pw_name);

okay:

	// finally actually execute the action we were here for

	return action(opts);
}
