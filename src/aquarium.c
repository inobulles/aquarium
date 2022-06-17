// TODO
//  - factor out a libaquarium library from the aquarium frontend
//  - manual page
//  - tests
//  - option for listing aquarium database
//  - better way of copying over linux-nvidia-libs (probably best to build the package in a way which assumes it's installing to a Linux install right off the bat, and then have some kind of aquarium mechanism to install packages like 'aquarium -p my-aquarium linux-nvidia-libs-510.39.01.pkg' or something)
//  - better solution than the 'compat.linux.emul_path' sysctl from FreeBSD, because that's super limited
//  - may be interesting to replace instances of fgets with fparseln

// building:
// $ cc aquarium.c -larchive -lfetch -lcrypto -lcopyfile -ljail -o aquarium
// $ chmod u+s aquarium && chown root:wheel aquarium

// create group:
// $ pw groupadd stoners
// $ pw groupmod stoners -g 420 -m obiwac

// some aquarium terminology:
//  - "templates" are the templates from which aquariums are created (immutable)
//  - "aquariums" are the actual instances of a certain template (mutable, they have a unique ID)
//  - "aquarium pointer files" are the files which users interact with to interact with aquariums (immutable, they can be moved by the user, but then it loses its status as a pointer file)

// recovering aquariums (takes in nothing):
//  - since we keep a record of all the pointer files, we can actually recover them if a user accidentally deletes one
//  - basically, follow the same steps, except if an aquarium is orphaned, regenerate its pointer file instead of deleting the aquarium and its database entry

// at this point, things seem to be working well enough to run full Linux apps quite well in aquariums
// here's a little tutorial of sorts for installing Chrome
// first, we need to create an Ubuntu aquarium and enter it:
// % aquarium -c ubuntu-aquarium -t amd64.ubuntu.focal
// % aquarium -e ubuntu-aquarium
// now we're in our Ubuntu aquarium, install a few things we'll need:
// % sudo apt install -y curl gpg
// once that's done, add the Google Chrome repository to APT sources & Google's signing key for Linux:
// % echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
// % curl https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
// % sudo apt update
// finally (at least for inside of the aquarium), install Chrome itself and exit:
// % sudo apt install -y google-chrome-stable
// % exit
// for hardware acceleration (on NVIDIA), we need to copy over the Linux libraries from the .run file to the aquarium
// fortunately, there's already a 'linux-nvidia-libs' package which contains these libraries for aquaBSD: https://github.com/inobulles/aquabsd-pkg-repo/releases/
// extract that and copy over the libraries to the aquarium (this is a very un-proper way of doing things, but whatever):
// % tar xzvf linux-nvidia-libs-510.39.01.pkg
// % cp -r compat/linux/usr/lib64/* $aquarium_path/lib/x86_64-linux-gnu
// and after all that, you should finally be able to set the Linux emulation path and launch Chrome:
// % sysctl compat.linux.emul_path=$aquarium_path
// % $aquarium_path/opt/google/chrome/chrome --no-sandbox --enable-features=VaapiVideoDecoder
// navigate to 'chrome://gpu' and verify that everything is working correctly

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

// includes

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <err.h>
#include <grp.h>
#include <paths.h>
#include <pwd.h>

#include <sys/param.h>

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
#include <copyfile.h>
#include <jail.h>
#include <fetch.h>

#include <openssl/sha.h>

// defines

#define STONERS_GROUP "stoners"

#define BASE_PATH "/etc/aquariums/"

#define TEMPLATES_PATH BASE_PATH "templates/"
#define AQUARIUMS_PATH BASE_PATH "aquariums/"

#define ILLEGAL_TEMPLATE_PREFIX '.'

#define SANCTIONED_TEMPLATES BASE_PATH "templates_remote"
#define AQUARIUM_DB_PATH     BASE_PATH "aquarium_db"

#define PROGRESS_FREQUENCY  (1 << 22)
#define FETCH_CHUNK_BYTES   (1 << 16)
#define ARCHIVE_CHUNK_BYTES (1 << 12)

// macros

#define IOV(name, val) \
	(struct iovec) { .iov_base = (name), .iov_len = strlen((name)) + 1 }, \
	(struct iovec) { .iov_base = (val ), .iov_len = strlen((val )) + 1 }

#define JAILPARAM(i, key, val) \
	jailparam_init  (&args[(i)], (key)); \
	jailparam_import(&args[(i)], (val));

// options

static char* template = "amd64.aquabsd.dev";
static char* path = NULL;

static void __dead2 usage(void) {
	fprintf(stderr,
		"usage: %1$s [-v]\n"
		"       %1$s [-v] -c path [-t template]\n"
		"       %1$s [-v] -e path\n"
		"       %1$s [-v] -l\n"
		"       %1$s [-v] -s\n",
	getprogname());

	exit(EXIT_FAILURE);
}

// utility functions

typedef enum {
	OS_GENERIC, OS_FBSD, OS_LINUX
} os_info_t;

static inline os_info_t __retrieve_os_info(void) {
	// this method of retrieving OS info relies on the existence of an /etc/os-release file on the installation
	// all officially supported OS' for aquariums should have this file, else they'll simply be reported as 'OS_GENERIC'

	FILE* fp = fopen("etc/os-release", "r");

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

static void load_linux_kmod(void) {
	if (!kldload("linux64")) {
		return;
	}

	if (errno == EEXIST) {
		return;
	}

	// jammer, iets is fout gegaan

	if (errno == ENOEXEC) {
		errx(EXIT_FAILURE, "kldload(\"linux64\"): please check dmesg(8) for details (or don't, I'm not your mum)");
	}

	errx(EXIT_FAILURE, "kldload(\"linux64\"): %s", strerror(errno));
}

typedef struct {
	char* pointer_path;
	char* aquarium_path;
} db_ent_t;

static bool next_db_ent(db_ent_t* ent, size_t buf_len, char buf[buf_len], FILE* fp, bool be_dramatic) {
	char* line = fgets(buf, buf_len, fp);

	if (!line) {
		return false;
	}

	// remove potential trailing newline

	size_t end_i = strlen(line) - 1;

	if (line[end_i] == '\n') {
		line[end_i] = '\0';
	}

	// parse tokens

	char* pointer_path  = strsep(&line, ":");
	char* aquarium_path = strsep(&line, ":");

	if (be_dramatic && (!pointer_path || !aquarium_path)) {
		errx(EXIT_FAILURE, "Aquarium database file %s has an invalid format", AQUARIUM_DB_PATH);
	}

	ent->pointer_path  = pointer_path;
	ent->aquarium_path = aquarium_path;

	return true;
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

static int do_list(void) {
	FILE* fp = fopen(AQUARIUM_DB_PATH, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", AQUARIUM_DB_PATH, strerror(errno));
	}

	printf("POINTER\tAQUARIUM\n");

	char buf[1024];
	db_ent_t ent;

	while (next_db_ent(&ent, sizeof buf, buf, fp, true)) {
		printf("%s\t%s\n", ent.pointer_path, ent.aquarium_path);
	}

	fclose(fp);

	return EXIT_SUCCESS;
}

static int do_list_templates(void) {
	DIR* dp = opendir(TEMPLATES_PATH);

	if (!dp) {
		errx(EXIT_FAILURE, "opendir: failed to open template directory %s: %s", TEMPLATES_PATH, strerror(errno));
	}

	printf("ARCH\tOS\tVERS\n");

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

	return EXIT_SUCCESS;
}

// creating aquariums (takes in a template name):
//  - check if template exists
//  - open pointer file for writing
//  - setuid root
//  - extract template in some aquariums folder if it exists
//  - if it doesn't, first download it, and compare hashed to a database of trusted templates to make sure there isn't anything weird going on
//  - create user and stuff
//  - do any final setup (e.g. copying '/etc/resolv.conf' for networking)
//  - write path of pointer file & its associated aquarium to aquarium database (and give it some unique ID)
//  - setuid user (CHECK FOR ERRORS!)
//  - write unique ID to pointer file

static inline void __download_template(const char* template) {
	// read list of sanctioned templates, and see if we have a match

	FILE* fp = fopen(SANCTIONED_TEMPLATES, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", SANCTIONED_TEMPLATES, strerror(errno));
	}

	char buf[1024]; // I don't super like doing this, but it's unlikely we'll run into any problems
	char* line;

	char* name;
	char* protocol;
	char* url;
	size_t bytes;
	char* sha256;

	while ((line = fgets(buf, sizeof buf, fp))) { // fgets reads one less than 'size', so we're fine just padding 'sizeof buf'
		enum {
			NAME, PROTOCOL, URL, BYTES, SHA256, SENTINEL
		} kind = 0;

		name = NULL;
		protocol = NULL;
		url = NULL;
		bytes = 0;
		sha256 = NULL;

		char* tok;

		while ((tok = strsep(&line, ":"))) {
			if (kind == NAME) {
				name = tok;

				if (strcmp(name, template)) {
					goto next;
				}
			}

			else if (kind == PROTOCOL) {
				protocol = tok;
			}

			else if (kind == URL) {
				url = tok;
			}

			else if (kind == BYTES) {
				__attribute__((unused)) char* endptr;
				bytes = strtol(tok, &endptr, 10);
			}

			else if (kind == SHA256) {
				sha256 = tok;
				sha256[strlen(sha256) - 1] = '\0';
			}

			if (++kind >= SENTINEL) {
				break;
			}
		}

		// we've found our template at this point

		goto found;

	next:

		continue;
	}

	// we didn't find our template, unfortunately :(

	fclose(fp);
	errx(EXIT_FAILURE, "Couldn't find template %s in list of sanctioned templates (%s)", template, SANCTIONED_TEMPLATES);

found:

	fclose(fp);

	// found template, start downloading it
	// it's initially downloaded with a '.' prefix, because otherwise, there's a potential for a race condition
	// e.g., if we downloaded it in its final destination, the template could be malicious, and an actor could coerce the user into creating an aquarium from that template before the checks have terminated
	// realistically, there's a slim chance of this, unless said malicious actor could somehow stall the SHA256 digesting, but we shouldn't rely on this if we can help it

	char* composed_url;
	asprintf(&composed_url, "%s://%s", protocol, url);

	printf("Found template, downloading from %s ...\n", composed_url);

	char* path; // don't care about freeing this (TODO: although I probably will if I factor this out into a libaquarium library)
	asprintf(&path, TEMPLATES_PATH "%c%s.txz", ILLEGAL_TEMPLATE_PREFIX, name);

	/* FILE* */ fp = fopen(path, "w");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", path, strerror(errno));
	}

	FILE* fetch_fp = fetchGetURL(composed_url, "");

	if (!fetch_fp) {
		fclose(fp);
		errx(EXIT_FAILURE, "Failed to download %s", composed_url);
	}

	free(composed_url);

	// checking (size & hash) stuff

	size_t total = 0;

	SHA256_CTX sha_context;
	SHA256_Init(&sha_context);

	// start download

	uint8_t chunk[FETCH_CHUNK_BYTES];
	size_t chunk_bytes;

	while ((chunk_bytes = fread(chunk, 1, sizeof chunk, fetch_fp)) > 0) {
		total += chunk_bytes;

		if (!(total % PROGRESS_FREQUENCY)) {
			float progress = (float) total / bytes;
			printf("Downloading %f%% done\n", progress * 100);
		}

		SHA256_Update(&sha_context, chunk, chunk_bytes);

		if (fwrite(chunk, 1, chunk_bytes, fp) < chunk_bytes) {
			break;
		}
	}

	// clean up & process SHA256 digest

	fclose(fp);
	fclose(fetch_fp);

	uint8_t hash[SHA256_DIGEST_LENGTH];
	SHA256_Final(hash, &sha_context);

	char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1] = { 0 }; // each byte in the hash can be represented with two hex digits

	for (size_t i = 0; i < sizeof hash; i++) {
		snprintf(hash_hex, sizeof hash_hex, "%s%02x", hash_hex, hash[i]);
	}

	// template has been downloaded, check its size & SHA256 hash

	if (total != bytes) {
		if (remove(path) < 0) {
			errx(EXIT_FAILURE, "remove: failed to remove %s: %s", path, strerror(errno));
		}

		errx(EXIT_FAILURE, "Total size of downloaded template (%zu bytes) is not the size expected (%zu bytes). Someone may be trying to swindle you!", total, bytes);
	}

	if (strcmp(hash_hex, sha256)) {
		if (remove(path) < 0) {
			errx(EXIT_FAILURE, "remove: failed to remove %s: %s", path, strerror(errno));
		}

		errx(EXIT_FAILURE, "SHA256 hash of downloaded template (%s) is not the same as expected (%s). Someone may be trying to swindle you!", hash_hex, sha256);
	}

	// checks have succeeded; move temporary file to permanent position

	char* final_path; // don't care about freeing this (TODO: although I probably will if I factor this out into a libaquarium library)
	asprintf(&final_path, TEMPLATES_PATH "%s.txz", name);

	if (rename(path, final_path) < 0) {
		errx(EXIT_FAILURE, "rename: failed to rename %s to %s: %s", path, final_path, strerror(errno));
	}
}

static int do_create(void) {
	// a few simple checks

	if (!path) {
		usage();
	}

	if (*template == ILLEGAL_TEMPLATE_PREFIX) {
		errx(EXIT_FAILURE, "%s template is illegal (starts with ILLEGAL_TEMPLATE_PREFIX, '%c'). Someone may be trying to swindle you!", template, ILLEGAL_TEMPLATE_PREFIX);
	}

	// generate final aquarium path

	char* aquarium_path; // don't care about freeing this (TODO: although I probably will if I factor this out into a libaquarium library)
	asprintf(&aquarium_path, AQUARIUMS_PATH "%s-XXXXXXX", template);
	aquarium_path = mkdtemp(aquarium_path);

	if (!aquarium_path) {
		errx(EXIT_FAILURE, "mkdtemp: failed to create aquarium directory: %s", strerror(errno));
	}

	// write to pointer file

	FILE* fp = fopen(path, "wx");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", path, strerror(errno));
	}

	fprintf(fp, "%s", aquarium_path);
	fclose(fp);

	// check that pointer file isn't already in the aquarium database
	// TODO haven't yet thought about how safe this'd be, but since the aquarium database also contains what the pointer file was supposed to point to, maybe it could be cool for this to automatically regenerate the pointer file instead of erroring?

	char* abs_path = realpath(path, NULL);

	if (!abs_path) {
		errx(EXIT_FAILURE, "realpath: %s", strerror(errno));
	}

	/* FILE* */ fp = fopen(AQUARIUM_DB_PATH, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", AQUARIUM_DB_PATH, strerror(errno));
	}

	char buf[1024];
	db_ent_t ent;

	while (next_db_ent(&ent, sizeof buf, buf, fp, true)) {
		if (!strcmp(ent.pointer_path, abs_path)) {
			errx(EXIT_FAILURE, "Pointer file already exists in the aquarium database at %s (pointer file is supposed to reside at %s and point to %s)", AQUARIUM_DB_PATH, ent.pointer_path, ent.aquarium_path);
		}
	}

	fclose(fp);

	// setuid root

	uid_t uid = getuid();

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid: %s", strerror(errno));
	}

	// build template path

	char* template_path; // don't care about freeing this (TODO: although I probably will if I factor this out into a libaquarium library)
	asprintf(&template_path, TEMPLATES_PATH "%s.txz", template);

	if (access(template_path, R_OK) < 0) {
		// file template doesn't yet exist; download & check it
		__download_template(template);
	}

	// make & change into final aquarium directory
	// as per archive_write_disk(3)'s "BUGS" section, we mustn't call 'chdir' between opening and closing archive objects

	if (chdir(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chdir: %s", strerror(errno));
	}

	// open archive

	struct archive* archive = archive_read_new();

	archive_read_support_filter_all(archive);
	archive_read_support_format_all(archive);

	if (archive_read_open_filename(archive, template_path, ARCHIVE_CHUNK_BYTES) < 0) {
		errx(EXIT_FAILURE, "archive_read_open_filename: failed to open %s template: %s", template_path, archive_error_string(archive));
	}

	// extract archive

	while (1) {
		struct archive_entry* entry;
		int res = archive_read_next_header(archive, &entry);

		if (res == ARCHIVE_OK) {
			// TODO when multithreading, the 'ARCHIVE_EXTRACT_ACL' flag results in a bus error
			//      it would seem as though there is a bug in 'libarchive', but unfortunately I have not yet had the time to resolve it

			res = archive_read_extract(archive, entry, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_OWNER | ARCHIVE_EXTRACT_PERM | /*ARCHIVE_EXTRACT_ACL |*/ ARCHIVE_EXTRACT_XATTR | ARCHIVE_EXTRACT_FFLAGS);
		}

		if (res == ARCHIVE_EOF) {
			break;
		}

		const char* error_string = archive_error_string(archive);
		unsigned useless_warning = error_string && !strcmp(error_string, "Can't restore time");

		if (res != ARCHIVE_OK && !(res == ARCHIVE_WARN && useless_warning)) {
			errx(EXIT_FAILURE, "archive_read_next_header: %s", error_string);
		}
	}

	// reached success

	archive_read_close(archive);
	archive_read_free(archive);

	// copy over /etc/resolv.conf for networking to, well, work

	#define COPYFILE_DEBUG (1 << 31)

	if (copyfile("/etc/resolv.conf", "etc/resolv.conf", 0, COPYFILE_ALL) < 0) {
		errx(EXIT_FAILURE, "copyfile: %s", strerror(errno));
	}

	// write info to aquarium database

	/* FILE* */ fp = fopen(AQUARIUM_DB_PATH, "a");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", AQUARIUM_DB_PATH, strerror(errno));
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

	os_info_t os = __retrieve_os_info();
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
		load_linux_kmod();

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

	struct jailparam args[7] = { 0 };

	JAILPARAM(0, "name", name);
	JAILPARAM(1, "path", aquarium_path);
	JAILPARAM(2, "host", NULL);
	JAILPARAM(3, "host.hostname", name);
	JAILPARAM(4, "vnet", NULL);
	JAILPARAM(5, "allow.raw_sockets", "true"); // allow for sending ICMP packets (for ping)
	JAILPARAM(6, "allow.socket_af", "true");

	if (jailparam_set(args, sizeof(args) / sizeof(*args), JAIL_CREATE | JAIL_ATTACH) < 0) {
		errx(EXIT_FAILURE, "jailparam_set: %s", strerror(errno));
	}

	jailparam_free(args, sizeof(args) / sizeof(*args));

	// fork the process and run that initial setup script
	// then, wait for it to finish parent-side (and check for errors blah blah)

	pid_t setup_pid = fork();

	if (!setup_pid) {
		// child process here

		execl("/bin/sh", "/bin/sh", "-c", setup_script, NULL);
		_exit(EXIT_FAILURE);
	}

	int child_rv = __wait_for_process(setup_pid);

	if (child_rv < 0) {
		errx(EXIT_FAILURE, "Child setup process exited with error code %d", child_rv);
	}

	// finish writing pointer file as user

	if (setuid(uid) < 0) {
		errx(EXIT_FAILURE, "setuid: %s", strerror(errno));
	}

	return EXIT_SUCCESS;
}

// entering aquariums (takes in a pointer file):
//  - make sure the path of the pointer file is well the one contained in the relevant entry of the aquarium database
//  - mount necessary filesystems (linsysfs, linprocfs, &c)
//  - link (or bind mount) necessary directories (/dev, /tmp if specified, &c)
//  - actually enter the aquarium

static int do_enter(void) {
	// read the pointer file

	FILE* fp = fopen(path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", path, strerror(errno));
	}

	fseek(fp, 0, SEEK_END);
	size_t len = ftell(fp);

	rewind(fp);

	char* aquarium_path = malloc(len + 1);
	aquarium_path[len] = 0;

	if (fread(aquarium_path, 1, len, fp) != len) {
		errx(EXIT_FAILURE, "fread: %s", strerror(errno));
	}

	fclose(fp);

	// make sure the path of the pointer file is well the one contained in the relevant entry of the aquarium database

	char* abs_path = realpath(path, NULL);

	if (!abs_path) {
		errx(EXIT_FAILURE, "realpath: %s", strerror(errno));
	}

	/* FILE* */ fp = fopen(AQUARIUM_DB_PATH, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", AQUARIUM_DB_PATH, strerror(errno));
	}

	char buf[1024];
	db_ent_t ent;

	while (next_db_ent(&ent, sizeof buf, buf, fp, true)) {
		if (strcmp(ent.pointer_path, abs_path)) {
			continue;
		}

		if (strcmp(ent.aquarium_path, aquarium_path)) {
			errx(EXIT_FAILURE, "Found pointer file in the aquarium database, but it doesn't point to the correct aquarium (%s vs %s)", aquarium_path, ent.aquarium_path);
		}

		goto found;
	}

	errx(EXIT_FAILURE, "Could not find pointer file %s in the aquarium database", abs_path);

found:

	free(abs_path);
	fclose(fp);

	// change into the aquarium directory

	if (chdir(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chdir: %s", strerror(errno));
	}

	// setuid root

	uid_t uid = getuid();

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid: %s", strerror(errno));
	}

	// mount devfs filesystem

	struct iovec iov_dev[] = {
		IOV("fstype", "devfs"),
		IOV("fspath", "dev"),
	};

	if (nmount(iov_dev, sizeof(iov_dev) / sizeof(*iov_dev), 0) < 0) {
		errx(EXIT_FAILURE, "nmount: failed to mount devfs: %s", strerror(errno));
	}

	// mount nullfs filesystem for /tmp
	// this will link the contents of /tmp between the aquarium and the host
	// we don't wanna overwrite anything potentially already inside of /tmp
	// to do that, the manual (nmount(2)) suggests we use the MNT_EMPTYDIR flag
	// there seem to be a few inconsistencies vis-à-vis the type of 'flags', so instead we can simply use the 'emptydir' iov (as can be seen in '/usr/include/sys/mount.h')

	struct iovec iov_tmp[] = {
		IOV("fstype", "nullfs"),
		IOV("fspath", "tmp"),
		IOV("target", "/tmp"),
		IOV("emptydir", ""),
	};

	if (nmount(iov_tmp, sizeof(iov_tmp) / sizeof(*iov_tmp), 0) < 0 && errno != ENOTEMPTY) {
		errx(EXIT_FAILURE, "nmount: failed to mount nullfs for /tmp: %s", strerror(errno));
	}

	// OS-specific actions
	// treat OS_GENERIC OS' as the default (i.e. like their host OS)

	os_info_t os = __retrieve_os_info();

	if (os == OS_LINUX) {
		load_linux_kmod();

		// mount /dev/shm as tmpfs
		// on linux, this needs to have mode 1777

		struct iovec iov_shm[] = {
			IOV("fstype", "tmpfs"),
			IOV("fspath", "dev/shm"),
			IOV("mode", "1777"),
		};

		if (nmount(iov_shm, sizeof(iov_shm) / sizeof(*iov_shm), 0) < 0) {
			errx(EXIT_FAILURE, "nmount: failed to mount shm tmpfs: %s", strerror(errno));
		}

		// mount fdescfs (with linrdlnk)

		struct iovec iov_fd[] = {
			IOV("fstype", "fdescfs"),
			IOV("fspath", "dev/fd"),
			IOV("linrdlnk", ""),
		};

		if (nmount(iov_fd, sizeof(iov_fd) / sizeof(*iov_fd), 0) < 0) {
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

		struct iovec iov_fd[] = {
			IOV("fstype", "fdescfs"),
			IOV("fspath", "dev/fd"),
		};

		if (nmount(iov_fd, sizeof(iov_fd) / sizeof(*iov_fd), 0) < 0) {
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

	char* name = strrchr(path, '/');

	if (!name) {
		name = path;
	}

	struct jailparam args[7] = { 0 };

	JAILPARAM(0, "name", name);
	JAILPARAM(1, "path", aquarium_path);
	JAILPARAM(2, "host", NULL);
	JAILPARAM(3, "host.hostname", name);
	JAILPARAM(4, "vnet", NULL);
	JAILPARAM(5, "allow.raw_sockets", "true"); // allow for sending ICMP packets (for ping)
	JAILPARAM(6, "allow.socket_af", "true");

	if (jailparam_set(args, sizeof(args) / sizeof(*args), JAIL_CREATE | JAIL_ATTACH) < 0) {
		errx(EXIT_FAILURE, "jailparam_set: %s", strerror(errno));
	}

	jailparam_free(args, sizeof(args) / sizeof(*args));

	// unfortunately we kinda need to use execlp here
	// different OS' may have different locations for the sh binary

	return execlp("sh", "sh", NULL);
}

// sweeping aquariums (takes in nothing):
//  - go through aquarium database
//  - if a valid pointer file doesn't exist at the path in the database, we say the aquarium has been "orphaned"
//  - if an aquarium is orphaned, we can safely delete it and remove it from the aquarium database

static void __remove_aquarium(char* aquarium_path) {
	if (chdir(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chdir: %s", strerror(errno));
	}

	// first, we make sure all possible mounted filesystems are unmounted (we do this all twice for a bit of encouragement)
	// things may go wrong unmounting, but that's a problem we can delegate to the subsequent rm call
	// similarly, the aquarium may have already been deleted (e.g. by a nosy user)
	// so we don't wanna do anything with the return value of '__wait_for_process'

	for (int i = 0; i < 2; i++) {
		unmount("dev",     MNT_FORCE);
		unmount("dev/fd",  MNT_FORCE);
		unmount("dev/shm", MNT_FORCE);
		unmount("proc",    MNT_FORCE);
		unmount("sys",     MNT_FORCE);
		unmount("tmp",     MNT_FORCE);
	}

	// then, we remove all the aquarium files
	// TODO I desperately need some easy API for removing files in the standard library on aquaBSD
	//      I'm not (I hope) dumb enough to do something like 'asprint(&cmd, "rm -rf %s", ent.aquarium_path)', but I know damn well other developers would be tempted to do such a thing given no other alternative

	pid_t rm_pid = fork();

	if (!rm_pid) {
		execl("/bin/rm", "/bin/rm", "-rf", aquarium_path, NULL);
		_exit(EXIT_FAILURE);
	}

	__wait_for_process(rm_pid);
}

static int do_sweep(void) {
	// list of database entries which survive the sweep

	size_t survivors_len = 0;
	db_ent_t* survivors = NULL;

	// go through aquarium database

	FILE* fp = fopen(AQUARIUM_DB_PATH, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", AQUARIUM_DB_PATH, strerror(errno));
	}

	char buf[1024];
	db_ent_t ent;

	while (next_db_ent(&ent, sizeof buf, buf, fp, false)) {
		// if something went wrong reading an entry (e.g. it's malformed), simply discard it
		// there is a chance then that some aquariums or pointer files will be left behind, but eh rather that than risk deleting something we shouldn't
		// also, under normal operation, this kind of condition shouldn't occur

		if (!ent.pointer_path || !ent.aquarium_path) {
			continue;
		}

		// if we can't find pointer file, remove the aquarium and that entry from the aquarium database

		if (access(ent.pointer_path, R_OK) < 0) {
			__remove_aquarium(ent.aquarium_path);

			// discard this entry obviously, we don't want nuffin to do with it no more 😡

			continue;
		}

		// if we can't find aquarium, remove the pointer file and that entry from the aquarium database
		// not sure under which circumstances this kind of stuff could happen, but handle it anyway

		if (access(ent.aquarium_path, R_OK) < 0) {
			// attempt to remove the pointer file
			// we don't care to do anything on error, because the file may very well have already been removed by the user

			remove(ent.pointer_path);

			// discard this entry &c &c

			continue;
		}

		// congratulations to the database entry! 🎉
		// it has survived unto the next sweep!

		survivors = realloc(survivors, (survivors_len + 1) * sizeof *survivors);
		db_ent_t* survivor = &survivors[survivors_len++];

		survivor->pointer_path  = strdup(ent.pointer_path);
		survivor->aquarium_path = strdup(ent.aquarium_path);
	}

	fclose(fp);

	// keep things nice and clean is to go through everything under /etc/aquariums/aquariums and see which aquariums were never "recensés" (censused?)

	DIR* dp = opendir(AQUARIUMS_PATH);

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
			db_ent_t* survivor = &survivors[i];
			char* aquarium = strrchr(survivor->aquarium_path, '/');

			aquarium += !!*aquarium;

			if (!strcmp(aquarium, name)) {
				goto found;
			}
		}

		// ah! couldn't find the aquarium in the list of survivors! remove it!

		char* aquarium_path;
		asprintf(&aquarium_path, "%s/%s", AQUARIUMS_PATH, name);

		__remove_aquarium(aquarium_path);
		free(aquarium_path);

	found:

		continue; // need something after a label in C for some reason
	}

	closedir(dp);

	// last thing to do is rebuild new aquarium database file with the entries that survived

	/* FILE* */ fp = fopen(AQUARIUM_DB_PATH, "w");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", AQUARIUM_DB_PATH, strerror(errno));
	}

	for (size_t i = 0; i < survivors_len; i++) {
		db_ent_t* survivor = &survivors[i];

		fprintf(fp, "%s:%s\n", survivor->pointer_path, survivor->aquarium_path);

		free(survivor->pointer_path);
		free(survivor->aquarium_path);
	}

	fclose(fp);
	free(survivors);

	return 0;
}

// main function

typedef int (*action_t) (void);

int main(int argc, char* argv[]) {
	action_t action = do_list;

	// parse options

	int c;

	while ((c = getopt(argc, argv, "c:e:lst:")) != -1) {
		// action options

		if (c == 'c') {
			action = do_create;
			path = optarg;
		}

		else if (c == 'e') {
			action = do_enter;
			path = optarg;
		}

		else if (c == 'l') {
			action = do_list_templates;
		}

		else if (c == 's') {
			action = do_sweep;
		}

		// name-passing options

		else if (c == 't') {
			template = optarg;
		}

		else {
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	// make sure the $STONERS_GROUP group exists, and error if not

	struct group* stoners_group = getgrnam(STONERS_GROUP);

	if (!stoners_group) {
		errx(EXIT_FAILURE, "Couldn't find \"" STONERS_GROUP "\" group");
	}

	endgrent();

	// make sure user is part of the $STONERS_GROUP group

	uid_t uid = getuid();
	struct passwd* passwd = getpwuid(uid);

	char** stoners = stoners_group->gr_mem;

	while (*stoners) {
		if (!strcmp(*stoners++, passwd->pw_name)) {
			goto okay;
		}
	}

	errx(EXIT_FAILURE, "%s is not part of the \"" STONERS_GROUP "\" group", passwd->pw_name);

okay:

	return action();
}
