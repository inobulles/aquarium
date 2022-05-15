// TODO
//  - factor out a libaquarium library from the aquarium frontend
//  - manual page
//  - tests

// building:
// $ cc aquarium.c -larchive -lfetch -lcrypto -o aquarium
// $ chmod u+s aquarium && chown root:wheel aquarium

// create group:
// $ pw groupadd stoners
// $ pw groupmod stoners -g 420 -m obiwac

// some aquarium terminology:
//  - "templates" are the templates from which aquariums are created (immutable)
//  - "aquariums" are the actual instances of a certain template (mutable, they have a unique ID)
//  - "aquarium pointer files" are the files which users interact with to interact with aquariums (immutable, they can be moved by the user, but then it loses its status as an aquarium pointer file)

// creating aquariums (takes in a template name):
//  - check if template exists
//  - open aquarium pointer file for writing
//  - setuid root
//  - extract template in some aquariums folder if it exists
//  - if it doesn't, first download it, and compare hashed to a database of trusted templates to make sure there isn't anything weird going on
//  - create user and stuff
//  - do any final setup (e.g. copying '/etc/resolv.conf' for networking)
//  - write path of aquarium pointer file & its associated aquarium to aquarium database (and give it some unique ID)
//  - setuid user (CHECK FOR ERRORS!)
//  - write unique ID to aquarium pointer file

// entering aquariums (takes in an aquarium pointer file):
//  - make sure the path of the aquarium pointer file is well the one contained in the relevant entry of the aquarium database
//  - mount necessary filesystems (linsysfs, linprocfs, &c)
//  - link (or bind mount) necessary directories (/dev, /tmp if specified, &c)
//  - chroot into that aquarium and login as the user wanting to enter the aquarium

// autocleaning aquariums (takes in nothing):
//  - go through aquarium database
//  - if a valid aquarium pointer file doesn't exist at the path in the database, we say the aquarium has been "orphaned"
//  - if an aquarium is orphaned, we can safely delete it and remove it from the aquarium database

// recovering aquariums (takes in nothing):
//  - since we keep a record of all the aquarium pointer files, we can actually recover them if a user accidentally deletes one
//  - basically, follow the same steps, except if an aquarium is orphaned, regenerate its aquarium pointer file instead of deleting the aquarium and its database entry

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

#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/uio.h>

// TODO the two following headers are necessary for 'fetch.h' but are not included
//      most likely a bug, fix this

#include <sys/param.h>
#include <time.h>

#include <archive.h>
#include <copyfile.h>
#include <fetch.h>

#include <openssl/sha.h>

// defines

#define STONERS_GROUP "stoners"

#define BASE_PATH "/etc/aquariums/"

#define TEMPLATES_PATH BASE_PATH "templates/"
#define AQUARIUMS_PATH BASE_PATH "aquariums/"

#define ILLEGAL_TEMPLATE_PREFIX '.'

#define SANCTIONED_TEMPLATES   BASE_PATH "templates_remote"
#define AQUARIUM_DATABASE_PATH BASE_PATH "aquariums_db"

#define PROGRESS_FREQUENCY  (1 << 22)
#define FETCH_CHUNK_BYTES   (1 << 16)
#define ARCHIVE_CHUNK_BYTES (1 << 12)

#define LOG(...) \
	if (verbose) { \
		printf(__VA_ARGS__); \
	}

// options

static bool verbose = false;

static char* template = "amd64.aquabsd.dev";
static char* path = NULL;

static void __dead2 usage(void) {
	fprintf(stderr,
		"usage: %1$s [-v]\n"
		"       %1$s [-v] -c path [-t template]\n"
		"       %1$s [-v] -e path\n",
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

	char buf[256];
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

// actions

static int do_list(void) {
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

	return EXIT_FAILURE;
}

static inline void __download_template(const char* template) {
	// read list of sanctioned templates, and see if we have a match

	FILE* fp = fopen(SANCTIONED_TEMPLATES, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", SANCTIONED_TEMPLATES, strerror(errno));
	}

	char buf[1024]; // I don't super like doing this, but it's unlikely we'll run into any problems
	char* line;

	char* name;
	char* url;
	size_t bytes;
	char* sha256;

	while ((line = fgets(buf, sizeof buf, fp))) { // fgets reads one less than 'size', so we're fine just padding 'sizeof buf'
		enum {
			NAME, URL, BYTES, SHA256, SENTINEL
		} kind = 0;

		name = NULL;
		url = NULL;
		bytes = 0;
		sha256 = NULL;

		char* tok;

		while ((tok = strsep(&line, " "))) {
			if (kind == NAME) {
				name = tok;

				if (strcmp(name, template)) {
					goto next;
				}
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

	printf("Found template, downloading from %s ...\n", url);

	char* path; // don't care about freeing this (TODO: although I probably will if I factor this out into a libaquarium library)
	asprintf(&path, TEMPLATES_PATH "%c%s.txz", ILLEGAL_TEMPLATE_PREFIX, name);

	/* FILE* */ fp = fopen(path, "w");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", path, strerror(errno));
	}

	FILE* fetch_fp = fetchGetURL(url, "");

	if (!fetch_fp) {
		fclose(fp);
		errx(EXIT_FAILURE, "Failed to download %s", url);
	}

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

	// write to aquarium pointer file

	FILE* fp = fopen(path, "wx");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", path, strerror(errno));
	}

	fprintf(fp, "%s", aquarium_path);
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
	// TODO copyfile: Operation not supported

	system("cp /etc/resolv.conf etc/resolv.conf");

	// if (copyfile("/etc/resolv.conf", "etc/resolv.conf", 0, COPYFILE_ALL) < 0) {
	// 	errx(EXIT_FAILURE, "copyfile: %s", strerror(errno));
	// }

	// enter the newly created aquarium to do a bit of configuration
	// we can't do this is all in C, because, well, there's a chance the template is not the operating system we're currently running
	// this does thus depend a lot on the platform we're running on
	// TODO for the moment this is all hardcoded, but in all likelyhood, this will be in a script found somewhere in the aquarium template
	//      this could probably be quite easy if all the aquarium info was passed as a standard set of environment variables or something
	//      the only problem with having a script in the aquarium, is that images must be built with the knowledge they may be run in an aquarium

	os_info_t os = __retrieve_os_info();

	if (chroot(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chroot: %s", strerror(errno));
	}

	if (os == OS_LINUX) {
		// for that sudo problem, see: https://askubuntu.com/questions/59458/error-message-sudo-unable-to-resolve-host-none
		system("useradd obiwac -u 1001 -m -s /bin/bash && passwd -d obiwac && echo 'obiwac ALL=(ALL:ALL) ALL' >> /etc/sudoers");
	}

	else {
		system("pw useradd obiwac -u 1001 -m -s /bin/sh -G wheel -w none");
	}

	// TODO write info to aquarium database

	// finish writing aquarium pointer file as user

	if (setuid(uid) < 0) {
		errx(EXIT_FAILURE, "setuid: %s", strerror(errno));
	}

	return EXIT_SUCCESS;
}

static int do_enter(void) {
	// read the aquarium pointer file

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

	// TODO make sure the path of the aquarium pointer file is well the one contained in the relevant entry of the aquarium database

	if (chdir(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chdir: %s", strerror(errno));
	}

	// setuid root

	uid_t uid = getuid();

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid: %s", strerror(errno));
	}

	// mount devfs filesystem

	#define IOV(name, val) \
		(struct iovec) { .iov_base = (name), .iov_len = strlen((name)) + 1 }, \
		(struct iovec) { .iov_base = (val ), .iov_len = strlen((val )) + 1 }

	struct iovec iov_dev[] = {
		IOV("fstype", "devfs"),
		IOV("fspath", "dev"),
	};

	if (nmount(iov_dev, sizeof(iov_dev) / sizeof(*iov_dev), 0) < 0) {
		errx(EXIT_FAILURE, "nmount: failed to mount devfs: %s", strerror(errno));
	}

	// mount tmpfs filesystem
	// we don't wanna overwrite anything potentially already inside of /tmp
	// to do that, the manual (nmount(2)) suggests we use the MNT_EMPTYDIR flag
	// there seem to be a few inconsistencies vis-à-vis the type of 'flags', so instead we can simply use the 'emptydir' iov (as can be seen in '/usr/include/sys/mount.h')

	struct iovec iov_tmp[] = {
		IOV("fstype", "tmpfs"),
		IOV("fspath", "tmp"),
		IOV("emptydir", ""),
	};

	if (nmount(iov_tmp, sizeof(iov_tmp) / sizeof(*iov_tmp), 0) < 0 && errno != ENOTEMPTY) {
		errx(EXIT_FAILURE, "nmount: failed to mount tmpfs: %s", strerror(errno));
	}

	// OS-specific actions
	// treat OS_GENERIC OS' as the default (i.e. like their host OS)

	os_info_t os = __retrieve_os_info();

	if (os == OS_LINUX) {
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
		// mount procfs

		struct iovec iov_proc[] = {
			IOV("fstype", "procfs"),
			IOV("fspath", "proc"),
		};

		if (nmount(iov_proc, sizeof(iov_proc) / sizeof(*iov_proc), 0) < 0) {
			errx(EXIT_FAILURE, "nmount: failed to mount procfs: %s", strerror(errno));
		}
	}

	// actually chroot

	// int flag = PROC_NO_NEW_PRIVS_ENABLE;

	// if (procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_CTL, &flag) < 0) {
	// 	errx(EXIT_FAILURE, "procctl: %s", strerror(errno));
	// }

	struct passwd* passwd = getpwuid(uid); // this must come before the chroot

	if (chroot(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chroot: %s", strerror(errno));
	}

	// if (setuid(uid) < 0) {
	// 	errx(EXIT_FAILURE, "setuid: %s", strerror(errno));
	// }

	// char* shell = NULL; // getenv("SHELL");

	// if (!shell) {
	// 	shell = _PATH_BSHELL; // /bin/sh
	// }

	// execlp(shell, shell, "-i", NULL);
	// errx(EXIT_FAILURE, "%s: %s", shell, strerror(errno));

	execlp("su", "su", "-", passwd->pw_name, NULL);
	// execlp("/bin/login", "/bin/login", "obiwac", NULL);

	return EXIT_SUCCESS;
}

// main function

typedef int (*action_t) (void);

int main(int argc, char* argv[]) {
	action_t action = do_list;

	// parse options

	int c;

	while ((c = getopt(argc, argv, "c:e:t:v")) != -1) {
		// general options

		if (c == 'v') {
			verbose = true;
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

	LOG("Making sure \"" STONERS_GROUP "\" exists\n")

	struct group* stoners_group = getgrnam(STONERS_GROUP);

	if (!stoners_group) {
		errx(EXIT_FAILURE, "Couldn't find \"" STONERS_GROUP "\" group");
	}

	endgrent();

	// make sure user is part of the $STONERS_GROUP group

	LOG("Making sure user is part of group (gid = %d)\n", stoners_group->gr_gid)

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

	LOG("Doing action\n");
	return action();
}
