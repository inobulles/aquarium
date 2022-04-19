// TODO
//  - factor out a libaquarium library from the aquarium frontend
//  - manual page
//  - tests

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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <err.h>
#include <grp.h>
#include <pwd.h>

// TODO the two following headers are necessary for 'fetch.h' but are not included
//      most likely a bug, fix this

#include <sys/param.h>
#include <time.h>

#include <archive.h>
#include <copyfile.h>
#include <fetch.h>

// defines

#define STONERS_GROUP "stoners"

#define BASE_PATH "/etc/aquariums/"

#define TEMPLATES_PATH BASE_PATH "templates/"
#define AQUARIUMS_PATH BASE_PATH "aquariums/"

#define SANCTIONED_TEMPLATES   BASE_PATH "template_remote"
#define AQUARIUM_DATABASE_PATH BASE_PATH "aquariums_db"

#define ARCHIVE_CHUNK_BYTES 4096

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

// actions

static int do_list(void) {
	// TODO list templates
	return EXIT_FAILURE;
}

static int do_create(void) {
	if (!path) {
		usage();
	}

	// build template path

	char* template_path; // don't care about freeing this
	asprintf(&template_path, TEMPLATES_PATH "%s.txz", template);

	// TODO check here if the template exists, and do the whole downloading & hash checking dance if not

	// open aquarium pointer file for writing

	FILE* fp = fopen(path, "w");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s\n", path, strerror(errno));
	}

	// setuid root

	uid_t uid = getuid();

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid: %s\n", strerror(errno));
	}

	// make & change into final aquarium directory
	// as per archive_write_disk(3)'s "BUGS" section, we mustn't call 'chdir' between opening and closing archive objects

	char* aquarium_path; // don't care about freeing this
	asprintf(&aquarium_path, AQUARIUMS_PATH "%s-XXXXXXX", template);
	aquarium_path = mkdtemp(aquarium_path);

	if (!aquarium_path) {
		errx(EXIT_FAILURE, "mkdtemp: failed to create aquarium directory: %s\n", strerror(errno));
	}

	if (chdir(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chdir: %s\n", strerror(errno));
	}

	// open archive

	struct archive* archive = archive_read_new();

	archive_read_support_filter_all(archive);
	archive_read_support_format_all(archive);

	if (archive_read_open_filename(archive, template_path, ARCHIVE_CHUNK_BYTES) < 0) {
		errx(EXIT_FAILURE, "archive_read_open_filename: failed to open %s template: %s\n", template_path, archive_error_string(archive));
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
		unsigned useless_warning = error_string && strcmp(error_string, "Can't restore time") == 0;

		if (res != ARCHIVE_OK && !(res == ARCHIVE_WARN && useless_warning)) {
			errx(EXIT_FAILURE, "archive_read_next_header: %s\n", error_string);
		}
	}

	// reached success

	archive_read_close(archive);
	archive_read_free(archive);

	// copy over /etc/resolv.conf for networking to, well, work

	if (copyfile("/etc/resolv.conf", "etc/resolv.conf", 0, COPYFILE_ALL) < 0) {
		errx(EXIT_FAILURE, "copyfile: %s\n", strerror(errno));
	}

	// TODO write info to aquarium database

	// finish writing aquarium pointer file as user

	if (setuid(uid) < 0) {
		errx(EXIT_FAILURE, "setuid: %s\n", strerror(errno));
	}

	fprintf(fp, "%s %s", template, aquarium_path);
	fclose(fp);

	return EXIT_SUCCESS;
}

static int do_enter(void) {
	// TODO enter aquarium
	return EXIT_FAILURE;
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
		errx(EXIT_FAILURE, "Couldn't find \"" STONERS_GROUP "\" group\n");
	}

	endgrent();

	// make sure user is part of the $STONERS_GROUP group

	LOG("Making sure user is part of group (gid = %d)\n", stoners_group->gr_gid)

	uid_t uid = getuid();
	struct passwd* passwd = getpwuid(uid);

	char** stoners = stoners_group->gr_mem;

	while (*stoners) {
		if (strcmp(*stoners++, passwd->pw_name) == 0) {
			goto okay;
		}
	}

	errx(EXIT_FAILURE, "%s is not part of the \"" STONERS_GROUP "\" group\n", passwd->pw_name);

okay:

	LOG("Doing action\n");
	return action();
}