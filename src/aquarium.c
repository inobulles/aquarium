// TODO
//  - factor out a libaquarium library from the aquarium frontend
//  - manual page
//  - tests
//  - option for listing aquarium database
//  - better way of copying over linux-nvidia-libs (probably best to build the package in a way which assumes it's installing to a Linux install right off the bat, and then have some kind of aquarium mechanism to install packages like 'aquarium -p my-aquarium linux-nvidia-libs-510.39.01.pkg' or something)
//  - better solution than the 'compat.linux.emul_path' sysctl from FreeBSD, because that's super limited
//  - may be interesting to replace instances of fgets with fparseln
//  - remove jails when sweeping (based on hash of aquarium path)

// building:
// $ cc aquarium.c -larchive -lfetch -lcrypto -ljail /usr/lib/libcopyfile.a -o aquarium
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

static char* template = "amd64.aquabsd.0622a";
static char* kernel_template = NULL;

static char* out_path = NULL;
static char* path = NULL;

static bool persist = false;
static char* base_path = DEFAULT_BASE_PATH;
static bool vnet_disable = false;

static char* templates_path;
static char* kernels_path;
static char* aquariums_path;

static char* sanctioned_templates;
static char* aquarium_db_path;

static void __dead2 usage(void) {
	fprintf(stderr,
		"usage: %1$s [-r base]\n"
		"       %1$s [-r base] -c path [-t template] [-k kernel_template]\n"
		"       %1$s [-r base] -f\n"
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

static void load_vmm_kmod(void) {
	__load_kmod("vmm");
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
		errx(EXIT_FAILURE, "Aquarium database file %s has an invalid format", aquarium_db_path);
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

static int do_struct(void) {
	// build filestructure if it doesn't yet exist for convenience
	// also create a sanctioned templates file with some default and trusted entries

	uid_t uid = getuid();

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid(0): %s", strerror(errno));
	}

	mode_t mode = 0770; // read/write/execute for owner (root), read/write/execute for group (stoners, execute access is required to list directory)

	#define SET_PERMS(path) \
		if (stoners_gid && chown((path), 0, stoners_gid) < 0) { \
			errx(EXIT_FAILURE, "chown(\"%s\", 0, %d): %s", (path), stoners_gid, strerror(errno)); \
		} \
		\
		if (chmod((path), mode) < 0) { \
			errx(EXIT_FAILURE, "chmod(\"%s\", 0, 0%o): %s", (path), mode, strerror(errno)); \
		}

	#define TRY_MKDIR(path) \
		if (mkdir((path), mode) < 0 && errno != EEXIST) { \
			errx(EXIT_FAILURE, "mkdir(\"%s\", 0%o): %s", (path), mode, strerror(errno)); \
		} \
		\
		SET_PERMS((path))

	TRY_MKDIR(base_path)

	TRY_MKDIR(templates_path)
	TRY_MKDIR(kernels_path)
	TRY_MKDIR(aquariums_path)

	if (access(sanctioned_templates, R_OK) < 0) {
		FILE* fp = fopen(sanctioned_templates, "wx");

		if (!fp) {
			errx(EXIT_FAILURE, "fopen(\"%s\"): %s", sanctioned_templates, strerror(errno));
		}

		fprintf(fp, "b:amd64.ubuntu.focal:https:github.com/inobulles/bob-linux-images/releases/download/amd64.ubuntu.focal/amd64.ubuntu.focal.txz:123438644:e1236bcc6a755a0db1d0fa34d4f6a942a56a51778a52d344c3d8c9c4f3b13682\n");
		fprintf(fp, "b:amd64.aquabsd.0622a:https:github.com/inobulles/aquabsd-core/releases/download/v0622a-beta/base.txz:100050160:60321fefa8d46642f82fb51f9a1f16c552768da3f2b65b41ffa5fbaf8ff621fe\n");
		fprintf(fp, "k:amd64.aquabsd.0622a:https:github.com/inobulles/aquabsd-core/releases/download/v0622a-beta/kernel.txz:46796444:da71214c6c6ed3de41599c2cef56c5215ec0c547eb839a49669e78598839a000\n");

		fclose(fp);
	}

	SET_PERMS(sanctioned_templates)

	if (access(aquarium_db_path, R_OK) < 0) {
		int fd = creat(aquarium_db_path, mode);

		if (!fd) {
			errx(EXIT_FAILURE, "creat(\"%s\", 0%o): %s", aquarium_db_path, mode, strerror(errno));
		}

		close(fd);
	}

	SET_PERMS(aquarium_db_path)

	if (setuid(uid) < 0) {
		errx(EXIT_FAILURE, "setuid(%d): %s", uid, strerror(errno));
	}

	return EXIT_SUCCESS;
}

static int do_list(void) {
	FILE* fp = fopen(aquarium_db_path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", aquarium_db_path, strerror(errno));
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

static int do_list_templates(void) {
	__list_templates_dir(templates_path, "BASE");
	__list_templates_dir(kernels_path, "KERNEL");

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

typedef enum {
	TEMPLATE_KIND_BASE, TEMPLATE_KIND_KERNEL
} template_kind_t;

static inline void __download_template(const char* save_path, const char* template, template_kind_t wanted_template_kind) {
	// read list of sanctioned templates, and see if we have a match

	FILE* fp = fopen(sanctioned_templates, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", sanctioned_templates, strerror(errno));
	}

	char buf[1024]; // I don't super like doing this, but it's unlikely we'll run into any problems
	char* line;

	template_kind_t template_kind;
	char* name;
	char* protocol;
	char* url;
	size_t bytes;
	char* sha256;

	while ((line = fgets(buf, sizeof buf, fp))) { // fgets reads one less than 'size', so we're fine just padding 'sizeof buf'
		enum {
			TYPE, NAME, PROTOCOL, URL, BYTES, SHA256, SENTINEL
		} kind = 0;

		template_kind = 0;
		name = NULL;
		protocol = NULL;
		url = NULL;
		bytes = 0;
		sha256 = NULL;

		char* tok;

		while ((tok = strsep(&line, ":"))) {
			if (kind == TYPE) {
				if (*tok == 'b') {
					template_kind = TEMPLATE_KIND_BASE;
				}

				else if (*tok == 'k') {
					template_kind = TEMPLATE_KIND_KERNEL;
				}

				else {
					errx(EXIT_FAILURE, "Unknown template kind ('%s')", tok);
				}

				if (template_kind != wanted_template_kind) {
					goto next;
				}
			}

			else if (kind == NAME) {
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
	errx(EXIT_FAILURE, "Couldn't find template %s in list of sanctioned templates (%s)", template, sanctioned_templates);

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
	asprintf(&path, "%s%c%s.txz", save_path, ILLEGAL_TEMPLATE_PREFIX, name);

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
	                                                     // TODO well shouldn't this be 'SHA256_DIGEST_LENGTH / 2 + 1' then?

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
	asprintf(&final_path, "%s%s.txz", save_path, name);

	if (rename(path, final_path) < 0) {
		errx(EXIT_FAILURE, "rename: failed to rename %s to %s: %s", path, final_path, strerror(errno));
	}
}

static inline void __extract_template(const char* aquarium_path, const char* name, template_kind_t kind) {
	if (!name) {
		return;
	}

	// where should we look for templates?

	char* search_path = templates_path;

	if (kind == TEMPLATE_KIND_KERNEL) {
		search_path = kernels_path;
	}

	// build template path
	// attempt to download it if it don't already exist

	char* template_path; // don't care about freeing this (TODO: although I probably will if I factor this out into a libaquarium library)
	asprintf(&template_path, "%s%s.txz", search_path, name);

	if (access(template_path, F_OK) < 0) {
		// file template doesn't yet exist; download & check it
		__download_template(search_path, name, kind);
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
}

static int do_create(void) {
	// a few simple checks

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
	asprintf(&aquarium_path, "%s%s-XXXXXXX", aquariums_path, template);

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

	FILE* fp = fopen(aquarium_db_path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", aquarium_db_path, strerror(errno));
	}

	char buf[1024];
	db_ent_t ent;

	while (next_db_ent(&ent, sizeof buf, buf, fp, true)) {
		if (!strcmp(ent.pointer_path, abs_path)) {
			errx(EXIT_FAILURE, "Pointer file already exists in the aquarium database at %s (pointer file is supposed to reside at %s and point to %s)", aquarium_db_path, ent.pointer_path, ent.aquarium_path);
		}
	}

	fclose(fp);

	// setuid root

	uid_t uid = getuid();

	if (setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid(0): %s", strerror(errno));
	}

	// extract templates

	__extract_template(aquarium_path, template, TEMPLATE_KIND_BASE);
	__extract_template(aquarium_path, kernel_template, TEMPLATE_KIND_KERNEL);

	// copy over /etc/resolv.conf for networking to, well, work

	#define COPYFILE_DEBUG (1 << 31)

	if (copyfile("/etc/resolv.conf", "etc/resolv.conf", 0, COPYFILE_ALL) < 0) {
		errx(EXIT_FAILURE, "copyfile: %s", strerror(errno));
	}

	// write info to aquarium database

	/* FILE* */ fp = fopen(aquarium_db_path, "a");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", aquarium_db_path, strerror(errno));
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

static inline char* __read_pointer_file(void) {
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
		errx(EXIT_FAILURE, "realpath(\"%s\"): %s", path, strerror(errno));
	}

	/* FILE* */ fp = fopen(aquarium_db_path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", aquarium_db_path, strerror(errno));
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

	return aquarium_path;
}

static int do_enter(void) {
	char* aquarium_path = __read_pointer_file();

	// change into the aquarium directory

	if (chdir(aquarium_path) < 0) {
		errx(EXIT_FAILURE, "chdir: %s", strerror(errno));
	}

	// setuid root

	uid_t uid = getuid();

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
	// different OS' may have different locations for the sh binary

	return execlp("sh", "sh", NULL);
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
		while (!unmount(fd, MNT_FORCE));
		while (!unmount(shm, MNT_FORCE));
	} while (!unmount(dev, MNT_FORCE));

	while (!unmount(proc, MNT_FORCE));
	while (!unmount(sys, MNT_FORCE));
	while (!unmount(tmp, MNT_FORCE));

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

static int do_sweep(void) {
	// list of database entries which survive the sweep

	size_t survivors_len = 0;
	db_ent_t* survivors = NULL;

	// go through aquarium database

	FILE* fp = fopen(aquarium_db_path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", aquarium_db_path, strerror(errno));
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
		db_ent_t* survivor = &survivors[survivors_len++];

		survivor->pointer_path  = strdup(ent.pointer_path);
		survivor->aquarium_path = strdup(ent.aquarium_path);
	}

	fclose(fp);

	// keep things nice and clean is to go through everything under /etc/aquariums/aquariums and see which aquariums were never "recensés" (censused?)

	DIR* dp = opendir(aquariums_path);

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
		asprintf(&aquarium_path, "%s/%s", aquariums_path, name);

		__remove_aquarium(aquarium_path);
		free(aquarium_path);

	found:

		continue; // need something after a label in C for some reason
	}

	closedir(dp);

	// last thing to do is rebuild new aquarium database file with the entries that survived

	/* FILE* */ fp = fopen(aquarium_db_path, "w");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for writing: %s", aquarium_db_path, strerror(errno));
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

// outputting aquariums (TODO: much of this code can be shared with do_enter)
//  - make sure the path of the pointer file is well the one contained in the relevant entry of the aquarium database
//  - walk the aquarium path and add files/directories to output archive

typedef struct {
	const char* out;
	int fd;
} do_out_state_t;

static int do_out_open_cb(struct archive* archive, void* _state) {
	do_out_state_t* state = _state;

	state->fd = open(state->out, O_WRONLY | O_CREAT, 0644);

	if (state->fd < 0) {
		warnx("open(\"%s\"): %s", state->out, strerror(errno));
		return ARCHIVE_FATAL;
	}

	return ARCHIVE_OK;
}

static la_ssize_t do_out_write_cb(struct archive* archive, void* _state, const void* buf, size_t len) {
	do_out_state_t* state = _state;
	return write(state->fd, buf, len);
}

static int do_out_close_cb(struct archive* archive, void* _state) {
	do_out_state_t* state = _state;

	if (state->fd >= 0) {
		close(state->fd);
	}

	return ARCHIVE_OK;
}

static int do_out(void) {
	if (!out_path) {
		usage();
	}

	char* aquarium_path = __read_pointer_file();

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

static int do_img_out(void) {
	if (!out_path) {
		usage();
	}

	char* aquarium_path = __read_pointer_file();

	// labels
	// TODO these should be options

	const char* rootfs_label = "aquabsd-rootfs";
	const char* esp_label = "aquabsd-esp";

	const char* esp_oem = "AQUABSD "; // must be 8 chars
	const char* esp_vol_label = "AQUABSD-ESP";

	// check the OS is actually supported

	os_info_t os = __retrieve_os_info(aquarium_path);

	if (os != OS_FBSD) {
		errx(EXIT_FAILURE, "Aquarium OS is unsupported (%d, only FreeBSD aquariums are currently supported)", os);
	}

	// make sure all filesystems are unmounted

	__unmount_aquarium(aquarium_path);

	// add necessary entries to fstab

	char* path;
	asprintf(&path, "%s/etc/fstab", aquarium_path);

	FILE* fp = fopen(path, "w");
	free(path);

	if (!fp) {
		errx(EXIT_FAILURE, "fopen(\"%s\"): %s", path, strerror(errno));
	}

	fprintf(fp, "/dev/gpt/%s / ufs ro,noatime 1 1\n", rootfs_label);
	fprintf(fp, "/dev/gpt/%s /boot/efi msdosfs ro,noatime 0 0\n", esp_label);

	fclose(fp);

	// generate entropy

	#define ENTROPY_BYTES 4096

	int random_fd = open("/dev/random", O_RDONLY);

	if (random_fd < 0) {
		errx(EXIT_FAILURE, "open(\"/dev/random\"): %s", strerror(errno));
	}

	char* entropy_path;
	asprintf(&entropy_path, "%s/boot/entropy", aquarium_path);

	int entropy_fd = open(entropy_path, O_CREAT | O_WRONLY, 0600 /* read/write by owner (root) */);

	if (entropy_fd < 0) {
		errx(EXIT_FAILURE, "open(\"%s\"): %s", entropy_path, strerror(errno));
	}

	free(entropy_path);

	uint8_t entropy[ENTROPY_BYTES];

	if (read(random_fd, entropy, sizeof entropy) != sizeof entropy) {
		errx(EXIT_FAILURE, "read: %s", strerror(errno));
	}

	if (write(entropy_fd, entropy, sizeof entropy) != sizeof entropy) {
		errx(EXIT_FAILURE, "write: %s", strerror(errno));
	}

	close(random_fd);
	close(entropy_fd);

	// create UFS2 rootfs image with the contents of the aquarium
	// we first need to make sure everything is properly unmounted though
	// % makefs -ZBle -o label=$rootfs_label -o version=2 $rootfs_label.img $aquarium_path

	pid_t pid = fork();

	if (!pid) {
		// child process
		// don't care about freeing anything in here

		char* label_opt;
		asprintf(&label_opt, "-olabel=%s", rootfs_label);

		execl(
			"/usr/sbin/makefs", "/usr/sbin/makefs", // 'makefs' binary location
			"-ZBle", label_opt, "-oversion=2",      // filesystem options
			"rootfs.img", aquarium_path,            // output/input paths
			NULL);

		_exit(EXIT_FAILURE);
	}

	int child_rv = __wait_for_process(pid);

	if (child_rv < 0) {
		errx(EXIT_FAILURE, "Child rootfs image creation process exited with error code %d", child_rv);
	}

	// create ESP image (FAT12 - UEFI code seems to be fussy with FAT32 partitions generated by FreeBSD) with the EFI loader
	// % mkdir -p $stage/EFI/BOOT
	// % cp $aquarium_path/boot/loader.efi $stage/EFI/BOOT/BOOTX64.EFI
	// % makefs -t msdos -o fat_type=12 -o sectors_per_cluster=1 -o OEM_string="$esp_oem" -o volume_label=$esp_vol_label -s 1m $esp_label.img /tmp/efi-XXXXXXX
	// see aquabsd-installer on how to stage the ESP partition (with 'EFI/BOOT/BOOTX64.EFI', gotten from '$aquarium_path/boot/loader.efi')
	// TODO nonsensical error when omitting size option from makefs (the whole tool is kinda a mess tbh)

	char* stage = strdup("/tmp/aquarium-esp-stage-XXXXXXX");
	stage = mkdtemp(stage);

	if (!stage) {
		errx(EXIT_FAILURE, "mkdtemp: failed to create ESP staging directory: %s", strerror(errno));
	}

	// % mkdir -p $stage/EFI/BOOT
	// % cp $aquarium_path/boot/loader.efi $stage/EFI/BOOT/BOOTX64.EFI

	char* stage_efi;
	asprintf(&stage_efi, "%s/EFI", stage);

	if (mkdir(stage_efi, 0700) < 0) {
		errx(EXIT_FAILURE, "mkdir(\"%s\", 0700): %s", stage_efi, strerror(errno));
	}

	free(stage_efi);

	char* stage_efi_boot;
	asprintf(&stage_efi_boot, "%s/BOOT", stage_efi);

	if (mkdir(stage_efi_boot, 0700) < 0) {
		errx(EXIT_FAILURE, "mkdir(\"%s\", 0700): %s", stage_efi_boot, strerror(errno));
	}

	char* loader_efi;
	asprintf(&loader_efi, "%s/boot/loader.efi", aquarium_path);

	int loader_fd = open(loader_efi, O_RDONLY);

	if (loader_fd < 0) {
		errx(EXIT_FAILURE, "open(\"%s\"): %s", loader_efi, strerror(errno));
	}

	free(loader_efi);

	char* bootx64_efi;
	asprintf(&bootx64_efi, "%s/BOOTX64.EFI", stage_efi_boot);

	int bootx64_fd = creat(bootx64_efi, 0660);

	if (bootx64_fd < 0) {
		errx(EXIT_FAILURE, "create(\"%s\", 0660): %s", bootx64_efi, strerror(errno));
	}

	free(bootx64_efi);
	free(stage_efi_boot);

	if (fcopyfile(loader_fd, bootx64_fd, 0, COPYFILE_ALL) < 0) {
		errx(EXIT_FAILURE, "fcopyfile(\"%s\", \"%s\"): %s", loader_efi, bootx64_efi, strerror(errno));
	}

	close(loader_fd);
	close(bootx64_fd);

	/* pid_t */ pid = fork();

	if (!pid) {
		// child process
		// don't care about freeing anything in here

		char* oem_string_opt;
		asprintf(&oem_string_opt, "-oOEM_string=%s", esp_oem);

		char* label_opt;
		asprintf(&label_opt, "-ovolume_label=%s", esp_vol_label);

		execl(
			"/usr/sbin/makefs", "/usr/sbin/makefs",                // 'makefs' binary location
			"-tmsdos", "-ofat_type=12", "-osectors_per_cluster=1", // filesystem options
			"-s1m", oem_string_opt, label_opt,                     // more filesystem options
			"esp.img", stage,                                      // output/input paths
			NULL);

		_exit(EXIT_FAILURE);
	}

	free(stage);

	/* int */ child_rv = __wait_for_process(pid);

	if (child_rv < 0) {
		errx(EXIT_FAILURE, "Child ESP image creation process exited with error code %d", child_rv);
	}

	// % mkimg -s gpt -f raw -b $aquarium_path/boot/pmbr -p freebsd-boot/bootfs:=$aquarium_path/boot/gptboot -p efi/$esp_label:=$esp_label.img -p freebsd-ufs/$rootfs_label:=$rootfs_label.img -o $out_path

	/* pid_t */ pid = fork();

	if (!pid) {
		// child process
		// don't care about freeing anything in here

		char* pmbr;
		asprintf(&pmbr, "-b%s/boot/pmbr", aquarium_path);

		char* gptboot;
		asprintf(&gptboot, "-pfreebsd-boot/bootfs:=%s/boot/gptboot", aquarium_path);

		char* esp;
		asprintf(&esp, "-pefi/%s:=esp.img", esp_label);

		char* ufs;
		asprintf(&ufs, "-pfreebsd-ufs/%s:=rootfs.img", rootfs_label);

		execl(
			"/usr/bin/mkimg", "/usr/bin/mkimg", // 'mkimg' binary location
			"-sgpt", "-fraw",                   // partition table & image type options
			pmbr,                               // MBR bootcode (for legacy BIOS booting yeah)
			gptboot, esp, ufs,                  // different partitions
			"-o", out_path,                     // output path
			NULL);

		_exit(EXIT_FAILURE);
	}

	/* int */ child_rv = __wait_for_process(pid);

	if (child_rv < 0) {
		errx(EXIT_FAILURE, "Child final image creation process exited with error code %d", child_rv);
	}

	return EXIT_SUCCESS;
}

// copy files from outside of the aquarium

static int do_copy(void) {
	if (!copy_args || copy_args_len < 2) {
		usage();
	}

	char* aquarium_path = __read_pointer_file();

	// setuid root

	uid_t uid = getuid();

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

typedef int (*action_t) (void);

int main(int argc, char* argv[]) {
	action_t action = do_list;

	// parse options

	int c;

	while ((c = getopt(argc, argv, "c:e:f:k:lo:pr:st:T:vy:")) != -1) {
		// general options

		if (c == 'p') {
			persist = true;
		}

		else if (c == 'r') {
			base_path = optarg;
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

		else if (c == 'f') {
			action = do_struct;
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

	asprintf(&templates_path,       "%s/" TEMPLATES_PATH,       base_path);
	asprintf(&kernels_path,         "%s/" KERNELS_PATH,         base_path);
	asprintf(&aquariums_path,       "%s/" AQUARIUMS_PATH,       base_path);

	asprintf(&sanctioned_templates, "%s/" SANCTIONED_TEMPLATES, base_path);
	asprintf(&aquarium_db_path,     "%s/" AQUARIUM_DB_PATH,     base_path);

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

	return action();
}
