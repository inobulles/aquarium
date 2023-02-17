#include <aquarium.h>
#include "archive.h"
#include "archive_entry.h"
#include "copyfile.h"
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char** copy_args = NULL;
static size_t copy_args_len = 0;

static char* template = "amd64.aquabsd.0922a";
static char* kernel_template = NULL;

static char* out_path = NULL;
static char* path = NULL;

static void usage(void) {
	fprintf(stderr,
		"usage: %1$s [-r base]\n"
		"       %1$s [-r base] -c path [-t template] [-k kernel_template]\n"
		"       %1$s [-r base] [-pv] [-h hostname] -e path\n"
		"       %1$s [-r base] -i path -o image\n"
		"       %1$s [-r base] -I drive [-t template] [-k kernel_template]\n"
		"       %1$s [-r base] -l\n"
		"       %1$s [-r base] -s\n"
		"       %1$s [-r base] -T path -o template\n"
		"       %1$s [-r base] -y path source_file ... target_directory\n",
	getprogname());

	exit(EXIT_FAILURE);
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

static int do_create(aquarium_opts_t* opts) {
	if (!path) {
		usage();
	}

	if (aquarium_create(opts, path, template, kernel_template) < 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int do_install(aquarium_opts_t* opts) {
	if (!path) {
		usage();
	}

	char* const target = path;

	// find our drive

	aquarium_drive_t* drives = NULL;
	size_t drives_len = 0;

	if (aquarium_drives_read(&drives, &drives_len) < 0) {
		return EXIT_FAILURE;
	}

	aquarium_drive_t* const drive = aquarium_drives_find(drives, drives_len, target);

	if (!drive) {
		return EXIT_FAILURE;
	}

	// create partition table on target

	if (aquarium_format_new_table(opts, drive) < 0) {
		return EXIT_FAILURE;
	}

	// create ZFS filesystem on target

	char const* const root = "/mnt";

	if (aquarium_format_create_zfs(opts, drive, root) < 0) {
		return EXIT_FAILURE;
	}

	// extract templates

	if (template && aquarium_extract_template(opts, root, template, AQUARIUM_TEMPLATE_KIND_BASE) < 0) {
		return EXIT_FAILURE;
	}

	if (kernel_template && aquarium_extract_template(opts, root, kernel_template, AQUARIUM_TEMPLATE_KIND_KERNEL) < 0) {
		return EXIT_FAILURE;
	}

	// create ESP on target

	if (aquarium_format_create_esp(opts, drive, root) < 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int enter_cb(__attribute__((unused)) void* param) {
	// unfortunately we kinda need to use execlp here
	// different OS' may have different locations for the 'env' binary
	// we use it instead of starting the shell directly to clear any environment variables that we shouldn't have access to (and which anyway isn't super relevant to us)
	// the one exception is the TERM variable, which we read and then pass on to env

	char* const term_env = getenv("TERM");
	char* term_arg;

	if (term_env) {
		if (asprintf(&term_arg, "TERM=%s", term_env)) {} // we don't concern ourselves with freeing this
	}

	else {
		term_arg = "";
	}

	execlp("env", "env", "-i", term_arg, "sh", NULL);
	_exit(EXIT_FAILURE);
}

static int do_enter(aquarium_opts_t* opts) {
	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	if (!aquarium_path) {
		return EXIT_FAILURE;
	}

	if (aquarium_enter(opts, aquarium_path, enter_cb, NULL) < 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int do_sweep(aquarium_opts_t* opts) {
	return aquarium_sweep(opts) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
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

	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	if (!aquarium_path) {
		return EXIT_FAILURE;
	}

	aquarium_os_t const os = aquarium_os_info(aquarium_path);

	if (aquarium_enter_setdown(aquarium_path, os) < 0) {
		return EXIT_FAILURE;
	}

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
		char buf[4096]; // TODO ARCHIVE_CHUNK_BYTES

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

static int do_img_out(aquarium_opts_t* opts) {
	if (!out_path) {
		usage();
	}

	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	if (!aquarium_path) {
		return EXIT_FAILURE;
	}

	return aquarium_img_out(opts, aquarium_path, out_path) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
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
	aquarium_opts_t* const opts = aquarium_opts_create();

	if (!opts) {
		return EXIT_FAILURE;
	}

	// parse options

	int c;

	while ((c = getopt(argc, argv, "c:e:fh:i:I:k:lo:pr:st:T:vy:")) != -1) {
		// general options

		if (c == 'h') {
			opts->hostname = optarg;
		}

		else if (c == 'p') {
			opts->persist = true;
		}

		else if (c == 'r') {
			aquarium_opts_set_base_path(opts, optarg);
		}

		else if (c == 'v') {
			opts->vnet_disable = true;
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

		else if (c == 'I') {
			action = do_install;
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

	if (aquarium_create_struct(opts) < 0) {
		return EXIT_FAILURE;
	}

	if (aquarium_sweep(opts) < 0) {
		return EXIT_FAILURE;
	}

	// finally actually execute the action we were here for

	return action(opts);
}
