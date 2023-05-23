#include <aquarium.h>
#include "archive.h"
#include "archive_entry.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/param.h>

#include <archive.h>
#include <fetch.h>

#define PROGRESS_FREQUENCY  (1 << 22)
#define FETCH_CHUNK_BYTES   (1 << 16)
#define ARCHIVE_CHUNK_BYTES (1 << 16)

typedef struct {
	aquarium_template_kind_t kind;
	char* name;
	char* protocol;
	char* url;
	size_t bytes;
	char* sha256;
} sanctioned_t;

static int fetch_template(sanctioned_t* sanctioned, char const* path, SHA256_CTX* sha_context, size_t* total_ref) {
	// actually fetch the template
	// it's initially downloaded with a '.' prefix, because otherwise, there's a potential for a race condition
	// e.g., if we downloaded it in its final destination, the template could be malicious, and an actor could coerce the user into creating an aquarium from that template before the checks have terminated
	// realistically, there's a slim chance of this, unless said malicious actor could somehow stall the SHA256 digesting, but we shouldn't rely on this if we can help it

	int rv = -1;

	char* composed_url;
	asprintf(&composed_url, "%s://%s", sanctioned->protocol, sanctioned->url);

	printf("Found template, downloading from %s ...\n", composed_url);

	FILE* const out_fp = fopen(path, "w");

	if (!out_fp) {
		warnx("fopen: failed to open %s for writing: %s", path, strerror(errno));
		goto out_open_err;
	}

	FILE* const remote_fp = fetchGetURL(composed_url, "");

	if (!remote_fp) {
		warnx("Failed to download %s", composed_url);
		goto remote_open_err;
	}

	// checking (size & hash) stuff

	SHA256_Init(sha_context);

	// start download

	uint8_t chunk[FETCH_CHUNK_BYTES];
	size_t chunk_bytes;

	*total_ref = 0;

	while ((chunk_bytes = fread(chunk, 1, sizeof chunk, remote_fp)) > 0) {
		*total_ref += chunk_bytes;

		if (!(*total_ref % PROGRESS_FREQUENCY)) {
			float progress = (float) *total_ref / sanctioned->bytes;
			printf("\rDownloading %d%% done", (int) (progress * 100));
			fflush(stdout);
		}

		SHA256_Update(sha_context, chunk, chunk_bytes);

		if (fwrite(chunk, 1, chunk_bytes, out_fp) < chunk_bytes) {
			break;
		}
	}

	printf("\rFinished             \n");

	// success

	rv = 0;

	fclose(remote_fp);

remote_open_err:

	fclose(out_fp);

out_open_err:

	free(composed_url);

	return rv;
}

static int check_template(sanctioned_t* sanctioned, char const* path, size_t total, SHA256_CTX* sha_context) {
	// get digest of hash

	uint8_t hash[SHA256_DIGEST_LENGTH];
	SHA256_Final(hash, sha_context);

	char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1] = { 0 }; // each byte in the hash can be represented with two hex digits

	for (size_t i = 0; i < sizeof hash; i++) {
		snprintf(hash_hex, sizeof hash_hex, "%s%02x", hash_hex, hash[i]);
	}

	// template has been downloaded, check its size & SHA256 hash

	if (total != sanctioned->bytes) {
		warnx("Total size of downloaded template (%zu bytes) is not the size expected (%zu bytes). Someone may be trying to swindle you!", total, sanctioned->bytes);
		goto err;
	}

	if (strcmp(hash_hex, sanctioned->sha256)) {
		warnx("SHA256 hash of downloaded template (%s) is not the same as expected (%s). Someone may be trying to swindle you!", hash_hex, sanctioned->sha256);
		goto err;
	}

	return 0;

err:

	if (remove(path) < 0) {
		warnx("remove(\"%s\"): %s", path, strerror(errno));
	}

	return -1;
}

int aquarium_download_template(aquarium_opts_t* opts, char const* path, char const* name, aquarium_template_kind_t kind) {
	// check if template is sanctioned, download it, and check the template integrity

	int rv = -1;

	// read list of sanctioned templates, and see if we have a match

	FILE* const fp = fopen(opts->sanctioned_path, "r");

	if (!fp) {
		warnx("fopen: failed to open %s for reading: %s", opts->sanctioned_path, strerror(errno));
		goto open_err;
	}

	char buf[1024];
	char* line;
	sanctioned_t sanctioned;

	while ((line = fgets(buf, sizeof buf, fp))) { // fgets reads one less than 'size', so we're fine just padding 'sizeof buf'
		enum {
			TYPE, NAME, PROTOCOL, URL, BYTES, SHA256, SENTINEL
		} tok_kind = 0;

		sanctioned.kind = 0;
		sanctioned.name = NULL;
		sanctioned.protocol = NULL;
		sanctioned.url = NULL;
		sanctioned.bytes = 0;
		sanctioned.sha256 = NULL;

		char* tok;

		while ((tok = strsep(&line, ":"))) {
			if (tok_kind == TYPE) {
				if (*tok == 'b') {
					sanctioned.kind = AQUARIUM_TEMPLATE_KIND_BASE;
				}

				else if (*tok == 'k') {
					sanctioned.kind = AQUARIUM_TEMPLATE_KIND_KERNEL;
				}

				else {
					warnx("Unknown template kind ('%s')", tok);
					goto template_kind_err;
				}

				if (sanctioned.kind != kind) {
					goto next;
				}
			}

			else if (tok_kind == NAME) {
				sanctioned.name = tok;

				if (strcmp(sanctioned.name, name)) {
					goto next;
				}
			}

			else if (tok_kind == PROTOCOL) {
				sanctioned.protocol = tok;
			}

			else if (tok_kind == URL) {
				sanctioned.url = tok;
			}

			else if (tok_kind == BYTES) {
				__attribute__((unused)) char* endptr;
				sanctioned.bytes = strtol(tok, &endptr, 10);
			}

			else if (tok_kind == SHA256) {
				sanctioned.sha256 = tok;
				sanctioned.sha256[strlen(sanctioned.sha256) - 1] = '\0';
			}

			if (++tok_kind >= SENTINEL) {
				break;
			}
		}

		// we've found our template at this point

		goto found;

	next:

		continue;
	}

	// we didn't find our template, unfortunately :(

	warnx("Couldn't find template %s in list of sanctioned templates (%s)", name, opts->sanctioned_path);
	goto not_sanctioned_err;

found: {}

	// create path for temporary file

	char* temp_path;
	asprintf(&temp_path, "%s/%c%s.txz", path, AQUARIUM_ILLEGAL_TEMPLATE_PREFIX, sanctioned.name);

	// found template, start downloading it

	SHA256_CTX sha_context;
	size_t total;

	if (fetch_template(&sanctioned, temp_path, &sha_context, &total) < 0) {
		goto fetch_err;
	}

	// check size & hash digest

	if (check_template(&sanctioned, temp_path, total, &sha_context) < 0) {
		goto check_err;
	}

	// checks have succeeded; move temporary file to permanent position

	char* final_path;
	asprintf(&final_path, "%s/%s.txz", path, sanctioned.name);

	if (rename(temp_path, final_path) < 0) {
		warnx("rename: failed to rename %s to %s: %s", temp_path, final_path, strerror(errno));
		goto rename_err;
	}

	// success

	rv = 0;

rename_err:

	free(final_path);

check_err:
fetch_err:

	free(temp_path);

not_sanctioned_err:
template_kind_err:

	fclose(fp);

open_err:

	return rv;
}

int aquarium_extract_template(aquarium_opts_t* opts, char const* path, char const* name, aquarium_template_kind_t kind) {
	int rv = -1;

	if (!name) {
		return -1;
	}

	// where should we look for templates?

	char* const search_path = kind == AQUARIUM_TEMPLATE_KIND_KERNEL ? opts->kernels_path : opts->templates_path;

	// build template path
	// attempt to download & check it if it don't already exist

	char* template_path;
	if (asprintf(&template_path, "%s/%s.txz", search_path, name)) {}

	if (access(template_path, F_OK) < 0) {
		if (aquarium_download_template(opts, search_path, name, kind) < 0) {
			goto download_err;
		}
	}

	// make & change into final aquarium directory
	// as per archive_write_disk(3)'s "BUGS" section, we mustn't call 'chdir' between opening and closing archive objects

	if (chdir(path) < 0) {
		warnx("chdir(\"%s\"): %s", path, strerror(errno));
		goto chdir_err;
	}

	// open archive

	struct archive* const archive = archive_read_new();

	archive_read_support_filter_all(archive);
	archive_read_support_format_all(archive);

	if (archive_read_open_filename(archive, template_path, ARCHIVE_CHUNK_BYTES) < 0) {
		warnx("archive_read_open_filename: failed to open %s template: %s", template_path, archive_error_string(archive));
		goto archive_read_open_err;
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

		char const* const err = archive_error_string(archive);
		bool const useless_warning = err && !strcmp(err, "Can't restore time");

		if (res != ARCHIVE_OK && !(res == ARCHIVE_WARN && useless_warning)) {
			warnx("archive_read_next_header: %s", err);
			goto archive_read_header_err;
		}
	}

	// success

	rv = 0;

	// XXX ERRORS LABELS HERE

archive_read_header_err:

	archive_read_close(archive);

archive_read_open_err:

	archive_read_free(archive);
	
chdir_err:
download_err:

	free(template_path);

	return rv;
}

// template outputting

typedef struct {
	const char* out;
	int fd;
} do_out_state_t;

static int do_out_open_cb(struct archive* archive, void* _state) {
	(void) archive;

	do_out_state_t* const state = _state;

	state->fd = open(state->out, O_WRONLY | O_CREAT, 0644);

	if (state->fd < 0) {
		warnx("open(\"%s\"): %s", state->out, strerror(errno));
		return ARCHIVE_FATAL;
	}

	return ARCHIVE_OK;
}

static la_ssize_t do_out_write_cb(struct archive* archive, void* _state, const void* buf, size_t len) {
	(void) archive;

	do_out_state_t* const state = _state;

	return write(state->fd, buf, len);
}

static int do_out_close_cb(struct archive* archive, void* _state) {
	(void) archive;

	do_out_state_t* const state = _state;

	if (state->fd >= 0)
		close(state->fd);

	return ARCHIVE_OK;
}

static void strfree(char* const* str) {
	if (str)
		free(*str);
}

int aquarium_template_out(aquarium_opts_t* opts, char const* path, char const* out) {
	(void) opts;

	aquarium_os_t const os = aquarium_os_info(path);

	// make sure everything is unmounted
	// this will (hopefully) fail if the aquarium is running (i.e. using the filesystems)

	if (aquarium_enter_setdown(path, os) < 0)
		return -1;

	// create template

	char* const __attribute__((cleanup(strfree))) cwd = getcwd(NULL, 0);

	if (!cwd)
		return -1;

	char* __attribute__((cleanup(strfree))) abs_template = NULL;
	asprintf(&abs_template, "%s/%s", cwd, out);

	if (chdir(path) < 0)
		errx(EXIT_FAILURE, "chdir: %s", strerror(errno));

	struct archive* const disk = archive_read_disk_new();

	archive_read_disk_set_standard_lookup(disk);
	archive_read_disk_set_behavior(disk, ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS);

	if (archive_read_disk_open(disk, ".") != ARCHIVE_OK)
		errx(EXIT_FAILURE, "archive_read_disk_open: %s", archive_error_string(disk));

	// try to deduce compression format to use based on file extension, and if that fails, default to XZ compression

	do_out_state_t state = {
		.out = abs_template
	};

	struct archive* const archive = archive_write_new();

	archive_write_add_filter_xz   (archive); // archive_write_filter(3)
	archive_write_set_format_ustar(archive); // archive_write_format(3)

	archive_write_set_filter_option(archive, "xz", "compression-level", "9");
	archive_write_set_filter_option(archive, "xz", "threads", "0"); // fixed as of https://github.com/libarchive/libarchive/pull/1664

	if (archive_write_open(archive, &state, do_out_open_cb, do_out_write_cb, do_out_close_cb) < 0)
		errx(EXIT_FAILURE, "archive_write_open: %s", archive_error_string(archive));

	for (;;) {
		// read next file and write entry

		struct archive_entry* const entry = archive_entry_new();
		int rv = archive_read_next_header2(disk, entry);

		if (rv == ARCHIVE_EOF)
			break;

		if (rv != ARCHIVE_OK)
			errx(EXIT_FAILURE, "archive_read_next_header2: %s", archive_error_string(disk));

		archive_read_disk_descend(disk);
		rv = archive_write_header(archive, entry);

		if (rv == ARCHIVE_FATAL)
			errx(EXIT_FAILURE, "archive_write_header: %s", archive_error_string(archive));

		if (rv < ARCHIVE_OK)
			warnx("archive_write_header: %s", archive_error_string(archive));

		if (rv <= ARCHIVE_FAILED)
			goto finish_entry;

		// write file content

		char const* const path = archive_entry_sourcepath(entry);
		printf("%s\n", path + 2);

		int fd;

		if ((fd = open(path, O_RDONLY)) < 0) {
			warnx("open(\"%s\"): %s", path, strerror(errno));
			goto finish_entry;
		}

		ssize_t len;
		char buf[4096]; // TODO ARCHIVE_CHUNK_BYTES

		while ((len = read(fd, buf, sizeof buf)) > 0)
			archive_write_data(archive, buf, len);

		close(fd);

	finish_entry:

		archive_entry_free(entry);
	}

	archive_read_close(disk);
	archive_read_free(disk);

	archive_write_close(archive);
	archive_write_free(archive);

	return 0;
}
