#pragma once

// TODO proper error handling with a nice traceback would be nice

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

// defines

#define AQUARIUM_ILLEGAL_TEMPLATE_PREFIX '.'

// enums

typedef enum {
	AQUARIUM_OS_GENERIC,
	AQUARIUM_OS_FBSD,
	AQUARIUM_OS_LINUX,
} aquarium_os_info_t;

typedef enum {
	AQUARIUM_TEMPLATE_KIND_BASE,
	AQUARIUM_TEMPLATE_KIND_KERNEL,
} aquarium_template_kind_t;

typedef enum {
	AQUARIUM_DRIVE_KIND_MD,    // memory disk
	AQUARIUM_DRIVE_KIND_ADA,   // ATA direct access
	AQUARIUM_DRIVE_KIND_DA,    // SCSI direct access
	AQUARIUM_DRIVE_KIND_NVME,  // NVMe
	AQUARIUM_DRIVE_KIND_CD,    // optical disk
	AQUARIUM_DRIVE_KIND_OTHER, // could be 'mmcsd', 'mmc', 'at91_mci', or 'sdhci'
} aquarium_drive_kind_t;

// structs

typedef struct {
	gid_t stoners_gid;

	// directory paths

	char* base_path;
	char* templates_path;
	char* kernels_path;
	char* aquariums_path;

	// file paths

	char* sanctioned_path;
	char* db_path;

	// image output & filesystem creation options

	char* rootfs_label;
	char* esp_label;
	char* esp_oem;
	char* esp_vol_label;
} aquarium_opts_t;

typedef struct {
	char* pointer_path;
	char* aquarium_path;
} aquarium_db_ent_t;

typedef struct {
	aquarium_drive_kind_t kind;
	char* provider;
	int rank;

	uint64_t sectors;
	uint64_t sector_size;

	uint64_t size;

	char* ident;
	char* name;
	char* label;
} aquarium_drive_t;

// function prototypes

aquarium_opts_t* aquarium_opts_create(void);
void aquarium_opts_free(aquarium_opts_t* opts);

bool aquarium_db_next_ent(aquarium_opts_t* opts, aquarium_db_ent_t* ent, size_t buf_len, char buf[buf_len], FILE* fp, bool be_dramatic);
char* aquarium_db_read_pointer_file(aquarium_opts_t* opts, char const* path);

int aquarium_download_template(aquarium_opts_t* opts, char const* path, char const* name, aquarium_template_kind_t kind);
int aquarium_extract_template(aquarium_opts_t* opts, char const* path, char const* name, aquarium_template_kind_t kind);

int aquarium_create(aquarium_opts_t* opts, char const* path, char const* template, char const* kernel_template);

int aquarium_drives_read(aquarium_drive_t** drives_ref, size_t* drives_len_ref);
void aquarium_drives_free(aquarium_drive_t* drives, size_t drives_len);
aquarium_drive_t* aquarium_drives_find(aquarium_drive_t* drives, size_t drives_len, char const* provider);

int aquarium_format_new_table(aquarium_drive_t* drive);
int aquarium_format_create_esp(aquarium_opts_t* opts, aquarium_drive_t* drive, char const* path);

int aquarium_img_populate_esp(char const* path, char const* stage);
int aquarium_img_out(aquarium_opts_t* opts, char const* path, char const* out);

// internal functions common to all source files

__attribute__((unused)) static int __aquarium_wait_for_process(pid_t pid) {
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
