#pragma once

// TODO proper error handling with a nice traceback would be nice

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

// defines

#define AQUARIUM_ILLEGAL_TEMPLATE_PREFIX '.'

// enums

typedef enum {
	AQUARIUM_OS_GENERIC,
	AQUARIUM_OS_FBSD,
	AQUARIUM_OS_LINUX,
} aquarium_os_info_t;

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
} aquarium_opts_t;

typedef struct {
	char* pointer_path;
	char* aquarium_path;
} aquarium_db_ent_t;

typedef enum {
	AQUARIUM_TEMPLATE_KIND_BASE,
	AQUARIUM_TEMPLATE_KIND_KERNEL,
} aquarium_template_kind_t;

// function prototypes

aquarium_opts_t* aquarium_opts_create(void);
void aquarium_opts_free(aquarium_opts_t* opts);

bool aquarium_db_next_ent(aquarium_opts_t* opts, aquarium_db_ent_t* ent, size_t buf_len, char buf[buf_len], FILE* fp, bool be_dramatic);

int aquarium_download_template(aquarium_opts_t* opts, char const* path, char const* name, aquarium_template_kind_t kind);
int aquarium_extract_template(aquarium_opts_t* opts, char const* path, char const* name, aquarium_template_kind_t kind);

int aquarium_create(aquarium_opts_t* opts, char const* path, char const* template, char const* kernel_template);
