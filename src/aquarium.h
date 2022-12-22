#pragma once

// TODO proper error handling with a nice traceback would be nice

// defines
 
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#define AQUARIUM_PROGRESS_FREQUENCY  (1 << 22)
#define AQUARIUM_FETCH_CHUNK_BYTES   (1 << 16)
#define AQUARIUM_ARCHIVE_CHUNK_BYTES (1 << 16)

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

// function prototypes

aquarium_opts_t* aquarium_opts_create(void);
void aquarium_opts_free(aquarium_opts_t* opts);

bool aquarium_db_next_ent(aquarium_opts_t* opts, aquarium_db_ent_t* ent, size_t buf_len, char buf[buf_len], FILE* fp, bool be_dramatic);

int create_aquarium(char const* path, char const* template, aquarium_opts_t* opts);
