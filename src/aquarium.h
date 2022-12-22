#pragma once

// TODO proper error handling with a nice traceback would be nice

// defines
 
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

// function prototypes

aquarium_opts_t* aquarium_opts_create(void);
void aquarium_opts_free(aquarium_opts_t* opts);

int create_aquarium(char const* path, char const* template, aquarium_opts_t* opts);
