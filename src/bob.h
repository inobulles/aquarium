#if !defined(__BOB_THE_BUILDER_LIB)
#define __BOB_THE_BUILDER_LIB

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// logging

#define BOB_LOG_SIGNATURE "[BOB]"

#define BOB_LOG_REGULAR "\033[0m"
#define BOB_LOG_RED     "\033[0;31m"
#define BOB_LOG_GREEN   "\033[0;32m"
#define BOB_LOG_YELLOW  "\033[0;33m"

extern unsigned bob_verbose;

#define BOB_INFO(...) \
	if (bob_verbose) { \
		printf(BOB_LOG_REGULAR "🔵 " BOB_LOG_SIGNATURE " " __VA_ARGS__); \
	}

#define BOB_FATAL(...) \
	fprintf(stderr, BOB_LOG_RED "🔴 " BOB_LOG_SIGNATURE " " __VA_ARGS__);

#define BOB_WARN(...) \
	fprintf(stderr, BOB_LOG_YELLOW "🟡 " BOB_LOG_SIGNATURE " " __VA_ARGS__);

#define BOB_SUCCESS(...) \
	printf(BOB_LOG_GREEN "🟢 " BOB_LOG_SIGNATURE " " __VA_ARGS__);

#define BOB_SANITY_CHECK(aquarium) \
	char* __bob_sanity_check_file = strdup(__FILE__); \
	char* _bob_sanity_check_file = strrchr(__bob_sanity_check_file, '/'); /* get last component of filepath */ \
	\
	if (!_bob_sanity_check_file) { \
		_bob_sanity_check_file = __bob_sanity_check_file; \
	} \
	\
	*strrchr(++_bob_sanity_check_file, '.') = '\0'; /* remove extension */ \
	\
	if (!(aquarium)->name || \
		strcmp(_bob_sanity_check_file, (aquarium)->name)) { \
		\
		BOB_WARN("Filename (%s) does not match aquarium name (%s)\n", _bob_sanity_check_file, (aquarium)->name) \
	} \
	\
	free(__bob_sanity_check_file);

// other macros

typedef enum {
	BOB_SYS_AQUABSD,
	BOB_SYS_FREEBSD,
	BOB_SYS_SYSTEMD,

	BOB_SYS_LEN
} bob_sys_t;

typedef struct {
	char* name;
	bob_sys_t sys;

	char* path;

	char* assembled_path;
} bob_aquarium_t;

// global settings functions

void bob_set_verbose(unsigned verbose);
void bob_set_chunk_bytes(unsigned chunk_bytes);

// aquarium creation/destruction functions

bob_aquarium_t* bob_new_aquarium(const char* name);
void bob_del_aquarium(bob_aquarium_t* aquarium);

// aquarium settings functions

int bob_aquarium_sys(bob_aquarium_t* aquarium, bob_sys_t sys);

// aquarium component functions

int bob_aquarium_net_component(bob_aquarium_t* aquarium, const char* name, const char* url);
int bob_aquarium_component_extract(bob_aquarium_t* aquarium, const char* name);

// aquarium configuration functions

int bob_aquarium_hostname(bob_aquarium_t* aquarium, const char* hostname);

// image component creation functions

int bob_aquarium_gen_fs(bob_aquarium_t* aquarium, const char* label);
int bob_aquarium_gen_esp(bob_aquarium_t* aquarium, const char* oem, const char* label);

int bob_aquarium_assemble(bob_aquarium_t* aquarium);

#endif