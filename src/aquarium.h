// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2023 Aymeric Wibo

#pragma once

// TODO proper error handling with a nice traceback would be nice

#include <err.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/wait.h>

// defines

#define AQUARIUM_ILLEGAL_TEMPLATE_PREFIX '.'

// enums

typedef enum {
	AQUARIUM_OS_GENERIC,
	AQUARIUM_OS_FREEBSD,
	AQUARIUM_OS_UBUNTU,
} aquarium_os_t;

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
	AQUARIUM_DRIVE_KIND_OTHER, // could be 'mmcsd', 'mmc', 'at91_mci', or 'sdhci', yo
} aquarium_drive_kind_t;

// these can all be found in /etc/defaults/devfs.rules

typedef enum {
	AQUARIUM_DEVFS_RULESET_HIDE_ALL     = 1, // devfsrules_hide_all
	AQUARIUM_DEVFS_RULESET_UNHIDE_BASIC = 2, // devfsrules_unhide_basic
	AQUARIUM_DEVFS_RULESET_UNHIDE_LOGIN = 3, // devfsrules_unhide_login
	AQUARIUM_DEVFS_RULESET_JAIL         = 4, // devfsrules_jail
	AQUARIUM_DEVFS_RULESET_JAIL_VNET    = 5, // devfsrules_jail_vnet
} aquarium_devfs_ruleset_t;

// other typedefs

typedef char aquarium_if_name_t[IFNAMSIZ];

// structs

typedef struct {
	int sock;
	bool attached;

	aquarium_if_name_t epair;
	aquarium_if_name_t internal_epair;
	aquarium_if_name_t bridge;
} aquarium_vnet_t;

typedef struct {
	uid_t initial_uid;
	gid_t initial_gid;

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

	// jail options

	char* hostname;
	bool persist;
	bool dhcp;
	uint32_t max_children;

	size_t jailparam_count;
	char** jailparam_keys;
	char** jailparam_vals;

	char* vnet_bridge;
	aquarium_vnet_t vnet;

	// devfs ruleset options

	size_t ruleset_count;
	aquarium_devfs_ruleset_t* rulesets;
} aquarium_opts_t;

typedef struct {
	char* pointer_path;
	char* aquarium_path;
} aquarium_db_ent_t;

typedef struct {
	aquarium_drive_kind_t kind;
	char* provider;
	int rank;

	size_t sectors;
	size_t sector_size;

	size_t size;

	char* ident;
	char* name;
	char* label;
} aquarium_drive_t;

// other typedefs

typedef int (*aquarium_enter_cb_t) (void* param);

// function prototypes

aquarium_opts_t* aquarium_opts_create(void);
void aquarium_opts_free(aquarium_opts_t* opts);

void aquarium_opts_set_base_path(aquarium_opts_t* opts, char const* base_path);
void aquarium_opts_add_devfs_ruleset(aquarium_opts_t* opts, aquarium_devfs_ruleset_t ruleset);
void aquarium_opts_add_jailparam(aquarium_opts_t* opts, char* key, char* val);

bool aquarium_db_next_ent(aquarium_opts_t* opts, aquarium_db_ent_t* ent, size_t buf_len, char buf[buf_len], FILE* fp, bool be_dramatic);
char* aquarium_db_read_pointer_file(aquarium_opts_t* opts, char const* path);

int aquarium_download_template(aquarium_opts_t* opts, char const* path, char const* name, aquarium_template_kind_t kind);
int aquarium_extract_template(aquarium_opts_t* opts, char const* path, char const* name, aquarium_template_kind_t kind);
int aquarium_template_out(aquarium_opts_t* opts, char const* path, char const* out);

aquarium_os_t aquarium_os_info(char const* path);
int aquarium_os_load_linux64_kmod(void);
int aquarium_os_load_epair_kmod(void);
int aquarium_os_load_bridge_kmod(void);

int aquarium_create_struct(aquarium_opts_t* opts);
int aquarium_create(aquarium_opts_t* opts, char const* path, char const* template, char const* kernel_template);

int aquarium_enter(aquarium_opts_t* opts, char const* path, aquarium_enter_cb_t cb, void* param);
int aquarium_enter_setdown(char const* path, aquarium_os_t os);

int aquarium_sweep(aquarium_opts_t* opts, bool go_hard);

int aquarium_drives_read(aquarium_drive_t** drives_ref, size_t* drives_len_ref);
void aquarium_drives_free(aquarium_drive_t* drives, size_t drives_len);
aquarium_drive_t* aquarium_drives_find(aquarium_drive_t* drives, size_t drives_len, char const* provider);

int aquarium_format_new_table(aquarium_opts_t* opts, aquarium_drive_t* drive);
int aquarium_format_create_esp(aquarium_opts_t* opts, aquarium_drive_t* drive, char const* path);
int aquarium_format_create_zfs(aquarium_opts_t* opts, aquarium_drive_t* drive, char const* path);

int aquarium_img_populate_esp(char const* path, char const* stage);
int aquarium_img_out(aquarium_opts_t* opts, char const* path, char const* out);

int aquarium_vnet_create(aquarium_vnet_t* vnet, char* bridge_name);
void aquarium_vnet_destroy(aquarium_vnet_t* vnet);

int aquarium_vnet_attach(aquarium_vnet_t* vnet, char* hash);
int aquarium_vnet_dhcp(aquarium_vnet_t* vnet);

// internal macros & functions common to all source files

#define __AQUARIUM_IOV(name, val) \
	(struct iovec) { .iov_base = (name), .iov_len = strlen((name)) + 1 }, \
	(struct iovec) { .iov_base = (val ), .iov_len = strlen((val )) + 1 }

__attribute__((unused)) static int __aquarium_wait_for_process(pid_t pid) {
	int wstatus = 0;
	while (waitpid(pid, &wstatus, 0) > 0);

	if (WIFSIGNALED(wstatus)) {
		if (WTERMSIG(wstatus) == SIGSEGV) {
			warnx("(Segmentation fault)");
		}

		return EXIT_FAILURE;
	}

	if (WIFEXITED(wstatus)) {
		return WEXITSTATUS(wstatus);
	}

	return EXIT_FAILURE;
}

__attribute__((unused)) static char* __aquarium_hash(char const* _str) { // djb2 algorithm
	char* str = (void*) _str;
	uint64_t hash = 5381;

	while (*str) {
		hash = ((hash << 5) + hash) + *str++;
	}

	asprintf(&str, "aquarium-%lx", hash);
	return str;
}
