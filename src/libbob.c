#include <bob.h>

// TODO the two following headers are necessary for 'fetch.h' but are not included
//      most likely a bug, fix this

#include <sys/param.h>
#include <time.h>

#include <fetch.h>
#include <archive.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/mount.h>

#include <mkfs_msdos.h>
// #include <mkfs_ufs.h>

#include <libutil.h> // for kld_* stuff
#include <paths.h>

#include <sys/mdioctl.h>
#include <copyfile.h>

#define ROOTFS_PATH "rootfs"
#define COMPONENT_PATH "components"

#define ESP_IMG_PATH "esp.img"
#define ESP_MOUNT "esp"

#define CHECK_VESSEL(vessel, rv) \
	if (!(vessel)) { \
		BOB_WARN("Using %s on a non-existant vessel\n", __func__) \
		return rv; \
	}

// global settings functions

static unsigned bob_verbose = 0;

void bob_set_verbose(unsigned verbose) {
	bob_verbose = verbose;
}

static unsigned bob_chunk_bytes = 4096;

void bob_set_chunk_bytes(unsigned chunk_bytes) {
	bob_chunk_bytes = chunk_bytes;
}

// vessel creation/destruction functions

bob_vessel_t* bob_new_vessel(const char* name) {
	BOB_INFO("Creating a new vessel (%s) ...\n", name)

	int rv = -1;

	bob_vessel_t* vessel = calloc(1, sizeof *vessel);

	vessel->name = strdup(name);
	vessel->sys = BOB_SYS_AQUABSD;

	char _path[] = "/tmp/bob-vessel-XXXXXXX";
	char* path = mkdtemp(_path);

	if (!path) {
		BOB_FATAL("Failed to create build directory for vessel\n")
		goto error;
	}

	vessel->path = strdup(path);

	if (chdir(vessel->path) < 0) {
		BOB_FATAL("Failed to enter vessel build directory (%s) (%s)\n", vessel->path, strerror(errno))
		goto error;
	}

	if (mkdir(ROOTFS_PATH, 0700) < 0 && errno != EEXIST) {
		BOB_FATAL("Failed to create rootfs subdirectory (%s)\n", strerror(errno))
		goto error;
	}

	if (mkdir(COMPONENT_PATH, 0700) < 0 && errno != EEXIST) {
		BOB_FATAL("Failed to create component subdirectory (%s)\n", strerror(errno))
		goto error;
	}

	// success

	rv = 0;

done:

	return vessel;

error:

	bob_del_vessel(vessel);
	goto done;
}

void bob_del_vessel(bob_vessel_t* vessel) {
	CHECK_VESSEL(vessel, )
	
	if (vessel->name) {
		BOB_INFO("Deleting vessel (%s) ...\n", vessel->name)
		free(vessel->name);
	}

	if (vessel->path) {
		if (rmdir(vessel->path) < 0) {
			BOB_FATAL("Failed to delete vessel directory (%s) (%s)\n", vessel->path, strerror(errno))
		}

		free(vessel->path);
	}
}

// vessel settings functions

int bob_vessel_sys(bob_vessel_t* vessel, bob_sys_t sys) {
	CHECK_VESSEL(vessel, -1)

	if ((unsigned) sys >= BOB_SYS_LEN) {
		BOB_WARN("Unknown system %d\n", sys)
		return -1;
	}

	vessel->sys = sys;
	return 0;
}

// vessel component functions

int bob_vessel_net_component(bob_vessel_t* vessel, const char* name, const char* url) {
	CHECK_VESSEL(vessel, -1)
	BOB_INFO("Downloading net component (%s) ...\n", name)

	int rv = -1;
	uint8_t chunk[bob_chunk_bytes]; // initialization of VLA must come before any jumps

	// get component output path

	char* path = malloc(strlen(COMPONENT_PATH) + strlen(name) + 64);
	sprintf(path, COMPONENT_PATH "/%s", name);

	FILE* out_fp = fopen(path, "w+");

	if (!out_fp) {
		BOB_FATAL("Failed to open %s for writing (%s)\n", path, strerror(errno))
		goto error_open_out;
	}

	// fetch the component itself

	FILE* fetch_fp = fetchGetURL(url, "");

	if (!fetch_fp) {
		BOB_FATAL("Failed to find %s component (%s)\n", name, url);
		goto error_open_fetch;
	}

	size_t bytes;

	while ((bytes = fread(chunk, 1, sizeof chunk, fetch_fp)) > 0) {
		if (fwrite(chunk, 1, bytes, out_fp) < bytes) {
			break;
		}
	}

	// success

	rv = 0;

error_open_fetch:

	fclose(out_fp);

error_open_out:

	free(path);

	return rv;
}

int bob_vessel_component_extract(bob_vessel_t* vessel, const char* name) {
	CHECK_VESSEL(vessel, -1)
	BOB_INFO("Extracting component %s ...\n", name)

	int rv = -1;

	// "chroot" (really just changing directories) to the final root
	// don't forget to go back to the vessel's build directory, so 'bob_vessel_component_extract' is atomic
	// as per archive_write_disk(3)'s "BUGS" section, we mustn't call 'chdir' between opening and closing archive objects

	if (chdir(ROOTFS_PATH) < 0) {
		BOB_FATAL("Failed to chroot into " ROOTFS_PATH " to extract the %s component (%s)\n", name, strerror(errno))
		goto error_chdir;
	}

	// get component path

	char* path = malloc(strlen(COMPONENT_PATH) + strlen(name) + 64);
	sprintf(path, "../" COMPONENT_PATH "/%s", name);

	// open archive

	struct archive* archive = archive_read_new();

	archive_read_support_filter_all(archive);
	archive_read_support_format_all(archive);

	if (archive_read_open_filename(archive, path, bob_chunk_bytes) < 0) {
		BOB_FATAL("Failed to open the %s component (%s)\n", name, archive_error_string(archive))
		goto error_read;
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
			BOB_FATAL("Failed to extract the %s component (%s)\n", name, error_string)
			goto error_extract;
		}
	}

	// reached success

	rv = 0;

error_extract:
error_read:

	archive_read_close(archive);
	archive_read_free(archive);

	// don't forget to change back to vessel build directory!

	if (chdir("..") < 0) {
		BOB_FATAL("Failed to change back into vessel build directory after component extraction (%s)\n", strerror(errno))
		rv = -1;
	}

error_chdir:

	return rv;
}

// vessel configuration functions

static int file_append(const char* path, const void* data, size_t len) {
	int rv = -1;

	FILE* fp = fopen(path, "a");

	if (!fp) {
		BOB_FATAL("Failed to open %s (%s)\n", path, strerror(errno))
		goto error_fopen;
	}

	fwrite(data, len, 1, fp);

	// success

	rv = 0;

	fclose(fp);

error_fopen:

	return rv;
}

static int file_append_str(const char* path, const char* str) {
	return file_append(path, str, strlen(str));
}

static int dummy_vessel_hostname(bob_vessel_t* vessel, const char* hostname) {
	BOB_FATAL("Setting hostname for system %d vessels is currently unsupported\n", vessel->sys)
	return -1;
}

static int freebsd_vessel_hostname(bob_vessel_t* vessel, const char* hostname) {
	char* ent = malloc(strlen(hostname) + 64);
	sprintf(ent, "hostname=%s\n", hostname);

	int rv = file_append_str(ROOTFS_PATH "/etc/rc.conf", ent);

	free(ent);

	return rv;
}

int bob_vessel_hostname(bob_vessel_t* vessel, const char* hostname) {
	CHECK_VESSEL(vessel, -1)
	BOB_INFO("Setting hostname to %s ...\n", hostname)

	int (*lut[BOB_SYS_LEN]) (bob_vessel_t* vessel, const char* hostname);

	for (int i = 0; i < sizeof(lut) / sizeof(*lut); i++) {
		lut[i] = dummy_vessel_hostname;
	}

	lut[BOB_SYS_FREEBSD] = freebsd_vessel_hostname;

	return lut[vessel->sys](vessel, hostname);
}

// image component creation functions

int bob_vessel_gen_esp(bob_vessel_t* vessel, const char* oem, const char* label) {
	CHECK_VESSEL(vessel, -1)
	BOB_INFO("Creating EFI system partition (%s) ...\n", label)
	
	int rv = -1;

	// create FAT32 partition for the ESP
	// % newfs_msdos -F 32 -c 1 $esp_img_path

	struct msdos_options options = {
		.OEM_string = oem,
		.volume_label = label,

		.fat_type = 32,

		.create_size = 33292 * 1024, // minimum FAT32 partition size
		.sectors_per_cluster = 1,
	};

	if (mkfs_msdos(ESP_IMG_PATH, NULL, &options) < 0) {
		BOB_FATAL("Failed to create FAT32 filesystem for ESP\n")
		goto error_mkfs;
	}

	// make sure the geom_md kernel module is loaded

	if (!kld_isloaded("g_md") && kld_load("geom_md") < 0) {
		BOB_FATAL("Failed to load the geom_md kernel module\n")
		goto error_geom_md;
	}

	// open a connection to /dev/mdctl

	int mdctl_fd = open(_PATH_DEV MDCTL_NAME, O_RDWR, 0);

	if (mdctl_fd < 0) {
		BOB_FATAL("Failed to open connection to " _PATH_DEV MDCTL_NAME " (%s)\n", strerror(errno))
		goto error_mdctl;
	}

	// create memory disk from that image
	// % mdconfig -a -f $ESP_IMG_PATH

	struct md_ioctl mdio = {
		.md_version = MDIOVERSION,

		.md_type = MD_VNODE,
		.md_options = MD_CLUSTER | MD_AUTOUNIT | MD_COMPRESS,
	};

	// get absolute path of ESP image

	mdio.md_file = realpath(ESP_IMG_PATH, NULL);

	if (!mdio.md_file) {
		BOB_FATAL("Failed to get absolute path for " ESP_IMG_PATH " (%s)\n", strerror(errno))
		goto error_realpath;
	}

	// read size of image

	int fd = open(mdio.md_file, O_RDONLY);

	if (fd < 0) {
		BOB_FATAL("Failed to open " ESP_IMG_PATH " (%s)\n", strerror(errno))
		goto error_md_file_open;
	}

	struct stat sb;
	
	if (fstat(fd, &sb) < 0) {
		BOB_FATAL("Failed to stat " ESP_IMG_PATH " (%s)\n", strerror(errno))
		goto error_stat;
	}

	mdio.md_mediasize = sb.st_size;

	// actually create memory disk

	if (ioctl(mdctl_fd, MDIOCATTACH, &mdio) < 0) {
		BOB_FATAL("Failed to attach memory disk (%s)\n", strerror(errno))
		goto error_attach;
	}

	char* esp_dev_path = malloc(strlen(MD_NAME) + 64);
	sprintf(esp_dev_path, MD_NAME "%d", mdio.md_unit);

	BOB_INFO("Created memory disk at %s\n", esp_dev_path)

	// mount ESP
	// % mkdir -p $ESP_MOUNT
	// % mount -t msdosfs -o longnames $ESP_IMG_PATH $ESP_MOUNT

	if (mkdir(ESP_MOUNT, 0700) < 0 && errno != EEXIST) {
		BOB_FATAL("Failed to create ESP mountpoint at %s (%s)", ESP_MOUNT, strerror(errno))
		goto error_mkdir_mount;
	}

	#define IOV(name, val) \
		(struct iovec) { .iov_base = (name), .iov_len = strlen((name)) + 1 }, \
		(struct iovec) { .iov_base = (val ), .iov_len = strlen((val )) + 1 }

	struct iovec iov[] = {
		IOV("fstype", "msdosfs"),
		IOV("fspath", ESP_MOUNT),
		IOV("from", esp_dev_path),
		IOV("longnames", ""),
	};

	if (nmount(iov, sizeof(iov) / sizeof(*iov), 0) < 0) {
		BOB_FATAL("Failed to mount ESP (from %s to %s) (%s)\n", esp_dev_path, ESP_MOUNT, strerror(errno))
		goto error_mount_esp;
	}

	// create EFI directory structure
	// % mkdir -p $ESP_MOUNT/EFI/BOOT

	if (mkdir(ESP_MOUNT "/EFI", 0700) < 0 && errno != EEXIST) {
		BOB_FATAL("Failed to create EFI directory structure (%s)\n", strerror(errno))
		goto error_efi_struct;
	}

	if (mkdir(ESP_MOUNT "/EFI/BOOT", 0700) < 0 && errno != EEXIST) {
		BOB_FATAL("Failed to create EFI directory structure (%s)\n", strerror(errno))
		goto error_efi_struct;
	}

	// copy over boot code
	// % cp $ROOTFS_PATH/boot/loader.efi $ESP_MOUNT/EFI/BOOT/BOOTX64.efi

	int loader_efi = open(ROOTFS_PATH "/boot/loader.efi", O_RDONLY);

	if (loader_efi < 0) {
		BOB_FATAL("Failed to open boot code at /boot/loader.efi (%s)\n", strerror(errno))
		goto error_boot_copy;
	}

	int bootx64 = creat(ESP_MOUNT "/EFI/BOOT/BOOTX64.efi", 0660);

	if (bootx64 < 0) {
		BOB_FATAL("Failed to create /EFI/BOOT/BOOTX64.efi on ESP partition (%s)\n", strerror(errno))
		
		close(loader_efi);
		goto error_boot_copy;
	}

	if (fcopyfile(loader_efi, bootx64, 0, COPYFILE_ALL) < 0) {
		BOB_FATAL("Failed to copy boot code (%s)\n", strerror(errno))
		
		close(loader_efi);
		close(bootx64);

		goto error_boot_copy;
	}

	close(loader_efi);
	close(bootx64);

	// finally, we can unmount the ESP
	// % umount $ESP_MOUNT

	if (unmount(ESP_MOUNT, 0) < 0) {
		BOB_FATAL("Failed to unmount ESP (%s)\n", strerror(errno))
		goto error_umount;
	}

	// success

	rv = 0;

error_umount:
error_boot_copy:
error_efi_struct:
error_mount_esp:
error_mkdir_mount:

	free(esp_dev_path);

	// detach memory disk (don't really care about any errors here)

	mdio.md_options &= ~MD_AUTOUNIT;

	if (ioctl(mdctl_fd, MDIOCDETACH, &mdio) < 0) {
		BOB_WARN("Failed to detach memory disk (%s)\n", strerror(errno))
	}

error_attach:

	close(mdctl_fd);

error_stat:

	close(fd);

error_md_file_open:

	free(mdio.md_file);

error_realpath:
error_mdctl:
error_geom_md:

	// should technically be removing the ESP image file on error,
	// but the whole vessel build directory will be deleted anyway so 🤷

error_mkfs:

	return rv;
}