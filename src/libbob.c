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

// TODO replace these very aquaBSD-specific (and frankly dirty) libraries with something a bit more generic

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

#define FS_IMG_PATH "fs.img"

#define ASSEMBLED_IMG_PATH "assembled.img"

#define CHECK_AQUARIUM(aquarium, rv) \
	if (!(aquarium)) { \
		BOB_WARN("Using %s on a non-existant aquarium\n", __func__) \
		return rv; \
	}

// global settings functions

unsigned bob_verbose = 0;

void bob_set_verbose(unsigned verbose) {
	bob_verbose = verbose;
}

static unsigned bob_chunk_bytes = 4096;

void bob_set_chunk_bytes(unsigned chunk_bytes) {
	bob_chunk_bytes = chunk_bytes;
}

// aquarium creation/destruction functions

bob_aquarium_t* bob_new_aquarium(const char* name) {
	BOB_INFO("Creating a new aquarium (%s) ...\n", name)

	int rv = -1;

	bob_aquarium_t* aquarium = calloc(1, sizeof *aquarium);

	aquarium->name = strdup(name);
	aquarium->sys = BOB_SYS_AQUABSD;

	char _path[] = "/tmp/bob-aquarium-XXXXXXX";
	char* path = mkdtemp(_path);

	if (!path) {
		BOB_FATAL("Failed to create build directory for aquarium\n")
		goto error;
	}

	aquarium->path = strdup(path);

	if (chdir(aquarium->path) < 0) {
		BOB_FATAL("Failed to enter aquarium build directory (%s) (%s)\n", aquarium->path, strerror(errno))
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

	return aquarium;

error:

	bob_del_aquarium(aquarium);
	goto done;
}

void bob_del_aquarium(bob_aquarium_t* aquarium) {
	CHECK_AQUARIUM(aquarium, )

	if (aquarium->name) {
		BOB_INFO("Deleting aquarium (%s) ...\n", aquarium->name)
		free(aquarium->name);
	}

	if (aquarium->path) {
		// TODO something similar to libcopyfile (should these be combined into a general libfsutils library or something?)
		//      this is currently really very super bad 😬

		char* cmd;

		asprintf(&cmd, "read _ && rm -rf \"%s\"", aquarium->path);
		BOB_WARN("Going to run the following command: %s\n", cmd);

		if (system(cmd)) {
			free(cmd);

			BOB_FATAL("Failed to delete aquarium directory (%s) (%s)\n", aquarium->path, strerror(errno))
		}

		free(cmd);
		free(aquarium->path);
	}
}

// aquarium settings functions

int bob_aquarium_sys(bob_aquarium_t* aquarium, bob_sys_t sys) {
	CHECK_AQUARIUM(aquarium, -1)

	if ((unsigned) sys >= BOB_SYS_LEN) {
		BOB_WARN("Unknown system %d\n", sys)
		return -1;
	}

	aquarium->sys = sys;
	return 0;
}

// aquarium component functions

int bob_aquarium_net_component(bob_aquarium_t* aquarium, const char* name, const char* url) {
	CHECK_AQUARIUM(aquarium, -1)
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

int bob_aquarium_component_extract(bob_aquarium_t* aquarium, const char* name) {
	CHECK_AQUARIUM(aquarium, -1)
	BOB_INFO("Extracting component (%s) ...\n", name)

	int rv = -1;

	// "chroot" (really just changing directories) to the final root
	// don't forget to go back to the aquarium's build directory, so 'bob_aquarium_component_extract' is atomic
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

	// don't forget to change back to aquarium build directory!

	if (chdir("..") < 0) {
		BOB_FATAL("Failed to change back into aquarium build directory after component extraction (%s)\n", strerror(errno))
		rv = -1;
	}

error_chdir:

	return rv;
}

// aquarium configuration functions

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

static int dummy_aquarium_hostname(bob_aquarium_t* aquarium, const char* hostname) {
	BOB_FATAL("Setting hostname for system %d aquariums is currently unsupported\n", aquarium->sys)
	return -1;
}

static int freebsd_aquarium_hostname(bob_aquarium_t* aquarium, const char* hostname) {
	char* ent = malloc(strlen(hostname) + 64);
	sprintf(ent, "hostname=%s\n", hostname);

	int rv = file_append_str(ROOTFS_PATH "/etc/rc.conf", ent);

	free(ent);

	return rv;
}

int bob_aquarium_hostname(bob_aquarium_t* aquarium, const char* hostname) {
	CHECK_AQUARIUM(aquarium, -1)
	BOB_INFO("Setting hostname to %s ...\n", hostname)

	int (*lut[BOB_SYS_LEN]) (bob_aquarium_t* aquarium, const char* hostname);

	// clear LUT entries

	for (int i = 0; i < sizeof(lut) / sizeof(*lut); i++) {
		lut[i] = dummy_aquarium_hostname;
	}

	lut[BOB_SYS_FREEBSD] = freebsd_aquarium_hostname;

	return lut[aquarium->sys](aquarium, hostname);
}

// image component creation functions

static int dummy_aquarium_gen_fs(bob_aquarium_t* aquarium, const char* label) {
	BOB_FATAL("Generating filesystem for system %d aquariums is currently unsupported\n", aquarium->sys);
	return -1;
}

static int aquabsd_aquarium_gen_fs(bob_aquarium_t* aquarium, const char* label) {
	BOB_WARN("%s is not really super well implemented just yet (cf. the long-ass comment at the beginning of the function in " __FILE__ ")\n", __func__)

	// TODO this is actually quite a bit more involved than I would have hoped 😅
	//      basically what imma need to do is create some kind of unified interface for creating file system partitions and populating them
	//      this will be done through some kind of libmkfs library, similar to libmkfs_msdos currently
	//      this library will be based off of makefs (aquabsd-core/usr.sbin/makefs), which is a program ported over from NetBSD
	//      makefs is a bit tricky to build out of tree (because of dependencies on sources from mtree, libnetbsd, &c), so I'll probably build libmkfs right into aquaBSD core when I get around to that
	//      this is a bit unfortunate because it means this program will only really work to build full aquarium images on aquaBSD, & not on FreeBSD
	//      oh well
	//      in any case, when I do implement libmkfs, I'll be able to
	//       - write it in a much cleaner, potentially modular way
	//       - deprecate libmkfs_msdos & libmkfs_ufs
	//       - deprecate the newfs & newfs_msdos utilities in aquaBSD core
	//       - rewrite makefs to basically just be a frontend for libmkfs (perhaps I can even change the name to just mkfs, similar to the Linux FS creation tools (mkfs.*) to emphasize this change?)
	//       - could probably move makefs to /usr/bin, so that you don't need to be a SU to simply create image files from folders
	//      so, for the meantime, this is just an ugly call to 'system'
	//      (to clarify, I can't use libmkfs_ufs, because I must decide the size of my partition first)

	char* cmd = malloc(strlen(label) + strlen(FS_IMG_PATH) + strlen(ROOTFS_PATH) + 64);
	sprintf(cmd, "makefs -B little -o label=%s " FS_IMG_PATH " " ROOTFS_PATH, label);

	BOB_WARN("Executing command: %s\n", cmd)

	int rv = system(cmd);
	free(cmd);

	return rv;
}

static int freebsd_aquarium_gen_fs(bob_aquarium_t* aquarium, const char* label) {
	// literally just a wrapper around aquabsd_aquarium_gen_fs

	return aquabsd_aquarium_gen_fs(aquarium, label);
}

int bob_aquarium_gen_fs(bob_aquarium_t* aquarium, const char* label) {
	CHECK_AQUARIUM(aquarium, -1)
	BOB_INFO("Creating filsystem partition (%s) ...\n", label)

	int (*lut[BOB_SYS_LEN]) (bob_aquarium_t* aquarium, const char* label);

	// clear LUT entries

	for (int i = 0; i < sizeof(lut) / sizeof(*lut); i++) {
		lut[i] = dummy_aquarium_gen_fs;
	}

	lut[BOB_SYS_AQUABSD] = aquabsd_aquarium_gen_fs;
	lut[BOB_SYS_FREEBSD] = freebsd_aquarium_gen_fs;

	return lut[aquarium->sys](aquarium, label);
}

int bob_aquarium_gen_esp(bob_aquarium_t* aquarium, const char* oem, const char* label) {
	CHECK_AQUARIUM(aquarium, -1)
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
	sprintf(esp_dev_path, _PATH_DEV MD_NAME "%d", mdio.md_unit);

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

	// success

	rv = 0;

error_boot_copy:
error_efi_struct:

	// unmount the ESP
	// don't really care about any errors here

	if (unmount(ESP_MOUNT, 0) < 0) {
		BOB_WARN("Failed to unmount ESP (%s)\n", strerror(errno))
	}

error_mount_esp:
error_mkdir_mount:

	free(esp_dev_path);

	// detach memory disk
	// don't really care about any errors here either

	int unit = mdio.md_unit;

	memset(&mdio, 0, sizeof mdio);

	mdio.md_version = MDIOVERSION;
	mdio.md_unit = unit;

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
	// but the whole aquarium build directory will be deleted anyway so 🤷

error_mkfs:

	return rv;
}

static int dummy_aquarium_assemble(bob_aquarium_t* aquarium) {
	BOB_FATAL("Assembling system %d aquariums is currently unsupported\n", aquarium->sys);
	return -1;
}

static int aquabsd_aquarium_assemble(bob_aquarium_t* aquarium) {
	BOB_WARN("%s is not really super well implemented just yet (cf. the long-ass comment at the beginning of the function in " __FILE__ ")\n", __func__)

	// TODO similar story to aquabsd_aquarium_gen_fs; create a libmkimg library to replace this shit
	//      this is even worse than that lol 💩
	// TODO also abandon MBR completely in favour of GPT pretty please - there's no reason the installer should be installing GPT but using MBR!

	char* cmd = malloc(strlen(ROOTFS_PATH) * 2 + strlen(ESP_IMG_PATH) + strlen(FS_IMG_PATH) + strlen(ASSEMBLED_IMG_PATH) + 128);
	sprintf(cmd, "mkimg -s mbr -b %s/boot/mbr -p efi:=%s -p freebsd:-\"mkimg -s bsd -b %s/boot/boot -p freebsd-ufs:=%s\" -a 2 -o %s", ROOTFS_PATH, ESP_IMG_PATH, ROOTFS_PATH, FS_IMG_PATH, ASSEMBLED_IMG_PATH);

	BOB_WARN("Executing command: %s\n", cmd)

	int rv = system(cmd);

	aquarium->assembled_path = realpath(ASSEMBLED_IMG_PATH, NULL);

	if (!aquarium->assembled_path) {
		BOB_FATAL("Failed to find assembled image file (%s) (%s)\n", ASSEMBLED_IMG_PATH, strerror(errno))
		rv = -1;
	}

	return rv;
}

static int freebsd_aquarium_assemble(bob_aquarium_t* aquarium) {
	// literally just a wrapper around aquabsd_aquarium_assemble

	return aquabsd_aquarium_assemble(aquarium);
}

int bob_aquarium_assemble(bob_aquarium_t* aquarium) {
	CHECK_AQUARIUM(aquarium, -1)
	BOB_INFO("Assembling image file ...\n")

	int (*lut[BOB_SYS_LEN]) (bob_aquarium_t* aquarium);

	// clear LUT entries

	for (int i = 0; i < sizeof(lut) / sizeof(*lut); i++) {
		lut[i] = dummy_aquarium_assemble;
	}

	lut[BOB_SYS_AQUABSD] = aquabsd_aquarium_assemble;
	lut[BOB_SYS_FREEBSD] = freebsd_aquarium_assemble;

	return lut[aquarium->sys](aquarium);
}