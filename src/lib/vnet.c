// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2023 Aymeric Wibo

#include <aquarium.h>

#include <err.h>
#include <errno.h>
#include <jail.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_bridgevar.h>
#include <string.h>
#include <sys/ioccom.h>
#include <sys/sockio.h>
#include <unistd.h>

// XXX using ioctl API rather than Netlink
//     see #36

static int if_create(aquarium_vnet_t* vnet, char const* type, aquarium_if_name_t name) {
	struct ifreq ifr = {};
	strlcpy(ifr.ifr_name, type, sizeof ifr.ifr_name);

#if defined(SIOCIFCREATE2)
	unsigned long const req = SIOCIFCREATE2;
	char const* const req_str = "SIOCIFCREATE2";
#else
	unsigned long const req = SIOCIFCREATE;
	char const* const req_str = "SIOCIFCREATE";
#endif

	if (ioctl(vnet->sock, req, &ifr) < 0) {
		warnx("ioctl(%s, \"%s\"): %s", req_str, type, strerror(errno));
		return -1;
	}

	strcpy(name, ifr.ifr_name);

	return 0;
}

static int if_destroy(aquarium_vnet_t* vnet, aquarium_if_name_t name) {
	struct ifreq ifr = {};
	strcpy(ifr.ifr_name, name);

	if (ioctl(vnet->sock, SIOCIFDESTROY, &ifr) < 0) {
		warnx("ioctl(SIOCIFDESTROY, \"%s\"): %s", name, strerror(errno));
		return -1;
	}

	return 0;
}

static int if_up(aquarium_vnet_t* vnet, aquarium_if_name_t name) {
	struct ifreq ifr = {
		.ifr_flags = IFF_UP,
	};

	strcpy(ifr.ifr_name, name);

	if (ioctl(vnet->sock, SIOCSIFFLAGS, &ifr) < 0) {
		warnx("ioctl(SIOCSIFFLAGS, IFF_UP, \"%s\"): %s", name, strerror(errno));
		return -1;
	}

	return 0;
}

static int bridge_add(aquarium_vnet_t* vnet, aquarium_if_name_t bridge, aquarium_if_name_t name) {
	struct ifbreq req = {};
	strcpy(req.ifbr_ifsname, name);

	struct ifdrv ifd = {
		.ifd_cmd = BRDGADD,
		.ifd_len = sizeof req,
		.ifd_data = &req,
	};

	strcpy(ifd.ifd_name, bridge);

	if (ioctl(vnet->sock, SIOCSDRVSPEC, &ifd) < 0) {
		warnx("ioctl(SIOCSDRVSPEC.BRDGADD, add \"%s\" to \"%s\"): %s", name, bridge, strerror(errno));
		return -1;
	}

	return 0;
}

static int if_vnet(aquarium_vnet_t* vnet, aquarium_if_name_t name, char* hash) {
	int const jid = jail_getid(hash);

	if (jid < 0) {
		warnx("jail_getid(\"%s\"): %s", hash, jail_errmsg);
		return -1;
	}

	struct ifreq ifr = {
		.ifr_jid = jid,
	};

	strcpy(ifr.ifr_name, name);

	if (ioctl(vnet->sock, SIOCSIFVNET, &ifr) < 0) {
		warnx("ioctl(SIOCSIFVNET, \"%s\"): %s", name, strerror(errno));
		return -1;
	}

	return 0;
}

int aquarium_vnet_create(aquarium_vnet_t* vnet, char* bridge_name) {
	int rv = -1;
	memset(vnet, 0, sizeof *vnet);

	// make sure if_epair is loaded in the kernel
	// this is necessary to create the epair interface cloner in the first place

	if (aquarium_os_load_epair_kmod() < 0) {
		goto err_kmod_epair;
	}

	// connection to API

	vnet->sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (vnet->sock < 0) {
		warnx("socket: %s", strerror(errno));
		goto err_sock;
	}

	// create epair interfaces

	if (if_create(vnet, "epair", vnet->epair) < 0) {
		goto err_create;
	}

	strcpy(vnet->internal_epair, vnet->epair);
	vnet->internal_epair[strlen(vnet->epair) - 1] = 'b';

	// if interface passed is not a bridge, create a new bridge and add that interface to it

	if (strncmp(bridge_name, "bridge", 6) != 0) {
		if (aquarium_os_load_bridge_kmod() < 0) {
			goto err_kmod_bridge;
		}

		if (if_create(vnet, "bridge", vnet->bridge) < 0) {
			goto err_bridge_create;
		}

		if (bridge_add(vnet, vnet->bridge, bridge_name /* not a bridge here */)) {
			goto err_bridge_add_if;
		}

		bridge_name = vnet->bridge;
	}

	// add external epair interface to bridge

	if (bridge_add(vnet, bridge_name, vnet->epair) < 0) {
		goto err_bridge_add;
	}

	// up the bridge

	if (if_up(vnet, bridge_name) < 0) {
		goto err_bridge_up;
	}

	// up the external epair

	if (if_up(vnet, vnet->epair) < 0) {
		goto err_epair_up;
	}

	// success 🎉

	rv = 0;

err_epair_up:
err_bridge_up:
err_bridge_add:
err_bridge_add_if:
err_bridge_create:
err_kmod_bridge:
err_create:
err_sock:
err_kmod_epair:

	if (rv < 0) {
		aquarium_vnet_destroy(vnet);
	}

	return rv;
}

void aquarium_vnet_destroy(aquarium_vnet_t* vnet) {
	if (*vnet->epair) {
		// epair*a and epair*b are linked at the driver level, such that destroying one always destroys the other and vice versa
		// cf. sys/net/if_epair.c

		if_destroy(vnet, vnet->epair);
	}

	if (*vnet->bridge) {
		if_destroy(vnet, vnet->bridge);
	}

	if (vnet->sock) {
		close(vnet->sock);
	}
}

int aquarium_vnet_attach(aquarium_vnet_t* vnet, char* hash) {
	if (if_vnet(vnet, vnet->internal_epair, hash) < 0) {
		return -1;
	}

	vnet->attached = true;
	return 0;
}

// to be run inside of the aquarium

int aquarium_vnet_dhcp(aquarium_vnet_t* vnet) {
	char* cmd;
	if (asprintf(&cmd, "dhclient %s", vnet->internal_epair)) {}

	if (system(cmd) != EXIT_SUCCESS) {
		warnx("'%s' failed", cmd);
		free(cmd);

		return -1;
	}

	free(cmd);
	return 0;
}
