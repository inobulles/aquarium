# aquarium

Repository for the source code of the `aquarium` frontend.
Aquariums allow you to create virtual environments from automatically-downloaded templates, interact with & mutate them, and then finally create new templates or complete bootable (UEFI+BIOS) images out of them.

Usage examples may be found in the `tests` directory.
This directory serves to automate building images, such as the aquaBSD installer image.

## Building

With [Bob the Builder](https://github.com/inobulles/bob) installed:

```console
bob build
```

To run the tests (which require aquariums to be installed, see the following section):

```console
sh tests.sh
```

## Installing

Just:

```console
bob install
```

As of Bob v0.2, build scripts are unable to use custom installation instructions.
This means that, if you would like to use the `aquarium` frontend tool as a user that's member of the `stoners` group, you must manually change ownership and add the setuid flag of the installed binary:

```console
chown root:wheel /usr/local/bin/aquarium
chmod +s /usr/local/bin/aquarium
```

(Depending on your platform, `aquarium` may not have been installed at that exact prefix.)

## Installed directory structure

- `/usr/local/aquarium/`: The base directory for all aquarium-related stuff. This can be modified with `-r`.
  - `/usr/local/aquarium/tmpls.remote`: List of sanctioned templates.
  - `/usr/local/aquarium/db`: Database of all aquariums.
  - `/usr/local/aquarium/tmpls/`: All cached templates.
    - `/usr/local/aquarium/tmpls/amd64.freebsd.14.1-RELEASE-p5.txz`: Example of a cached template.
  - `/usr/local/aquarium/kerns/`: All cached kernels.
    - `/usr/local/aquarium/kerns/amd64.freebsd.14.1-RELEASE-p5.txz`: Example of a cached kernel.
  - `/usr/local/aquarium/roots/`: Physical locations of the root file systems of the aquariums.
    - `/usr/local/aquarium/roots/7538ef/`: Example of a root file system.
