# aquarium

Repository for the source code of the `aquarium` frontend.
Aquariums allow you to create virtual environments from automatically-downloaded templates, interact with & mutate them, and then finally create new templates or complete bootable (UEFI+BIOS) images out of them.

Usage examples may be found in the `img` directory.
This directory serves to automate building images, such as the aquaBSD installer image.

## Compilation

As root, run:

```console
sh build.sh
```

This will generate the `aquarium` frontend in `bin/aquarium`.

## Testing

As user, run:

```console
sh test.sh
```

This will go through all of the `img` directories and build all bootable image artifacts, which will then be placed in `.build`.
This is what the CI setup does.
