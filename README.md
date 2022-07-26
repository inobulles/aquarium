# aquabsd-builder

Say hello to Bob the builder 👷
Bob the builder will help you create aquaBSD images.

This help is presented through the `aquarium` frontend, which allow you to create virtual environments from templates (which are downloaded remotely and checked by size & SHA256 hash), interact with said virtual environments, and then finally either create more templates or bootable (UEFI+BIOS) images out of them.

There are usage examples in the `img` directory.
This directory serves to automate building images, such as the aquaBSD installer image.

## Compilation

As root, run:

```console
sh build.sh
```

This will generate the `aquarium` frontend in `bin/aquarium`.

## Testing

Bob the builder always enjoys giving a hand!
Don't be afraid to ask him to run a few tests:

```console
sh test.sh
```

He'll then go through all of the `img` directories and build all bootable image artifacts, which he'll then place in `.build`.
This is what the CI setup does.

[https://www.youtube.com/watch?v=0ldh_Cw6W0c](https://www.youtube.com/watch?v=0ldh_Cw6W0c)
