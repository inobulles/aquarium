# aquarium

Repository for the source code of the `aquarium` frontend.
Aquariums allow you to create virtual environments from automatically-downloaded templates, interact with & mutate them, and then finally create new templates or complete bootable (UEFI+BIOS) images out of them.

Usage examples may be found in the `img` directory.
This directory serves to automate building images, such as the aquaBSD installer image.

## Building

With [Bob the Builder](https://github.com/inobulles/bob) installed:

```console
bob test install
```
