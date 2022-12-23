# `include/` subdirectory

## Why is this here?

FreeBSD, at least as of `13-RELEASE` & `14-CURRENT`, includes the `libzfs.h` header in base (in `/usr/include`).
This file isn't meant for usage (in fact it doesn't exist whatsoever on aquaBSD core), which is why it has a couple dependency issues.
More specifically, the following files are required by `libzfs.h`, but aren't installed on base:

| Header file          | Path in OpenZFS source tree             |
|----------------------|-----------------------------------------|
| `libnvpair.h`        | `include/libnvpair.h`                   |
| `ucred.h`            | `lib/libspl/include/ucred.h`            |
| `sys/avl.h`          | `lib/libspl/include/sys/avl.h`          |
| `sys/avl_impl.h`     | `lib/libspl/include/sys/avl_impl.h`     |
| `sys/zio_priority.h` | `lib/libspl/include/sys/zio_priority.h` |
| `sys/fs/zfs.h`       | `lib/libspl/include/sys/fs/zfs.h`       |
| `sys/varargs.h`      | `lib/libspl/include/sys/varargs.h`      |
| `sys/mnttab.h`       | `lib/libspl/include/sys/mnttab.h`       |

Additionally, the `libzfs_core.h` is required (`include/libzfs_core.h` in OpenZFS source tree), and is installed on base, but depends on `libnvpair.h`, which isn't.

The same thing is true for `sys/nvpair.h` library (which doesn't exist on aquaBSD core either); it's installed on FreeBSD base and depends on the following types, which are only defined in the OpenZFS source tree:

| Type       | Equivalent  | Path to definition in OpenZFS source tree |
|------------|-------------|-------------------------------------------|
| `uint_t`   | `u_int`     | `include/os/freebsd/spl/sys/types.h`      |
| `uchar_t`  | `u_char`    | `include/os/freebsd/spl/sys/types.h`      |
| `ulong_t`  | `u_long`    | `include/os/freebsd/spl/sys/types.h`      |
| `hrtime_t` | `long long` | `include/os/freebsd/spl/sys/time.h`       |

As not to copy the entirety of the OpenZFS source tree over for a few types, they're defined "manually" at the top of `include/sys/nvpair.h`.

## Where do these files come from?

From the [OpenZFS source tree](https://github.com/openzfs/zfs), at the paths specified in the previous section.

## Why did you take the time to write this file?

Procrastination.

## Notes

More information on the issue can be found on this FreeBSD forum post: [Missing ZFS headers?](https://forums.freebsd.org/threads/missing-zfs-headers.82564/)
