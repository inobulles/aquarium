// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2024 Aymeric Wibo

#pragma once

// clang-format off

static char const* const SANCTIONED =
	// XXX Linux kernels are unsupported as of yet, so all Linux aquariums are base template only.
	// Ubuntu 20.04.6 LTS (Focal Fossa).

	"b:amd64.ubuntu.focal:https:github.com/inobulles/bob-linux-images/releases/download/amd64.ubuntu.focal/amd64.ubuntu.focal.txz:123438644:e1236bcc6a755a0db1d0fa34d4f6a942a56a51778a52d344c3d8c9c4f3b13682\n"

	// FreeBSD 15.0-RELEASE.

	"b:amd64.freebsd.15-0-release:https:download.freebsd.org/ftp/releases/amd64/15.0-RELEASE/base.txz:165127228:ac0c933cc02ee8af4da793f551e4a9a15cdcf0e67851290b1e8c19dd6d30bba8\n"
	"k:amd64.freebsd.15-0-release:https:download.freebsd.org/ftp/releases/amd64/15.0-RELEASE/kernel.txz:44701208:1c36f7e635dc2bba32b7e64de35a730ffc439a4072bd40d0e7221d6df35f12da\n"
	"o:amd64.freebsd.15-0-release.src:https:download.freebsd.org/ftp/releases/amd64/15.0-RELEASE/src.txz:249714004:83c3e8157b6d7afcae57167fda75693bf1e5f581ca149a6ecb2d398b71bdfab0\n"

	// FreeBSD 14.2-RELEASE.

	"b:amd64.freebsd.14-2-release:https:download.freebsd.org/ftp/releases/amd64/14.2-RELEASE/base.txz:205880752:e3971a3d4f36ed1ac67d2e7a5501726de79dd3695aa76bfad2a4ebe91a88a134\n"
	"k:amd64.freebsd.14-2-release:https:download.freebsd.org/ftp/releases/amd64/14.2-RELEASE/kernel.txz:57859924:b441661d86cbea3be3191db462d0477e099e7dbdc4d2ca186ebb14df1a848480\n"
	"o:amd64.freebsd.14-2-release.src:https:download.freebsd.org/ftp/releases/amd64/14.2-RELEASE/src.txz:214942672:2e8a48c5209302e5372ccbaf3e0adf8f21c9cadfdc8277420bf43ac236387a93\n"
;

// vim: nospell
