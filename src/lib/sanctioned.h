// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2024 Aymeric Wibo

#pragma once

static char const* const SANCTIONED =
	// XXX Linux kernels are unsupported as of yet, so all Linux aquariums are base template only.
	// Ubuntu 20.04.6 LTS (Focal Fossa).

	"b:amd64.ubuntu.focal:https:github.com/inobulles/bob-linux-images/releases/download/amd64.ubuntu.focal/amd64.ubuntu.focal.txz:123438644:e1236bcc6a755a0db1d0fa34d4f6a942a56a51778a52d344c3d8c9c4f3b13682\n"

	// FreeBSD 14.2-RELEASE.

	"b:amd64.freebsd.14-2-release:https:download.freebsd.org/ftp/releases/amd64/14.2-RELEASE/base.txz:205880752:e3971a3d4f36ed1ac67d2e7a5501726de79dd3695aa76bfad2a4ebe91a88a134\n"
	"k:amd64.freebsd.14-2-release:https:download.freebsd.org/ftp/releases/amd64/14.2-RELEASE/kernel.txz:57859924:b441661d86cbea3be3191db462d0477e099e7dbdc4d2ca186ebb14df1a848480\n"
	"o:amd64.freebsd.14-2-release.src:https:download.freebsd.org/ftp/releases/amd64/14.2-RELEASE/src.txz:214942672:idk\n"
;

// vim: nospell
