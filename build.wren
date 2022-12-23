// install dependencies

Deps.git_inherit("https://github.com/inobulles/libcopyfile")
Deps.git_inherit("https://github.com/inobulles/libmkfs_msdos")

// C compilation

var cc = CC.new()

cc.add_opt("-std=c99")
cc.add_opt("-isystem=/usr/local/include")
cc.add_opt("-L/usr/local/lib")
cc.add_opt("-fPIC")
cc.add_opt("-Wall")
cc.add_opt("-Wextra")
cc.add_opt("-Isrc/lib/include")

var lib_src = File.list("src/lib")
	.where { |path| path.endsWith(".c") }

var aquarium_src = File.list("src/aquarium")
	.where { |path| path.endsWith(".c") }

var installer_src = File.list("src/installer")
	.where { |path| path.endsWith(".c") }

var src = lib_src.toList + aquarium_src.toList + installer_src

src
	.each { |path| cc.compile(path) }

// create static & dynamic libraries

var linker = Linker.new(cc)

linker.archive(lib_src.toList, "libaquarium.a")
linker.link(lib_src.toList, ["archive", "copyfile", "crypto", "fetch", "geom", "jail", "mkfs_msdos", "zfs"], "libaquarium.so", true)

// create aquarium command-line frontend

linker.link(aquarium_src.toList, ["aquarium", "archive", "copyfile"], "aquarium")

// create installer command-line frontend

linker.link(installer_src.toList, ["aquarium"], "installer")

// copy over headers

File.list("src", 1)
	.where { |path| path.endsWith(".h") }
	.each  { |path| Resources.install(path) }

// running

class Runner {
	static run(args) { File.exec("installer", args) }
}

// installation map

class Installer {
	static aquarium(path) {
		File.chmod(path, File.EXTRA, File.SETUID)
		File.chown(path, "root", "wheel")

		return "%(Meta.prefix())/bin/aquarium"
	}
}

var install = {
	"aquarium":       ":aquarium",
	"installer":      "%(Meta.prefix())/bin/installer",
	"libaquarium.a":  "%(Meta.prefix())/lib/libaquarium.a",
	"libaquarium.so": "%(Meta.prefix())/lib/libaquarium.so",
	"aquarium.h":     "%(Meta.prefix())/include/aquarium.h",
}

// testing

class Tests {
	// e2e tests

	static img_aquabsd_installer { // try to compile an aquaBSD installer image
		return File.exec("sh", ["build.sh"])
	}

	static img_just_vim_yo { // try to compile an aquaBSD image with just vim installed
		return File.exec("sh", ["build.sh"])
	}
}

var tests = [
	// "img_aquabsd_installer", // disable this one for now, because it takes a long time and is relatively unstable
	"img_just_vim_yo",
]
