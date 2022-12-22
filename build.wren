// install dependencies

Deps.git_inherit("https://github.com/inobulles/libcopyfile")
Deps.git_inherit("https://github.com/inobulles/libmkfs_msdos")

// C compilation

var cc = CC.new()

cc.add_opt("-std=c99")
cc.add_opt("-isystem=/usr/local/include")
cc.add_opt("-L/usr/local/lib")
cc.add_opt("-Wall")
cc.add_opt("-Wextra")

var src = File.list("src")
	.where { |path| path.endsWith(".c") }

src
	.each { |path| cc.compile(path) }

// linking

var linker = Linker.new(cc)
linker.link(src.toList, ["archive", "copyfile", "crypto", "fetch", "geom", "jail", "mkfs_msdos", "pkg", "zfs"], "aquarium")

// running

class Runner {
	static run(args) { File.exec("aquarium", args) }
}

// installation map
// TODO how will setuid work?
// for reference: chmod u+s aquarium && chown root:wheel aquarium
// probably should be in the build stage right? or the runner won't work...

class Installer {
	static aquarium(path) {
		File.chmod(path, File.EXTRA, File.SETUID)
		File.chown(path, "root", "wheel")

		return true
	}
}

var install = {
	"aquarium": "%(Meta.prefix())/bin/aquarium",
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
