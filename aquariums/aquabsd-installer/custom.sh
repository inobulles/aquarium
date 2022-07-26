service os-release start # important or the aquarium frontend will refuse to create an image

export IGNORE_OSVERSION=yes
export ALWAYS_YES=yes

pkg install -y vim
