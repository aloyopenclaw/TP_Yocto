SUMMARY = "Strict iptables firewall for the IoT gateway (SSH 22 + lo only)"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://firewall-init"

S = "${WORKDIR}"

inherit update-rc.d
INITSCRIPT_NAME = "firewall"
INITSCRIPT_PARAMS = "start 10 2 3 4 5 . stop 90 0 1 6 ."

do_install () {
    install -d ${D}${sysconfdir}/init.d
    install -m 0755 ${WORKDIR}/firewall-init ${D}${sysconfdir}/init.d/firewall
}

FILES:${PN} = "${sysconfdir}/init.d/firewall"
RDEPENDS:${PN} = "iptables"
