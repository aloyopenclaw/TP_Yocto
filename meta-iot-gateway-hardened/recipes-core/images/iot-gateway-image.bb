SUMMARY = "Hardened IoT Gateway image"
DESCRIPTION = "core-image-base derivative: locked root, admin user, hardened sshd, read-only rootfs, iptables firewall"
LICENSE = "MIT"

inherit core-image
inherit extrausers

IMAGE_FEATURES += "ssh-server-openssh read-only-rootfs"

IMAGE_INSTALL:append = " iptables sudo firewall-config"

# admin in sudo group with SHA-512 password; root login locked.
# Hash generated with: openssl passwd -6 'AdminTP2026!'
# \$ escapes $ for BitBake (prevents variable expansion of $6, $7nOk..., etc.)
EXTRA_USERS_PARAMS = " \
    groupadd -f sudo; \
    useradd -p '\$6\$7nOkTIAhvuoszZjH\$pDkpmS/.mXgLulu3WgNdyT/oydvwINYxGp4c7pE6K28X.e9kRzf4hyKqMrjIDtn8RScNf71V0.H11aXBtZPGb0' -G sudo admin; \
    usermod -L root; \
"

# Enable %sudo group in sudoers (Yocto's default sudoers doesn't include it)
setup_sudoers() {
    echo '%sudo ALL=(ALL) ALL' > ${IMAGE_ROOTFS}${sysconfdir}/sudoers.d/sudo
    chmod 0440 ${IMAGE_ROOTFS}${sysconfdir}/sudoers.d/sudo
}

# Enforce our sshd_config AFTER read_only_rootfs_hook (which overrides PermitRootLogin to yes)
enforce_sshd_hardening() {
    for f in ${IMAGE_ROOTFS}${sysconfdir}/ssh/sshd_config ${IMAGE_ROOTFS}${sysconfdir}/ssh/sshd_config_readonly; do
        if [ -f "$f" ]; then
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$f"
            sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' "$f"
            sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication no/' "$f"
            # Ensure directives exist
            grep -q '^PermitRootLogin no' "$f" || echo 'PermitRootLogin no' >> "$f"
            grep -q '^PasswordAuthentication yes' "$f" || echo 'PasswordAuthentication yes' >> "$f"
            grep -q '^PubkeyAuthentication no' "$f" || echo 'PubkeyAuthentication no' >> "$f"
        fi
    done
}

ROOTFS_POSTPROCESS_COMMAND += "setup_sudoers; "
ROOTFS_POSTPROCESS_COMMAND += "enforce_sshd_hardening; "
