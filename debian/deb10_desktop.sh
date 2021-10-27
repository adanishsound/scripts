#!/bin/bash
# 
# deb10_desktop.sh
#
# Live install script for deb + ZFS + enterprise setup
#
# If testing under qemu the host IP is 10.0.2.2
set -e

# Proxy e.g. http://user:password@proxy.company.com:80/
PROXY_URL=${PROXY_URL:-no}
UEFI_BOOT=${UEFI_BOOT:-no}
# Determine the non-HDMI snd device
ALSA_CARD=${ALSA_CARD:-1}
RT_ENABLE=${RT_ENABLE:-no}

PART_BIOS_BOOT=1
PART_BIOS_NAME=bios
PART_UEFI_BOOT=2
PART_UEFI_NAME=EFI
PART_SWAP=3
PART_SWAP_NAME=debswap
PART_SWAP_SIZE=16G
PART_ROOT=4
PART_ROOT_NAME=debroot
PART_ROOT_SIZE=40G
PART_ZFS=5
PART_ZFS_NAME=debzfs
# suffix for setup of /dev/disk/by-id devices
PART_SUFFIX="-part"

# Connection timeout in seconds
CONNECT_TIMEOUT=180

# deb release details
DEB_NAME="buster"
DEB_VERS_MAJOR=10
# building ZFS from source package for now to get 0.8
DEB_ZFS_SRC_NAME="bullseye"
# https://www.debian.org/mirror/list
# DEB_REPO=deb.debian.org/debian
DEB_REPO=ftp.au.debian.org/debian
# https://www.debian.org/security/
DEB_SEC_REPO=security.debian.org/debian-security
DEB_CONNECT_CHECK_URL=http://${DEB_REPO}/dists/${DEB_NAME}/Release.gpg

SCRIPT_NAME=$(basename $0)
SCRIPT=$(readlink -f "$0")
SCRIPT_PATH=$(dirname "${SCRIPT}")

DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

ZFS_POOL=hpool
ZFS_DB_HOME=/db
ZFS_SCRATCH_HOME=/scratch

NET_WIRED_CONF=/etc/network/interfaces.d/wired_cfg
NET_WIFI_CONF=/etc/network/interfaces.d/wifi_cfg

# Can use --user-agent to disown curl ...
CURL_CMD="curl -fsSL --connect-timeout ${CONNECT_TIMEOUT}"
if [ "${PROXY_URL}" != "no" ]; then
    CURL_CMD="${CURL_CMD} --proxy ${PROXY_URL}"
fi

# curl timestamp format to give feedback on response times
CURL_TS='time_namelookup:%{time_namelookup},time_connect:%{time_connect}:time_redirect:%{time_redirect},time_total:%{time_total}\n' 

GIT_CMD="git"
if [ "${PROXY_URL}" != "no" ]; then
    GIT_CMD="${GIT_CMD} -c http.proxy=${PROXY_URL}"
fi

check_root_perm() {
    if [ "$EUID" -ne 0 ]; then
        echo "Run as root."
        exit
    fi
}

store_envs() {
    local TGT_INST_DEV=$1
    echo "Recording environment: ${SCRIPT_PATH}/env_${SCRIPT_NAME}"
    { \
        echo -e "TGT_INST_DEV=${TGT_INST_DEV}"; \
        echo -e "PROXY_URL=${PROXY_URL}"; \
        echo -e "UEFI_BOOT=${UEFI_BOOT}"; \
        echo -e "ALSA_CARD=${ALSA_CARD}"; \
    } > ${SCRIPT_PATH}/env_${SCRIPT_NAME}
}

source_envs() {
    echo "Sourcing environment: ${SCRIPT_PATH}/env_${SCRIPT_NAME}"
    source ${SCRIPT_PATH}/env_${SCRIPT_NAME}
    if [ "${PROXY_URL}" != "no" ]; then
        CURL_CMD="${CURL_CMD} --proxy ${PROXY_URL}"
        GIT_CMD="${GIT_CMD} -c http.proxy=${PROXY_URL}"
    fi
}

check_connection() {
    local TARGET_URL=$1
    echo "Checking connectivity of url: ${TARGET_URL} ... "
    ${CURL_CMD} -o /dev/null -w ${CURL_TS} ${TARGET_URL}
}

check_repo_connection() {
    check_connection ${DEB_CONNECT_CHECK_URL}
}

append_file_with_line() {
    local FILEPATH=$1
    local LINESTRING=$2
    grep -x "${LINESTRING}" ${FILEPATH} > /dev/null || echo "${LINESTRING}" >> ${FILEPATH}
}

#  https://changelog.complete.org/archives/9999-tips-for-upgrading-to-and-securing-debian-buster
apt_harden() {
    # Going to third party repos so use seccomp
    { \
        echo -e "APT::Sandbox::Seccomp \"true\";"; \
    } > /etc/apt/apt.conf.d/99hardening
}

# https://manpages.debian.org/stretch/apt/apt.conf.5.en.html
# In the bowels of enterprise...
# Give a generous timeout around 120 secs, scanners take time ...
apt_settings() {
    { \
        echo -e "Acquire::http::Timeout \"${CONNECT_TIMEOUT}\";"; \
        echo -e "Acquire::https::Timeout \"${CONNECT_TIMEOUT}\";"; \
        echo -e "Acquire::ftp::Timeout \"${CONNECT_TIMEOUT}\";"; \
    } > /etc/apt/apt.conf.d/99timeout
    { \
        echo -e "APT::Install-Recommends \"0\";"; \
        echo -e "APT::Install-Suggests \"0\";"; \
    } > /etc/apt/apt.conf.d/99norecommend
    { \
        echo -e '// One connection per host'; \
        echo -e 'Acquire::Queue-Mode "host";'; \
        echo -e 'Acquire::Retries "4";'; \
        echo -e '// Try using HTTP/1.1 connection recycling'; \
        echo -e 'Acquire::http::Pipeline-Depth "5";'; \
    } > /etc/apt/apt.conf.d/99retries
    # turn off translations, speed up apt update
    # mkdir -p /etc/apt/apt.conf.d
    echo 'Acquire::Languages "none";' > /etc/apt/apt.conf.d/99translations
}

apt_proxy_settings() {
    { \
        echo -e "Acquire::http::proxy \"${PROXY_URL}\";"; \
        echo -e "Acquire::https::proxy \"${PROXY_URL}\";"; \
        echo -e "Acquire::ftp::proxy \"${PROXY_URL}\";"; \
    } > /etc/apt/apt.conf.d/99proxy
}

# In the bowels of enterprise...
# May need to specify an alternate USER_AGENT
apt_agent_settings() {
    { \
        echo -e "Acquire::http::User-Agent \"${USER_AGENT}\";"; \
        echo -e "Acquire::https::User-Agent \"${USER_AGENT}\";"; \
    } > /etc/apt/apt.conf.d/99agent
}

setup_boot_sources() {
    { \
        echo -e "deb http://${DEB_REPO}/ ${DEB_NAME}   main  "; \
    } > /etc/apt/sources.list.d/base.list
}

# 'cause this is au ...
disable_ipv6() {
    echo 'net.ipv6.conf.all.disable_ipv6 = 1' > /etc/sysctl.d/70-disable-ipv6.conf
    echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4
}

setup_tuning() {
    # https://www.debian.org/doc/manuals/securing-debian-howto
    { \
        echo -e '# Disables the magic SysRq key'; \
        echo -e 'kernel.sysrq = 0'; \
        echo -e '# Ignore ICMP broadcasts'; \
        echo -e 'net/ipv4/icmp_echo_ignore_broadcasts = 1'; \
        echo -e '# Ignore bogus ICMP errors'; \
        echo -e 'net/ipv4/icmp_ignore_bogus_error_responses = 1'; \
    } > /etc/sysctl.d/80-harden.conf
    # This is a dev machine - crank the global file open/watch count
    # chromium uses a tonne of file handles :)
    { \
      echo 'fs.file-max = 1048576'; \
      echo 'fs.inotify.max_queued_events = 524288'; \
      echo 'fs.inotify.max_user_instances = 524288'; \
      echo 'fs.inotify.max_user_watches = 524288'; \
      # Double the fs cache pressure to 200 to reclaim dirs/inodes since
      # this is a dev box with frequently rebuilt dirs/files
      # https://www.kernel.org/doc/Documentation/sysctl/vm.txt
      echo 'vm.vfs_cache_pressure = 200'; \
      # Have a decent amount of RAM so avoid swap where we can
      echo 'vm.swappiness = 10'; \
    } > /etc/sysctl.d/81-files.conf
    { \
        echo -e '*  soft  nofile  1048576'; \
        echo -e '*  hard  nofile  1048576'; \
    } > /etc/security/limits.d/50-files.conf
    # inputrc (bash)  - $ setterm -blength 0
    { \
        echo -e 'set horizontal-scroll-mode Off'; \
        echo -e 'set bell-style none'; \
        echo -e 'set editing-mode vi'; \
        echo -e 'set keymap vi'; \
    } >> /etc/inputrc
    # silence is golden ...
    echo -e 'blacklist pcspkr' > /etc/modprobe.d/99-nobeep.conf
    # set the sound device
    { \
        echo -e "defaults.pcm.!card ${ALSA_CARD}"; \
        echo -e "defaults.ctl.!card ${ALSA_CARD}"; \
        echo -e "defaults.pcm.!device 0"; \
        echo -e "defaults.ctl.!device 0"; \
    } > /etc/asound.conf
}

init_packages() {
    # Assumes basic /etc/apt/sources.list setup:
    # deb http://deb.debian.org/debian bob main contrib
    # parted for partprobe 
    apt install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        dirmngr \
        lsb-release \
        gnupg2 \
        software-properties-common \
        gdisk \
        parted \
        seccomp \
        build-essential \
        cryptsetup-bin \
        --no-install-recommends

    if [ -f $NET_WIFI_CONF ]; then
        # wifi
        apt install -y \
            wireless-tools \
            wpasupplicant \
            --no-install-recommends
    fi
}

init_live_packages() {
    # turn off translations, speed up apt update
    # mkdir -p /etc/apt/apt.conf.d
    local APT_FILE=/etc/apt/apt.conf.d/99translations
    if [ ! -f ${APT_FILE} ]; then
        echo 'Acquire::Languages "none";' > ${APT_FILE}
    fi

    echo "setting up extra live packages ..."

    apt update
    apt -y upgrade
    apt install -y \
        curl \
        debootstrap \
        gdisk \
        parted \
        --no-install-recommends

}

zfs_service() {
    { \
        echo -e '[Unit]'; \
        echo -e 'Description=Load encryption keys'; \
        echo -e 'DefaultDependencies=no'; \
        echo -e 'After=systemd-udev-settle.service'; \
        echo -e 'After=zfs-import.target'; \
        echo -e 'After=systemd-remount-fs.service'; \
        echo -e 'Before=zfs-mount.service'; \
        echo -e ''; \
        echo -e '[Service]'; \
        echo -e 'Type=oneshot'; \
        echo -e 'RemainAfterExit=yes'; \
        echo -e "ExecStart=/usr/bin/bash -c '/usr/bin/systemd-ask-password \"zfs encrypt key: \" | /usr/sbin/zfs load-key -a'"; \
        echo -e ''; \
        echo -e '[Install]'; \
        echo -e 'WantedBy=zfs.target'; \
        echo -e ''; \
    } > /etc/systemd/system/zfs-load-key.service
    systemctl enable zfs-load-key.service
}

setup_zfs_root() {
    local ZFS_DEV=$1
    zpool create -f -o ashift=12 \
          -O atime=off -O canmount=off -O compression=lz4 \
          -O normalization=formD -O xattr=sa \
          -O dedup=off -O acltype=posixacl -O dnodesize=auto \
          $ZFS_POOL $ZFS_DEV

    zfs create -o mountpoint=/var/lib/docker -o com.sun:auto-snapshot=false   ${ZFS_POOL}/docker
    # encrypted home ...
    until zfs create -o encryption=aes-256-gcm -o keylocation=prompt -o keyformat=passphrase \
          -o mountpoint=/home ${ZFS_POOL}/home
    do
        echo "failed to set password, try again..."
    done
}

setup_vols() {
    # e.g. /dev/disk/by-id/ata-...
    local INSTALL_DEV=$1
    # Clear part table
    echo "Clearing partition table for device: ${INSTALL_DEV}"
    dd if=/dev/zero of=${INSTALL_DEV} bs=512 count=1
    sgdisk --zap-all ${INSTALL_DEV}
    # BIOS - GPT requires a BIOS boot partition
    sgdisk -a1 -n${PART_BIOS_BOOT}:24K:1000K -t${PART_BIOS_BOOT}:EF02 -c${PART_BIOS_BOOT}:${PART_BIOS_NAME} ${INSTALL_DEV}
   
    # UEFI
    sgdisk -n${PART_UEFI_BOOT}:1M:+512M -t${PART_UEFI_BOOT}:EF00 -c${PART_UEFI_BOOT}:${PART_UEFI_NAME} ${INSTALL_DEV}
    # Separate swap as ZFS has some races
    sgdisk -n${PART_SWAP}:0:+${PART_SWAP_SIZE} -t${PART_SWAP}:8200 -c${PART_SWAP}:${PART_SWAP_NAME} ${INSTALL_DEV}
    # use standard ext4 linux root
    sgdisk -n${PART_ROOT}:0:+${PART_ROOT_SIZE} -t${PART_ROOT}:8300 -c${PART_ROOT}:${PART_ROOT_NAME} ${INSTALL_DEV}
    # zfs partition
    sgdisk -n${PART_ZFS}:0:0 -t${PART_ZFS}:BF01 -c${PART_ZFS}:${PART_ZFS_NAME} ${INSTALL_DEV}
}

setup_live_install() {
    local INST_HOST=$1
    # Optional
    local INST_FQDN=$2
    local DEBOOT_CMD="debootstrap --include=curl"
    # PROXY_URL
    if [ "${PROXY_URL}" != "no" ]; then
        # Does not look like debootstrap honours proxy apt settings 
        DEBOOT_CMD="env http_proxy=${PROXY_URL} ${DEBOOT_CMD}"
    fi
    ${DEBOOT_CMD} ${DEB_NAME} /mnt
    echo "${INST_HOST}" > /mnt/etc/hostname
    echo "127.0.1.1     ${INST_FQDN} ${INST_HOST}" >> /mnt/etc/hosts
}

setup_live_chroot() {
    echo "Executing: chroot /mnt /${SCRIPT_NAME} setup_chroot "
    chroot /mnt /${SCRIPT_NAME} setup_chroot 
}

setup_live_finish() {
    # setup chroot
    mount --rbind /dev  /mnt/dev
    mount --rbind /proc  /mnt/proc
    mount --rbind /sys  /mnt/sys
    echo "Copying $0 to /mnt/"
    cp $0 /mnt/
    cp ${SCRIPT_PATH}/env_${SCRIPT_NAME} /mnt/
    setup_live_chroot
}

export_zfs() {
    # remove any fstab mounts...
    mount | grep -v zfs | tac | awk '/\/mnt/ {print $3}' | xargs -i{} umount -lf {}
    echo "export zfs pools ..."
    zpool export -a
}


setup_wired() {
    local NET_IF=$1
    { \
        echo "auto ${NET_IF}"; \
        echo "allow-hotplug ${NET_IF}"; \
        echo "iface ${NET_IF} inet dhcp"; \
    } > /mnt${NET_WIRED_CONF}
    setup_live_finish
}

init_wifi() {
    local NET_IF=$1
    local WPA_SSID="$2"
    local WPA_PASS=$3
    wpa_passphrase "$WPA_SSID" "$WPA_PASS" > /etc/wpa_supplicant.conf
    ip link set $NET_IF down
    ip link set $NET_IF up
    wpa_supplicant -B -i$NET_IF -c /etc/wpa_supplicant.conf
    dhclient $NET_IF
}

setup_wifi() {
    local NET_IF=$1
    local WPA_SSID="$2"
    local WPA_PASS=$3
    { \
    echo "auto ${NET_IF}"; \
    echo "iface ${NET_IF} inet dhcp"; \
    echo "    wpa-ssid \"${WPA_SSID}\""; \
    echo "    wpa-psk \"${WPA_PASS}\""; \
    } > /mnt${NET_WIFI_CONF}
    setup_live_finish
}

setup_live() {
    # e.g. /dev/sda
    local INSTALL_DEV="$1"
    # myhost
    INST_HOST=$2
    # Optional
    INST_FQDN=$3
    check_root_perm
    store_envs ${INSTALL_DEV}
    apt_settings
    if [ "${PROXY_URL}" != "no" ]; then
        apt_proxy_settings
    fi
    disable_ipv6
    setup_boot_sources
    init_live_packages

    echo "Setup Volumes ..."
    setup_vols ${INSTALL_DEV}
    echo "Probing new partitions ..."
    partprobe ${INSTALL_DEV}
    sleep 2
    echo "setup root filesystem..."
    mkfs.ext4 -F -L ${PART_ROOT_NAME} ${INSTALL_DEV}${PART_SUFFIX}${PART_ROOT}
    mount ${INSTALL_DEV}${PART_SUFFIX}${PART_ROOT} /mnt
    
    echo "setup live config..."
    setup_live_install ${INST_HOST} ${INST_FQDN}
    # UEFI
    if [ "${UEFI_BOOT}" != "no" ]; then
        echo "loading efivars module before chroot ..."
        modprobe efivars
    fi
    echo ""
    echo " Execute setup_wired or setup_wifi"
    echo ""
}

setup_sources() {
    { \
        echo -e "deb http://${DEB_REPO} ${DEB_NAME}          main contrib non-free"; \
        echo -e "deb http://${DEB_REPO} ${DEB_NAME}-updates  main contrib non-free"; \
        echo -e "deb http://${DEB_SEC_REPO} ${DEB_NAME}/updates  main contrib non-free"; \
    } > /etc/apt/sources.list
}

setup_sources_backports() {
    { \
        echo -e "deb http://${DEB_REPO} ${DEB_NAME}-backports  main contrib non-free"; \
    } > /etc/apt/sources.list.d/backport.list
}

setup_docker_sources() {
    # https://docs.docker.com/install/linux/docker-ce/debian/#set-up-the-repository
    ${CURL_CMD} https://download.docker.com/linux/debian/gpg | gpg --dearmor > /etc/apt/trusted.gpg.d/docker.gpg
    echo "deb [arch=amd64] https://download.docker.com/linux/debian ${DEB_NAME} stable" > /etc/apt/sources.list.d/docker.list
    # Add "edge" after "stable" if necessary
}

base_packages() {
    apt install -y \
        apt-transport-https \
        ca-certificates \
        lsb-release \
        adduser \
        bash-completion \
        coreutils \
        dnsutils \
        file \
        git \
        subversion \
        rsync \
        gnupg \
        gnupg-agent \
        grep \
        gzip \
        hostname \
        indent \
        iptables \
        less \
        locales \
        lsof \
        iotop \
        mount \
        net-tools \
        bzip2 \
        unzip \
        xz-utils \
        build-essential \
        git-buildpackage \
        gcc-multilib \
        wget \
        libncurses5-dev \
        pinentry-curses \
        openssh-client \
        keychain \
        strace \
        sudo \
        tar \
        tree \
        tzdata \
        zip \
        pciutils \
        usbutils \
        gdisk \
        cpufrequtils \
        pm-utils \
        perf-tools-unstable \
        cmake \
        libnss3-tools \
        vim-tiny \
        nmap \
        dpkg-dev \
        rfkill \
        --no-install-recommends

    # systemd interactions
    apt install -y \
        dbus-user-session \
        --no-install-recommends

    apt autoremove
    apt autoclean
    apt clean
}


base_services() {
    echo "configure base services..."
    # disable sshd by default
    #  systemctl disable ssh.service
    # nano is still lurking around ...
    update-alternatives --install /usr/bin/editor editor "$(which vim.tiny)" 60
    # don't use the timesync daemon by default
    timedatectl set-ntp false
    # remove those other ttys, just need the one
    append_file_with_line /etc/systemd/logind.conf "NAutoVTs=1"
    append_file_with_line /etc/systemd/logind.conf "ReserveVT=1"
}

#  https://www.chromium.org/administrators/policy-list-3
#  https://www.chromium.org/administrators/linux-quick-start
chromium_policy() {
    echo "installing chromium policy ..."
    local POL_DIR=/etc/chromium/policies/managed
    mkdir -p ${POL_DIR}
    { \
        echo -e '{'; \
        echo -e '"EnableMediaRouter": false, '; \
        echo -e '"BrowserSignin": 0, '; \
        echo -e '"NetworkPredictionOptions": 2 ,'; \
        echo -e '"PasswordManagerEnabled" : false , '; \
        echo -e '"SyncDisabled": true, '; \
        echo -e '"BackgroundModeEnabled": false, '; \
        echo -e '"DefaultCookiesSetting": 4, '; \
        echo -e '"DefaultGeolocationSetting": 3, '; \
        echo -e '"DefaultWebUsbGuardSetting": 2, '; \
        echo -e '"SpellcheckEnabled": false, '; \
        echo -e '"TranslateEnabled": false, '; \
        echo -e '"CloudPrintProxyEnabled": false, '; \
        echo -e '"CloudPrintSubmitEnabled": false, '; \
        echo -e '"BrowserNetworkTimeQueriesEnabled": false, '; \
        echo -e '"PromotionalTabsEnabled": false, '; \
        echo -e '"BuiltInDnsClientEnabled": false, '; \
        echo -e '"DefaultBrowserSettingEnabled": false, '; \
        echo -e '"DeveloperToolsAvailability": 1, '; \
        echo -e '"DefaultSearchProviderEnabled": true, '; \
        echo -e '"DefaultSearchProviderName": "DuckDuckGo", '; \
        echo -e '"DefaultSearchProviderKeyword": "ddg", '; \
        echo -e '"DefaultSearchProviderIconURL": "https://duckduckgo.com/favicon.ico", '; \
        echo -e '"DefaultSearchProviderSearchURL": "https://duckduckgo.com/?q=%s" '; \
        echo -e '}'; \
    } > ${POL_DIR}/my_policy.json
    # Some cloude services require third party cookies
    #   echo -e '"BlockThirdPartyCookies": true, '; \
    # Interesting flags:
    #  AuthServerWhiteList   - IWA
}

desktop_packages() {
    apt update;
    apt -y upgrade;
    apt install -y \
        xorg \
        xserver-xorg-input-evdev \
        xserver-xorg-input-libinput \
        xserver-xorg-input-mouse \
        xorg-dev \
        xfonts-base \
        xfonts-terminus \
        xfonts-mplus \
        xbindkeys \
        xclip \
        xsel \
        ssh-askpass \
        xterm \
        ttf-bitstream-vera \
        fonts-hack \
        fonts-dejavu-core \
        fonts-dejavu-extra \
        fonts-roboto \
        fonts-firacode \
        adwaita-icon-theme \
        moka-icon-theme \
        arc-theme \
        alsa-utils \
        jackd1 \
        feh \
        webp \
        neovim \
        emacs-gtk \
        xarchiver \
        suckless-tools \
        xautolock \
        gtk2-engines-murrine \
        scrot \
        rxvt-unicode \
        sassc \
        optipng \
        inkscape \
        xpdf \
        qemu \
        chromium \
        chromium-ublock-origin \
        chromium-sandbox \
        fonts-stix \
        fonts-lmodern \
        libxcb1-dev \
        dbus-x11 \
        gnome-keyring \
        libpam-gnome-keyring \
        gnome-keyring-pkcs11 \
        eject \
        --no-install-recommends

    # xdm  - if you are feeling brave, 
    # but I like to startx until all is well...

    apt autoremove
    apt autoclean
    apt clean
}

clickpad_config() {
    mkdir -p /etc/X11/xorg.conf.d
    { \
        echo 'Section "InputClass"'; \
        echo '  Identifier "synatpics-setup"'; \
        echo '  MatchIsTouchpad "on"'; \
        echo '  MatchDriver "libinput"'; \
        echo '  Option "Tapping" "off"'; \
        echo '  Option "NaturalScrolling" "true"'; \
        echo '  # AccelSpeed -1.0 to 1.0'; \
        echo '  Option "AccelSpeed" "0.7"'; \
        echo '  Option "DisableWhileTyping" "true"'; \
        echo 'EndSection'; \
    } > /etc/X11/xorg.conf.d/40-libinput.conf
    # Prevent suspend...
    append_file_with_line /etc/systemd/logind.conf "HandleLidSwitch=lock"
}

# https://wiki.debian.org/InstallingDebianOn/Thinkpad/T420/jessie
# https://wiki.debian.org/InstallingDebianOn/Thinkpad/T440p/jessie
# dock:
# https://support.lenovo.com/us/en/solutions/ACC100315
# thinkpad basic dock usb 3.0
# https://wiki.archlinux.org/index.php/DisplayLink
# https://github.com/AdnanHodzic/displaylink-debian
# https://wiki.archlinux.org/index.php/Backlight
laptop_packages() {

    # laptop-mode-tools uses qt4 libs
    apt install -y \
        acpid \
        acpi-support-base \
        laptop-mode-tools \
        guvcview \
        --no-install-recommends

    apt autoremove
    apt autoclean
    apt clean
}

laptop_setup() {
    laptop_packages
    clickpad_config
}

desktop_config() {
    mkdir -p /etc/X11/xorg.conf.d
    { \
        echo 'Section "ServerFlags"'; \
        echo '  # Do not allow Ctl-Alt-Fn switching"'; \
        echo '  Option "DontVTSwitch" "True"'; \
        echo '  # Do not allow Ctl-Alt-Backsp logout"'; \
        echo '  Option "DontZap" "True"'; \
        echo 'EndSection'; \
    } > /etc/X11/xorg.conf.d/99-harden.conf
    # limit chrome just a little
    chromium_policy
    echo "Some suggested hardening..."
    echo "systemctl disable avahi-daemon.socket"
    echo "systemctl disable avahi-daemon.service"
    echo "/etc/avahi/avahi-daemon.conf : "
    echo "use-ipv4=no"
    echo "use-ipv6=no"
    echo "systemctl disable ModemManager.service"

} 

common_desktop_packages() {
    apt install -y \
        libassimp-dev \
        --no-install-recommends
    # https://wiki.archlinux.org/index.php/Xfce
    apt install -y \
        xfce4 \
        thunar-volman \
        thunar-vcs-plugin \
        policykit-1-gnome \
        gvfs \
        gvfs-backends \
        gvfs-fuse \
        xfce4-notifyd \
        xfce4-goodies \
        xfce4-terminal \
        desktop-base \
        tango-icon-theme \
        system-config-printer \
        parole \
        gstreamer1.0-plugins-bad \
        gstreamer1.0-plugins-ugly \
        orage \
        --no-install-recommends

    # themes ... stay frosty ...
    ${CURL_CMD} -o /usr/share/xfce4/terminal/colorschemes/nord.theme \
        https://raw.githubusercontent.com/arcticicestudio/nord-xfce-terminal/develop/src/nord.theme
    (
        cd /usr/share/themes
        ${CURL_CMD} https://github.com/EliverLara/Nordic/releases/download/v1.6.5/Nordic.tar.xz | tar xvJf -
    )
}

#  -vga std
qemu_desktop_packages() {
    apt install -y \
        xserver-xorg-video-fbdev \
        --no-install-recommends
    desktop_packages
}

# https://wiki.gentoo.org/wiki/Intel
# https://wiki.archlinux.org/index.php/Intel_graphics
intel_desktop_packages() {
    dpkg --add-architecture i386
    # Use modesetting driver rather than the xserver-xorg-video-intel
    apt install -y \
        xserver-xorg-video-dummy \
        --no-install-recommends
    desktop_packages
    apt install -y \
        intel-microcode \
        --no-install-recommends
    apt install -y \
        libwayland-egl1 \
        libgl1-mesa-{dri,glx} \
        libgl1-mesa-dev \
        libegl1-mesa \
        libegl1-mesa-dev \
        libglu1-mesa-dev \
        libglapi-mesa \
        libgles2-mesa \
        libvulkan-dev \
        libwayland-dev \
        mesa-vulkan-drivers \
        vulkan-tools \
        --no-install-recommends
    # following should drag in libxcb-dri3
    # libdrm-intel1 should be included with libgl1-mesa-dri
    # Use the modestting xorg driver rather than xserver-xorg-video-intel
    apt  install -y \
        mesa-utils \
        mesa-utils-extra \
        libglfw3-dev \
        i965-va-driver \
        libvdpau-va-gl1 \
        vainfo \
        xbacklight \
        --no-install-recommends
    # allow use of xbacklight
    # brightness-udev
    mkdir -p /etc/X11/xorg.conf.d
    { \
        echo 'Section "Device"'; \
        echo '  Identifier  "intel-graphics"'; \
        echo '  Driver      "modesetting"'; \
        echo '  Option      "AccelMethod"  "glamor"'; \
        echo '  Option      "DRI"  "3"'; \
        echo '  # Option        "PageFlip"  "true"'; \
        echo 'EndSection'; \
    } > /etc/X11/xorg.conf.d/20-modesetting.conf
    # list all options: /sbin/modinfo -p i915
    # Reduce GPU usage
    echo 'options i915 i915_enable_rc6=7 i915_enable_fbc=1 lvds_downclock=1' > /etc/modprobe.d/i915.conf
}

intel_setup() {
    check_root_perm 
    source_envs
    intel_desktop_packages
    common_desktop_packages
    desktop_config
}

# $ apt install nvidia-detect 
# $ nvidia-detect
# Install the deb packages. Or alternately ...
#  https://download.nvidia.com/XFree86/Linux-x86_64/
# sh ./NVIDIA-Linux-x86_64-435.17.run -s \
#    --module-signing-secret-key=/path/to/signing.key \
#    --module-signing-public-key=/path/to/signing.x509 \
# --ui=none
# echo blacklist nouveau > /etc/modprobe.d/blacklist-nvidia-nouveau.conf
nvidia_desktop_packages() {
    dpkg --add-architecture i386
    apt install -y \
        nvidia-kernel-dkms \
        --no-install-recommends
    desktop_packages
    apt install -y \
        nvidia-driver-libs \
        libglx-nvidia0 \
        libgles-nvidia1 \
        libgles-nvidia2 \
        libopengl0 \
        libnvidia-cfg1 \
        nvidia-driver-libs-i386 \
        nvidia-vulkan-icd \
        --no-install-recommends
    apt install -y \
        nvidia-driver \
        nvidia-settings \
        vulkan-tools \
        --no-install-recommends
    # test with vulkaninfo | less
    # 
    # If multiple drivers installed, select with:
    # $ update-glx --config nvidia
    mkdir -p /etc/X11/xorg.conf.d
    { \
        echo 'Section "Device"'; \
        echo '  Identifier "Nvidia GPU"'; \
        echo '  Driver "nvidia"'; \
        echo 'EndSection'; \
    } > /etc/X11/xorg.conf.d/20-nvidia.conf
}

nvidia_setup() {
    check_root_perm 
    source_envs
    nvidia_desktop_packages
    common_desktop_packages
    desktop_config
}

# run this script as a qemu guest for testing
qemu_setup() {
    check_root_perm 
    source_envs
    qemu_desktop_packages
    common_desktop_packages
    desktop_config
}

office_setup() {
    check_root_perm 
    apt install -y \
        cifs-utils \
        libreoffice \
        remmina \
        remmina-plugin-rdp \
        --no-install-recommends
}

llvm_setup() {
    # LLVM 7 basics ...
    apt install -y \
        llvm-7 lldb-7 clang-7 \
        --no-install-recommends
}

dev_setup() {
    check_root_perm 
    source_envs
    apt update
    llvm_setup
    # android tools
    apt install -y \
        adb \
        fastboot \
        --no-install-recommends
    apt install -y \
        git \
        autoconf \
        libtool \
        libtool-bin \
        make \
        pkg-config \
        automake \
        build-essential \
        gettext \
        cmake \
        python \
        --no-install-recommends

    apt autoremove
    apt autoclean
    apt clean
}

docker_proxy() {
    mkdir -p /etc/systemd/system/docker.service.d
    { \
        echo -e "[Service]"; \
        echo -n -e "Environment=\"HTTP_PROXY=${PROXY_URL}\""; \
        echo -n -e " \"HTTPS_PROXY=${PROXY_URL}\""; \
        echo -e " \"NO_PROXY=localhost,127.0.0.1\""; \
    } > /etc/systemd/system/docker.service.d/http-proxy.conf
}

docker_setup() {
    check_root_perm 
    source_envs
    setup_docker_sources
    apt update
    mkdir -p /etc/docker
    chmod 0700 /etc/docker
    # use zfs rather than overlay2
    { \
        echo -e '{'; \
        echo -e '  "data-root": "/var/lib/docker", '; \
        echo -e '  "storage-driver": "zfs", '; \
        echo -e '  "storage-opts": [ '; \
        echo -e "     \"zfs.fsname=${ZFS_POOL}/docker\"  "; \
        echo -e '   ],  '; \
        echo -e '  "ipv6": false '; \
        echo -e '}'; \
    } > /etc/docker/daemon.json
    apt install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        --no-install-recommends
    if [ "${PROXY_URL}" != "no" ]; then
        systemctl stop docker
        docker_proxy
        echo "Restarting docker for proxy settings"
        systemctl daemon-reload
        systemctl start docker
        systemctl show --property=Environment docker
    fi
    echo ""
    echo " To update users:"
    echo "   $ usermod -a -G docker user"
    echo ""
    echo " Test with:"
    echo "   $ docker run hello-world"
    echo ""
}

dkms_sign_scripts() {
    # An issue with dkms means $kernelver an $arch are not exported to the script
    # Pass them as explicit params for now
    { \
        echo -e '#!/bin/bash'; \
        echo -e 'KERN_VERS=${kernelver:-$1}'; \
        echo -e 'KERN_ARCH=${arch:-$2}'; \
        echo -e 'cd ../$KERN_VERS/$KERN_ARCH/module/'; \
        echo -e 'for kernel_object in *.ko'; \
        echo -e 'do'; \
        echo -e '    echo "Signing kernel_object: $kernel_object"'; \
        echo -e '    /usr/src/linux-headers-$KERN_VERS/scripts/sign-file sha256 /root/MOK.priv /root/MOK.der "$kernel_object";'; \
        echo -e 'done'; \
        echo -e ''; \
    } > /root/sign-kernel.sh
    chmod +x /root/sign-kernel.sh
    echo -e 'POST_BUILD="../../../../../../root/sign-kernel.sh $kernelver $arch"' > /etc/dkms/sign-kernel-objects.conf
    ln -sf /etc/dkms/sign-kernel-objects.conf /etc/dkms/zfs.conf
    ln -sf /etc/dkms/sign-kernel-objects.conf /etc/dkms/nvidia.conf
}

dkms_sign() {
    apt install openssl mokutil
    # to clear any previous MOKs ...
    # $ mokutil --reset
    # then reboot
    (
      cd /root
      echo "generating MOK ..."
      openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=Deb Machine Owner Key/"
      echo "importing MOK, one time password for reboot will be prompted..."
      mokutil --import MOK.der
    )
    dkms_sign_scripts
}

setup_zfs_sources() {
    { \
        echo -e "deb-src http://${DEB_REPO} ${DEB_ZFS_SRC_NAME}          main contrib"; \
    } > /etc/apt/sources.list.d/zfssrc.list
}

zfs_build_sources() {
    setup_zfs_sources
    apt update
    # https://github.com/zfsonlinux/zfs/wiki/Building-ZFS
    apt install -y build-essential autoconf automake libtool gawk alien fakeroot ksh
    apt install -y zlib1g-dev uuid-dev libattr1-dev libblkid-dev libselinux-dev libudev-dev
    apt install -y libacl1-dev libaio-dev libdevmapper-dev libssl-dev libelf-dev
    apt install -y python3 python3-all-dev python3-setuptools python3-cffi python3-sphinx
    mkdir -p /usr/src/zfs
    cd /usr/src/zfs
    # build the packages without the dbgsyms
    DEB_BUILD_OPTIONS=noddebs apt --build source zfs-linux
    dpkg -i zfs-dkms_*_all.deb
    echo "loading zfs module ..."
    /sbin/modprobe zfs
    for i in libnvpair1linux libuutil1linux libzfs2linux libzpool2linux libzfslinux-dev zfsutils-linux zfs-zed ; do
        dpkg -i ${i}_*_amd64.deb
    done
}


zfs_init() {
    # This is a workstation/laptop so cap the zfs arc
    # the default arc limit should be half RAM
    { \
        echo -e '# /etc/modprobe.d/zfs.conf'; \
        echo -e '# Limit arc to 4GB'; \
        echo -e 'options zfs zfs_arc_max=4294967296'; \
        # avoid burstiness for some general overhead
        # prefetch good for spinners not so necessary for SSD
        echo -e 'options zfs zfs_prefetch_disable=1'; \
        echo -e 'options zfs zfs_txg_timeout=10'; \
    } > /etc/modprobe.d/zfs.conf
    zfs_build_sources
    #apt install -y -t ${DEB_NAME}-backports zfs-dkms zfsutils-linux zfs-zed
    #echo "loading zfs module ..."
    #/sbin/modprobe zfs
    # Resume from hibernate is not currently supported by ZFS
    echo RESUME=none > /etc/initramfs-tools/conf.d/nozfsresume
    # zfs maintenance
    { \
        echo -e '#!/bin/sh'; \
        echo -e "/sbin/zpool scrub ${ZFS_POOL}"; \
    } > /etc/cron.weekly/zfsscrub
}

db_dataset_setup() {
    check_root_perm
    # https://people.freebsd.org/~seanc/postgresql/scale15x-2017-postgresql_zfs_best_practices.pdf
    if [ -d ${ZFS_DB_HOME} ]; then
        echo "Root DB dataset: ${ZFS_DB_HOME} already exits"
    else
        echo "Creating root DB Dataset: ${ZFS_DB_HOME}"
        zfs create -o mountpoint=${ZFS_DB_HOME} ${ZFS_POOL}${ZFS_DB_HOME}
        zfs set atime=off ${ZFS_POOL}${ZFS_DB_HOME}
        zfs set dedup=off ${ZFS_POOL}${ZFS_DB_HOME}
        zfs set compression=lz4 ${ZFS_POOL}${ZFS_DB_HOME}
        # Following suggest not to put 128k pages sizes down to 8k
        # https://blog.2ndquadrant.com/pg-phriday-postgres-zfs/
        zfs set recordsize=16K ${ZFS_POOL}${ZFS_DB_HOME}
        # primarycache=all if datasets do not fit in memory
        # zfs arc only cache metadata
        zfs set primarycache=metadata ${ZFS_POOL}${ZFS_DB_HOME}
        # Avoid the ZIL (intent log) since DB have own tran logs
        zfs set logbias=throughput ${ZFS_POOL}${ZFS_DB_HOME}
        # Put a limit on the db store
        #zfs set quota=128G ${ZFS_POOL}${ZFS_DB_HOME}
        # Sacrifice some redundancy for less i/o
        # typically mirroring storage so should be a good trade-off
        zfs set redundant_metadata=most ${ZFS_POOL}${ZFS_DB_HOME}
    fi
}

db_vol_setup() {
    local VOL_NAME=$1 
    check_root_perm
    db_dataset_setup
    if [ -d  ${ZFS_DB_HOME}/${VOL_NAME} ]; then
        echo "Volume ${ZFS_DB_HOME}/${VOL_NAME} already exists"
    else
        echo "Creating volume ${ZFS_DB_HOME}/${VOL_NAME}"
        # setup the default db instance 
        zfs create ${ZFS_POOL}${ZFS_DB_HOME}/${VOL_NAME}
    fi
}

# Building large source projects
# Fast and loose ...
scratch_dataset_setup() {
    check_root_perm
    if [ -d  ${ZFS_SCRATCH_HOME} ]; then
        echo "Dataset ${ZFS_SCRATCH_HOME} already exists"
    else
        echo "Creating dataset ${ZFS_SCRATCH_HOME}"
        zfs create -o mountpoint=${ZFS_SCRATCH_HOME} ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set atime=off ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set dedup=off ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set compression=off ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set recordsize=8K ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        # ensure consistency in the scratch space and always sync
        # zfs set sync=always ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set sync=disabled ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        # zfs set sync=standard ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set logbias=throughput ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        # zfs set primarycache=metadata ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set primarycache=all ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set com.sun:auto-snapshot=false ${ZFS_POOL}${ZFS_SCRATCH_HOME}
        zfs set xattr=sa ${ZFS_POOL}${ZFS_SCRATCH_HOME}
    fi
}

scratch_vol_setup() {
    local VOL_NAME=$1
    check_root_perm
    scratch_dataset_setup
    if [ -d  ${ZFS_SCRATCH_HOME}/${VOL_NAME} ]; then
        echo "Volume ${ZFS_SCRATCH_HOME}/${VOL_NAME} already exists"
    else
        echo "Creating volume ${ZFS_SCRATCH_HOME}/${VOL_NAME}"
        zfs create ${ZFS_POOL}${ZFS_SCRATCH_HOME}/${VOL_NAME}
    fi
}

config_grub() {
    mkdir -p /etc/default/grub.d
    # _DEFAULT entries are enabled for normal boot and not recovery
    echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=0"' > /etc/default/grub.d/apparmor.cfg
    # qemu vga passthrough ...
    # echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT intel_iommu=on"' > /etc/default/grub.d/intel_iommu.cfg
    # panic=0  disallow initramfs dropping to a shell at boot
    echo 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX panic=0"' > /etc/default/grub.d/panic.cfg
    # zfs does not support hibernation yet
    echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT noresume"' > /etc/default/grub.d/resume.cfg
}

chroot_install_post() {
    local INSTALL_DEV=$1
    if [ "${UEFI_BOOT}" != "no" ]; then
        mkdosfs -F 32 -s 1 -n EFI ${INSTALL_DEV}${PART_SUFFIX}${PART_UEFI_BOOT}
        # UEFI
        mkdir /boot/efi
        echo ${INSTALL_DEV}${PART_SUFFIX}${PART_UEFI_BOOT} \
            /boot/efi vfat defaults  0  2 >> /etc/fstab
        mount /boot/efi
        # apt install --yes grub-efi-amd64 shim
        apt install --yes grub-efi-amd64-signed shim-signed
        apt install --yes efibootmgr efivar
    else
        # MBR style
        apt install --yes grub-pc
    fi
    echo "Peform GRUB install ..."
    echo " grub-probe /"
    grub-probe /
    # refresh initrd
    update-initramfs -u -k all

    config_grub

    # Update any changes to /etc/default/grub or /etc/grub.d/
    # update-grub should do: grub-mkconfig -o /boot/grub/grub.cfg
    mkdir -p /boot/grub
    update-grub
    if [ "${UEFI_BOOT}" != "no" ]; then
        # UEFI
        grub-install --target=x86_64-efi --efi-directory=/boot/efi \
           --bootloader-id=debian --recheck --no-floppy --force
        umount /boot/efi
    else
        # MBR style
        grub-install ${INSTALL_DEV}
    fi

    echo ""
    echo "Setting the root password ..."
    until passwd
    do
        echo "failed to set password, try again..."
    done

    echo ""
    echo "Reboot and run $0 first_boot "
    echo ""
}


setup_chroot_common() {
    check_root_perm
    source_envs
    apt_settings
    if [ "${PROXY_URL}" != "no" ]; then
        apt_proxy_settings
    fi
    check_repo_connection 
    setup_sources
    apt update
    apt -y upgrade
    disable_ipv6
    init_packages
    apt_harden

    local MTAB_FILE=/etc/mstab
    if [ ! -f ${MTAB_FILE} ]; then
        ln -s /proc/self/mounts ${MTAB_FILE}
    fi

    if [ "${RT_ENABLE}" != "no" ]; then
        # audio rt kernels
        apt install -y linux-headers-rt-amd64 linux-image-rt-amd64
    else
        # standard kernels
        apt install -y linux-headers-amd64 linux-image-amd64
    fi 
    apt install -y dkms locales tzdata kbd
    # load all the likely firmware for a clean first up boot ...
    apt install -y firmware-linux firmware-atheros \
        firmware-iwlwifi firmware-brcm80211 firmware-realtek \
        firmware-intel-sound midisport-firmware
    apt install -y debconf file libc6-dev \
        keyutils dosfstools
}

setup_default_locale() {
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
    dpkg-reconfigure --frontend=noninteractive locales
    update-locale LANG=en_US.UTF-8
}

setup_chroot() {
    setup_chroot_common
    setup_default_locale
    setup_tuning
    echo ${TGT_INST_DEV}${PART_SUFFIX}${PART_ROOT} \
	    /  ext4   defaults,noatime  0  1 >> /etc/fstab
    # Always encrypt swap
    echo cryptswap \
         ${TGT_INST_DEV}${PART_SUFFIX}${PART_SWAP} /dev/urandom \
         swap,cipher=aes-xts-plain64:sha256,size=256 >> /etc/crypttab
    echo /dev/mapper/cryptswap  none  swap  defaults  0  0 >> /etc/fstab
    
    chroot_install_post ${TGT_INST_DEV}
}

setup_sudo() {
    local TARGET_USER=$1
    { \
        echo -e 'Defaults   env_keep += "ftp_proxy http_proxy https_proxy no_proxy EDITOR"'; \
    } > /etc/sudoers.d/proxyenv
    { \
        echo -e "# Uncomment the following for no passwords at all "; \
        echo -e "# ${TARGET_USER} ALL=(ALL) NOPASSWD:ALL"; \
        echo -e "${TARGET_USER} ALL=NOPASSWD: /sbin/shutdown, /sbin/ifconfig, /sbin/ifup, /sbin/ifdown, /sbin/ifquery, /usr/bin/mount, /usr/bin/umount"; \
    } > /etc/sudoers.d/usr${TARGET_USER}
}

setup_user() {
    local TARGET_USER=$1
    local USER_PREF=/home
    # Setup default user - base_packages should install sudo
    zfs create  ${ZFS_POOL}${USER_PREF}/${TARGET_USER}
    until adduser --gecos "" --home ${USER_PREF}/${TARGET_USER} ${TARGET_USER}
    do
        "failed to add the user ${TARGET_USER}, try again..."
    done
    cp -a /etc/skel/.[!.]* ${USER_PREF}/${TARGET_USER}
    { \
        echo "HISTCONTROL=ignoreboth"; \
        echo "HISTSIZE=1000"; \
        echo "HISTFILESIZE=2000"; \
        echo "PS1='[\u:\W]\$ '"; \
    } > ${USER_PREF}/${TARGET_USER}/.bashrc

    # Let startx work off the bat ...
    { \
        echo -e '#!/bin/sh'; \
        echo -e '# .xsession'; \
        echo -e '# setxkbmap -option caps:escape'; \
        echo -e 'setxkbmap -option ctrl:nocaps'; \
        echo -e 'exec startxfce4'; \
    } > ${USER_PREF}/${TARGET_USER}/.xsession
    # appears to need to be exec to use startx ...
    chmod +x ${USER_PREF}/${TARGET_USER}/.xsession
    chown -R ${TARGET_USER}:${TARGET_USER} ${USER_PREF}/${TARGET_USER}
    usermod -a -G audio,cdrom,dip,floppy,netdev,plugdev,sudo,video ${TARGET_USER}
    setup_sudo ${TARGET_USER}
}

first_boot() {
    check_root_perm 
    source_envs
    # Install all the things...
    apt update
    apt dist-upgrade --yes
    # apt -y upgrade;
    base_packages
    base_services

    echo "initializing ZFS ..."
    zfs_init
    echo "setup zfs password systemd"
    zfs_service
    setup_zfs_root ${TGT_INST_DEV}${PART_SUFFIX}${PART_ZFS}
    
    echo ""
    echo "Run: "
    echo ""
    echo "  $ dpkg-reconfigure locales && dpkg-reconfigure tzdata"
    echo ""
    echo "   (select en_US.UTF-8 and anything else)"
    echo ""
}

usage() {
    echo ""
    echo -e "${SCRIPT_NAME} \\nThis script does setup for debian\\n"
    echo ""
    echo " Use Debian live xfce : user/live"
    echo "   $ sudo -s "
    echo ""
    echo "  https://www.debian.org/CD/live/"
    echo "     including the non-free firmware for some laptops/desktops..."
    echo "  https://cdimage.debian.org/images/unofficial/non-free/images-including-firmware/"
    echo ""
    echo "ENVs:"
    echo " PROXY_URL  : e.g. http://proxy.company.com:80/"
    echo " UEFI_BOOT  : a value other than \"no\" will install EFI"
    echo " ALSA_CARD  : the card number $ aplay -l "
    echo ""
    echo "Parameters:"
    echo "INSTALL_DEV: target install device ( $ lsblk )"
    echo "   e.g. /dev/disk/by-id/... , /dev/vda"
    echo "  To identify disks:"
    echo "    # ls /dev/disk/by-id/"
    echo "    # sgdisk -p /dev/disk/by-id/..."
    echo "  To remove partition:"
    echo "    # sgdisk -d <part_num> /dev/disk/by-id/..."
    echo "INST_HOST: your new hostname"
    echo "INST_FQDN: optional fully qualified domain name"
    echo "NET_IF: primary net interface e.g. eth0  ( $ ip addr ) "
    echo ""
    echo "Usage:"
    echo "  intel_setup"
    echo "        - intel desktop"
    echo "  nvidia_setup"
    echo "        - nvidia desktop"
    echo "  qemu_setup"
    echo "        - qemu desktop for testing"
    echo "  docker_setup"
    echo "        - docker daemon"
    echo "  office_setup"
    echo "        - office apps, libreoffice etc"
    echo "  dev_setup"
    echo "        - llvm toolchain etc"
    echo "  db_vol_setup <VOL_NAME>"
    echo "        -  create DB(postgres) style dataset under /db/<VOL_NAME>"
    echo "  scratch_vol_setup <VOL_NAME>"
    echo "        -  create scratch style dataset under /scratch/<VOL_NAME>"
    echo "  setup_user <USER>"
    echo "        - setup default user"
    echo "  dkms_sign"
    echo "        - SecureBoot support for modules like nvidia and zfs"
    echo "  first_boot"
    echo "        - first install boot"
    echo "  setup_wired <NET_IF>"
    echo "        - configure networking"
    echo "  setup_wifi <NET_IF> <WPA_SSID> <WPA_PWD>"
    echo "        - configure wifi networking for install"
    echo "  init_wifi <NET_IF> <WPA_SSID> <WPA_PWD>"
    echo "        - configure wifi for live boot"
    echo "  setup_live <INSTALL_DEV> <INST_HOST> [<INST_FQDN>]"
    echo "        - first step setup from the live image"
    echo "        - ENV: PROXY_URL, UEFI_BOOT, ALSA_CARD"
    echo ""
    echo "Run setup_live first."
    echo ""
}

main() {
    local cmd=$1

    if [[ -z "$cmd" ]]; then
        usage
        exit 1
    fi

    if [[ $cmd == "setup_live" ]]; then
        setup_live "$2" $3 $4
    elif [[ $cmd == "setup_wired" ]]; then
        setup_wired $2
    elif [[ $cmd == "setup_chroot" ]]; then
        setup_chroot
    elif [[ $cmd == "setup_wifi" ]]; then
        setup_wifi $2 "$3" "$4"
    elif [[ $cmd == "init_wifi" ]]; then
        init_wifi $2 "$3" "$4"
    elif [[ $cmd == "first_boot" ]]; then
        first_boot
    elif [[ $cmd == "dkms_sign" ]]; then
        dkms_sign
    elif [[ $cmd == "setup_user" ]]; then
        setup_user $2
    elif [[ $cmd == "nvidia_setup" ]]; then
       nvidia_setup
    elif [[ $cmd == "intel_setup" ]]; then
       intel_setup
    elif [[ $cmd == "qemu_setup" ]]; then
        qemu_setup
    elif [[ $cmd == "docker_setup" ]]; then
        docker_setup
    elif [[ $cmd == "office_setup" ]]; then
        office_setup
    elif [[ $cmd == "dev_setup" ]]; then
        dev_setup
    elif [[ $cmd == "db_vol_setup" ]]; then
        db_vol_setup $2
    elif [[ $cmd == "scratch_vol_setup" ]]; then
        scratch_vol_setup $2
    else
        usage
    fi
}

main "$@"

