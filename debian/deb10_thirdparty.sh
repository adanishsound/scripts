#!/bin/bash
# 
# deb10_thirdparty.sh
#
set -e

# Proxy e.g. http://user:password@proxy.company.com:80/
PROXY_URL=${PROXY_URL:-no}

# Connection timeout in seconds
CONNECT_TIMEOUT=180

# deb release details
DEB_NAME="buster"
DEB_VERS_MAJOR=10

SCRIPT_NAME=$(basename $0)

DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

# Directory for package caches for things like node and nuget
# ... a shed-load of rubbish ...
SCRATCH_HOME=/scratch

# Can use --user-agent to disown curl ...
CURL_CMD="curl -fsSL --connect-timeout ${CONNECT_TIMEOUT}"
if [ "${PROXY_URL}" != "no" ]; then
    CURL_CMD="${CURL_CMD} --proxy ${PROXY_URL}"
fi

check_root_perm() {
    if [ "$EUID" -ne 0 ]; then
        echo "Run as root."
        exit
    fi
}

scratch_dir_setup() {
    local DIR_NAME=$1
    check_root_perm
    if [ -d  ${SCRATCH_HOME}/${DIR_NAME} ]; then
        echo "Scratch directory ${SCRATCH_HOME}/${DIR_NAME} already exists"
    else
        echo "Creating scratch directory ${SCRATCH_HOME}/${DIR_NAME}"
        mkdir -p ${SCRATCH_HOME}/${DIR_NAME}
    fi
}


append_file_with_line() {
    local FILEPATH=$1
    local LINESTRING=$2
    grep -x "${LINESTRING}" ${FILEPATH} > /dev/null || echo "${LINESTRING}" >> ${FILEPATH}
}

init_https_packages() {
    apt update
    apt install -y \
        ca-certificates \
        software-properties-common \
        apt-transport-https \
        curl \
        gnupg \
        --no-install-recommends
}

setup_docker_sources() {
    # https://docs.docker.com/install/linux/docker-ce/debian/#set-up-the-repository
    ${CURL_CMD} https://download.docker.com/linux/debian/gpg | gpg --dearmor > /etc/apt/trusted.gpg.d/docker.gpg
    echo "deb [arch=amd64] https://download.docker.com/linux/debian ${DEB_NAME} stable" > /etc/apt/sources.list.d/docker.list
    # Add "edge" after "stable" if necessary
}

setup_ms_key() {
    ${CURL_CMD} https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/microsoft.gpg
}

setup_dotnet_sources() {
    setup_ms_key
    # dotnet core ...
    ${CURL_CMD} https://packages.microsoft.com/config/debian/${DEB_VERS_MAJOR}/prod.list > /etc/apt/sources.list.d/dotnet.list
}

setup_code_sources() {
    setup_ms_key
    # vscode
    echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list
}

setup_azure_cli_sources() {
    setup_ms_key
    # azure cli
    echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli ${DEB_NAME} main" > /etc/apt/sources.list.d/azurecli.list
}


setup_teams_sources() {
    setup_ms_key
    #${CURL_CMD} https://packages.microsoft.com/keys/msopentech.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/msopentech.gpg
    # teams
    echo "deb [arch=amd64] https://packages.microsoft.com/repos/ms-teams stable main" > /etc/apt/sources.list.d/teams.list
}

setup_mono_sources() {
    ${CURL_CMD} "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF" | gpg --dearmor > /etc/apt/trusted.gpg.d/mono.gpg
    echo "deb https://download.mono-project.com/repo/debian stable-${DEB_NAME} main" > /etc/apt/sources.list.d/mono-official-stable.list
}

setup_azul_sources() {
    ${CURL_CMD} "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB1998361219BD9C9" | gpg --dearmor > /etc/apt/trusted.gpg.d/azul.gpg
    echo "deb http://repos.azulsystems.com/debian stable main" > /etc/apt/sources.list.d/azul-stable.list
}

setup_nodejs_sources() {
    echo "Setup node sources ..."
    local VERS=node_12.x
    ${CURL_CMD} "https://deb.nodesource.com/gpgkey/nodesource.gpg.key" | gpg --dearmor > /etc/apt/trusted.gpg.d/nodejs.gpg
    echo "deb https://deb.nodesource.com/$VERS ${DEB_NAME} main" > /etc/apt/sources.list.d/nodejs.list
}

setup_yarn_sources() {
    echo "Setup yarn sources ..."
    ${CURL_CMD} "https://dl.yarnpkg.com/debian/pubkey.gpg" | gpg --dearmor > /etc/apt/trusted.gpg.d/yarn.gpg
    echo "deb https://dl.yarnpkg.com/debian/ stable main" > /etc/apt/sources.list.d/yarn.list
}

setup_nodejs_env() {
    # change the node global environment
    scratch_dir_setup nodejs
    local NODE_PREFIX=${SCRATCH_HOME}/nodejs
    mkdir -p $NODE_PREFIX/cache
    chmod -R g+w $NODE_PREFIX
    chgrp -R staff $NODE_PREFIX
    # Set global repo 
    # node globalconfig by default is /usr/etc/npmrc  ... hmmm
    # would need to change npm_config_globalconfig globally anyway so ...
    # $ npm config ls -l
    { \
        echo "npm_config_prefix=$NODE_PREFIX"; \
        echo "npm_config_cache=$NODE_PREFIX/cache"; \
        echo 'export npm_config_prefix npm_config_cache'; \
    } > /etc/profile.d/nodejs.sh
}

setup_nuget_env() {
    scratch_dir_setup nuget
    local NUGET_PREFIX=${SCRATCH_HOME}/nuget
    mkdir -p $NUGET_PREFIX/packages
    mkdir -p $NUGET_PREFIX/cache
    mkdir -p $NUGET_PREFIX/plugins-cache
    chmod -R g+w $NUGET_PREFIX
    chgrp -R staff $NUGET_PREFIX
    { \
        echo "NUGET_PACKAGES=$NUGET_PREFIX/packages"; \
        echo "NUGET_HTTP_CACHE_PATH=$NUGET_PREFIX/cache"; \
        echo "NUGET_PLUGINS_CACHE_PATH=$NUGET_PREFIX/plugins-cache"; \
        echo 'export NUGET_PACKAGES NUGET_HTTP_CACHE_PATH NUGET_PLUGINS_CACHE_PATH'; \
    } > /etc/profile.d/nuget.sh
}

jdk_setup() {
    local JDK_VERS=$1
    echo "Installing JDK vers $1"
    setup_azul_sources
    apt update
    apt install -y \
        zulu-$JDK_VERS \
        --no-install-recommends
    { \
        echo "JAVA_HOME=/usr/lib/jvm/zulu-$JDK_VERS-amd64"; \
        echo 'export JAVA_HOME'; \
    } > /etc/profile.d/jvm_$JDK_VERS.sh
    echo "To update alternatives:"
    echo " $ update-alternatives --config java"
}

nodejs_setup() {
    setup_nodejs_sources
    apt install -y \
        nodejs \
        --no-install-recommends
}

yarn_setup() {
    setup_yarn_sources
    apt install -y \
        yarn \
        --no-install-recommends
}

mono_setup() {
    check_root_perm 
    setup_mono_sources
    apt update
    apt install -y \
        mono-complete \
        --no-install-recommends
}

code_setup() {
    check_root_perm 
    setup_code_sources
    apt update
    apt install -y \
        code \
        --no-install-recommends
}

dotnet_setup() {
    local DOTNET_VERS=$1
    echo "Installing dotnet core vers $1"
    check_root_perm 
    setup_dotnet_sources
    # avoid some dialing home ...
    { \
        echo 'DOTNET_CLI_TELEMETRY_OPTOUT=1'; \
        echo 'export DOTNET_CLI_TELEMETRY_OPTOUT'; \
    } > /etc/profile.d/dotnet_telemetry.sh
    apt update
    apt install -y \
        dotnet-sdk-${DOTNET_VERS} \
        --no-install-recommends
}

azure_cli_setup() {
    check_root_perm
    setup_azure_cli_sources
    apt update
    apt install -y \
        azure-cli \
        --no-install-recommends
}

teams_setup() {
    check_root_perm
    setup_teams_sources
    apt update
    apt install -y \
        teams \
        --no-install-recommends
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
    setup_docker_sources
    scratch_dir_setup docker
    apt update
    mkdir -p /etc/docker
    chmod 0700 /etc/docker
    { \
        echo -e '{'; \
        echo -e "  \"data-root\": \"${SCRATCH_DIR}/docker\", "; \
        echo -e '  "ipv6": false '; \
        echo -e '}'; \
    } > /etc/docker/daemon.json
    apt install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        --no-install-recommends
    echo "Disabling docker daemon at startup"
    systemctl stop docker 
    systemctl disable docker
    echo " Use the following manual startup:  sudo systemctl start docker"
    if [ "${PROXY_URL}" != "no" ]; then
        docker_proxy
        echo "Restarting docker for proxy settings"
        systemctl daemon-reload
    fi
    echo ""
    echo " To update users:"
    echo "   $ usermod -a -G docker user"
    echo ""
    echo " Test with:"
    echo "   $ docker run hello-world"
    echo ""
}

usage() {
    echo ""
    echo -e "${SCRIPT_NAME} \\nThis script does setup for third party repos\\n"
    echo ""
    echo "ENVs:"
    echo " PROXY_URL  : e.g. http://proxy.company.com:80/"
    echo ""
    echo "Usage:"
    echo "  nodejs_setup"
    echo "      - NodeJS"
    echo "  yarn_setup"
    echo "      - Yarn"
    echo "  jdk_setup <VERS>"
    echo "      - install Azul JDK version e.g. 11"
    echo "  docker_setup"
    echo "      - docker daemon"
    echo "  mono_setup"
    echo "      - mono runtime"
    echo "  code_setup"
    echo "      - vscode editor"
    echo "  dotnet_setup <VERS>"
    echo "      - dotnet core"
    echo "  teams_setup"
    echo "      - ms teams app"
    echo "  azure_cli_setup"
    echo "      - azure cli command line"
    echo "  scratch_dir_setup <DIR_NAME>"
    echo "      - create scratch style dataset under $SCRATCH_HOME/<DIR_NAME>"
    echo ""
}

main() {
    local cmd=$1

    if [[ -z "$cmd" ]]; then
        usage
        exit 1
    fi

    if [[ $cmd == "docker_setup" ]]; then
        docker_setup
    elif [[ $cmd == "nodejs_setup" ]]; then
        nodejs_setup
    elif [[ $cmd == "yarn_setup" ]]; then
        yarn_setup
    elif [[ $cmd == "mono_setup" ]]; then
        mono_setup
    elif [[ $cmd == "code_setup" ]]; then
        code_setup
    elif [[ $cmd == "dotnet_setup" ]]; then
        dotnet_setup $2
    elif [[ $cmd == "teams_setup" ]]; then
        teams_setup
    elif [[ $cmd == "azure_cli_setup" ]]; then
        azure_cli_setup
    elif [[ $cmd == "jdk_setup" ]]; then
        jdk_setup $2
    elif [[ $cmd == "scratch_dir_setup" ]]; then
        scratch_dir_setup $2
    else
        usage
    fi
}

main "$@"

