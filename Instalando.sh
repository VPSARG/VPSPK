#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH


# shell version
# ====================
SHELL_VERSION="ADM PLUS"
# ====================


# current path
CUR_DIR=$( pwd )


# base url
methods="Online"
BASE_URL="https://github.com/loyess/Shell/raw/master"
if [ -e plugins ] && [ -e prepare ] && [ -e service ] && [ -e templates ] && [ -e tools ] && [ -e utils ]; then
    methods="Local"
    BASE_URL="." 
fi


# bbr
TEDDYSUN_BBR_SCRIPT_URL="https://git.io/vbUk0"
CHIAKGE_BBR_SCRIPT_URL="https://git.io/vxJ1I"


# Humanization config PATH
HUMAN_CONFIG="/etc/shadowsocks/humanization.conf"


# shadowsocks config
SHADOWSOCKS_CONFIG="/etc/shadowsocks/config.json"

# shadowsocks-libev config and init
SHADOWSOCKS_LIBEV_INSTALL_PATH="/usr/local/bin"
SHADOWSOCKS_LIBEV_BIN_PATH="/usr/local/bin/ss-server"
SHADOWSOCKS_LIBEV_INIT="/etc/init.d/shadowsocks-libev"
SHADOWSOCKS_LIBEV_INIT_LOCAL="./service/shadowsocks-libev.sh"
SHADOWSOCKS_LIBEV_INIT_ONLINE="${BASE_URL}/service/shadowsocks-libev.sh"

# shadowsocks-rust config and init
SHADOWSOCKS_RUST_INSTALL_PATH="/usr/local/bin"
SHADOWSOCKS_RUST_BIN_PATH="/usr/local/bin/ssserver"
SHADOWSOCKS_RUST_INIT="/etc/init.d/shadowsocks-rust"
SHADOWSOCKS_RUST_INIT_LOCAL="./service/shadowsocks-rust.sh"
SHADOWSOCKS_RUST_INIT_ONLINE="${BASE_URL}/service/shadowsocks-rust.sh"

# go-shadowsocks2 config and init
GO_SHADOWSOCKS2_INSTALL_PATH="/usr/local/bin"
GO_SHADOWSOCKS2_BIN_PATH="/usr/local/bin/go-shadowsocks2"
GO_SHADOWSOCKS2_INIT="/etc/init.d/go-shadowsocks2"
GO_SHADOWSOCKS2_INIT_LOCAL="./service/go-shadowsocks2.sh"
GO_SHADOWSOCKS2_INIT_ONLINE="${BASE_URL}/service/go-shadowsocks2.sh"
GO_SHADOWSOCKS2_VERSION_FILE="/etc/shadowsocks/go-shadowsocks2.v"


# v2ray-plugin
V2RAY_PLUGIN_INSTALL_PATH="/usr/local/bin"
V2RAY_PLUGIN_BIN_PATH="/usr/local/bin/v2ray-plugin"


# kcptun
KCPTUN_INSTALL_PATH="/usr/local/kcptun"
KCPTUN_BIN_PATH="/usr/local/kcptun/kcptun-server"
KCPTUN_INIT="/etc/init.d/kcptun"
KCPTUN_CONFIG="/etc/kcptun/config.json"
KCPTUN_INIT_LOCAL="./service/kcptun.sh"
KCPTUN_INIT_ONLINE="${BASE_URL}/service/kcptun.sh"


# simple-obfs
SIMPLE_OBFS_INSTALL_PATH="/usr/local/bin"
SIMPLE_OBFS_BIN_PATH="/usr/local/bin/obfs-server"


# goquiet
GOQUIET_INSTALL_PATH="/usr/local/bin"
GOQUIET_BIN_PATH="/usr/local/bin/gq-server"


# cloak
CLOAK_INSTALL_PATH="/usr/local/bin"
CLOAK_SERVER_BIN_PATH="/usr/local/bin/ck-server"
CLOAK_CLIENT_BIN_PATH="/usr/local/bin/ck-client"
CLOAK_INIT="/etc/init.d/cloak"
CLOAK_INIT_LOCAL="./service/cloak.sh"
CLOAK_INIT_ONLINE="${BASE_URL}/service/cloak.sh"
CK_DB_PATH="/etc/cloak"
CK_CLIENT_CONFIG="/etc/cloak/ckclient.json"
CK_SERVER_CONFIG="/etc/cloak/ckserver.json"


# mos-tls-tunnel
MTT_VERSION_FILE="/etc/shadowsocks/mtt.v"
MTT_INSTALL_PATH="/usr/local/bin"
MTT_BIN_PATH="/usr/local/bin/mtt-server"


# rabbit-tcp
RABBIT_INSTALL_PATH="/usr/local/bin"
RABBIT_BIN_PATH="/usr/local/bin/rabbit-tcp"
RABBIT_INIT="/etc/init.d/rabbit-tcp"
RABBIT_CONFIG="/etc/rabbit-tcp/config.json"
RABBIT_VERSION_FILE="/etc/rabbit-tcp/rabbit-tcp.v"
RABBIT_INIT_LOCAL="./service/rabbit-tcp.sh"
RABBIT_INIT_ONLINE="${BASE_URL}/service/rabbit-tcp.sh"


# simple-tls
SIMPLE_TLS_INSTALL_PATH="/usr/local/bin"
SIMPLE_TLS_BIN_PATH="/usr/local/bin/simple-tls"
SIMPLE_TLS_VERSION_FILE="/etc/shadowsocks/simple-tls.v"


# caddy
CADDY_INSTALL_PATH="/usr/local/caddy"
CADDY_BIN_PATH="/usr/local/caddy/caddy"
CADDY_CONF_FILE="/usr/local/caddy/Caddyfile"
CADDY_VERSION_FILE="/usr/local/caddy/caddy.v"
CADDY_INIT="/etc/init.d/caddy"
CADDY_INIT_LOCAL="./service/caddy.sh"
CADDY_INIT_ONLINE="${BASE_URL}/service/caddy.sh"
CADDY_V2_INIT_LOCAL="./service/caddy2.sh"
CADDY_V2_INIT_ONLINE="${BASE_URL}/service/caddy2.sh"


# nginx
NGINX_BIN_PATH="/usr/sbin/nginx"
NGINX_CONFIG="/etc/nginx/nginx.conf"


# RE
EMAIL_RE="^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$"
DOMAIN_RE="^(www\.)?[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(:\d+)*(\/\w+\.\w+)*$"
IPV4_RE="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
IPV4_PORT_RE="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\:443$"
HTTPS_DOMAIN_RE="^(https:\/\/)?(www\.)?[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(:\d+)*(\/\w+\.\w+)*$"
IPV6_RE="^\s*((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?\s*$"


# Font color and background color
Green="\033[32m" && Red="\033[31m" && Yellow="\033[0;33m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && suffix="\033[0m"
Info="${Green}[信息]${suffix}"
Error="${Red}[错误]${suffix}"
Point="${Red}[提示]${suffix}"
Tip="${Green}[注意]${suffix}"
Warning="${Yellow}[警告]${suffix}"
Separator_1="——————————————————————————————"


# Root permission
[[ $EUID -ne 0 ]] && echo -e "[${Red}Error${suffix}] This script must be run as root!" && exit 1


usage() {
	cat >&1 <<-EOF
	Usage:
	  ./ss-plugins.sh [options...] [args...]

	Available Options:
	  install          安装
	  uninstall        卸载
	  update           升级
	  start            启动
	  stop             关闭
	  restart          重启
	  status           查看状态
	  script           升级脚本
	  show             可视化配置
	  log              查看日志文件
	  uid              添加一个新的uid用户(Cloak)
	  cert             为.cf .ga .gq .ml .tk申请证书(90天)
	  link             用新添加的uid生成一个新的SS://链接(Cloak)
	  scan             用ss://链接在当前终端上生成一个可供扫描的二维码
	  help             打印帮助信息并退出

	EOF

	exit $1
}

status_init(){
    if [[ -e ${SHADOWSOCKS_LIBEV_BIN_PATH} ]]; then
        ssName="Shadowsocks-libev"
        ssPath=${SHADOWSOCKS_LIBEV_BIN_PATH}
        ssPid=`ps -ef | grep -v grep | grep ss-server | awk '{print $2}'`
    elif [[ -e ${SHADOWSOCKS_RUST_BIN_PATH} ]]; then
        ssName="Shadowsocks-rust"
        ssPath=${SHADOWSOCKS_RUST_BIN_PATH}
        ssPid=`ps -ef | grep -v grep | grep ssserver | awk '{print $2}'`
    elif [[ -e ${GO_SHADOWSOCKS2_BIN_PATH} ]]; then
        ssName="Go-shadowsocks2"
        ssPath=${GO_SHADOWSOCKS2_BIN_PATH}
        ssPid=`ps -ef | grep -v grep | grep go-shadowsocks2 | awk '{print $2}'`
    fi

    if [[ -e ${V2RAY_PLUGIN_BIN_PATH} ]]; then
        pluginName="V2ray-plugin"
        pluginPath=${V2RAY_PLUGIN_BIN_PATH}
        pluginPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep v2ray-plugin | awk '{print $2}'`
    elif [[ -e ${KCPTUN_BIN_PATH} ]]; then
        pluginName="KcpTun"
        pluginPath=${KCPTUN_BIN_PATH}
        pluginPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep kcptun-server | awk '{print $2}'`
    elif [[ -e ${SIMPLE_OBFS_BIN_PATH} ]]; then
        pluginName="Simple-obfs"
        pluginPath=${SIMPLE_OBFS_BIN_PATH}
        pluginPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep obfs-server | awk '{print $2}'`
    elif [[ -e ${GOQUIET_BIN_PATH} ]]; then
        pluginName="GoQuiet"
        pluginPath=${GOQUIET_BIN_PATH}
        pluginPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep gq-server | awk '{print $2}'`
    elif [[ -e ${CLOAK_SERVER_BIN_PATH} ]]; then
        pluginName="Cloak"
        pluginPath=${CLOAK_SERVER_BIN_PATH}
        pluginPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep ck-server | awk '{print $2}'`
    elif [[ -e ${MTT_BIN_PATH} ]]; then
        pluginName="Mos-tls-tunnel"
        pluginPath=${MTT_BIN_PATH}
        pluginPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep mtt-server | awk '{print $2}'`
    elif [[ -e ${RABBIT_BIN_PATH} ]]; then
        pluginName="Rabbit-Tcp"
        pluginPath=${RABBIT_BIN_PATH}
        pluginPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep rabbit-tcp | awk '{print $2}'`
    elif [[ -e ${SIMPLE_TLS_BIN_PATH} ]]; then
        pluginName="Simple-tls"
        pluginPath=${SIMPLE_TLS_BIN_PATH}
        pluginPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep simple-tls | awk '{print $2}'`
    fi

    if [[ -e ${CADDY_BIN_PATH} ]]; then
        webName="Caddy"
        webPath=${CADDY_BIN_PATH}
        webPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep caddy | awk '{print $2}'`
    elif [[ -e ${NGINX_BIN_PATH} ]]; then
        webName="Nginx"
        webPath=${NGINX_BIN_PATH}
        webPid=`ps -ef | grep -vE 'grep|-plugin-opts' | grep nginx.conf | awk '{print $2}'`
    fi
}

status_menu(){
    local NoInstall=" estado actual: ${Red}no instalado${suffix}"
    local InstallStart=" estado actual: ${Green}ha sido instalado${suffix} y ${Green}activado${suffix}"
    local InstallNoStart=" estado actual: ${Green}Ha sido instalado${suffix} y ${Red}no ha comenzado${suffix}"

    status_init

    if [[ -e ${ssPath} ]] && [[ -e ${pluginPath} ]] && [[ -e ${webPath} ]]; then
        if [[ -n ${ssPid} ]] && [[ -n ${pluginPid} ]] && [[ -n ${webPid} ]]; then
            echo -e "${InstallStart}"
        else
            echo -e "${InstallNoStart}"
        fi
    elif [[ -e ${ssPath} ]] && [[ -e ${pluginPath} ]]; then
        if [[ -n ${ssPid} ]] && [[ -n ${pluginPid} ]]; then
            echo -e "${InstallStart}"
        else
            echo -e "${InstallNoStart}"
        fi
    elif [[ -e ${ssPath} ]]; then
        if [[ -n ${ssPid} ]]; then
            echo -e "${InstallStart}"
        else
            echo -e "${InstallNoStart}"
        fi
    else
        echo -e "${NoInstall}"
    fi
}

check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

package_install(){
    local package_name=$1
    
    if check_sys packageManager yum; then
        yum install -y $1 > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${Error} 安装 $1 失败."
            exit 1
        fi
    elif check_sys packageManager apt; then
        apt-get -y update > /dev/null 2>&1
        apt-get -y install $1 > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${Error} la instalacion $1 fracaso."
            exit 1
        fi
    fi
    echo -e "${Info} $1 la instalacion se ha completado."
}

improt_package(){
    local package=$1
    local sh_file=$2
    
    if [ ! "$(command -v curl)" ]; then
        package_install "curl" > /dev/null 2>&1
    fi
    
    if [[ ${methods} == "Online" ]]; then
        source <(curl -sL ${BASE_URL}/${package}/${sh_file})
    else
        cd ${CUR_DIR}
        source ${BASE_URL}/${package}/${sh_file}
    fi
}

disable_selinux(){
    if [ -s /etc/selinux/config ] && grep -q 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

install_check(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        if centosversion 5; then
            return 1
        fi
        return 0
    else
        return 1
    fi
}

is_ipv4_or_ipv6(){
    ip=$1
    
    if [ -n "$(echo $ip | grep -E $IPV4_RE)" ] || [ -n "$(echo $ip | grep -E $IPV6_RE)" ]; then
        return 0
    else
        return 1
    fi
}

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

version_gt(){
    test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
}

check_latest_version(){
    local current_v=$1
    local latest_v=$2
    if version_gt ${latest_v} ${current_v}; then
        return 0
    else
        return 1
    fi
}

check_port_occupy(){
    local PROT=$1
    
    if [ ! "$(command -v lsof)" ]; then
        package_install "lsof" > /dev/null 2>&1
    fi
    
    if [[ `lsof -i:"${PROT}" | grep -v google_ | grep -v COMMAND | wc -l` -ne 0 ]];then
        # Occupied
        return 0
    else
        # Unoccupied
        return 1
    fi
}

check_script_update(){
    local isShow=${1:-"show"}

    SHELL_VERSION_NEW=$(wget --no-check-certificate -qO- "https://git.io/fjlbl"|grep 'SHELL_VERSION="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
    [[ -z ${SHELL_VERSION_NEW} ]] && echo -e "${Error} no se puede vincular a Github !" && exit 0
    if version_gt ${SHELL_VERSION_NEW} ${SHELL_VERSION}; then
        echo
        echo -e "${Green}当前脚本版本为：${SHELL_VERSION} 检测到有新版本可更新.${suffix}"
        echo -e "Presione cualquier tecla para comenzar ... o presione Ctrl + C para cancelar"
        char=`get_char`
        wget -N --no-check-certificate -O ss-plugins.sh "https://git.io/fjlbl" && chmod +x ss-plugins.sh
        echo -e "El script se ha actualizado a la última versión.[ ${SHELL_VERSION_NEW} ] si surge errores solo ignore" && exit 0
    else
        if [[ ${isShow} == "show" ]]; then
            echo
            echo -e "${Info} La versión actual del script es: ${SHELL_VERSION} No se detectó una versión más nueva."
            echo
        fi
    fi
}

check_ss_port(){
    local SS_PORT=$1
    while true
    do
        if [[ ${SS_PORT} -ne "443" ]]; then
            echo -e "${Tip} El puerto SS-libev es${Green}${shadowsocksport}${suffix}"
            echo
            break
        fi
        
        gen_random_prot
        if check_port_occupy ${ran_prot}; then
            continue
        fi
        
        shadowsocksport=${ran_prot}
        echo -e "${Tip} El puerto SS-libev ha sido cambiado${Red}443${suffix}Restablecer a${Green}${shadowsocksport}${suffix}"
        echo  
        break
    done
}

choose_script_bbr(){
    echo
    echo -e "Seleccione el script de instalación de BBR"
    echo
    echo -e "    ${Green}1.${suffix} BBR"
    echo -e "    ${Green}2.${suffix} BBR|BBR|BBRplus|Lotserver"
    echo && read -e -p "porfavor ingrese el numero [1-2]：" bbr_menu_num
    case "${bbr_menu_num}" in
        1)
            source <(curl -sL ${TEDDYSUN_BBR_SCRIPT_URL})
            ;;
        2)
            source <(curl -sL ${CHIAKGE_BBR_SCRIPT_URL})
            ;;
        *)
            echo -e "${Error} porfavor ingrese el numero correcto [1-2]"
            ;;
    esac
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo ${IP}
}

get_ipv6(){
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ -z ${ipv6} ] && return 1 || return 0
}

get_char(){
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

get_str_base64_encode(){
    echo -n $1 | base64 -w0
}

get_str_replace(){
    echo -n $1 | sed 's/:/%3A/g;s/;/%3B/g;s/=/%3D/g;s/\//%2F/g'
}

gen_random_prot(){
    ran_prot=$(shuf -i 9000-19999 -n 1)
}

gen_random_str(){
    ran_str8=$(head -c 100 /dev/urandom | tr -dc a-z0-9A-Z |head -c 12)
    ran_str16=$(head -c 100 /dev/urandom | tr -dc a-z0-9A-Z |head -c 16)
}

gen_credentials(){
    while true
    do
        ckauid=$(ck-server -u)
        IFS=, read ckpub ckpv <<< $(ck-server -k)
        
        # filter "+" from ckauid and ckpub
        if [[ $(echo ${ckauid} | grep "+") || $(echo ${ckpub} | grep "+") ]]; then
            continue
        fi
        break
    done
}

gen_credentials_cca(){
    local domain=$1
    if [[ ${domainType} = Other ]]; then
        cerPath="/etc/simple-tls/${domain}.cert"
        keyPath="/etc/simple-tls/${domain}.key"
        if [ ! -d "$(dirname ${cerPath})" ]; then
            mkdir -p $(dirname ${cerPath})
        fi
        simple-tls -gen-cert -n ${domain} -key ${keyPath} -cert ${cerPath}
        base64Cert=$(cat ${cerPath} | base64 -w0 | sed 's/=//g')
    fi
}

get_version(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(get_version)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

config_ss(){
    local server_value="\"0.0.0.0\""

    if get_ipv6; then
        local V=${SS_VERSION}
        local N=${plugin_num}
        if [[ ${V} = "ss-libev" ]] && [[ ${N} = "2" ]] || [[ ${N} = "3" ]] || [[ ${N} == "5" ]] || [[ -z ${N} ]]; then
            server_value="[\"[::0]\",\"0.0.0.0\"]"
        fi
    fi

    if [ ! -d "$(dirname ${SHADOWSOCKS_CONFIG})" ]; then
        mkdir -p $(dirname ${SHADOWSOCKS_CONFIG})
    fi

    if [[ ${plugin_num} == "1" ]]; then
        improt_package "templates/config" "v2ray_plugin_config.sh"
        config_ss_v2ray_plugin
    elif [[ ${plugin_num} == "2" ]]; then
        improt_package "templates/config" "kcptun_config.sh"
        config_ss_kcptun
    elif [[ ${plugin_num} == "3" ]]; then
        improt_package "templates/config" "simple_obfs_config.sh"
        config_ss_simple_obfs
    elif [[ ${plugin_num} == "4" ]]; then
        improt_package "templates/config" "goquiet_config.sh"
        ss_goquiet_config
    elif [[ ${plugin_num} == "5" ]]; then
        improt_package "templates/config" "cloak_config.sh"
        config_ss_cloak
    elif [[ ${plugin_num} == "6" ]]; then
        improt_package "templates/config" "mos_tls_tunnel_config.sh"
        config_ss_mos_tls_tunnel
    elif [[ ${plugin_num} == "7" ]]; then
        improt_package "templates/config" "rabbit_tcp_config.sh"
        config_ss_rabbit_tcp
    elif [[ ${plugin_num} == "8" ]]; then
        improt_package "templates/config" "simple_tls_config.sh"
        config_ss_simple_tls
    else
        improt_package "templates/config" "ss_original_config.sh"
        ss_config_standalone
    fi
}

gen_ss_links(){
    if [[ ${plugin_num} == "1" ]]; then
        improt_package "templates/links" "v2ray_plugin_link.sh"
        gen_ss_v2ray_plugin_link
    elif [[ ${plugin_num} == "2" ]]; then
        improt_package "templates/links" "kcptun_link.sh"
        ss_kcptun_link
    elif [[ ${plugin_num} == "3" ]]; then
        improt_package "templates/links" "simple_obfs_link.sh"
        gen_ss_simple_obfs_link
    elif [[ ${plugin_num} == "4" ]]; then
        improt_package "templates/links" "goquiet_link.sh"
        ss_goquiet_link
    elif [[ ${plugin_num} == "5" ]]; then
        improt_package "templates/links" "cloak_link.sh"
        ss_cloak_link_new
    elif [[ ${plugin_num} == "6" ]]; then
        improt_package "templates/links" "mos_tls_tunnel_link.sh"
        gen_ss_mos_tls_tunnel_link
    elif [[ ${plugin_num} == "7" ]]; then
        improt_package "templates/links" "rabbit_tcp_link.sh"
        ss_rabbit_tcp_link
    elif [[ ${plugin_num} == "8" ]]; then
        improt_package "templates/links" "simple_tls_link.sh"
        gen_ss_simple_tls_link
    else
        improt_package "templates/links" "ss_original_link.sh"
        ss_link
    fi
}

install_completed(){
    ldconfig
    if [[ ${SS_VERSION} = "ss-libev" ]]; then
        ${SHADOWSOCKS_LIBEV_INIT} start > /dev/null 2>&1
    elif [[ ${SS_VERSION} = "ss-rust" ]]; then
        ${SHADOWSOCKS_RUST_INIT} start > /dev/null 2>&1
    elif [[ ${SS_VERSION} = "go-ss2" ]]; then
        ${GO_SHADOWSOCKS2_INIT} start > /dev/null 2>&1
    fi

    if [[ ${plugin_num} == "1" ]]; then
        improt_package "templates/visible" "v2ray_plugin_visible.sh"
        ss_v2ray_plugin_visible
    elif [[ ${plugin_num} == "2" ]]; then
        improt_package "templates/visible" "kcptun_visible.sh"
        ss_kcptun_visible
    elif [[ ${plugin_num} == "3" ]]; then
        improt_package "templates/visible" "simple_obfs_visible.sh"
        ss_simple_obfs_visible
    elif [[ ${plugin_num} == "4" ]]; then
        improt_package "templates/visible" "goquiet_visible.sh"
        ss_goquiet_show
    elif [[ ${plugin_num} == "5" ]]; then
        improt_package "templates/visible" "cloak_visible.sh"
        ss_cloak_visible
    elif [[ ${plugin_num} == "6" ]]; then
        improt_package "templates/visible" "mos_tls_tunnel_visible.sh"
        ss_mos_tls_tunnel_visible
    elif [[ ${plugin_num} == "7" ]]; then
        improt_package "templates/visible" "rabbit_tcp_visible.sh"
        ss_rabbit_tcp_visible
    elif [[ ${plugin_num} == "8" ]]; then
        improt_package "templates/visible" "simple_tls_visible.sh"
        ss_simple_tls_visible
    else
        improt_package "templates/visible" "ss_original_visible.sh"
        ss_show
    fi
}

install_prepare(){
    local plugin
    local pluginName=(
        v2ray-plugin
        kcptun
        simple-obfs
        goquiet
        cloak
        mos-tls-tunnel
        rabbit-tcp
        simple-tls
    )

    check_script_update "notShow"
    improt_package "prepare" "shadowsocks_prepare.sh"
    choose_ss_install_version
    install_prepare_port
    install_prepare_password
    install_prepare_cipher

    echo -e "\nSeleccione el complemento Shadowsocks para instalar\n"
    for ((i=1;i<=${#pluginName[@]};i++ )); do
        plugin="${pluginName[$i-1]}"
        if [[ ${i} -le 9 ]]; then
            echo -e "${Green}  ${i}.${suffix} ${plugin}"
        else
            echo -e "${Green} ${i}.${suffix} ${plugin}"
        fi
    done
    echo && read -e -p "(Predeterminado:no instalado)：" plugin_num
    [[ -z "${plugin_num}" ]] && plugin_num="" && echo -e "\n${Tip}Actualmente no hay ningún complemento seleccionado${SS_VERSION}."

    if [[ ${plugin_num} == "1" ]]; then
        improt_package "prepare" "v2ray_plugin_prepare.sh"
        install_prepare_libev_v2ray
    elif [[ ${plugin_num} == "2" ]]; then
        improt_package "prepare" "kcptun_prepare.sh"
        install_prepare_libev_kcptun
    elif [[ ${plugin_num} == "3" ]]; then
        improt_package "prepare" "simple_obfs_prepare.sh"
        install_prepare_libev_obfs
    elif [[ ${plugin_num} == "4" ]]; then
        improt_package "prepare" "goquiet_prepare.sh"
        install_prepare_libev_goquiet
    elif [[ ${plugin_num} == "5" ]]; then
        improt_package "prepare" "cloak_prepare.sh"
        install_prepare_libev_cloak
    elif [[ ${plugin_num} == "6" ]]; then
        improt_package "prepare" "mos_tls_tunnel_prepare.sh"
        install_prepare_libev_mos_tls_tunnel
    elif [[ ${plugin_num} == "7" ]]; then
        improt_package "prepare" "rabbit_tcp_prepare.sh"
        install_prepare_libev_rabbit_tcp
    elif [[ ${plugin_num} == "8" ]]; then
        improt_package "prepare" "simple_tls_prepare.sh"
        install_prepare_libev_simple_tls
    elif [[ ${plugin_num} == "" ]]; then
        :
    else
        echo -e "${Error} Ingrese el número correcto [1-8]" && exit 1
    fi
    
    echo
    echo "Presione cualquier tecla para comenzar ... o presione Ctrl + C para cancelar"
    char=`get_char`
}

install_main(){
    if [[ ${SS_VERSION} = "ss-libev" ]]; then
        install_libsodium_logic
        if ! ldconfig -p | grep -wq "/usr/lib"; then
            echo "/usr/lib" > /etc/ld.so.conf.d/lib.conf
        fi
        ldconfig
        install_mbedtls_logic
    fi
    
    improt_package "tools" "shadowsocks_install.sh"
    if [[ ${SS_VERSION} = "ss-libev" ]]; then
        install_shadowsocks_libev
    elif [[ ${SS_VERSION} = "ss-rust" ]]; then
        install_shadowsocks_rust
    elif [[ ${SS_VERSION} = "go-ss2" ]]; then
        install_go_shadowsocks2
    fi
    
    if [ "${plugin_num}" == "1" ]; then
        improt_package "plugins" "v2ray_plugin_install.sh"
        install_v2ray_plugin
        if [[ ${web_flag} = "1" ]]; then
            improt_package "tools" "caddy_install.sh"
            install_caddy
        elif [[ ${web_flag} = "2" ]]; then
            improt_package "tools" "nginx_install.sh"
            install_nginx
        fi
        plugin_client_name="v2ray-plugin"
    elif [ "${plugin_num}" == "2" ]; then
        improt_package "plugins" "kcptun_install.sh"
        install_kcptun
        plugin_client_name="kcptun"
    elif [ "${plugin_num}" == "3" ]; then
        improt_package "plugins" "simple_obfs_install.sh"
        install_simple_obfs
        plugin_client_name="obfs-local"
    elif [ "${plugin_num}" == "4" ]; then
        improt_package "plugins" "goquiet_install.sh"
        install_goquiet
        plugin_client_name="gq-client"
    elif [ "${plugin_num}" == "5" ]; then
        improt_package "plugins" "cloak_install.sh"
        install_cloak
        gen_credentials
        plugin_client_name="ck-client"
    elif [ "${plugin_num}" == "6" ]; then
        improt_package "plugins" "mos_tls_tunnel_install.sh"
        install_mos_tls_tunnel
        if [[ ${web_flag} = "1" ]]; then
            improt_package "tools" "caddy_install.sh"
            install_caddy
        elif [[ ${web_flag} = "2" ]]; then
            improt_package "tools" "nginx_install.sh"
            install_nginx
        fi
        plugin_client_name="mostlstunnel"
    elif [ "${plugin_num}" == "7" ]; then
        improt_package "plugins" "rabbit_tcp_install.sh"
        install_rabbit_tcp
        plugin_client_name="rabbit-plugin"
    elif [ "${plugin_num}" == "8" ]; then
        improt_package "plugins" "simple_tls_install.sh"
        install_simple_tls
        gen_credentials_cca "${serverName}"
        plugin_client_name="simple-tls"
    fi
}

status_install(){
    status_init

    if [[ -e ${ssPath} ]] && [[ -e ${pluginPath} ]] && [[ -e ${webPath} ]]; then
        echo -e "\n${Info} ${ssName} ${pluginName} ${webName} Ya instalado.\n"
        exit 1
    elif [[ -e ${ssPath} ]] && [[ -e ${pluginPath} ]]; then
        echo -e "\n${Info} ${ssName} ${pluginName} Ya instalado.\n"
        exit 1
    elif [[ -e ${ssPath} ]]; then
        echo -e "\n${Info} ${ssName} Ya instalado.\n"
        exit 1
    fi
}

install_step_all(){
    status_install
    disable_selinux
    install_prepare
    improt_package "utils" "dependencies.sh"
    install_dependencies_logic
    improt_package "utils" "downloads.sh"
    download_ss_file
    download_plugins_file
    improt_package "utils" "firewalls.sh"
    config_firewall_logic
    install_main
    add_more_entropy
    install_cleanup
    config_ss
    gen_ss_links
    install_completed
    do_show
}

install_cleanup(){
    cd ${CUR_DIR}
    # ss-libev
    rm -rf ${LIBSODIUM_FILE} ${LIBSODIUM_FILE}.tar.gz
    rm -rf ${MBEDTLS_FILE} ${MBEDTLS_FILE}.tar.gz
    rm -rf ${shadowsocks_libev_file} ${shadowsocks_libev_file}.tar.gz
    
    # ss-rust
    rm -rf ${shadowsocks_rust_file}.tar.xz
    
    # v2ray-plugin
    rm -rf v2ray-plugin_linux_amd64 ${v2ray_plugin_file}.tar.gz
    
    # kcptun
    rm -rf client_linux_amd64 server_linux_amd64 ${kcptun_file}.tar.gz
    
    # simple-obfs
    rm -rf simple-obfs
    
    # goquiet
    rm -rf ${goquiet_file}
    
    # cloak
    rm -rf ${cloak_file}
    
    # mos-tls-tunnel
    rm -rf ${mtt_file}.zip LICENSE README.md mtt-client

    #simple-tls
    rm -rf ${simple_tls_file}.zip LICENSE  README.md README_zh.md
}

do_uid(){
    improt_package "utils" "ck_user_manager.sh"
    user_manager_by_uid
}

do_link(){
    improt_package "utils" "ck_sslink.sh"
    gen_ssurl_by_uid "$1"
}

do_scan(){
    improt_package "utils" "qr_code.sh"
    gen_qr_code "$1"
}

do_show(){
    local mark=$1

    if [ ! -e $HUMAN_CONFIG ]; then
        echo "The visible config not found."
        exit 1
    fi
    if [[ ${mark} == "cleanScreen" ]]; then
        clear -x
    fi
    cat $HUMAN_CONFIG
}

do_log(){
    improt_package "utils" "view_log.sh"
    show_log
}

do_cert(){
    improt_package "utils" "gen_certificates.sh"
    acme_get_certificate_by_manual_force "$1"
}

do_start(){
    status_init
    if [[ -z "${ssPath}" ]]; then
        echo -e "\n ${Red} Shadowsocks no está instalado, intente instalarlo antes de realizar esta operación.${suffix}\n"
        exit 1
    fi
    improt_package "utils" "start.sh"
    start_services
}

do_stop(){
    improt_package "utils" "stop.sh"
    stop_services
}

do_restart(){
    do_stop
    do_start
}

do_status(){
    improt_package "utils" "status.sh"
    other_status
}

do_update(){
    cd ${CUR_DIR}
    improt_package "utils" "update.sh"
    update_logic
}

do_uninstall(){
    status_init

    if [[ -e ${ssPath} ]] && [[ -e ${pluginPath} ]] && [[ -e ${webPath} ]]; then
        local pkgName="${ssName} ${pluginName} ${webName}"
    elif [[ -e ${ssPath} ]] && [[ -e ${pluginPath} ]]; then
        local pkgName="${ssName} ${pluginName}"
    elif [[ -e ${ssPath} ]]; then
        local pkgName="${ssName}"
    else
        local pkgName="Shadowsocks"
    fi
    echo -e "\nEstas seguro que lo quieres desinstalar ${pkgName} si? [y/n]\n"
    read -e -p "(por defecto: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" != "y" ] && [ "${answer}" != "Y" ]; then
        echo -e "\n${Info} ${pkgName} desinstalar.\n"
        exit 1
    fi
    
    # start uninstall
    improt_package "utils" "uninstall.sh"
    uninstall_services
    echo -e "\n${Info} ${pkgName} la desinstalacion fue exitos.\n"
}

do_install(){
    local FLAG
    
    # check supported
    if ! install_check; then
        echo -e "[${Red}Error${suffix}] Your OS is not supported to run it!"
        echo "Please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
        exit 1
    fi
    
    if [[ -e ${SHADOWSOCKS_LIBEV_BIN_PATH} ]]; then
        FLAG="Shadowsocks-libev"
    elif [[ -e ${SHADOWSOCKS_RUST_BIN_PATH} ]]; then
        FLAG="Shadowsocks-rust"
    elif [[ -e ${GO_SHADOWSOCKS2_BIN_PATH} ]]; then
        FLAG="Go-shadowsocks2"
    else
        FLAG="Shadowsocks"
    fi
    
    echo -e " ${FLAG}script ${Red}[v${SHELL_VERSION} ${methods}]${suffix}

    ${Green}1.${suffix} BBR
    ${Green}2.${suffix} Instalar
    ${Green}3.${suffix} Desintalar
     "
    status_menu
    echo && read -e -p "porfavor ingrese el numero [1-3]：" menu_num
    case "${menu_num}" in
        1)   
            choose_script_bbr
            ;;
        2)
            install_step_all
            ;;
        3)
            do_uninstall
            ;;
        *)
            echo -e "${Error} porfavor ingrese el numero correcto [1-3]"
            ;;
    esac
}



# install and tools
action=${1:-"install"}

case ${action} in
    install|uninstall|update|start|stop|restart)
        do_${action}
        ;;
    status)
        do_${action}
        ;;
    script)
        check_script_update
        ;;
    uid)
        do_${action} 
        ;;
    link)
        do_${action}  "${2}"
        ;;
    scan)
        do_${action}  "${2}"
        ;;
    show)
        do_${action} "cleanScreen"
        ;;
    log)
        do_${action}
        ;;
    cert)
        do_${action} "${2}"
        ;;
    help)
        usage 0
        ;;
    *)
        usage 1
        ;;
esac
