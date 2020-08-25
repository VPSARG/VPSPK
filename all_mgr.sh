#!/bin/bash
#=================================================
#	System Required: :Debian 9+/Ubuntu 18.04+/Centos 7+
#	Description: ClashR&V2ray&SSR script
#	Version: 1.0.0
# Official document: www.v2ray.com
#=================================================
sh_ver="VPSPACK ARGENTO"
RED="\033[0;31m"
NO_COLOR="\033[0m"
GREEN="\033[32m\033[01m"
FUCHSIA="\033[0;35m"
BLUE="\033[0;36m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[INFORMACION]${Font_color_suffix}"
Error="${Red_font_prefix}[ERROR]${Font_color_suffix}"
Tip="${Green_font_prefix}[NOTA]${Font_color_suffix}"
nginx_bin_old_file="/usr/sbin/nginx"
nginx_conf_dir="/etc/nginx/conf/conf.d"
nginx_conf="${nginx_conf_dir}/default.conf"
nginx_dir="/etc/nginx"
v2ray_bin_dir="/usr/bin/v2ray"
v2ray_systemd_file="/etc/systemd/system/v2ray.service"
nginx_bin_file="/etc/nginx/sbin/nginx"
v2ray_conf_dir="/etc/v2ray"
v2ray_conf="${v2ray_conf_dir}/config.json"
v2ray_shadowrocket_qr_config_file="${v2ray_conf_dir}/shadowrocket_qrconfig.json"
v2ray_win_and_android_qr_config_file="${v2ray_conf_dir}/win_and_android_qrconfig.json"
caddy_bin_dir="/usr/bin/caddy"
caddy_conf_dir="/etc/caddy"
caddy_conf="${caddy_conf_dir}/Caddyfile"
caddy_systemd_file="/usr/lib/systemd/system/caddy.service"
trojan_bin_dir="/usr/local/bin/trojan"
trojan_conf_dir="/usr/local/etc/trojan"
trojan_conf="${trojan_conf_dir}/config.json"
trojan_qr_config_file="${trojan_conf_dir}/qrconfig.json"
trojan_systemd_file="/etc/systemd/system/trojan.service"
ssr_conf_dir="/etc/shadowsocks-r"
ssr_conf="${ssr_conf_dir}/config.json"
ssr_systemd_file="/etc/init.d/shadowsocks-r"
ssr_bin_dir="/usr/local/shadowsocks"
ssr_qr_config_file="${ssr_conf_dir}/qrconfig.json"
web_dir="/usr/wwwroot"
check_root(){
  [[ $EUID != 0 ]] && echo -e "${Error} No eres usuario ROOT o sin permisos ROOT,ejecute el siguiente comando ${Green_background_prefix}sudo -i${Font_color_suffix} ya eres usuario ROOT" && exit 1
}
trojan_info_extraction() {
  grep "$1" ${trojan_qr_config_file} | awk -F '"' '{print $4}'
}
v2ray_info_extraction() {
  grep "$1" ${v2ray_shadowrocket_qr_config_file} | awk -F '"' '{print $4}'
}
ssr_qr_info_extraction() {
  grep "$1" ${ssr_qr_config_file} | awk -F '"' '{print $4}'
}
output_trojan_information() {
  uuid=$(trojan_info_extraction '\"uuid\"')
  domain=$(trojan_info_extraction '\"domain\"')
  password1=$(trojan_info_extraction '\"password1\"')
  password2=$(trojan_info_extraction '\"password2\"')
  trojanport=$(trojan_info_extraction '\"trojanport\"')
  webport=$(trojan_info_extraction '\"webport\"')
}
output_v2ray_information() {
  uuid=$(v2ray_info_extraction '\"id\"')
  domain=$(v2ray_info_extraction '\"add\"')
  webport=$(v2ray_info_extraction '\"port\"')
}
output_ssr_information(){
  uuid=$(ssr_qr_info_extraction '\"uuid\"')
  domain=$(ssr_qr_info_extraction '\"domain\"')
  protocol=$(ssr_qr_info_extraction '\"protocol\"')
  method=$(ssr_qr_info_extraction '\"method\"')
  obfs=$(ssr_qr_info_extraction '\"obfs\"')
  password=$(ssr_qr_info_extraction '\"password\"')
}
remove_trojan_old_information() {
  rm -f ${web_dir}/${uuid}.html
  rm -f ${web_dir}/${uuid}-01.png
  rm -f ${web_dir}/${uuid}-02.png
}
remove_v2ray_old_information() {
  rm -f ${web_dir}/${uuid}.html
  rm -f ${web_dir}/${uuid}-01.png
  rm -f ${web_dir}/${uuid}-02.png
}
remove_ssr_old_information() {
  rm -f ${web_dir}/${uuid}.html
  rm -f ${web_dir}/${uuid}.png
}
input_trojan_password(){
  read -rp "$(echo -e "${Info}ingrese la contraseña 1 para ClashR:")" password1
  while [[ -z ${password1} ]]; do
    read -rp "$(echo -e "${Info}no puede estar vacio,vuelva a escribir:")" password1
  done
  read -rp "$(echo -e "${Info}ingrese la contraseña 2 para ClashR:")" password2
  while [[ -z ${password2} ]]; do
    read -rp "$(echo -e "${Info}no puede estar vacio,vuelva a escribir:")" password2
  done
}
trojan_conf() {
  cat >${trojan_conf} <<_EOF
  {
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": ${trojanport},
    "remote_addr": "127.0.0.1",
    "remote_port": ${webport},
    "password": [
        "${password1}",
        "${password2}"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/data/${domain}/fullchain.crt",
        "key": "/data/${domain}/privkey.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "alpn_port_override": {
            "h2": 81
        },
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "ClashR",
        "username": "ClashR",
        "password": "",
        "cafile": ""
    }
}
_EOF
  # sed -i "8c \"$password1\"," ${trojan_conf}
  # sed -i "9c \"$password2\"," ${trojan_conf}
  # sed -i "s/password1/${password1}/g" ${trojan_conf}
  # sed -i "s/password2/${password2}/g" ${trojan_conf}
  # sed -i "/\"cert\":/c \"cert\": \"/etc/letsencrypt/live/$domain/fullchain.pem\"," ${trojan_conf}
  # sed -i "/\"key\":/c \"key\": \"/etc/letsencrypt/live/$domain/privkey.pem\"," ${trojan_conf}
}
v2ray_conf() {
  uuid=$(cat /proc/sys/kernel/random/uuid)
  read -rp "$(echo -e "${Tip}se ha generado uuid:${uuid},confirmar para usar?[Y/n]?")" yn
  while [[ "${yn}" != [Yy] ]]; do
    uuid=$(cat /proc/sys/kernel/random/uuid)
    read -rp "$(echo -e "${Tip}se ha generado uuid:${uuid},confirmar para usar?[Y/n]?")" yn
  done
  cat >${v2ray_conf} <<"_EOF"
	  {
      "inbounds": [
        {
          "port": 10000,
          "listen":"127.0.0.1",
          "protocol": "vmess",
          "settings": {
            "clients": [
              {
                "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "alterId": 64
              }
            ]
          },
          "streamSettings": {
            "network": "ws",
            "wsSettings": {
            "path": "/ray/"
            }
          }
        }
      ],
      "outbounds": [
        {
          "protocol": "freedom",
          "settings": {}
        }
      ]
    }
_EOF
  sed -i "s/b831381d-6324-4d53-ad4f-8cda48b30811/${uuid}/g" ${v2ray_conf}
}
input_ssr_password(){
  read -rp "$(echo -e "${Info}Ingrese una nueva contraseña:")" password
  while [[ -z ${password} ]]; do
    read -rp "$(echo -e "${Info}la contraseña no puede estar vacia,vuelva a escribir:")" password
  done
}
ssr_conf() {
  #sed -i "\"server_port\": /c         \"server_port\":443," ${ssr_conf}
  #sed -i "\"redirect\": /c        \"redirect\":[\"*:443#127.0.0.1:80\"]," ${ssr_conf}
  cat >${ssr_conf} <<EOF
  {
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":${ssrport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${password}",
    "timeout":120,
    "method":"chacha20-ietf",
    "protocol":"auth_chain_a",
    "protocol_param":"",
    "obfs":"tls1.2_ticket_auth",
    "obfs_param":"",
    "redirect":["*:${ssrport}#127.0.0.1:1234"],
    "dns_ipv6":false,
    "fast_open":true,
    "workers":1
}
EOF
}
ssr_qr_link_image(){
  uuid=$(cat /proc/sys/kernel/random/uuid)
  tmp1=$(echo -n "${password}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
  tmp2=$(echo -n "${domain}:${ssrport}:${protocol}:${method}:${obfs}:${tmp1}/?obfsparam=" | base64 -w0)
  ssr_link="ssr://${tmp2}"
  qrencode -o ${web_dir}/${uuid}.png -s 8 "${ssr_link}"
}
trojan_qr_link_image() {
  uuid=$(cat /proc/sys/kernel/random/uuid)
  trojan_link1="trojan://${password1}@${domain}:${trojanport}"
  trojan_link2="trojan://${password2}@${domain}:${trojanport}"
  qrencode -o ${web_dir}/${uuid}-01.png -s 6 "${trojan_link1}"
  qrencode -o ${web_dir}/${uuid}-02.png -s 6 "${trojan_link2}"
}

v2ray_shadowrocket_qr_link_image() {
  v2ray_link1="vmess://$(base64 -w 0 ${v2ray_shadowrocket_qr_config_file})"
  qrencode -o ${web_dir}/${uuid}-1.png -s 6 "${v2ray_link1}"
}
v2ray_win_and_android_qr_link_image() {
  v2ray_link2="vmess://$(base64 -w 0 ${v2ray_win_and_android_qr_config_file})"
  qrencode -o ${web_dir}/${uuid}-2.png -s 6 "${v2ray_link2}"
}

trojan_info_html() {
  vps="ClashR"
  wget --no-check-certificate -O ${web_dir}/trojan_tmpl.html https://raw.githubusercontent.com/monsbri/geminis/master/marzo.html
  chmod +x ${web_dir}/trojan_tmpl.html
  eval "cat <<EOF
  $(<${web_dir}/trojan_tmpl.html)
EOF
  " >${web_dir}/${uuid}.html
}
v2ray_info_html() {
  vps="v2ray"
  wget --no-check-certificate -O ${web_dir}/v2ray_tmpl.html https://raw.githubusercontent.com/monsbri/geminis/master/febrero.html
  chmod +x ${web_dir}/v2ray_tmpl.html
  eval "cat <<EOF
  $(<${web_dir}/v2ray_tmpl.html)
EOF
  " >${web_dir}/${uuid}.html
}
ssr_info_html(){
  vps="SSR"
  wget --no-check-certificate -O ${web_dir}/ssr_tmpl.html https://raw.githubusercontent.com/monsbri/geminis/master/enero.html
  chmod +x ${web_dir}/ssr_tmpl.html
  eval "cat <<EOF
  $(< ${web_dir}/ssr_tmpl.html)
EOF
  "  > ${web_dir}/${uuid}.html
}
trojan_qr_config() {
  cat >${trojan_qr_config_file} <<-EOF
  "domain": "${domain}"
  "uuid": "${uuid}"
  "password1": "${password1}"
  "password2": "${password2}"
  "trojanport":"${trojanport}"
  "webport":"${webport}"
EOF
}
v2ray_qr_config() {
  sed -i "6c \"id\": \"${uuid}\"," ${v2ray_shadowrocket_qr_config_file}
  sed -i "6c \"id\": \"${uuid}\"," ${v2ray_win_and_android_qr_config_file}
}
v2ray_qr_port_config() {
  sed -i "5c \"port\": \"${webport}\"," ${v2ray_shadowrocket_qr_config_file}
  sed -i "5c \"port\": \"${webport}\"," ${v2ray_win_and_android_qr_config_file}
}
ssr_qr_config() {
  sed -i "2c \"uuid\":\"${uuid}\"," ${ssr_qr_config_file}
  sed -i "4c \"password\":\"${password}\"," ${ssr_qr_config_file}
  sed -i "8c \"ssrport\":\"${ssrport}\"" ${ssr_qr_config_file}
}

ssr_basic_information() {
  {
echo -e "
${GREEN} ─═———————————————— ▲ SSR+tls —————————————————═─
${YELLOW} ─═—————— SSR INFORMACION By ARGENTO ———————————═─
${GREEN} DOMINIO：   $(ssr_qr_info_extraction '\"domain\"')
${GREEN} PUERTO：   ${ssrport}
${GREEN} CONTRASEÑA：   ${password}
${GREEN} METHODO：  $(ssr_qr_info_extraction '\"method\"')
${GREEN} PROTOCOLO：  $(ssr_qr_info_extraction '\"protocol\"')
${GREEN} OBFUSCATION：  $(ssr_qr_info_extraction '\"obfs\"')
${YELLOW} ─═———— Compartir enlace y código QR——————————═─
${GREEN} compartir enlace：
${ssr_link}
${GREEN} codigo QR：  ${web_dir}/${uuid}.png
${YELLOW} ─═———————— VISITE SU SITIO WEB ———————————————═─
${GREEN} DETALLES：https://${domain}:${ssrport}/${uuid}.html${NO_COLOR}"
} | tee /etc/motd
}
trojan_basic_information() {
  {
echo -e "
${GREEN} ─═—————————————— ▲ ClashR+tls  —————————————————————═─
${YELLOW} ─═——————— ClashR INFORMACION By ARGENTO—————————————═─
${GREEN} DOMINIO：   $(trojan_info_extraction '\"domain\"')
${GREEN} PUERTO：   ${trojanport}
${GREEN} CONTRASEÑA 1：  $(trojan_info_extraction '\"password1\"')
${GREEN} CONTRASEÑA 2：  $(trojan_info_extraction '\"password2\"')
${YELLOW} ─═——————— Compartir enlace y código QR ————————————═─
${GREEN}COMPARTIR ENLACE CONTRASEÑA 1：
${trojan_link1}
${GREEN}COMPARTIR ENLACE CONTRASEÑA 2：
${trojan_link2}
${GREEN}CODIGO QR 1：  ${web_dir}/${uuid}-01.png
${GREEN}CODIGO QR 2：  ${web_dir}/${uuid}-02.png
${YELLOW} ─═————————————— VISITE SU SITIO WEB ———————————————═─
${GREEN}DETALLES：https://${domain}:${trojanport}/${uuid}.html${NO_COLOR}"
} | tee /etc/motd
}
v2ray_basic_information() {
  {
    echo -e "
${GREEN} ─═—————————————— ▲ V2ray+ws+tls ——————————————————═─
${YELLOW} ─═—————— V2ray INFORMACION By ARGENTO—————————═─
${GREEN} DIRECCION:       $(v2ray_info_extraction '\"add\"')
${GREEN} PUERTO：        ${webport}
${GREEN} UUID：      $(v2ray_info_extraction '\"id\"')
${GREEN} ALTERID：   64
${GREEN} security：SEGURIDAD
${GREEN} network： ws
${GREEN} type：    none
${GREEN} PATH：   /ray/
${GREEN} METODO：   tls
${YELLOW} ─═—————— Compartir enlace y código QR ———————————═─
${BLUE}enlace para cliente windows y android：
${GREEN}${v2ray_link2}
${BLUE}enlace para cliente IOS：
${GREEN}${v2ray_link1}
${BLUE}enlace de codigo QR para cliente windows y android：
${GREEN}${web_dir}/${uuid}-1.png
${BLUE}enlace de codigo QR para cliente windows y android：
${GREEN}${web_dir}/${uuid}-2.png
${YELLOW} ─═——————————— VISITE SU SITIO WEB ————————————————═─
${GREEN}DETALLES: https://$(v2ray_info_extraction '\"add\"'):${webport}/${uuid}.html${NO_COLOR}"
  } | tee /etc/motd
}

trojan_count_days(){
  if [[ -f ${trojan_qr_config_file} ]]; then
    trojan_info_extraction
    output_trojan_information
    end_time=$(echo | openssl s_client -servername "$domain" -connect "$domain":"${webport}" 2>/dev/null | openssl x509 -in /data/$domain/fullchain.crt -noout -dates |grep 'After'| awk -F '=' '{print $2}'| awk -F ' +' '{print $1,$2,$4 }' )
    end_times=$(date +%s -d "$end_time")
    now_time=$(date +%s -d "$(date | awk -F ' +'  '{print $2,$3,$6}')")
    RST=$(($((end_times-now_time))/(60*60*24)))
    echo -e "${GREEN}Los días restantes del período de validez del certificado son：${RST}${NO_COLOR}"
  fi
}
v2ray_count_days(){
  if [[ -f ${v2ray_win_and_android_qr_config_file} ]]; then
    v2ray_info_extraction
    output_v2ray_information
    end_time=$(echo | openssl s_client -servername "$domain" -connect "$domain":"${webport}" 2>/dev/null | openssl x509 -in /data/$domain/fullchain.crt -noout -dates |grep 'After'| awk -F '=' '{print $2}'| awk -F ' +' '{print $1,$2,$4 }' )
    end_times=$(date +%s -d "$end_time")
    now_time=$(date +%s -d "$(date | awk -F ' +'  '{print $2,$3,$6}')")
    RST=$(($((end_times-now_time))/(60*60*24)))
    echo -e "${GREEN}Los días restantes del período de validez del certificado son：${RST}${NO_COLOR}"
  fi
}
ssr_count_days(){
  if [[ -f ${trojan_qr_config_file} ]]; then
    ssr_qr_info_extraction
    output_ssr_information
    end_time=$(echo | openssl s_client -servername "$domain" -connect "$domain":"${webport}" 2>/dev/null | openssl x509 -in /data/$domain/fullchain.crt -noout -dates |grep 'After'| awk -F '=' '{print $2}'| awk -F ' +' '{print $1,$2,$4 }' )
    end_times=$(date +%s -d "$end_time")
    now_time=$(date +%s -d "$(date | awk -F ' +'  '{print $2,$3,$6}')")
    RST=$(($((end_times-now_time))/(60*60*24)))
    echo -e "${GREEN}Los días restantes del período de validez del certificado son：${RST}${NO_COLOR}"
  fi
}
set_port() {
    while true
    do
    dport=$(shuf -i 9000-19999 -n 1)
    echo -e "${Info}porfavor escribe$1 el numero de puerto[1-65535],NOTA:no se puede duplicar los puertos para v2ray、caddy、ClashR、SSR"
    read -rp "(puerto predeterminado: ${dport}):" port
    [ -z "$port" ] && port=${dport}
    expr "$port" + 1 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && [ "$port" != 0 ]; then
            echo
            echo -e "${Info}$1 el puerto es：$port"
            echo
            break
        fi
    fi
    echo -e "${Error} ingrese un puerto correcto[1-65535]"
    done
}
port_used_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${Info} $1 el puerto no esta ocupado"
        sleep 1
    else
        echo -e "${Error}se detecto $1 puerto ocupado $1 informacion de puerto ocupado ${Font}"
        lsof -i:"$1"
        echo -e "${Info} En 5s se eliminara el puerto ocupado"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${Info} se ha eliminado"
        sleep 1
    fi
}
left_second(){
    seconds_left=10
    echo "$1 Reiniciando,espere${seconds_left} segundos……"
    while [ $seconds_left -gt 0 ];do
      echo -n $seconds_left
      sleep 1
      seconds_left=$(($seconds_left - 1))
      echo -ne "\r     \r"
    done
}
change_nginx_port(){
  v2ray_info_extraction
  output_v2ray_information
  rm -f ${web_dir}/${uuid}-01.png
  rm -f ${web_dir}/${uuid}-02.png
  set_port nginx
  webport=$port
  port_used_check "${webport}"
  sed -i "2c listen ${webport} ssl http2;" ${nginx_conf}
  v2ray_qr_port_config
  v2ray_shadowrocket_qr_link_image
  v2ray_win_and_android_qr_link_image
  v2ray_info_html
  left_second ${webserver}
  systemctl restart nginx
  v2ray_basic_information
}
change_caddy_port(){
  v2ray_info_extraction
  output_v2ray_information
  rm -f ${web_dir}/${uuid}-01.png
  rm -f ${web_dir}/${uuid}-02.png
  set_port nginx
  webport=$port
  port_used_check "${webport}"
  sed -i "1c https://${domain}:${webport} {" ${caddy_conf}
  v2ray_qr_port_config
  v2ray_shadowrocket_qr_link_image
  v2ray_win_and_android_qr_link_image
  v2ray_info_html
  systemctl restart caddy.service
  left_second ${webserver}
  v2ray_basic_information
}
change_trojan_port(){
  trojan_info_extraction
  output_trojan_information
  remove_trojan_old_information
  set_port trojanport
  trojanport=$port
  port_used_check "${trojanport}"
  trojan_conf
  trojan_qr_link_image
  trojan_info_html
  trojan_qr_config
  systemctl restart trojan
  left_second ${webserver}
  trojan_basic_information
}
change_trojan_password(){
  trojan_info_extraction
  output_trojan_information
  remove_trojan_old_information
  input_trojan_password
  trojan_conf
  trojan_qr_link_image
  trojan_info_html
  trojan_qr_config
  systemctl restart trojan
  left_second ${webserver}
  trojan_basic_information
}
change_v2ray_uuid(){
  v2ray_info_extraction
  output_v2ray_information
  remove_v2ray_old_information
  v2ray_conf
  v2ray_qr_config
  v2ray_shadowrocket_qr_link_image
  v2ray_win_and_android_qr_link_image
  v2ray_info_html
  left_second ${webserver}
  service v2ray restart
  v2ray_basic_information
}
change_ssr_password(){
  ssr_qr_info_extraction
  output_ssr_information
  remove_ssr_old_information
  input_ssr_password
  ssr_conf
  ssr_qr_link_image
  ssr_info_html
  ssr_qr_config
  ssr_basic_information
}
change_ssr_port(){
  ssr_qr_info_extraction
  output_ssr_information
  remove_ssr_old_information
  set_port ssr
  ssrport=$port
  port_used_check "${ssrport}"
  ssr_conf
  ssr_qr_link_image
  ssr_info_html
  ssr_qr_config
  ssr_basic_information
}
main(){
  check_root
  if [[ -e "${nginx_bin_file}" ]] && [[ -e "${trojan_bin_dir}" ]]; then
      echo -e "
      $RED :::::::::::::::::::::::::::
      ${GREEN}  ▲ ClashR+nginx+tls
      $RED :::::::::::::::::::::::::::
      ${GREEN}1. DETENER ClashR        
      ${GREEN}2. REINICIAR ClashR
      ${GREEN}3. CAMBIAR CONTRASEÑA     
      ${GREEN}4. DETENER nginx
      ${GREEN}5. REINICIAR nginx          
      ${GREEN}6. CAMBIAR PUERTO
      ${GREEN}0. REGRESAR
      $RED ::::::::::::::::::::::::::${NO_COLOR}"
      read -rp "Ingrese el número de la acción que desea realizar:" aNum
      case $aNum in
          1)systemctl stop trojan
            echo -e  "${GREEN}trojan${NO_COLOR}"
          ;;
          2)systemctl restart trojan
            echo -e  "${GREEN}trojan${NO_COLOR}"
          ;;
          3)webserver=trojan
            change_trojan_password
          ;;
          4)systemctl stop nginx
            echo -e  "${GREEN}nginx${NO_COLOR}"
          ;;
          5)systemctl restart nginx
            echo -e  "${GREEN}nginx${NO_COLOR}"
          ;;
          6)webserver=trojan
            change_trojan_port
          ;;
          0)vpspack
          ;;
          *)echo -e "${RED}error de entrada！！！${NO_COLOR}"
            exit
          ;;
      esac
  elif [[ -e "${caddy_bin_dir}" ]] && [[ -e "${trojan_bin_dir}" ]]; then
      echo -e "
      $RED :::::::::::::::::::::::::::::
      ${GREEN}    ▲ ClashR+caddy+tls
      $RED :::::::::::::::::::::::::::::
      ${GREEN}1. DETENER ClashR            
      ${GREEN}2. REINICIAR ClashR
      ${GREEN}3. CAMBIAR CONTRASEÑA      
      ${GREEN}4. DETENER caddy
      ${GREEN}5. REINICIAR caddy              
      ${GREEN}6. CAMBIAR PUERTO
      ${GREEN}0. REGRESAR
      $RED ::::::::::::::::::::::::::::${NO_COLOR}"
      read -rp "Ingrese el número de la acción que desea realizar:" aNum
      case $aNum in
          1)systemctl stop trojan
            echo -e  "${GREEN}trojan${NO_COLOR}"
          ;;
          2)systemctl restart trojan
            echo -e  "${GREEN}trojan{NO_COLOR}"
          ;;
          3)webserver=trojan
            change_trojan_password
          ;;
          4)systemctl stop caddy.service
            echo -e  "${GREEN}caddy${NO_COLOR}"
          ;;
          5)systemctl restart caddy.service
            echo -e  "${GREEN}caddy${NO_COLOR}"
          ;;
          6)webserver=trojan
            change_trojan_port
          ;;
          0)vpspack
          ;;
          *)echo -e "${RED}error de entrada！！！${NO_COLOR}"
            exit
          ;;
      esac
  elif [[ -e "${nginx_bin_file}" ]] && [[ -e "${v2ray_bin_dir}/v2ray" ]]; then
       echo -e "
      $RED :::::::::::::::::::::::::::
      ${GREEN}    ▲ v2ray+nginx+tls
      $RED :::::::::::::::::::::::::::
      ${GREEN}1. DETENER v2ray          
      ${GREEN}2. REINICIAR v2ray
      ${GREEN}3. MODIFICAR UUID            
      ${GREEN}4. DETENER nginx
      ${GREEN}5. REINICIAR nginx          
      ${GREEN}6 ACTUALIZAR v2ray 
      ${GREEN}7. MODIFICAR PUERTO
      ${GREEN}0.↫ REGRESAR
      $RED :::::::::::::::::::::::::${NO_COLOR}"
      read -rp "Ingrese el número de la acción que desea realizar:" aNum
      case $aNum in
          1)service v2ray stop
            echo -e  "${GREEN}v2ray${NO_COLOR}"
          ;;
          2)service v2ray restart
            echo -e  "${GREEN}v2ray${NO_COLOR}"
          ;;
          3)webserver=v2ray
            change_v2ray_uuid
          ;;
          4)systemctl stop nginx
            echo -e  "${GREEN}nginx${NO_COLOR}"
          ;;
          5)systemctl restart nginx
            echo -e  "${GREEN}nginx${NO_COLOR}"
          ;;
          6)bash <(curl -L -s https://install.direct/go.sh)
            service v2ray restart
          ;;
          7)webserver=nginx
            change_nginx_port
          ;;
          0)vpspack
          ;;
          *)echo -e "${RED}error de entrada！！！${NO_COLOR}"
            exit
          ;;
      esac
  elif [[ -e "${caddy_bin_dir}" ]] && [[ -e "${v2ray_bin_dir}/v2ray" ]]; then
      echo -e "
      $FUCHSIA=======================================================
      ${GREEN}   v2ray+caddy+tls
      $FUCHSIA=======================================================
      ${GREEN}1. DETENER v2ray            ${GREEN}2. REINICIARv2ray
      $FUCHSIA=======================================================
      ${GREEN}3. MODIFICAR UUID             ${GREEN}4. DETENER caddy
      $FUCHSIA=======================================================
      ${GREEN}5. REINICIAR caddy            ${GREEN}6. DIAS RESTANTES TLS
      $FUCHSIA=======================================================
      ${GREEN}7. ACTUALIZAR TLS     ${GREEN}8. ACTUALIZAR v2ray core
      $FUCHSIA=======================================================
      ${GREEN}9. MODIFICAR PUERTO
      $FUCHSIA=======================================================
      ${GREEN}0. NO HACER NADA
      $FUCHSIA=======================================================${NO_COLOR}"
      read -rp "Ingrese el número de la acción que desea realizar:" aNum
      case $aNum in
          1)service v2ray stop
            echo -e  "${GREEN}v2ray服务停止${NO_COLOR}"
          ;;
          2)service v2ray restart
            echo -e  "${GREEN}v2ray服务启动${NO_COLOR}"
          ;;
          3)webserver=v2ray
            change_v2ray_uuid
          ;;
          4)systemctl stop caddy.service
            echo -e  "${GREEN}caddy服务停止${NO_COLOR}"
          ;;
          5)systemctl restart caddy.service
            echo -e  "${GREEN}caddy服务启动${NO_COLOR}"
          ;;
          6)v2ray_count_days
          ;;
          7)echo -e "EL CERTIFICADO SE ACTUALIZARA CADA 60 DIAS"
          ;;
          8)bash <(curl -L -s https://install.direct/go.sh)
            service v2ray restart
          ;;
          9)webserver=caddy
            change_caddy_port
          ;;
          0) exit
          ;;
          *)echo -e "${RED}error de entrada！！！${NO_COLOR}"
            exit
          ;;
      esac

  elif [[ -e "${caddy_bin_dir}" ]] && [[ -d "${ssr_bin_dir}" ]]; then
      echo -e "
      $RED :::::::::::::::::::::::::
      ${GREEN}   ▲ SSR+caddy+tls
      $RED :::::::::::::::::::::::::
      ${GREEN}1. DETENER SSR         
      ${GREEN}2. REINICIAR SSR
      ${GREEN}3. CAMBIAR CONTRASEÑA     
      ${GREEN}4. DETENER caddy
      ${GREEN}5. REINICAR caddy         
      ${GREEN}6. CAMBIAR PUERTO
      ${GREEN}0.↫ REGRESAR
      $RED ::::::::::::::::::::::::${NO_COLOR}"
      read -rp "Ingrese el número de la acción que desea realizar:" aNum
      case $aNum in
          1)/etc/init.d/shadowsocks-r stop
            echo -e  "${GREEN}ssr${NO_COLOR}"
          ;;
          2)/etc/init.d/shadowsocks-r restart
            echo -e  "${GREEN}ssr${NO_COLOR}"
          ;;
          3)change_ssr_password
            /etc/init.d/shadowsocks-r restart
          ;;
          4)systemctl stop caddy.service
            echo -e  "${GREEN}caddy${NO_COLOR}"
          ;;
          5)systemctl restart caddy.service
            echo -e  "${GREEN}caddy${NO_COLOR}"
          ;;
          6)change_ssr_port
            /etc/init.d/shadowsocks-r restart
          ;;
          0)vpspack
          ;;
          *)echo -e "${RED}error de entrada！！！${NO_COLOR}"
            exit
          ;;
      esac
  fi
}
main
