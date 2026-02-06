#!/bin/bash
#################### x-ui-pro v2.4.3 @ github.com/GFW4Fun ##############################################
set -o pipefail
trap '(( $? )) && printf "[ERROR] Script exited with code %d\n" "$?" >&2' EXIT

##############################Constants##################################################################
XUIDB="/etc/x-ui/x-ui.db"
IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
IP6_REGEX="([a-f0-9:]+:+)+[a-f0-9]+"
PKG_MGR=$(type apt &>/dev/null && echo "apt" || echo "yum")

# Color codes used by install_panel()
green='\033[0;32m'
red='\033[0;31m'
yellow='\033[0;33m'
blue='\033[0;34m'
plain='\033[0m'

##############################Message Helpers#############################################################
msg_ok()  { printf '\e[1;42m %s \e[0m\n' "$1"; }
msg_err() { printf '\e[1;41m %s \e[0m\n' "$1"; }
msg_inf() { printf '\e[1;34m%s\e[0m\n' "$1"; }
die()     { msg_err "$1"; exit "${2:-1}"; }
warn()    { printf '\e[1;33mWARN: %s\e[0m\n' "$1" >&2; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

##############################Root Check##################################################################
ensure_root() {
	if [[ $EUID -ne 0 ]]; then
		msg_inf "Not root, re-executing with sudo..."
		exec sudo -E bash "$0" "$@"
	fi
}
ensure_root "$@"

##############################Banner######################################################################
show_banner() {
	echo
	msg_inf '           ___    _   _   _  '
	msg_inf ' \/ __ | |  | __ |_) |_) / \ '
	msg_inf ' /\    |_| _|_   |   | \ \_/ '
	echo
}
show_banner

##############################OS & CPU Preflight Check####################################################
check_os() {
	if [[ ! -f /etc/os-release ]]; then
		msg_err "Cannot detect OS: /etc/os-release not found."
		return 1
	fi
	. /etc/os-release
	OS_ID="${ID,,}"
	local os_ver="${VERSION_ID%%.*}"
	case "$OS_ID" in
		ubuntu)
			if [[ -n "$os_ver" ]] && (( os_ver < 24 )); then
				msg_err "Unsupported OS: Ubuntu $VERSION_ID detected. Ubuntu 24+ is required. Please upgrade your OS."
				return 1
			fi
			;;
		debian)
			if [[ -n "$os_ver" ]] && (( os_ver < 12 )); then
				msg_err "Unsupported OS: Debian $VERSION_ID detected. Debian 12 or 13 is required. Please upgrade your OS."
				return 1
			fi
			;;
		*)
			msg_err "Unsupported OS: $PRETTY_NAME. Only Ubuntu 24+ and Debian 12/13 are supported."
			return 1
			;;
	esac
	return 0
}

check_cpu() {
	local cpu_model
	cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)
	if [[ "$cpu_model" == *"QEMU"* ]]; then
		msg_err "QEMU virtual CPU detected ($cpu_model). Please contact your hosting provider's support and request changing the CPU model to host CPU."
		return 1
	fi
	return 0
}

preflight_checks() {
	local fail=0
	check_os  || fail=1
	check_cpu || fail=1
	if (( fail )); then
		die "Preflight checks failed. Exiting."
	fi
	# Initialize release for install_panel() Alpine checks
	release="$OS_ID"
}
preflight_checks

##############################IP Detection################################################################
detect_ips() {
	IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po -- 'src \K\S*')
	[[ "$IP4" =~ $IP4_REGEX ]] || IP4=$(curl -s ipv4.icanhazip.com | tr -d '[:space:]')
	IP6=$(ip route get 2620:fe::fe 2>&1 | grep -Po -- 'src \K\S*')
	[[ "$IP6" =~ $IP6_REGEX ]] || IP6=$(curl -s ipv6.icanhazip.com | tr -d '[:space:]')
}

resolve_to_ip() {
	local host="$1"
	local a
	a=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
	[[ -n "$a" ]] && [[ "$a" == "$IP4" ]]
}

##############################Port & String Generators####################################################
get_random_port() {
	echo $(( ((RANDOM<<15)|RANDOM) % 49152 + 10000 ))
}

gen_random_string() {
	local length="$1"
	head -c 4096 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$length"
	echo
}

port_in_use() {
	local port="$1"
	nc -z 127.0.0.1 "$port" &>/dev/null
}

make_port() {
	local p
	while true; do
		p=$(get_random_port)
		if ! port_in_use "$p"; then
			echo "$p"
			break
		fi
	done
}

##############################Architecture Detection######################################################
arch() {
	case "$(uname -m)" in
		x86_64 | x64 | amd64) echo 'amd64' ;;
		i*86 | x86) echo '386' ;;
		armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
		armv7* | armv7 | arm) echo 'armv7' ;;
		armv6* | armv6) echo 'armv6' ;;
		armv5* | armv5) echo 'armv5' ;;
		s390x) echo 's390x' ;;
		*) printf '%bUnsupported CPU architecture!%b\n' "${green}" "${plain}" && exit 1 ;;
	esac
}

##############################Sysctl Idempotent Writer#####################################################
sysctl_ensure() {
	local key="$1" value="$2"
	local entry="$key=$value"
	if grep -q "^${key}[[:space:]]*=" /etc/sysctl.conf 2>/dev/null; then
		sed -i "s|^${key}[[:space:]]*=.*|${entry}|" /etc/sysctl.conf
	else
		echo "$entry" >> /etc/sysctl.conf
	fi
}

##############################Argument Parsing############################################################
parse_args() {
	domain=""
	UNINSTALL="x"
	INSTALL="n"
	PNLNUM=1
	CFALLOW="n"
	CLASH=0
	CUSTOMWEBSUB=0
	AUTODOMAIN="n"

	while [[ "$#" -gt 0 ]]; do
		case "$1" in
			-auto_domain) AUTODOMAIN="$2"; shift 2;;
			-install) INSTALL="$2"; shift 2;;
			-panel) PNLNUM="$2"; shift 2;;
			-subdomain) domain="$2"; shift 2;;
			-reality_domain) reality_domain="$2"; shift 2;;
			-ONLY_CF_IP_ALLOW) CFALLOW="$2"; shift 2;;
			-websub) CUSTOMWEBSUB="$2"; shift 2;;
			-clash) CLASH="$2"; shift 2;;
			-uninstall) UNINSTALL="$2"; shift 2;;
			*) shift 1;;
		esac
	done
}

##############################Uninstall###################################################################
uninstall_xui() {
	printf 'y\n' | x-ui uninstall
	rm -rf "/etc/x-ui/" "/usr/local/x-ui/" "/usr/bin/x-ui/"
	"$PKG_MGR" -y remove nginx nginx-common nginx-core nginx-full python3-certbot-nginx
	"$PKG_MGR" -y purge nginx nginx-common nginx-core nginx-full python3-certbot-nginx
	"$PKG_MGR" -y autoremove
	"$PKG_MGR" -y autoclean
	rm -rf "/var/www/html/" "/etc/nginx/" "/usr/share/nginx/"
}

##############################Clean Previous Install######################################################
clean_previous_install() {
	systemctl stop x-ui 2>/dev/null
	rm -rf /etc/systemd/system/x-ui.service
	rm -rf /usr/local/x-ui
	rm -rf /etc/x-ui
	rm -rf /etc/nginx/sites-enabled/*
	rm -rf /etc/nginx/sites-available/*
	rm -rf /etc/nginx/stream-enabled/*
}

##############################Install Packages############################################################
install_packages() {
	if [[ "${INSTALL}" == *"y"* ]]; then
		"$PKG_MGR" -y update
		"$PKG_MGR" -y install curl wget jq bash sudo nginx-full certbot python3-certbot-nginx sqlite3 ufw
		systemctl daemon-reload && systemctl enable --now nginx
	fi
	systemctl stop nginx
	fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null
}

##############################SSL Helper##################################################################
obtain_ssl() {
	local cert_domain="$1"
	certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "$cert_domain"
	if [[ ! -d "/etc/letsencrypt/live/${cert_domain}/" ]]; then
		systemctl start nginx >/dev/null 2>&1
		die "$cert_domain SSL could not be generated! Check Domain/IP Or Enter new domain!"
	fi
}

##############################Nginx Config################################################################
setup_nginx() {
	mkdir -p "/root/cert/${domain}"
	chmod 700 /root/cert/*

	ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" "/root/cert/${domain}/fullchain.pem"
	ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem" "/root/cert/${domain}/privkey.pem"

	mkdir -p /etc/nginx/stream-enabled
	cat > "/etc/nginx/stream-enabled/stream.conf" << EOF
map \$ssl_preread_server_name \$sni_name {
    hostnames;
    ${reality_domain}      xray;
    ${domain}           www;
    default              xray;
}

upstream xray {
    server 127.0.0.1:8443;
}

upstream www {
    server 127.0.0.1:7443;
}

server {
    proxy_protocol on;
    set_real_ip_from unix:;
    listen          443;
    proxy_pass      \$sni_name;
    ssl_preread     on;
}

EOF

	grep -qF "stream { include /etc/nginx/stream-enabled/*.conf; }" /etc/nginx/nginx.conf || echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf

	# --- ngx_stream_module: load only if not already available ---
	# The module may be: (a) compiled statically, (b) loaded via /etc/nginx/modules-enabled/,
	# or (c) already present in nginx.conf from a previous run.  Adding a duplicate load_module
	# causes "module is already loaded" and Nginx refuses to start.
	if nginx -V 2>&1 | grep -q -- '--with-stream\b'; then
		msg_inf "stream module is compiled statically, skipping load_module"
	elif ls /etc/nginx/modules-enabled/*stream* &>/dev/null; then
		msg_inf "stream module already enabled via modules-enabled, skipping load_module"
	elif grep -qF "load_module" /etc/nginx/nginx.conf 2>/dev/null \
	     && grep -qF "ngx_stream_module" /etc/nginx/nginx.conf 2>/dev/null; then
		msg_inf "stream module already loaded in nginx.conf, skipping"
	elif [[ -f /usr/lib/nginx/modules/ngx_stream_module.so ]]; then
		sed -i '1s|^|load_module /usr/lib/nginx/modules/ngx_stream_module.so; \n|' /etc/nginx/nginx.conf
		msg_inf "stream module loaded dynamically via load_module"
	else
		warn "ngx_stream_module.so not found and stream not built-in; install libnginx-mod-stream"
	fi

	# --- ngx_stream_geoip2_module: same logic ---
	if ls /etc/nginx/modules-enabled/*geoip2* &>/dev/null; then
		msg_inf "stream geoip2 module already enabled via modules-enabled, skipping"
	elif grep -qF "ngx_stream_geoip2_module" /etc/nginx/nginx.conf 2>/dev/null; then
		msg_inf "stream geoip2 module already loaded in nginx.conf, skipping"
	elif [[ -f /usr/lib/nginx/modules/ngx_stream_geoip2_module.so ]]; then
		sed -i '1s|^|load_module /usr/lib/nginx/modules/ngx_stream_geoip2_module.so; \n|' /etc/nginx/nginx.conf
		msg_inf "stream geoip2 module loaded dynamically via load_module"
	else
		warn "ngx_stream_geoip2_module.so not found; geoip2 filtering will not work"
	fi

	grep -qF "worker_rlimit_nofile 16384;" /etc/nginx/nginx.conf || echo "worker_rlimit_nofile 16384;" >> /etc/nginx/nginx.conf
	sed -i "/worker_connections/c\worker_connections 4096;" /etc/nginx/nginx.conf

	cat > "/etc/nginx/sites-available/80.conf" << EOF
server {
    listen 80;
    server_name ${domain} ${reality_domain};
    return 301 https://\$host\$request_uri;
}
EOF

	cat > "/etc/nginx/sites-available/${domain}" << EOF
server {
	server_tokens off;
	server_name ${domain};
	listen 7443 ssl http2 proxy_protocol;
	listen [::]:7443 ssl http2 proxy_protocol;
	index index.html index.htm index.php index.nginx-debian.html;
	root /var/www/html/;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
	ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
	if (\$host !~* ^(.+\.)?$domain\$ ){return 444;}
	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^(.+\.)?$domain\$ ) {set \$safe "\${safe}0"; }
	if (\$safe = 10){return 444;}
	if (\$request_uri ~ "(\"|'|\`|~|,|:|--|;|%|\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)"){set \$hack 1;}
	error_page 400 401 402 403 500 501 502 503 504 =404 /404;
	proxy_intercept_errors on;
	#X-UI Admin Panel
	location /${panel_path}/ {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        proxy_pass https://127.0.0.1:${panel_port};
		break;
	}
        location /${panel_path} {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        proxy_pass https://127.0.0.1:${panel_port};
		break;
	}
	include /etc/nginx/snippets/includes.conf;

}
EOF

	cat > "/etc/nginx/snippets/includes.conf" << EOF
  	#sub2sing-box
	location /${sub2singbox_path}/ {
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:8080/;
		}
    # Path to open clash.yaml and generate YAML
    location ~ ^/${web_path}/clashmeta/(.+)$ {
        default_type text/plain;
        ssi on;
        ssi_types text/plain;
        set \$subid \$1;
        root /var/www/subpage;
        try_files /clash.yaml =404;
    }
    # web
    location ~ ^/${web_path} {
        root /var/www/subpage;
        index index.html;
        try_files \$uri \$uri/ /index.html =404;
    }
 	#Subscription Path (simple/encode)
        location /${sub_path} {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass https://127.0.0.1:${sub_port};
                break;
        }
	location /${sub_path}/ {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass https://127.0.0.1:${sub_port};
                break;
        }
	location /assets/ {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass https://127.0.0.1:${sub_port};
                break;
        }
	location /assets {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass https://127.0.0.1:${sub_port};
                break;
        }
	#Subscription Path (json/fragment)
        location /${json_path} {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass https://127.0.0.1:${sub_port};
                break;
        }
	location /${json_path}/ {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass https://127.0.0.1:${sub_port};
                break;
        }
        #XHTTP
        location /${xhttp_path} {
          grpc_pass grpc://unix:/dev/shm/uds2023.sock;
          grpc_buffer_size         16k;
          grpc_socket_keepalive    on;
          grpc_read_timeout        1h;
          grpc_send_timeout        1h;
          grpc_set_header Connection         "";
          grpc_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
          grpc_set_header X-Forwarded-Proto  \$scheme;
          grpc_set_header X-Forwarded-Port   \$server_port;
          grpc_set_header Host               \$host;
          grpc_set_header X-Forwarded-Host   \$host;
          }
 	#Xray Config Path
	location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)\$ {
		if (\$hack = 1) {return 404;}
		client_max_body_size 0;
		client_body_timeout 1d;
		grpc_read_timeout 1d;
		grpc_socket_keepalive on;
		proxy_read_timeout 1d;
		proxy_http_version 1.1;
		proxy_buffering off;
		proxy_request_buffering off;
		proxy_socket_keepalive on;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		#proxy_set_header CF-IPCountry \$http_cf_ipcountry;
		#proxy_set_header CF-IP \$realip_remote_addr;
		if (\$content_type ~* "GRPC") {
			grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args;
			break;
		}
		if (\$http_upgrade ~* "(WEBSOCKET|WS)") {
			proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
			break;
	        }
		if (\$request_method ~* ^(PUT|POST|GET)\$) {
			proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
			break;
		}
	}
	location / { try_files \$uri \$uri/ =404; }
EOF

	cat > "/etc/nginx/sites-available/${reality_domain}" << EOF
server {
	server_tokens off;
	server_name ${reality_domain};
	listen 9443 ssl http2;
	listen [::]:9443 ssl http2;
	index index.html index.htm index.php index.nginx-debian.html;
	root /var/www/html/;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
	ssl_certificate /etc/letsencrypt/live/$reality_domain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$reality_domain/privkey.pem;
	if (\$host !~* ^(.+\.)?${reality_domain}\$ ){return 444;}
	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^(.+\.)?${reality_domain}\$ ) {set \$safe "\${safe}0"; }
	if (\$safe = 10){return 444;}
	if (\$request_uri ~ "(\"|'|\`|~|,|:|--|;|%|\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)"){set \$hack 1;}
	error_page 400 401 402 403 500 501 502 503 504 =404 /404;
	proxy_intercept_errors on;
	#X-UI Admin Panel
	location /${panel_path}/ {
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:${panel_port};
		break;
	}
        location /$panel_path {
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:${panel_port};
		break;
	}
include /etc/nginx/snippets/includes.conf;
}
EOF
}

##############################Enable Nginx Sites##########################################################
enable_nginx_sites() {
	if [[ -f "/etc/nginx/sites-available/${domain}" ]]; then
		unlink "/etc/nginx/sites-enabled/default" >/dev/null 2>&1
		rm -f "/etc/nginx/sites-enabled/default" "/etc/nginx/sites-available/default"
		ln -sf "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/"
		ln -sf "/etc/nginx/sites-available/${reality_domain}" "/etc/nginx/sites-enabled/"
		ln -sf "/etc/nginx/sites-available/80.conf" "/etc/nginx/sites-enabled/"
	else
		die "${domain} nginx config not exist!"
	fi

	if [[ $(nginx -t 2>&1 | grep -o 'successful') != "successful" ]]; then
		die "nginx config is not ok!"
	else
		systemctl start nginx
	fi
}

##############################Read Existing XUI DB########################################################
read_existing_xui_db() {
	if [[ -f "$XUIDB" ]]; then
		XUIPORT=$(sqlite3 -list "$XUIDB" 'SELECT "value" FROM settings WHERE "key"="webPort" LIMIT 1;' 2>&1)
		XUIPATH=$(sqlite3 -list "$XUIDB" 'SELECT "value" FROM settings WHERE "key"="webBasePath" LIMIT 1;' 2>&1)
		if [[ "$XUIPORT" -gt 0 && "$XUIPORT" != "54321" && "$XUIPORT" != "2053" ]] && [[ ${#XUIPORT} -gt 4 ]]; then
			RNDSTR=$(echo "$XUIPATH" 2>&1 | tr -d '/')
			PORT=$XUIPORT
			sqlite3 "$XUIDB" <<EOF
	DELETE FROM "settings" WHERE ( "key"="webCertFile" ) OR ( "key"="webKeyFile" );
	INSERT INTO "settings" ("key", "value") VALUES ("webCertFile",  "");
	INSERT INTO "settings" ("key", "value") VALUES ("webKeyFile", "");
EOF
		fi
	fi
}

##############################Update XUI DB###############################################################
update_xui_db() {
if [[ -f "$XUIDB" ]]; then
        x-ui stop
        output=$(/usr/local/x-ui/bin/xray-linux-amd64 x25519)

        private_key=$(echo "$output" | grep "^PrivateKey:" | awk '{print $2}')
        public_key=$(echo "$output" | grep "^Password:" | awk '{print $2}')

        client_id=$(/usr/local/x-ui/bin/xray-linux-amd64 uuid)
        client_id2=$(/usr/local/x-ui/bin/xray-linux-amd64 uuid)
        client_id3=$(/usr/local/x-ui/bin/xray-linux-amd64 uuid)
	trojan_pass=$(gen_random_string 10)
        emoji_flag=$(LC_ALL=en_US.UTF-8 curl -s https://ipwho.is/ | jq -r '.flag.emoji')

	# Generate shortIds via loop
	local shor=()
	local i
	for i in {1..8}; do
		shor+=("$(openssl rand -hex 8)")
	done

       	sqlite3 "$XUIDB" <<EOF
             INSERT INTO "settings" ("key", "value") VALUES ("subPort",  '${sub_port}');
	     INSERT INTO "settings" ("key", "value") VALUES ("subPath",  '/${sub_path}/');
	     INSERT INTO "settings" ("key", "value") VALUES ("subURI",  '${sub_uri}');
             INSERT INTO "settings" ("key", "value") VALUES ("subJsonPath",  '${json_path}');
	     INSERT INTO "settings" ("key", "value") VALUES ("subJsonURI",  '${json_uri}');
             INSERT INTO "settings" ("key", "value") VALUES ("subEnable",  'true');
             INSERT INTO "settings" ("key", "value") VALUES ("webListen",  '');
	     INSERT INTO "settings" ("key", "value") VALUES ("webDomain",  '');
             INSERT INTO "settings" ("key", "value") VALUES ("webCertFile",  '');
	     INSERT INTO "settings" ("key", "value") VALUES ("webKeyFile",  '');
      	     INSERT INTO "settings" ("key", "value") VALUES ("sessionMaxAge",  '60');
             INSERT INTO "settings" ("key", "value") VALUES ("pageSize",  '50');
             INSERT INTO "settings" ("key", "value") VALUES ("expireDiff",  '0');
             INSERT INTO "settings" ("key", "value") VALUES ("trafficDiff",  '0');
             INSERT INTO "settings" ("key", "value") VALUES ("remarkModel",  '-ieo');
             INSERT INTO "settings" ("key", "value") VALUES ("tgBotEnable",  'false');
             INSERT INTO "settings" ("key", "value") VALUES ("tgBotToken",  '');
             INSERT INTO "settings" ("key", "value") VALUES ("tgBotProxy",  '');
             INSERT INTO "settings" ("key", "value") VALUES ("tgBotAPIServer",  '');
	     INSERT INTO "settings" ("key", "value") VALUES ("tgBotChatId",  '');
             INSERT INTO "settings" ("key", "value") VALUES ("tgRunTime",  '@daily');
	     INSERT INTO "settings" ("key", "value") VALUES ("tgBotBackup",  'false');
             INSERT INTO "settings" ("key", "value") VALUES ("tgBotLoginNotify",  'true');
	     INSERT INTO "settings" ("key", "value") VALUES ("tgCpu",  '80');
             INSERT INTO "settings" ("key", "value") VALUES ("tgLang",  'en-US');
	     INSERT INTO "settings" ("key", "value") VALUES ("timeLocation",  'Europe/Moscow');
             INSERT INTO "settings" ("key", "value") VALUES ("secretEnable",  'false');
	     INSERT INTO "settings" ("key", "value") VALUES ("subDomain",  '');
             INSERT INTO "settings" ("key", "value") VALUES ("subCertFile",  '');
	     INSERT INTO "settings" ("key", "value") VALUES ("subKeyFile",  '');
             INSERT INTO "settings" ("key", "value") VALUES ("subUpdates",  '12');
	     INSERT INTO "settings" ("key", "value") VALUES ("subEncrypt",  'true');
             INSERT INTO "settings" ("key", "value") VALUES ("subShowInfo",  'true');
	     INSERT INTO "settings" ("key", "value") VALUES ("subJsonFragment",  '');
             INSERT INTO "settings" ("key", "value") VALUES ("subJsonNoises",  '');
	     INSERT INTO "settings" ("key", "value") VALUES ("subJsonMux",  '');
             INSERT INTO "settings" ("key", "value") VALUES ("subJsonRules",  '');
	     INSERT INTO "settings" ("key", "value") VALUES ("datepicker",  'gregorian');
             INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset") VALUES ('1','1','first','0','0','0','0','0');
	     INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset") VALUES ('2','1','first_1','0','0','0','0','0');
		   INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset") VALUES ('3','1','firstX','0','0','0','0','0');
	     INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset") VALUES ('4','1','firstT','0','0','0','0','0');
             INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing") VALUES (
             '1',
	     '0',
             '0',
	     '0',
             '${emoji_flag} reality',
	     '1',
             '0',
	     '',
             '8443',
	     'vless',
             '{
	     "clients": [
    {
      "id": "${client_id}",
      "flow": "xtls-rprx-vision",
      "email": "first",
      "limitIp": 0,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": true,
      "tgId": "",
      "subId": "first",
      "reset": 0,
      "created_at": 1756726925000,
      "updated_at": 1756726925000

    }
  ],
  "decryption": "none",
  "fallbacks": []
}',
	     '{
  "network": "tcp",
  "security": "reality",
  "externalProxy": [
    {
      "forceTls": "same",
      "dest": "${domain}",
      "port": 443,
      "remark": ""
    }
  ],
  "realitySettings": {
    "show": false,
    "xver": 0,
    "target": "127.0.0.1:9443",
    "serverNames": [
      "$reality_domain"
    ],
    "privateKey": "${private_key}",
    "minClient": "",
    "maxClient": "",
    "maxTimediff": 0,
    "shortIds": [
      "${shor[0]}",
      "${shor[1]}",
      "${shor[2]}",
      "${shor[3]}",
      "${shor[4]}",
      "${shor[5]}",
      "${shor[6]}",
      "${shor[7]}"
    ],
    "settings": {
      "publicKey": "${public_key}",
      "fingerprint": "random",
      "serverName": "",
      "spiderX": "/"
    }
  },
  "tcpSettings": {
    "acceptProxyProtocol": true,
    "header": {
      "type": "none"
    }
  }
}',
             'inbound-8443',
	     '{
  "enabled": false,
  "destOverride": [
    "http",
    "tls",
    "quic",
    "fakedns"
  ],
  "metadataOnly": false,
  "routeOnly": false
}'
	     );
      INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing") VALUES (
             '1',
	     '0',
             '0',
	     '0',
             '${emoji_flag} ws',
	     '1',
             '0',
	     '',
             '${ws_port}',
	     'vless',
             '{
  "clients": [
    {
      "id": "${client_id2}",
      "flow": "",
      "email": "first_1",
      "limitIp": 0,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": true,
      "tgId": "",
      "subId": "first",
      "reset": 0,
      "created_at": 1756726925000,
      "updated_at": 1756726925000

    }
  ],
  "decryption": "none",
  "fallbacks": []
}','{
  "network": "ws",
  "security": "none",
  "externalProxy": [
    {
      "forceTls": "tls",
      "dest": "${domain}",
      "port": 443,
      "remark": ""
    }
  ],
  "wsSettings": {
    "acceptProxyProtocol": false,
    "path": "/${ws_port}/${ws_path}",
    "host": "${domain}",
    "headers": {}
  }
}',
             'inbound-${ws_port}',
	     '{
  "enabled": false,
  "destOverride": [
    "http",
    "tls",
    "quic",
    "fakedns"
  ],
  "metadataOnly": false,
  "routeOnly": false
}'
	     );
      INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing") VALUES (
             '1',
	     '0',
             '0',
	     '0',
             '${emoji_flag} xhttp',
	     '1',
             '0',
	     '/dev/shm/uds2023.sock,0666',
             '0',
	     'vless',
             '{
  "clients": [
    {
      "id": "${client_id3}",
      "flow": "",
      "email": "firstX",
      "limitIp": 0,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": true,
      "tgId": "",
      "subId": "first",
      "reset": 0,
	  "created_at": 1756726925000,
      "updated_at": 1756726925000
    }
  ],
  "decryption": "none",
  "fallbacks": []
}','{
  "network": "xhttp",
  "security": "none",
  "externalProxy": [
    {
      "forceTls": "tls",
      "dest": "${domain}",
      "port": 443,
      "remark": ""
    }
  ],
  "xhttpSettings": {
    "path": "/${xhttp_path}",
    "host": "",
    "headers": {},
    "scMaxBufferedPosts": 30,
    "scMaxEachPostBytes": "1000000",
    "noSSEHeader": false,
    "xPaddingBytes": "100-1000",
    "mode": "packet-up"
  },
  "sockopt": {
    "acceptProxyProtocol": false,
    "tcpFastOpen": true,
    "mark": 0,
    "tproxy": "off",
    "tcpMptcp": true,
    "tcpNoDelay": true,
    "domainStrategy": "UseIP",
    "tcpMaxSeg": 1440,
    "dialerProxy": "",
    "tcpKeepAliveInterval": 0,
    "tcpKeepAliveIdle": 300,
    "tcpUserTimeout": 10000,
    "tcpcongestion": "bbr",
    "V6Only": false,
    "tcpWindowClamp": 600,
    "interface": ""
  }
}',
             'inbound-/dev/shm/uds2023.sock,0666:0|',
	     '{
  "enabled": true,
  "destOverride": [
    "http",
    "tls",
    "quic",
    "fakedns"
  ],
  "metadataOnly": false,
  "routeOnly": false
}'
	     );
	INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing") VALUES (
	     '1',
	     '0',
         '0',
	     '0',
         '${emoji_flag} trojan-grpc',
	     '1',
         '0',
		 '',
		 '${trojan_port}',
		 'trojan',
		 '{
  "clients": [
    {
      "comment": "",
      "created_at": 1756726925000,
      "email": "firstT",
      "enable": true,
      "expiryTime": 0,
      "limitIp": 0,
      "password": "${trojan_pass}",
      "reset": 0,
      "subId": "first",
      "tgId": 0,
      "totalGB": 0,
      "updated_at": 1756726925000
    }
  ],
  "fallbacks": []
}',
'{
  "network": "grpc",
  "security": "none",
  "externalProxy": [
    {
      "forceTls": "tls",
      "dest": "${domain}",
      "port": 443,
      "remark": ""
    }
  ],
  "grpcSettings": {
    "serviceName": "/${trojan_port}/${trojan_path}",
    "authority": "${domain}",
    "multiMode": false
  }
}',
'inbound-${trojan_port}',
'{
  "enabled": false,
  "destOverride": [
    "http",
    "tls",
    "quic",
    "fakedns"
  ],
  "metadataOnly": false,
  "routeOnly": false
}'
	);
EOF
/usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${panel_port}" -webBasePath "${panel_path}"
/usr/local/x-ui/x-ui cert -webCert "/root/cert/${domain}/fullchain.pem" -webCertKey "/root/cert/${domain}/privkey.pem"
x-ui start
else
	die "x-ui.db file not exist! Maybe x-ui isn't installed."
fi
}

##############################Config After Install########################################################
config_after_install() {
	/usr/local/x-ui/x-ui setting -username "asdfasdf" -password "asdfasdf" -port "2096" -webBasePath "asdfasdf"
	/usr/local/x-ui/x-ui migrate
}

##############################Install Panel###############################################################
install_panel() {
apt-get update && apt-get install -y -q wget curl tar tzdata
    cd /usr/local/

    # Download resources
    if [ $# == 0 ]; then
        tag_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            printf '%bTrying to fetch version with IPv4...%b\n' "${yellow}" "${plain}"
            tag_version=$(curl -4 -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            if [[ ! -n "$tag_version" ]]; then
                printf '%bFailed to fetch x-ui version, it may be due to GitHub API restrictions, please try it later%b\n' "${red}" "${plain}"
                exit 1
            fi
        fi
        echo -e "Got x-ui latest version: ${tag_version}, beginning the installation..."
        wget -N -O /usr/local/x-ui-linux-$(arch).tar.gz https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            printf '%bDownloading x-ui failed, please be sure that your server can access GitHub%b\n' "${red}" "${plain}"
            exit 1
        fi
    else
        tag_version=$1
        tag_version_numeric=${tag_version#v}
        min_version="2.3.5"

        if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
            printf '%bPlease use a newer version (at least v2.3.5). Exiting installation.%b\n' "${red}" "${plain}"
            exit 1
        fi

        url="https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
        echo -e "Beginning to install x-ui $1"
        wget -N -O /usr/local/x-ui-linux-$(arch).tar.gz ${url}
        if [[ $? -ne 0 ]]; then
            printf '%bDownload x-ui %s failed, please check if the version exists%b\n' "${red}" "$1" "${plain}"
            exit 1
        fi
    fi
    wget -O /usr/bin/x-ui-temp https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh
    if [[ $? -ne 0 ]]; then
        printf '%bFailed to download x-ui.sh%b\n' "${red}" "${plain}"
        exit 1
    fi

    # Stop x-ui service and remove old resources
    if [[ -e /usr/local/x-ui/ ]]; then
        if [[ "$release" == "alpine" ]]; then
            rc-service x-ui stop
        else
            systemctl stop x-ui
        fi
        rm /usr/local/x-ui/ -rf
    fi

    # Extract resources and set permissions
    tar zxvf x-ui-linux-$(arch).tar.gz
    rm x-ui-linux-$(arch).tar.gz -f

    cd x-ui
    chmod +x x-ui
    chmod +x x-ui.sh

    # Check the system's architecture and rename the file accordingly
    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi
    chmod +x x-ui bin/xray-linux-$(arch)

    # Update x-ui cli and se set permission
    mv -f /usr/bin/x-ui-temp /usr/bin/x-ui
    chmod +x /usr/bin/x-ui
	config_after_install

    if [[ "$release" == "alpine" ]]; then
        wget --inet4-only -O /etc/init.d/x-ui https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.rc
        if [[ $? -ne 0 ]]; then
            printf '%bFailed to download x-ui.rc%b\n' "${red}" "${plain}"
            exit 1
        fi
        chmod +x /etc/init.d/x-ui
        rc-update add x-ui
        rc-service x-ui start
    else
        cp -f x-ui.service.debian /etc/systemd/system/x-ui.service
        systemctl daemon-reload
        systemctl enable x-ui
        systemctl start x-ui
    fi

    printf '%bx-ui %s%b installation finished, it is running now...\n' "${green}" "${tag_version}" "${plain}"
    echo -e ""
    printf '┌───────────────────────────────────────────────────────┐
│  %bx-ui control menu usages (subcommands):%b              │
│                                                       │
│  %bx-ui%b              - Admin Management Script          │
│  %bx-ui start%b        - Start                            │
│  %bx-ui stop%b         - Stop                             │
│  %bx-ui restart%b      - Restart                          │
│  %bx-ui status%b       - Current Status                   │
│  %bx-ui settings%b     - Current Settings                 │
│  %bx-ui enable%b       - Enable Autostart on OS Startup   │
│  %bx-ui disable%b      - Disable Autostart on OS Startup  │
│  %bx-ui log%b          - Check logs                       │
│  %bx-ui banlog%b       - Check Fail2ban ban logs          │
│  %bx-ui update%b       - Update                           │
│  %bx-ui legacy%b       - Legacy version                   │
│  %bx-ui install%b      - Install                          │
│  %bx-ui uninstall%b    - Uninstall                        │
└───────────────────────────────────────────────────────┘\n' \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}" \
    "${blue}" "${plain}"

}

##############################Tune System#################################################################
tune_system() {
	apt-get install -yqq --no-install-recommends ca-certificates
	sysctl_ensure "net.core.default_qdisc" "fq"
	sysctl_ensure "net.ipv4.tcp_congestion_control" "bbr"
	sysctl_ensure "fs.file-max" "2097152"
	sysctl_ensure "net.ipv4.tcp_timestamps" "1"
	sysctl_ensure "net.ipv4.tcp_sack" "1"
	sysctl_ensure "net.ipv4.tcp_window_scaling" "1"
	sysctl_ensure "net.core.rmem_max" "16777216"
	sysctl_ensure "net.core.wmem_max" "16777216"
	sysctl_ensure "net.ipv4.tcp_rmem" "4096 87380 16777216"
	sysctl_ensure "net.ipv4.tcp_wmem" "4096 65536 16777216"
	sysctl -p
}

##############################Install sub2sing-box########################################################
install_sub2singbox() {
	if pgrep -x "sub2sing-box" > /dev/null; then
		echo "kill sub2sing-box..."
		pkill -x "sub2sing-box"
	fi
	if [ -f "/usr/bin/sub2sing-box" ]; then
		echo "delete sub2sing-box..."
		rm -f /usr/bin/sub2sing-box
	fi
	wget -P /root/ https://github.com/legiz-ru/sub2sing-box/releases/download/v0.0.9/sub2sing-box_0.0.9_linux_amd64.tar.gz
	tar -xvzf /root/sub2sing-box_0.0.9_linux_amd64.tar.gz -C /root/ --strip-components=1 sub2sing-box_0.0.9_linux_amd64/sub2sing-box
	mv /root/sub2sing-box /usr/bin/
	chmod +x /usr/bin/sub2sing-box
	rm /root/sub2sing-box_0.0.9_linux_amd64.tar.gz
	su -c "/usr/bin/sub2sing-box server --bind 127.0.0.1 --port 8080 & disown" root
}

##############################Install Fake Site###########################################################
install_fake_site() {
	bash <(wget -qO- https://raw.githubusercontent.com/mozaroc/x-ui-pro/refs/heads/master/randomfakehtml.sh)
}

##############################Install Web Sub Page########################################################
install_web_sub_page() {
	local URL_SUB_PAGE=(
		"https://github.com/legiz-ru/x-ui-pro/raw/master/sub-3x-ui.html"
		"https://github.com/legiz-ru/x-ui-pro/raw/master/sub-3x-ui-classical.html"
	)
	local URL_CLASH_SUB=(
		"https://github.com/legiz-ru/x-ui-pro/raw/master/clash/clash.yaml"
		"https://github.com/legiz-ru/x-ui-pro/raw/master/clash/clash_skrepysh.yaml"
		"https://github.com/legiz-ru/x-ui-pro/raw/master/clash/clash_fullproxy_without_ru.yaml"
		"https://github.com/legiz-ru/x-ui-pro/raw/master/clash/clash_refilter_ech.yaml"
	)
	local DEST_DIR_SUB_PAGE="/var/www/subpage"
	local DEST_FILE_SUB_PAGE="$DEST_DIR_SUB_PAGE/index.html"
	local DEST_FILE_CLASH_SUB="$DEST_DIR_SUB_PAGE/clash.yaml"

	mkdir -p "$DEST_DIR_SUB_PAGE"

	curl -L "${URL_CLASH_SUB[$CLASH]}" -o "$DEST_FILE_CLASH_SUB"
	curl -L "${URL_SUB_PAGE[$CUSTOMWEBSUB]}" -o "$DEST_FILE_SUB_PAGE"

	sed -i "s/\${DOMAIN}/$domain/g" "$DEST_FILE_SUB_PAGE"
	sed -i "s/\${DOMAIN}/$domain/g" "$DEST_FILE_CLASH_SUB"
	sed -i "s#\${SUB_JSON_PATH}#$json_path#g" "$DEST_FILE_SUB_PAGE"
	sed -i "s#\${SUB_PATH}#$sub_path#g" "$DEST_FILE_SUB_PAGE"
	sed -i "s#\${SUB_PATH}#$sub_path#g" "$DEST_FILE_CLASH_SUB"
	sed -i "s|sub.legiz.ru|$domain/$sub2singbox_path|g" "$DEST_FILE_SUB_PAGE"
}

##############################Setup Crontab###############################################################
setup_crontab() {
	crontab -l | grep -v "certbot\|x-ui\|cloudflareips\|sub2sing-box" | crontab -
	(crontab -l 2>/dev/null; echo '@reboot /usr/bin/sub2sing-box server --bind 127.0.0.1 --port 8080 > /dev/null 2>&1') | crontab -
	(crontab -l 2>/dev/null; echo '@daily x-ui restart > /dev/null 2>&1 && nginx -s reload;') | crontab -
	(crontab -l 2>/dev/null; echo '@monthly certbot renew --nginx --non-interactive --post-hook "nginx -s reload" > /dev/null 2>&1;') | crontab -
}

##############################Setup UFW###################################################################
setup_ufw() {
	ufw disable
	ufw allow 22/tcp
	ufw allow 80/tcp
	ufw allow 443/tcp
	ufw --force enable
}

##############################Show Details#################################################################
show_details() {
	if systemctl is-active --quiet x-ui; then
		clear
		printf '0\n' | x-ui | grep --color=never -i ':'
		msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
		nginx -T | grep -i 'ssl_certificate\|ssl_certificate_key'
		msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
		certbot certificates | grep -i 'Path:\|Domains:\|Expiry Date:'
		msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
		msg_inf "X-UI Secure Panel: https://${domain}/${panel_path}/"
		printf '\n'
		printf 'Username:  %s\n\n' "${config_username}"
		printf 'Password:  %s\n\n' "${config_password}"
		msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
		msg_inf "Web Sub Page your first client: https://${domain}/${web_path}?name=first"
		printf '\n'
		msg_inf "Your local sub2sing-box instance: https://${domain}/$sub2singbox_path/"
		printf '\n'
		msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
		msg_inf "Please Save this Screen!!"
	else
		nginx -t && printf '0\n' | x-ui | grep --color=never -i ':'
		msg_err "sqlite and x-ui to be checked, try on a new clean linux! "
	fi
}

##############################Main########################################################################
main() {
	# 1. Parse arguments BEFORE any destructive action
	parse_args "$@"

	# 2. Handle uninstall early (no wipe needed)
	if [[ "${UNINSTALL}" == *"y"* ]]; then
		uninstall_xui
		clear && msg_ok "Completely Uninstalled!"
		exit 0
	fi

	# 3. Detect IPs (needed for auto-domain)
	detect_ips

	# 4. Auto-domain setup
	if [[ "${AUTODOMAIN}" == *"y"* ]]; then
		domain="${IP4}.cdn-one.org"
		reality_domain="${IP4//./-}.cdn-one.org"
	fi

	# 5. Domain prompts
	while true; do
		if [[ -n "$domain" ]]; then
			break
		fi
		printf "Enter available subdomain (sub.domain.tld): " && read domain
	done

	domain=$(echo "$domain" 2>&1 | tr -d '[:space:]')
	SubDomain=$(echo "$domain" 2>&1 | sed 's/^[^ ]* \|\..*//g')
	MainDomain=$(echo "$domain" 2>&1 | sed 's/.*\.\([^.]*\..*\)$/\1/')

	if [[ "${SubDomain}.${MainDomain}" != "${domain}" ]]; then
		MainDomain=${domain}
	fi

	while true; do
		if [[ -n "$reality_domain" ]]; then
			break
		fi
		printf "Enter available subdomain for REALITY (sub.domain.tld): " && read reality_domain
	done

	reality_domain=$(echo "$reality_domain" 2>&1 | tr -d '[:space:]')
	RealitySubDomain=$(echo "$reality_domain" 2>&1 | sed 's/^[^ ]* \|\..*//g')
	RealityMainDomain=$(echo "$reality_domain" 2>&1 | sed 's/.*\.\([^.]*\..*\)$/\1/')

	if [[ "${RealitySubDomain}.${RealityMainDomain}" != "${reality_domain}" ]]; then
		RealityMainDomain=${reality_domain}
	fi

	# 6. NOW do destructive cleanup (after args parsed, uninstall handled)
	clean_previous_install

	# 7. Generate random ports and paths
	sub_port=$(make_port)
	panel_port=$(make_port)
	web_path=$(gen_random_string 10)
	sub2singbox_path=$(gen_random_string 10)
	sub_path=$(gen_random_string 10)
	json_path=$(gen_random_string 10)
	panel_path=$(gen_random_string 10)
	ws_port=$(make_port)
	trojan_port=$(make_port)
	ws_path=$(gen_random_string 10)
	trojan_path=$(gen_random_string 10)
	xhttp_path=$(gen_random_string 10)
	config_username=$(gen_random_string 10)
	config_password=$(gen_random_string 10)

	# 8. Install packages & disable UFW initially
	ufw disable 2>/dev/null
	install_packages

	# 9. Auto-domain DNS verification
	if [[ "${AUTODOMAIN}" == *"y"* ]]; then
		if ! resolve_to_ip "$domain"; then
			die "Auto-domain $domain does not resolve to this server IP ($IP4). Fix DNS/service and retry."
		fi
		if ! resolve_to_ip "$reality_domain"; then
			die "Auto-domain $reality_domain does not resolve to this server IP ($IP4). Fix DNS/service and retry."
		fi
	fi

	# 10. Obtain SSL certificates (DRY)
	obtain_ssl "$domain"
	obtain_ssl "$reality_domain"

	# 11. Read existing XUI DB (if upgrading)
	read_existing_xui_db

	# 12. Setup nginx configs
	setup_nginx
	enable_nginx_sites

	# 13. Generate URIs
	sub_uri="https://${domain}/${sub_path}/"
	json_uri="https://${domain}/${web_path}?name="

	# 14. Install or restart X-UI panel
	if systemctl is-active --quiet x-ui; then
		x-ui restart
	else
		install_panel
		update_xui_db
		if ! systemctl is-enabled --quiet x-ui; then
			systemctl daemon-reload && systemctl enable x-ui.service
		fi
		x-ui restart
	fi

	# 15. Tune system (idempotent sysctl)
	tune_system

	# 16. Install sub2sing-box
	install_sub2singbox

	# 17. Install fake site
	install_fake_site

	# 18. Install web sub page
	install_web_sub_page

	# 19. Setup crontab
	setup_crontab

	# 20. Setup UFW
	setup_ufw

	# 21. Show details
	show_details
}

main "$@"
#################################################N-joy##################################################
