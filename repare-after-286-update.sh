#!/bin/bash

while true; do	
	if [[ -n "$domain" ]]; then
		break
	fi
	echo -en "Enter your panel domain(sub.domain.tld): " && read domain 
done

XUIPORT=$(sqlite3 -list /etc/x-ui/x-ui.db 'SELECT "value" FROM settings WHERE "key"="webPort" LIMIT 1;' 2>&1)
XUIPATH=$(sqlite3 -list /etc/x-ui/x-ui.db 'SELECT "value" FROM settings WHERE "key"="webBasePath" LIMIT 1;' 2>&1)
sub_port=$(sqlite3 -list /etc/x-ui/x-ui.db 'SELECT "value" FROM settings WHERE "key"="subPort" LIMIT 1;' 2>&1)
sub_path=$(sqlite3 -list /etc/x-ui/x-ui.db 'SELECT "value" FROM settings WHERE "key"="subPath" LIMIT 1;' 2>&1)
web_path


mkdir -p /root/cert/${domain}
chmod 755 /root/cert/*

ln -s /etc/letsencrypt/live/${domain}/fullchain.pem /root/cert/${domain}/fullchain.pem
ln -s /etc/letsencrypt/live/${domain}/privkey.pem /root/cert/${domain}/privkey.pem



NGINX_CONF="/etc/nginx/sites-available/${domain}"
BACKUP="/root/${domain}.backup.$(date +%F_%H%M%S)"
cp -a "$NGINX_CONF" "$BACKUP"


XUIPATH_NORM="${XUIPATH#/}"
XUIPATH_NORM="${XUIPATH_NORM%/}"


read -r -d '' XUI_LOCATION_BODY <<EOF
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        proxy_pass https://127.0.0.1:${XUIPORT};
        break;
EOF


patch_location_block() {
  local conf="$1"
  local loc="$2"     
  local body="$3"


  local loc_re
  loc_re="$(printf '%s' "$loc" | sed -e 's/[.[\*^$()+?{|\\]/\\&/g' -e 's/\//\\\//g')"


  if perl -0777 -ne "exit(index(\$_, 'location ${loc} ') >= 0 ? 0 : 1)" "$conf"; then
    perl -0777 -i -pe "
      s/location\\s+${loc_re}\\s*\\{.*?\\n\\s*\\}/location ${loc} {\\n${body}\\n    }/sg
    " "$conf"
    return 0
  fi

  return 1
}


insert_location_block() {
  local conf="$1"
  local loc="$2"
  local body="$3"

  local block="    location ${loc} {\n${body}\n    }\n"

 
  if grep -qE '^\s*include\s+/etc/nginx/snippets/includes\.conf;' "$conf"; then
    perl -0777 -i -pe "s/(\\n\\s*include\\s+\\/etc\\/nginx\\/snippets\\/includes\\.conf;)/\\n${block}\$1/s" "$conf"
  else
   
    perl -0777 -i -pe "s/\\n\\}\\s*\$/\\n${block}\\n}\\n/s" "$conf"
  fi
}


LOC1="/${XUIPATH_NORM}/"
LOC2="/${XUIPATH_NORM}"

patch_location_block "$NGINX_CONF" "$LOC1" "$XUI_LOCATION_BODY" || insert_location_block "$NGINX_CONF" "$LOC1" "$XUI_LOCATION_BODY"
patch_location_block "$NGINX_CONF" "$LOC2" "$XUI_LOCATION_BODY" || insert_location_block "$NGINX_CONF" "$LOC2" "$XUI_LOCATION_BODY"


nginx -t && systemctl restart nginx


/usr/local/x-ui/x-ui cert -webCert "/root/cert/${domain}/fullchain.pem" -webCertKey "/root/cert/${domain}/privkey.pem"
x-ui restart
systemctl restart nginx

