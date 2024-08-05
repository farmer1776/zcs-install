#!/bin/bash
# Installer for ZCS 10.1 Beta (install.sh wrapper script)
# Note: If using cloudflare DNS plugin for Letsencrypt on a production cloudflare controlled domain:
# export CF_EMAIL=<cloudflare account email>
# export CF_KEY=<your_cloudflare_apikey>
# For Ubuntu 22.04 LTS
UVER=$(lsb_release -d)
if (echo $UVER) | grep -q "Ubuntu 22.04"; then
   echo $UVER is supported
else
   echo $UVER is not supported
   exit
fi

echo

# Argbash - see https://argbash.io for more info
die() {
        local _ret="${2:-1}"
        test "${_PRINT_HELP:-no}" = yes && print_help >&2
        echo "$1" >&2
        exit "${_ret}"
}

u=`id -un`
if [ x$u != "xroot" ]; then
    echo "Error: must be run as root user"
    exit 1
fi

print_help() {
    printf '%s\n'
    printf '%s\n' "Install and configure Zimbra 10.1 ..."
    printf 'Usage: %s [-p|--password <arg>] [-t|--timezone <arg>] [-le|--letsencypt <arg>] [-h|--help] <domain>\n' "$(basename $0)"
    printf '\t%s\n' "<domain>: Domain to install Zimbra for"
    printf '\t%s\n' "-p, --password: Admin password to use (no default)"
    printf '\t%s\n' "-n, --hostname: Hostname to use for the server (default: mail)"
    printf '\t%s\n' "-t, --timezone: Timezone to set the server to user (optional) (default: 'New_York')"
    printf '\t%s\n' "-e, --letsencypt: Use Let's Encrypt for providing TLS certificates (optional y/n) (default: 'n')"
    printf '\t%s\n' "-a, --apache: Add support for spell check and convertd (optional y/n) (default: 'n')"
    printf '\t%s\n' "-h, --help: Prints help"
    printf '%s\n'
    printf '%s\n' "Usage: $(basename $0) [-p mypassword] [-t 'TimeZone'] [-n Server-Name] [-a n] [-le y] Domain-Name"
    printf '%s\n' "Example: $(basename $0) -p alRTFGmn1 -n zmail -t 'Europe/London' -a n -le y myorg.co.uk"
    exit 1
}

parse_commandline() {
    _positionals_count=0
    while test $# -gt 0; do
        _key="$1"
        case "$_key" in
            -p|--password)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_password="$2"
                shift
                ;;
            --password=*)
                _arg_password="${_key##--password=}"
                ;;
            -p*)
                _arg_password="${_key##-p}"
                ;;
            -n|--hostname)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_hostname="$2"
                shift
                ;;
            --hostname=*)
                _arg_hostname="${_key##--hostname=}"
                ;;
            -n*)
                _arg_hostname="${_key##-n}"
                ;;
            -t|--timezone)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_timezone="$2"
                shift
                ;;
            --timezone=*)
                _arg_timezone="${_key##--timezone=}"
                ;;
            -t*)
                _arg_timezone="${_key##-t}"
                ;;
            -a|--apache)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_apace="$2"
                shift
                ;;
            --apache=*)
                _arg_apache="${_key##--apache=}"
                ;;
            -a*)
                _arg_apache="${_key##-a}"
                ;;
            -e|--letsencrypt)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_letsencrypt="$2"
                shift
                ;;
            --letsencrypt=*)
                _arg_letsencrypt="${_key##--letsencrypt=}"
                ;;
            -e*)
                _arg_letsencrypt="${_key##-e=}"
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            -h*)
                print_help
                exit 0
                ;;
            *)
                _last_positional="$1"
                _positionals+=("$_last_positional")
                _positionals_count=$((_positionals_count + 1))
                ;;
        esac
        shift
    done
}

handle_passed_args_count() {
        local _required_args_string="'domain' "
        test "${_positionals_count}" -ge 1 || _PRINT_HELP=yes die "FATAL ERROR: Not enough positional arguments - we require exactly 1 (namely: $_required_args_string), but got only ${_positionals_count}." 1
        test "${_positionals_count}" -le 1 || _PRINT_HELP=yes die "FATAL ERROR: There were spurious positional arguments --- we expect exactly 1 (namely: $_required_args_string), but got ${_positionals_count} (the last one was: '${_last_positional}')." 1
}

assign_positional_args() {
        local _positional_name _shift_for=$1
        _positional_names="_arg_domain "

        shift "$_shift_for"
        for _positional_name in ${_positional_names}
        do
                test $# -gt 0 || break
                eval "$_positional_name=\${1}" || die "Error during argument parsing, possibly an Argbash bug." 1
                shift
        done
}

parse_commandline "$@"
handle_passed_args_count
assign_positional_args 1 "${_positionals[@]}"


MYIP=$(hostname -I | cut -f1 -d" " | tr -d '[:space:]')
LICENSE="$_arg_license"
DOMAIN="$_arg_domain"
HOSTONLY="${_arg_hostname:="mail"}"
HOSTNAME="${_arg_hostname:-"mail"}"."$DOMAIN"
TIMEZONE="${_arg_timezone:-"America/New_York"}"
LETSENCRYPT="${_arg_letsencrypt:-"n"}"
APACHE="${_arg_apache:-"y"}"
MYPASSWORD="${_arg_password:-$(openssl rand -base64 12)}"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
SYSTEMMEMORY=$(($(grep MemAvailable /proc/meminfo | awk '{print $2}')/1024/1024))

# Begin 

echo "Updating system and installing some essential packages ..."
#What are the other essential packages?
DEBIAN_FRONTEND=noninteractive apt-get update -qq -y < /dev/null > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get upgrade -qq -y < /dev/null > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y apt-utils< /dev/null > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y netcat-openbsd sudo libpcre3 libgmp10 libexpat1 libstdc++6 libaio1 resolvconf unzip pax sysstat sqlite3< /dev/null > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y lsb-release net-tools netfilter-persistent dnsutils iptables sed wget rsyslog ldapscripts< /dev/null > /dev/null
# Make sure we even need these packages with 10.1?

#Make sure to enable PAM
cat /etc/ssh/sshd_config | grep -v -i usepam > /tmp/sshd_config
echo "UsePAM yes" >>/tmp/sshd_config
mv /tmp/sshd_config /etc/ssh/sshd_config
systemctl restart sshd

echo "Enabling rsyslog ..."

systemctl enable rsyslog
systemctl restart rsyslog

# Check DNS
echo "Checking DNS ..."
name=`host license.zimbra.com`
if [[ "$name" == *"not found"* ]]; then
    echo -e "${RED}DNS resolution failed! Check your resolve.conf file.${NC}"
    exit 1
else
    echo -e "${GREEN}... Done.${NC}"
fi

# Reset the hosts file
echo "Rewriting the /etc/hosts file ..."
mv /etc/hosts /etc/hosts.old
printf '127.0.0.1\tlocalhost.localdomain\tlocalhost\n127.0.1.1\tubuntu\n'$MYIP'\t'$HOSTNAME'\t'$HOSTONLY'\t' | tee -a /etc/hosts >/dev/null 2>&1
echo -e "${GREEN}... Done.${NC}"
echo "Setting hostname ($HOSTNAME) and timezone ($TIMEZONE) ..."
hostnamectl set-hostname $HOSTNAME >/dev/null 2>&1
timedatectl set-timezone $TIMEZONE >/dev/null 2>&1
echo -e "${GREEN}... Done.${NC}"
apt-get -qq update < /dev/null > /dev/null

# Can add nfs packages / mounts here and pickup custom zmprov config files if needed for VM configuration
# apt install nfs-common -y
# echo "192.168.x.x:/mnt/raid/shared    /mnt/nas    nfs          rw            0    0" >> /etc/fstab
# mount -a

# ============== Letsencrypt/cloudflare stuff ==================
# export CF_ values before running script

if [ "$LETSENCRYPT" != "${LETSENCRYPT#[Yy]}" ] ;then # this grammar (the #[] operator) means that the variable $answer where any Y or y in 1st position will be dropped if they exist.
      echo "Installing certbot w/ cloudflare plugin and configure API"

      apt install certbot python3-certbot-dns-cloudflare -y
      
      mkdir -p ~/.secrets/certbot
      cat >>  ~/.secrets/certbot/cloudflare.ini << EOF
dns_cloudflare_email = $CF_EMAIL
dns_cloudflare_api_key = $CF_KEY
EOF

chmod 600 ~/.secrets/certbot/cloudflare.ini

      cat >> /usr/local/sbin/letsencrypt-zimbra << EOF
#!/bin/bash
MAILTO=""
# /usr/local/sbin/certbot renew
/usr/local/sbin/certbot certonly \
-d $(hostname --fqdn) \
-n \
--preferred-chain  "ISRG Root X2" \
--agree-tos \
--register-unsafely-without-email \
--dns-cloudflare \
--dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
--dns-cloudflare-propagation-seconds 60

cp "/etc/letsencrypt/live/$(hostname --fqdn)/privkey.pem" /opt/zimbra/ssl/zimbra/commercial/commercial.key
chown zimbra:zimbra /opt/zimbra/ssl/zimbra/commercial/commercial.key
wget -O /tmp/ISRG-X2.pem https://letsencrypt.org/certs/isrg-root-x2.pem
rm -f "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
cp "/etc/letsencrypt/live/$(hostname --fqdn)/chain.pem" "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
cat /tmp/ISRG-X2.pem >> "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
chown zimbra:zimbra /etc/letsencrypt -R
cd /tmp
su - zimbra -c '/opt/zimbra/bin/zmcertmgr deploycrt comm "/etc/letsencrypt/live/$(hostname --fqdn)/cert.pem" "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"'
rm -f "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
EOF
      chmod +rx /usr/local/sbin/letsencrypt-zimbra

/usr/local/sbin/letsencrypt-zimbra

# certbot command here to pull initial certificate and prestage in /etc/letsencrypt/live/$HOSTNAME
# /usr/bin/certbot certonly \
# -d $(hostname --fqdn) \
# --preferred-chain  "ISRG Root X2" \
# --agree-tos \
# --register-unsafely-without-email \
# --dns-cloudflare \
# --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
# --dns-cloudflare-propagation-seconds 60

# Then run "certbot renew" in script above

fi

# Preparing the config files to inject
if [ ! -d "/tmp/zcs" ]; then
    mkdir /tmp/zcs
else
    rm -rf /tmp/zcs/*    #Dangerous Command
fi

# Download binaries
echo "Downloading Zimbra 10.1 beta for $UVER ..."
wget -P /tmp/ https://packages.zcsplus.com/dlz/zcs-PLUS-10.1.0_BETA_4634.UBUNTU22_64.20240610092518.tgz > /dev/nuff 2>&1

echo "Extracting the files ..."
cd /tmp/zcs && tar xzf /tmp/zcs-PLUS-10.1.0_BETA_4634.UBUNTU22_64.20240610092518.tgz

echo "Creating the auto-install input files ..."
> /tmp/zcs/zconfig
cat <<EOF >/tmp/zcs/zconfig
AVDOMAIN="$DOMAIN"
AVUSER="super-admin@$DOMAIN"
CREATEADMIN="super-admin@$DOMAIN"
CREATEADMINPASS="$MYPASSWORD"
CREATEDOMAIN="$DOMAIN"
DOCREATEADMIN="yes"
DOCREATEDOMAIN="yes"
DOTRAINSA="yes"
ENABLEDEFAULTBACKUP="yes"
EXPANDMENU="no"
HOSTNAME="$HOSTNAME"
HTTPPORT="8080"
HTTPPROXY="TRUE"
HTTPPROXYPORT="80"
HTTPSPORT="8443"
HTTPSPROXYPORT="443"
IMAPPORT="7143"
IMAPPROXYPORT="143"
IMAPSSLPORT="7993"
IMAPSSLPROXYPORT="993"
INSTALL_WEBAPPS="service zimlet zimbra zimbraAdmin"
JAVAHOME="/opt/zimbra/common/lib/jvm/java"
LDAPBESSEARCHSET="set"
LDAPAMAVISPASS="$MYPASSWORD"
LDAPPOSTPASS="$MYPASSWORD"
LDAPROOTPASS="$MYPASSWORD"
LDAPADMINPASS="$MYPASSWORD"
LDAPREPPASS="$MYPASSWORD"
LDAPBESSEARCHSET="set"
LDAPDEFAULTSLOADED="1"
LDAPHOST="$HOSTNAME"
LDAPPORT="389"
LDAPREPLICATIONTYPE="master"
LDAPSERVERID="2"
LICENSEACTIVATIONOPTIONMSG="UNSET"
MAILBOXDMEMORY="1920"
MAILPROXY="TRUE"
MODE="https"
MYSQLMEMORYPERCENT="30"
ONLYOFFICEHOSTNAME="$HOSTNAME"
ONLYOFFICESTANDALONE="no"
POPPORT="7110"
POPPROXYPORT="110"
POPSSLPORT="7995"
POPSSLPROXYPORT="995"
PROXYMODE="https"
REMOVE="no"
RUNARCHIVING="no"
RUNAV="yes"
RUNCBPOLICYD="no"
RUNDKIM="yes"
RUNSA="yes"
RUNVMHA="no"
SERVICEWEBAPP="yes"
SMTPDEST="super-admin@$DOMAIN"
SMTPHOST="$HOSTNAME"
SMTPNOTIFY="yes"
SMTPSOURCE="super-admin@$DOMAIN"
SNMPNOTIFY="yes"
SNMPTRAPHOST="$HOSTNAME"
SPELLURL="http://$HOSTNAME:7780/aspell.php"
STARTSERVERS="yes"
STRICTSERVERNAMEENABLED="TRUE"
SYSTEMMEMORY="$SYSTEMMEMORY"
TRAINSAHAM="ham.account@$DOMAIN"
TRAINSASPAM="spam.account@$DOMAIN"
UIWEBAPPS="yes"
UPGRADE="yes"
USEKBSHORTCUTS="TRUE"
USESPELL="yes"
VERSIONUPDATECHECKS="TRUE"
VIRUSQUARANTINE="virus-quarantine.account@$DOMAIN"
ZIMBRA_REQ_SECURITY="yes"
ldap_bes_searcher_password="$MYPASSWORD"
ldap_dit_base_dn_config="cn=zimbra"
ldap_nginx_password="$MYPASSWORD"
mailboxd_directory="/opt/zimbra/mailboxd"
mailboxd_keystore="/opt/zimbra/mailboxd/etc/keystore"
mailboxd_keystore_password="$MYPASSWORD"
mailboxd_server="jetty"
mailboxd_truststore="/opt/zimbra/common/lib/jvm/java/lib/security/cacerts"
mailboxd_truststore_password="changeit"
postfix_mail_owner="postfix"
postfix_setgid_group="postdrop"
ssl_default_digest="sha256"
zimbraDNSMasterIP="8.8.4.4"
zimbraDNSTCPUpstream="no"
zimbraDNSUseTCP="yes"
zimbraDNSUseUDP="yes"
zimbraDefaultDomainName="$DOMAIN"
zimbraFeatureBriefcasesEnabled="Enabled"
zimbraFeatureTasksEnabled="Enabled"
zimbraIPMode="ipv4"
zimbraMailProxy="FALSE"
zimbraMtaMyNetworks="127.0.0.0/8 $MYIP/32 [::1]/128 [fe80::]/64"
zimbraPrefTimeZoneId="$TIMEZONE"
zimbraReverseProxyLookupTarget="TRUE"
zimbraVersionCheckInterval="1d"
zimbraVersionCheckNotificationEmail="super-admin@$DOMAIN"
zimbraVersionCheckNotificationEmailFrom="super-admin@$DOMAIN"
zimbraVersionCheckSendNotifications="TRUE"
zimbraWebProxy="TRUE"
zimbra_ldap_userdn="uid=zimbra,cn=admins,cn=zimbra"
zimbra_require_interprocess_security="1"
zimbra_server_hostname="$HOSTNAME"
EOF

if [[ "$APACHE" == "y" ]]; then
    echo 'INSTALL_PACKAGES="zimbra-core zimbra-ldap zimbra-logger zimbra-mta zimbra-snmp zimbra-store zimbra-apache zimbra-spell zimbra-memcached zimbra-proxy"' >>/tmp/zcs/zconfig
else
    echo 'INSTALL_PACKAGES="zimbra-core zimbra-ldap zimbra-logger zimbra-mta zimbra-snmp zimbra-store zimbra-memcached zimbra-proxy"' >>/tmp/zcs/zconfig
fi

> /tmp/zcs/zkeys
cat <<EOF >/tmp/zcs/zkeys
y
y
y
y
y
n
n
y
y
$APACHE
$APACHE
y
y
y
y
y
y
EOF

echo
read -p "Press enter to continue ... "


D=`date +%s`
echo -e "${GREEN}... Done.${NC}"
echo "Installing the Zimbra binaries ..."
echo -e "For more details you can open a new terminal and run ${GREEN}tail -f /tmp/install.log.*${NC}"
cd /tmp/zcs/zcs-* && ./install.sh -s < /tmp/zcs/zkeys >> /tmp/zcs/install-$D.log 2>&1
echo -e "${GREEN}... Done.${NC}"

echo
read -p "Press enter to continue ... "

echo "Setting up your Zimbra configuration, this can take up to 20 minutes or slightly more."
echo -e "For more details you can open a new terminal and run ${GREEN}tail -f /tmp/zmsetup.log${NC}."

# Where the zmsetup phase runs //
/opt/zimbra/libexec/zmsetup.pl -c /tmp/zcs/zconfig >> /tmp/zcs/install-$D.log 2>&1


# Security tweaks stuff here  - Add more attributes as needed for use case
echo "Setting optimal security settings"
rm -Rf /tmp/provfile

cat >> /tmp/provfile << EOF
mcf zimbraPublicServiceProtocol https
mcf zimbraPublicServicePort 443
mcf zimbraPublicServiceHostname $HOSTNAME
mcf zimbraReverseProxySSLProtocols TLSv1.2
mcf +zimbraReverseProxySSLProtocols TLSv1.3
mcf zimbraReverseProxySSLCiphers ""
mcf +zimbraResponseHeader "Strict-Transport-Security: max-age=31536000; includeSubDomains"
mcf +zimbraResponseHeader "X-Content-Type-Options: nosniff"
mcf +zimbraResponseHeader "X-Robots-Tag: noindex"
mcf +zimbraResponseHeader "Referrer-Policy: no-referrer"
mcf zimbraMailKeepOutWebCrawlers TRUE
mcf zimbraSmtpSendAddMailer FALSE

mcf zimbraSSLDHParam /etc/ffdhe4096.pem

mcf zimbraMtaSmtpdTlsCiphers medium
mcf zimbraMtaSmtpdTlsMandatoryCiphers  medium
mcf zimbraMtaSmtpdTlsProtocols '>=TLSv1.2'
mcf zimbraMtaTlsSecurityLevel may

ms $HOSTNAME zimbraPop3CleartextLoginEnabled FALSE
ms $HOSTNAME zimbraImapCleartextLoginEnabled FALSE

mcf zimbraLastLogonTimestampFrequency 1s
mc default zimbraPrefShortEmailAddress FALSE
mc default zimbraFeatureTwoFactorAuthAvailable TRUE
mc default zimbraFeatureTrustedDevicesEnabled FALSE

mcf +zimbraMailTrustedIP 127.0.0.1
mcf +zimbraMailTrustedIP $MYIP
mcf +zimbraGalLdapAttrMap manager=manager
mcf zimbraBackupReportEmailSender super-admin@$DOMAIN zimbraBackupReportEmailRecipients super-admin@$DOMAIN

ms $HOSTNAME zimbraFileUploadMaxSize 80000000
ms $HOSTNAME zimbraMailContentMaxSize 80000000
mcf zimbraMtaMaxMessageSize 80000000
mcf zimbraFileUploadMaxSize 80000000
mcf zimbraMailContentMaxSize 80000000
EOF

sed -i 's/-server -Dhttps.protocols=TLSv1.2 -Djdk.tls.client.protocols=TLSv1.2/-server -Dhttps.protocols=TLSv1.2,TLSv1.3 -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3/g' /opt/zimbra/conf/localconfig.xml
wget -q https://raw.githubusercontent.com/internetstandards/dhe_groups/master/ffdhe4096.pem -O /etc/ffdhe4096.pem

su - zimbra -c '/opt/zimbra/bin/postconf -e fast_flush_domains=""'
su - zimbra -c '/opt/zimbra/bin/postconf -e smtpd_etrn_restrictions=reject'
su - zimbra -c '/opt/zimbra/bin/postconf -e disable_vrfy_command=yes'
su - zimbra -c '/opt/zimbra/bin/postconf -e tls_medium_cipherlist=$(/opt/zimbra/common/bin/openssl ciphers)'
su - zimbra -c '/opt/zimbra/bin/postconf -e tls_preempt_cipherlist=no'

su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e ldap_common_tlsprotocolmin="3.3"'
su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e ldap_common_tlsciphersuite="HIGH"'
su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e ldap_starttls_supported=1'
su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e zimbra_require_interprocess_security=1'
su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e ldap_starttls_required=true'

su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e alias_login_enabled=false'
su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e zimbra_same_site_cookie="Strict"'

su - zimbra -c '/opt/zimbra/bin/zmprov < /tmp/provfile'

#https://wiki.zimbra.com/wiki/Enabling_Admin_Console_Proxy
su - zimbra -c "/opt/zimbra/libexec/zmproxyconfig -e -w -C -H $HOSTNAME"

# Update Authkeys and Syslog
su - zimbra -c '/opt/zimbra/bin/zmupdateauthkeys'
/opt/zimbra/libexec/zmsyslogsetup

su - zimbra -c '/opt/zimbra/bin/zmcontrol restart'

echo
echo
echo "Zimbra installation details:"
echo
echo "  - Webmail Login:  https://${HOSTNAME}"
echo "  - Admin Console:  https://${HOSTNAME}:9071"
echo "  - Admin Username: super-admin"
echo "  - Admin Password: ${MYPASSWORD}"
echo ""
