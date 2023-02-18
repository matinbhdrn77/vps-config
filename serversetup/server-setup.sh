#!/usr/bin/env bash

# set -e

# Colors
Color_Off='\033[0m'
OK="\033[0;32m[OK]"
ERROR="\033[0;91m[ERROR]"
INFO="\033[0;33m[INFO]"

SLEEP="sleep 0.5"

#print OK
function print_ok() {
    echo -e "${OK} $1 ${Color_Off}"
}

#print ERROR
function print_error() {
    echo -e "${ERROR} $1 ${Color_Off}"
}

#print INFO
function print_info() {
    echo -e "${INFO} $1 ${Color_Off}"
}

function installit() {
    apt-get update && apt install -y "$@"
}

function judge() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 Finished"
        $SLEEP
    else
        print_error "$1 Failed"
        exit 1
    fi
}

function ask_do() {
    unset CONFIRM
    until [[ ${CONFIRM} =~ ^(y|n)$ ]]; do
        read -rp "${1}? (y/n) " -e -i "y" CONFIRM
    done
    if [[ $CONFIRM == "y" ]]; then
        $2
        judge "$1"
    fi
}

function check_root() {
    if [ "${EUID}" -ne 0 ]; then
        echo "You need to run this script as root"
        exit 1
    fi
}

# install commons
function install_commons() {
    print_info "Installing common packages"
    apt-get update &&
        apt-get install -y curl wget vim gnupg iptables iptables-persistent nginx obfs4proxy privoxy tmux tcpdump tor htop speedtest-cli nload vnstat netcat-traditional sudo iperf3
    systemctl disable --now privoxy tor
}

# add personal configs
function add_personal_configs() {
    print_info "Adding personal confis"
    CONFIG_EXISTS=$(grep 'sreset' $HOME/.bashrc)
    if [[ -z $CONFIG_EXISTS ]]; then
        cat <<-'EOF' >>$HOME/.bashrc
# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=
HISTFILESIZE=
# export hist immedietly
shopt -s histappend                      # append to history, don't overwrite it
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"

# aliases
alias pingo="ping 1.1.1.1"
alias upup="sudo apt-get update && sudo apt-get upgrade -y"
alias ls='ls --color=auto'
alias lo='ls -ohA'
alias sreset="sudo systemctl restart"
alias sreload="sudo systemctl reload"
alias sstatus="sudo systemctl status"
alias sstop="sudo systemctl stop"
alias plz="sudo"
EOF

        cat <<-'EOF' >>$HOME/.bash_history
resolvectl reset-statistics
resolvectl statistics
resolvectl query docker.io
vnstat --days
vnstat --months
ss --no-header  --tcp -4 -o state established '( sport = :https )' | awk '{ print $4 }' | sort -n | uniq -c | sort -n
journalctl -u xray --since -24h | awk '{print $8}' | grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u | wc -l
journalctl -u xray --since -24h | awk '{print $8}' | grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u | less
iperf3 -s
rm -f /dev/shm/nginx*.sock || nginx -t && systemctl restart nginx
xray run -test -c /usr/local/etc/xray/config.json  && sreset xray
du -csh /{etc,home,opt,root,srv,var/www}  | sort -h
tar -cvf /tmp/$(date +%F-%H%M)--$(uname -n)--$(uname -r).tar /{etc,home,opt,root,srv,var/www,var/spool} > /tmp/tar.out 2> /tmp/tar.erorrs
journalctl -u xray --since -24h | grep accepted | awk '{print $8}' | grep -Po '(\d\d?\d?\.){3}\d\d?\d?'  | sort -u | wc -l
EOF
        # configure tmux and vim
        echo 'setw -g mouse on' >>$HOME/.tmux.conf
        echo 'set paste' >>$HOME/.vimrc

        # auto attach to tmux session
        unset CONFIRM
        until [[ ${CONFIRM} =~ ^(y|n)$ ]]; do
            read -rp "Tmux automatically attach session? (y/n) " -e -i "y" CONFIRM
        done
        if [[ $CONFIRM == "y" ]]; then
            cat <<-'EOF' >>$HOME/.bashrc
            # @, automatically join tmux sesison or create one
            if [[ -n "$PS1" ]] && [[ -z "$TMUX" ]] && [[ -n "$SSH_CONNECTION" ]]; then
                tmux attach-session -t ssh_tmux || tmux new-session -s ssh_tmux
            fi
EOF
        fi
    fi
}

# create dude user
function add_newuser() {
    useradd -m -s /usr/bin/bash dude
    echo "Enter password for 'the dude' user: "
    passwd dude
    usermod -aG sudo dude
}

# enable BBR congestion algorithm
function enable_bbr() {
    cat >/etc/sysctl.d/50-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl -p /etc/sysctl.d/50-bbr.conf
}

# HAProxy
function install_haproxy() {
    source /etc/os-release
    if [[ ${ID} == "debian" ]]; then
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net ${VERSION_CODENAME}-backports-2.6 main >/etc/apt/sources.list.d/haproxy.list
        apt-get update && apt-get install -y haproxy=2.6.\*

    elif [[ "${ID}" == "ubuntu" ]]; then
        if [[ $VERSION_ID =~ ^(18.04|20.04|22.04)$ ]]; then
            apt-get install -y --no-install-recommends software-properties-common
            add-apt-repository -y ppa:vbernat/haproxy-2.6
            apt-get install -y haproxy=2.6.\*
        fi
    fi

    cp -ir bridge-server/etc/* /etc/

    # Disable privoxy
    systemctl disable --now privoxy
}

# V2Ray & XRay
function install_v2ray_xray() {
    # bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    # Download Iran hosted domains
    curl -s https://api.github.com/repos/bootmortis/iran-hosted-domains/releases/latest |
        grep "browser_download_url.*iran.dat" | cut -d : -f 2,3 | tr -d '"' |
        wget -qO /usr/local/share/xray/iran.dat -i -
}

function install_fakeupload_cronjob() {
    CRONFILE='/tmp/cronjob'
    crontab -l >$CRONFILE
    cat <<-'EOF' >>$CRONFILE
*/7 * * * * SIZE=$(shuf -i 789-1456 -n 1); truncate -s ${SIZE}M /tmp/garbage && curl --limit-rate 4000k -H "Max-Days: 1" --upload-file /tmp/garbage https://transfer.sh/wordpress.zip
#*/2 * * * * SIZE=$(shuf -i 456-989 -n 1); truncate -s ${SIZE}M /tmp/garbage && netcat -u -q0 185.88.176.223 1433 < /tmp/garbage
EOF
    crontab $CRONFILE
    rm $CRONFILE
}

function disable_ssh_password_authentication() {
    if [[ -d /etc/ssh/sshd_config.d/ ]]; then
        SSH_CONFIG="/etc/ssh/sshd_config.d/100-disbale_PasswordAuthentication.conf"
    else
        SSH_CONFIG="/etc/ssh/sshd_config"
    fi

    cat <<-EOF >>$SSH_CONFIG
    PasswordAuthentication no
    PubkeyAuthentication yes
EOF
    sshd -t && systemctl restart sshd
}

function setup_DOT() {
    cat <<-EOF >>/etc/systemd/resolved.conf
[Resolve]
DNS=185.222.222.222#dot.sb 1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net 8.8.8.8#dns.google 2606:4700:4700::1111#cloudflare-dns.com 2620:fe::9#dns.quad9.net 2001:4860:4860::8888#dns.google 178.22.122.100#free.shecan.ir
DNSSEC=allow-downgrade
DNSOverTLS=true
LLMNR=no
Cache=yes
#CacheFromLocalhost=no
ReadEtcHosts=yes
EOF

    if ! [[ -L /etc/resolv.conf ]]; then
        mv /etc/resolv.conf /etc/resolv.conf.bak
        ln -fsr /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi
    systemctl restart systemd-resolved

    # SETUP DOH

    #     installit acl dnsdist
    #     cat <<-EOF > /etc/dnsdist/dnsdist.conf
    # -- allow query from all IP addresses
    # addACL('0.0.0.0/0')

    # -- add a DoH resolver listening on port 443 of all interfaces
    # addDOHLocal("127.0.0.1:53443", "/etc/ssl/helena.work.gd/domain.pem", "/etc/ssl/helena.work.gd/domain-key.pem", { "/" }, { doTCP=true, reusePort=true, tcpFastOpenSize=0 })

    # -- downstream resolver
    # newServer({address="127.0.0.53:53",qps=5, name="resolver1"})
    # EOF

    #     setfacl -R -m u:_dnsdist:rx /etc/ssl/helena.work.gd
    #     systemctl restart dnsdist
}

function setup_xray_nginx() {
    XRAY_CONFIG="/usr/local/etc/xray/config.json"
    if [[ -d "/etc/nginx/sites-enabled/" ]]; then
        NGINX_SITES_ENABLED="/etc/nginx/sites-enabled/"
    elif [[ -d "/etc/nginx/conf.d" ]]; then
        NGINX_SITES_ENABLED="/etc/nginx/conf.d/"
    fi

    # Disable nginx default website, and copy new config
    rm ${NGINX_SITES_ENABLED}/default
    cp vpn-server/etc/nginx/sites-enabled/* ${NGINX_SITES_ENABLED}/
    cp -r vpn-server/var/www /var/
    # copy xray config
    cp vpn-server/xray.json $XRAY_CONFIG
    # change ssl certificates for xray & add server_names for nginx
    cp -r vpn-server/etc/ssl/* /etc/ssl/
    print_info "change ssl certificates for xray & add server_names for nginx if needed!"
    rm -f /dev/shm/nginx*.sock || nginx -t && systemctl restart nginx && print_ok "Nginx"
    xray run -test -c $XRAY_CONFIG && systemctl restart xray && print_ok "Xray"
}

function setup_warp() {
    # install wireguard
    apt-get install -y wireguard iptables resolvconf
    # insall wgcf
    curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest |
        grep "browser_download_url.*linux_amd64" | cut -d : -f 2,3 | tr -d '"' |
        wget -qO /usr/bin/wgcf -i - && chmod +x /usr/bin/wgcf

    # Register with WARP
    if [[ -s ./wgcf-account.toml ]] || [[ 0 -eq $(wgcf register --accept-tos) ]]; then
        PRIVATE_KEY=$(grep private_key wgcf-account.toml | cut -d " " -f 3 | tr -d \')
        # GOOGLE_CIDRS=$(curl https://www.gstatic.com/ipranges/goog.json  | jq -r '.prefixes[]  | {ipv4Prefix,ipv6Prefix} | join("")'  | sed ':a;N;$!ba;s/\n/,/g')
        # CLOUDFRONT_CIDRS=$(curl https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select(.service | match("CLOUDFRONT")) | {ip_prefix} | join(",") ' |  sed ':a;N;$!ba;s/\n/,/g')
        # Configure Wireguard
        cat <<-EOF | sed -e "s:PRIVATE_KEY_HERE:${PRIVATE_KEY}:" >/etc/wireguard/wg0.conf
[Interface]
PrivateKey = PRIVATE_KEY_HERE
Address = 172.16.0.2/32
Address = 2606:4700:110:8a5f:7068:7a4f:23a3:1da9/128
#DNS = 1.1.1.1,127.0.0.53,2606:4700:4700::1111,2001:4860:4860::8888,2001:4860:4860::8844
MTU = 1420
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
# Google
AllowedIPs = 23.236.48.0/20,23.251.128.0/19,34.0.0.0/15,34.2.0.0/16,34.3.0.0/23,34.3.3.0/24,34.3.4.0/24,34.3.8.0/21,34.3.16.0/20,34.3.32.0/19,34.3.64.0/18,34.3.128.0/17,34.4.0.0/14,34.8.0.0/13,34.16.0.0/12,34.32.0.0/11,34.64.0.0/10,34.128.0.0/10,35.184.0.0/13,35.192.0.0/14,35.196.0.0/15,35.198.0.0/16,35.199.0.0/17,35.199.128.0/18,35.200.0.0/13,35.208.0.0/12,35.224.0.0/12,35.240.0.0/13,64.15.112.0/20,64.233.160.0/19,66.22.228.0/23,66.102.0.0/20,66.249.64.0/19,70.32.128.0/19,72.14.192.0/18,74.114.24.0/21,74.125.0.0/16,104.154.0.0/15,104.196.0.0/14,104.237.160.0/19,107.167.160.0/19,107.178.192.0/18,108.59.80.0/20,108.170.192.0/18,108.177.0.0/17,130.211.0.0/16,136.112.0.0/12,142.250.0.0/15,146.148.0.0/17,162.216.148.0/22,162.222.176.0/21,172.110.32.0/21,172.217.0.0/16,172.253.0.0/16,173.194.0.0/16,173.255.112.0/20,192.158.28.0/22,192.178.0.0/15,193.186.4.0/24,199.36.154.0/23,199.36.156.0/24,199.192.112.0/22,199.223.232.0/21,207.223.160.0/20,208.65.152.0/22,208.68.108.0/22,208.81.188.0/22,208.117.224.0/19,209.85.128.0/17,216.58.192.0/19,216.73.80.0/20,216.239.32.0/19,2001:4860::/32,2404:6800::/32,2404:f340::/32,2600:1900::/28,2606:73c0::/32,2607:f8b0::/32,2620:11a:a000::/40,2620:120:e000::/40,2800:3f0::/32,2a00:1450::/32,2c0f:fb50::/32
# AWS CloudFront
AllowedIPS = 120.52.22.96/27,205.251.249.0/24,180.163.57.128/26,204.246.168.0/22,111.13.171.128/26,18.160.0.0/15,205.251.252.0/23,54.192.0.0/16,204.246.173.0/24,54.230.200.0/21,120.253.240.192/26,116.129.226.128/26,130.176.0.0/17,108.156.0.0/14,99.86.0.0/16,205.251.200.0/21,223.71.71.128/25,13.32.0.0/15,120.253.245.128/26,13.224.0.0/14,70.132.0.0/18,15.158.0.0/16,111.13.171.192/26,13.249.0.0/16,18.238.0.0/15,18.244.0.0/15,205.251.208.0/20,65.9.128.0/18,130.176.128.0/18,58.254.138.0/25,54.230.208.0/20,3.160.0.0/14,116.129.226.0/25,52.222.128.0/17,18.164.0.0/15,111.13.185.32/27,64.252.128.0/18,205.251.254.0/24,54.230.224.0/19,71.152.0.0/17,216.137.32.0/19,204.246.172.0/24,18.172.0.0/15,120.52.39.128/27,118.193.97.64/26,223.71.71.96/27,18.154.0.0/15,54.240.128.0/18,205.251.250.0/23,180.163.57.0/25,52.46.0.0/18,223.71.11.0/27,52.82.128.0/19,54.230.0.0/17,54.230.128.0/18,54.239.128.0/18,130.176.224.0/20,36.103.232.128/26,52.84.0.0/15,143.204.0.0/16,144.220.0.0/16,120.52.153.192/26,119.147.182.0/25,120.232.236.0/25,111.13.185.64/27,54.182.0.0/16,58.254.138.128/26,120.253.245.192/27,54.239.192.0/19,18.68.0.0/16,18.64.0.0/14,120.52.12.64/26,99.84.0.0/16,130.176.192.0/19,52.124.128.0/17,204.246.164.0/22,13.35.0.0/16,204.246.174.0/23,36.103.232.0/25,119.147.182.128/26,118.193.97.128/25,120.232.236.128/26,204.246.176.0/20,65.8.0.0/16,65.9.0.0/17,108.138.0.0/15,120.253.241.160/27,64.252.64.0/18,130.176.88.0/21,54.239.134.0/23,52.82.134.0/23,130.176.86.0/23,130.176.140.0/22,130.176.0.0/18,54.239.204.0/22,130.176.160.0/19,70.132.0.0/18,15.158.0.0/16,130.176.136.0/23,54.239.170.0/23,52.46.0.0/22,130.176.96.0/19,54.182.184.0/22,204.246.166.0/24,130.176.64.0/21,54.182.172.0/22,205.251.218.0/24,52.46.4.0/23,130.176.144.0/20,54.182.176.0/21,130.176.78.0/23,54.182.248.0/22,64.252.128.0/18,54.182.154.0/23,64.252.64.0/18,54.182.144.0/21,54.182.224.0/21,130.176.128.0/21,52.46.32.0/19,52.82.128.0/23,18.68.0.0/16,54.182.156.0/22,54.182.160.0/21,54.182.240.0/21,130.176.192.0/19,130.176.76.0/24,52.46.16.0/20,54.239.208.0/21,54.182.188.0/23,130.176.80.0/22,54.182.128.0/20,130.176.72.0/22,13.113.196.64/26,13.113.203.0/24,52.199.127.192/26,13.124.199.0/24,13.124.199.0/24,3.35.130.128/25,52.78.247.128/26,13.233.177.192/26,15.207.13.128/25,15.207.213.128/25,52.66.194.128/26,13.228.69.0/24,52.220.191.0/26,13.210.67.128/26,13.54.63.128/26,99.79.169.0/24,18.192.142.0/23,35.158.136.0/24,52.57.254.0/24,13.48.32.0/24,18.200.212.0/23,52.212.248.0/26,3.10.17.128/25,3.11.53.0/24,52.56.127.0/25,15.188.184.0/24,52.47.139.0/24,18.229.220.192/26,54.233.255.128/26,3.231.2.0/25,3.234.232.224/27,3.236.169.192/26,3.236.48.0/23,34.195.252.0/24,34.226.14.0/24,13.59.250.0/26,18.216.170.128/25,3.128.93.0/24,3.134.215.0/24,52.15.127.128/26,3.101.158.0/23,52.52.191.128/26,34.216.51.0/25,34.223.12.224/27,34.223.80.192/26,35.162.63.192/26,35.167.191.128/26,44.227.178.0/24,44.234.108.128/25,44.234.90.252/30
Endpoint = engage.cloudflareclient.com:2408
PersistentKeepalive = 5
EOF
        # Enable wireguard service
        wg-quick down wg0
        wg-quick up wg0
        systemctl enable --now wg-quick@wg0

        # Check if warp has been activated
        curl -s -m 4 https://ipinfo.io | grep -qi cloudflare
        judge "WARP activation"
    else
        print_error "wgcf register failed"
    fi
}

function basic_optimizations() {
    # Load hybla modlue
    if lsmod | grep -q 'hybla'; then
        modprobe tcp_hybla &&
            echo "tcp_hybla" >>/etc/modules-load.d/modules.conf
    fi

    if [[ -d /etc/sysctl.d/ ]]; then
        cat <<-EOF >/etc/sysctl.d/90-basic-optimizations.conf
fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = hybla
EOF
        sysctl -p /etc/sysctl.d/90-basic-optimizations.conf
    fi

    if [[ -d /etc/security/limits.d/ ]]; then
        echo -e "* soft nofile 51200\n* hard nofile 51200" >>/etc/security/limits.d/nofile.conf
    fi
}

# function create_subscription() {

# }

function main() {
    check_root
    install_commons
    judge "install commons"

    ask_do "Add personal configs(aliases, auto-attach tmux and ...)" add_personal_configs
    ask_do "Add the dude user" add_newuser
    ask_do "Install HAProxy" install_haproxy
    ask_do "Install fake upload cronjob" install_fakeupload_cronjob
    ask_do "Install v2fly and Xray" install_v2ray_xray
    ask_do "Disable SSH password authentication" disable_ssh_password_authentication
    ask_do "Setup DOT via systemd-resolved" setup_DOT
    ask_do "Setup Xray+Nginx automatically" setup_xray_nginx
    ask_do "Setup and enable WARP" setup_warp
    ask_do "Apply basic Optimization configs(max number of files, tcp_congestion_control, ...)" basic_optimizations
}

main
