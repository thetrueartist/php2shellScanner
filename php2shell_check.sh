#!/usr/bin/env bash
# php2shell_check.sh - local patch, exposure and compromise check for
# CVE-2026-109618 / CVE-2026-109619 (PHP2Shell). Read-only, changes nothing.
# Run on each box:  sudo bash php2shell_check.sh
# Exit: 0 patched+clean, 1 vulnerable PHP present, 2 restart needed, 3 indicators worth reviewing
set -u
CVES='CVE-2026-10961[89]'
SINCE="${SINCE:-2026-10-20}"          # leak date; override with SINCE=YYYY-MM-DD
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
MARKERS=('memory_hard_limit_percent' 'Hard memory limit of')   # strings added by the fix commit
R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
[ -t 1 ] || { R=; G=; Y=; B=; N=; }
vuln=0; restart=0; ioc=0
hdr(){ echo; echo "${B}== $*${N}"; }
[ "$(id -u)" -eq 0 ] || echo "${Y}! not root: log, process and file checks will be incomplete${N}"
echo "${B}php2shell_check${N} on ${SHOW_HOST:+$(hostname) - }$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-?}") / $(uname -m)"

# ---------- 1. packages ----------
hdr "1. Installed PHP packages"
branches=$(dpkg-query -W -f='${Package}\n' 'php[5-8]*' 'libapache2-mod-php*' 2>/dev/null | grep -oE 'php[5-8]\.[0-9]+' | sed 's/php//' | sort -uV)
[ -z "$branches" ] && echo "  no distro PHP packages"
for br in $branches; do
  pkgs=$(dpkg-query -W -f='${Status} ${Package} ${Version}\n' "php${br}-*" "libapache2-mod-php${br}" 2>/dev/null | awk '$3=="installed"{print $4" "$5}')
  [ -z "$pkgs" ] && continue
  ver=$(echo "$pkgs" | awk '$1 ~ /-(common|cli)$/{print $2; exit}'); [ -z "$ver" ] && ver=$(echo "$pkgs" | awk 'NR==1{print $2}')
  up=${ver%%-*}; up=${up#*:}
  src=ubuntu; echo "$ver" | grep -q sury && src=ondrej-ppa
  cl=no; for c in /usr/share/doc/php${br}-*/changelog.Debian.gz /usr/share/doc/libapache2-mod-php${br}/changelog.Debian.gz; do
    [ -f "$c" ] && zgrep -qE "$CVES" "$c" 2>/dev/null && { cl=yes; break; }; done
  vr=no; [ -n "${FIXED[$br]:-}" ] && dpkg --compare-versions "$up" ge "${FIXED[$br]}" && vr=yes
  if [ $cl = yes ] || [ $vr = yes ]; then
    echo "  ${G}PATCHED${N}    php$br $ver ($src; changelog=$cl version=$vr)"
  else
    vuln=1; h="wait for Ubuntu USN"; [ $src = ondrej-ppa ] && h="need >= ${FIXED[$br]:-a backport} from PPA"
    [ -z "${FIXED[$br]:-}" ] && h="EOL upstream: patched only if your vendor backports"
    echo "  ${R}VULNERABLE${N} php$br $ver ($src) -> $h"
  fi
done

# ---------- 2. binary fingerprints ----------
hdr "2. Fix fingerprint in the binaries actually loaded"
echo "  (looks for strings the fix adds; absence on a changelog-patched distro build can mean a minimal backport)"
bins=$(ls /usr/lib/apache2/modules/libphp*.so /usr/sbin/php-fpm* /usr/bin/php[5-8]* /usr/bin/php-cgi* 2>/dev/null | sort -u)
[ -z "$bins" ] && echo "  no PHP binaries found in standard paths"
for f in $bins; do
  [ -L "$f" ] && continue
  hits=0; for m in "${MARKERS[@]}"; do grep -aqF "$m" "$f" 2>/dev/null && hits=$((hits+1)); done
  if [ $hits -eq ${#MARKERS[@]} ]; then echo "  ${G}fix present${N}  $f"
  else echo "  ${Y}no marker${N}    $f"; fi
done

# ---------- 3. what is serving and is it exposed ----------
hdr "3. Serving and exposure"
if command -v apache2ctl >/dev/null 2>&1; then
  echo "  apache2 modules: $(apache2ctl -M 2>/dev/null | grep -iE 'php|proxy_fcgi|mpm' | awk '{print $1}' | xargs)"
fi
fpm=$(systemctl list-units --type=service --state=running --no-legend 'php*-fpm*' 2>/dev/null | awk '{print $1}' | xargs)
echo "  php-fpm running: ${fpm:-none}"
pub=$(ss -ltnpH 2>/dev/null | awk '{print $4, $6}' | grep -E 'apache2|httpd|php-fpm|lsphp|frankenphp' | grep -vE '^(127\.|\[::1\]|::1)')
if [ -n "$pub" ]; then
  echo "  ${Y}listening on non-loopback (reachable directly unless firewalled):${N}"; echo "$pub" | sed 's/^/      /'
  command -v ufw >/dev/null 2>&1 && echo "      ufw: $(ufw status 2>/dev/null | head -1)"
else echo "  ${G}PHP web listeners are loopback-only or absent${N}"; fi
for d in /etc/php/*/apache2 /etc/php/*/fpm; do
  [ -f "$d/php.ini" ] || continue
  v=$(PHP_INI_SCAN_DIR="$d/conf.d" php -c "$d/php.ini" -r 'echo var_export(ini_get("session.upload_progress.enabled"),true);' 2>/dev/null)
  echo "  session.upload_progress.enabled for $d: ${v:-?}"
done
command -v cloudflared >/dev/null 2>&1 && echo "  cloudflared: $(systemctl is-active cloudflared 2>/dev/null || echo unknown)"
# these two are local stopgap filenames; harmless no-op if you never created them
for f in /etc/apache2/conf-enabled/php2shell.conf /etc/php/*/*/conf.d/99-php2shell.ini; do [ -e "$f" ] && echo "  stopgap present: $f"; done

# ---------- 4. stale processes ----------
hdr "4. Old PHP still in memory"
stale=$(grep -lE '(libphp|/php[5-8]?[0-9.]*|php-fpm[0-9.]*)[^/]*\(deleted\)' /proc/[0-9]*/maps 2>/dev/null | cut -d/ -f3 | sort -un | xargs -r ps -o pid=,comm= -p 2>/dev/null)
if [ -n "$stale" ]; then restart=1; echo "  ${Y}RESTART NEEDED${N} (apache2 with mod_php needs restart, not reload):"; echo "$stale" | sed 's/^/      /'
else echo "  ${G}none${N}"; fi

# ---------- 5. compromise indicators ----------
hdr "5. Indicators since $SINCE (review, not proof)"
mon=$(date -d "$SINCE" +%b 2>/dev/null); days=$(for i in 0 1 2 3; do date -d "$SINCE +$i day" '+%b %d' 2>/dev/null; done | sed 's/ 0/ /' | paste -sd'|')
logs=$(ls /var/log/apache2/*error*.log* /var/log/php*-fpm.log* 2>/dev/null)
if [ -n "$logs" ]; then
  win=$(zgrep -hE "($days)[^]]* $(date -d "$SINCE" +%Y)" $logs 2>/dev/null)
  seg=$(printf '%s' "$win" | grep -cE 'Segmentation fault|exit signal|SIGSEGV|SIGBUS|signal 11' || true); seg=${seg:-0}
  oom=$(printf '%s' "$win" | grep -cE 'Allowed memory size of .* exhausted.* in Unknown on line 0' || true); oom=${oom:-0}
  echo "  worker crashes (segfault/signal) in error logs: $seg"
  echo "  pre-script OOM fatals ('in Unknown on line 0'): $oom"
  if [ "$seg" -gt 0 ] || [ "$oom" -gt 0 ]; then
    ioc=1
    printf '%s' "$win" | grep -E 'Segmentation fault|exit signal|SIGSEGV|signal 11|Unknown on line 0' | tail -5 | cut -c1-200 | sed 's/^/      /'
  fi
else echo "  no apache/fpm error logs found"; fi

roots=$( { apache2ctl -S 2>/dev/null | grep -oE 'DocumentRoot: "[^"]+"' | cut -d'"' -f2; grep -rhoE '^\s*DocumentRoot\s+\S+' /etc/apache2/sites-enabled/ 2>/dev/null | awk '{print $2}' | tr -d '"'; echo /var/www; } | sort -u)
for r in $roots; do
  [ -d "$r" ] || continue
  new=$(find "$r" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.htaccess' -o -name '.user.ini' \) -newermt "$SINCE" \
        -not -path '*/cache/*' 2>/dev/null)
  n=$(printf '%s' "$new" | grep -c .)
  if [ "$n" -gt 0 ]; then ioc=1; echo "  ${Y}$n PHP/config files changed under $r${N} (WP updates cause false positives):"; echo "$new" | head -15 | sed 's/^/      /'
  else echo "  ${G}no changed PHP/config files under $r${N}"; fi
done

wd=$(id -u www-data 2>/dev/null || echo 33)
tmp=$(find /tmp /var/tmp /dev/shm -xdev -user "$wd" -newermt "$SINCE" \( -type f -o -type d \) 2>/dev/null | grep -vE '/(sess_|php[A-Za-z0-9]{6}$)' | head -15)
[ -n "$tmp" ] && { ioc=1; echo "  ${Y}www-data files in tmp:${N}"; echo "$tmp" | sed 's/^/      /'; } || echo "  ${G}nothing unusual from www-data in tmp${N}"

cr=$(crontab -l -u www-data 2>/dev/null | grep -vE '^\s*(#|$)')
[ -n "$cr" ] && { ioc=1; echo "  ${Y}www-data crontab:${N}"; echo "$cr" | sed 's/^/      /'; } || echo "  ${G}no www-data crontab${N}"

procs=$(ps -u "$wd" -o pid=,etime=,args= 2>/dev/null | grep -vE 'apache2|httpd|php-fpm|lsphp' )
[ -n "$procs" ] && { ioc=1; echo "  ${Y}non-server processes running as www-data:${N}"; echo "$procs" | cut -c1-160 | sed 's/^/      /'; } || echo "  ${G}no stray www-data processes${N}"

# ---------- 6. docker ----------
if command -v docker >/dev/null 2>&1 && [ -n "$(docker ps -q 2>/dev/null)" ]; then
  hdr "6. Docker containers"
  for id in $(docker ps -q); do
    name=$(docker inspect -f '{{.Name}} ({{.Config.Image}})' "$id")
    v=$(docker exec "$id" php -r 'echo PHP_VERSION;' 2>/dev/null) || continue
    br=${v%.*}
    if [ -n "${FIXED[$br]:-}" ] && dpkg --compare-versions "$v" ge "${FIXED[$br]}"; then echo "  ${G}PATCHED${N}    $name php $v"
    else vuln=1; echo "  ${R}VULNERABLE${N} $name php $v -> rebuild with --pull"; fi
  done
fi

echo
[ $ioc -eq 1 ] && echo "${Y}${B}Indicators found: review section 5 before going live.${N}"
if   [ $vuln -eq 1 ];    then echo "${R}${B}VERDICT: VULNERABLE - keep sites offline${N}"; exit 1
elif [ $ioc -eq 1 ];     then echo "${Y}${B}VERDICT: patched, but review indicators before going live${N}"; exit 3
elif [ $restart -eq 1 ]; then echo "${Y}${B}VERDICT: patched on disk, restart services before going live${N}"; exit 2
else echo "${G}${B}VERDICT: PATCHED and no indicators - safe to bring sites back, then remove stopgaps${N}"; exit 0; fi
