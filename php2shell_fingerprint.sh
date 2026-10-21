#!/usr/bin/env bash
# php2shell_fingerprint.sh - behavioural patch check for CVE-2026-109618 / 109619,
# derived from the fix commit (php-src 3c832b523e) rather than from version strings.
#
# Method: the fix adds a new INI entry, memory_hard_limit_percent, as part of its
# hard-memory-limit mechanism. If a PHP binary or module knows that setting, it
# contains the fix. Version-independent, so it works for Ubuntu/Debian backports
# that keep the old version number, source builds, EOL vendor backports and
# containers. Read-only: nothing is modified, no requests are sent.
#
# Caveat: absence is strong but not absolute proof. A vendor shipping a hand-cut
# minimal backport could fix the bug without adding the INI entry, so treat a
# NOT FOUND alongside a changelog that cites the CVEs as "probably patched,
# verify with the vendor".
set -u
MARK=memory_hard_limit_percent
CVES='CVE-2026-10961[89]'
R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; [ -t 1 ] || { R=; G=; Y=; B=; N=; }
bad=0; unsure=0

say_patched(){ echo "  ${G}FIX PRESENT${N} $1"; }
say_vuln(){ echo "  ${R}FIX ABSENT${N}  $1"; bad=1; }

echo "${B}== Runtime check (registered INI entries)${N}"
found_bin=0
for p in /usr/bin/php /usr/bin/php[78].[0-9] /usr/bin/php[78].[0-9][0-9] /usr/local/bin/php; do
  [ -x "$p" ] || continue; found_bin=1
  v=$("$p" -r 'echo PHP_VERSION;' 2>/dev/null) || continue
  if "$p" -r 'exit(array_key_exists("memory_hard_limit_percent", ini_get_all(null,false)) ? 0 : 1);' 2>/dev/null; then
    say_patched "$p (PHP $v)"
  else
    say_vuln "$p (PHP $v)"
  fi
done
[ $found_bin -eq 1 ] || echo "  no PHP CLI binary found"

echo "${B}== Binary/module check (symbol present in the file)${N}"
mods=$(ls /usr/lib/apache2/modules/libphp*.so /usr/lib/php/*/*.so 2>/dev/null | grep -E 'libphp' )
sapis=$(ls /usr/sbin/php-fpm* /usr/bin/php-cgi* 2>/dev/null)
for f in $mods $sapis; do
  [ -f "$f" ] || continue
  if grep -aqF "$MARK" "$f" 2>/dev/null; then say_patched "$f"; else say_vuln "$f"; fi
done
[ -n "${mods}${sapis}" ] || echo "  no mod_php / php-fpm / php-cgi binaries found"

echo "${B}== Cross-check against vendor changelog${N}"
cl=0
for c in /usr/share/doc/php*/changelog.Debian.gz; do
  [ -f "$c" ] || continue
  if zgrep -qE "$CVES" "$c" 2>/dev/null; then echo "  ${G}CVEs cited${N} in $c"; cl=1; fi
done
[ $cl -eq 1 ] || echo "  ${Y}no changelog cites the CVEs yet${N}"
if [ $bad -eq 1 ] && [ $cl -eq 1 ]; then
  unsure=1
  echo "  ${Y}conflict: changelog claims the fix but the INI marker is missing."
  echo "   -> possible minimal vendor backport; confirm with the vendor before going live${N}"
fi

echo "${B}== Post-patch capacity check (new hard limit = 2x memory_limit per worker)${N}"
ram=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
# read the WEB sapi php.ini, not the CLI one (CLI defaults to -1)
ml=$(grep -hoP '^\s*memory_limit\s*=\s*\K\S+' /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini 2>/dev/null | tail -1)
[ -z "$ml" ] && ml=128M
case "$ml" in *G|*g) mlm=$(( ${ml%[Gg]} * 1024 ));; *M|*m) mlm=${ml%[Mm]};; -1) mlm=0;; *) mlm=$(( ${ml:-134217728} / 1048576 ));; esac
w=$(grep -rhoP '^\s*MaxRequestWorkers\s+\K[0-9]+' /etc/apache2 2>/dev/null | head -1)
[ -z "$w" ] && w=$(grep -rhoP '^\s*pm\.max_children\s*=\s*\K[0-9]+' /etc/php/*/fpm/pool.d 2>/dev/null | head -1)
if [ -n "$w" ] && [ "${mlm:-0}" -gt 0 ] && [ -n "$ram" ]; then
  if [ "$mlm" -ge 1024 ]; then hard=$(( mlm + 1024 )); else hard=$(( mlm * 2 )); fi
  worst=$(( w * hard ))
  echo "  RAM ${ram}MB | memory_limit ${ml} | workers ${w} | new worst case $(( worst ))MB"
  if [ "$worst" -gt "$ram" ]; then
    echo "  ${Y}after patching, worst case exceeds RAM. Consider memory_hard_limit_percent=120"
    echo "   or lowering worker count, so a burst cannot OOM the box${N}"
  else
    echo "  ${G}headroom ok${N}"
  fi
else
  echo "  skipped (no worker count or memory_limit found)"
fi

echo
if [ $bad -eq 1 ] && [ $unsure -eq 1 ]; then echo "${Y}${B}VERDICT: UNCLEAR - vendor changelog and binary disagree${N}"; exit 2
elif [ $bad -eq 1 ]; then echo "${R}${B}VERDICT: FIX ABSENT - stay offline${N}"; exit 1
else echo "${G}${B}VERDICT: FIX PRESENT in everything checked${N}"; exit 0; fi
