# php2shellScanner

Local patch check for PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Read-only, no
requests sent, nothing modified. Run it on the box you are checking.

Version strings lie here. Ubuntu backports the fix as `8.3.6-0ubuntu0.24.04.13` and
`php -v` still says `8.3.6`. These scripts check the binary for
`memory_hard_limit_percent`, the INI entry the fix adds.

## Before

```sh
sudo bash php2shell_check.sh       | tee /tmp/php2shell-before.txt
sudo bash php2shell_fingerprint.sh | tee -a /tmp/php2shell-before.txt
```

## Patch

```sh
sudo apt update
sudo apt install --only-upgrade $(dpkg -l | awk '/^ii  php/{print $2}')
sudo systemctl restart apache2        # restart, not reload, or old code stays mapped
sudo systemctl restart 'php*-fpm'     # if you use FPM
```

Docker needs a rebuild, host updates do nothing for the image:

```sh
docker compose build --pull && docker compose up -d
```

7.4, 8.0 and 8.1 are EOL. Upstream published source backports and some vendors ship
packages, so check your changelog before assuming you are stuck.

## After

```sh
sudo bash php2shell_check.sh       | tee /tmp/php2shell-after.txt
sudo bash php2shell_fingerprint.sh | tee -a /tmp/php2shell-after.txt
diff /tmp/php2shell-before.txt /tmp/php2shell-after.txt
```

## Exit codes

`php2shell_check.sh`: 0 clean, 1 vulnerable, 2 restart needed, 3 indicators to review.

`php2shell_fingerprint.sh`: 0 fix present, 1 fix absent, 2 changelog and binary disagree.

Exit 2 usually means a minimal vendor backport that fixed the bug without adding the INI
entry. Ask your vendor, do not guess.

## Notes

Indicator output is triage, not proof. WordPress updates touch PHP files and show up
there. `SINCE=YYYY-MM-DD` moves the window.

Hostname is left out of output so it is safe to paste. `SHOW_HOST=1` puts it back.

Fixed upstream: 8.2.35, 8.3.36, 8.4.27, 8.5.12.

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://ubuntu.com/security/notices/USN-8948-1
