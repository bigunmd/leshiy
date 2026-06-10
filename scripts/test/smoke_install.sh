#!/bin/sh
# Exercises install.sh's REAL verify_and_install_binary against a FAKE local release inside a
# throwaway container: download (under the artifact's real name) -> minisign verify -> sha256
# check -> extract -> install. Asserts a good release installs a working binary, and a tampered
# tarball aborts. Running the actual function (not a hand-rolled copy) is what catches name/flag
# mismatches in the real download path.
set -eu
here="$(cd "$(dirname "$0")/../.." && pwd)"

docker run --rm -v "$here":/work -w /work debian:12 sh -eu -c '
  apt-get update -qq && apt-get install -y -qq curl minisign python3 >/dev/null 2>&1

  # 1) Build a fake release: a dummy leshiy binary tarball under the REAL artifact name.
  mkdir -p /srv/rel
  printf "#!/bin/sh\necho fake-leshiy\n" > /srv/bin-leshiy && chmod +x /srv/bin-leshiy
  tar -C /srv -czf /srv/rel/leshiy-vT-x86_64-unknown-linux-musl.tar.gz \
    --transform s,bin-leshiy,leshiy, bin-leshiy
  ( cd /srv/rel && sha256sum *.tar.gz > SHA256SUMS )

  # 2) Sign SHA256SUMS with a throwaway passwordless minisign key.
  minisign -G -p /srv/minisign.pub -s /srv/minisign.key -W -f >/dev/null 2>&1
  printf "\n" | minisign -S -s /srv/minisign.key -m /srv/rel/SHA256SUMS >/dev/null 2>&1
  PUB="$(tail -1 /srv/minisign.pub)"

  # 3) Serve the release over HTTP.
  ( cd /srv/rel && python3 -m http.server 8000 >/dev/null 2>&1 & )
  sleep 1

  # 4) Source the REAL install.sh (main guarded off) with the test pubkey embedded, then run
  #    its actual verify_and_install_binary against the local release.
  sed "s|^MINISIGN_PUB=.*|MINISIGN_PUB=\"$PUB\"|" /work/scripts/install.sh > /tmp/install.sh
  export LESHIY_SOURCED=1 LESHIY_BASE_URL=http://127.0.0.1:8000 LESHIY_BINDIR=/tmp/bin LESHIY_REPO=test/test
  . /tmp/install.sh
  VERSION=vT

  # Good path: must download (real name), verify, checksum, extract, install a working binary.
  verify_and_install_binary
  [ -x /tmp/bin/leshiy ] || { echo "BINARY-NOT-INSTALLED"; exit 1; }
  /tmp/bin/leshiy | grep -q fake-leshiy || { echo "BINARY-NOT-RUNNABLE"; exit 1; }
  echo "GOOD-PATH-OK"

  # Tamper: corrupt the served tarball; verify must now abort at the checksum step.
  printf "x" >> /srv/rel/leshiy-vT-x86_64-unknown-linux-musl.tar.gz
  rm -f /tmp/bin/leshiy
  if ( verify_and_install_binary ) >/dev/null 2>&1; then
    echo "TAMPER-NOT-DETECTED"; exit 1
  else
    echo "TAMPER-DETECTED-OK"
  fi
'
