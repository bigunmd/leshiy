#!/bin/sh
# Runs install.sh verify logic against a FAKE local release inside a throwaway container.
# Asserts: good artifacts verify; a tampered tarball aborts (checksum mismatch).
set -eu
here="$(cd "$(dirname "$0")/../.." && pwd)"

docker run --rm -v "$here":/work -w /work debian:12 sh -eu -c '
  apt-get update -qq && apt-get install -y -qq minisign >/dev/null 2>&1

  # Build a tiny fake "release": a dummy leshiy binary + checksums + signature.
  mkdir -p /srv/rel
  printf "#!/bin/sh\necho fake-leshiy\n" > /srv/bin-leshiy && chmod +x /srv/bin-leshiy
  tar -C /srv -czf /srv/rel/leshiy-vT-x86_64-unknown-linux-musl.tar.gz \
    --transform s,bin-leshiy,leshiy, bin-leshiy
  ( cd /srv/rel && sha256sum *.tar.gz > SHA256SUMS )

  # Generate a passwordless keypair (-W suppresses password encryption on keygen).
  minisign -G -p /srv/minisign.pub -s /srv/minisign.key -W -f >/dev/null 2>&1

  # Sign with empty password (passwordless key still prompts without piped input).
  printf "\n" | minisign -S -s /srv/minisign.key -m /srv/rel/SHA256SUMS >/dev/null 2>&1

  # Sanity: confirm the pubkey placeholder in install.sh can be substituted.
  PUB="$(tail -1 /srv/minisign.pub)"
  sed "s|RWQ_REPLACE_WITH_REAL_PUBKEY_LINE|$PUB|" scripts/install.sh > /tmp/install.sh
  grep -q "$PUB" /tmp/install.sh || { echo "PUBKEY-SUBST-FAILED"; exit 1; }

  # Good path: verify exactly the way install.sh::verify_and_install_binary does.
  minisign -Vm /srv/rel/SHA256SUMS -p /srv/minisign.pub -x /srv/rel/SHA256SUMS.minisig \
    || { echo "SIG-VERIFY-FAILED"; exit 1; }
  ( cd /srv/rel && grep "leshiy-vT-x86_64-unknown-linux-musl.tar.gz" SHA256SUMS | sha256sum -c - ) \
    || { echo "CHECKSUM-VERIFY-FAILED"; exit 1; }
  echo "GOOD-PATH-OK"

  # Tamper: flip a byte in the tarball; the checksum check MUST now fail.
  printf "x" >> /srv/rel/leshiy-vT-x86_64-unknown-linux-musl.tar.gz
  if ( cd /srv/rel && grep "leshiy-vT-x86_64-unknown-linux-musl.tar.gz" SHA256SUMS \
       | sha256sum -c - ) 2>/dev/null; then
    echo "TAMPER-NOT-DETECTED"; exit 1
  else
    echo "TAMPER-DETECTED-OK"
  fi
'
