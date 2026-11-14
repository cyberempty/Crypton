#!/bin/sh
# Builds the single-file Linux launcher "Crypton-Linux" from two binaries.
#
#     sh packaging/linux/make-launcher.sh <crypton-x86_64> <crypton-aarch64> <output>
#
# The result is a small shell script followed by a compressed archive holding both
# programs. When started, it unpacks the one matching the processor into a private
# temporary folder, runs it and deletes it when Crypton is closed. Nothing is
# installed. It works on any Linux that has sh, tar and gzip (all of them).
#
# The two binaries are built as described in the README, with cargo-zigbuild:
#     cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17
#     cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.17
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <crypton-x86_64> <crypton-aarch64> <output>" >&2
  exit 1
fi
X86="$1"
ARM="$2"
OUT="$3"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp "$X86" "$WORK/crypton-x86_64"
cp "$ARM" "$WORK/crypton-aarch64"
chmod 755 "$WORK/crypton-x86_64" "$WORK/crypton-aarch64"
tar -czf "$WORK/payload.tgz" -C "$WORK" crypton-x86_64 crypton-aarch64

# The stub has a fixed-width OFFSET field (padded with spaces), so its size is known
# before filling it in.
cat > "$WORK/stub" <<'STUB'
#!/bin/sh
# Crypton for Linux: one file for every Linux (x86-64 and ARM64).
# It contains both programs. On start it unpacks the right one into a private
# temporary folder, runs it, and deletes it when you close Crypton.
OFFSET=0000000
case "$(uname -m)" in
  x86_64|amd64)  NAME=crypton-x86_64 ;;
  aarch64|arm64) NAME=crypton-aarch64 ;;
  *) echo "Crypton: unsupported processor ($(uname -m)). Supported: x86-64 and ARM64." >&2; exit 1 ;;
esac
case "$0" in /*) SELF="$0" ;; *) SELF="$PWD/$0" ;; esac
[ -r "$SELF" ] || { echo "Crypton: cannot read $SELF" >&2; exit 1; }

DIR=""
cleanup() { [ -n "$DIR" ] && rm -rf "$DIR"; }
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT TERM HUP

# Some systems mount /tmp with "noexec": try several places until one can run programs.
for BASE in "${XDG_RUNTIME_DIR:-}" /tmp "${HOME:-}/.cache" "$PWD"; do
  [ -n "$BASE" ] && [ -d "$BASE" ] && [ -w "$BASE" ] || continue
  DIR="$(mktemp -d "$BASE/crypton.XXXXXX" 2>/dev/null)" || { DIR=""; continue; }
  if tail -c +$((OFFSET + 1)) "$SELF" | tar -xzf - -C "$DIR" "$NAME" 2>/dev/null; then
    chmod 700 "$DIR/$NAME"
    "$DIR/$NAME" "$@"
    RC=$?
    # 126/127: this place cannot execute programs, try the next one
    if [ "$RC" -ne 126 ] && [ "$RC" -ne 127 ]; then
      exit "$RC"
    fi
  fi
  rm -rf "$DIR"
  DIR=""
done
echo "Crypton: could not unpack and start the program (no writable folder that allows running programs)." >&2
exit 1
# (the compressed program archive follows this line)
STUB

SIZE="$(wc -c < "$WORK/stub" | tr -d ' ')"
PADDED="$(printf '%-7s' "$SIZE")"
sed "s/^OFFSET=0000000\$/OFFSET=$PADDED/" "$WORK/stub" > "$WORK/stub2"
[ "$(wc -c < "$WORK/stub2" | tr -d ' ')" = "$SIZE" ] || { echo "internal error: stub size changed" >&2; exit 1; }

cat "$WORK/stub2" "$WORK/payload.tgz" > "$OUT"
chmod 755 "$OUT"
echo "Created $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
