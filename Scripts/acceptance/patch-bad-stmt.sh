#!/bin/sh
# G27: patch-asm must fail on a statement it cannot assemble after ';' instead of dropping it and
# writing the rest. Copied from flagship-acceptance/harness/machgraph/recheck/patch_bad_stmt.sh; the only
# additions are the default binary path and a throwaway HOME for the product command.
# Usage: patch-bad-stmt.sh [<MachGraph executable>]
set -u
BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/.build/debug/MachGraph}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/home"
printf 'int add(int a,int b){return a+b;}\nint main(void){return add(1,2);}\n' > "$W/t.c"
clang -arch arm64 -O0 -o "$W/t" "$W/t.c" || exit 99
ADDR="0x$(nm "$W/t" | awk '$3=="_add"{print $1}')"
fail=0
for asm in "nop; bogus x1" "mov x0, #1; garbage" "nop; ; nop extra words here"; do
  cp "$W/t" "$W/in"
  HOME="$W/home" CFFIXED_USER_HOME="$W/home" "$BIN" patch-asm "$W/in" --address "$ADDR" --asm "$asm" --output "$W/out" >/dev/null 2>&1
  code=$?
  if [ "$code" -eq 0 ] || [ -e "$W/out" ] || ! cmp -s "$W/t" "$W/in"; then
    echo "FAIL: --asm \"$asm\" exit $code, output file $( [ -e "$W/out" ] && echo written || echo not written )"
    fail=1
  else
    echo "ok:   --asm \"$asm\" exit $code, no output file, input unchanged"
  fi
  rm -f "$W/out"
done
exit $fail
