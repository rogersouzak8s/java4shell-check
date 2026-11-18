#!/usr/bin/env bash
# Integration test: runs check-java4shell.sh against real JVMs in Docker and
# checks that it finds the process, reads the effective flags and gives the
# verdict that matches this machine's CPU. Needs Docker. Starts its own
# containers (prefix j4s-it-) and removes them at the end.
#
# On an x86-64 host with AVX-512 VBMI (e.g. Intel Ice Lake or newer) this
# exercises the EXPOSED and MITIGATED verdicts on real hardware.
set -u
cd "$(dirname "$0")" || exit 1

# Pinned, affected releases: the expected verdicts do not drift with new tags.
IMG21="eclipse-temurin:21.0.5_11-jdk"
IMG8="eclipse-temurin:8u432-b06-jdk"
APP='class S{public static void main(String[] a)throws Exception{Thread.sleep(3600000);}}'
NAMES=(j4s-it-21 j4s-it-21-wa j4s-it-8)
cleanup() { docker rm -f "${NAMES[@]}" >/dev/null 2>&1; }
trap cleanup EXIT
cleanup

start() { # start <name> <image> <extra java flags>
  docker run -d --name "$1" "$2" bash -c "mkdir -p /tmp/s && cd /tmp/s && echo '$APP' > S.java && javac S.java && exec java $3 -cp /tmp/s S" >/dev/null
}
start j4s-it-21    "$IMG21" ""
start j4s-it-21-wa "$IMG21" "-XX:-UseBASE64Intrinsics"
start j4s-it-8     "$IMG8"  ""

for _ in $(seq 1 60); do # wait until java runs in all three
  up=0
  for c in "${NAMES[@]}"; do
    docker exec "$c" bash -c 'for d in /proc/[0-9]*; do read -r n < "$d/comm" 2>/dev/null; [ "$n" = java ] && exit 0; done; exit 1' 2>/dev/null && up=$((up+1))
  done
  [ "$up" = 3 ] && break; sleep 2
done

ARCH=$(docker exec j4s-it-21 uname -m)
VBMI=no; docker exec j4s-it-21 grep -qw avx512vbmi /proc/cpuinfo && VBMI=yes
echo "host: $ARCH, avx512vbmi: $VBMI"
case "$ARCH:$VBMI" in
  x86_64:yes) EXP21="EXPOSED"; EXPWA="MITIGATED (WORKAROUND)";;
  x86_64:no)  EXP21="NOT EXPOSED ON THIS NODE"; EXPWA="NOT EXPOSED ON THIS NODE";;
  *)          EXP21="OUT OF SCOPE"; EXPWA="OUT OF SCOPE";;
esac

OUT=$(./check-java4shell.sh --timeout 120 docker "${NAMES[@]}"); RC=$?
echo "$OUT"

PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok    $1: $2"; else FAIL=$((FAIL+1)); echo "  FAIL  $1: expected [$2] got [$3]"; fi; }
block() { awk -v n="── docker:$1" '$0==n{f=1;next} /^── /{f=0} f' <<<"$OUT"; }
field() { block "$1" | sed -n -E "s/^   $2: *//p" | head -1; }
verdict() { field "$1" verdict | sed 's/ —.*//'; }

check "21: process found (Temurin 21.0.5)" "21.0.5+11-LTS (Eclipse Adoptium)" "$(field j4s-it-21 JDK)"
check "21: intrinsic on"                   "UseBASE64Intrinsics=true"         "$(field j4s-it-21 'effective flags' | grep -o 'UseBASE64Intrinsics=[a-z]*')"
check "21: verdict"                        "$EXP21"                           "$(verdict j4s-it-21)"
check "21-wa: workaround read"             "UseBASE64Intrinsics=false"        "$(field j4s-it-21-wa 'effective flags' | grep -o 'UseBASE64Intrinsics=[a-z]*')"
check "21-wa: verdict"                     "$EXPWA"                           "$(verdict j4s-it-21-wa)"
check "8: process found (Java 8)"          "1.8.0_432-b06"                    "$(field j4s-it-8 JDK | cut -d' ' -f1)"
check "8: verdict"                         "OUT OF SCOPE"                     "$(verdict j4s-it-8)"
case "$EXP21" in EXPOSED) WANT=2;; *) WANT=0;; esac
check "exit code"                          "$WANT"                            "$RC"

echo
echo "Result: $PASS ok, $FAIL failed"
[ "$FAIL" = 0 ]
