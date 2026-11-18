#!/usr/bin/env bash
# Unit tests for check-java4shell.sh: feed the analyzer synthetic probe output
# and check the verdict. Touches no environment.
set -u
cd "$(dirname "$0")"
CHECK_JAVA4SHELL_LIB=1 source ./check-java4shell.sh

PASS=0; FAIL=0
X86_VBMI='JCPU=[0.002s][info][os,cpu] CPU: total 4 family 6 model 106, sse4.2, avx, avx2, bmi1, bmi2, avx512f, avx512bw, avx512_vbmi, avx512_vbmi2, fma'
X86_NOVBMI='JCPU=[0.002s][info][os,cpu] CPU: total 4 family 6 model 85, sse4.2, avx, avx2, bmi2, avx512f, avx512dq, avx512bw, avx512vl, fma'
X86_ONLY_VBMI2='JCPU=[0.002s][info][os,cpu] CPU: total 4, avx2, bmi2, avx512f, avx512bw, avx512_vbmi2, fma'
ARM='JCPU=[0.002s][info][os,cpu] CPU: total 12 0x61:0x0:0x000:0, fp, asimd, aes, sha256'

# mk <runtime.version> <os.arch> <JCPU line> <UseAVX> <UseBASE64Intrinsics>
mk() {
  printf 'PROP=    java.runtime.version = %s\nPROP=    java.vendor = Test\nPROP=    os.arch = %s\n%s\n' "$1" "$2" "$3"
  [ -n "$4" ] && printf 'JFLAG=     int UseAVX                                   = %s                                    {ARCH product} {default}\n' "$4"
  [ -n "$5" ] && printf 'JFLAG=     bool UseBASE64Intrinsics                      = %s                                      {product} {default}\n' "$5"
}
t() { # t <name> <expected verdict> <probe output>
  local got; got=$(analyze "$1" - <<<"$3" | sed -n -E 's/^   (verdict|veredito): *([^—]*) —.*/\2/p' | sed 's/ *$//')
  if [ "$got" = "$2" ]; then PASS=$((PASS+1)); printf '  ok    %-44s %s\n' "$1" "$got"
  else FAIL=$((FAIL+1)); printf '  FAIL  %-44s expected [%s] got [%s]\n' "$1" "$2" "$got"; fi
}

echo "Versions and lines"
t "Red Hat 21.0.12.1 x86 VBMI"            EXPOSED                "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true)"
t "Temurin 21.0.5 x86 VBMI"               EXPOSED                "$(mk 21.0.5+11-LTS amd64 "$X86_VBMI" 3 true)"
t "21.0.13 (October) still affected"       EXPOSED                "$(mk 21.0.13+11-LTS amd64 "$X86_VBMI" 3 true)"
t "21.0.13.1 fixed"                   FIXED              "$(mk 21.0.13.1+2-LTS amd64 "$X86_VBMI" 3 true)"
t "21.0.14 fixed"                     FIXED              "$(mk 21.0.14+7-LTS amd64 "$X86_VBMI" 3 true)"
t "Corretto 21.0.13.1.2"                  FIXED              "$(mk 21.0.13.1.2+2-LTS amd64 "$X86_VBMI" 3 true)"
t "Oracle internal 21.0.13.0.3"            EXPOSED                "$(mk 21.0.13.0.3+1 amd64 "$X86_VBMI" 3 true)"
t "17.0.5 before the intrinsic"             "OUT OF SCOPE"       "$(mk 17.0.5+8 amd64 "$X86_VBMI" 3 true)"
t "17.0.6 first affected"               EXPOSED                "$(mk 17.0.6+10 amd64 "$X86_VBMI" 3 true)"
t "17.0.21 affected"                       EXPOSED                "$(mk 17.0.21+9 amd64 "$X86_VBMI" 3 true)"
t "17.0.21.1 fixed"                   FIXED              "$(mk 17.0.21.1+4 amd64 "$X86_VBMI" 3 true)"
t "25 GA (25+36) affected"                 EXPOSED                "$(mk 25+36-LTS amd64 "$X86_VBMI" 3 true)"
t "25.0.5.1 fixed"                    FIXED              "$(mk 25.0.5.1+2-LTS amd64 "$X86_VBMI" 3 true)"
t "27.0.1.1 fixed"                    FIXED              "$(mk 27.0.1.1+4 amd64 "$X86_VBMI" 3 true)"
t "27.0.1 affected"                        EXPOSED                "$(mk 27.0.1+9 amd64 "$X86_VBMI" 3 true)"
t "Java 11"                               "OUT OF SCOPE"       "$(mk 11.0.25+9 amd64 "$X86_VBMI" 3 true)"
t "Java 8 (1.8.0_412)"                    "OUT OF SCOPE"       "$(mk 1.8.0_412-b08 amd64 "$X86_VBMI" 3 true)"
t "Java 23 (non-LTS) affected"             EXPOSED                "$(mk 23.0.2+7 amd64 "$X86_VBMI" 3 true)"
t "leading zero 21.0.08"    EXPOSED                "$(mk 21.0.08+1 amd64 "$X86_VBMI" 3 true)"

echo "CPU and architecture"
t "ARM64"                                 "OUT OF SCOPE"       "$(mk 21.0.12.1+1-LTS aarch64 "$ARM" "" true)"
t "x86 Cascade Lake (no VBMI)"           "NOT EXPOSED ON THIS NODE" "$(mk 21.0.12.1+1-LTS amd64 "$X86_NOVBMI" 3 true)"
t "avx512_vbmi2 alone is not vbmi"   "NOT EXPOSED ON THIS NODE" "$(mk 21.0.12.1+1-LTS amd64 "$X86_ONLY_VBMI2" 3 true)"
t "/proc/cpuinfo fallback with avx512vbmi" EXPOSED                "$(mk 21.0.12.1+1-LTS amd64 'FLAGS=flags : avx2 bmi2 avx512f avx512bw avx512vbmi' 3 true)"
t "no CPU features"                   UNDETERMINED          "$(mk 21.0.12.1+1-LTS amd64 "" 3 true)"

echo "Workaround (effective JVM value)"
t "UseBASE64Intrinsics=false"             "MITIGATED (WORKAROUND)" "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 false)"
t "UseAVX=2"                              "MITIGATED (WORKAROUND)" "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 2 true)"
t "effective flags unreadable"              UNDETERMINED          "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" "" "")"

echo "Portuguese output (--lang pt)"
J4S_LANG=pt
t "pt: exposed"                           EXPOSTO                "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true)"
t "pt: not exposed on this node"              "NÃO EXPOSTO NESTE NÓ" "$(mk 21.0.12.1+1-LTS amd64 "$X86_NOVBMI" 3 true)"
t "pt: mitigated"                          "MITIGADO (WORKAROUND)" "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 false)"
J4S_LANG=en

echo "Collection failures"
t "no java"                              UNDETERMINED          "JPID="

echo
echo "ver_ge"
for p in "21.0.12.1 21.0.13.1 1" "21.0.13.1 21.0.13.1 0" "21.0.14 21.0.13.1 0" "17.0.5 17.0.6 1" "17.0.21 17.0.21.1 1" "17.0.21.1.2 17.0.21.1 0"; do
  set -- $p; ver_ge "$1" "$2"; r=$?
  if [ "$r" = "$3" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "  FAIL ver_ge $1 $2 → $r"; fi
done
echo "  $((PASS)) checks so far"

echo
echo "Result: $PASS ok, $FAIL failed"
[ "$FAIL" = 0 ]
