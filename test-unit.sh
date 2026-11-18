#!/usr/bin/env bash
# Unit tests for check-java4shell.sh: feed the analyzer synthetic probe output
# and check the verdict; exercise the parallel job runner with local commands.
# Touches no container, cluster or JVM.
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=check-java4shell.sh
CHECK_JAVA4SHELL_LIB=1 source ./check-java4shell.sh

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok    %-44s %s\n' "$1" "$2"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %-44s expected [%s] got [%s]\n' "$1" "$2" "$3"; }

X86_VBMI='JCPU=[0.002s][info][os,cpu] CPU: total 4 family 6 model 106, sse4.2, avx, avx2, bmi1, bmi2, avx512f, avx512bw, avx512_vbmi, avx512_vbmi2, fma'
X86_NOVBMI='JCPU=[0.002s][info][os,cpu] CPU: total 4 family 6 model 85, sse4.2, avx, avx2, bmi2, avx512f, avx512dq, avx512bw, avx512vl, fma'
X86_ONLY_VBMI2='JCPU=[0.002s][info][os,cpu] CPU: total 4, avx2, bmi2, avx512f, avx512bw, avx512_vbmi2, fma'
ARM='JCPU=[0.002s][info][os,cpu] CPU: total 12 0x61:0x0:0x000:0, fp, asimd, aes, sha256'

# mk <runtime.version> <os.arch> <JCPU line> <UseAVX> <UseBASE64Intrinsics> [extra probe lines]
mk() {
  printf 'PROP=    java.runtime.version = %s\nPROP=    java.vendor = Test\nPROP=    os.arch = %s\n%s\n' "$1" "$2" "$3"
  [ -n "$4" ] && printf 'JFLAG=     int UseAVX                                   = %s                                    {ARCH product} {default}\n' "$4"
  [ -n "$5" ] && printf 'JFLAG=     bool UseBASE64Intrinsics                      = %s                                      {product} {default}\n' "$5"
  [ -n "${6:-}" ] && printf '%s\n' "$6"
  return 0
}
verdict_of() { sed -n -E 's/^   (verdict|veredito): *([^—]*) —.*/\2/p' | sed 's/ *$//'; }
t() { # t <name> <expected verdict> <probe output>
  local got; got=$(analyze "$1" - <<<"$3" | verdict_of)
  if [ "$got" = "$2" ]; then ok "$1" "$got"; else bad "$1" "$2" "$got"; fi
}
has() { # has <name> <text expected in the output> <probe output>
  local o; o=$(analyze target - <<<"$3")
  if grep -qF -- "$2" <<<"$o"; then ok "$1" "contains: $2"; else bad "$1" "$2" "(missing)"; fi
}
hasnt() { # hasnt <name> <text that must not appear> <probe output>
  local o; o=$(analyze target - <<<"$3")
  if grep -qF -- "$2" <<<"$o"; then bad "$1" "no '$2'" "(present)"; else ok "$1" "no: $2"; fi
}

echo "Versions and lines"
t "Red Hat 21.0.12.1 x86 VBMI"               EXPOSED                    "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true)"
t "Temurin 21.0.5 x86 VBMI"                  EXPOSED                    "$(mk 21.0.5+11-LTS amd64 "$X86_VBMI" 3 true)"
t "21.0.13 (October) still affected"         EXPOSED                    "$(mk 21.0.13+11-LTS amd64 "$X86_VBMI" 3 true)"
t "21.0.13.1 fixed"                          FIXED                      "$(mk 21.0.13.1+2-LTS amd64 "$X86_VBMI" 3 true)"
t "21.0.14 fixed"                            FIXED                      "$(mk 21.0.14+7-LTS amd64 "$X86_VBMI" 3 true)"
t "Corretto 21.0.13.1.2"                     FIXED                      "$(mk 21.0.13.1.2+2-LTS amd64 "$X86_VBMI" 3 true)"
t "Oracle internal 21.0.13.0.3"              EXPOSED                    "$(mk 21.0.13.0.3+1 amd64 "$X86_VBMI" 3 true)"
t "17.0.5 before the intrinsic"              "OUT OF SCOPE"             "$(mk 17.0.5+8 amd64 "$X86_VBMI" 3 true)"
t "17.0.6 first affected"                    EXPOSED                    "$(mk 17.0.6+10 amd64 "$X86_VBMI" 3 true)"
t "17.0.21 affected"                         EXPOSED                    "$(mk 17.0.21+9 amd64 "$X86_VBMI" 3 true)"
t "17.0.21.1 fixed"                          FIXED                      "$(mk 17.0.21.1+4 amd64 "$X86_VBMI" 3 true)"
t "25 GA (25+36) affected"                   EXPOSED                    "$(mk 25+36-LTS amd64 "$X86_VBMI" 3 true)"
t "25.0.5.1 fixed"                           FIXED                      "$(mk 25.0.5.1+2-LTS amd64 "$X86_VBMI" 3 true)"
t "27.0.1.1 fixed"                           FIXED                      "$(mk 27.0.1.1+4 amd64 "$X86_VBMI" 3 true)"
t "27.0.1 affected"                          EXPOSED                    "$(mk 27.0.1+9 amd64 "$X86_VBMI" 3 true)"
t "Java 11"                                  "OUT OF SCOPE"             "$(mk 11.0.25+9 amd64 "$X86_VBMI" 3 true)"
t "Java 8 (1.8.0_412)"                       "OUT OF SCOPE"             "$(mk 1.8.0_412-b08 amd64 "$X86_VBMI" 3 true)"
t "Java 23 (non-LTS) affected"               EXPOSED                    "$(mk 23.0.2+7 amd64 "$X86_VBMI" 3 true)"
t "leading zero 21.0.08"                     EXPOSED                    "$(mk 21.0.08+1 amd64 "$X86_VBMI" 3 true)"

echo "CPU and architecture"
t "ARM64"                                    "OUT OF SCOPE"             "$(mk 21.0.12.1+1-LTS aarch64 "$ARM" "" true)"
t "x86 Cascade Lake (no VBMI)"               "NOT EXPOSED ON THIS NODE" "$(mk 21.0.12.1+1-LTS amd64 "$X86_NOVBMI" 3 true)"
t "avx512_vbmi2 alone is not vbmi"           "NOT EXPOSED ON THIS NODE" "$(mk 21.0.12.1+1-LTS amd64 "$X86_ONLY_VBMI2" 3 true)"
t "/proc/cpuinfo fallback with avx512vbmi"   EXPOSED                    "$(mk 21.0.12.1+1-LTS amd64 'FLAGS=flags : avx2 bmi2 avx512f avx512bw avx512vbmi' 3 true)"
t "no CPU features"                          UNDETERMINED               "$(mk 21.0.12.1+1-LTS amd64 "" 3 true)"

echo "Workaround (effective JVM value)"
t "UseBASE64Intrinsics=false"                "MITIGATED (WORKAROUND)"   "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 false)"
t "UseAVX=2"                                 "MITIGATED (WORKAROUND)"   "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 2 true)"
t "effective flags unreadable"               UNDETERMINED               "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" "" "")"

echo "Application-specific text"
has   "Keycloak: Calif note"                     "Calif lists Keycloak"          "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true APP=keycloak)"
has   "Keycloak: JAVA_OPTS_APPEND advice"        "JAVA_OPTS_APPEND"              "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true APP=keycloak)"
hasnt "other app: no Keycloak claim"             "Keycloak"                      "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true)"
has   "other app: generic Base64 advice"         "java.util.Base64"              "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true)"
has   "other app: generic flag advice"           "start the JVM with -XX:-UseBASE64Intrinsics" "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true)"
t     "no C2 (-Xint) stays EXPOSED"              EXPOSED                         "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true NOC2=-Xint)"
has   "no C2 (-Xint) gets a note"                "no C2 compiler"                "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true NOC2=-Xint)"

echo "Portuguese output (--lang pt)"
J4S_LANG=pt
t "pt: exposed"                              EXPOSTO                    "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 true)"
t "pt: not exposed on this node"             "NÃO EXPOSTO NESTE NÓ"     "$(mk 21.0.12.1+1-LTS amd64 "$X86_NOVBMI" 3 true)"
t "pt: mitigated"                            "MITIGADO (WORKAROUND)"    "$(mk 21.0.12.1+1-LTS amd64 "$X86_VBMI" 3 false)"
J4S_LANG=en

echo "Collection failures"
t "no java"                                  UNDETERMINED               "JPID="

echo "Parallel runner (local commands, no containers)"
FAKE=$(mk 21.0.12.1+1-LTS amd64 "$X86_NOVBMI" 3 true)
SLOW="sleep 5; echo late"
J_KIND=(); J_TARGET=(); J_LABEL=(); J_NODE=()
add_job sh "printf '%s\n' \"$FAKE\""  job-ok   -
add_job sh "$SLOW"                     job-slow -
add_job sh "echo boom >&2; exit 7"     job-fail -
add_job sh "printf '%s\n' \"$FAKE\""  job-ok2  -
EXPOSED=0; UNKNOWN=0; TIMEOUT=1; PARALLEL=2
start=$(date +%s)
OUT=$(run_jobs; echo "UNKNOWN=$UNKNOWN")
took=$(( $(date +%s) - start ))
order=$(sed -n 's/^── \([a-z0-9-]*\).*/\1/p' <<<"$OUT" | tr '\n' ' ')
[ "$order" = "job-ok job-slow job-fail job-ok2 " ] && ok "results keep the input order" "$order" || bad "results keep the input order" "job-ok job-slow job-fail job-ok2" "$order"
grep -q 'job-slow: no answer within 1s' <<<"$OUT" && ok "slow target hits the timeout" "timeout" || bad "slow target hits the timeout" "timeout" "$(grep job-slow <<<"$OUT")"
grep -q 'job-fail: exec failed' <<<"$OUT" && grep -q 'boom' <<<"$OUT" && ok "failed exec is reported with its error" "exec failed" || bad "failed exec is reported" "exec failed + boom" "$(grep -A1 job-fail <<<"$OUT")"
[ "$(grep -c 'NOT EXPOSED ON THIS NODE' <<<"$OUT")" = 2 ] && ok "good targets still analyzed" "2 verdicts" || bad "good targets still analyzed" "2" "$(grep -c 'NOT EXPOSED' <<<"$OUT")"
grep -q 'UNKNOWN=1' <<<"$OUT" && ok "timeout/failure sets UNDETERMINED" "UNKNOWN=1" || bad "timeout/failure sets UNDETERMINED" "UNKNOWN=1" "$(tail -1 <<<"$OUT")"
[ "$took" -le 3 ] && ok "timeout bounds the run time" "${took}s" || bad "timeout bounds the run time" "<= 3s" "${took}s"
sleep 0.2; leftovers=$(pgrep -f "sleep 5; echo late" | wc -l | tr -d ' ')
[ "$leftovers" = 0 ] && ok "timed-out job is killed" "no leftover" || bad "timed-out job is killed" "0" "$leftovers"
# Concurrency: 4 jobs of 1 s with PARALLEL=4 should take about 1 s, not 4 s.
J_KIND=(); J_TARGET=(); J_LABEL=(); J_NODE=()
for n in 1 2 3 4; do add_job sh "sleep 1; printf '%s\n' \"$FAKE\"" "p$n" -; done
TIMEOUT=10; PARALLEL=4; start=$(date +%s); run_jobs >/dev/null; took=$(( $(date +%s) - start ))
[ "$took" -le 2 ] && ok "4 jobs run in parallel" "${took}s" || bad "4 jobs run in parallel" "<= 2s" "${took}s"

echo "ver_ge"
for p in "21.0.12.1 21.0.13.1 1" "21.0.13.1 21.0.13.1 0" "21.0.14 21.0.13.1 0" "17.0.5 17.0.6 1" "17.0.21 17.0.21.1 1" "17.0.21.1.2 17.0.21.1 0"; do
  # shellcheck disable=SC2086
  set -- $p; ver_ge "$1" "$2"; r=$?
  if [ "$r" = "$3" ]; then PASS=$((PASS+1)); else bad "ver_ge $1 $2" "$3" "$r"; fi
done

echo
echo "Result: $PASS ok, $FAIL failed"
[ "$FAIL" = 0 ]
