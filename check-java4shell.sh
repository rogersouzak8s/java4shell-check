#!/usr/bin/env bash
# check-java4shell.sh — checks, without any intrusive test, whether a Keycloak
# (or any other Java service) is exposed to CVE-2026-114938 ("Java4Shell").
#
# Read-only. For each container/pod it:
#   1. finds the running java process and its exact binary (/proc/<pid>/exe);
#   2. runs that same binary once with "-version" (small heap, no perf data
#      file), passing along the process's AVX/Base64 flags (JAVA_TOOL_OPTIONS,
#      JDK_JAVA_OPTIONS, command line, _JAVA_OPTIONS, in that order), and reads
#      what the JVM ITSELF reports: version, architecture, CPU features
#      (avx512_vbmi) and the effective values of UseBASE64Intrinsics and UseAVX;
#   3. decides using the four conditions from the advisories.
# It does NOT send malformed Base64 or anything else that could crash the JVM.
#
# Usage:
#   ./check-java4shell.sh [options] docker <container> [<container>...]
#   ./check-java4shell.sh [options] k8s <namespace> <selector> [--context <ctx>] [-c <container>]
#       e.g. ./check-java4shell.sh k8s identity app=keycloak --context prod
# Options:
#   --lang pt       output in Portuguese (default English; or J4S_LANG=pt)
#   --timeout N     seconds per container/pod before giving up (default 60)
#   --parallel N    containers/pods checked at the same time (default 8)
#
# Verdicts: EXPOSED | MITIGATED (WORKAROUND) | FIXED | NOT EXPOSED ON THIS NODE |
#           OUT OF SCOPE | UNDETERMINED
# Exit code: 0 no exposed/undetermined; 2 at least one exposed;
#            3 at least one undetermined (and none exposed); 1 usage error.
#
# Limits: needs bash inside the container (distroless images have none);
# Oracle Java SE 8 "Enterprise Performance Pack" (8u511-perf) is also affected
# and is not detected here (regular Java 8 is not affected).
set -uo pipefail

VERSION="1.1.0"

# Fixed versions (Oracle / OpenJDK, 2026-11-17).
FIX_17="17.0.21.1"; FIX_21="21.0.13.1"; FIX_25="25.0.5.1"; FIX_27="27.0.1.1"

# Probe that runs INSIDE the container. Only bash and /proc (works on minimal images).
read -r -d '' PROBE <<'EOS'
JPID=""
for d in /proc/[0-9]*; do
  [ -r "$d/comm" ] || continue
  read -r c < "$d/comm" 2>/dev/null || continue
  if [ "$c" = "java" ]; then JPID="${d#/proc/}"; break; fi
done
echo "JPID=$JPID"
FL=()
pick() {
  case "$1" in
    -XX:*UseAVX=*|-XX:[+-]UseBASE64Intrinsics) FL+=("$1");;
    -Xint|-XX:TieredStopAtLevel=[0-3]|-XX:-UseCompiler) echo "NOC2=$1";;
  esac
}
if [ -n "$JPID" ]; then
  mapfile -d '' ARGS < "/proc/$JPID/cmdline"
  # The process's java binary. Under emulation (Rosetta/QEMU) /proc/<pid>/exe points
  # to the emulator; in that case use argv[0] from the command line.
  JBIN=""
  EXE=$(readlink "/proc/$JPID/exe" 2>/dev/null)
  case "$EXE" in */java) JBIN="/proc/$JPID/exe";; esac
  if [ -z "$JBIN" ]; then
    case "${ARGS[0]}" in
      */java) [ -x "${ARGS[0]}" ] && JBIN="${ARGS[0]}";;
      java) JBIN=$(command -v java);;
    esac
  fi
  [ -n "$JBIN" ] || JBIN=$(command -v java)
  for a in "${ARGS[@]}"; do case "$a" in *keycloak*) echo "APP=keycloak"; break;; esac; done
  mapfile -d '' ENVS < "/proc/$JPID/environ" 2>/dev/null
  JTO=""; JJO=""; JUO=""
  for e in "${ENVS[@]}"; do
    case "$e" in
      JAVA_TOOL_OPTIONS=*) JTO="${e#*=}"; echo "ENV=$e";;
      JDK_JAVA_OPTIONS=*)  JJO="${e#*=}"; echo "ENV=$e";;
      _JAVA_OPTIONS=*)     JUO="${e#*=}"; echo "ENV=$e";;
    esac
  done
  # Order in which the JVM applies them: JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS, command line, _JAVA_OPTIONS (last one wins).
  set -f   # options from the environment are split into words, never globbed
  for a in $JTO; do pick "$a"; done
  for a in $JJO; do pick "$a"; done
  for a in "${ARGS[@]:1}"; do pick "$a"; done
  for a in $JUO; do pick "$a"; done
  set +f
else
  JBIN=$(command -v java)
fi
echo "JBIN=$JBIN"
printf 'FLAG=%s\n' "${FL[@]}"
[ -n "$JBIN" ] || exit 0
# A small, quiet JVM: 16 MB heap, serial GC, no hsperfdata file in the container's /tmp.
# None of these change the effective UseAVX / UseBASE64Intrinsics values.
run() { env -u JAVA_TOOL_OPTIONS -u JDK_JAVA_OPTIONS -u _JAVA_OPTIONS \
  "$JBIN" -Xmx16m -XX:+UseSerialGC -XX:-UsePerfData -Xshare:auto "${FL[@]}" "$@" -version 2>&1; }
# One run on Java 9+; Java 8 does not know -Xlog, so it gets a second run without it.
OUT=$(run -XX:+PrintFlagsFinal -XshowSettings:properties -Xlog:os+cpu=info)
case "$OUT" in *java.runtime.version*) ;; *) OUT=$(run -XX:+PrintFlagsFinal -XshowSettings:properties);; esac
while IFS= read -r l; do
  case "$l" in
    *java.runtime.version\ =*|*java.vendor\ =*|*os.arch\ =*) echo "PROP=$l";;
    *"[os,cpu] CPU:"*) echo "JCPU=$l";;
    *" UseAVX "*|*" UseBASE64Intrinsics "*) echo "JFLAG=$l";;
    *"{"*"}"*) ;;
    Error*|*"Unrecognized"*|*"Could not create"*|*"rosetta error"*|*"qemu"*) echo "JERR=$l";;
  esac
done <<<"$OUT"
while IFS= read -r l; do
  case "$l" in flags*|Features*) echo "FLAGS=$l"; break;; esac
done < /proc/cpuinfo
EOS

ver_ge() { # ver_ge A B → true if A >= B (numeric, part by part)
  local a b i x y
  IFS=. read -r -a a <<<"$1"
  IFS=. read -r -a b <<<"$2"
  for i in 0 1 2 3; do
    x=${a[i]:-0}; y=${b[i]:-0}
    x=${x//[^0-9]/}; y=${y//[^0-9]/}
    ((10#${x:-0} > 10#${y:-0})) && return 0
    ((10#${x:-0} < 10#${y:-0})) && return 1
  done
  return 0
}

# is_fixed <numeric version> → true if it is the fixed release of its line or later
is_fixed() {
  local num=$1 feat=${1%%.*}
  case "$feat" in
    17) ver_ge "$num" "$FIX_17";;
    21) ver_ge "$num" "$FIX_21";;
    25) ver_ge "$num" "$FIX_25";;
    27) ver_ge "$num" "$FIX_27";;
    *) return 1;;
  esac
}

# Output language: English by default, Portuguese with --lang pt or J4S_LANG=pt.
J4S_LANG=${J4S_LANG:-en}
T() { if [ "$J4S_LANG" = pt ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
# Verdict codes are English; this maps them for display.
show_verdict() {
  case "$1" in
    EXPOSED) T "EXPOSED" "EXPOSTO";;
    MITIGATED) T "MITIGATED (WORKAROUND)" "MITIGADO (WORKAROUND)";;
    FIXED) T "FIXED" "CORRIGIDO";;
    NOT_EXPOSED) T "NOT EXPOSED ON THIS NODE" "NÃO EXPOSTO NESTE NÓ";;
    OUT_OF_SCOPE) T "OUT OF SCOPE" "FORA DO ESCOPO";;
    *) T "UNDETERMINED" "INDETERMINADO";;
  esac
}

EXPOSED=0; UNKNOWN=0
analyze() { # $1 = label, $2 = node (or "-"), stdin = probe output
  local label=$1 node=$2 out; out=$(cat)
  local rt vendor arch jcpu flags b64 avx jerr app noc2
  rt=$(sed -n 's/^PROP=.*java.runtime.version = //p' <<<"$out" | head -1)
  vendor=$(sed -n 's/^PROP=.*java.vendor = //p' <<<"$out" | head -1)
  arch=$(sed -n 's/^PROP=.*os.arch = //p' <<<"$out" | head -1)
  jcpu=$(sed -n 's/^JCPU=//p' <<<"$out" | head -1)
  flags=$(sed -n 's/^FLAGS=//p' <<<"$out" | head -1)
  b64=$(sed -n 's/^JFLAG=.* UseBASE64Intrinsics *= *\([a-z]*\).*/\1/p' <<<"$out" | head -1)
  avx=$(sed -n 's/^JFLAG=.* UseAVX *= *\([0-9]*\).*/\1/p' <<<"$out" | head -1)
  jerr=$(sed -n 's/^JERR=//p' <<<"$out" | head -1)
  app=$(sed -n 's/^APP=//p' <<<"$out" | head -1)
  noc2=$(sed -n 's/^NOC2=//p' <<<"$out" | tail -1)

  # Java 8 reports 1.8.0_412-b08; later versions, 21.0.13.1+2-LTS.
  local num=${rt%%[+-]*} feat
  feat=${num%%.*}; [ "$feat" = 1 ] && feat=8

  # VBMI: from the JVM (named avx512_vbmi), with /proc/cpuinfo as fallback.
  local vbmi="?" src="JVM"
  if [ -n "$jcpu" ]; then
    if grep -Eq '(^|[ ,])avx512_?vbmi([ ,]|$)' <<<"$jcpu"; then vbmi=yes; else vbmi=no; fi
  elif [ -n "$flags" ]; then
    src="/proc/cpuinfo"
    if grep -Eq '(^|[ ,])avx512_?vbmi([ ,]|$)' <<<"$flags"; then vbmi=yes; else vbmi=no; fi
  fi
  local vbmi_s=$vbmi
  [ "$vbmi" = yes ] && vbmi_s=$(T yes sim); [ "$vbmi" = no ] && vbmi_s=$(T no não)

  echo "── $label"
  [ "$node" != "-" ] && echo "   $(T 'node:           ' 'nó:             ')  $node"
  [ -n "$app" ] && echo "   $(T 'application:    ' 'aplicação:      ')  Keycloak"
  echo "   JDK:              ${rt:-$(T 'not identified' 'não identificado')} (${vendor:-?})"
  echo "   $(T 'architecture:   ' 'arquitetura:    ')  ${arch:-?}"
  echo "   AVX-512 VBMI:     $vbmi_s ($(T source fonte): $src)"
  echo "   $(T 'effective flags:' 'flags efetivas: ')  UseAVX=${avx:-n/a}  UseBASE64Intrinsics=${b64:-n/a}"
  [ -n "$jerr" ] && echo "   $(T 'JVM warning:    ' 'aviso da JVM:   ')  $jerr"

  local verdict why
  if [ -z "$rt" ]; then
    verdict=UNDETERMINED; why=$(T "could not read the JDK version (no running java, or no bash in the image)" "não consegui ler a versão do JDK (sem java em execução ou sem bash na imagem)")
  elif [ "$feat" -lt 17 ] 2>/dev/null; then
    verdict=OUT_OF_SCOPE; why=$(T "Java $feat does not have the affected intrinsic" "Java $feat não tem o intrinsic afetado")
  elif [ "$feat" = 17 ] && ! ver_ge "$num" "17.0.6"; then
    verdict=OUT_OF_SCOPE; why=$(T "Java 17 older than 17.0.6" "Java 17 anterior ao 17.0.6")
  elif is_fixed "$num"; then
    verdict=FIXED; why=$(T "fixed release of the $feat line or later" "versão igual ou posterior à corrigida da linha $feat")
  elif [ "$arch" != "amd64" ] && [ "$arch" != "x86_64" ]; then
    verdict=OUT_OF_SCOPE; why=$(T "architecture $arch (only x86-64 has the vulnerable code path)" "arquitetura $arch (só x86-64 tem o caminho vulnerável)")
  elif [ "$vbmi" = "?" ]; then
    verdict=UNDETERMINED; why=$(T "could not read the CPU features" "não consegui ler as features da CPU")
  elif [ "$vbmi" = no ]; then
    verdict=NOT_EXPOSED; why=$(T "affected JDK, but the CPU has no AVX-512 VBMI; check again if the pod moves to another node or machine type" "JDK afetado, mas a CPU não tem AVX-512 VBMI; reavalie se o pod mudar de nó ou de tipo de máquina")
  elif [ "$b64" = "false" ] || { [ -n "$avx" ] && [ "$avx" -lt 3 ]; }; then
    verdict=MITIGATED; why=$(T "affected JDK on an affected CPU, but the JVM runs with the intrinsic/AVX-512 turned off; update and then remove the flag" "JDK afetado em CPU afetada, mas a JVM roda com o intrinsic/AVX-512 desligado; atualize e remova a flag")
  elif [ -z "$b64" ]; then
    verdict=UNDETERMINED; why=$(T "affected JDK on an affected CPU, but could not read the JVM's effective flags" "JDK afetado em CPU afetada, mas não consegui ler as flags efetivas da JVM")
  else
    verdict=EXPOSED
    why=$(T "affected JDK + CPU with AVX-512 VBMI + intrinsic on" "JDK afetado + CPU com AVX-512 VBMI + intrinsic ligado")
    if [ -n "$app" ]; then
      why="$why. $(T "Calif lists Keycloak as exploitable before login" "A Calif lista o Keycloak como explorável antes do login")"
    else
      why="$why. $(T "Check whether untrusted input reaches java.util.Base64 (basic or URL decoder), e.g. HTTP Basic, JWT with auth0 java-jwt, SAML" "Verifique se dados de fora chegam ao java.util.Base64 (decoder básico ou URL), ex.: HTTP Basic, JWT com auth0 java-jwt, SAML")"
    fi
    [ -n "$noc2" ] && why="$why. $(T "Note: the JVM runs with $noc2 (no C2 compiler), so the intrinsic is likely never used" "Obs.: a JVM roda com $noc2 (sem o compilador C2), então o intrinsic provavelmente nunca é usado")"
  fi
  if [ "$feat" -gt 17 ] 2>/dev/null; then
    case "$feat:$verdict" in
      21:*|25:*|27:*|*:OUT_OF_SCOPE|*:FIXED) ;;
      *) why="$why. $(T "Java $feat is not LTS and will get no fix: move to 21, 25 or 27" "Java $feat não é LTS e não terá correção: migre para 21, 25 ou 27")";;
    esac
  fi
  case "$verdict" in EXPOSED) EXPOSED=1;; UNDETERMINED) UNKNOWN=1;; esac
  echo "   $(T 'verdict:        ' 'veredito:       ')  $(show_verdict "$verdict") — $why"
  if [ "$verdict" = EXPOSED ]; then
    echo "   $(T 'what to do:     ' 'o que fazer:    ')  $(T "update to JDK $FIX_17 / $FIX_21 / $FIX_25 / $FIX_27 (or your distribution's build);" "atualize para JDK $FIX_17 / $FIX_21 / $FIX_25 / $FIX_27 (ou o build da sua distribuição);")"
    if [ -n "$app" ]; then
      echo "                     $(T 'until then: JAVA_OPTS_APPEND="-XX:-UseBASE64Intrinsics" and restart Keycloak.' 'até lá: JAVA_OPTS_APPEND="-XX:-UseBASE64Intrinsics" e reinicie o Keycloak.')"
    else
      echo "                     $(T 'until then, start the JVM with -XX:-UseBASE64Intrinsics.' 'até lá, suba a JVM com -XX:-UseBASE64Intrinsics.')"
    fi
  fi
  echo
}

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 1; }

# ---- Running the probe on many targets, in parallel and with a timeout ----
# Jobs are described by kind (docker|k8s), target, label and node; KC/CT/NS are
# the kubectl prefix, container flag and namespace for k8s jobs.
TIMEOUT=${J4S_TIMEOUT:-60}; PARALLEL=${J4S_PARALLEL:-8}
J_KIND=(); J_TARGET=(); J_LABEL=(); J_NODE=(); J_PID=(); J_WD=()
KC=(kubectl); CT=(); NS=""

exec_target() { # runs in a background subshell; exec makes it the real process, so a timeout can kill it
  case "$1" in
    docker) exec docker exec "$2" bash -c "$PROBE";;
    k8s) exec "${KC[@]}" -n "$NS" exec "$2" ${CT[@]+"${CT[@]}"} -- bash -c "$PROBE";;
    sh) exec bash -c "$2";;   # used by the tests
  esac
}
start_job() {
  local i=$1
  ( exec_target "${J_KIND[i]}" "${J_TARGET[i]}" ) >"$TMPD/$i.out" 2>&1 </dev/null &
  J_PID[i]=$!
  ( trap 'kill "$s" 2>/dev/null; exit 0' TERM
    sleep "$TIMEOUT" & s=$!; wait "$s"
    kill -TERM "${J_PID[i]}" 2>/dev/null && : >"$TMPD/$i.timeout" ) &
  J_WD[i]=$!
}
finish_job() {
  local i=$1 rc
  wait "${J_PID[i]}"; rc=$?
  kill "${J_WD[i]}" 2>/dev/null; wait "${J_WD[i]}" 2>/dev/null
  if [ -e "$TMPD/$i.timeout" ]; then
    echo "── ${J_LABEL[i]}: $(T "no answer within ${TIMEOUT}s" "sem resposta em ${TIMEOUT}s") — $(show_verdict UNDETERMINED)"; echo; UNKNOWN=1
  elif [ "$rc" != 0 ]; then
    echo "── ${J_LABEL[i]}: $(T "exec failed" "falha no exec") — $(show_verdict UNDETERMINED)"
    head -3 "$TMPD/$i.out" | sed 's/^/   /'; echo; UNKNOWN=1
  else
    analyze "${J_LABEL[i]}" "${J_NODE[i]}" <"$TMPD/$i.out"
  fi
}
run_jobs() { # starts up to PARALLEL jobs at a time and prints results in order
  local n=${#J_KIND[@]} i
  TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT
  for ((i = 0; i < n; i++)); do
    ((i >= PARALLEL)) && finish_job $((i - PARALLEL))
    start_job "$i"
  done
  for ((i = (n > PARALLEL ? n - PARALLEL : 0); i < n; i++)); do finish_job "$i"; done
}
add_job() { J_KIND+=("$1"); J_TARGET+=("$2"); J_LABEL+=("$3"); J_NODE+=("$4"); }

# Allows "source" from the tests without running anything.
[ "${CHECK_JAVA4SHELL_LIB:-}" = 1 ] && return 0 2>/dev/null

# Global options may appear anywhere.
ARGV=()
while [ $# -gt 0 ]; do
  case "$1" in
    --lang) J4S_LANG=${2:-en}; shift 2;;
    --timeout) TIMEOUT=${2:-}; shift 2;;
    --parallel) PARALLEL=${2:-}; shift 2;;
    --version) echo "check-java4shell $VERSION"; exit 0;;
    -h|--help) usage;;
    *) ARGV+=("$1"); shift;;
  esac
done
case "$TIMEOUT$PARALLEL" in *[!0-9]*|"") usage;; esac
((TIMEOUT > 0 && PARALLEL > 0)) || usage
set -- ${ARGV[@]+"${ARGV[@]}"}

case "${1:-}" in
  docker)
    shift; [ $# -ge 1 ] || usage
    for c in "$@"; do add_job docker "$c" "docker:$c" -; done ;;
  k8s)
    shift; [ $# -ge 2 ] || usage
    NS=$1 sel=$2; shift 2
    while [ $# -gt 0 ]; do
      case "$1" in
        --context) KC+=(--context "$2"); shift 2;;
        -c) CT=(-c "$2"); shift 2;;
        *) usage;;
      esac
    done
    pods=$("${KC[@]}" -n "$NS" get pods -l "$sel" --field-selector=status.phase=Running \
      -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.nodeName}{"\n"}{end}') || exit 1
    [ -n "$pods" ] || { echo "$(T "no running pod matches $sel in $NS" "nenhum pod em execução com $sel em $NS")"; exit 1; }
    while read -r pod node; do
      [ -n "$pod" ] && add_job k8s "$pod" "k8s:$NS/$pod" "$node"
    done <<<"$pods" ;;
  *) usage ;;
esac

run_jobs

((EXPOSED)) && exit 2
((UNKNOWN)) && exit 3
exit 0
