# java4shell-check

[![ci](https://github.com/rogersouzak8s/java4shell-check/actions/workflows/ci.yml/badge.svg)](https://github.com/rogersouzak8s/java4shell-check/actions/workflows/ci.yml)

Read-only checker for **CVE-2026-114938 ("Java4Shell")**, the out-of-bounds heap write in HotSpot's AVX-512 Base64 decode intrinsic. It tells you whether a running Keycloak, or any other Java service, is actually exposed, by asking the JVM itself.

It sends nothing to your application. No malformed Base64, no exploit, nothing that could crash the JVM.

## Why

The flaw only matters when four things are true at the same time:

1. **An affected JDK**: OpenJDK 17.0.6 to 17.0.21, 21 before 21.0.13.1, 25 before 25.0.5.1, 27 before 27.0.1.1. Non-LTS lines 18–24 and 26 are affected too and will get no fix.
2. **An x86-64 CPU with AVX-512 VBMI**: Intel Ice Lake or newer, AMD Zen 4 or newer. ARM64 is not affected.
3. **The intrinsic is on**: `UseBASE64Intrinsics` true and `UseAVX` ≥ 3, the default on such CPUs.
4. **Untrusted input reaches `java.util.Base64`**: basic or URL decoder, ideally before login. The discoverers (Calif) list Keycloak, Jira, Confluence, Artifactory, Jenkins and PingFederate as exploitable before login in their default configuration.

The script checks 1 to 3 on the real running process. Condition 4 depends on the application; see the references.

## Usage

```bash
./check-java4shell.sh [options] docker <container> [<container>...]
./check-java4shell.sh [options] k8s <namespace> <label-selector> [--context <ctx>] [-c <container>]

# examples
./check-java4shell.sh docker keycloak
./check-java4shell.sh k8s identity app=keycloak --context prod
./check-java4shell.sh --lang pt docker keycloak     # output in Portuguese
```

| Option | Default | |
| --- | --- | --- |
| `--lang pt` | `en` | Output in Portuguese (also `J4S_LANG=pt`) |
| `--timeout N` | `60` | Seconds per container/pod; a target that does not answer is reported as `UNDETERMINED` |
| `--parallel N` | `8` | Containers/pods checked at the same time; results are printed in input order |
| `--version` | | Prints the version |

Requirements: `bash` on your machine (3.2+, macOS works), `docker` or `kubectl` with permission to `exec`, and `bash` inside the target container.

### Example output

```
── k8s:identity/keycloak-568c44d9b7-4dkp6
   node:             aks-nodepool1-0000000-vmss000001
   application:      Keycloak
   JDK:              21.0.12.1+1-LTS (Red Hat, Inc.)
   architecture:     amd64
   AVX-512 VBMI:     no (source: JVM)
   effective flags:  UseAVX=3  UseBASE64Intrinsics=true
   verdict:          NOT EXPOSED ON THIS NODE — affected JDK, but the CPU has no AVX-512 VBMI; check again if the pod moves to another node or machine type
```

### Verdicts and exit codes

| Verdict | Meaning | Exit |
| --- | --- | --- |
| `EXPOSED` | Affected JDK, CPU with VBMI, intrinsic on | 2 |
| `MITIGATED (WORKAROUND)` | Affected JDK and CPU, but the JVM runs with the intrinsic or AVX-512 off | 0 |
| `FIXED` | Fixed release of its line or later | 0 |
| `NOT EXPOSED ON THIS NODE` | Affected JDK, but this CPU has no VBMI. Recheck if pods move | 0 |
| `OUT OF SCOPE` | Java 8/11, Java 17 before 17.0.6, or not x86-64 | 0 |
| `UNDETERMINED` | Could not read the JVM (no running java, no bash in the image) | 3 |

Exit code 2 wins over 3. The script can run as a CI or cron check.

## How it works

1. Finds the `java` process in the container and its exact binary. Under emulation (Rosetta, QEMU) it uses `argv[0]`, because `/proc/<pid>/exe` points to the emulator.
2. Rebuilds the process's `UseAVX` and `UseBASE64Intrinsics` flags in the order the JVM applies them: `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, command line, `_JAVA_OPTIONS`.
3. Runs that same binary once, with those flags and `-version`, and reads what the JVM reports: `java.runtime.version`, `os.arch`, the CPU features from `-Xlog:os+cpu` (`avx512_vbmi`), and the effective flag values from `-XX:+PrintFlagsFinal`. `/proc/cpuinfo` is only a fallback. Java 8 does not know `-Xlog`, so it gets a second run without it.
4. That extra JVM is kept small and quiet: `-Xmx16m -XX:+UseSerialGC -XX:-UsePerfData`. It peaks at about 30 MB inside the target container, runs in about 0.1 s and writes no `hsperfdata` file. None of these flags change the effective `UseAVX` or `UseBASE64Intrinsics` values; this was checked on a real x86-64 node.
5. When the process command line mentions Keycloak, the verdict and advice are specific to Keycloak; otherwise they are generic.

## If you are exposed

1. Update to a fixed JDK: **17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1**, or your distribution's equivalent build, and rebuild your images.
2. Until then, start the JVM with `-XX:-UseBASE64Intrinsics`. On Keycloak: `JAVA_OPTS_APPEND="-XX:-UseBASE64Intrinsics"`. `-XX:UseAVX=2` also works on x86-64, but it slows down other vectorised code, and an ARM64 JVM will not start with it.
3. Run the script again: the verdict should be `MITIGATED (WORKAROUND)` and later `FIXED`. Remove the flag once you are on a fixed JDK.

## Tests

```bash
./test-unit.sh          # 52 checks, no Docker needed
./test-integration.sh   # real JVMs in Docker (pinned Temurin 21.0.5 and 8u432)
```

- **Unit:** synthetic probe output for vendor version strings (Red Hat, Temurin, Corretto, Oracle), Java 8, 11, 17.0.5/17.0.6, 23 and 25 GA, ARM64, x86 with and without VBMI, `avx512_vbmi2` alone, the workaround through `UseBASE64Intrinsics=false` and `UseAVX=2`, Keycloak-specific and generic advice, the no-C2 note, Portuguese output; plus the parallel runner: input order, timeout, failed exec, and that 4 targets run at the same time.
- **Integration:** starts real JVMs and checks that the script finds the process, reads the workaround flag and gives the verdict that matches the host CPU. On an x86-64 host with AVX-512 VBMI, it exercises `EXPOSED` and `MITIGATED (WORKAROUND)` on real hardware.
- **CI** runs shellcheck, the unit tests on Ubuntu (bash 5) and macOS (bash 3.2), and the integration test on an x86-64 runner. The runner's CPU model and whether it has `avx512vbmi` are printed in the log.

It was also run by hand against Keycloak 26.8.1 on arm64 and amd64 (emulated), with the workaround and with an overridden flag, against an image without bash, and against a Keycloak on AKS.

## Limits

- Needs `bash` inside the container. Distroless images have none, and the script reports `UNDETERMINED`.
- Checks the first `java` process in each container.
- A JVM running without the C2 compiler (`-Xint`, `-XX:TieredStopAtLevel` below 4, `-XX:-UseCompiler`) never uses the intrinsic, but is still reported as `EXPOSED`, with a note. This errs on the safe side.
- Oracle Java SE 8 Enterprise Performance Pack (8u511-perf) is also affected and is not detected. Regular Java 8 is not affected.
- It does not check whether your code passes untrusted data to the decoder (condition 4).

## References

- Calif, discoverers' write-up: https://calif.io/java4shell/
- Datadog Security Labs analysis: https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/
- Red Hat bulletin RHSB-2026-018: https://access.redhat.com/security/vulnerabilities/RHSB-2026-018
- Deep dive, with how to assess your applications: https://leavory.com/articles/java4shell-cve-2026-114938-deep-dive/

## License

MIT
