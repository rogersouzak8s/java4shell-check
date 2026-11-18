# Changelog

## 1.1.0

- Keycloak is detected from the process command line; the verdict and advice for other Java applications are now generic instead of mentioning Keycloak.
- The probe JVM runs once instead of twice (Java 8 falls back to two runs), with `-Xmx16m -XX:+UseSerialGC -XX:-UsePerfData`: about 30 MB peak, no `hsperfdata` file left in the target container.
- Containers and pods are checked in parallel (`--parallel`, default 8), each with a timeout (`--timeout`, default 60 s). Results keep the input order. A target that hangs no longer blocks the run.
- Environment options are split into words without glob expansion.
- A JVM running without C2 gets a note: the intrinsic is likely never used.
- `--version`, `--help`; global options may appear anywhere.
- Integration test with real JVMs in Docker, and CI (shellcheck, unit tests on Ubuntu and macOS, integration on x86-64).

## 1.0.0

- First release.
