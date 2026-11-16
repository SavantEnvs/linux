#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for the userspace libraries fuzzed here (libbpf, libfdt, dtc).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

K="$SRC/mayhem/build-kat"
G="$SRC/mayhem/kat"
for f in "$K/kat_btf" "$K/kat_bpf" "$K/kat_fdt" "$K/dtc/dtc" "$K/prog.bpf.o" "$G/sample.dts"; do
  [ -e "$f" ] || { echo "missing $f (mayhem/build.sh did not produce it)" >&2; emit_ctrf "kat" 0 1 0; exit 1; }
done

passed=0 failed=0
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

check() { # <name> <golden> <actual file>
  if cmp -s "$2" "$3"; then
    passed=$((passed + 1)); echo "PASS $1"
  else
    failed=$((failed + 1)); echo "FAIL $1"; diff "$2" "$3" | head -20
  fi
}

# libbpf BTF: build, round-trip through the raw format, list types, dump as C
"$K/kat_btf" >"$T/btf.out" 2>"$T/btf.err"; check libbpf-btf "$G/kat_btf.golden" "$T/btf.out"
# libbpf ELF loader: programs, maps and BTF of a clang -target bpf object
"$K/kat_bpf" "$K/prog.bpf.o" >"$T/bpf.out" 2>"$T/bpf.err"; check libbpf-object "$G/kat_bpf.golden" "$T/bpf.out"
# dtc (libfdt writer + checks): source -> blob -> source, and libfdt reader on the blob
"$K/dtc/dtc" -q -I dts -O dtb -o "$T/s.dtb" "$G/sample.dts" 2>"$T/dtc.err"
"$K/dtc/dtc" -q -I dtb -O dts "$T/s.dtb" >"$T/rt.dts" 2>>"$T/dtc.err"; check dtc-roundtrip "$G/sample.roundtrip.dts.golden" "$T/rt.dts"
"$K/kat_fdt" "$T/s.dtb" >"$T/fdt.out" 2>"$T/fdt.err"; check libfdt-walk "$G/kat_fdt.golden" "$T/fdt.out"

emit_ctrf "mayhem-kat" "$passed" "$failed" 0
