#!/usr/bin/env bash
#
# mayhem/build.sh — build the userspace parts of the kernel tree that parse untrusted files:
#   * libbpf  (tools/lib/bpf)   — BTF, BPF ELF objects, BPF static linker
#   * libfdt  (scripts/dtc/libfdt) — flattened device tree blobs (read-only, read-write, overlays)
# The kernel itself cannot run in a fuzz process, so the fuzzed code is these libraries, compiled
# exactly as upstream's tools/ build does (same sources, same defines) but with the sanitizers.
#
# Outputs (gitignored, recreated on every run):
#   .mayhem-bin/<fuzzer>, .mayhem-bin/<fuzzer>-standalone   sanitized fuzz binaries + reproducers; kept
#       outside mayhem/ because verify-repo.sh greps mayhem/ for the ASan runtime's default-options symbol
#   mayhem/build-kat/                                       normal-flags build for mayhem/test.sh
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"
BIN="$SRC/.mayhem-bin"
FZ="$M/build-fuzz"
KAT="$M/build-kat"

case "$(uname -m)" in
  x86_64) SRCARCH=x86 ;;
  aarch64) SRCARCH=arm64 ;;
  *) SRCARCH="$(uname -m)" ;;
esac

rm -rf "$BIN" "$FZ" "$KAT"
mkdir -p "$BIN" "$FZ/libbpf" "$FZ/libfdt" "$KAT/libbpf" "$KAT/libfdt" "$KAT/dtc"

read -ra SAN <<<"$SANITIZER_FLAGS"
read -ra DBG <<<"$DEBUG_FLAGS"
read -ra COV <<<"$COVERAGE_FLAGS"

# Upstream's tools/lib/bpf/Makefile flags (std, visibility, large-file defines, include paths).
BPF_SRCS=$(tr -s ' \t\\' '\n' <tools/lib/bpf/Build | sed -n 's|\.o$|.c|p' | sed 's|^|tools/lib/bpf/|')
BPF_CF=(-std=gnu89 -fvisibility=hidden -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
        -I"$SRC/tools/lib/bpf" -I"$SRC/tools/include" -I"$SRC/tools/include/uapi"
        -I"$SRC/tools/arch/$SRCARCH/include" -Wno-pointer-sign)
# libfdt's userspace build, as scripts/dtc/Makefile does (-I libfdt picks the userspace libfdt_env.h).
FDT_SRCS=$(for f in fdt fdt_ro fdt_wip fdt_sw fdt_rw fdt_strerror fdt_empty_tree fdt_addresses fdt_overlay; do echo "scripts/dtc/libfdt/$f.c"; done)
FDT_CF=(-I"$SRC/scripts/dtc/libfdt")

compile_one() {
  local out=$1 src=$2
  shift 2
  "$CC" "$@" -c "$SRC/$src" -o "$out/$(basename "${src%.c}").o"
}
export -f compile_one
build_objs() { # <outdir> <srcs> <cflags...>
  local out=$1 srcs=$2
  shift 2
  printf '%s\n' $srcs | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile_one "$@"' _ "$out" {} "$@"
}

# ---- 1) sanitized + SanCov-instrumented libraries (the fuzzed code) ---------------------------
FUZZ_CF=(-O1 "${SAN[@]}" "${DBG[@]}" -fsanitize=fuzzer-no-link)
# libbpf passes NULL+0 / (NULL, 0) to memcpy-style calls on empty sections and reads ELF/BTF structs
# straight out of the (byte-aligned) input buffer: benign on x86/arm64, so exactly these three checks are
# relaxed for libbpf only (ASan and every other UBSan check stay halting).
build_objs "$FZ/libbpf" "$BPF_SRCS" "${BPF_CF[@]}" "${FUZZ_CF[@]}" -fno-sanitize=pointer-overflow,nonnull-attribute,alignment
build_objs "$FZ/libfdt" "$FDT_SRCS" "${FDT_CF[@]}" "${FUZZ_CF[@]}"
llvm-ar rcs "$FZ/libbpf.a" "$FZ"/libbpf/*.o
llvm-ar rcs "$FZ/libfdt.a" "$FZ"/libfdt/*.o

# ---- 2) harnesses: fuzzer binary + standalone reproducer, LSan off ----------------------------
"$CXX" "${SAN[@]}" "${DBG[@]}" -c "$M/lsan_off.cc" -o "$FZ/lsan_off.o"
"$CC" "${SAN[@]}" "${DBG[@]}" -x c -c "$STANDALONE_FUZZ_MAIN" -o "$FZ/standalone_main.o"

BPF_LIBS=("$FZ/libbpf.a" -lelf -lz -lzstd -pthread)
FDT_LIBS=("$FZ/libfdt.a")
build_harness() { # <name> <include flags...> -- <libs...>
  local name=$1
  shift
  local -a inc=() libs=()
  while [ "$1" != -- ]; do inc+=("$1"); shift; done
  shift
  libs=("$@")
  "$CC" -O1 "${SAN[@]}" "${DBG[@]}" "${inc[@]}" $LIB_FUZZING_ENGINE "$M/harnesses/$name.c" \
        "$FZ/lsan_off.o" "${libs[@]}" -o "$BIN/$name"
  "$CC" -O1 "${SAN[@]}" "${DBG[@]}" "${inc[@]}" "$FZ/standalone_main.o" "$M/harnesses/$name.c" \
        "$FZ/lsan_off.o" "${libs[@]}" -o "$BIN/$name-standalone"
}
BPF_INC=(-I"$SRC/tools/lib/bpf" -I"$SRC/tools/include" -I"$SRC/tools/include/uapi" -I"$SRC/tools/arch/$SRCARCH/include")
FDT_INC=(-I"$SRC/scripts/dtc/libfdt" -I"$M/harnesses")
for h in fuzz_btf fuzz_btf_dedup fuzz_bpf_object fuzz_bpf_linker; do build_harness "$h" "${BPF_INC[@]}" -- "${BPF_LIBS[@]}"; done
for h in fuzz_fdt_ro fuzz_fdt_rw fuzz_fdt_overlay; do build_harness "$h" "${FDT_INC[@]}" -- "${FDT_LIBS[@]}"; done

# ---- 3) known-answer probes + dtc, NORMAL flags (no sanitizer, no -gdwarf-3) for test.sh ------
KAT_CF=(-O2 "${COV[@]}")
build_objs "$KAT/libbpf" "$BPF_SRCS" "${BPF_CF[@]}" "${KAT_CF[@]}"
build_objs "$KAT/libfdt" "$FDT_SRCS" "${FDT_CF[@]}" "${KAT_CF[@]}"
llvm-ar rcs "$KAT/libbpf.a" "$KAT"/libbpf/*.o
llvm-ar rcs "$KAT/libfdt.a" "$KAT"/libfdt/*.o
"$CC" "${KAT_CF[@]}" "${BPF_INC[@]}" "$M/kat/kat_btf.c" "$KAT/libbpf.a" -lelf -lz -lzstd -pthread -o "$KAT/kat_btf"
"$CC" "${KAT_CF[@]}" "${BPF_INC[@]}" "$M/kat/kat_bpf.c" "$KAT/libbpf.a" -lelf -lz -lzstd -pthread -o "$KAT/kat_bpf"
"$CC" "${KAT_CF[@]}" -I"$SRC/scripts/dtc/libfdt" "$M/kat/kat_fdt.c" "$KAT/libfdt.a" -o "$KAT/kat_fdt"
# the kernel's own BPF target build of a tiny program, parsed by kat_bpf
"$CC" -target bpf -O2 -g -I"$SRC/tools/include/uapi" -c "$M/kat/prog.bpf.c" -o "$KAT/prog.bpf.o"

# dtc, built from scripts/dtc as upstream's Makefile does (flex/bison generated sources)
DT="$SRC/scripts/dtc"
bison -o "$KAT/dtc/dtc-parser.tab.c" -d "$DT/dtc-parser.y"
flex -o "$KAT/dtc/dtc-lexer.lex.c" -L "$DT/dtc-lexer.l"
DTC_CF=(-O2 "${COV[@]}" -DNO_YAML -I"$DT/libfdt" -I"$DT" -I"$KAT/dtc" -Wno-unused-result)
DTC_SRCS=()
for f in dtc flattree fstree data livetree treesource srcpos checks util; do DTC_SRCS+=("$DT/$f.c"); done
"$CC" "${DTC_CF[@]}" "${DTC_SRCS[@]}" "$KAT/dtc/dtc-lexer.lex.c" "$KAT/dtc/dtc-parser.tab.c" \
      "$KAT/libfdt.a" -o "$KAT/dtc/dtc"

echo "mayhem/build.sh: done"
