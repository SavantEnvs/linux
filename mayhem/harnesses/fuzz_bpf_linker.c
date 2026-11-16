// libFuzzer harness: libbpf's BPF static linker (tools/lib/bpf/linker.c).
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libbpf.h"

static int quiet_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	char buf[512];

	vsnprintf(buf, sizeof(buf), fmt, ap);
	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	libbpf_set_print(quiet_print);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct bpf_linker *linker;
	int out_fd, err = -1;

	/* Input goes in through bpf_linker__add_buf and output into a memfd: no files on disk. */
	out_fd = memfd_create("fuzz_linker_out", MFD_CLOEXEC);
	if (out_fd < 0)
		return 0;

	linker = bpf_linker__new_fd(out_fd, NULL);
	if (linker) {
		err = bpf_linker__add_buf(linker, (void *)data, size, NULL);
		if (!err)
			bpf_linker__finalize(linker);
		bpf_linker__free(linker);
	}

	close(out_fd);
	return err ? -1 : 0;
}
