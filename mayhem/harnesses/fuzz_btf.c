// libFuzzer harness: libbpf's BTF parser (tools/lib/bpf/btf.c) and BTF-to-C dumper (btf_dump.c).
// Dedup is fuzzed separately (fuzz_btf_dedup.c) so a dump-side crash or slow dump can't starve it.
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf.h"
#include "libbpf.h"

static int quiet_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	char buf[512];

	vsnprintf(buf, sizeof(buf), fmt, ap);
	return 0;
}

/* Per input: the first DUMP_FORMAT_CALLS lines are formatted, the rest are skipped. */
#define DUMP_FORMAT_CALLS 4096

struct dump_ctx {
	unsigned int calls;
};

static void dump_printf(void *ctx, const char *fmt, va_list ap)
{
	struct dump_ctx *c = ctx;
	char buf[512];

	if (c->calls >= DUMP_FORMAT_CALLS)
		return;
	c->calls++;
	vsnprintf(buf, sizeof(buf), fmt, ap);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	libbpf_set_print(quiet_print);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct btf *btf = btf__new(data, size);
	struct btf_dump *d;
	struct dump_ctx dctx = { 0 };
	unsigned int id, n;

	if (!btf)
		return -1;

	n = btf__type_cnt(btf);
	for (id = 1; id < n; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!t)
			continue;
		(void)btf__name_by_offset(btf, t->name_off);
		(void)btf__resolve_size(btf, id);
		(void)btf__align_of(btf, id);
		(void)btf__resolve_type(btf, id);
	}

	d = btf_dump__new(btf, dump_printf, &dctx, NULL);
	if (d) {
		for (id = 1; id < n; id++)
			btf_dump__dump_type(d, id);
		btf_dump__free(d);
	}

	btf__free(btf);
	return 0;
}
