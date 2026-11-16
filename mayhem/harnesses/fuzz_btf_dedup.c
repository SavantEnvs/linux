// libFuzzer harness: libbpf's BTF deduplication (btf__dedup in tools/lib/bpf/btf.c) on parsed BTF.
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

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	libbpf_set_print(quiet_print);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct btf *btf = btf__new(data, size);
	unsigned int id, n;
	__u32 raw_size;
	int err;

	if (!btf)
		return -1;

	err = btf__dedup(btf, NULL);
	if (!err) {
		n = btf__type_cnt(btf);
		for (id = 1; id < n; id++) {
			const struct btf_type *t = btf__type_by_id(btf, id);

			if (t)
				(void)btf__name_by_offset(btf, t->name_off);
		}
		(void)btf__raw_data(btf, &raw_size);
	}

	btf__free(btf);
	return 0;
}
