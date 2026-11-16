/* Known-answer probe: build a BTF blob with libbpf, serialise, re-parse and dump it as C. */
#include <stdarg.h>
#include <stdio.h>

#include "btf.h"

static void out(void *ctx, const char *fmt, va_list ap)
{
	vprintf(fmt, ap);
}

int main(void)
{
	struct btf *btf = btf__new_empty(), *back;
	struct btf_dump *d;
	const void *raw;
	__u32 raw_size, i, n;
	int u32, ptr, st, td;

	if (!btf)
		return 1;
	u32 = btf__add_int(btf, "unsigned int", 4, 0);
	ptr = btf__add_ptr(btf, u32);
	st = btf__add_struct(btf, "pkt_stats", 16);
	btf__add_field(btf, "count", u32, 0, 0);
	btf__add_field(btf, "next", ptr, 64, 0);
	td = btf__add_typedef(btf, "pkt_stats_t", st);
	if (u32 < 0 || ptr < 0 || st < 0 || td < 0)
		return 1;

	raw = btf__raw_data(btf, &raw_size);
	if (!raw)
		return 1;
	back = btf__new(raw, raw_size);
	if (!back)
		return 1;
	n = btf__type_cnt(back);
	printf("types %u size %u\n", n - 1, btf__resolve_size(back, st) > 0 ? (unsigned)btf__resolve_size(back, st) : 0);
	for (i = 1; i < n; i++)
		printf("type %u kind %u name %s\n", i, btf_kind(btf__type_by_id(back, i)),
		       btf__name_by_offset(back, btf__type_by_id(back, i)->name_off));
	d = btf_dump__new(back, out, NULL, NULL);
	if (!d)
		return 1;
	btf_dump__dump_type(d, td);
	btf_dump__free(d);
	btf__free(back);
	btf__free(btf);
	return 0;
}
