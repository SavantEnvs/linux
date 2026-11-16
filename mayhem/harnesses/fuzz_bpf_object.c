// libFuzzer harness: libbpf's BPF ELF object loader front end (bpf_object__open_mem).
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	LIBBPF_OPTS(bpf_object_open_opts, opts, .object_name = "fuzz");
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_object *obj;

	obj = bpf_object__open_mem(data, size, &opts);
	if (!obj)
		return -1;

	bpf_object__for_each_program(prog, obj) {
		(void)bpf_program__name(prog);
		(void)bpf_program__section_name(prog);
		(void)bpf_program__insn_cnt(prog);
		(void)bpf_program__type(prog);
		(void)bpf_program__expected_attach_type(prog);
		(void)bpf_program__insns(prog);
	}
	bpf_object__for_each_map(map, obj) {
		(void)bpf_map__name(map);
		(void)bpf_map__type(map);
		(void)bpf_map__key_size(map);
		(void)bpf_map__value_size(map);
		(void)bpf_map__max_entries(map);
		(void)bpf_map__btf_key_type_id(map);
		(void)bpf_map__btf_value_type_id(map);
		(void)bpf_map__initial_value(map, &(size_t){ 0 });
	}
	(void)bpf_object__btf(obj);

	bpf_object__close(obj);
	return 0;
}
