/* Known-answer probe: libbpf parses a BPF ELF object and reports its programs and maps. */
#include <stdio.h>

#include "libbpf.h"

int main(int argc, char **argv)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_object *obj;

	if (argc != 2)
		return 2;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj)
		return 1;
	printf("object %s\n", bpf_object__name(obj));
	bpf_object__for_each_program(prog, obj)
		printf("prog %s sec=%s insns=%zu type=%d\n", bpf_program__name(prog),
		       bpf_program__section_name(prog), bpf_program__insn_cnt(prog),
		       (int)bpf_program__type(prog));
	bpf_object__for_each_map(map, obj)
		printf("map %s type=%d key=%u value=%u max=%u\n", bpf_map__name(map),
		       (int)bpf_map__type(map), bpf_map__key_size(map), bpf_map__value_size(map),
		       bpf_map__max_entries(map));
	printf("btf %s\n", bpf_object__btf(obj) ? "yes" : "no");
	bpf_object__close(obj);
	return 0;
}
