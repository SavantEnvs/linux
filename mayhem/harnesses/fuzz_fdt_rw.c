// libFuzzer harness: libfdt's fdt_validate() validator, then (for blobs it accepts) the read-write
// API: reorganise into a larger buffer, edit properties and nodes, pack, and re-validate.
#include "fdt_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	void *fdt = fdt_copy_checked(data, size);
	size_t cap;
	void *rw;
	int node;

	if (!fdt)
		return -1;
	if (fdt_validate(fdt, size) != 0) {
		free(fdt);
		return -1;
	}

	fdt_walk_ro(fdt);

	cap = fdt_totalsize(fdt) + 512;
	rw = malloc(cap);
	if (!rw)
		abort();
	if (fdt_open_into(fdt, rw, (int)cap) == 0) {
		node = fdt_path_offset(rw, "/");
		if (node >= 0) {
			int sub = fdt_add_subnode(rw, node, "mayhem-node");

			if (sub >= 0) {
				(void)fdt_setprop_u32(rw, sub, "mayhem-prop", 0x1234);
				(void)fdt_appendprop_string(rw, sub, "compatible", "mayhem,test");
				(void)fdt_delprop(rw, sub, "mayhem-prop");
				(void)fdt_del_node(rw, sub);
			}
			(void)fdt_setprop_string(rw, node, "model", "mayhem");
			(void)fdt_delprop(rw, node, "model");
		}
		if (fdt_pack(rw) == 0) {
			(void)fdt_validate(rw, cap);
			fdt_walk_ro(rw);
		}
	}
	free(rw);
	free(fdt);
	return 0;
}
