// libFuzzer harness: libfdt's overlay application (fdt_overlay.c). Input = 2-byte big-endian base
// length, base blob, overlay blob.
#include "fdt_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t base_len, ovl_len, cap;
	void *base, *ovl, *grown;

	if (size < 2)
		return -1;
	base_len = ((size_t)data[0] << 8) | data[1];
	if (base_len > size - 2)
		return -1;
	ovl_len = size - 2 - base_len;

	/* fdt_overlay_apply() documents valid trees as input: both must pass fdt_validate(). */
	base = fdt_copy_checked(data + 2, base_len);
	if (!base)
		return -1;
	ovl = fdt_copy_checked(data + 2 + base_len, ovl_len);
	if (!ovl) {
		free(base);
		return -1;
	}
	if (fdt_validate(base, base_len) != 0 || fdt_validate(ovl, ovl_len) != 0) {
		free(base);
		free(ovl);
		return -1;
	}

	cap = fdt_totalsize(base) + fdt_totalsize(ovl) + 1024;
	grown = malloc(cap);
	if (!grown)
		abort();
	if (fdt_open_into(base, grown, (int)cap) == 0) {
		if (fdt_overlay_apply(grown, ovl) == 0) {
			(void)fdt_pack(grown);
			(void)fdt_validate(grown, cap);
		}
	}
	free(grown);
	free(ovl);
	free(base);
	return 0;
}
