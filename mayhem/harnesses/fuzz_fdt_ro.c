// libFuzzer harness: libfdt's read-only API (scripts/dtc/libfdt) on a blob that only passed
// fdt_check_header(), the way early-boot code consumes a bootloader-supplied dtb.
#include "fdt_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	void *fdt = fdt_copy_checked(data, size);

	if (!fdt)
		return -1;
	fdt_walk_ro(fdt);
	free(fdt);
	return 0;
}
