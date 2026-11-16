/* Known-answer probe: libfdt walks a dtb and prints every node path and property. */
#include <stdio.h>
#include <stdlib.h>

#include "libfdt.h"

int main(int argc, char **argv)
{
	FILE *f;
	long sz;
	void *fdt;
	int off = 0, depth = 0, len;
	char path[256];

	if (argc != 2 || !(f = fopen(argv[1], "rb")))
		return 2;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	rewind(f);
	fdt = malloc(sz);
	if (!fdt || fread(fdt, 1, sz, f) != (size_t)sz)
		return 2;
	fclose(f);
	if (fdt_check_header(fdt) || fdt_totalsize(fdt) > (unsigned long)sz)
		return 1;

	do {
		int prop;

		if (fdt_get_path(fdt, off, path, sizeof(path)))
			return 1;
		printf("node %s\n", path);
		fdt_for_each_property_offset(prop, fdt, off) {
			const struct fdt_property *p = fdt_get_property_by_offset(fdt, prop, &len);
			const char *name = fdt_string(fdt, fdt32_to_cpu(p->nameoff));
			const char *v = (const char *)p->data;
			int printable = len > 1 && v[len - 1] == '\0';

			for (int i = 0; i < len - 1; i++)
				if ((unsigned char)v[i] < 32 || (unsigned char)v[i] > 126)
					printable = 0;
			if (printable)
				printf("  %s = \"%s\" (%d)\n", name, v, len);
			else if (len == 4)
				printf("  %s = <0x%x>\n", name, fdt32_to_cpu(*(const fdt32_t *)p->data));
			else
				printf("  %s (%d bytes)\n", name, len);
		}
		off = fdt_next_node(fdt, off, &depth);
	} while (off >= 0 && depth >= 0);
	printf("max phandle %u\n", fdt_get_max_phandle(fdt));
	return 0;
}
