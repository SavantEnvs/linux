#ifndef MAYHEM_FDT_COMMON_H
#define MAYHEM_FDT_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libfdt.h"

/*
 * libfdt's contract (libfdt.h): the buffer holds the whole blob, i.e. fdt_totalsize() bytes, and
 * starts with a complete struct fdt_header. Copy the input into an exactly-sized heap block so that
 * ASan sees any read past what the header promises.
 */
static inline void *fdt_copy_checked(const uint8_t *data, size_t size)
{
	void *buf;

	if (size < sizeof(struct fdt_header))
		return NULL;
	buf = malloc(size);
	if (!buf)
		abort();
	memcpy(buf, data, size);
	if (fdt_check_header(buf) != 0 || fdt_totalsize(buf) > size) {
		free(buf);
		return NULL;
	}
	return buf;
}

/*
 * Whole-tree validator with the algorithm of upstream libfdt's fdt_check_full(), which the kernel's
 * trimmed copy in scripts/dtc/libfdt omits (no fdt_check.c). Returns 0 for a well-formed blob.
 */
static inline int fdt_validate(const void *fdt, size_t bufsize)
{
	unsigned int depth = 0;
	int nextoffset = 0, offset, err;
	int expect_end = 0;

	if (bufsize < FDT_V1_SIZE)
		return -FDT_ERR_TRUNCATED;
	err = fdt_check_header(fdt);
	if (err != 0)
		return err;
	if (bufsize < fdt_totalsize(fdt))
		return -FDT_ERR_TRUNCATED;
	err = fdt_num_mem_rsv(fdt);
	if (err < 0)
		return err;

	for (;;) {
		uint32_t tag;
		const char *propname;

		offset = nextoffset;
		tag = fdt_next_tag(fdt, offset, &nextoffset);
		if (nextoffset < 0)
			return nextoffset;
		if (expect_end && tag != FDT_END)
			return -FDT_ERR_BADSTRUCTURE;
		switch (tag) {
		case FDT_NOP:
			break;
		case FDT_END:
			return depth != 0 ? -FDT_ERR_BADSTRUCTURE : 0;
		case FDT_BEGIN_NODE:
			if (++depth > INT_MAX)
				return -FDT_ERR_BADSTRUCTURE;
			break;
		case FDT_END_NODE:
			if (depth == 0)
				return -FDT_ERR_BADSTRUCTURE;
			if (--depth == 0)
				expect_end = 1;
			break;
		case FDT_PROP:
			if (!fdt_getprop_by_offset(fdt, offset, &propname, &err))
				return err;
			break;
		default:
			return -FDT_ERR_INTERNAL;
		}
	}
}

/* Read-only traversal of a blob: nodes, properties, paths, phandles, aliases, reserve map. */
static inline void fdt_walk_ro(const void *fdt)
{
	char path[256];
	uint32_t phandle;
	int off = 0, depth = 0, len, prop, i, n, visited = 0;

	n = fdt_num_mem_rsv(fdt);
	for (i = 0; i < n; i++) {
		uint64_t addr, sz;

		(void)fdt_get_mem_rsv(fdt, i, &addr, &sz);
	}
	(void)fdt_find_max_phandle(fdt, &phandle);
	(void)fdt_path_offset(fdt, "/");
	(void)fdt_path_offset(fdt, "/chosen");
	(void)fdt_get_alias(fdt, "serial0");

	do {
		const char *name = fdt_get_name(fdt, off, &len);
		int sub, parent;

		(void)name;
		/* these walk from the root per call: first nodes only, so big blobs stay linear */
		if (visited++ < 32) {
			if (fdt_get_path(fdt, off, path, sizeof(path)) == 0)
				(void)fdt_path_offset(fdt, path);
			(void)fdt_address_cells(fdt, off);
			(void)fdt_size_cells(fdt, off);
			parent = fdt_parent_offset(fdt, off);
			(void)parent;
			(void)fdt_supernode_atdepth_offset(fdt, off, 0, NULL);
			(void)fdt_node_depth(fdt, off);
		}
		(void)fdt_get_phandle(fdt, off);
		(void)fdt_node_check_compatible(fdt, off, "ti,am335x");
		(void)fdt_getprop(fdt, off, "compatible", &len);
		(void)fdt_stringlist_count(fdt, off, "compatible");
		(void)fdt_stringlist_search(fdt, off, "compatible", "simple-bus");

		fdt_for_each_property_offset(prop, fdt, off) {
			const char *pname;
			int plen;

			if (!fdt_getprop_by_offset(fdt, prop, &pname, &plen))
				continue;
			(void)fdt_getprop(fdt, off, pname, &plen);
			(void)fdt_stringlist_count(fdt, off, pname);
		}
		fdt_for_each_subnode(sub, fdt, off)
			(void)fdt_get_name(fdt, sub, &len);

		off = fdt_next_node(fdt, off, &depth);
	} while (off >= 0 && depth >= 0);

	(void)fdt_node_offset_by_compatible(fdt, -1, "simple-bus");
	(void)fdt_node_offset_by_prop_value(fdt, -1, "status", "okay", 5);
	(void)fdt_node_offset_by_phandle(fdt, 1);
}

#endif
