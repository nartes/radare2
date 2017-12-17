/* radare2 - LGPL - Copyright 2017 - condret, MaskRay */

#include <r_io.h>
#include <stdlib.h>
#include <sdb.h>
#include "r_binheap.h"
#include "r_util.h"
#include "r_vector.h"

#define END_OF_MAP_IDS  0xffffffff

static int r_io_map_cmp_map_by_id(const RIOMap *a, const RIOMap *b) {
	if (a->id < b->id) {
		return -1;
	} else if (a->id > b->id) {
		return 1;
	} else {
		return 0;
	}
}

// Store map parts that are not covered by others into io->map_skyline
R_API void r_io_map_calculate_skyline(RIO *io) {
	if (io->skyline_ctx) {
		r_skyline_free(io->skyline_ctx);
	}

	r_vector_clean(&(io->map_skyline), free);

	io->skyline_ctx = r_skyline_new();

	RVector *ranges = r_vector_new();

	ls_foreach(io->maps, iter, map) {
		RSkylineURange *ur = R_NEW0(RSkylineUserData);

		ur->from = map->itv.addr;
		ur->to = map->itv.end;
		ur->data = map;

		r_vector_push(ranges, ur);
	}

	r_skyline_init(io->skyline_ctx, ranges, r_io_map_cmp_map_by_id);

	r_vector_clear(ranges, free);

	RSkylineIter *it;
	it = r_skyline_begin(io->skyline_ctx);
	while (it != r_skyline_end(io->skyline_ctx)) {
		RSkylineUserData * ud = r_skyline_get_data_with_highest_priority(it);

		RIOMapSkyline * ms = R_NEW0(RIOMapSkyline);
		ms->itv->addr = ud->from;
		ms->itv->end = ud->to;
		ms->map = ud->data;

		r_vector_push(&(io->map_skyline), ms);
	}
}

R_API RIOMap* r_io_map_new(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline) {
	if (!size || !io || !io->maps || !io->map_ids) {
		return NULL;
	}
	RIOMap* map = R_NEW0 (RIOMap);
	if (!map || !io->map_ids || !r_id_pool_grab_id (io->map_ids, &map->id)) {
		free (map);
		return NULL;
	}
	map->fd = fd;
	map->itv.addr = addr;
	map->delta = delta;
	if ((UT64_MAX - size + 1) < addr) {
		r_io_map_new (io, fd, flags, delta - addr, 0LL, size + addr, do_skyline);
		size = -addr;
	}
	// RIOMap describes an interval of addresses (map->from; map->to)
	map->itv.size = size;
	map->flags = flags;
	map->delta = delta;
	// new map lives on the top, being top the list's tail
	ls_append (io->maps, map);
	if (do_skyline) {
		r_io_map_calculate_skyline (io);
	}
	return map;
}

R_API bool r_io_map_remap (RIO *io, ut32 id, ut64 addr) {
	RIOMap *map;
	if (!(map = r_io_map_resolve (io, id))) {
		return false;
	}
	ut64 size = map->itv.size;
	map->itv.addr = addr;
	if (UT64_MAX - size + 1 < addr) {
		map->itv.size = -addr;
		r_io_map_new (io, map->fd, map->flags, map->delta - addr, 0, size + addr, true);
		return true;
	}
	r_io_map_calculate_skyline (io);
	return true;
}

static void _map_free(void* p) {
	RIOMap* map = (RIOMap*) p;
	if (map) {
		free (map->name);
		free (map);
	}
}

R_API void r_io_map_init(RIO* io) {
	if (io && !io->maps) {
		io->maps = ls_newf ((SdbListFree)_map_free);
		if (io->map_ids) {
			r_id_pool_free (io->map_ids);
		}
		io->map_ids = r_id_pool_new (1, END_OF_MAP_IDS);
		r_vector_init(&(io->map_skyline));
	}
}

// check if a map with exact the same properties exists
R_API bool r_io_map_exists(RIO* io, RIOMap* map) {
	SdbListIter* iter;
	RIOMap* m;
	if (!io || !io->maps || !map) {
		return false;
	}
	ls_foreach (io->maps, iter, m) {
		if (!memcmp (m, map, sizeof (RIOMap))) {
			return true;
		}
	}
	return false;
}

// check if a map with specified id exists
R_API bool r_io_map_exists_for_id(RIO* io, ut32 id) {
	return r_io_map_resolve (io, id) != NULL;
}

R_API RIOMap* r_io_map_resolve(RIO* io, ut32 id) {
	SdbListIter* iter;
	RIOMap* map;
	if (!io || !io->maps || !id) {
		return NULL;
	}
	ls_foreach (io->maps, iter, map) {
		if (map->id == id) {
			return map;
		}
	}
	return NULL;
}

R_API RIOMap* r_io_map_add(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline) {
	//check if desc exists
	RIODesc* desc = r_io_desc_get (io, fd);
	if (desc) {
		//a map cannot have higher permissions than the desc belonging to it
		return r_io_map_new (io, fd, (flags & desc->flags) | (flags & R_IO_EXEC),
				delta, addr, size, do_skyline);
	}
	return NULL;
}

R_API RIOMap* r_io_map_get_paddr(RIO* io, ut64 paddr) {
	RIOMap* map;
	SdbListIter* iter;
	if (!io) {
		return NULL;
	}
	ls_foreach_prev (io->maps, iter, map) {
		if (map->delta <= paddr && paddr <= map->delta + map->itv.size - 1) {
			return map;
		}
	}
	return NULL;
}

// gets first map where addr fits in
R_API RIOMap* r_io_map_get(RIO* io, ut64 addr) {
	RIOMap* map;
	SdbListIter* iter;
	if (!io) {
		return NULL;
	}
	ls_foreach_prev (io->maps, iter, map) {
		if (r_itv_contain (map->itv, addr)) {
			return map;
		}
	}
	return NULL;
}

R_API void r_io_map_reset(RIO* io) {
	r_io_map_fini (io);
	r_io_map_init (io);
	r_io_map_calculate_skyline (io);
}

R_API bool r_io_map_del(RIO* io, ut32 id) {
	if (io) {
		RIOMap* map;
		SdbListIter* iter;
		ls_foreach (io->maps, iter, map) {
			if (map->id == id) {
				ls_delete (io->maps, iter);
				r_id_pool_kick_id (io->map_ids, id);
				r_io_map_calculate_skyline (io);
				return true;
			}
		}
	}
	return false;
}

//delete all maps with specified fd
R_API bool r_io_map_del_for_fd(RIO* io, int fd) {
	SdbListIter* iter, * ator;
	RIOMap* map;
	bool ret = false;
	if (!io) {
		return ret;
	}
	ls_foreach_safe (io->maps, iter, ator, map) {
		if (!map) {
			ls_delete (io->maps, iter);
		} else if (map->fd == fd) {
			r_id_pool_kick_id (io->map_ids, map->id);
			//delete iter and map
			ls_delete (io->maps, iter);
			ret = true;
		}
	}
	if (ret) {
		r_io_map_calculate_skyline (io);
	}
	return ret;
}

//brings map with specified id to the tail of of the list
//return a boolean denoting whether is was possible to prioritized
R_API bool r_io_map_prioritize(RIO* io, ut32 id) {
	SdbListIter* iter;
	RIOMap* map;
	if (!io) {
		return false;
	}
	ls_foreach (io->maps, iter, map) {
		// search for iter with the correct map
		if (map->id == id) {
			ls_split_iter (io->maps, iter);
			ls_append (io->maps, map);
			r_io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

R_API bool r_io_map_prioritize_for_fd(RIO* io, int fd) {
	SdbListIter* iter, * ator;
	RIOMap *map;
	SdbList* list;
	if (!io || !io->maps) {
		return false;
	}
	if (!(list = ls_new ())) {
		return false;
	}
	//we need a clean list for this, or this becomes a segfault-field
	r_io_map_cleanup (io);
	//tempory set to avoid free the map and to speed up ls_delete a bit
	io->maps->free = NULL;
	ls_foreach_safe (io->maps, iter, ator, map) {
		if (map->fd == fd) {
			ls_prepend (list, map);
			ls_delete (io->maps, iter);
		}
	}
	ls_join (io->maps, list);
	ls_free (list);
	io->maps->free = _map_free;
	r_io_map_calculate_skyline (io);
	return true;
}


//may fix some inconsistencies in io->maps
R_API void r_io_map_cleanup(RIO* io) {
	SdbListIter* iter, * ator;
	RIOMap* map;
	if (!io || !io->maps) {
		return;
	}
	//remove all maps if no descs exist
	if (!io->files) {
		r_io_map_fini (io);
		r_io_map_init (io);
		return;
	}
	bool del = false;
	ls_foreach_safe (io->maps, iter, ator, map) {
		//remove iter if the map is a null-ptr, this may fix some segfaults
		if (!map) {
			ls_delete (io->maps, iter);
			del = true;
		} else if (!r_io_desc_get (io, map->fd)) {
			//delete map and iter if no desc exists for map->fd in io->files
			r_id_pool_kick_id (io->map_ids, map->id);
			ls_delete (io->maps, iter);
			del = true;
		}
	}
	if (del) {
		r_io_map_calculate_skyline (io);
	}
}

R_API void r_io_map_fini(RIO* io) {
	if (!io) {
		return;
	}
	ls_free (io->maps);
	io->maps = NULL;
	r_id_pool_free (io->map_ids);
	io->map_ids = NULL;

	r_skyline_free(io->skyline_ctx);
	r_vector_clear(&(io->map_skyline), free);
}

R_API void r_io_map_set_name(RIOMap* map, const char* name) {
	if (!map || !name) {
		return;
	}
	free (map->name);
	map->name = strdup (name);
}

R_API void r_io_map_del_name(RIOMap* map) {
	if (map) {
		R_FREE (map->name);
	}
}

//TODO: Kill it with fire
R_API RIOMap* r_io_map_add_next_available(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, ut64 load_align) {
	RIOMap* map;
	SdbListIter* iter;
	ut64 next_addr = addr,
	end_addr = next_addr + size;
	end_addr = next_addr + size;
	ls_foreach (io->maps, iter, map) {
		ut64 to = r_itv_end (map->itv);
		next_addr = R_MAX (next_addr, to + (load_align - (to % load_align)) % load_align);
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		// adding the check for the map's fd to see if this removes contention for
		// memory mapping with multiple files.

		if (map->fd == fd && ((map->itv.addr <= next_addr && next_addr < to) ||
						r_itv_contain (map->itv, end_addr))) {
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			next_addr = to + (load_align - (to % load_align)) % load_align;
			return r_io_map_add_next_available (io, fd, flags, delta, next_addr, size, load_align);
		}
		break;
	}
	return r_io_map_new (io, fd, flags, delta, next_addr, size, true);
}

R_API RList* r_io_map_get_for_fd(RIO* io, int fd) {
	RList* map_list = r_list_newf (NULL);
	SdbListIter* iter;
	RIOMap* map;
	if (!map_list) {
		return NULL;
	}

	ls_foreach (io->maps, iter, map) {
		if (map && map->fd == fd) {
			r_list_append (map_list, map);
		}
	}
	return map_list;
}

R_API bool r_io_map_resize(RIO *io, ut32 id, ut64 newsize) {
	RIOMap *map;
	if (!newsize || !(map = r_io_map_resolve (io, id))) {
		return false;
	}
	ut64 addr = map->itv.addr;
	if (UT64_MAX - newsize + 1 < addr) {
		map->itv.size = -addr;
		r_io_map_new (io, map->fd, map->flags, map->delta - addr, 0, newsize + addr, true);
		return true;
	}
	map->itv.size = newsize;
	r_io_map_calculate_skyline (io);
	return true;
}
