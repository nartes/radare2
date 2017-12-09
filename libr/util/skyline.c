/* radare - LGPL - Copyright 2017 - nartes */
#include <r_util.h>


RVector *r_skyline_events_to_sls(RVector *events);
RVector *r_skyline_sls_to_subranges(RVector *sls);
void r_skyline_search_subrange_by_offset(RSkylineCtx *ctx, ut64 off);
RVector *r_skyline_get_ranges_by_offset(RSkylineCtx * ctx, ut64 off);

inline bool int iter_less(void **a, void **b, bool is_reversed = false) {
	if (is_reversed) {
		return a > b;
	} else {
		return b < a;
	}
}

inline void iter_increment(void ***a, bool is_reversed = false) {
	if (is_reversed) {
		--(*a);
	} else {
		++(*a);
	}
}

inline void r_vector_merge_sorted_ranges(RVector * vec, void **a_beg, void **a_end, void **b_beg, void **b_end, RVectorComparator *cmp, bool a_is_reversed = false, bool b_is_reversed = false) {
	void **pa;
	void **pb;
	bool pal;
	bool pbl;

	while (true) {
		pal = iter_less(pa, a_end, a_is_reversed);
		pbl = iter_less(pb, b_end, b_is_reversed);

		if (!pal && !pbl) {
			break;
		}

		if (pal && pbl) {
			if (cmp(*pa, *pb) < 0) {
				r_vector_push(vec, *pa);
				iter_increment(pa, a_is_reversed);
			} else {
				r_vector_push(vec, *pb);
				iter_increment(pb, b_is_reversed);
			}
		} else if (pal) {
			r_vector_push(vec, *pa);
			iter_increment(pa, a_is_reversed);
		} else { // pbl
			r_vector_push(vec, *pb);
			iter_increment(pb, b_is_reversed);
		}
	}
}

inline void r_vector_subtract_sorted_ranges(RVector * vec, void **a_beg, void **a_end, void **b_beg, void **b_end, RVectorComparator *cmp, bool a_is_reversed = false, bool b_is_reversed = false) {
	void **pa;
	void **pb;
	bool pal;
	bool pbl;

	while (true) {
		pal = iter_less(pa, a_end, a_is_reversed);
		pbl = iter_less(pb, b_end, b_is_reversed);

		if (!pal && !pbl) {
			break;
		}

		if (pal && pbl) {
			if (cmp(*pa, *pb) == 0) {
				iter_increment(pa, a_is_reversed);
				iter_increment(pb, b_is_reversed);
			} else {
				r_vector_push(vec, *pa);
				iter_increment(pa, a_is_reversed);
			}
		} else if (pal) {
			r_vector_push(vec, *pa);
			iter_increment(pa, a_is_reversed);
		} else { // pbl
			iter_increment(pb, b_is_reversed);
		}
	}
}

RSkylineSl* r_skyline_sl_new(void) {
	RSkyline *sl = R_NEW0(RSkylineSl);
	if (!sl) {
		goto err;
	}

	sl->ranges = r_list_new();
	if (!sl->ranges) {
		goto err;
	}

err:
	r_list_free(sl->ranges);
	R_FREE(sl);

out:

	return sl;
}
void r_skyline_srange_free(RSkylineSRange *srange) {
	free(srange->user_data);
	free(srange);
}

bool r_skyline_event_cmp1_less(const RSkylineEvent *a, const RSkylineEvent *b) {
	void *ua;
	void *ub;
	RVectorComparator *ucmp;

	if (!a || !a->range || !a->cmp ||
		!b || !b->range || !b->cmp) {
		return false;
	}

	ua = a->range->user_data->data;
	ub = b->range->user_data->data;
	ucmp = a->range->user_data->cmp;

	return a->off < b->off ||
		   a->off == b->off && a->is_start && b->is_start && ucmp(ua, ub) ||
		   a->off == b->off && !a->is_start && !b->is_start && ucmp(ub, ua) ||
		   a->off == b->off && a->is_start && !b->is_start;
}

int r_skyline_event_cmp2(const RSkylineEvent *a, const RSkylineEvent *b) {
	if (r_skyline_event_cmp1_less(a, b)) {
		return -1;
	} else if (r_skyline_event_cmp1_less(b, a)) {
		return 1;
	} else {
		return 0;
	}
}

int r_skyline_event_cmp3_by_user_data(const RSkylineEvent *a, const RSkylineEvent *b) {
	void *ua;
	void *ub;
	RVectorComparator *ucmp;

	if (!a || !a->range || !a->range->user_data || !b || !b->range || !b->range->user_data) {
		return 0;
	}

	ua = a->range->user_data->data;
	ub = b->range->user_data->data;
	ucmp = a->range->user_data->cmp;

	return ucmp(ua, ub);
}

RSkylineCtx *r_skyline_new(void) {
	return R_NEW0(RSkylineCtx);
}

bool r_skyline_init(RSkylineCtx *ctx, RVector *ranges, RVectorComparator *cmp) {
	bool result = false;
	RVector *events;
	RSkylineEvent *event;
	RSkylineURange *itu;
	RSkylineSRange *srange;
	RSkylineSRange *its;
	RVector *sls;

	if (!ctx || !cmp || !ranges || ranges->len == 0) {
		goto out;
	}

	ctx->ranges = r_vector_new ();
	if (!ctx->ranges) {
		goto err;
	}

	r_vector_reserve (ctx->ranges, ranges->len);

	r_vector_foreach (ranges, itu) {
		srange = R_NEW0 (RSkylineSRange);
		if (!srange) {
			goto err;
		}

		srange->user_data = R_NEW0 (RSkylineUserData);
		if (!srange->user_data) {
			goto err;
		}

		srange->user_data->data = itu->data;
		srange->user_data->cmp = cmp;

		r_vector_push (srange);
	}

	events = r_vector_new ();
	if (!events) {
		goto out;
	}

	r_vector_reserve (events, 2 * ctx->ranges->len);

	r_vector_foreach (ctx->ranges, its) {
		if (its->from > its->to) {
			its->from = -1;
			its->to = -1;
		}

		event = R_NEW0 (RSkylineEvent);
		if (!event) {
			goto err;
		}

		event->off = its->from;
		event->is_start = true;
		event->range = its;

		r_vector_push (events, event);

		event = R_NEW0 (RSkylineEvent);
		if (!event) {
			goto err;
		}

		event->off = its->to;
		event->is_start = false;
		event->range = its;

		r_vector_push (events, event);
	}

	r_vector_sort(events, r_skyline_event_cmp2);

	sls = r_skyline_events_to_sls (events);
	if (!sls) {
		goto err;
	}

	subranges = r_skyline_sls_to_subranges (sls);
	if !(subranges) {
		goto err;
	}

	ctx->subranges = subranges;

err:
	r_vector_free(events);

out:

	return result;
}

bool r_skyline_free(RSkylineCtx *ctx) {
	bool result = false;

	if (!ctx) {
		goto out;
	}

	r_vector_free (ctx->subranges);
	r_list_free (ctx->lru_subrange);
	r_vector_free (ctx->ranges);
	ctx->cmp = NULL;

	result = true;

out:

	return result;
}

RVector *r_skyline_events_to_sls(RVector *events) {
	RVector *prev;
	RVector *cur;
	RVector *tmp;
	int start_count;
	int finish_count;
	RSkylineEvent **mid_point_iter;
	RSkylineEvent **cur_sl_end;
	RSkylineEvent **i;
	RSkylineEvent **events_begin;
	RSkylineEvent **events_end;
	RSkylineEvent **event;
	RSkylineSl *sl;
	RVector *sls;

	sls = r_vector_new();
	if (!sls) {
		goto err;
	}

	prev = r_vector_new();
	cur = r_vector_new();
	tmp = r_vector_new();
	if (!prev || !cur || !tmp) {
		goto err;
	}

	events_begin = events->a;
	events_end = events_begin + events->len;

	for(i = events_begin; i < events_end; i = cur_sl_end) {
		start_count = 0;
		finish_count = 0;
		mid_point_iter = NULL;

		for (cur_sl_end = i; cur_sl_end < events_env && cur_sl_end->off == cur_sl_end->off; ++cur_sl_end) {
			if (cur_sl_end->is_start) {
				++start_count;
			} else {
				if (mid_point_iter == NULL) {
					mid_point_iter = cur_sl_end;

					++finish_count;
				}
			}

			if (mid_point_iter == NULL) {
				mid_point_iter = cur_sl_end;
			}

			prev = cur;

			r_vector_reserve(tmp, prev->len + start_count);
			r_vector_merge_sorted_ranges(tmp, i, w, prev->a, prev->a + prev->len, r_skyline_event_cmp3_by_user_data);
			r_vector_reserve(cur, prev->len + start_count - finish_count);
			r_vector_subtract_sorted_ranges(cur, mid_point_iter, cur_sl_end, tmp->a + tmp->len - 1, tmp->a - 1, r_skyline_event_cmp3_by_user_data, false, true);

			r_vector_clear(tmp, NULL);
			r_vector_clear(prev, NULL);

			sl = r_skyline_sl_new();
			if (!sl) {
				goto err;
			}

			r_vector_foreach(cur, event) {
				r_vector_push(sl->ranges, event->range);
			}

			r_vector_push(sls, sl);
		}
	}

err:

out:

	return sls;
}

RVector *r_skyline_sls_to_subranges(RVector *sls) {
	RVector *subranges;
	RSkylineSubrange *subrange;

	subranges = r_vector_new();
	if (!subranges) {
		goto err;
	}

	RSkylineSl *sl;

	for (sl = sls->a; sl < sls->a + sls->len - 1; ++sl) {
		subrange = R_NEW0(RSkylineSubrange);
		if (!subranges) {
			goto err;
		}

		subrange->from = sl->off;
		subrange->to = (sl + 1)->off;
		subrange->ranges = r_vector_clone(sl->ranges);

		r_vector_push(subranges, subrange);
	}

err:

out:

	return subranges;
}

st64 *r_skyline_ssbo_binary_search(RSkylineCtx *ctx, ut64 off) {
	st64 pos;

	r_vector_lower_bound(ctx->subranges, &off, pos, r_skyline_sl_subrange_cmp4_by_off);

	return pos;
}

void r_skyline_search_subrange_by_offset(RSkylineCtx *ctx, ut64 off) {
	st64 pos = ctx->lru_subrange_pos;

	if (pos != -1) {
		if (0 <= pos && pos < ctx->subranges->len && r_skyline_sl_subrange_cmp4_by_off(&off, ctx->subranges[pos]) == 0) {
			// do nothing
		} else if (0 <= pos + 1 && pos + 1 < ctx->subranges->len && r_skyline_sl_subrange_cmp4_by_off(&off, ctx->subranges[pos]) == 0) {
			++pos;
		} else if (0 <= pos - 1 && pos - 1 < ctx->subranges->len && r_skyline_sl_subrange_cmp4_by_off(&off, ctx->subranges[pos]) == 0) {
			--pos;
		} else {
			pos = -1;
		}
	}

	if (pos == -1) {
		pos = r_skyline_ssbo_binary_search(ctx, off);
	}

	ctx->lru_subrange_pos = pos;
}

RVector *r_skyline_get_ranges_by_offset(RSkylineCtx * ctx, ut64 off) {
	if (ctx->lru_subrange_pos != -1) {
		return ctx->subranges->a[ctx->lru_subrange_pos]->ranges;
	}

	return NULL;
}

RSkylineURange *r_skyline_get_range_by_offset_with_highest_priority(RSkylineCtx *ctx, ut64 off) {
	RSkylineURange *urange;
	RSkylineSRange *srange;
	RVector *ranges;

	urange = NULL;

	if (ctx->lru_subrange_pos != -1) {
		ranges = r_skyline_get_ranges_by_offset(ctx, off);
		if (!ranges || ranges->len == 0) {
			goto out;
		}

		urange = R_NEW0(RSkylineURange);
		if (!urange) {
			goto err;
		}

		srange = ranges->a[0];
		urange->from = srange->from;
		urange->to = srange->to;
		urange->data = srange->user_data->data;
	}

err:

out:
	return urange;
}
