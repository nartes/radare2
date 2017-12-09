#ifndef R_SKYLINE_H
#define R_SkYLINE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_skyline_user_data_t {
	void *data;
	RVectorComparator *cmp;
} RSkylineUserData;

typedef struct r_skyline_event_t {
	ut64 off;
	bool is_start;
	RSkylineSRange* range;
} RSkylineEvent;

typedef struct r_skyline_urange_t {
	ut64 from;
	ut64 to;
	void *data;
} RSkylineURange;

typedef struct r_skyline_srange_t {
	ut64 from;
	ut64 to;
	RSkylineUserData *user_data;
} RSkylineSRange;

typedef struct r_skyline_sl_t {
	ut64 off;
	RVector *ranges;
} RSkylineSl;

typedef struct r_skyline_sl_subrange_t {
	ut64 from;
	ut64 to;
	RVector *ranges;
} RSkylineSlSubrange;

typedef struct r_skyline_ctx_t {
	RVector *ranges;
	RVector *subranges;
	st64 lru_subrange_pos;
} RSkylineCtx;

R_API RSkylineCtx *r_skyline_new(void);
R_API bool r_skyline_init(RSkylineCtx *ctx, RVector *ranges, RVectorComparator* cmp);
R_API bool r_skyline_free(RSkylineCtx *ctx);
R_API RSkylineURange *r_skyline_get_range_by_offset_with_highest_priority(RSkylineCtx *ctx, ut64 off);

#ifdef __cplusplus
}
#endif

#endif // R_SKYLINE_H
