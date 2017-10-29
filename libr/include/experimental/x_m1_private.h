#ifndef X_M1_PRIVATE
#define X_M1_PRIVATE

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_bin_x_s1_t {
	ut64 off;
	bool start;
	int s_id;
} RBinXS1;

typedef struct r_bin_x_s2_t {
	ut64 from;
	ut64 to;
	int s_id;
} RBinXS2;

typedef struct r_bin_x_s3_t {
	int l;
	int *s;
	ut64 off;
} RBinXS3;

typedef struct r_bin_x_s4_t {
	ut64 from;
	ut64 to;
	int *s;
	int l;
} RBinXS4;

typedef struct r_bin_x_s5_t {
	RBinXS4 *d;
	int u;
	RBinXS4 *sections;
} RBinXS5;

static void r_bin_x_f2 (RBinXS1 *b, int n, RBinXS3 **out, int *out_len);
static int _r_bin_x_f2 (RBinXS1 *b, int n, int dry, RBinXS3 **out, int out_len);
static int r_bin_x_f3 (RBinXS3 *c, int m, RBinXS4 **out);
static void r_bin_x_f1 (RBinObject *o);
static void r_bin_x_f5 (RBinObject *o);
static void r_bin_x_f6_bt (RBinObject *o, ut64 off, int va);
static RBinSection *r_bin_x_f7_get_first (RBinObject *o, int va);
static int r_bin_x_cmp1 (RBinXS1 const *x, RBinXS1 const *y);
static int r_bin_x_cmp2_less (RBinXS1 const *x, RBinXS1 const *y);

#ifdef __cplusplus
}
#endif

#endif
