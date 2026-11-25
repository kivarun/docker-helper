/* MNB39 no-exec wrapper policy verification probe (diagnostic only).
 *
 * Measures, IN-PROCESS and without exec'ing any external tool:
 *   1. the kernel-native security_check_context interface
 *      (/sys/fs/selinux/check_context, class security perm
 *      check_context over security_t) against the exact composed
 *      workload context of the wrapper;
 *   2. an exact parse of the LOADED binary policy
 *      (/sys/fs/selinux/policy) for the class constraints (fifo_file)
 *      and the roletype relation, following the reader order of the
 *      kernel security/selinux/ss/policydb.c (magic, version/config,
 *      policycaps/permissive/neveraudit ebitmaps, then the symbol
 *      tables commons -> classes -> roles -> types, stopping before
 *      the avtab).
 *
 * Behavior matrix rows (per the MNB39 directive): valid context,
 * unknown type, role not authorized for type, wrong category,
 * unavailable interface — each recorded with rc and errno.
 *
 * No permanent policy change; the guest harness loads a separately
 * removable diagnostic module and verifies its unload.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define POLICYDB_MAGIC 0xf97cff8cu
#define POLICYDB_STRING "SE Linux"

/* include/uapi/.../policydb.h + libsepol version family */
#define POLICYDB_VERSION_VALIDATETRANS 19
#define POLICYDB_VERSION_MLS 19
#define POLICYDB_VERSION_POLCAP 22
#define POLICYDB_VERSION_PERMISSIVE 23
#define POLICYDB_VERSION_BOUNDARY 24
#define POLICYDB_VERSION_NEW_OBJECT_DEFAULTS 27
#define POLICYDB_VERSION_DEFAULT_TYPE 28
#define POLICYDB_VERSION_CONSTRAINT_NAMES 29
#define POLICYDB_VERSION_NEVERAUDIT 35

/* constraint.h */
#define CEXPR_NOT 1
#define CEXPR_AND 2
#define CEXPR_OR 3
#define CEXPR_ATTR 4
#define CEXPR_NAMES 5

#define CEXPR_USER 1
#define CEXPR_ROLE 2
#define CEXPR_TYPE 4
#define CEXPR_TARGET 8
#define CEXPR_XTARGET 16
#define CEXPR_L1L2 32
#define CEXPR_L1H2 64
#define CEXPR_H1L2 128
#define CEXPR_H1H2 256
#define CEXPR_L1H1 512
#define CEXPR_L2H2 1024

#define CEXPR_EQ 1
#define CEXPR_NEQ 2
#define CEXPR_DOM 3
#define CEXPR_DOMBY 4
#define CEXPR_INCOMP 5

#define CEXPR_MAXDEPTH 5

#define MAXCLASSES 512
#define MAXCONS 16
#define MAXEXPR 64
#define MAXPERMS 32
#define MAXTYPES 8192

static int trace_enabled;
static void TR(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void TR(const char *fmt, ...)
{
	if (!trace_enabled)
		return;
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "TRACE: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	putchar('\n');
	va_end(ap);
}

/* ---------------- byte reader ---------------- */

struct rd {
	const uint8_t *b;
	size_t o, n;
};

static void die(const struct rd *r, const char *what)
{
	fprintf(stderr, "PARSE-FAIL at offset %zu: %s\n", r->o, what);
	exit(3);
}

static uint32_t u32r(struct rd *r)
{
	if (r->n - r->o < 4)
		die(r, "truncated u32");
	uint32_t v = (uint32_t)r->b[r->o] | ((uint32_t)r->b[r->o + 1] << 8) |
		     ((uint32_t)r->b[r->o + 2] << 16) | ((uint32_t)r->b[r->o + 3] << 24);
	r->o += 4;
	TR("u32 @%zu = 0x%08x (%u)", r->o - 4, v, v);
	return v;
}

static uint64_t u64r(struct rd *r)
{
	if (r->n - r->o < 8)
		die(r, "truncated u64");
	uint64_t v = 0;
	for (int i = 7; i >= 0; i--)
		v = (v << 8) | r->b[r->o + i];
	r->o += 8;
	TR("u64 @%zu = 0x%016llx", r->o - 8, (unsigned long long)v);
	return v;
}

static uint8_t *bytesr(struct rd *r, size_t len)
{
	if (r->n - r->o < len)
		die(r, "truncated bytes");
	uint8_t *p = malloc(len + 1);
	memcpy(p, r->b + r->o, len);
	p[len] = 0;
	r->o += len;
	return p;
}

/* kernel ebitmap reader: u32 mapunit (must be 64), u32 highbit,
 * u32 count, then count * (u32 startbit, u64 map). */
struct ebitmap {
	uint32_t count;
	uint32_t start[64];
	uint64_t map[64];
};

static void ebitmap_parse(struct rd *r, const char *what, struct ebitmap *e)
{
	memset(e, 0, sizeof *e);
	uint32_t mapunit = u32r(r);
	(void)u32r(r); /* highbit */
	e->count = u32r(r);
	if (mapunit != 64)
		die(r, "ebitmap mapunit");
	if (e->count > 64)
		die(r, "ebitmap count");
	for (uint32_t i = 0; i < e->count; i++) {
		e->start[i] = u32r(r);
		e->map[i] = u64r(r);
	}
	TR("%s ebitmap count=%u", what, e->count);
}

static int ebitmap_test(const struct ebitmap *e, uint32_t bit)
{
	for (uint32_t i = 0; i < e->count; i++)
		if (bit >= e->start[i] && bit - e->start[i] < 64)
			return (e->map[i] >> (bit - e->start[i])) & 1ULL;
	return 0;
}

/* ---------------- policy symbols ---------------- */

struct symtab_named {
	uint32_t nprim;
	char *name[MAXTYPES];
};

static struct symtab_named roles_tab, types_tab;
static struct {
	char *name;
	uint32_t nperm;
	char *perm[MAXPERMS];
} commons[MAXTYPES];
static uint32_t ncommons;
static struct ebitmap role_types_bits[MAXTYPES];
static unsigned char types_attr[MAXTYPES];

/* commons: char common_read: u32 len, u32 value, u32 perms_nprim,
 * u32 nperm; key str; nperm * (u32 plen, u32 pval, name str) */
static void parse_commons(struct rd *r, uint32_t nel)
{
	for (uint32_t j = 0; j < nel; j++) {
		uint32_t len = u32r(r);
		uint32_t value = u32r(r);
		uint32_t perms_nprim = u32r(r);
		uint32_t nperm = u32r(r);
		if (len == 0 || len == 0xffffffffu || nperm > MAXPERMS)
			die(r, "common header");
		char *nm = (char *)bytesr(r, len);
		TR("common %s value=%u nprim=%u nperm=%u", nm, value, perms_nprim, nperm);
		ncommons = j + 1;
		commons[j].name = strdup(nm);
		commons[j].nperm = perms_nprim;
		for (uint32_t k = 0; k < nperm; k++) {
			uint32_t plen = u32r(r);
			uint32_t pval = u32r(r);
			if (plen == 0 || plen == 0xffffffffu || pval == 0 || pval > MAXPERMS)
				die(r, "common perm header");
			char *pn = (char *)bytesr(r, plen);
			TR("  common perm value=%u name=%s", pval, pn);
			if (pval <= MAXPERMS)
				commons[j].perm[pval - 1] = strdup(pn);
		}
	}
}

/* constraint reader, verbatim kernel order */
struct expr {
	uint32_t expr_type, attr, op;
	struct ebitmap names;
	struct ebitmap tn_types, tn_negset;
	uint32_t tn_flags;
};

struct constraint {
	uint32_t permissions;
	uint32_t nexpr;
	struct expr expr[MAXEXPR];
};

struct classinfo {
	char *name;
	uint32_t value;
	char *comkey;
	struct ebitmap common_bits; /* not used for rendering */
	char *ownperm[MAXPERMS];
	uint32_t perms_nprim;
	struct constraint cons[MAXCONS];
	uint32_t ncons;
	struct constraint vtrans[MAXCONS];
	uint32_t nvtrans;
};

static struct classinfo classes[MAXCLASSES];
static uint32_t nclasses;

static void constraint_vec_read(struct rd *r, struct constraint *cons, uint32_t ncons,
				uint32_t policyvers, int allowxtarget)
{
	for (uint32_t i = 0; i < ncons; i++) {
		struct constraint *c = &cons[i];
		c->permissions = u32r(r);
		c->nexpr = u32r(r);
		TR("constraint[%u] permissions=0x%x nexpr=%u", i, c->permissions, c->nexpr);
		if (c->nexpr > MAXEXPR)
			die(r, "too many exprs");
		int depth = -1;
		for (uint32_t j = 0; j < c->nexpr; j++) {
			struct expr *e = &c->expr[j];
			e->expr_type = u32r(r);
			e->attr = u32r(r);
			e->op = u32r(r);
			switch (e->expr_type) {
			case CEXPR_NOT:
				if (depth < 0)
					die(r, "bad NOT depth");
				break;
			case CEXPR_AND:
			case CEXPR_OR:
				if (depth < 1)
					die(r, "bad AND/OR depth");
				depth--;
				break;
			case CEXPR_ATTR:
				if (depth == CEXPR_MAXDEPTH - 1)
					die(r, "attr depth");
				depth++;
				switch (e->attr) {
				case CEXPR_USER:
				case CEXPR_TYPE:
					if (e->op != CEXPR_EQ && e->op != CEXPR_NEQ)
						die(r, "attr op");
					break;
				case CEXPR_ROLE:
				case CEXPR_L1L2:
				case CEXPR_L1H2:
				case CEXPR_H1L2:
				case CEXPR_H1H2:
				case CEXPR_L1H1:
				case CEXPR_L2H2:
					if (e->op < CEXPR_EQ || e->op > CEXPR_INCOMP)
						die(r, "attr op range");
					break;
				default:
					die(r, "attr kind");
				}
				break;
			case CEXPR_NAMES:
				if (!allowxtarget && (e->attr & CEXPR_XTARGET))
					die(r, "xtarget");
				if (depth == CEXPR_MAXDEPTH - 1)
					die(r, "names depth");
				depth++;
				switch (e->attr & ~(CEXPR_TARGET | CEXPR_XTARGET)) {
				case CEXPR_USER:
				case CEXPR_ROLE:
				case CEXPR_TYPE:
					break;
				default:
					die(r, "names attr");
				}
				if ((e->attr & (CEXPR_TARGET | CEXPR_XTARGET)) ==
				    (CEXPR_TARGET | CEXPR_XTARGET))
					die(r, "names xtarget");
				if (e->op != CEXPR_EQ && e->op != CEXPR_NEQ)
					die(r, "names op");
				ebitmap_parse(r, "names", &e->names);
				if (policyvers >= POLICYDB_VERSION_CONSTRAINT_NAMES) {
					ebitmap_parse(r, "tn-types", &e->tn_types);
					ebitmap_parse(r, "tn-negset", &e->tn_negset);
					e->tn_flags = u32r(r);
				}
				break;
			default:
				die(r, "expr kind");
			}
		}
		if (depth != 0)
			die(r, "expr stack");
	}
}

/* class_read, verbatim kernel order */
static void parse_class(struct rd *r, uint32_t policyvers)
{
	struct classinfo *c = &classes[nclasses++];
	memset(c, 0, sizeof *c);
	uint32_t len = u32r(r);
	uint32_t len2 = u32r(r);
	uint32_t val = u32r(r);
	c->perms_nprim = u32r(r);
	uint32_t npermown = u32r(r);
	uint32_t ncons = u32r(r);
	if (len == 0 || len == 0xffffffffu || npermown > MAXPERMS || ncons > MAXCONS ||
	    nclasses > MAXCLASSES)
		die(r, "class header");
	c->name = (char *)bytesr(r, len);
	c->value = val;
	TR("class %s value=%u nprim=%u own=%u ncons=%u", c->name, val, c->perms_nprim, npermown, ncons);
	if (len2) {
		if (len2 > 128)
			die(r, "comkey len");
		c->comkey = (char *)bytesr(r, len2);
		TR("  comkey=%s", c->comkey);
	}
	for (uint32_t k = 0; k < npermown; k++) {
		uint32_t plen = u32r(r);
		uint32_t pval = u32r(r);
		if (plen == 0 || plen == 0xffffffffu || pval == 0 || pval > MAXPERMS)
			die(r, "class perm header");
		char *pn = (char *)bytesr(r, plen);
		TR("  own perm value=%u name=%s", pval, pn);
		if (pval > c->perms_nprim)
			die(r, "class perm value");
		c->ownperm[pval - 1] = strdup(pn);
	}
	constraint_vec_read(r, c->cons, ncons, policyvers, 0);
	if (policyvers >= POLICYDB_VERSION_VALIDATETRANS) {
		c->nvtrans = u32r(r);
		if (c->nvtrans > MAXCONS)
			die(r, "vtrans count");
		constraint_vec_read(r, c->vtrans, c->nvtrans, policyvers, 1);
	}
}

/* role_read: u32 len, u32 value, [u32 bounds]; key; dominates ebitmap;
 * types ebitmap. The streamed first entry is object_r. */
static void parse_role(struct rd *r, uint32_t policyvers)
{
	(void)policyvers;
	uint32_t len = u32r(r);
	uint32_t value = u32r(r);
	uint32_t bounds = u32r(r); /* family >= BOUNDARY */
	if (len == 0 || len == 0xffffffffu)
		die(r, "role header");
	char *nm = (char *)bytesr(r, len);
	TR("role %s value=%u bounds=%u", nm, value, bounds);
	static struct ebitmap dom;
	ebitmap_parse(r, "role-dominates", &dom);
	if (value == 0 || value >= MAXTYPES)
		die(r, "role value");
	if (strcmp(nm, "object_r") == 0) {
		/* kernel skips inserting object_r but consumes its datums */
		static struct ebitmap skip;
		ebitmap_parse(r, "object_r-types", &skip);
		roles_tab.name[0] = strdup("object_r");
		return;
	}
	roles_tab.name[value - 1] = strdup(nm);
	ebitmap_parse(r, "role-types", &role_types_bits[value - 1]);
}

/* type_read: u32 len, u32 value, u32 prop, u32 bounds; key */
static void parse_type(struct rd *r, uint32_t policyvers)
{
	(void)policyvers;
	uint32_t len = u32r(r);
	uint32_t value = u32r(r);
	uint32_t prop = u32r(r);
	uint32_t bounds = u32r(r);
	if (len == 0 || len == 0xffffffffu)
		die(r, "type header");
	char *nm = (char *)bytesr(r, len);
	TR("type %s value=%u prop=0x%x bounds=%u", nm, value, prop, bounds);
	if (value == 0 || value >= MAXTYPES)
		die(r, "type value");
	types_tab.name[value - 1] = strdup(nm);
	types_attr[value - 1] = ((prop & 2) != 0) ? 1 : 0;
}

/* ---------------- policy load ---------------- */

static uint32_t policyvers_g;

static void load_policy(const char *ppath)
{
	int fd = open(ppath, O_RDONLY);
	if (fd < 0) {
		out("policy-open %s: %s", ppath, strerror(errno));
		exit(2);
	}
	struct stat st;
	if (fstat(fd, &st)) {
		out("policy-fstat: %s", strerror(errno));
		exit(2);
	}
	uint8_t *blob = malloc((size_t)st.st_size);
	size_t got = 0;
	while (got < (size_t)st.st_size) {
		ssize_t rn = read(fd, blob + got, (size_t)st.st_size - got);
		if (rn <= 0)
			break;
		got += (size_t)rn;
	}
	close(fd);
	out("policy-open: accepted (%zu bytes)", got);

	struct rd r = { blob, 0, got };
	if (u32r(&r) != POLICYDB_MAGIC)
		die(&r, "magic");
	char *pstr = (char *)bytesr(&r, u32r(&r));
	if (strcmp(pstr, POLICYDB_STRING) != 0)
		die(&r, "policy string");
	policyvers_g = u32r(&r);
	uint32_t config = u32r(&r);
	out("policyinfo: version=%u mls=%u", policyvers_g, config & 1);
	static struct ebitmap x;
	if (policyvers_g >= POLICYDB_VERSION_POLCAP)
		ebitmap_parse(&r, "policycaps", &x);
	if (policyvers_g >= POLICYDB_VERSION_PERMISSIVE)
		ebitmap_parse(&r, "permissive", &x);
	if (policyvers_g >= POLICYDB_VERSION_NEVERAUDIT)
		ebitmap_parse(&r, "neveraudit", &x);
	uint32_t sym_num = u32r(&r);
	uint32_t ocon_num = u32r(&r);
	out("policyinfo: sym_num=%u ocon_num=%u", sym_num, ocon_num);
	if (sym_num != 8)
		die(&r, "sym_num");

	/* symtab[0]: commons */
	{
		uint32_t nprim = u32r(&r);
		uint32_t nel = u32r(&r);
		TR("commons nprim=%u nel=%u", nprim, nel);
		parse_commons(&r, nel);
	}
	/* symtab[1]: classes (own perms + constraints) */
	{
		uint32_t nprim = u32r(&r);
		uint32_t nel = u32r(&r);
		TR("classes nprim=%u nel=%u", nprim, nel);
		for (uint32_t j = 0; j < nel; j++)
			parse_class(&r, policyvers_g);
	}
	/* symtab[2]: roles (first streamed entry is object_r) */
	{
		uint32_t nprim = u32r(&r);
		uint32_t nel = u32r(&r);
		TR("roles nprim=%u nel=%u", nprim, nel);
		for (uint32_t j = 0; j < nel; j++)
			parse_role(&r, policyvers_g);
	}
	/* symtab[3]: types (len value prop bounds name) */
	{
		uint32_t nprim = u32r(&r);
		uint32_t nel = u32r(&r);
		TR("types nprim=%u nel=%u", nprim, nel);
		if (nel >= MAXTYPES)
			die(&r, "types nel");
		for (uint32_t j = 0; j < nel; j++)
			parse_type(&r, policyvers_g);
	}
	/* parsing stops here: the avtab and everything after is not needed */
}

static struct classinfo *find_class(const char *nm)
{
	for (uint32_t i = 0; i < nclasses; i++)
		if (strcmp(classes[i].name, nm) == 0)
			return &classes[i];
	return NULL;
}

static const char *merged_perm_name(const struct classinfo *c, uint32_t bit)
{
	/* bit <-> perm value (bit = value - 1); the class inherits the
	 * common's permission ordinals first (the kernel perm_claimed_mask
	 * validation pins that order), then its own perms. */
	if (c->comkey) {
		for (uint32_t k = 0; k < ncommons; k++) {
			if (strcmp(commons[k].name, c->comkey) != 0)
				continue;
			if (bit < commons[k].nperm && commons[k].perm[bit])
				return commons[k].perm[bit];
			break;
		}
	}
	if (c->ownperm[bit])
		return c->ownperm[bit];
	return "(unresolved)";
}

/* render one constraint node; returns the rendered expression into buf */
static void render_expr(const struct constraint *c, char *buf, size_t bufsz)
{
	char stack[CEXPR_MAXDEPTH + 1][1024];
	int sp = 0;
	for (uint32_t j = 0; j < c->nexpr; j++) {
		const struct expr *e = &c->expr[j];
		if (sp <= 0 || sp > CEXPR_MAXDEPTH) {
			fprintf(stderr, "PARSE-FAIL: render stack depth %d\n", sp);
			exit(3);
		}
		switch (e->expr_type) {
		case CEXPR_ATTR: {
			char lead[16];
			switch (e->attr) {
			case CEXPR_USER: strcpy(lead, "u1"); break;
			case CEXPR_ROLE: strcpy(lead, "r1"); break;
			case CEXPR_TYPE: strcpy(lead, "t1"); break;
			case CEXPR_L1L2: strcpy(lead, "l1 l2"); break;
			case CEXPR_L1H2: strcpy(lead, "l1 h2"); break;
			case CEXPR_H1L2: strcpy(lead, "h1 l2"); break;
			case CEXPR_H1H2: strcpy(lead, "h1 h2"); break;
			case CEXPR_L1H1: strcpy(lead, "l1 h1"); break;
			case CEXPR_L2H2: strcpy(lead, "l2 h2"); break;
			default:
				fprintf(stderr, "PARSE-FAIL: attr 0x%x\n", e->attr);
				exit(3);
			}
			const char *o = e->op == CEXPR_EQ ? "=" :
					e->op == CEXPR_NEQ ? "!=" :
					e->op == CEXPR_DOM ? "dom" :
					e->op == CEXPR_DOMBY ? "domby" : "incomp";
			snprintf(stack[sp], sizeof stack[0], "%s %s", lead, o);
			sp++;
			break;
		}
		case CEXPR_NAMES: {
			char lead[8];
			const uint32_t base = e->attr & ~(CEXPR_TARGET | CEXPR_XTARGET);
			uint32_t idx = (e->attr & CEXPR_TARGET) ? 2 : 1;
			if (base == CEXPR_USER)
				snprintf(lead, sizeof lead, "u%u", idx);
			else if (base == CEXPR_ROLE)
				snprintf(lead, sizeof lead, "r%u", idx);
			else
				snprintf(lead, sizeof lead, "t%u", idx);
			const char *o = e->op == CEXPR_EQ ? "=" : "!=";
			char names[900];
			names[0] = 0;
			uint32_t ncnt = 0;
			uint32_t lastbits[MAXTYPES];
			for (uint32_t b = 0; b < types_tab.nprim; b++)
				if (ebitmap_test(&e->tn_types, b))
					lastbits[ncnt++] = b;
			for (uint32_t n = 0; n < ncnt; n++) {
				if (n)
					strncat(names, " ", sizeof names - strlen(names) - 1);
				strncat(names, types_tab.name[lastbits[n]]
						  ? types_tab.name[lastbits[n]]
						  : "(unknown)",
					sizeof names - strlen(names) - 1);
			}
			snprintf(stack[sp], sizeof stack[0],
				 ncnt > 1 ? "%s %s { %s }" : "%s %s %s", lead, o, names);
			sp++;
			break;
		}
		case CEXPR_NOT: {
			char tmp[1024];
			sp--;
			snprintf(tmp, sizeof tmp, "%s", stack[sp]);
			snprintf(stack[sp], sizeof stack[0], "(not %s)", tmp);
			sp++;
			break;
		}
		case CEXPR_AND:
		case CEXPR_OR: {
			const char *o = e->expr_type == CEXPR_OR ? "or" : "and";
			char lft[1024], rgt[1024];
			sp -= 2;
			snprintf(lft, sizeof lft, "%s", stack[sp]);
			snprintf(rgt, sizeof rgt, "%s", stack[sp + 1]);
			snprintf(stack[sp], sizeof stack[0], "(%s %s %s)", lft, o, rgt);
			sp++;
			break;
		}
		default:
			fprintf(stderr, "PARSE-FAIL: render type %u\n", e->expr_type);
			exit(3);
		}
	}
	if (sp != 1) {
		fprintf(stderr, "PARSE-FAIL: render final depth %d\n", sp);
		exit(3);
	}
	snprintf(buf, bufsz, "%s", stack[0]);
}

/* ---------------- checkctx ---------------- */

static int checkctx_once(const char *path, const char *ctx, const char *label)
{
	int fd = open(path, O_RDWR);
	if (fd < 0) {
		out("checkctx %s: open: %s rc=2", label, strerror(errno));
		return 2;
	}
	ssize_t w = write(fd, ctx, strlen(ctx));
	int e = errno;
	char canon[512];
	ssize_t rdn = read(fd, canon, sizeof canon - 1);
	close(fd);
	if (w != (ssize_t)strlen(ctx)) {
		out("checkctx %s: DENIED (write %ld errno=%d %s) rc=1",
		    label, (long)w, e, strerror(e));
		return 1;
	}
	if (rdn < 0) {
		out("checkctx %s: write ok, read-back failed: %s rc=1", label, strerror(errno));
		return 1;
	}
	canon[rdn] = 0;
	out("checkctx %s: ACCEPT canon=%s", label, canon);
	return 0;
}

/* ---------------- main ---------------- */

int main(int argc, char **argv)
{
	if (getenv("MNB39_TRACE"))
		trace_enabled = 1;
	if (argc < 2) {
		fprintf(stderr, "usage: probe checkctx <path> <ctx> <label>"
				" | policyinfo | constrain <class> | roletype <type>\n");
		return 64;
	}
	if (strcmp(argv[1], "selfctx") == 0) {
		char buf[256];
		int sfd = open("/proc/self/attr/current", O_RDONLY);
		if (sfd < 0) {
			out("selfctx: open: %s", strerror(errno));
			return 2;
		}
		ssize_t n = read(sfd, buf, sizeof buf - 1);
		close(sfd);
		if (n <= 0) {
			out("selfctx: read: %s", strerror(errno));
			return 2;
		}
		while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == 0))
			n--;
		buf[n] = 0;
		printf("%s\n", buf);
		return 0;
	}
	if (strcmp(argv[1], "checkctx") == 0) {
		if (argc < 5) {
			fprintf(stderr, "checkctx needs path ctx label\n");
			return 64;
		}
		return checkctx_once(argv[2], argv[3], argv[4]);
	}
	const char *ppath = getenv("MNB39_POLICY_PATH");
	if (!ppath)
		ppath = "/sys/fs/selinux/policy";
	load_policy(ppath);

	if (strcmp(argv[1], "policyinfo") == 0) {
		out("policyinfo: classes=%u commons_names=", nclasses);
		return 0;
	}
	if (strcmp(argv[1], "constrain") == 0) {
		if (argc < 3) {
			fprintf(stderr, "constrain needs class name\n");
			return 64;
		}
		struct classinfo *c = find_class(argv[2]);
		if (!c) {
			out("constrain: class %s not found in the loaded policy", argv[2]);
			return 4;
		}
		for (uint32_t i = 0; i < c->ncons; i++) {
			struct constraint *cn = &c->cons[i];
			char perms[400];
			perms[0] = 0;
			for (uint32_t bit = 0; bit < 32; bit++) {
				if (cn->permissions & (1U << bit)) {
					if (perms[0])
						strncat(perms, " ", sizeof perms - strlen(perms) - 1);
					strncat(perms, merged_perm_name(c, bit),
						sizeof perms - strlen(perms) - 1);
				}
			}
			char exprbuf[1100];
			render_expr(cn, exprbuf, sizeof exprbuf);
			int mls = 0;
			for (uint32_t j = 0; j < cn->nexpr; j++) {
				uint32_t a = cn->expr[j].attr &
					     ~(CEXPR_TARGET | CEXPR_XTARGET);
				if (a >= CEXPR_L1L2)
					mls = 1;
			}
			out("%s %s { %s } (%s);", mls ? "mlsconstrain" : "constraint",
			    c->name, perms, exprbuf);
		}
		return 0;
	}
	if (strcmp(argv[1], "roletype") == 0) {
		if (argc < 3) {
			fprintf(stderr, "roletype needs type name\n");
			return 64;
		}
		uint32_t bit = 0xffffffffu;
		for (uint32_t t = 0; t < MAXTYPES; t++)
			if (types_tab.name[t] && strcmp(types_tab.name[t], argv[2]) == 0)
				bit = t;
		if (bit == 0xffffffffu) {
			out("roletype: type %s not found in the loaded policy", argv[2]);
			return 4;
		}
		for (uint32_t v = 0; v < MAXTYPES; v++) {
			if (roles_tab.name[v] && role_types_bits[v].count &&
			    ebitmap_test(&role_types_bits[v], bit))
				out("%s", roles_tab.name[v]);
		}
		return 0;
	}
	fprintf(stderr, "unknown subcommand %s\n", argv[1]);
	return 64;
}
