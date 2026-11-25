/* MNB39 no-exec wrapper policy verification probe (diagnostic only).
 *
 * Freestanding, syscall-only build: the guest gcc static-glibc archive
 * is unusable (SUSE glibc 2.44 .bss relocation bug), and a loader-free
 * binary needs no file grants beyond its own exec — every libc-touched
 * syscall is routed through the inline kernel-syscall wrappers below,
 * all output through the mini formatter, and all allocation through an
 * mmap bump arena. The parse logic follows the reader order of the
 * kernel security/selinux/ss/policydb.c.
 *
 * Measures, IN-PROCESS and without spawning any external executable:
 *   1. the kernel-native security_check_context interface
 *      (/sys/fs/selinux/check_context, class security perm
 *      check_context over security_t) against a supplied context —
 *      the behavior matrix rows are composed by the guest harness;
 *   2. an exact parse of the LOADED binary policy
 *      (/sys/fs/selinux/policy) for the loaded class constraints
 *      (fifo_file) and the roletype relation.
 *
 * Storage design (the loaded policy is multi-MB on this distro):
 *   - the policy blob is mmap'd;
 *   - constraint data is retained ONLY for the requested class (the
 *     byte range of its constraint tree, plus its node count); the
 *     rendering streams over that range after the type table is loaded
 *     so nameset bits resolve against type names;
 *   - role->types bitmaps are converted to compact set-bit lists;
 *   - type names are retained in one flat array.
 *
 * No permanent policy change; the guest harness loads separately
 * removable diagnostic modules and verifies their unload.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_fstat 5
#define SYS_mmap 9
#define SYS_exit_group 231
#define SYS_dup2 33

#define MAXPERMS 32
#define MAXCLASSES 512
#define MAXCOMMONS 64
#define MAXTYPES 12288

/* constraint tokens (kernel constraint.h) */
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

/* kernel policy versions */
#define POLICYDB_VERSION_VALIDATETRANS 19
#define POLICYDB_VERSION_POLCAP 22
#define POLICYDB_VERSION_PERMISSIVE 23
#define POLICYDB_VERSION_NEVERAUDIT 35
#define POLICYDB_VERSION_CONSTRAINT_NAMES 29
#define POLICYDB_MAGIC 0xf97cff8cu

static void sys_exit_group(long rc) __attribute__((noreturn));

static int trace_enabled;
static void TR(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* ---------------- raw x86_64 syscall interface ---------------- */

static long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long r;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__asm__ volatile ("syscall"
			  : "=a"(r)
			  : "a"(n), "D"(a1), "S"(a2), "d"(a3),
			    "r"(r10), "r"(r8), "r"(r9)
			  : "rcx", "r11", "memory");
	return r;
}

static long sys_open(const char *p, int fl) { return syscall6(SYS_open, (long)p, fl, 0, 0, 0, 0); }
static long sys_read(int fd, void *b, unsigned long n) { return syscall6(SYS_read, fd, (long)b, (long)n, 0, 0, 0); }
static long sys_write(int fd, const void *b, unsigned long n) { return syscall6(SYS_write, fd, (long)b, (long)n, 0, 0, 0); }
static long sys_close(int fd) { return syscall6(SYS_close, fd, 0, 0, 0, 0, 0); }
static long sys_dup2(int old, int new) { return syscall6(SYS_dup2, old, new, 0, 0, 0, 0); }
static void *sys_mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off)
{
	return (void *)syscall6(SYS_mmap, (long)addr, len, prot, flags, fd, off);
}

/* x86_64 struct stat: st_size at offset 0x30 */
struct sys_stat { uint8_t b[0x30]; uint64_t st_size; uint8_t tail[64]; };

static void sys_exit_group(long rc)
{
	syscall6(SYS_exit_group, rc, 0, 0, 0, 0, 0);
	for (;;)
		;
}

/* ---------------- mini libc ---------------- */

static void *memset_v(void *d, int c, size_t n)
{
	unsigned char *p = d;
	while (n--)
		*p++ = (unsigned char)c;
	return d;
}
#define memset memset_v

static void *memcpy_v(void *d, const void *s, size_t n)
{
	unsigned char *dd = d;
	const unsigned char *ss = s;
	while (n--)
		*dd++ = *ss++;
	return d;
}
#define memcpy memcpy_v

static size_t strlen_v(const char *s)
{
	size_t n = 0;
	while (*s++)
		n++;
	return n;
}
#define strlen strlen_v

static int strcmp_v(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}
#define strcmp strcmp_v

static void strncat_v(char *d, const char *s, size_t dn)
{
	size_t l = strlen(d);
	while (*s && l + 1 < dn)
		d[l++] = *s++;
	d[l] = 0;
}
#define strncat strncat_v

static void fmt_ull(char **pp, size_t *left, uint64_t v, unsigned base, int uppercase, int width, char pad)
{
	char tmp[24];
	const char *dig = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
	int n = 0;
	if (!v)
		tmp[n++] = '0';
	while (v) {
		tmp[n++] = dig[v % base];
		v /= base;
	}
	while (width > n && *left) {
		*(*pp)++ = pad;
		(*left)--;
		width--;
	}
	while (n && *left) {
		*(*pp)++ = tmp[--n];
		(*left)--;
	}
}

static size_t mini_vsnprintf(char *ob, size_t sz, const char *fmt, va_list ap)
{
	char *p = ob;
	size_t left = sz ? sz - 1 : 0;
	const char *f = fmt;
	while (*f && left) {
		if (*f != '%') {
			*p++ = *f++;
			left--;
			continue;
		}
		f++;
		int pad = ' ';
		int width = 0;
		if (*f == '0') {
			pad = '0';
			f++;
		}
		while (*f >= '0' && *f <= '9') {
			width = width * 10 + (*f - '0');
			f++;
		}
		int lmod = 0;
		while (*f == 'l' || *f == 'z') {
			lmod++;
			f++;
		}
		char c = *f++;
		if (c == 'u' || c == 'd' || c == 'i' || c == 'x' || c == 'X') {
			uint64_t v, mag;
			long sv;
			if (lmod) {
				v = va_arg(ap, long);
				sv = (long)v;
			} else {
				v = va_arg(ap, unsigned int);
				sv = (int)v;
			}
			if (c == 'u')
				fmt_ull(&p, &left, v, 10, 0, width, pad);
			else if (c == 'x' || c == 'X')
				fmt_ull(&p, &left, v, 16, c == 'X', width, pad);
			else {
				mag = (uint64_t)(sv < 0 ? -sv : sv);
				if (sv < 0 && left) {
					*p++ = '-';
					left--;
				}
				fmt_ull(&p, &left, mag, 10, 0, width, pad);
			}
		} else if (c == 's') {
			const char *s = va_arg(ap, const char *);
			s = s ? s : "(null)";
			while (*s && left) {
				*p++ = *s++;
				left--;
			}
		} else if (c == '%') {
			*p++ = '%';
			left--;
		} else {
			/* unsupported specifier: emit nothing */
		}
	}
	if (sz)
		*p = 0;
	return (size_t)(p - ob);
}

static void msnprintf_fill(char *dst, size_t sz, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	mini_vsnprintf(dst, sz, fmt, ap);
	va_end(ap);
}
#define snprintf msnprintf_fill

static void out(const char *fmt, ...)
{
	static char obuf[4096];
	va_list ap;
	va_start(ap, fmt);
	size_t n = mini_vsnprintf(obuf, sizeof obuf, fmt, ap);
	va_end(ap);
	if (n < sizeof obuf - 1) {
		obuf[n++] = '\n';
		sys_write(1, obuf, n);
	}
}

static void TR(const char *fmt, ...)
{
	static char obuf[1024];
	if (!trace_enabled)
		return;
	va_list ap;
	va_start(ap, fmt);
	size_t n = mini_vsnprintf(obuf, sizeof obuf, fmt, ap);
	va_end(ap);
	if (n < sizeof obuf - 1) {
		obuf[n++] = '\n';
		sys_write(2, obuf, n);
	}
}

/* bump arena on one anonymous mmap */
#define ARENA_SIZE (64UL << 20)
static char *arena_head;
static size_t arena_off;
static void arena_init(void)
{
	arena_head = sys_mmap(0, ARENA_SIZE, 3 /*PROT_READ|WRITE*/, 0x22, -1, 0);
	if ((long)arena_head < 0) {
		out("arena mmap failed");
		sys_exit_group(2);
	}
	arena_off = 0;
}
static void *balloc(size_t n)
{
	n = (n + 15) & ~(size_t)15;
	if (arena_off + n >= ARENA_SIZE) {
		out("arena exhausted");
		sys_exit_group(3);
	}
	void *p = arena_head + arena_off;
	arena_off += n;
	return p;
}

/* ---------------- policy tables ---------------- */

static uint8_t *g_blob;

struct rd {
	const uint8_t *b;
	size_t o, n;
};

static void die(const struct rd *r, const char *what)
{
	out("PARSE-FAIL at offset %zu: %s", r->o, what);
	if (g_blob) {
		for (size_t i = 0; i < 64; i += 4)
			out("h[%02zu]=%08x", i, g_blob[i] | (g_blob[i+1] << 8) |
			    (g_blob[i+2] << 16) | ((unsigned)g_blob[i+3] << 24));
	}
	sys_exit_group(3);
}

static uint32_t u32r(struct rd *r)
{
	if (r->n - r->o < 4)
		die(r, "truncated u32");
	uint32_t v = (uint32_t)r->b[r->o] | ((uint32_t)r->b[r->o + 1] << 8) |
		     ((uint32_t)r->b[r->o + 2] << 16) | ((uint32_t)r->b[r->o + 3] << 24);
	r->o += 4;
	TR("u32 @%zu = 0x%x (%u)", r->o - 4, v, v);
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
	TR("u64 @%zu = %llu", r->o - 8, (unsigned long long)v);
	return v;
}

static char *bytesr(struct rd *r, size_t len)
{
	if (len == 0 || len == 0xffffffffu || r->n - r->o < len || len > 4096)
		die(r, "bytes range");
	char *p = balloc(len + 1);
	memcpy(p, r->b + r->o, len);
	p[len] = 0;
	r->o += len;
	return p;
}

/* compact bit list (arena) */
struct bitlist {
	uint32_t n;
	uint32_t bits[];
};

/* kernel ebitmap: u32 mapunit(==64), u32 highbit, u32 count, then
 * count * (u32 startbit, u64 map) */
static void ebitmap_parse(struct rd *r, const char *what, struct bitlist **dst)
{
	uint32_t mapunit = u32r(r);
	(void)u32r(r); /* highbit */
	uint32_t count = u32r(r);
	if (mapunit != 64)
		die(r, "ebitmap mapunit");
	if (count > 512)
		die(r, "ebitmap count");
	uint32_t total = 0;
	struct bitlist *tmp = balloc(sizeof(struct bitlist) + sizeof(uint32_t) * count * 64);
	for (uint32_t i = 0; i < count; i++) {
		uint32_t start = u32r(r);
		uint64_t map = u64r(r);
		for (uint32_t b = 0; b < 64; b++)
			if ((map >> b) & 1ULL)
				tmp->bits[total++] = start + b;
	}
	TR("%s ebitmap nodes=%u bits=%u", what, count, total);
	if (!dst)
		return;
	struct bitlist *bl = balloc(sizeof(struct bitlist) + sizeof(uint32_t) * total);
	bl->n = total;
	memcpy(bl->bits, tmp->bits, sizeof(uint32_t) * total);
	*dst = bl;
}

struct common_entry {
	char *name;
	uint32_t value;
	uint32_t nperm;
	char *perm[MAXPERMS];
};

struct class_entry {
	char *name;
	uint32_t value;
	uint32_t perms_nprim;
	uint32_t ncons;
	char *ownperm[MAXPERMS];
	char *comkey;
	uint32_t cons_off;
	uint32_t cons_len;
	uint8_t *cons_bytes;
};

static struct common_entry commons[MAXCOMMONS];
static uint32_t ncommons;
static struct class_entry classes[MAXCLASSES];
static uint32_t nclasses;
static struct class_entry *g_target;
static const char *g_target_class;

#define MAXROLEBITS (MAXTYPES)
static char *roles_names[MAXTYPES];
static struct bitlist *roles_types[MAXTYPES];
static char *types_names[MAXTYPES];
static uint32_t types_nprim_g;
static uint32_t policyvers_g;

/* expression reader (kernel order); optionally records the node mask
 * and the mls flag for the cap class */
static void expr_stream(struct rd *r, uint32_t nexpr, int allowxtarget, int *mls_out)
{
	int depth = -1;
	int mls = 0;
	for (uint32_t j = 0; j < nexpr; j++) {
		uint32_t et = u32r(r);
		uint32_t attr = u32r(r);
		uint32_t op = u32r(r);
		TR("expr type=%u attr=0x%x op=%u depth=%d", et, attr, op, depth);
		switch (et) {
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
			switch (attr) {
			case CEXPR_USER:
			case CEXPR_TYPE:
				if (op != CEXPR_EQ && op != CEXPR_NEQ)
					die(r, "attr op");
				break;
			case CEXPR_ROLE:
			case CEXPR_L1L2:
			case CEXPR_L1H2:
			case CEXPR_H1L2:
			case CEXPR_H1H2:
			case CEXPR_L1H1:
			case CEXPR_L2H2:
				if (op < CEXPR_EQ || op > CEXPR_INCOMP)
					die(r, "attr op range");
				break;
			default:
				die(r, "attr kind");
			}
			if (attr >= CEXPR_L1L2)
				mls = 1;
			break;
		case CEXPR_NAMES:
			if (!allowxtarget && (attr & CEXPR_XTARGET))
				die(r, "xtarget");
			if (depth == CEXPR_MAXDEPTH - 1)
				die(r, "names depth");
			depth++;
			switch (attr & ~(CEXPR_TARGET | CEXPR_XTARGET)) {
			case CEXPR_USER:
			case CEXPR_ROLE:
			case CEXPR_TYPE:
				break;
			default:
				die(r, "names attr");
			}
			if ((attr & (CEXPR_TARGET | CEXPR_XTARGET)) ==
			    (CEXPR_TARGET | CEXPR_XTARGET))
				die(r, "names xtarget");
			if (op != CEXPR_EQ && op != CEXPR_NEQ)
				die(r, "names op");
			ebitmap_parse(r, "names", 0);
			if (policyvers_g >= POLICYDB_VERSION_CONSTRAINT_NAMES) {
				ebitmap_parse(r, "tn-types", 0);
				ebitmap_parse(r, "tn-negset", 0);
				u32r(r); /* the type_set flags */
			}
			break;
		default:
			die(r, "expr kind");
		}
	}
	if (depth != 0)
		die(r, "expr stack");
	if (mls_out)
		*mls_out = mls;
}

static void constraint_tree_walk(struct rd *r, uint32_t ncons, int allowxtarget)
{
	for (uint32_t i = 0; i < ncons; i++) {
		uint32_t permissions = u32r(r);
		uint32_t nexpr = u32r(r);
		if (nexpr > 64)
			die(r, "expr count");
		TR("constraint permissions=0x%x nexpr=%u", permissions, nexpr);
		expr_stream(r, nexpr, allowxtarget, 0);
	}
}

static void parse_common(struct rd *r)
{
	uint32_t hlen = u32r(r);
	uint32_t value = u32r(r);
	uint32_t perms_nprim = u32r(r);
	uint32_t nperm = u32r(r);
	if (hlen == 0 || hlen == 0xffffffffu || perms_nprim > MAXPERMS || nperm > MAXPERMS)
		die(r, "common header");
	if (ncommons >= MAXCOMMONS)
		die(r, "commons overflow");
	struct common_entry *cm = &commons[ncommons++];
	cm->name = bytesr(r, hlen);
	cm->value = value;
	cm->nperm = perms_nprim;
	TR("common %s value=%u nprim=%u nperm=%u", cm->name, value, perms_nprim, nperm);
	for (uint32_t k = 0; k < nperm; k++) {
		uint32_t plen = u32r(r);
		uint32_t pval = u32r(r);
		if (plen == 0 || pval == 0 || pval > MAXPERMS)
			die(r, "common perm header");
		cm->perm[pval - 1] = bytesr(r, plen);
		TR("  common perm value=%u name=%s", pval, cm->perm[pval - 1]);
	}
}

static void parse_class(struct rd *r)
{
	if (nclasses >= MAXCLASSES)
		die(r, "class overflow");
	struct class_entry *c = &classes[nclasses++];
	memset(c, 0, sizeof *c);
	uint32_t hlen = u32r(r);
	uint32_t clen2 = u32r(r);
	c->value = u32r(r);
	c->perms_nprim = u32r(r);
	uint32_t npermown = u32r(r);
	c->ncons = u32r(r);
	if (hlen == 0 || hlen == 0xffffffffu || npermown > MAXPERMS)
		die(r, "class header");
	c->name = bytesr(r, hlen);
	TR("class %s value=%u nprim=%u own=%u ncons=%u", c->name, c->value, c->perms_nprim, npermown, c->ncons);
	if (clen2) {
		if (clen2 > 128)
			die(r, "comkey len");
		c->comkey = bytesr(r, clen2);
		TR("  comkey=%s", c->comkey);
	}
	for (uint32_t k = 0; k < npermown; k++) {
		uint32_t plen = u32r(r);
		uint32_t pval = u32r(r);
		if (plen == 0 || pval == 0 || pval > c->perms_nprim || pval > MAXPERMS)
			die(r, "class perm header");
		c->ownperm[pval - 1] = bytesr(r, plen);
		TR("  own perm value=%u name=%s", pval, c->ownperm[pval - 1]);
	}
	if (g_target_class && strcmp(c->name, g_target_class) == 0) {
		g_target = c;
		c->cons_off = (uint32_t)r->o;
	}
	constraint_tree_walk(r, c->ncons, 0);
	if (g_target == c) {
		c->cons_len = (uint32_t)(r->o - c->cons_off);
		c->cons_bytes = balloc(c->cons_len);
		memcpy(c->cons_bytes, g_blob + c->cons_off, c->cons_len);
	}
	if (policyvers_g >= POLICYDB_VERSION_VALIDATETRANS) {
		uint32_t nv = u32r(r);
		if (nv > 64)
			die(r, "vtrans count");
		constraint_tree_walk(r, nv, 1);
	}
	if (policyvers_g >= 27) {
		(void)u32r(r); /* default_user */
		(void)u32r(r); /* default_role */
		(void)u32r(r); /* default_range */
	}
	if (policyvers_g >= 28) {
		(void)u32r(r); /* default_type */
	}
}

static void parse_role(struct rd *r)
{
	uint32_t hlen = u32r(r);
	uint32_t value = u32r(r);
	uint32_t bounds = u32r(r); /* the family >= BOUNDARY */
	if (hlen == 0 || hlen == 0xffffffffu)
		die(r, "role header");
	char *nm = bytesr(r, hlen);
	TR("role %s value=%u bounds=%u", nm, value, bounds);
	if (value == 0 || value > MAXTYPES)
		die(r, "role value");
	if (strcmp(nm, "object_r") == 0) {
		/* the kernel pre-inserts object_r (value 1) and skips its
		 * streamed datum after consuming it */
		static struct bitlist *skip;
		ebitmap_parse(r, "object_r-dominates", &skip);
		ebitmap_parse(r, "object_r-types", &skip);
		return;
	}
	roles_names[value - 1] = nm;
	static struct bitlist *dom;
	ebitmap_parse(r, "role-dominates", &dom);
	ebitmap_parse(r, "role-types", &roles_types[value - 1]);
}

static void parse_type(struct rd *r)
{
	uint32_t hlen = u32r(r);
	uint32_t value = u32r(r);
	uint32_t prop = u32r(r);
	uint32_t bounds = u32r(r); /* the family >= BOUNDARY */
	if (hlen == 0 || hlen == 0xffffffffu)
		die(r, "type header");
	char *nm = bytesr(r, hlen);
	TR("type %s value=%u prop=0x%x bounds=%u", nm, value, prop, bounds);
	if (value == 0 || value > MAXTYPES)
		die(r, "type value");
	types_names[value - 1] = nm;
	(void)prop;
	(void)bounds;
}

static void load_policy(const char *ppath)
{
	int fd = (int)sys_open(ppath, O_RDONLY);
	if (fd < 0) {
		out("policy-open errno=%d", (int)(-fd));
		sys_exit_group(2);
	}
	struct sys_stat st;
	if (syscall6(SYS_fstat, fd, (long)&st, 0, 0, 0, 0)) {
		out("policy-fstat failed");
		sys_exit_group(2);
	}
	size_t sz = (size_t)st.st_size;
	g_blob = sys_mmap(0, (sz + 4095) & ~(size_t)4095, 3, 0x02 /*MAP_PRIVATE*/, fd, 0);
	if ((long)g_blob < 0) {
		out("policy mmap failed");
		sys_exit_group(2);
	}
	sys_close(fd);
	out("policy-open: accepted (%zu bytes)", sz);

	struct rd r = { g_blob, 0, sz };
	if (u32r(&r) != POLICYDB_MAGIC)
		die(&r, "magic");
	uint32_t len = u32r(&r);
	char *pstr = bytesr(&r, len);
	if (strcmp(pstr, "SE Linux") != 0)
		die(&r, "policy string");
	policyvers_g = u32r(&r);
	uint32_t config = u32r(&r);
	uint32_t sym_num = u32r(&r);
	uint32_t ocon_num = u32r(&r);
	out("policyinfo: version=%u mls=%u sym_num=%u ocon_num=%u",
	    policyvers_g, config & 1, sym_num, ocon_num);
	if (policyvers_g >= POLICYDB_VERSION_POLCAP)
		ebitmap_parse(&r, "policycaps", 0);
	if (policyvers_g >= POLICYDB_VERSION_PERMISSIVE)
		ebitmap_parse(&r, "permissive", 0);
	if (policyvers_g >= POLICYDB_VERSION_NEVERAUDIT)
		ebitmap_parse(&r, "neveraudit", 0);
	if (sym_num != 8)
		die(&r, "sym_num");

	{
		uint32_t nprim = u32r(&r);
		uint32_t nel = u32r(&r);
		TR("commons nprim=%u nel=%u", nprim, nel);
		(void)nprim;
		for (uint32_t j = 0; j < nel; j++)
			parse_common(&r);
	}
	{
		uint32_t nprim = u32r(&r);
		uint32_t nel = u32r(&r);
		TR("classes nprim=%u nel=%u", nprim, nel);
		(void)nprim;
		for (uint32_t j = 0; j < nel; j++)
			parse_class(&r);
	}
	{
		uint32_t nprim = u32r(&r);
		uint32_t nel = u32r(&r);
		TR("roles nprim=%u nel=%u", nprim, nel);
		(void)nprim;
		for (uint32_t j = 0; j < nel; j++)
			parse_role(&r);
	}
	{
		uint32_t nprim = u32r(&r);
		uint32_t nel = u32r(&r);
		TR("types nprim=%u nel=%u", nprim, nel);
		(void)nprim;
		if (nel > MAXTYPES)
			die(&r, "types nel");
		types_nprim_g = nprim;
		for (uint32_t j = 0; j < nel; j++)
			parse_type(&r);
	}
	/* the avtab and the later tables are not needed */
}

/* ---------------- rendering ---------------- */

static int mls_seen;

static const char *type_name_of(uint32_t value1)
{
	/* ebitmap bits index type values as value-1 */
	if (value1 == 0 || value1 > MAXTYPES)
		return "(none)";
	return types_names[value1 - 1] ? types_names[value1 - 1] : "(unknown)";
}

static struct bitlist *g_tn_bits;
static char last_rendered_root[1536];
static int last_render_mls;

static void render_expr_stream(struct rd *r, uint32_t nexpr)
{
	char stack[CEXPR_MAXDEPTH + 1][1536];
	char tmp[1536];
	int sp = 0;
	mls_seen = 0; /* per-node reset */
	for (uint32_t j = 0; j < nexpr; j++) {
		uint32_t et = u32r(r);
		uint32_t attr = u32r(r);
		uint32_t op = u32r(r);
		TR("render expr type=%u attr=0x%x op=%u sp=%d", et, attr, op, sp);
		if ((et == CEXPR_AND || et == CEXPR_OR) && sp < 2)
			die(r, "render stack under-op");
		if (et == CEXPR_NOT && sp < 1)
			die(r, "render stack under-not");
		if ((et == CEXPR_ATTR || et == CEXPR_NAMES) && sp >= CEXPR_MAXDEPTH)
			die(r, "render stack overflow");
		switch (et) {
		case CEXPR_ATTR: {
			if (attr >= CEXPR_L1L2)
				mls_seen = 1;
			if (attr >= CEXPR_L1L2 && attr <= CEXPR_L2H2) {
				/* pairwise (two-level) comparison: the kernel
				 * packs both fields into one attr; setools
				 * renders it as an infix triple */
				const char *first, *second;
				switch (attr) {
				case CEXPR_L1L2: first = "l1"; second = "l2"; break;
				case CEXPR_L1H2: first = "l1"; second = "h2"; break;
				case CEXPR_H1L2: first = "h1"; second = "l2"; break;
				case CEXPR_H1H2: first = "h1"; second = "h2"; break;
				case CEXPR_L1H1: first = "l1"; second = "h1"; break;
				case CEXPR_L2H2: first = "l2"; second = "h2"; break;
				default:
					die(r, "render attr kind");
				}
				const char *o = op == CEXPR_EQ ? "eq" :
						op == CEXPR_NEQ ? "neq" :
						op == CEXPR_DOM ? "dom" :
						op == CEXPR_DOMBY ? "domby" :
						op == CEXPR_INCOMP ? "incomp" : "?";
				snprintf(stack[sp], sizeof stack[0], "%s %s %s", first, o, second);
				sp++;
				break;
			}
			const char *lead;
			switch (attr) {
			case CEXPR_USER: lead = "u1"; break;
			case CEXPR_ROLE: lead = "r1"; break;
			case CEXPR_TYPE: lead = "t1"; break;
			default:
				die(r, "render attr kind");
			}
			const char *o = op == CEXPR_EQ ? "=" :
					op == CEXPR_NEQ ? "!=" :
					op == CEXPR_DOM ? "dom" :
					op == CEXPR_DOMBY ? "domby" :
					op == CEXPR_INCOMP ? "incomp" : "?";
			snprintf(stack[sp], sizeof stack[0], "%s %s", lead, o);
			sp++;
			break;
		}
		case CEXPR_NAMES: {
			uint32_t base = attr & ~(CEXPR_TARGET | CEXPR_XTARGET);
			uint32_t idx = (attr & CEXPR_TARGET) ? 2 : 1;
			char lead[8];
			if (base == CEXPR_USER)
				snprintf(lead, sizeof lead, "u%u", idx);
			else if (base == CEXPR_ROLE)
				snprintf(lead, sizeof lead, "r%u", idx);
			else
				snprintf(lead, sizeof lead, "t%u", idx);
			const char *o = op == CEXPR_EQ ? "=" : "!=";
			ebitmap_parse(r, "render-names", &g_tn_bits);
			struct bitlist *tn = 0, *tng = 0;
			if (policyvers_g >= POLICYDB_VERSION_CONSTRAINT_NAMES) {
				ebitmap_parse(r, "render-tn", &tn);
				ebitmap_parse(r, "render-tnn", &tng);
				u32r(r); /* flags */
			}
			const struct bitlist *use = tn ? tn : g_tn_bits;
			char names[1024];
			names[0] = 0;
			uint32_t nn = 0;
			for (uint32_t b = 0; use && b < use->n; b++) {
				uint32_t bitidx = use->bits[b];
				const char *nm = type_name_of(bitidx + 1);
				if (strcmp(nm, "(unknown)") == 0)
					continue;
				if (nn)
					strncat(names, " ", sizeof names - strlen(names) - 1);
				strncat(names, nm, sizeof names - strlen(names) - 1);
				nn++;
			}
			if (nn == 0)
				strncat(names, "(unresolved)", sizeof names - strlen(names) - 1);
			snprintf(stack[sp], sizeof stack[0],
				 nn > 1 ? "%s %s { %s }" : "%s %s %s", lead, o, names);
			sp++;
			break;
		}
		case CEXPR_NOT: {
			sp--;
			snprintf(tmp, sizeof tmp, "%s", stack[sp]);
			snprintf(stack[sp], sizeof stack[0], "(not %s)", tmp);
			sp++;
			break;
		}
		case CEXPR_AND:
		case CEXPR_OR: {
			const char *o = et == CEXPR_OR ? "or" : "and";
			char lft[1536], rgt[1536];
			sp -= 2;
			snprintf(lft, sizeof lft, "%s", stack[sp]);
			snprintf(rgt, sizeof rgt, "%s", stack[sp + 1]);
			snprintf(stack[sp], sizeof stack[0], "(%s %s %s)", lft, o, rgt);
			sp++;
			break;
		}
		default:
			die(r, "render expr kind");
		}
	}
	if (sp != 1)
		die(r, "render final depth");
	snprintf(last_rendered_root, sizeof last_rendered_root, "%s", stack[0]);
	last_render_mls = mls_seen;
}

/* the rendered root of the current node (render_expr_stream writes it) */
static char last_rendered_root[1536];
static int last_render_mls;
static char rendered_root[1536];

static void constrain_emit(struct class_entry *c)
{
	struct rd r = { c->cons_bytes, 0, c->cons_len };
	for (uint32_t i = 0; i < c->ncons; i++) {
		uint32_t permissions = u32r(&r);
		uint32_t nexpr = u32r(&r);
		char perms[400];
		perms[0] = 0;
		for (uint32_t bit = 0; bit < 32; bit++) {
			if (permissions & (1U << bit)) {
				const char *nm = 0;
				if (c->comkey) {
					for (uint32_t k = 0; k < ncommons; k++) {
						if (strcmp(commons[k].name, c->comkey) != 0)
							continue;
						if (bit < commons[k].nperm && commons[k].perm[bit])
							nm = commons[k].perm[bit];
						break;
					}
				}
				if (!nm && c->ownperm[bit])
					nm = c->ownperm[bit];
				if (!nm)
					nm = "(unresolved)";
				if (perms[0])
					strncat(perms, " ", sizeof perms - strlen(perms) - 1);
				strncat(perms, nm, sizeof perms - strlen(perms) - 1);
			}
		}
		render_expr_stream(&r, nexpr);
		snprintf(rendered_root, sizeof rendered_root, "%s", last_rendered_root);
		int mls = last_render_mls;
		out("%s %s { %s } %s;", mls ? "mlsconstrain" : "constraint", c->name, perms, rendered_root);
	}
}

/* ---------------- checkctx ---------------- */

static int checkctx_once(const char *path, const char *ctx, const char *label)
{
	int fd = (int)sys_open(path, O_RDWR);
	if (fd < 0) {
		out("checkctx %s: open errno=%d rc=2", label, (int)(-fd));
		return 2;
	}
	size_t clen = strlen(ctx);
	long w = sys_write(fd, ctx, clen);
	int e = w < 0 ? (int)(-w) : 0;
	char canon[512];
	long rdn = w == (long)clen ? sys_read(fd, canon, sizeof canon - 1) : 0;
	sys_close(fd);
	if (w != (long)clen) {
		out("checkctx %s: DENIED errno=%d rc=1", label, e);
		return 1;
	}
	if (rdn < 0) {
		out("checkctx %s: write ok, read-back errno=%d rc=1", label, (int)(-rdn));
		return 1;
	}
	if ((size_t)rdn < sizeof canon)
		canon[rdn] = 0;
	out("checkctx %s: ACCEPT canon=%s", label, canon);
	return 0;
}

/* ---------------- main ---------------- */

static int probe_run(int argc, char **argv)
{
	/* "out <path> <sub> ...": the probe opens the output file itself and
	 * dups it over stdout so the caller-shell never needs a write face
	 * on the probe type; the shell reads the file back afterwards */
	if (argc >= 3 && strcmp(argv[1], "out") == 0) {
		int ofd = (int)sys_open(argv[2], O_WRONLY | O_CREAT | O_TRUNC);
		if (ofd < 0) {
			out("out: open errno=%d", (int)-ofd);
			return 2;
		}
		if (sys_dup2(ofd, 1) < 0) {
			out("out: dup2 errno=%d", (int)-sys_dup2(ofd, 1));
			return 2;
		}
		sys_close(ofd);
		argv += 2;
		argc -= 2;
	}
	if (argc < 2) {
		out("usage: probe [checkctx <path> <ctx> <label> | policyinfo | constrain <class> | roletype <type>] | selfctx");
		return 64;
	}
	if (strcmp(argv[1], "checkctx") == 0) {
		if (argc < 5) {
			out("checkctx needs path ctx label");
			return 64;
		}
		return checkctx_once(argv[2], argv[3], argv[4]);
	}
	if (strcmp(argv[1], "selfctx") == 0) {
		char buf[256];
		int sfd = (int)sys_open("/proc/self/attr/current", O_RDONLY);
		if (sfd < 0) {
			out("selfctx: open errno=%d", (int)-sfd);
			return 2;
		}
		long n = sys_read(sfd, buf, sizeof buf - 1);
		sys_close(sfd);
		if (n <= 0) {
			out("selfctx: read errno=%d", (int)-n);
			return 2;
		}
		while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == 0))
			n--;
		buf[n] = 0;
		out("%s", buf);
		return 0;
	}
#ifdef MNB39_POLICY_PATH_OVERRIDE
	const char *ppath = MNB39_POLICY_PATH_OVERRIDE;
	const char *penv = 0;
	(void)penv;
#else
	const char *ppath = "/sys/fs/selinux/policy";
#endif
	g_target_class = 0;
	if (strcmp(argv[1], "policyinfo") == 0) {
		;
	} else if (strcmp(argv[1], "constrain") == 0) {
		if (argc < 3) {
			out("constrain needs a class name");
			return 64;
		}
		g_target_class = argv[2];
	} else if (strcmp(argv[1], "roletype") == 0) {
		if (argc < 3) {
			out("roletype needs a type name");
			return 64;
		}
	} else {
		out("unknown subcommand %s", argv[1]);
		return 64;
	}
	load_policy(ppath);
	if (strcmp(argv[1], "policyinfo") == 0) {
		out("policyinfo: classes=%u", nclasses);
		return 0;
	}
	if (strcmp(argv[1], "roletype") == 0) {
		uint32_t bit = 0xffffffffu;
		for (uint32_t t = 0; t < MAXTYPES; t++)
			if (types_names[t] && strcmp(types_names[t], argv[2]) == 0)
				bit = t;
		if (bit == 0xffffffffu) {
			out("roletype: type %s not found in the loaded policy", argv[2]);
			return 4;
		}
		for (uint32_t v = 0; v < MAXTYPES; v++) {
			struct bitlist *bl = roles_types[v];
			if (!roles_names[v] || !bl)
				continue;
			for (uint32_t b = 0; b < bl->n; b++) {
				if (bl->bits[b] == bit) {
					out("%s", roles_names[v]);
					break;
				}
				if (bl->bits[b] > bit)
					break;
			}
		}
		return 0;
	}
	/* constrain */
	if (!g_target) {
		out("constrain: class %s not found in the loaded policy", g_target_class);
		return 4;
	}
	constrain_emit(g_target);
	return 0;
}

int probe_main(int argc, char **argv) __attribute__((noreturn));
int probe_main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "TRACE") == 0) {
		trace_enabled = 1;
		argv++;
		argc--;
	}
	arena_init();
	int rc = probe_run(argc, argv);
	sys_exit_group(rc);
}

void _start(void) __attribute__((naked, noreturn));
void _start(void)
{
	__asm__ volatile ("mov (%rsp), %rdi\n"
			  "lea 8(%rsp), %rsi\n"
			  "call probe_main\n"
			  "mov $60, %eax\n"
			  "syscall\n"
			  "mov $60, %eax\n"
			  "syscall\n");
}
