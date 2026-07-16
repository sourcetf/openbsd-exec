// exec.c - OpenBSD pledge/unveil launcher (self-restricting)
// Build: cc -O2 -o exec exec.c -Wall -Wextra
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <ctype.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#define MAX_UNVEIL 64
#define MAX_ARGS 64
#define ARG_LEN 4096
#define MAX_STARTER_NAME_LEN 256
#define MAX_PLEDGES_LEN 4096
#define MAX_UNVEIL_STR_LEN 65536
#define MAX_CREATION_CMD_LEN 8192

struct unveil_pair {
	char path[4096];
	char perms[8];
};

struct pledge_info {
	const char *name;
	const char *desc;
	int selected;
};

/* Signal-safe flag for terminal restoration */
static volatile sig_atomic_t sig_received = 0;
static volatile sig_atomic_t winch_flag = 0;

static struct termios orig_termios;
static int raw_mode_enabled = 0;

/* TUI input error message (shown in draw_unveil / draw_command) */
static char input_error[256] = "";

static void
usage(const char *prog)
{
	if (prog == NULL)
		prog = "exec";
	const char *base = strrchr(prog, '/');
	if (base == NULL) {
		base = prog;
	} else {
		base++;
		if (*base == '\0')	/* trailing slash */
			base = "exec";
	}

	fprintf(stderr,
	    "Usage: %s pledge1,pledge2,... /unveil-dir1[:perms],... [--] command [args...]\n"
	    "       %s pledge1,pledge2,... /unveil-dir1[:perms],...   (uses EXEC_CMD env or /bin/sh)\n"
	    "       %s --make-starter starter_name pledges unveil [--] command [args...]\n"
	    "         (creates a self-contained starter binary with fixed args)\n"
	    "       %s --menuconfig\n"
	    "         (interactive TUI to configure and run)\n"
	    "       %s --version\n"
	    "         (show version information)\n\n",
	    base, base, base, base, base);

	fprintf(stderr,
	    "Available pledges and their purposes:\n"
	    "  stdio      Basic I/O, memory, timers, pipes, socketpair.\n"
	    "             Most programs need this. Includes read/write/\n"
	    "             mmap/close/dup/pipe/poll/select/sigaction etc.\n"
	    "  rpath      Read paths, stat files, open read-only.\n"
	    "  wpath      Write paths, open for writing.\n"
	    "  cpath      Create and delete files/directories.\n"
	    "  dpath      Create special files (mkfifo, mknod).\n"
	    "  inet       TCP/IPv4 and IPv6 sockets (web servers, clients).\n"
	    "  mcast      Multicast socket options (requires inet).\n"
	    "  unix       UNIX domain sockets.\n"
	    "  dns        DNS resolution (reads /etc/resolv.conf, /etc/hosts).\n"
	    "  fattr      Change file attributes (chmod, chflags, utimes).\n"
	    "  chown      Change file ownership.\n"
	    "  flock      File locking (fcntl, flock, lockf).\n"
	    "  getpw      Read user/group databases (/etc/passwd, /etc/group).\n"
	    "  sendfd     Send file descriptors via sendmsg(2).\n"
	    "  recvfd     Receive file descriptors via recvmsg(2).\n"
	    "  tape       Tape drive ioctl operations.\n"
	    "  tty        Terminal device operations (/dev/tty, TTY ioctls).\n"
	    "  proc       Process creation (fork, vfork, kill, setpriority).\n"
	    "  exec       Execute programs (execve). Needs proc for fork+exec.\n"
	    "  prot_exec  Executable memory mappings (PROT_EXEC).\n"
	    "  settime    Set system time (settimeofday, adjtime).\n"
	    "  ps         Inspect other processes (sysctl for ps(1)).\n"
	    "  vminfo     Inspect virtual memory (sysctl for top, vmstat).\n"
	    "  id         Change process identity (setuid, setgid, setgroups).\n"
	    "  pf         Packet Filter (pf) ioctl operations.\n"
	    "  route      Read routing table.\n"
	    "  wroute     Modify routing table.\n"
	    "  audio      Audio device ioctl operations.\n"
	    "  video      Video (V4L) device ioctl operations.\n"
	    "  bpf        BPF device statistics.\n"
	    "  disklabel  Disk label ioctl operations.\n"
	    "  drm        DRM device ioctl operations.\n"
	    "  vmm        VMM (hypervisor) ioctl operations.\n"
	    "  unveil     Allow calling unveil(2). REQUIRED if unveil dirs given.\n"
	    "  error      Return ENOSYS on violations instead of SIGABRT.\n"
	    "             Useful for debugging pledge requirements.\n\n");

	fprintf(stderr,
	    "Unveil permissions (default: r):\n"
	    "  r          Read access\n"
	    "  w          Write access\n"
	    "  x          Execute access\n"
	    "  c          Create and delete\n\n");

	fprintf(stderr,
	    "Unveil path quoting:\n"
	    "  If a path contains ':' use double quotes around it.\n"
	    "  Use \\X to escape any character X inside quoted paths.\n"
	    "  Example: \"/tmp/my\\\"dir\":rwc,/other/dir:rx\n"
	    "  Empty unveil list (\"\") means pledge-only, no unveil.\n\n");

	fprintf(stderr, "Common usage examples:\n\n");

	fprintf(stderr,
	    "  # Static web server (e.g., darkhttpd, nginx static)\n"
	    "  %s stdio,rpath,inet /var/www/htdocs:r -- ./darkhttpd /var/www/htdocs\n\n",
	    base);

	fprintf(stderr,
	    "  # CGI/FastCGI web server (needs child process support)\n"
	    "  %s stdio,rpath,wpath,cpath,inet,proc,exec,unveil \\\n"
	    "      /var/www/htdocs:r,/var/tmp:rwc,/usr/local/bin:rx -- ./nginx\n\n",
	    base);

	fprintf(stderr,
	    "  # Reverse proxy / load balancer\n"
	    "  %s stdio,inet,unix,dns /etc:r -- ./relayd\n\n",
	    base);

	fprintf(stderr,
	    "  # File server (read-only)\n"
	    "  %s stdio,rpath,inet /srv/files:r -- ./ftpd\n\n",
	    base);

	fprintf(stderr,
	    "  # Log writer / log aggregator\n"
	    "  %s stdio,wpath,cpath /var/log:rwc -- ./mylogger\n\n",
	    base);

	fprintf(stderr,
	    "  # DNS client resolver (e.g., drill, dig)\n"
	    "  %s stdio,inet,dns /etc:r -- /usr/bin/drill\n\n",
	    base);

	fprintf(stderr,
	    "  # Shell script runner (minimal)\n"
	    "  %s stdio,rpath,exec /bin:rx,/usr/bin:rx -- /bin/sh script.sh\n\n",
	    base);

	fprintf(stderr,
	    "  # Database server (e.g., SQLite, PostgreSQL)\n"
	    "  %s stdio,rpath,wpath,cpath,inet /var/db:rwc -- ./postgres\n\n",
	    base);

	fprintf(stderr,
	    "  # Mail server (SMTP, e.g., OpenSMTPD)\n"
	    "  %s stdio,rpath,wpath,cpath,inet,dns,getpw \\\n"
	    "      /var/mail:rwc,/etc:r -- /usr/sbin/smtpd\n\n",
	    base);

	fprintf(stderr,
	    "  # SSH server (OpenSSH, very restricted)\n"
	    "  %s stdio,rpath,wpath,cpath,inet,unix,getpw,proc,exec,tty \\\n"
	    "      /etc:r,/var/empty:r,/usr/bin:rx -- /usr/sbin/sshd\n\n",
	    base);

	fprintf(stderr,
	    "  # Path with colon, using quotes\n"
	    "  %s stdio,rpath,wpath \\\n"
	    "      \"/tmp/my:dir\":rwc,/var/log:rwc -- ./myapp\n\n",
	    base);

	fprintf(stderr,
	    "  # Path with literal quote, using escape\n"
	    "  %s stdio,rpath \\\n"
	    "      \"/tmp/my\\\"dir\":rwc -- ./myapp\n\n",
	    base);

	fprintf(stderr,
	    "  # Create a self-contained starter binary\n"
	    "  %s --make-starter webd stdio,rpath,inet /var/www/htdocs:r -- ./darkhttpd /var/www/htdocs\n"
	    "  # Then run: ./webd\n"
	    "  # And:      ./webd --help   (shows creation parameters)\n\n",
	    base);

	fprintf(stderr,
	    "  # Interactive configuration\n"
	    "  %s --menuconfig\n\n",
	    base);

	fprintf(stderr,
	    "  # Pledge only, no unveil (pass empty string)\n"
	    "  %s stdio,rpath,inet \"\" -- ./myapp\n\n",
	    base);

	fprintf(stderr,
	    "  # Debug mode: find missing pledges without crashing\n"
	    "  %s stdio,rpath,error /var/www:r -- ./myserver\n\n",
	    base);

	fprintf(stderr,
	    "Notes:\n"
	    "  - The 'unveil' promise is auto-added if unveil dirs are specified.\n"
	    "  - Use 'error' pledge to debug: violations return ENOSYS not SIGABRT.\n"
	    "  - Check /var/log/messages for pledge violations when using 'error'.\n"
	    "  - Always use the minimum set of pledges needed for your application.\n"
	    "  - 'exec' promise is required in pledge list to run a program.\n"
	    "  - --make-starter uses mkstemp() for temporary files to prevent TOCTOU.\n"
	    "  - Ensure PATH is trusted when using --make-starter (uses 'cc' from PATH).\n");
	exit(1);
}

static int
is_whitespace(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/*
 * Copy input to output, converting commas to spaces.
 * outsize must be >= strlen(input) + 1.
 * Returns 0 on success, -1 if output buffer too small.
 */
static int
parse_pledges(const char *input, char *out, size_t outsize)
{
	if (input == NULL || out == NULL)
		return -1;
	size_t len = strlen(input);
	if (len + 1 > outsize)
		return -1;
	memmove(out, input, len + 1);
	for (char *p = out; *p; p++) {
		if (*p == ',')
			*p = ' ';
	}
	return 0;
}

static int
is_valid_perm(char c)
{
	return c == 'r' || c == 'w' || c == 'x' || c == 'c';
}

/*
 * Word match using strstr with boundary checks.
 * Assumes space-separated words (parse_pledges converts commas to spaces).
 * Handles multiple consecutive spaces correctly.
 */
static int
has_word(const char *haystack, const char *needle)
{
	const char *p = haystack;
	size_t nlen = strlen(needle);
	if (nlen == 0)
		return 0;

	while ((p = strstr(p, needle)) != NULL) {
		int left_ok = (p == haystack) || is_whitespace(*(p - 1));
		int right_ok = (p[nlen] == '\0') || is_whitespace(p[nlen]);
		if (left_ok && right_ok)
			return 1;
		p += nlen;
	}
	return 0;
}

static size_t
parse_unveil_one(const char *input, char *path, size_t pathsize,
    char *perms_buf, size_t perms_size)
{
	const char *p = input;
	const char *path_start;
	const char *path_end;

	if (perms_size < 2)
		errx(1, "parse_unveil_one: perms_size too small (need at least 2)");

	strlcpy(perms_buf, "r", perms_size);

	while (is_whitespace(*p))
		p++;

	if (*p == '\0')
		return 0;

	/* Skip empty entries (e.g., consecutive commas) */
	if (*p == ',') {
		return 1; /* consumed just the comma, caller will skip it */
	}

	if (*p == '"') {
		p++;
		path_start = p;
		while (*p && *p != '"') {
			if (*p == '\\' && *(p + 1)) {
				p += 2;
			} else {
				p++;
			}
		}
		if (*p != '"')
			errx(1, "unveil: unterminated quote in path");
		path_end = p;
		p++;

		if (*p == ':') {
			p++;
			size_t perms_len = 0;
			memset(perms_buf, 0, perms_size);
			while (*p && !is_whitespace(*p) && *p != ',' &&
			    perms_len < perms_size - 1) {
				if (!is_valid_perm(*p))
					errx(1, "unveil: invalid permission '%c'", *p);
				if (strchr(perms_buf, *p)) {
					p++;
					continue;
				}
				if (perms_len >= 4)
					errx(1, "unveil: too many permissions (max 4: rwxc)");
				perms_buf[perms_len++] = *p;
				p++;
			}
			perms_buf[perms_len] = '\0';
			if (perms_len == 0)
				errx(1, "unveil: empty permissions after colon");
		}
	} else {
		path_start = p;
		const char *last_colon = NULL;
		while (*p && !is_whitespace(*p) && *p != ',') {
			if (*p == ':')
				last_colon = p;
			p++;
		}
		path_end = p;

		if (last_colon != NULL) {
			const char *perm_start = last_colon + 1;
			size_t perm_len = path_end - perm_start;
			if (perm_len == 0)
				errx(1, "unveil: unquoted path contains ':' with empty permissions; use double quotes for paths containing ':'");
			for (size_t i = 0; i < perm_len; i++) {
				if (!is_valid_perm(perm_start[i]))
					errx(1, "unveil: unquoted path contains ':'; use double quotes for paths containing ':'");
			}
			size_t j = 0;
			memset(perms_buf, 0, perms_size);
			for (size_t i = 0; i < perm_len && j < perms_size - 1; i++) {
				if (strchr(perms_buf, perm_start[i]))
					continue;
				if (j >= 4)
					errx(1, "unveil: too many permissions (max 4: rwxc)");
				perms_buf[j++] = perm_start[i];
			}
			perms_buf[j] = '\0';
			if (j == 0)
				errx(1, "unveil: empty permissions after colon");
			path_end = last_colon;
		}
	}

	while (is_whitespace(*p))
		p++;

	size_t raw_len = path_end - path_start;
	if (raw_len == 0)
		errx(1, "unveil: empty path");

	/* Compute escaped length first, then validate */
	size_t escaped_len = 0;
	for (size_t i = 0; i < raw_len; i++) {
		if (path_start[i] == '\\' && i + 1 < raw_len) {
			escaped_len++;
			i++;
		} else {
			escaped_len++;
		}
	}
	if (escaped_len >= pathsize)
		errx(1, "unveil: path too long");

	size_t j = 0;
	for (size_t i = 0; i < raw_len; i++) {
		if (path_start[i] == '\\' && i + 1 < raw_len) {
			path[j++] = path_start[i + 1];
			i++;
		} else {
			path[j++] = path_start[i];
		}
	}
	path[j] = '\0';

	return p - input;
}

static int
parse_unveil(const char *input)
{
	const char *p = input;
	int count = 0;
	char path[4096];
	char perms_buf[8];

	while (*p) {
		if (count >= MAX_UNVEIL)
			errx(1, "unveil: too many paths (max %d)", MAX_UNVEIL);

		size_t consumed = parse_unveil_one(p, path, sizeof(path),
		    perms_buf, sizeof(perms_buf));
		if (consumed == 0)
			break;

		/* Skip empty entries (consumed just a comma) */
		if (consumed == 1 && *p == ',') {
			p += consumed;
			continue;
		}

		if (unveil(path, perms_buf) == -1)
			err(1, "unveil(\"%s\", \"%s\")", path, perms_buf);

		p += consumed;
		count++;

		if (*p == ',')
			p++;
	}

	return count;
}

static int
parse_unveil_to_pairs(const char *input, struct unveil_pair *pairs, int max_pairs)
{
	const char *p = input;
	int count = 0;
	char path[4096];
	char perms_buf[8];

	while (*p) {
		if (count >= max_pairs)
			errx(1, "unveil: too many paths (max %d)", max_pairs);

		size_t consumed = parse_unveil_one(p, path, sizeof(path),
		    perms_buf, sizeof(perms_buf));
		if (consumed == 0)
			break;

		/* Skip empty entries */
		if (consumed == 1 && *p == ',') {
			p += consumed;
			continue;
		}

		strlcpy(pairs[count].path, path, sizeof(pairs[count].path));
		strlcpy(pairs[count].perms, perms_buf, sizeof(pairs[count].perms));
		count++;

		p += consumed;
		if (*p == ',')
			p++;
	}

	return count;
}

/*
 * Escape a string for use as a C string literal.
 * Escapes \, ", and rejects control characters that would break the literal.
 * dstsize must be large enough (at least 2*strlen(src)+1).
 */
static void
c_escape(const char *src, char *dst, size_t dstsize)
{
	if (dstsize == 0)
		errx(1, "c_escape: destination buffer size cannot be zero");
	size_t j = 0;
	for (size_t i = 0; src[i]; i++) {
		unsigned char c = (unsigned char)src[i];
		/* Reject control characters that cannot appear in string literals */
		if (c < 0x20 || c == 0x7f) {
			errx(1, "c_escape: control character 0x%02x in string, cannot embed in C literal", c);
		}
		int need_escape = (c == '\\' || c == '"');
		if (j + need_escape + 1 >= dstsize)
			errx(1, "c_escape: destination buffer too small for escaped string");
		if (need_escape)
			dst[j++] = '\\';
		dst[j++] = (char)c;
	}
	dst[j] = '\0';
}

/*
 * Validate starter_name: only [-_.a-zA-Z0-9] allowed, non-empty,
 * and length limited to prevent mkstemp template truncation.
 */
static int
is_valid_starter_name(const char *name)
{
	if (name == NULL || name[0] == '\0')
		return 0;
	for (size_t i = 0; name[i]; i++) {
		char c = name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
			return 0;
	}
	return 1;
}

/*
 * Check if current directory is safe for creating temporary files.
 * Returns 1 if safe (owned by current user, not group/world writable),
 * 0 otherwise.
 */
static int
is_safe_cwd(void)
{
	struct stat st;
	if (stat(".", &st) == -1)
		return 0;
	if (st.st_uid != getuid())
		return 0;
	if (st.st_mode & (S_IWGRP | S_IWOTH))
		return 0;
	return 1;
}

/*
 * Append a path string to dst with C-string escaping for " and \.
 * Returns 1 on success, 0 if truncated.
 */
static int
append_escaped_path(char *dst, size_t dstsize, const char *path)
{
	if (dstsize == 0)
		return 0;
	for (size_t k = 0; path[k]; k++) {
		char tmp[3];
		if (path[k] == '"' || path[k] == '\\') {
			tmp[0] = '\\';
			tmp[1] = path[k];
			tmp[2] = '\0';
		} else {
			tmp[0] = path[k];
			tmp[1] = '\0';
		}
		if (strlcat(dst, tmp, dstsize) >= dstsize)
			return 0;
	}
	return 1;
}

/*
 * Check if a string needs shell-style quoting (contains whitespace,
 * quotes, or backslashes).
 */
static int
str_needs_quoting(const char *s)
{
	for (size_t i = 0; s[i]; i++) {
		char c = s[i];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
		    c == '"' || c == '\\')
			return 1;
	}
	return 0;
}

/*
 * Validate that all pledge names in a comma-separated list are known.
 * Returns 1 if all valid or if unknown (warned and passed to kernel).
 * Returns 0 only on parse/format errors.
 */
static int
is_valid_pledge_list(const char *pledges)
{
	/* Known pledge names, must match OpenBSD 7.5 */
	static const char *valid_pledges[] = {
		"stdio", "rpath", "wpath", "cpath", "dpath",
		"inet", "mcast", "unix", "dns", "fattr",
		"chown", "flock", "getpw", "sendfd", "recvfd",
		"tape", "tty", "proc", "exec", "prot_exec",
		"settime", "ps", "vminfo", "id", "pf",
		"route", "wroute", "audio", "video", "bpf",
		"disklabel", "drm", "vmm", "unveil", "error",
		NULL
	};

	char tmp[MAX_PLEDGES_LEN];
	if (parse_pledges(pledges, tmp, sizeof(tmp)) == -1)
		return 0;

	const char *p = tmp;
	while (*p) {
		while (is_whitespace(*p))
			p++;
		if (*p == '\0')
			break;

		const char *start = p;
		while (*p && !is_whitespace(*p))
			p++;
		size_t len = p - start;

		int found = 0;
		for (int i = 0; valid_pledges[i] != NULL; i++) {
			if (strlen(valid_pledges[i]) == len &&
			    strncmp(start, valid_pledges[i], len) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "warning: unknown pledge '%.*s' (will be validated by kernel)\n",
			    (int)len, start);
			/* Do not return 0; let the kernel validate for forward compatibility */
		}
	}
	return 1;
}

/*
 * Restore terminal to original state. Safe to call multiple times.
 */
static void
safe_disable_raw_mode(void)
{
	if (raw_mode_enabled) {
		tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
		raw_mode_enabled = 0;
	}
}

static void
make_starter(const char *starter_name, const char *pledges_raw,
    const char *unveil_raw, int cmd_argc, char **cmd_argv,
    const char *creation_cmd, const char *prog_name)
{
	static struct unveil_pair pairs[MAX_UNVEIL];
	int npairs = 0;

	if (!is_valid_starter_name(starter_name))
		errx(1, "invalid starter name '%s': must be non-empty and only contain [-_.a-zA-Z0-9]", starter_name);
	if (strlen(starter_name) > MAX_STARTER_NAME_LEN)
		errx(1, "starter name too long (max %d characters)", MAX_STARTER_NAME_LEN);

	if (!is_safe_cwd())
		errx(1, "current directory is not safe for --make-starter "
		    "(must be owned by you and not group/world writable)");

	if (access(starter_name, F_OK) == 0)
		errx(1, "starter '%s' already exists; remove it first", starter_name);

	if (!is_valid_pledge_list(pledges_raw))
		errx(1, "invalid pledge name in '%s'", pledges_raw);

	if (strlen(unveil_raw) > 0 && strcmp(unveil_raw, "\"\"") != 0)
		npairs = parse_unveil_to_pairs(unveil_raw, pairs, MAX_UNVEIL);

	/* Pre-process pledges: commas to spaces, auto-add unveil if needed */
	char pledges[MAX_PLEDGES_LEN];
	if (parse_pledges(pledges_raw, pledges, sizeof(pledges)) == -1)
		errx(1, "pledges string too long (max %zu bytes)", sizeof(pledges) - 1);

	if (strcmp(unveil_raw, "") != 0 && strcmp(unveil_raw, "\"\"") != 0 && !has_word(pledges, "unveil")) {
		size_t plen = strlen(pledges);
		if (plen + 8 > sizeof(pledges))
			errx(1, "pledges string too long to auto-append 'unveil'");
		snprintf(pledges + plen, sizeof(pledges) - plen, " unveil");
	}

	/*
	 * Use mkstemp for safe temporary file creation.
	 * Compile with -x c to force C language mode regardless of file suffix.
	 * Use execlp("cc", ...) which searches PATH for the compiler.
	 * The caller is responsible for ensuring PATH is trusted.
	 */
	char src_path[4096];
	snprintf(src_path, sizeof(src_path), "%s.XXXXXX", starter_name);
	int fd = mkstemp(src_path);
	if (fd == -1)
		err(1, "mkstemp");

	FILE *fp = fdopen(fd, "w");
	if (!fp) {
		close(fd);
		unlink(src_path);
		err(1, "fdopen");
	}

	char buf[16384];

	/* Header */
	fprintf(fp, "/* Auto-generated starter by exec.c */\n");
	fprintf(fp, "/* Do not edit manually. Regenerate with exec.c --make-starter. */\n");
	fprintf(fp, "#include <stdio.h>\n");
	fprintf(fp, "#include <stdlib.h>\n");
	fprintf(fp, "#include <string.h>\n");
	fprintf(fp, "#include <unistd.h>\n");
	fprintf(fp, "#include <err.h>\n\n");

	/* Hardcoded strings - pledge string is pre-validated and space-separated */
	c_escape(creation_cmd, buf, sizeof(buf));
	fprintf(fp, "static const char *creation_cmd = \"%s\";\n", buf);
	c_escape(pledges, buf, sizeof(buf));
	fprintf(fp, "static const char *pledges = \"%s\";\n", buf);

	/* usage() - ALL format strings use %%s with parameters, never embed user data */
	fprintf(fp, "\nstatic void\n");
	fprintf(fp, "usage(const char *prog)\n");
	fprintf(fp, "{\n");
	fprintf(fp, "    fprintf(stderr, \"Auto-generated starter.\\n\");\n");
	fprintf(fp, "    fprintf(stderr, \"Created by: %%s\\n\", creation_cmd);\n");
	fprintf(fp, "    fprintf(stderr, \"Usage: %%s [--help]\\n\", prog);\n");
	fprintf(fp, "    fprintf(stderr, \"\\n\");\n");
	fprintf(fp, "    fprintf(stderr, \"Pledges: %%s\\n\", pledges);\n");
	c_escape(unveil_raw, buf, sizeof(buf));
	fprintf(fp, "    fprintf(stderr, \"Unveil:  %%s\\n\", \"%s\");\n", buf);
	/* Command: use %%s placeholders, then pass each arg as parameter */
	fprintf(fp, "    fprintf(stderr, \"Command:");
	for (int i = 0; i < cmd_argc; i++)
		fprintf(fp, " %%s");
	fprintf(fp, "\\n\"");
	for (int i = 0; i < cmd_argc; i++) {
		c_escape(cmd_argv[i], buf, sizeof(buf));
		fprintf(fp, ", \"%s\"", buf);
	}
	fprintf(fp, ");\n");
	fprintf(fp, "    fprintf(stderr, \"\\n\");\n");
	fprintf(fp, "    fprintf(stderr, \"This starter is self-contained and does not depend on exec.c.\\n\");\n");
	fprintf(fp, "    exit(1);\n");
	fprintf(fp, "}\n\n");

	/* is_whitespace (same implementation as exec.c) */
	fprintf(fp, "static int is_whitespace(char c)\n");
	fprintf(fp, "{\n");
	fprintf(fp, "    return c == ' ' || c == '\\t' || c == '\\n' || c == '\\r' || c == '\\f' || c == '\\v';\n");
	fprintf(fp, "}\n\n");

	/* has_word (same implementation as exec.c) */
	fprintf(fp, "static int has_word(const char *haystack, const char *needle)\n");
	fprintf(fp, "{\n");
	fprintf(fp, "    const char *p = haystack;\n");
	fprintf(fp, "    size_t nlen = strlen(needle);\n");
	fprintf(fp, "    if (nlen == 0) return 0;\n");
	fprintf(fp, "    while ((p = strstr(p, needle)) != NULL) {\n");
	fprintf(fp, "        int left_ok = (p == haystack) || is_whitespace(*(p - 1));\n");
	fprintf(fp, "        int right_ok = (p[nlen] == '\\0') || is_whitespace(p[nlen]);\n");
	fprintf(fp, "        if (left_ok && right_ok) return 1;\n");
	fprintf(fp, "        p += nlen;\n");
	fprintf(fp, "    }\n");
	fprintf(fp, "    return 0;\n");
	fprintf(fp, "}\n\n");

	/* main() */
	fprintf(fp, "int\nmain(int argc, char *argv[])\n");
	fprintf(fp, "{\n");
	fprintf(fp, "    if (argc >= 2 && (strcmp(argv[1], \"--help\") == 0 ||\n");
	fprintf(fp, "                      strcmp(argv[1], \"-h\") == 0))\n");
	fprintf(fp, "        usage(argv[0]);\n\n");
	fprintf(fp, "    if (!has_word(pledges, \"exec\"))\n");
	fprintf(fp, "        errx(1, \"pledges must include 'exec' to run a program\");\n\n");

	/* unveil calls - only if paths were configured */
	if (npairs > 0) {
		for (int i = 0; i < npairs; i++) {
			c_escape(pairs[i].path, buf, sizeof(buf));
			fprintf(fp, "    if (unveil(\"%s\", \"%s\") == -1)\n", buf, pairs[i].perms);
			fprintf(fp, "        err(1, \"unveil(\\\"%%s\\\", \\\"%%s\\\")\", \"%s\", \"%s\");\n",
			    buf, pairs[i].perms);
		}
		fprintf(fp, "    if (unveil(NULL, NULL) == -1)\n");
		fprintf(fp, "        err(1, \"unveil(NULL, NULL)\");\n\n");
	}

	/* pledge */
	fprintf(fp, "    if (pledge(pledges, pledges) == -1)\n");
	fprintf(fp, "        err(1, \"pledge(\\\"%%s\\\", \\\"%%s\\\")\", pledges, pledges);\n\n");
	fprintf(fp, "    if (has_word(pledges, \"stdio\")) {\n");
	fprintf(fp, "        if (pledge(\"stdio exec\", pledges) == -1)\n");
	fprintf(fp, "            err(1, \"pledge(\\\"stdio exec\\\", \\\"%%s\\\")\", pledges);\n");
	fprintf(fp, "    } else {\n");
	fprintf(fp, "        if (pledge(\"exec\", pledges) == -1)\n");
	fprintf(fp, "            err(1, \"pledge(\\\"exec\\\", \\\"%%s\\\")\", pledges);\n");
	fprintf(fp, "    }\n\n");

	/* exec */
	if (cmd_argc > 0) {
		fprintf(fp, "    char *cmd_argv[] = { ");
		for (int i = 0; i < cmd_argc; i++) {
			c_escape(cmd_argv[i], buf, sizeof(buf));
			fprintf(fp, "\"%s\", ", buf);
		}
		fprintf(fp, "NULL };\n");
		fprintf(fp, "    execvp(cmd_argv[0], cmd_argv);\n");
		fprintf(fp, "    err(1, \"execvp %%s\", cmd_argv[0]);\n");
	} else {
		fprintf(fp, "    const char *cmd = getenv(\"EXEC_CMD\");\n");
		fprintf(fp, "    if (!cmd || cmd[0] == '\\0') cmd = \"/bin/sh\";\n");
		fprintf(fp, "    execl(cmd, cmd, (char *)NULL);\n");
		fprintf(fp, "    err(1, \"execl %%s\", cmd);\n");
	}
	fprintf(fp, "    return 1;\n");
	fprintf(fp, "}\n");

	fclose(fp);

	/*
	 * Compile using fork/exec instead of system() to prevent injection.
	 * Use -x c to force C language mode regardless of file suffix.
	 * Use execlp("cc", ...) which searches PATH for the compiler.
	 * The caller is responsible for ensuring PATH is trusted.
	 */
	/*
	 * Compile to a temporary output file first, then atomically rename.
	 * This eliminates the TOCTOU window between access() and creation.
	 */
	char out_tmp[4096];
	snprintf(out_tmp, sizeof(out_tmp), "%s.out.XXXXXX", starter_name);
	int out_fd = mkstemp(out_tmp);
	if (out_fd == -1) {
		unlink(src_path);
		err(1, "mkstemp for output file");
	}
	close(out_fd);
	
	pid_t pid = fork();
	if (pid == -1) {
		unlink(src_path);
		unlink(out_tmp);
		err(1, "fork");
	}
	if (pid == 0) {
		execlp("cc", "cc", "-O2", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
		    "-fPIE", "-pie", "-Wl,-z,relro", "-Wl,-z,now",
		    "-x", "c", "-o", out_tmp, src_path,
		    "-Wall", "-Wextra", (char *)NULL);
		err(1, "execlp cc");
	}
	int status;
	for (;;) {
		if (waitpid(pid, &status, 0) == -1) {
			if (errno == EINTR)
				continue;
			unlink(src_path);
			unlink(out_tmp);
			err(1, "waitpid");
		}
		break;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		unlink(out_tmp);
		errx(1, "compilation of %s failed (cc exited %d). Source retained at %s for inspection.",
		    starter_name, exit_status, src_path);
	}

	unlink(src_path);
	if (rename(out_tmp, starter_name) == -1) {
		unlink(out_tmp);
		err(1, "rename %s to %s", out_tmp, starter_name);
	}

	printf("Starter created: ./%s\n", starter_name);
}

/* ======================================================================== */
/* --menuconfig TUI implementation                                          */
/* ======================================================================== */

#define KEY_UP    1000
#define KEY_DOWN  1001
#define KEY_LEFT  1002
#define KEY_RIGHT 1003
#define KEY_ENTER 13
#define KEY_ESC   27
#define KEY_SPACE 32
#define KEY_Q     113
#define KEY_D     100
#define KEY_A     97
#define KEY_BACKSPACE 127
#define KEY_EOF   -1

/*
 * Signal handlers: ONLY set flags, NEVER call non-async-signal-safe
 * Terminal restoration is handled by atexit or main loop.
 */
static void
sig_handler(int sig)
{
	if (sig == SIGWINCH) {
		winch_flag = 1;
	} else {
		sig_received = sig;
	}
}

/*
 * Fatal signal handler: use only async-signal-safe operations.
 * Do NOT call tcsetattr, sigaction, or other non-safe functions.
 * Terminal may remain in raw mode; user can run 'stty sane' to recover.
 */
static void
sig_fatal(int sig)
{
	const char msg[] = "Fatal signal caught. Run 'stty sane' if terminal is garbled.\n";
	write(STDERR_FILENO, msg, sizeof(msg) - 1);
	_exit(128 + sig);
}

static void
enable_raw_mode(void)
{
	if (raw_mode_enabled)
		return;
	if (tcgetattr(STDIN_FILENO, &orig_termios) == -1)
		err(1, "tcgetattr");
	raw_mode_enabled = 1;
	atexit(safe_disable_raw_mode);
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = sig_fatal;
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);

	struct sigaction sa_winch;
	memset(&sa_winch, 0, sizeof(sa_winch));
	sa_winch.sa_handler = sig_handler;
	sigemptyset(&sa_winch.sa_mask);
	sa_winch.sa_flags = SA_RESTART;
	sigaction(SIGWINCH, &sa_winch, NULL);

	/* Ignore SIGPIPE to prevent crash on broken pipe */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &sa, NULL);

	struct termios raw = orig_termios;
	raw.c_iflag &= ~(IXON | ICRNL | INPCK | ISTRIP | BRKINT);
	raw.c_oflag &= ~(OPOST);
	raw.c_cflag |= (CS8);
	raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1)
		err(1, "tcsetattr");
}

/*
 * read_key: Read a single keypress from stdin.
 *
 * With VMIN=1, VTIME=0, read() blocks until at least one byte is available.
 * For ESC sequences, we use a short select() timeout to detect incomplete
 * sequences without blocking forever.
 */
static int
read_key(void)
{
	unsigned char c;   // ← 改为 unsigned，范围 0–255
	int nread;
	while ((nread = read(STDIN_FILENO, &c, 1)) != 1) {
		if (nread == 0)
			return KEY_EOF;
		if (nread == -1 && errno == EAGAIN) {
			usleep(10000);
			continue;
		}
		if (nread == -1 && errno == EINTR) {
			continue;
		}
		if (nread == -1)
			err(1, "read");
	}

	if (c == '\x1b') {
		fd_set rfds;
		struct timeval tv;
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = 100000;	/* 100ms timeout for ESC sequence */

		char seq[3];
		int ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
		if (ret == -1 && errno == EINTR) {
			/* Signal interrupted select, check if we should exit */
			if (sig_received)
				return KEY_Q;  /* Force quit on signal */
			return KEY_ESC;
		}
		if (ret <= 0)
			return KEY_ESC;
		if (read(STDIN_FILENO, &seq[0], 1) != 1)
			return KEY_ESC;

		tv.tv_usec = 100000;
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
		if (ret == -1 && errno == EINTR) {
			if (sig_received)
				return KEY_Q;
			return KEY_ESC;
		}
		if (ret <= 0)
			return KEY_ESC;
		if (read(STDIN_FILENO, &seq[1], 1) != 1)
			return KEY_ESC;

		if (seq[0] == '[') {
			switch (seq[1]) {
			case 'A': return KEY_UP;
			case 'B': return KEY_DOWN;
			case 'C': return KEY_RIGHT;
			case 'D': return KEY_LEFT;
			case '3':
				{
					char tilde;
					if (read(STDIN_FILENO, &tilde, 1) == 1 && tilde == '~')
						return KEY_ESC; /* Delete key - ignore */
				}
				return KEY_ESC;
			case '5':
				{
					char tilde;
					if (read(STDIN_FILENO, &tilde, 1) == 1 && tilde == '~')
						return KEY_ESC; /* Page Up - ignore */
				}
				return KEY_ESC;
			case '6':
				{
					char tilde;
					if (read(STDIN_FILENO, &tilde, 1) == 1 && tilde == '~')
						return KEY_ESC; /* Page Down - ignore */
				}
				return KEY_ESC;
			}
		} else if (seq[0] == 'O') {
			/* screen/tmux sends \x1bOA (SS3), \x1bOB, etc. */
			switch (seq[1]) {
			case 'A': return KEY_UP;
			case 'B': return KEY_DOWN;
			case 'C': return KEY_RIGHT;
			case 'D': return KEY_LEFT;
			}
		}
		return KEY_ESC;
	}
	return (int)c;
}

static void
clear_screen(void)
{
	write(STDOUT_FILENO, "\x1b[2J", 4);
	write(STDOUT_FILENO, "\x1b[H", 3);
}

static void
move_cursor(int row, int col)
{
	char buf[32];
	if (row < 1) row = 1;
	if (col < 1) col = 1;
	snprintf(buf, sizeof(buf), "\x1b[%d;%dH", row, col);
	write(STDOUT_FILENO, buf, strlen(buf));
}

static void
hide_cursor(void)
{
	write(STDOUT_FILENO, "\x1b[?25l", 6);
}

static void
show_cursor(void)
{
	write(STDOUT_FILENO, "\x1b[?25h", 6);
}

static int
get_window_size(int *rows, int *cols)
{
	struct winsize ws;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0 || ws.ws_row == 0)
		return -1;
	*cols = ws.ws_col;
	*rows = ws.ws_row;
	return 0;
}

static void
print_line(const char *s)
{
	write(STDOUT_FILENO, s, strlen(s));
}

/*
 * Sanitize a string for safe terminal display by replacing control
 * characters (0x00-0x1F and 0x7F) with '?'. This prevents malicious
 * or accidental terminal escape sequences from corrupting the TUI.
 */
static void
sanitize_for_display(const char *src, char *dst, size_t dstsize)
{
	size_t j = 0;
	if (dstsize == 0)
		return;
	for (size_t i = 0; src[i] && j + 1 < dstsize; i++) {
		unsigned char c = (unsigned char)src[i];
		if (c < 0x20 || c == 0x7f)
			dst[j++] = '?';
		else
			dst[j++] = (char)c;
	}
	dst[j] = '\0';
}

/*
 * In-place variant of sanitize_for_display.
 */
static void
sanitize_for_display_inplace(char *str)
{
	size_t j = 0;
	for (size_t i = 0; str[i]; i++) {
		unsigned char c = (unsigned char)str[i];
		if (c < 0x20 || c == 0x7f)
			str[j++] = '?';
		else
			str[j++] = (char)c;
	}
	str[j] = '\0';
}

/*
 * Pledge names verified against OpenBSD 7.5.
 * Unknown pledges are warned but passed to the kernel for validation,
 * allowing forward compatibility with newer OpenBSD versions.
 * If building/running on a different OpenBSD version, cross-check
 * with man pledge(2) on the target system.
 *
 * TUI defaults: only stdio and exec are selected by default.
 * All other pledges must be explicitly enabled by the user.
 */
static struct pledge_info pledges[] = {
	{"stdio",     "Basic I/O, memory, timers, pipes, socketpair", 1},
	{"rpath",     "Read paths, stat files, open read-only", 0},
	{"wpath",     "Write paths, open for writing", 0},
	{"cpath",     "Create and delete files/directories", 0},
	{"dpath",     "Create special files (mkfifo, mknod)", 0},
	{"inet",      "TCP/IPv4 and IPv6 sockets", 0},
	{"mcast",     "Multicast socket options (requires inet)", 0},
	{"unix",      "UNIX domain sockets", 0},
	{"dns",       "DNS resolution", 0},
	{"fattr",     "Change file attributes (chmod, chflags)", 0},
	{"chown",     "Change file ownership", 0},
	{"flock",     "File locking (fcntl, flock, lockf)", 0},
	{"getpw",     "Read user/group databases", 0},
	{"sendfd",    "Send file descriptors via sendmsg(2)", 0},
	{"recvfd",    "Receive file descriptors via recvmsg(2)", 0},
	{"tape",      "Tape drive ioctl operations", 0},
	{"tty",       "Terminal device operations", 0},
	{"proc",      "Process creation (fork, vfork, kill)", 0},
	{"exec",      "Execute programs (execve) [REQUIRED]", 1},
	{"prot_exec", "Executable memory mappings (PROT_EXEC)", 0},
	{"settime",   "Set system time", 0},
	{"ps",        "Inspect other processes", 0},
	{"vminfo",    "Inspect virtual memory", 0},
	{"id",        "Change process identity", 0},
	{"pf",        "Packet Filter ioctl operations", 0},
	{"route",     "Read routing table", 0},
	{"wroute",    "Modify routing table", 0},
	{"audio",     "Audio device ioctl operations", 0},
	{"video",     "Video (V4L) device ioctl operations", 0},
	{"bpf",       "BPF device statistics", 0},
	{"disklabel", "Disk label ioctl operations", 0},
	{"drm",       "DRM device ioctl operations", 0},
	{"vmm",       "VMM (hypervisor) ioctl operations", 0},
	{"unveil",    "Allow calling unveil(2)", 0},
	{"error",     "Return ENOSYS on violations (debug)", 0},
};
#define N_PLEDGES (sizeof(pledges) / sizeof(pledges[0]))

struct unveil_entry {
	char path[4096];
	int has_r, has_w, has_x, has_c;
};

static struct unveil_entry unveil_entries[MAX_UNVEIL];
static int n_unveil = 0;

static char cmd_path[4096] = "";
static char cmd_args[MAX_ARGS][ARG_LEN];
static int n_cmd_args = 0;

static int menu_tab = 0;
static int pledge_cursor = 0;
static int unveil_cursor = 0;
static int unveil_mode = 0;
static char unveil_input[4096] = "";
static int unveil_input_len = 0;
static int unveil_perm_cursor = 0;
static int cmd_mode = 0;
static char cmd_input[ARG_LEN] = "";
static int cmd_input_len = 0;

static void
draw_frame(int rows, int cols)
{
	char buf[256];
	clear_screen();

	move_cursor(1, 2);
	print_line("\x1b[1mOpenBSD Pledge/Unveil Launcher -- Menuconfig\x1b[0m");

	move_cursor(3, 2);
	const char *tabs[] = {"[Pledges]", "[Unveil]", "[Command]", "[Execute]"};
	for (int i = 0; i < 4; i++) {
		if (i > 0) print_line("  ");
		if (i == menu_tab) {
			snprintf(buf, sizeof(buf), "\x1b[7m %s \x1b[0m", tabs[i]);
		} else {
			snprintf(buf, sizeof(buf), " %s ", tabs[i]);
		}
		print_line(buf);
	}

	move_cursor(4, 2);
	for (int i = 0; i < cols - 4; i++) print_line("-");
}

static void
draw_pledges(int rows, int cols)
{
	char buf[512];
	int start_row = 6;
	int visible = rows - start_row - 2;
	if (visible < 1) visible = 1;
	int start = pledge_cursor - visible / 2;
	if (start < 0) start = 0;
	if (start > (int)N_PLEDGES - visible) start = N_PLEDGES - visible;
	if (start < 0) start = 0;

	for (int i = start; i < (int)N_PLEDGES && i < start + visible; i++) {
		move_cursor(start_row + (i - start), 4);
		const char *mark = pledges[i].selected ? "\x1b[32m[X]\x1b[0m" : "[ ]";
		const char *forced = (strcmp(pledges[i].name, "exec") == 0) ?
		    " \x1b[33m[required]\x1b[0m" : "";
		if (i == pledge_cursor) {
			snprintf(buf, sizeof(buf), "\x1b[7m> %s %s %-12s %s%s\x1b[0m",
			    mark, "", pledges[i].name, pledges[i].desc, forced);
		} else {
			snprintf(buf, sizeof(buf), "  %s %s %-12s %s%s",
			    mark, "", pledges[i].name, pledges[i].desc, forced);
		}
		print_line(buf);
	}

	move_cursor(rows - 1, 2);
	print_line("\x1b[2mSPACE: toggle  ENTER: confirm  <-->: tabs  q: quit\x1b[0m");
}

static void
draw_unveil(int rows, int cols)
{
	char buf[8192];
	int start_row = 6;

	if (unveil_mode == 0) {
		move_cursor(start_row, 4);
		print_line("\x1b[1mConfigured unveil paths:\x1b[0m");

		if (n_unveil == 0) {
			move_cursor(start_row + 2, 6);
			print_line("(none -- press 'a' to add)");
		} else {
			for (int i = 0; i < n_unveil; i++) {
				move_cursor(start_row + 2 + i, 6);
				char perms[8] = "";
				int p = 0;
				if (unveil_entries[i].has_r) perms[p++] = 'r';
				if (unveil_entries[i].has_w) perms[p++] = 'w';
				if (unveil_entries[i].has_x) perms[p++] = 'x';
				if (unveil_entries[i].has_c) perms[p++] = 'c';
				perms[p] = '\0';
				char display_path[sizeof(unveil_entries[i].path)];
				sanitize_for_display(unveil_entries[i].path, display_path, sizeof(display_path));
				if (i == unveil_cursor) {
					snprintf(buf, sizeof(buf), "\x1b[7m> %s:%s\x1b[0m",
					    display_path, perms);
				} else {
					snprintf(buf, sizeof(buf), "  %s:%s",
					    display_path, perms);
				}
				print_line(buf);
			}
		}

		move_cursor(rows - 1, 2);
		print_line("\x1b[2mUP/DOWN: move  a: add  d: delete  <-->: tabs  q: quit\x1b[0m");
	} else if (unveil_mode == 1) {
		move_cursor(start_row, 4);
		print_line("\x1b[1mEnter path to unveil:\x1b[0m");
		move_cursor(start_row + 2, 6);
		char display_input[sizeof(unveil_input)];
		sanitize_for_display(unveil_input, display_input, sizeof(display_input));
		snprintf(buf, sizeof(buf), "> %s\x1b[7m \x1b[0m", display_input);
		print_line(buf);
		move_cursor(start_row + 4, 6);
		print_line("Use \"\" for paths containing ':'  Use \\X to escape characters");
		if (input_error[0]) {
			move_cursor(start_row + 6, 6);
			char ebuf[512];
			snprintf(ebuf, sizeof(ebuf), "\x1b[31mError: %s\x1b[0m", input_error);
			print_line(ebuf);
		}
		move_cursor(rows - 1, 2);
		print_line("\x1b[2mENTER: confirm  BACKSPACE: delete  q: cancel\x1b[0m");
	} else if (unveil_mode == 2) {
		move_cursor(start_row, 4);
		print_line("\x1b[1mSelect permissions for:\x1b[0m");
		move_cursor(start_row + 1, 6);
		char display_input[sizeof(unveil_input)];
		sanitize_for_display(unveil_input, display_input, sizeof(display_input));
		print_line(display_input);
		const char *perm_names[] = {"r - Read", "w - Write", "x - Execute", "c - Create/delete"};
		for (int i = 0; i < 4; i++) {
			move_cursor(start_row + 3 + i, 8);
			int *perm_val;
			switch (i) {
			case 0: perm_val = &unveil_entries[n_unveil].has_r; break;
			case 1: perm_val = &unveil_entries[n_unveil].has_w; break;
			case 2: perm_val = &unveil_entries[n_unveil].has_x; break;
			case 3: perm_val = &unveil_entries[n_unveil].has_c; break;
			default: perm_val = NULL; break;
			}
			const char *mark = *perm_val ? "\x1b[32m[X]\x1b[0m" : "[ ]";
			if (i == unveil_perm_cursor) {
				snprintf(buf, sizeof(buf), "\x1b[7m> %s %s\x1b[0m", mark, perm_names[i]);
			} else {
				snprintf(buf, sizeof(buf), "  %s %s", mark, perm_names[i]);
			}
			print_line(buf);
		}
		if (input_error[0]) {
			move_cursor(start_row + 8, 8);
			char ebuf[512];
			snprintf(ebuf, sizeof(ebuf), "\x1b[31mError: %s\x1b[0m", input_error);
			print_line(ebuf);
		}
		move_cursor(rows - 1, 2);
		print_line("\x1b[2mSPACE: toggle  UP/DOWN: move  ENTER: confirm  q: cancel\x1b[0m");
	}
}

static void
draw_command(int rows, int cols)
{
	char buf[8192];
	int start_row = 6;

	if (cmd_mode == 0) {
		move_cursor(start_row, 4);
		print_line("\x1b[1mEnter command path:\x1b[0m");
		int input_row = start_row + 2;
		if (strlen(cmd_path) > 0) {
			move_cursor(input_row, 6);
			char display_current[sizeof(cmd_path)];
			sanitize_for_display(cmd_path, display_current, sizeof(display_current));
			snprintf(buf, sizeof(buf), "Current: %s", display_current);
			print_line(buf);
			input_row++;
		}
		move_cursor(input_row, 6);
		char display_input[ARG_LEN];
		sanitize_for_display(cmd_input, display_input, sizeof(display_input));
		snprintf(buf, sizeof(buf), "> %s\x1b[7m \x1b[0m", display_input);
		print_line(buf);
		move_cursor(input_row + 2, 6);
		print_line("Relative paths are preserved (e.g. ./myapp, ../bin/tool)");
		move_cursor(input_row + 3, 6);
		print_line("Absolute paths are used as-is (e.g. /bin/sh, /usr/local/bin/nginx)");
		if (input_error[0]) {
			move_cursor(input_row + 5, 6);
			char ebuf[512];
			snprintf(ebuf, sizeof(ebuf), "\x1b[31mError: %s\x1b[0m", input_error);
			print_line(ebuf);
		}
		move_cursor(rows - 1, 2);
		print_line("\x1b[2mENTER: confirm  BACKSPACE: delete  q: cancel\x1b[0m");
	} else if (cmd_mode == 1) {
		move_cursor(start_row, 4);
		print_line("\x1b[1mEnter arguments (one per line, empty line to finish):\x1b[0m");
		move_cursor(start_row + 2, 6);
		print_line("Command:");
		move_cursor(start_row + 2, 16);
		char display_path[sizeof(cmd_path)];
		sanitize_for_display(cmd_path, display_path, sizeof(display_path));
		print_line(display_path);
		for (int i = 0; i < n_cmd_args; i++) {
			move_cursor(start_row + 4 + i, 6);
			char display_arg[ARG_LEN];
			sanitize_for_display(cmd_args[i], display_arg, sizeof(display_arg));
			snprintf(buf, sizeof(buf), "arg[%d]: %s", i, display_arg);
			print_line(buf);
		}
		move_cursor(start_row + 4 + n_cmd_args, 6);
		char display_input[ARG_LEN];
		sanitize_for_display(cmd_input, display_input, sizeof(display_input));
		snprintf(buf, sizeof(buf), "arg[%d]: %s\x1b[7m \x1b[0m", n_cmd_args, display_input);
		print_line(buf);
		if (input_error[0]) {
			move_cursor(start_row + 6 + n_cmd_args, 6);
			char ebuf[512];
			snprintf(ebuf, sizeof(ebuf), "\x1b[31mError: %s\x1b[0m", input_error);
			print_line(ebuf);
		}
		move_cursor(rows - 1, 2);
		print_line("\x1b[2mENTER: next arg (empty=done)  BACKSPACE: delete  q: cancel\x1b[0m");
	}
}

static void
draw_execute(int rows, int cols, const char *prog_name)
{
	char buf[8192];
	int start_row = 6;

	move_cursor(start_row, 4);
	print_line("\x1b[1mReview configuration:\x1b[0m");

	move_cursor(start_row + 2, 6);
	print_line("Pledges:");
	int first = 1;
	buf[0] = '\0';
	for (size_t i = 0; i < N_PLEDGES; i++) {
		if (pledges[i].selected) {
			if (!first) strlcat(buf, ",", sizeof(buf));
			strlcat(buf, pledges[i].name, sizeof(buf));
			first = 0;
		}
	}
	move_cursor(start_row + 2, 16);
	print_line(buf);

	move_cursor(start_row + 4, 6);
	print_line("Unveil:");
	if (n_unveil == 0) {
		move_cursor(start_row + 4, 16);
		print_line("(none)");
	} else {
		for (int i = 0; i < n_unveil; i++) {
			move_cursor(start_row + 4 + i, 16);
			char perms[8] = "";
			int p = 0;
			if (unveil_entries[i].has_r) perms[p++] = 'r';
			if (unveil_entries[i].has_w) perms[p++] = 'w';
			if (unveil_entries[i].has_x) perms[p++] = 'x';
			if (unveil_entries[i].has_c) perms[p++] = 'c';
			perms[p] = '\0';
			char display_path[sizeof(unveil_entries[i].path)];
			sanitize_for_display(unveil_entries[i].path, display_path, sizeof(display_path));
			snprintf(buf, sizeof(buf), "%s:%s", display_path, perms);
			print_line(buf);
		}
	}

	/* Clamp cmd_row to avoid display overflow with many unveil paths */
	int cmd_row = start_row + 6 + (n_unveil > 0 ? n_unveil : 1);
	if (cmd_row > rows - 4) cmd_row = rows - 4;
	if (cmd_row < start_row + 6) cmd_row = start_row + 6;

	move_cursor(cmd_row, 6);
	print_line("Command:");
	move_cursor(cmd_row, 16);
	if (strlen(cmd_path) == 0) {
		print_line("(not set)");
	} else {
		int cmd_ok = 1;
		int truncated = 0;
		char display_path[sizeof(cmd_path)];
		sanitize_for_display(cmd_path, display_path, sizeof(display_path));
		snprintf(buf, sizeof(buf), "%s", display_path);
		for (int i = 0; i < n_cmd_args; i++) {
			cmd_ok = cmd_ok && strlcat(buf, " ", sizeof(buf)) < sizeof(buf);
			if (!cmd_ok && !truncated) {
				truncated = 1;
				break;
			}
			char display_arg[ARG_LEN];
			sanitize_for_display(cmd_args[i], display_arg, sizeof(display_arg));
			cmd_ok = cmd_ok && strlcat(buf, display_arg, sizeof(buf)) < sizeof(buf);
			if (!cmd_ok && !truncated)
				truncated = 1;
		}
		if (cmd_ok) {
			sanitize_for_display_inplace(buf);
			print_line(buf);
		} else {
			print_line("(command too long to display)");
		}
	}

	int eq_row = cmd_row + 3;
	if (eq_row < rows - 1) {
		move_cursor(eq_row, 6);
		print_line("\x1b[1mEquivalent command line:\x1b[0m");
		if (eq_row + 1 < rows - 1) {
			move_cursor(eq_row + 1, 6);
			/* Use prog_name instead of hardcoded "./exec" */
			static char cmdline[65536];
			int cmdline_ok = 1;
			cmdline[0] = '\0';
			if (prog_name != NULL && prog_name[0] != '\0') {
				if (str_needs_quoting(prog_name)) {
					cmdline_ok = cmdline_ok && strlcat(cmdline, "\"", sizeof(cmdline)) < sizeof(cmdline);
					cmdline_ok = cmdline_ok && append_escaped_path(cmdline, sizeof(cmdline), prog_name);
					cmdline_ok = cmdline_ok && strlcat(cmdline, "\"", sizeof(cmdline)) < sizeof(cmdline);
				} else {
					cmdline_ok = cmdline_ok && strlcat(cmdline, prog_name, sizeof(cmdline)) < sizeof(cmdline);
				}
			} else {
				cmdline_ok = cmdline_ok && strlcat(cmdline, "./exec", sizeof(cmdline)) < sizeof(cmdline);
			}
			cmdline_ok = cmdline_ok && strlcat(cmdline, " ", sizeof(cmdline)) < sizeof(cmdline);
			first = 1;
			for (size_t i = 0; i < N_PLEDGES; i++) {
				if (pledges[i].selected) {
					if (!first) cmdline_ok = cmdline_ok && strlcat(cmdline, ",", sizeof(cmdline)) < sizeof(cmdline);
					cmdline_ok = cmdline_ok && strlcat(cmdline, pledges[i].name, sizeof(cmdline)) < sizeof(cmdline);
					first = 0;
				}
			}
			cmdline_ok = cmdline_ok && strlcat(cmdline, " ", sizeof(cmdline)) < sizeof(cmdline);
			if (n_unveil == 0) {
				cmdline_ok = cmdline_ok && strlcat(cmdline, "\"\"", sizeof(cmdline)) < sizeof(cmdline);
			} else {
				first = 1;
				for (int i = 0; i < n_unveil; i++) {
					if (!first) cmdline_ok = cmdline_ok && strlcat(cmdline, ",", sizeof(cmdline)) < sizeof(cmdline);
					int need_quote = strchr(unveil_entries[i].path, ':') != NULL ||
					                 strchr(unveil_entries[i].path, ',') != NULL ||
					                 strchr(unveil_entries[i].path, ' ') != NULL ||
					                 strchr(unveil_entries[i].path, '\t') != NULL ||
					                 strchr(unveil_entries[i].path, '\n') != NULL ||
					                 strchr(unveil_entries[i].path, '\r') != NULL ||
					                 strchr(unveil_entries[i].path, '"') != NULL ||
					                 strchr(unveil_entries[i].path, '\\') != NULL;
					if (need_quote) cmdline_ok = cmdline_ok && strlcat(cmdline, "\"", sizeof(cmdline)) < sizeof(cmdline);
					cmdline_ok = cmdline_ok && append_escaped_path(cmdline, sizeof(cmdline), unveil_entries[i].path);
					if (need_quote) cmdline_ok = cmdline_ok && strlcat(cmdline, "\"", sizeof(cmdline)) < sizeof(cmdline);
					char perms[8] = "";
					int p = 0;
					if (unveil_entries[i].has_r) perms[p++] = 'r';
					if (unveil_entries[i].has_w) perms[p++] = 'w';
					if (unveil_entries[i].has_x) perms[p++] = 'x';
					if (unveil_entries[i].has_c) perms[p++] = 'c';
					perms[p] = '\0';
					cmdline_ok = cmdline_ok && strlcat(cmdline, ":", sizeof(cmdline)) < sizeof(cmdline);
					cmdline_ok = cmdline_ok && strlcat(cmdline, perms, sizeof(cmdline)) < sizeof(cmdline);
					first = 0;
				}
			}
			cmdline_ok = cmdline_ok && strlcat(cmdline, " -- ", sizeof(cmdline)) < sizeof(cmdline);
			if (str_needs_quoting(cmd_path)) {
				cmdline_ok = cmdline_ok && strlcat(cmdline, "\"", sizeof(cmdline)) < sizeof(cmdline);
				cmdline_ok = cmdline_ok && append_escaped_path(cmdline, sizeof(cmdline), cmd_path);
				cmdline_ok = cmdline_ok && strlcat(cmdline, "\"", sizeof(cmdline)) < sizeof(cmdline);
			} else {
				cmdline_ok = cmdline_ok && strlcat(cmdline, cmd_path, sizeof(cmdline)) < sizeof(cmdline);
			}
			for (int i = 0; i < n_cmd_args; i++) {
				cmdline_ok = cmdline_ok && strlcat(cmdline, " ", sizeof(cmdline)) < sizeof(cmdline);
				if (str_needs_quoting(cmd_args[i])) {
					cmdline_ok = cmdline_ok && strlcat(cmdline, "\"", sizeof(cmdline)) < sizeof(cmdline);
					cmdline_ok = cmdline_ok && append_escaped_path(cmdline, sizeof(cmdline), cmd_args[i]);
					cmdline_ok = cmdline_ok && strlcat(cmdline, "\"", sizeof(cmdline)) < sizeof(cmdline);
				} else {
					cmdline_ok = cmdline_ok && strlcat(cmdline, cmd_args[i], sizeof(cmdline)) < sizeof(cmdline);
				}
			}
			if (cmdline_ok) {
				sanitize_for_display_inplace(cmdline);
				print_line(cmdline);
			} else {
				print_line("(command line too long to display)");
			}
		}
	}

	move_cursor(rows - 1, 2);
	print_line("\x1b[2mENTER: execute  <-->: tabs  q: quit\x1b[0m");
}

static void
draw_screen(const char *prog_name)
{
	int rows, cols;
	if (get_window_size(&rows, &cols) == -1) {
		rows = 24;
		cols = 80;
	}
	if (rows < 8 || cols < 30) {
		clear_screen();
		move_cursor(1, 1);
		print_line("Terminal too small (need at least 8x30)\r\n");
		fflush(stdout);
		return;
	}
	draw_frame(rows, cols);
	switch (menu_tab) {
	case 0: draw_pledges(rows, cols); break;
	case 1: draw_unveil(rows, cols); break;
	case 2: draw_command(rows, cols); break;
	case 3: draw_execute(rows, cols, prog_name); break;
	}
	write(STDOUT_FILENO, "\x1b[0m", 4);
	fflush(stdout);
}

static void
build_pledges_string(char *out, size_t outsize)
{
	int first = 1;
	out[0] = '\0';
	for (size_t i = 0; i < N_PLEDGES; i++) {
		if (pledges[i].selected) {
			if (!first) {
				if (strlcat(out, ",", outsize) >= outsize)
					errx(1, "pledges string too long");
			}
			if (strlcat(out, pledges[i].name, outsize) >= outsize)
				errx(1, "pledges string too long");
			first = 0;
		}
	}
}

static void
build_unveil_string(char *out, size_t outsize)
{
	if (n_unveil == 0) {
		strlcpy(out, "\"\"", outsize);
		return;
	}
	out[0] = '\0';
	int first = 1;
	for (int i = 0; i < n_unveil; i++) {
		if (!first) {
			if (strlcat(out, ",", outsize) >= outsize)
				errx(1, "unveil string too long");
		}
		int need_quote = strchr(unveil_entries[i].path, ':') != NULL ||
		                 strchr(unveil_entries[i].path, ',') != NULL ||
		                 strchr(unveil_entries[i].path, ' ') != NULL ||
		                 strchr(unveil_entries[i].path, '\t') != NULL ||
		                 strchr(unveil_entries[i].path, '\n') != NULL ||
		                 strchr(unveil_entries[i].path, '\r') != NULL ||
		                 strchr(unveil_entries[i].path, '"') != NULL ||
		                 strchr(unveil_entries[i].path, '\\') != NULL;
		if (need_quote) {
			if (strlcat(out, "\"", outsize) >= outsize)
				errx(1, "unveil string too long");
		}
		if (!append_escaped_path(out, outsize, unveil_entries[i].path))
			errx(1, "unveil string too long");
		if (need_quote) {
			if (strlcat(out, "\"", outsize) >= outsize)
				errx(1, "unveil string too long");
		}
		char perms[8] = "";
		int p = 0;
		if (unveil_entries[i].has_r) perms[p++] = 'r';
		if (unveil_entries[i].has_w) perms[p++] = 'w';
		if (unveil_entries[i].has_x) perms[p++] = 'x';
		if (unveil_entries[i].has_c) perms[p++] = 'c';
		perms[p] = '\0';
		if (strlcat(out, ":", outsize) >= outsize ||
		    strlcat(out, perms, outsize) >= outsize)
			errx(1, "unveil string too long");
		first = 0;
	}
}

static void
exec_default_cmd(void)
{
	const char *cmd = getenv("EXEC_CMD");
	if (!cmd || cmd[0] == '\0')
		cmd = "/bin/sh";
	execl(cmd, cmd, (char *)NULL);
	err(1, "execl %s", cmd);
}

/*
 * Apply pledge and unveil, then exec the configured command.
 * This function does not return on success.
 */
static void
run_from_config(void)
{
	char pledges_str[MAX_PLEDGES_LEN];
	char unveil_str[MAX_UNVEIL_STR_LEN];
	char *cmd_argv[MAX_ARGS + 2];

	build_pledges_string(pledges_str, sizeof(pledges_str));
	build_unveil_string(unveil_str, sizeof(unveil_str));

	if (strlen(cmd_path) == 0) {
		clear_screen();
		show_cursor();
		safe_disable_raw_mode();
		fprintf(stderr, "Error: No command configured.\n");
		exit(1);
	}

	if (!has_word(pledges_str, "exec")) {
		clear_screen();
		show_cursor();
		safe_disable_raw_mode();
		fprintf(stderr, "Error: 'exec' pledge is required.\n");
		exit(1);
	}

	/* Parse pledges into space-separated buffer (stack allocated) */
	char pledges[MAX_PLEDGES_LEN];
	if (parse_pledges(pledges_str, pledges, sizeof(pledges)) == -1) {
		clear_screen();
		show_cursor();
		safe_disable_raw_mode();
		errx(1, "pledges string too long");
	}

	int unveiled;
	if (strcmp(unveil_str, "\"\"") == 0) {
		unveiled = 0;
	} else {
		unveiled = parse_unveil(unveil_str);
	}

	if (unveiled > 0 && !has_word(pledges, "unveil")) {
		size_t len = strlen(pledges);
		if (len + 8 > sizeof(pledges)) {
			clear_screen();
			show_cursor();
			safe_disable_raw_mode();
			errx(1, "pledges string too long to auto-append 'unveil'");
		}
		snprintf(pledges + len, sizeof(pledges) - len, " unveil");
	}

	if (unveiled > 0) {
		if (unveil(NULL, NULL) == -1) {
			clear_screen();
			show_cursor();
			safe_disable_raw_mode();
			err(1, "unveil(NULL, NULL)");
		}
	}

	if (pledge(pledges, pledges) == -1) {
		clear_screen();
		show_cursor();
		safe_disable_raw_mode();
		err(1, "pledge(\"%s\", \"%s\")", pledges, pledges);
	}

	if (has_word(pledges, "stdio")) {
		if (pledge("stdio exec", pledges) == -1) {
			clear_screen();
			show_cursor();
			safe_disable_raw_mode();
			err(1, "pledge(\"stdio exec\", \"%s\") self-restriction failed",
			    pledges);
		}
	} else {
		if (pledge("exec", pledges) == -1) {
			clear_screen();
			show_cursor();
			safe_disable_raw_mode();
			err(1, "pledge(\"exec\", \"%s\") self-restriction failed",
			    pledges);
		}
	}

	cmd_argv[0] = cmd_path;
	for (int i = 0; i < n_cmd_args; i++)
		cmd_argv[i + 1] = cmd_args[i];
	cmd_argv[n_cmd_args + 1] = NULL;

	show_cursor();
	safe_disable_raw_mode();

	execvp(cmd_argv[0], cmd_argv);
	err(1, "execvp %s", cmd_argv[0]);
}

static void
menuconfig(const char *prog_name)
{
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Error: --menuconfig requires an interactive terminal\n");
		exit(1);
	}
	enable_raw_mode();
	hide_cursor();

	int running = 1;
	while (running) {
		/* Check for pending signals */
		if (sig_received) {
			running = 0;
			sig_received = 0;
			break;
		}
		/* Atomic check and clear winch_flag */
		if (winch_flag) {
			winch_flag = 0;
			clear_screen();
		}
		draw_screen(prog_name);
		int key = read_key();

		if (key == KEY_Q || key == 3 || key == KEY_EOF) {
			if (unveil_mode != 0 || cmd_mode != 0) {
				/* Cancel current input mode instead of quitting */
				if (unveil_mode != 0) {
					unveil_mode = 0;
					unveil_input[0] = '\0';
					unveil_input_len = 0;
					input_error[0] = '\0';
				}
				if (cmd_mode != 0) {
					cmd_mode = 0;
					cmd_input[0] = '\0';
					cmd_input_len = 0;
					input_error[0] = '\0';
				}
				break; /* re-loop, do not quit */
			}
			running = 0;
			break;
		}

		switch (menu_tab) {
		case 0: /* Pledges */
			if (key == KEY_UP) {
				if (pledge_cursor > 0) pledge_cursor--;
			} else if (key == KEY_DOWN) {
				if (pledge_cursor < (int)N_PLEDGES - 1) pledge_cursor++;
			} else if (key == KEY_SPACE) {
				if (strcmp(pledges[pledge_cursor].name, "exec") != 0)
					pledges[pledge_cursor].selected = !pledges[pledge_cursor].selected;
			} else if (key == KEY_RIGHT) {
				menu_tab = 1;
				unveil_mode = 0;
			} else if (key == KEY_ENTER) {
				/* nothing, just visual feedback */
			}
			break;

		case 1: /* Unveil */
			if (unveil_mode == 0) {
				if (key == KEY_UP) {
					if (unveil_cursor > 0) unveil_cursor--;
				} else if (key == KEY_DOWN) {
					if (unveil_cursor < n_unveil - 1) unveil_cursor++;
				} else if (key == KEY_A) {
					if (n_unveil < MAX_UNVEIL) {
						unveil_mode = 1;
						unveil_input[0] = '\0';
						unveil_input_len = 0;
						input_error[0] = '\0';
					}
				} else if (key == KEY_D) {
					if (n_unveil > 0 && unveil_cursor < n_unveil) {
						for (int i = unveil_cursor; i < n_unveil - 1; i++)
							unveil_entries[i] = unveil_entries[i + 1];
						n_unveil--;
						if (unveil_cursor >= n_unveil && unveil_cursor > 0)
							unveil_cursor--;
					}
				} else if (key == KEY_LEFT) {
					menu_tab = 0;
					unveil_mode = 0;
				} else if (key == KEY_RIGHT) {
					menu_tab = 2;
					unveil_mode = 0;
				}
			} else if (unveil_mode == 1) {
				if (key == KEY_ENTER) {
					if (unveil_input_len > 0) {
						if (strlen(unveil_input) >= sizeof(unveil_entries[n_unveil].path)) {
							snprintf(input_error, sizeof(input_error),
							    "path too long (max %zu chars)",
							    sizeof(unveil_entries[n_unveil].path) - 1);
						} else {
							input_error[0] = '\0';
							unveil_mode = 2;
							unveil_perm_cursor = 0;
							/* Default: only read permission enabled */
							unveil_entries[n_unveil].has_r = 1;
							unveil_entries[n_unveil].has_w = 0;
							unveil_entries[n_unveil].has_x = 0;
							unveil_entries[n_unveil].has_c = 0;
						}
					}
				} else if (key == KEY_BACKSPACE || key == 8) {
					if (unveil_input_len > 0) {
						unveil_input_len--;
						unveil_input[unveil_input_len] = '\0';
					}
				} else if (key == KEY_ESC || key == KEY_Q) {
					unveil_mode = 0;
					unveil_input[0] = '\0';
					unveil_input_len = 0;
					input_error[0] = '\0';
				} else if (key >= 32 && key != 127 && unveil_input_len < (int)sizeof(unveil_input) - 1) {
					unveil_input[unveil_input_len++] = key;
					unveil_input[unveil_input_len] = '\0';
					input_error[0] = '\0';
				}
			} else if (unveil_mode == 2) {
				if (key == KEY_UP) {
					if (unveil_perm_cursor > 0) unveil_perm_cursor--;
				} else if (key == KEY_DOWN) {
					if (unveil_perm_cursor < 3) unveil_perm_cursor++;
				} else if (key == KEY_SPACE) {
					switch (unveil_perm_cursor) {
					case 0: unveil_entries[n_unveil].has_r = !unveil_entries[n_unveil].has_r; break;
					case 1: unveil_entries[n_unveil].has_w = !unveil_entries[n_unveil].has_w; break;
					case 2: unveil_entries[n_unveil].has_x = !unveil_entries[n_unveil].has_x; break;
					case 3: unveil_entries[n_unveil].has_c = !unveil_entries[n_unveil].has_c; break;
					}
				} else if (key == KEY_ENTER) {
					if (strlen(unveil_input) >= sizeof(unveil_entries[n_unveil].path)) {
						snprintf(input_error, sizeof(input_error),
						    "path too long (max %zu chars)",
						    sizeof(unveil_entries[n_unveil].path) - 1);
					} else {
						input_error[0] = '\0';
						strlcpy(unveil_entries[n_unveil].path, unveil_input,
						    sizeof(unveil_entries[n_unveil].path));
						n_unveil++;
						unveil_mode = 0;
						unveil_cursor = n_unveil - 1;
					}
				} else if (key == KEY_ESC || key == KEY_Q) {
					unveil_mode = 0;
					unveil_input[0] = '\0';
					unveil_input_len = 0;
					input_error[0] = '\0';
				}
			}
			break;

		case 2: /* Command */
			if (cmd_mode == 0) {
				if (key == KEY_ENTER) {
					if (cmd_input_len > 0) {
						if (strlen(cmd_input) >= sizeof(cmd_path)) {
							snprintf(input_error, sizeof(input_error),
							    "command path too long (max %zu chars)",
							    sizeof(cmd_path) - 1);
						} else {
							input_error[0] = '\0';
							strlcpy(cmd_path, cmd_input, sizeof(cmd_path));
							cmd_mode = 1;
							cmd_input[0] = '\0';
							cmd_input_len = 0;
							n_cmd_args = 0;
						}
					}
				} else if (key == KEY_BACKSPACE || key == 8) {
					if (cmd_input_len > 0) {
						cmd_input_len--;
						cmd_input[cmd_input_len] = '\0';
					}
				} else if (key == KEY_ESC || key == KEY_Q) {
					cmd_mode = 0;
					cmd_input[0] = '\0';
					cmd_input_len = 0;
					input_error[0] = '\0';
				} else if (key >= 32 && key != 127 && cmd_input_len < ARG_LEN - 1) {
					cmd_input[cmd_input_len++] = key;
					cmd_input[cmd_input_len] = '\0';
					input_error[0] = '\0';
				}
				if (key == KEY_LEFT) {
					menu_tab = 1;
					unveil_mode = 0;
				}
				if (key == KEY_RIGHT) {
					menu_tab = 3;
					unveil_mode = 0;
				}
			} else if (cmd_mode == 1) {
				if (key == KEY_ENTER) {
					if (cmd_input_len == 0) {
						input_error[0] = '\0';
						cmd_mode = 0;
					} else if (n_cmd_args < MAX_ARGS) {
						if (strlen(cmd_input) >= ARG_LEN) {
							snprintf(input_error, sizeof(input_error),
							    "argument too long (max %d chars)", ARG_LEN - 1);
						} else {
							input_error[0] = '\0';
							strlcpy(cmd_args[n_cmd_args], cmd_input, ARG_LEN);
							n_cmd_args++;
							cmd_input[0] = '\0';
							cmd_input_len = 0;
						}
					} else {
						snprintf(input_error, sizeof(input_error),
						    "too many arguments (max %d)", MAX_ARGS);
					}
				} else if (key == KEY_BACKSPACE || key == 8) {
					if (cmd_input_len > 0) {
						cmd_input_len--;
						cmd_input[cmd_input_len] = '\0';
					}
				} else if (key == KEY_ESC || key == KEY_Q) {
					cmd_mode = 0;
					input_error[0] = '\0';
				} else if (key >= 32 && key != 127 && cmd_input_len < ARG_LEN - 1) {
					cmd_input[cmd_input_len++] = key;
					cmd_input[cmd_input_len] = '\0';
					input_error[0] = '\0';
				}
				/* LEFT/RIGHT intentionally ignored in argument input mode */
			}
			break;

		case 3: /* Execute */
			if (key == KEY_ENTER) {
				running = 0;
				clear_screen();
				show_cursor();
				run_from_config();
				/* never returns */
			} else if (key == KEY_LEFT) {
				menu_tab = 2;
				unveil_mode = 0;
			} else if (key == KEY_RIGHT) {
				menu_tab = 0;
				unveil_mode = 0;
			}
			break;
		}
	}

	clear_screen();
	show_cursor();
}

/* ======================================================================== */
/* Main                                                                     */
/* ======================================================================== */

int
main(int argc, char *argv[])
{
	if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
		usage(argv[0]);

	/* --version */
	if (strcmp(argv[1], "--version") == 0) {
		printf("exec.c - OpenBSD pledge/unveil launcher\n");
		printf("Version 1.5 (pledge list: OpenBSD 7.5)\n");
		printf("Build: cc -O2 -o exec exec.c -Wall -Wextra\n");
		return 0;
	}

	/* --menuconfig mode */
	if (strcmp(argv[1], "--menuconfig") == 0) {
		menuconfig(argv[0]);
		return 0;
	}

	/* --make-starter mode: must be handled before pledge/unveil */
	if (argc >= 3 && strcmp(argv[1], "--make-starter") == 0) {
		if (argc < 5)
			errx(1, "Usage: %s --make-starter starter_name pledges unveil [--] command [args...]", argv[0]);

		const char *starter_name = argv[2];
		const char *pledges_raw = argv[3];
		const char *unveil_raw = argv[4];

		/* Validate pledge string length */
		if (strlen(pledges_raw) >= MAX_PLEDGES_LEN)
			errx(1, "pledges string too long (max %d bytes)", MAX_PLEDGES_LEN - 1);

		/* Validate unveil string length */
		if (strlen(unveil_raw) >= MAX_UNVEIL_STR_LEN)
			errx(1, "unveil string too long (max %d bytes)", MAX_UNVEIL_STR_LEN - 1);

		int cmd_start;
		if (argc >= 6 && strcmp(argv[5], "--") == 0) {
			cmd_start = 6;
		} else {
			cmd_start = 5;
		}
		int cmd_argc = argc - cmd_start;

		/* Reconstruct creation command line for help display */
		char creation_cmd[MAX_CREATION_CMD_LEN];
		if (strlen(argv[0]) >= sizeof(creation_cmd))
			errx(1, "creation command too long");
		snprintf(creation_cmd, sizeof(creation_cmd), "%s", argv[0]);
		size_t off = strlen(creation_cmd);
		for (int i = 1; i < argc; i++) {
			size_t arglen = strlen(argv[i]);
			/* Need space + arg + null terminator */
			if (off + 1 + arglen >= sizeof(creation_cmd))
				errx(1, "creation command too long");
			creation_cmd[off++] = ' ';
			memcpy(creation_cmd + off, argv[i], arglen);
			off += arglen;
		}
		creation_cmd[off] = '\0';

		make_starter(starter_name, pledges_raw, unveil_raw,
		    cmd_argc, argv + cmd_start, creation_cmd, argv[0]);
		return 0;
	}

	if (argc < 3)
		usage(argv[0]);

	/* Validate pledge string length */
	if (strlen(argv[1]) >= MAX_PLEDGES_LEN)
		errx(1, "pledges string too long (max %d bytes)", MAX_PLEDGES_LEN - 1);

	/* Validate unveil string length */
	if (strlen(argv[2]) >= MAX_UNVEIL_STR_LEN)
		errx(1, "unveil string too long (max %d bytes)", MAX_UNVEIL_STR_LEN - 1);

	/* Validate pledge names before proceeding */
	if (!is_valid_pledge_list(argv[1]))
		errx(1, "invalid pledge name in '%s'", argv[1]);

	/* Parse pledges into stack buffer (no dynamic allocation) */
	char pledges[MAX_PLEDGES_LEN];
	if (parse_pledges(argv[1], pledges, sizeof(pledges)) == -1)
		errx(1, "pledges string too long");

	if (!has_word(pledges, "exec"))
		errx(1, "pledges must include 'exec' to run a program");

	int unveiled;
	if (strlen(argv[2]) == 0 || strcmp(argv[2], "\"\"") == 0) {
		unveiled = 0;
	} else {
		unveiled = parse_unveil(argv[2]);
	}

	if (unveiled > 0 && !has_word(pledges, "unveil")) {
		size_t len = strlen(pledges);
		if (len + 8 > sizeof(pledges))
			errx(1, "pledges string too long to auto-append 'unveil'");
		snprintf(pledges + len, sizeof(pledges) - len, " unveil");
	}

	if (unveiled > 0) {
		if (unveil(NULL, NULL) == -1)
			err(1, "unveil(NULL, NULL)");
	}

	if (pledge(pledges, pledges) == -1)
		err(1, "pledge(\"%s\", \"%s\")", pledges, pledges);

	if (has_word(pledges, "stdio")) {
		if (pledge("stdio exec", pledges) == -1)
			err(1, "pledge(\"stdio exec\", \"%s\") self-restriction failed",
			    pledges);
	} else {
		if (pledge("exec", pledges) == -1)
			err(1, "pledge(\"exec\", \"%s\") self-restriction failed",
			    pledges);
	}

	char **exec_argv;
	int exec_argc;
	if (argc >= 4 && strcmp(argv[3], "--") == 0) {
		exec_argv = argv + 4;
		exec_argc = argc - 4;
	} else if (argc >= 4) {
		exec_argv = argv + 3;
		exec_argc = argc - 3;
	} else {
		exec_default_cmd();
	}

	if (exec_argc == 0)
		exec_default_cmd();

	execvp(exec_argv[0], exec_argv);
	err(1, "execvp %s", exec_argv[0]);
}
