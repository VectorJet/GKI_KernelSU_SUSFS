import re, sys, os

os.chdir(os.environ.get('GITHUB_WORKSPACE', '.') + '/kernel/common')
SECURITY_C = 'security/security.c'
USERNS_C   = 'kernel/user_namespace.c'

def force_default_1(path, label):
    with open(path) as f:
        src = f.read()
    new = re.sub(r'(int\s+unprivileged_userns_clone\s*=\s*)0', r'\g<1>1', src)
    if new != src:
        with open(path, 'w') as f:
            f.write(new)
        print(f'[userns] {label}: flipped unprivileged_userns_clone default to 1')
        return True
    return False

# Strategy 1: sysctl already exists somewhere, just flip default
# NOTE: we do NOT exit(0) here — fall through so the current_chrooted()
# gate in user_namespace.c still gets patched regardless of which file
# already carries the sysctl declaration.
for path, label in [(SECURITY_C, 'security.c'), (USERNS_C, 'user_namespace.c')]:
    if os.path.exists(path):
        with open(path) as f:
            txt = f.read()
        if 'unprivileged_userns_clone' in txt:
            if force_default_1(path, label):
                print(f'[userns] {label}: sysctl already present, will still patch current_chrooted gate')
            else:
                print(f'[userns] {label}: already =1, will still patch current_chrooted gate')
            # Skip security.c injection (Strategy 2) since sysctl already exists,
            # but jump straight to Strategy 2b (current_chrooted bypass)
            break

# Strategy 2: inject sysctl + short-circuit into security_create_user_ns
if not os.path.exists(SECURITY_C):
    print(f'[userns] ERROR: {SECURITY_C} not found', file=sys.stderr)
    sys.exit(1)

with open(SECURITY_C) as f:
    src = f.read()

if 'security_create_user_ns' not in src:
    # Strategy 3 fallback: noop the call-site in user_namespace.c
    print('[userns] security_create_user_ns not in security.c; trying user_namespace.c fallback')
    if not os.path.exists(USERNS_C):
        print(f'[userns] ERROR: {USERNS_C} not found either', file=sys.stderr)
        sys.exit(1)
    with open(USERNS_C) as f:
        usrc = f.read()
    old = '\tret = security_create_user_ns(new);\n\tif (ret < 0)\n\t\tgoto fail_dec;'
    new = '\tret = 0; /* Wild: unprivileged userns allowed */\n\tif (ret < 0)\n\t\tgoto fail_dec;'
    patched = usrc.replace(old, new)
    if patched == usrc:
        print('[userns] ERROR: could not locate security_create_user_ns call-site', file=sys.stderr)
        sys.exit(1)
    with open(USERNS_C, 'w') as f:
        f.write(patched)
    print(f'[userns] Patched {USERNS_C}: security_create_user_ns call no-oped')
    sys.exit(0)

sysctl_block = """
/* Wild kernel: allow unprivileged user namespace creation.
 * Set kernel.unprivileged_userns_clone=0 to restore LSM enforcement.
 * Non-static: shared with kernel/user_namespace.c's current_chrooted() gate. */
int unprivileged_userns_clone = 1;

#ifdef CONFIG_SYSCTL
static struct ctl_table wild_userns_sysctls[] = {
	{
		.procname	= "unprivileged_userns_clone",
		.data		= &unprivileged_userns_clone,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{ }
};

static int __init wild_userns_sysctl_init(void)
{
	return register_sysctl("kernel", wild_userns_sysctls) ? 0 : -ENOMEM;
}
late_initcall(wild_userns_sysctl_init);
#endif /* CONFIG_SYSCTL */

"""

fn_pat = re.compile(
    r'(int\s+security_create_user_ns\s*\([^)]*\)\s*\{)([^}]*)(\})',
    re.DOTALL
)

def patch_fn(m):
    new_body = (
        '\n\tif (unprivileged_userns_clone)\n'
        '\t\treturn 0;\n'
        '\treturn call_int_hook(userns_create, 0, cred);\n'
    )
    return sysctl_block + m.group(1) + new_body + m.group(3)

new_src, n = fn_pat.subn(patch_fn, src, count=1)
if n == 0:
    print('[userns] ERROR: could not match security_create_user_ns body', file=sys.stderr)
    sys.exit(1)

with open(SECURITY_C, 'w') as f:
    f.write(new_src)

print(f'[userns] Patched {SECURITY_C}: unprivileged_userns_clone sysctl injected (default=1)')

# ── Strategy 2b: bypass the current_chrooted() gate in create_user_ns() ──
#
# security_create_user_ns() is NOT the only gatekeeper. create_user_ns() in
# kernel/user_namespace.c checks current_chrooted() *before* it ever calls
# security_create_user_ns(). current_chrooted() compares the caller's fs->root
# against its mount namespace root — a bare chroot(2) (no accompanying
# unshare(CLONE_NEWNS) + pivot) can never satisfy that equality, so this check
# is a hard, unconditional EPERM for any process living in a plain chroot jail.
# Confirmed against android15-6.6.50_r00 kernel/user_namespace.c:105.
if not os.path.exists(USERNS_C):
    print(f'[userns] ERROR: {USERNS_C} not found, cannot patch current_chrooted gate', file=sys.stderr)
    sys.exit(1)

with open(USERNS_C) as f:
    usrc = f.read()

if 'unprivileged_userns_clone' in usrc:
    print('[userns] current_chrooted gate already patched in user_namespace.c, skipping')
else:
    old_gate = '\tret = -EPERM;\n\tif (current_chrooted())\n\t\tgoto fail_dec;'
    new_gate = (
        'extern int unprivileged_userns_clone;\n\n'
        '\tret = -EPERM;\n'
        '\tif (current_chrooted() && !unprivileged_userns_clone)\n'
        '\t\tgoto fail_dec;'
    )
    patched_usrc = usrc.replace(old_gate, new_gate, 1)
    if patched_usrc == usrc:
        print('[userns] ERROR: could not locate current_chrooted() gate in user_namespace.c', file=sys.stderr)
        sys.exit(1)
    with open(USERNS_C, 'w') as f:
        f.write(patched_usrc)
    print(f'[userns] Patched {USERNS_C}: current_chrooted() gate now bypassed when unprivileged_userns_clone=1')
