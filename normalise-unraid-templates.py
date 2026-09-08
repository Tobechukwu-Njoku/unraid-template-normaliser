#!/usr/bin/env python3
"""
normalise-unraid-templates.py
=============================

Cleans and normalises Unraid dockerMan user templates (my-*.xml).

    python3 normalise-unraid-templates.py [SRC_DIR] [DST_DIR]

Defaults:
    SRC  ~/Downloads/templates-user                     (read only, never modified)
    DST  ~/Documents/Claude/Projects/XML Docker         (overwritten)

Requires nothing but the Python 3 standard library.

WHAT IT DOES
------------
Structure
  * Elements emitted in Unraid's canonical order; <Config> attributes in the
    canonical order Name, Target, Default, Mode, Description, Type, Display,
    Required, Mask.
  * <DateInstalled> and <MyMAC> dropped. <MyIP> kept.
  * <Overview> whitespace collapsed (stray carriage returns, blank-line runs).

Config blocks
  * Re-ordered: Ports, Paths, Devices, Variables, Labels, then
    PUID/PGID/UID/GID/UMASK/TZ pinned last.
  * Within the Variable block, context sub-groups are tightened by first-word key
    (Database*, Valkey*, Machine Learning*) while preserving first-appearance
    order, so related settings sit together.
  * Raw env-var labels (Name identical to Target, e.g. VPN_PIA_USER) swapped for
    human ones via _review-variable-renames.txt, which sits beside this script.
    Edit that file's right-hand side to change a label, or delete a line to skip
    that variable. Target is never changed. A "Var NN:" prefix is preserved and
    only the raw tail is replaced.
  * Paths and Ports renamed to "Path NN: Label" / "Port NN: Label", title-cased.
    Dotted sub-numbering (Path 04.0, 04.1, ...) is preserved where the source
    used it, and grouped members are emitted together in minor order.
    Variable names are deliberately left alone.

Attributes
  * Required="false" on everything.
  * Mask="true" on credentials, tokens and keys. The live VALUE is kept; the
    Default is blanked instead, because Unraid's mask does not cover Defaults.
    Only Type="Variable" is ever masked, boolean-valued fields never are, and a
    field already marked Mask="true" is never unmasked.
    A Default that merely documents a connection-string shape
    (postgres://POSTGRES_USER:POSTGRES_PASSWORD@POSTGRES_IP:5432/db) is kept,
    since it carries no real secret.
  * Default synced to the live value, except Unraid dropdown option-lists
    ("true|false") which are left intact, and masked fields which get "".
  * Mask="null" / Mask="{8}" -> "false".  Mode="{3}" -> "" on Variables.
  * Display "-hide" suffixes stripped (always-hide -> always, advanced-hide ->
    advanced) so no field is locked read-only. Display="none" is left alone.

The source directory is only ever read. Re-running is idempotent.
"""
import glob, os, re, sys, json
import xml.etree.ElementTree as ET
from collections import defaultdict

SRC = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/Downloads/templates-user")
DST = os.path.expanduser(sys.argv[2] if len(sys.argv) > 2 else "~/Documents/Claude/Projects/XML Docker")

# ---------- host ----------
# Your Unraid host's LAN IP. Only used by the browser-facing entries in
# VALUE_OVERRIDES further down, which have to point at a host IP + host port
# rather than a container name (a browser is not on the docker network).
# Set it once here, or export UNRAID_HOST_IP to override without editing.
HOST_IP = os.environ.get('UNRAID_HOST_IP', '192.168.1.10')

# ---------- variable label map ----------
# Optional file of "RAW_ENV_VAR -> Human Label" lines. Blank lines and lines
# starting with # are ignored; an inline "# n uses" comment is stripped.
# Only the Name shown in the Unraid UI changes -- Target is never touched.
MAPFILE = os.path.expanduser(sys.argv[3]) if len(sys.argv) > 3 else None
def load_labels():
    for cand in filter(None, [MAPFILE,
                              os.path.join(DST, '_review-variable-renames.txt'),
                              os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           '_review-variable-renames.txt')]):
        if os.path.isfile(cand):
            m = {}
            for line in open(cand, encoding='utf-8'):
                line = line.strip()
                if not line or line.startswith('#') or '->' not in line:
                    continue
                raw, label = line.split('->', 1)
                m[raw.strip()] = label.split('#')[0].strip()
            return {k: v for k, v in m.items() if k and v}
    return {}
LABELS = load_labels()
VARPREFIX_KEEP = re.compile(r'^(?P<pre>Var(?:iable)?[\s0-9.]*:\s*)(?P<raw>\S+)$')

def relabel(name, target, ctype):
    """Swap a raw env-var label for its human form, preserving any 'Var NN:' prefix."""
    if ctype != 'Variable' or not LABELS:
        return name
    if name == target and name in LABELS:
        return LABELS[name]
    m = VARPREFIX_KEEP.match(name or '')
    if m and m.group('raw') in LABELS:
        return m.group('pre') + LABELS[m.group('raw')]
    return name


# ---------- element / attribute canonical order ----------
ELEM_ORDER = ["Name","Repository","Registry","Network","MyIP","Shell","Privileged",
              "Support","Project","ReadMe","Overview","Category","WebUI","TemplateURL",
              "Icon","ExtraParams","PostArgs","CPUset","DonateText","DonateLink","Requires"]
DROP_ELEMS = {"MyMAC","DateInstalled"}
TAIL_ELEMS = ["TailscaleStateDir"]
ATTR_ORDER = ["Name","Target","Default","Mode","Description","Type","Display","Required","Mask"]

# ---------- masking ----------
def norm(s):
    return re.sub(r'[_\-.]+', ' ', s or '')

MATCH = re.compile(r'(password|passwd|\bpwd\b|\bpass\b|secret|token|api ?key|\bkey\b|'
                   r'username|user ?name|\buser\b|credential|\bpin\b|client ?id|'
                   r'client ?secret|app ?id|app ?secret|\bsalt\b|\bcreds?\b)', re.I)
EXCL  = re.compile(r'(port|\burl\b|\buri\b|host|enabled?|timeout|attribute|scope|filter|'
                   r'version|\bpath\b|\bdir\b|directory|folder|level|method|provider|'
                   r'\btype\b|count|limit|interval|expiry|class|\bdn\b|allow|require|'
                   r'header|agent|keyboard|prefix|creation|signup|title|\bfile\b)', re.I)
TARGET_NEVER = {"PUID","PGID","UMASK","TZ","UID","GID"}
BOOLISH = {"true","false","yes","no","on","off"}
EMBED = re.compile(r'://[^/\s:@]+:[^/\s@]+@')
TAIL_TARGETS = ["PUID","PGID","UID","GID","UMASK","TZ"]

def should_mask(name, target, value, ctype, old_mask):
    if old_mask == "true":
        return True                      # never unmask what you already masked
    if EMBED.search(value or ""):
        return True                      # credential embedded in a connection string
    if ctype != "Variable":
        return False                     # only Variables can be masked
    if target in TARGET_NEVER:
        return False
    if (value or "").strip().lower() in BOOLISH:
        return False                     # a toggle that merely sounds secret
    n, t = norm(name), norm(target)
    if EXCL.search(n) or EXCL.search(t):
        return False
    return bool(MATCH.search(n) or MATCH.search(t))

# ---------- casing ----------
def smart_title(s):
    """Capitalise all-lowercase words, leave MixedCase/ALLCAPS alone."""
    out = []
    for w in (s or '').split(' '):
        if w and w.islower() and w[0].isalpha():
            out.append(w[0].upper() + w[1:])
        else:
            out.append(w)
    return ' '.join(out)

# ---------- name parsing for Paths / Ports ----------
PREFIX_RE = re.compile(
    r'^\s*(?:container\s+)?(?:host\s+)?(?:path|port)\s*'
    r'(?P<maj>\d+)?(?:\.(?P<min>\d+))?\s*[:.\-]?\s*(?P<rest>.*)$', re.I)

def parse_pathport(name, target, ctype):
    m = PREFIX_RE.match(name or '')
    maj = mn = None
    label = (name or '').strip()
    if m and (m.group('maj') is not None or (m.group('rest') is not None and
              re.match(r'^\s*(?:container\s+)?(?:host\s+)?(?:path|port)\b', name or '', re.I))):
        maj = int(m.group('maj')) if m.group('maj') else None
        mn  = int(m.group('min')) if m.group('min') else None
        label = (m.group('rest') or '').strip(' :.-')
    if not label:
        label = (target or '').strip('/').split('/')[-1] or (target or '')
    return maj, mn, smart_title(label)

def renumber(items, kind):
    """items: (maj, min, label, rec) in source order.

    A major number is only treated as a shared group when the source actually
    used dotted sub-numbering for it (Plex's Path 01.0/01.1/...). Plain majors
    each get their own sequential number, so duplicates in the source can never
    collide. Members of a group are emitted together, ordered by minor.
    """
    dotted = {maj for maj, mn, _, _ in items if mn is not None and maj is not None}
    seen, gid_of = {}, []
    for i, (maj, mn, lab, rec) in enumerate(items):
        key = ('m', maj) if (maj is not None and maj in dotted) else ('u', i)
        if key not in seen:
            seen[key] = len(seen) + 1
        gid_of.append(seen[key])
    rows = [(gid_of[i], items[i][1] if items[i][1] is not None else -1, i, items[i])
            for i in range(len(items))]
    rows.sort(key=lambda r: (r[0], r[1], r[2]))
    out = []
    for gid, _, _, (maj, mn, lab, rec) in rows:
        num = f"{gid:02d}" + (f".{mn}" if mn is not None else "")
        out.append((f"{kind} {num}: {lab}", rec))
    return out

# ---------- variable sub-group tightening ----------
VARPREFIX = re.compile(r'^\s*(?:var(?:iable)?\s*\d*\s*[:.\-]\s*)', re.I)
def group_key(name):
    n = VARPREFIX.sub('', name or '').strip()
    n = re.sub(r'[_\-.]+', ' ', n).strip()
    first = n.split(' ')[0].lower() if n else ''
    return first


# ---------- prose litter ----------
# Unraid stores prose double-encoded (xml_encode on save, xml_decode on read, on top
# of the XML parser's own layer), so "&amp;nbsp;" here really is a non-breaking space
# and "&amp;amp;" really is a literal "&". Neither is a bug -- do not touch the escaping.
#
# What IS litter: bare "br" tokens (a <br> that lost its angle brackets and now renders
# as the word "br"), and runs of &nbsp; used as fake indentation that upstream templates
# never had. Every rule below is deliberately narrow, because plenty of real content
# contains the letters "br": browser, browsable, Calibre, LibreOffice, library, breaking,
# bridge, brilliant, "cbr/cbz", the "br0" bridge interface, and even a Pangolin CDN URL
# containing "gbrTU0". Those must all survive.
NB = '&amp;nbsp;'
BR_WORDS = ('browserless', 'browser', 'browsers', 'browsable', 'browse', 'browsing',
            'browsed', 'bridge', 'bridges', 'breaking', 'brilliant', 'brief', 'briefly',
            'brand', 'branch')
_BR_START     = re.compile(r'^(?:br)+(?![a-z])')
_BR_BEFORE_NB = re.compile(r'(?:br)+(?=' + re.escape(NB) + r')')
_BR_AFTER_NB  = re.compile(r'(?<=' + re.escape(NB) + r')(?:br)+')
_BR_LINE      = re.compile(r'(?<=\n)(?:br)+(?![a-z])')
_BR_INLINE    = re.compile(r'(?<=[a-z.,;:)])(?:br)+(?=[A-Z])')
_BR_SLASH     = re.compile(r'(?<=[.,;:)])(?:br)+\s*/(?![a-zA-Z])(\s?)')
_BR_LINE_LC   = re.compile(r'(?:(?<=\n)|^)(?:br)+(?=[a-z])')
_NB_RUN       = re.compile(r'(?:' + re.escape(NB) + r')+')

def _line_lc(m, text):
    """Line-initial "br" before a lowercase word: litter, unless the word really
    does start with "br" (a line beginning "browserless is a web-service...")."""
    tail = re.match(r'[a-z]+', text[m.end():])
    word = (m.group(0) + (tail.group(0) if tail else '')).lower()
    return m.group(0) if word.startswith(BR_WORDS) else ''

def strip_br_litter(t):
    if not t or ('br' not in t and NB not in t):
        return t
    t = _BR_START.sub('', t)
    t = _BR_BEFORE_NB.sub('', t)
    t = _BR_AFTER_NB.sub('', t)
    t = _BR_LINE.sub('', t)
    t = _BR_INLINE.sub('\n', t)                       # a <br> joining two sentences
    # "br/" after punctuation: drop it if a real newline already follows, else become one
    t = _BR_SLASH.sub(lambda m: m.group(1) if m.group(1) in ('\r', '\n') else '\n', t)
    out, last = [], 0
    for m in _BR_LINE_LC.finditer(t):
        out.append(t[last:m.start()]); out.append(_line_lc(m, t)); last = m.end()
    out.append(t[last:]); t = ''.join(out)
    t = _NB_RUN.sub('', t)                             # fake indentation, always leading
    return t

def dedupe_names(recs):
    """Disambiguate Configs that ended up sharing a Name, using their Targets."""
    seen, n = {}, 0
    for r in recs:
        key = r['Name']
        if key not in seen:
            seen[key] = r
            continue
        base = set(re.split(r'[_\-.\s]+', (seen[key]['Target'] or '').upper()))
        mine = [w for w in re.split(r'[_\-.\s]+', (r['Target'] or '').upper()) if w and w not in base]
        if mine:
            r['Name'] = f"{key} ({' '.join(w.capitalize() for w in mine)})"
            n += 1
    return n


# ---------- Postgres healthcheck ----------
# Unraid interpolates ExtraParams into the docker command RAW (Helpers.php:575, no
# escapeshellarg) and runs it via popen() -> /bin/sh. So a double-quoted --health-cmd
# gets $POSTGRES_USER expanded on the HOST, where it is empty. Single quotes defer
# expansion to the container, which is where the variable actually exists.
PG_REPO = re.compile(r'postgres|pgvector', re.I)
PG_HEALTHCHECK = ("--health-cmd='pg_isready -U $POSTGRES_USER -d $POSTGRES_DB' "
                  "--health-interval=60s --health-start-period=30s")
_HEALTH_FLAG = re.compile(
    r"""--health-[a-z-]+=(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)\s*""")

VALKEY_REPO = re.compile(r'valkey', re.I)
VALKEY_HEALTHCHECK_PW = ("--health-cmd='REDISCLI_AUTH=$VALKEY_PASSWORD valkey-cli ping | grep -q PONG' "
                         "--health-interval=60s --health-start-period=15s")
VALKEY_HEALTHCHECK_NOPW = ("--health-cmd='valkey-cli ping | grep -q PONG' "
                           "--health-interval=60s --health-start-period=15s")

def strip_health(extra):
    return _HEALTH_FLAG.sub('', extra or '').strip()

BAZARR_REPO = re.compile(r'bazarr', re.I)

BROWSERLESS_REPO = re.compile(r'browserless', re.I)

def set_browserless_healthcheck(repo, extra, configs):
    """browserless: use /pressure, its purpose-built health/load endpoint, present in
    both v1 and v2 and verified returning 200 on the live container.

    NOT /active -- that route is v2-only and 404s on browserless/chrome (v1), which is
    what is deployed here. Checking / would also work (verified 200), but /pressure
    reports the service's actual serving state rather than just that HTTP is answering.
    Plain 200 check only: /pressure returns isAvailable=false when merely at capacity,
    which is busy, not unhealthy. Note v2 (ghcr.io/browserless/chromium) requires a token
    on this route, so a move to v2 with TOKEN set would need ?token=... appended."""
    if not BROWSERLESS_REPO.search(repo or ''):
        return extra, False
    ports = [c.get('Target') for c in configs
             if c.get('Type') == 'Port' and (c.get('Target') or '').isdigit()]
    if len(ports) != 1:
        return extra, False
    hc = (f"--health-cmd='curl -fsS -o /dev/null --max-time 5 "
          f"http://localhost:{ports[0]}/pressure || exit 1' "
          "--health-interval=60s --health-start-period=30s")
    rest = strip_health(extra)
    new = (rest + ' ' + hc).strip() if rest else hc
    return new, new != (extra or '')

def set_bazarr_healthcheck(repo, name, extra, configs):
    """Bazarr's ping endpoint is /api/system/ping, not /ping -- it is a Flask app, not a
    Servarr .NET one, and its whole API sits behind a /api blueprint prefix. The bare
    /ping the templates used returned 404, which -fSs turned into a permanent unhealthy.
    The endpoint is documented as unauthenticated, so -f is meaningful here.
    localhost, not the container's own name: these are hotio VPN-capable images, and with
    VPN_ENABLED=true a name-based URL would route out through the tunnel. User-verified."""
    # Match on the REPOSITORY only, never the container Name: "Bazarr-PostgreSQL16" is a
    # postgres image whose name merely starts with Bazarr, and matching on name clobbered
    # its pg_isready healthcheck.
    if not BAZARR_REPO.search(repo or ''):
        return extra, False
    ports = [c.get('Target') for c in configs
             if c.get('Type') == 'Port' and (c.get('Target') or '').isdigit()]
    if len(ports) != 1:
        return extra, False
    hc = (f"--health-cmd='curl -fSs http://localhost:{ports[0]}/api/system/ping || exit 1' "
          "--health-interval=60s --health-start-period=60s")
    rest = strip_health(extra)
    new = (rest + ' ' + hc).strip() if rest else hc
    return new, new != (extra or '')

def set_valkey_healthcheck(repo, name, extra, configs):
    """Valkey containers get an authenticated check when a non-empty VALKEY_PASSWORD
    is set, and a plain unauthenticated one otherwise. The authenticated form names
    that exact variable, so using it without the variable would silently fail."""
    if not VALKEY_REPO.search((repo or '') + ' ' + (name or '')):
        return extra, False, None
    has_pw = any((c.get('Target') or '') == 'VALKEY_PASSWORD' and (c.text or '').strip()
                 for c in configs)
    hc = VALKEY_HEALTHCHECK_PW if has_pw else VALKEY_HEALTHCHECK_NOPW
    rest = strip_health(extra)
    new = (rest + ' ' + hc).strip() if rest else hc
    return new, new != (extra or ''), has_pw

def set_pg_healthcheck(repo, extra):
    if not PG_REPO.search(repo or ''):
        return extra, False
    rest = _HEALTH_FLAG.sub('', extra or '').strip()
    new = (rest + ' ' + PG_HEALTHCHECK).strip() if rest else PG_HEALTHCHECK
    return new, new != (extra or '')


# ---------- explicit per-file corrections ----------
# Deliberate fixes agreed with the user, applied on every run so they survive
# regeneration from the (unmodified) source templates.

# <Network> typo: every other template uses "dockernetwork". A container on
# "dockernet" would sit alone on a second network and resolve nothing by name.
NETWORK_FIX = {'my-Home-FMD_Server.xml': ('dockernet', 'dockernetwork')}

# Host-port reassignments to clear collisions. Keyed by file, then by the ORIGINAL
# host port, so the mapping is idempotent and obvious. Container ports are untouched.
PORT_OVERRIDES = {
    'my-Argus-GarageS3Tailscale.xml': {'9001': '9011', '3901': '3911',
                                       '3902': '3912', '3903': '3913'},
    'my-SparkyFitness-Frontend.xml':  {'3004': '3030'},
    'my-SparkyFitness-Backend.xml':   {'3010': '3031'},
    'my-SparkyFitness-Garmin.xml':    {'8003': '8006'},
    'my-Home-FMD_Server.xml':         {'8097': '8102'},
    'my-Broken-Tool-Databag.xml':     {'7000': '7002'},
    'my-Broken-Helparr-Shelfmark.xml':{'8093': '8103'},
}

# Variable corrections, verified against the SparkyFitness docs and source:
#   SPARKY_FITNESS_SERVER_PORT - the BACKEND's port, used by the frontend's internal
#     nginx proxy. Container-to-container, so it is the container port 3010, not a
#     host port. It was 3004, the frontend's own host port.
#   GARMIN_SERVICE_PORT - passed to uvicorn as --port (start_garmin_microservice.sh),
#     i.e. the port the service listens on INSIDE the container. It was 8003 while the
#     container published 8000, so nothing could reach it.
#   GARMIN_MICROSERVICE_URL - docs say pass the same container-name URL to both the
#     server and the garmin service. The backend already uses the correct form.
#   SPARKY_FITNESS_FRONTEND_URL - browser-facing, so host IP + host port. It pointed at
#     3024, which belongs to AI-Browserless. The host IP comes from HOST_IP
#     at the top of this file.
VALUE_OVERRIDES = {
    'my-SparkyFitness-Frontend.xml': {
        'SPARKY_FITNESS_SERVER_PORT':  ('3004', '3010'),
        'SPARKY_FITNESS_FRONTEND_URL': (f'http://{HOST_IP}:3024', f'http://{HOST_IP}:3030'),
    },
    'my-SparkyFitness-Backend.xml': {
        'SPARKY_FITNESS_FRONTEND_URL': (f'http://{HOST_IP}:3024', f'http://{HOST_IP}:3030'),
    },
    'my-SparkyFitness-Garmin.xml': {
        'GARMIN_SERVICE_PORT':     ('8003', '8000'),
        'GARMIN_MICROSERVICE_URL': (f'http://{HOST_IP}:8003', 'http://SparkyFitness-Garmin:8000'),
    },
}


# Containers where the local template sets Privileged=true but the UPSTREAM template
# does not. Verified against each template's own TemplateURL:
#   Duplicati  linuxserver          -> false
#   Dozzle     selfhosters          -> no <Privileged> element at all (defaults false)
#   Beszel     JamsRepos            -> false
#   NPM        mgutt                -> false
# Left privileged deliberately: DiskSpeed and Scrutiny genuinely need raw device access
# (Scrutiny also mounts /run/udev and /dev/disk read-only for SMART), and Authentik,
# PhantomBot, Krusader and ownCloud are set true by their own upstream templates.
UNPRIVILEGE = {
    'my-Dev-DL-Duplicati.xml',
    'my-Dev-Log-Dozzle.xml',
    'my-Log-Beszel.xml',
    'my-Net-NPM.xml',
}

def apply_override(fname, ctype, target, value):
    """Return the corrected value, or the original if no correction applies.
    Each override names the expected current value, so a source change upstream
    makes the override silently stop matching rather than clobbering new data."""
    if ctype == 'Port':
        want = PORT_OVERRIDES.get(fname, {}).get(value)
        if want: return want, True
    else:
        pair = VALUE_OVERRIDES.get(fname, {}).get(target)
        if pair and value == pair[0]: return pair[1], True
    return value, False


# ---------- healthchecks for containers that have none ----------
# Probed every image in the set against its registry (config blob -> .config.Healthcheck):
# 29 images already define their own HEALTHCHECK. Passing --health-cmd on `docker run`
# OVERRIDES the image's built-in one, so those are left strictly alone -- several
# (authentik's `ak healthcheck`, Mealie's and Jellyfin's scripts, Uptime Kuma's
# extra/healthcheck) are better than anything generic.
BUILTIN_HEALTHCHECK = {
    'bellamy/wallos', 'binhex/arch-code-server', 'binhex/arch-krusader',
    'binhex/arch-nginx', 'binhex/arch-pycharm', 'carrotwaxr/peek-stash-browser',
    'clusterzx/paperless-ai', 'codewithcj/sparkyfitness', 'codewithcj/sparkyfitness_server',
    'databasus/databasus', 'dialmaster/youtarr', 'donetick/donetick',
    'dumbwareio/dumbwhois', 'ghcr.io/calibrain/shelfmark', 'ghcr.io/goauthentik/server',
    'ghcr.io/linkwarden/linkwarden', 'ghcr.io/mealie-recipes/mealie',
    'ghcr.io/open-webui/open-webui', 'ghcr.io/paperless-ngx/paperless-ngx',
    'ghcr.io/phantombot/phantombot', 'ghcr.io/silo-server/silo-server',
    'gtstef/filebrowser', 'jellyfin/jellyfin', 'localai/localai',
    'louislam/uptime-kuma', 'lukevella/rallly', 'nodered/node-red',
    'stirlingtools/stirling-pdf', 'vaultwarden/server',
}
# Bazarr is deliberately NOT here: it is a separate Flask project with no /ping.
# Its endpoint is /api/system/ping -- see set_bazarr_healthcheck below.
SERVARR = re.compile(r'(sonarr|radarr|whisparr|lidarr|readarr|prowlarr)', re.I)
WEBUI_PORT = re.compile(r'\[PORT:(\d+)\]')

# <WebUI> referenced [PORT:8090] but only 8080/8096/13378 are declared, so the WebUI
# button pointed at nothing. The image's own healthcheck confirms 8080 is the web port.
WEBUI_FIX = {'my-Silo-Silo.xml': ('http://[IP]:[PORT:8090]', 'http://[IP]:[PORT:8080]')}

def build_healthcheck(fname, repo, name, webui, extra, configs):
    """Add a healthcheck only where there is none, the image defines none, and the
    WebUI port is a port the container actually declares."""
    if '--health-cmd' in (extra or ''):
        return extra, None
    base = (repo or '').split(':')[0]
    if base in BUILTIN_HEALTHCHECK:
        return extra, 'builtin'
    m = WEBUI_PORT.search(webui or '')
    if not m:
        return extra, 'no-webui-port'
    port = m.group(1)
    declared = {c.get('Target') for c in configs if c.get('Type') == 'Port'}
    if port not in declared:
        return extra, 'port-not-declared'
    if SERVARR.search(base) or SERVARR.search(name or ''):
        cmd, kind = f"curl -fSs http://localhost:{port}/ping || exit 1", 'servarr'
    elif port == '32400' and 'plex' in base.lower():
        cmd, kind = ("curl --connect-timeout 15 --silent --show-error --fail "
                     "http://localhost:32400/identity || exit 1"), 'plex'
    else:
        # Deliberately no curl -f: many apps answer / with 401/403 when auth is on, and
        # a false "unhealthy" is worse than a slightly weaker check. This proves the app
        # is listening and speaking HTTP. wget covers images that ship no curl.
        cmd, kind = (f"curl -sS -o /dev/null --max-time 5 http://localhost:{port}/ "
                     f"|| wget -q -T 5 -O /dev/null http://localhost:{port}/ || exit 1"), 'generic'
    hc = f"--health-cmd='{cmd}' --health-interval=60s --health-start-period=30s"
    rest = strip_health(extra)
    return ((rest + ' ' + hc).strip() if rest else hc), kind

# ---------- serialisation ----------
def esc_text(s):
    # A literal CR in element content is silently normalised to LF by any XML
    # parser, so it has to be written as a character reference or the output is
    # not idempotent (several <Requires> blocks carry stray carriage returns).
    return ((s or '').replace('&','&amp;').replace('<','&lt;')
                     .replace('>','&gt;').replace('\r','&#13;'))
def esc_attr(s):
    return esc_text(s).replace('"','&quot;').replace('\n','&#10;').replace('\r','&#13;')

def tidy_overview(s):
    if not s: return s
    s = s.replace('\r\n','\n').replace('\r','\n')
    lines = [l.strip() for l in s.split('\n')]
    out, blank = [], False
    for l in lines:
        if not l:
            if out and not blank: out.append('')
            blank = True
        else:
            out.append(l); blank = False
    return '\n'.join(out).strip()

PORT_DESC_OK = re.compile(r'^[^.]*\.?$')

stats = defaultdict(int)
masked_report, renamed_report = [], []

def process(path):
    tree = ET.parse(path)
    root = tree.getroot()
    fname = os.path.basename(path)

    # --- scalar elements ---
    scalars = {}
    for e in list(root):
        if e.tag == 'Config':
            continue
        if e.tag in DROP_ELEMS:
            stats['dropped_elems'] += 1
            continue
        txt = e.text or ''
        if e.tag in ('Overview', 'Requires', 'DonateText'):
            new = strip_br_litter(txt)
            if new != txt: stats['br_litter_removed'] += 1
            txt = new
        if e.tag == 'Overview':
            new = tidy_overview(txt)
            if new != txt: stats['overview_tidied'] += 1
            txt = new
        scalars[e.tag] = txt

    if fname in UNPRIVILEGE and scalars.get('Privileged','').lower() == 'true':
        scalars['Privileged'] = 'false'
        stats['privilege_dropped'] += 1

    nf = NETWORK_FIX.get(fname)
    if nf and scalars.get('Network') == nf[0]:
        scalars['Network'] = nf[1]
        stats['network_fixed'] += 1

    newep, changed = set_pg_healthcheck(scalars.get('Repository',''), scalars.get('ExtraParams',''))
    if changed:
        scalars['ExtraParams'] = newep
        stats['pg_healthcheck_set'] += 1

    newep, changed = set_browserless_healthcheck(scalars.get('Repository',''),
                                                 scalars.get('ExtraParams',''), root.findall('Config'))
    if changed:
        scalars['ExtraParams'] = newep
        stats['browserless_healthcheck_set'] += 1

    newep, changed = set_bazarr_healthcheck(scalars.get('Repository',''), scalars.get('Name',''),
                                            scalars.get('ExtraParams',''), root.findall('Config'))
    if changed:
        scalars['ExtraParams'] = newep
        stats['bazarr_healthcheck_set'] += 1

    wf = WEBUI_FIX.get(fname)
    if wf and scalars.get('WebUI') == wf[0]:
        scalars['WebUI'] = wf[1]
        stats['webui_fixed'] += 1

    newep, changed, vk_pw = set_valkey_healthcheck(scalars.get('Repository',''), scalars.get('Name',''),
                                                  scalars.get('ExtraParams',''), root.findall('Config'))
    if changed:
        scalars['ExtraParams'] = newep
        stats['valkey_healthcheck_authed' if vk_pw else 'valkey_healthcheck_plain'] += 1

    newep, kind = build_healthcheck(fname, scalars.get('Repository',''), scalars.get('Name',''),
                                    scalars.get('WebUI',''), scalars.get('ExtraParams',''),
                                    root.findall('Config'))
    if kind in ('servarr', 'plex', 'generic'):
        scalars['ExtraParams'] = newep
        stats['hc_' + kind] += 1
    elif kind:
        stats['hc_skipped_' + kind.replace('-', '_')] += 1

    ports, paths, devices, labels, variables, tail = [], [], [], [], [], []

    for c in root.findall('Config'):
        name  = c.get('Name','') or ''
        tgt   = c.get('Target','') or ''
        dflt  = c.get('Default','') or ''
        mode  = c.get('Mode','') or ''
        desc  = strip_br_litter(c.get('Description','') or '')
        if desc != (c.get('Description','') or ''): stats['description_litter_removed'] += 1
        ctype = c.get('Type','Variable') or 'Variable'
        disp  = c.get('Display','always') or 'always'
        req   = c.get('Required','false') or 'false'
        mask  = c.get('Mask','false') or 'false'
        val   = (c.text or '').strip()

        val, overridden = apply_override(fname, ctype, tgt, val)
        if overridden: stats['override_applied'] += 1

        if req == 'true': stats['required_cleared'] += 1
        if mask in ('null','{8}'): stats['bad_mask_fixed'] += 1

        newmask = should_mask(name, tgt, val, ctype, mask)
        if newmask and mask != 'true':
            stats['newly_masked'] += 1
            masked_report.append((fname, name, tgt))

        # Default
        if newmask:
            newdflt = ''
            if dflt and EMBED.search(val or '') and dflt != val:
                # keep a Default that documents the URL shape, provided it does not
                # itself carry the live credential
                m = EMBED.search(val)
                cred = m.group(0)[3:-1] if m else None      # "user:pass"
                secret = cred.split(':', 1)[1] if cred and ':' in cred else None
                if not (secret and secret in dflt):
                    newdflt = dflt
                    stats['placeholder_default_kept'] += 1
            if dflt and not newdflt: stats['default_blanked_masked'] += 1
        elif '|' in dflt:
            newdflt = dflt                          # Unraid dropdown option-list
        else:
            newdflt = val
            if dflt != val: stats['default_synced'] += 1

        # Mode
        if ctype == 'Variable':
            if mode: stats['mode_cleared'] += 1
            newmode = ''
        elif ctype == 'Path':
            newmode = mode if mode in ('rw','ro','rw,slave','rslave','rshared') else 'rw'
        elif ctype == 'Port':
            newmode = mode if mode in ('tcp','udp') else 'tcp'
        else:
            newmode = mode

        # Display: unlock every locked field. "-hide" makes Unraid render the
        # field read-only, so it can be neither edited nor cleared.
        # Display="none" is left alone (deliberately absent from the UI).
        newdisp = disp
        if disp.endswith('-hide'):
            newdisp = disp[:-len('-hide')]
            stats['unhidden_' + ctype.lower()] += 1

        # Description tidy for short Port descriptions
        newdesc = desc
        if ctype == 'Port' and desc:
            d = desc.strip()
            if len(d.split()) <= 5 and d.count('.') <= 1 and d.endswith('.'):
                d = d[:-1]
            if len(d.split()) <= 5 and '.' not in d:
                newdesc = smart_title(d)

        # relabel AFTER the mask decision, which keys off the original name
        newname = relabel(name, tgt, ctype)
        if newname != name: stats['relabelled'] += 1

        rec = dict(Name=newname, Target=tgt, Default=newdflt, Mode=newmode,
                   Description=newdesc, Type=ctype, Display=newdisp,
                   Required='false', Mask='true' if newmask else 'false', _value=val)

        if ctype == 'Port':
            maj, mn, lab = parse_pathport(name, tgt, ctype)
            ports.append((maj, mn, lab, rec))
        elif ctype == 'Path':
            maj, mn, lab = parse_pathport(name, tgt, ctype)
            paths.append((maj, mn, lab, rec))
        elif ctype == 'Device':
            devices.append(rec)
        elif ctype == 'Label':
            labels.append(rec)
        else:
            if tgt in TAIL_TARGETS:
                tail.append(rec)
            else:
                variables.append(rec)

    # rename + renumber Ports and Paths
    ordered = []
    for newname, rec in renumber(ports, 'Port'):
        if rec['Name'] != newname:
            stats['renamed'] += 1; renamed_report.append((fname, rec['Name'], newname))
        rec['Name'] = newname; ordered.append(rec)
    for newname, rec in renumber(paths, 'Path'):
        if rec['Name'] != newname:
            stats['renamed'] += 1; renamed_report.append((fname, rec['Name'], newname))
        rec['Name'] = newname; ordered.append(rec)
    ordered += devices

    # tighten variable sub-groups (stable: group order = first appearance)
    firstidx = {}
    for i, r in enumerate(variables):
        k = group_key(r['Name'])
        firstidx.setdefault(k, i)
    variables = [r for _, r in sorted(
        ((( firstidx[group_key(r['Name'])], i), r) for i, r in enumerate(variables)),
        key=lambda p: p[0])]
    ordered += variables + labels

    tail.sort(key=lambda r: TAIL_TARGETS.index(r['Target']) if r['Target'] in TAIL_TARGETS else 99)
    ordered += tail

    d = dedupe_names(ordered)
    if d: stats['names_disambiguated'] += d

    # --- write ---
    L = ['<?xml version="1.0"?>', f'<Container version="{root.get("version","2")}">']
    def emit(tag, txt):
        if txt is None or txt == '':
            L.append(f'  <{tag}/>')
        else:
            L.append(f'  <{tag}>{esc_text(txt)}</{tag}>')
    for tag in ELEM_ORDER:
        if tag in scalars: emit(tag, scalars[tag])
    for tag in scalars:                       # anything unexpected, preserved
        if tag not in ELEM_ORDER and tag not in TAIL_ELEMS: emit(tag, scalars[tag])
    for rec in ordered:
        attrs = ' '.join(f'{k}="{esc_attr(rec[k])}"' for k in ATTR_ORDER)
        v = rec['_value']
        L.append(f'  <Config {attrs}/>' if v == '' else f'  <Config {attrs}>{esc_text(v)}</Config>')
    for tag in TAIL_ELEMS:
        if tag in scalars: emit(tag, scalars[tag])
    L.append('</Container>')
    L.append('')
    with open(os.path.join(DST, fname), 'w', encoding='utf-8') as f:
        f.write('\n'.join(L))
    stats['files'] += 1

os.makedirs(DST, exist_ok=True)
for p in sorted(glob.glob(os.path.join(SRC, '*.xml'))):
    try:
        process(p)
    except Exception as e:
        print(f"!! FAILED {os.path.basename(p)}: {e}", file=sys.stderr)
        stats['failed'] += 1

print(json.dumps(dict(stats), indent=2))
with open(os.path.join(DST, '_report-masked.txt'),'w') as f:
    for r in masked_report: f.write(' | '.join(r)+'\n')
with open(os.path.join(DST, '_report-renamed.txt'),'w') as f:
    for r in renamed_report: f.write(' | '.join(r)+'\n')
