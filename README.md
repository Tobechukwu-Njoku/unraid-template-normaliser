# Unraid Template Normaliser

Cleans and normalises Unraid dockerMan user templates (`my-*.xml`) — the XML files
Unraid writes to `/boot/config/plugins/dockerMan/templates-user/` for every container
you add.

Templates accumulate cruft: inconsistent element order, unlabelled raw env vars,
duplicate `Path`/`Port` numbering, `Required="true"` fields you can't clear,
`-hide` display flags that lock a field read-only, `<br>` tags that lost their angle
brackets and now render as the word "br", and credentials sitting unmasked in the UI.
This script rewrites a whole directory of them into one consistent, idempotent form.

Pure Python 3 standard library — no dependencies.

## Usage

```bash
python3 normalise-unraid-templates.py [SRC_DIR] [DST_DIR] [LABEL_MAP]
```

- `SRC_DIR` — templates to read. **Only ever read, never modified.**
  Default `~/Downloads/templates-user`.
- `DST_DIR` — where normalised copies are written (overwritten). Default
  `~/Documents/Claude/Projects/XML Docker`.
- `LABEL_MAP` — optional; defaults to `_review-variable-renames.txt` beside the script.

Set `HOST_IP` at the top of the script to your Unraid host's LAN IP, or export
`UNRAID_HOST_IP` to override it without editing:

```bash
UNRAID_HOST_IP=192.168.1.50 python3 normalise-unraid-templates.py ~/templates-user ~/templates-clean
```

It is only used by the browser-facing entries in `VALUE_OVERRIDES`, which have to name a
host IP and host port rather than a container name — a browser isn't on the docker
network.

Copy your templates off the Unraid flash drive first, run against that copy, review the
diff, then copy back. Re-running on its own output is a no-op.

A JSON summary of every change is printed to stdout, plus two reports written to
`DST_DIR`: `_report-masked.txt` (variables newly masked) and `_report-renamed.txt`
(paths and ports renumbered).

## What it does

**Structure** — elements emitted in Unraid's canonical order; `<Config>` attributes in
the order `Name, Target, Default, Mode, Description, Type, Display, Required, Mask`.
`<DateInstalled>` and `<MyMAC>` dropped, `<MyIP>` kept. `<Overview>` whitespace
collapsed.

**Config blocks** — reordered to Ports, Paths, Devices, Variables, Labels, with
`PUID`/`PGID`/`UID`/`GID`/`UMASK`/`TZ` pinned last. Related variables are grouped by
first-word key while preserving first-appearance order. Paths and ports are renamed to
`Path NN: Label` / `Port NN: Label`, title-cased, with dotted sub-numbering
(`Path 04.0`, `04.1`) preserved where the source used it.

**Labels** — raw env-var names shown in the UI (`VPN_PIA_USER`) are swapped for human
ones via `_review-variable-renames.txt`. Edit the right-hand side to change a label,
delete a line to skip that variable. `Target` is never changed.

**Masking** — `Mask="true"` is set on credentials, tokens and keys by matching the field
name against a keyword list, with an exclusion list so `PORT`, `URL`, `HOST`, `TYPE` and
friends are never masked. The live value is kept; the `Default` is blanked instead,
because Unraid's mask doesn't cover Defaults. Boolean-valued fields are never masked,
and a field already masked is never unmasked. A `Default` that merely documents a
connection-string *shape* is kept.

**Attributes** — `Required="false"` on everything; `Default` synced to the live value
(dropdown option-lists left intact); `Mask="null"` / `Mask="{8}"` → `"false"`;
`-hide` display suffixes stripped so no field is locked read-only.

**Health checks** — adds `--health-cmd` to containers that have none, skipping the 29
images that define their own `HEALTHCHECK` (passing `--health-cmd` on `docker run`
overrides the image's built-in one). Purpose-built checks for Postgres/pgvector, Valkey
(authenticated when `VALKEY_PASSWORD` is set), Bazarr (`/api/system/ping`, not `/ping`),
browserless (`/pressure`), Servarr apps (`/ping`) and Plex (`/identity`), with a generic
HTTP check otherwise.

One subtlety worth knowing if you write your own: Unraid interpolates `ExtraParams` into
the docker command raw and runs it through `/bin/sh`, so a **double**-quoted
`--health-cmd` gets `$POSTGRES_USER` expanded on the host, where it's empty. Single
quotes defer expansion to the container.

## Site-specific overrides

`PORT_OVERRIDES`, `VALUE_OVERRIDES`, `NETWORK_FIX`, `WEBUI_FIX` and `UNPRIVILEGE` near
the middle of the script are **my** corrections for **my** containers, keyed by template
filename (and, for the browser-facing URLs, your `HOST_IP`). They're included as
worked examples of the pattern — each override names the
expected current value, so it stops matching rather than clobbering data if the source
changes upstream. Delete them or replace them with your own; they simply don't fire on
filenames you don't have.

## Licence

MIT
