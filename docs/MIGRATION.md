# Repository migration: 30,241 files → 88

## What was wrong

The `haafiz-ai` repository tracked **30,241 files** and **~1 GB** of working tree,
with a `.git` directory of **336 MB**. Of those, **30,151 files (99.7%) were not
project code.**

| Category | Files | Largest examples |
|---|---|---|
| `ai-service/venv/` | 10,344 | `cv2/cv2.pyd` (69 MB), `playwright/driver/node.exe` (67 MB), `libopenblas64.dll` (37 MB), `opencv_videoio_ffmpeg481_64.dll` (26 MB), `libscipy_openblas.dll` (20 MB) |
| `frontend/node_modules/` + `backend/node_modules/` | 19,796 | `esbuild.exe` (9.5 MB), `tailwindcss/peers/index.js` (4.3 MB), `lucide-react` source maps (3.5 MB each), `sqlite-autoconf.tar.gz` (3.1 MB) |
| Installers | 2 | `python-3.11.9-amd64.exe` (26 MB), `VC_redist.x64.exe` (25 MB) |
| Archive | 1 | `Grand_Final_v5_0_fixed.zip` (51 MB) |
| Bytecode | 5 | `__pycache__/*.cpython-312.pyc` |
| Database | 1 | `backend/haafiz.db` (110 KB) — **see SECURITY.md** |
| Environment | 2 | `backend/.env`, `frontend/.env` — **see SECURITY.md** |

**Actual project code: 88 files, ~5,000 lines.**

### Concrete consequences

1. **GitHub language statistics were fiction.** The repo reported C, Cython, C++,
   Fortran, CUDA, Go Template, Smarty, Roff, Meson, Assembly and Jupyter as
   project languages — all from vendored `site-packages`. Python showed as 93 MB
   against a genuine ~5,000-line codebase. Anyone evaluating the project saw the
   wrong thing entirely.

2. **Cloning was slow and CI was impossible.** No CI system will happily check out
   336 MB of history containing 30,000 files. This is a large part of why the
   project had no CI, no tests, and no deployment path.

3. **Dependency updates were invisible.** Vendoring `venv/` means `requirements.txt`
   and the actual installed packages could drift silently, and no tool could tell
   you which was authoritative.

4. **Windows-only binaries.** The committed `.dll`, `.pyd` and `.exe` files made the
   repository unbuildable on Linux and macOS — blocking Docker, cloud deployment,
   and every non-Windows contributor. The only run script was `start-haafiz.bat`.

5. **Secrets and user data were public.** See `docs/SECURITY.md`.

---

## How it was fixed

### Step 1 — identify genuine source

```bash
cd haafiz-ai-src
git ls-files \
  | grep -vE "venv/|node_modules/|__pycache__|\.pyc$|\.exe$|\.zip$|\.dll$|\.db$|\.env$|package-lock" \
  > /tmp/keep.txt

wc -l /tmp/keep.txt     # 88
```

### Step 2 — copy only those files

```bash
tar -cf - -T /tmp/keep.txt | (cd /home/user/dhr && tar -xf -)
```

### Step 3 — verify

```bash
find . -path ./.git -prune -o -type f -print | wc -l   # 88
du -sh .                                                # 550 KB
```

**Result: 1 GB → 550 KB. 30,241 files → 88. A 99.95% reduction.**

`package-lock.json` files were excluded from this pass because they were
intertwined with the vendored `node_modules`; they should be **regenerated** with
`npm install` against the declared `package.json` dependencies rather than
carried over, so the lockfile reflects a clean install.

### Step 4 — write a .gitignore that actually holds

The old `.gitignore` already contained `venv/`, `node_modules/`, `__pycache__/`,
`*.pyc`, `.env` and `*.db`. **It failed anyway**, because of a rule that is easy
to miss:

> `.gitignore` only affects **untracked** files. Once a path is in the index, git
> commits changes to it forever, no matter what any ignore file says.

The new `.gitignore` documents this explicitly and adds installers, archives,
shared libraries, model artifacts, media, editor cruft and build output. It also
uses `!.env.example` so the template is tracked while real environment files are
not — a negation that only works because `.env` is excluded by pattern rather than
by a broader rule.

### Step 5 — verify nothing sensitive remains

```bash
git ls-files | grep -E "\.env$|\.db$|\.exe$|\.zip$|\.dll$|\.pyc$|venv/|node_modules/"
# (must print nothing)
```

---

## What still must be done to the ORIGINAL repository

This migration produced a clean tree **in this repository**. The original
`haafiz-ai` repo still has the problems, including in its **history**, which a
new commit does not fix.

To clean `haafiz-ai` itself:

```bash
# 1. Remove vendored paths and secrets from history (not just the tip)
pip install git-filter-repo

git filter-repo --invert-paths \
  --path ai-service/venv \
  --path backend/node_modules \
  --path frontend/node_modules \
  --path ai-service/python-3.11.9-amd64.exe \
  --path ai-service/VC_redist.x64.exe \
  --path ai-service/Grand_Final_v5_0_fixed.zip \
  --path backend/.env \
  --path frontend/.env \
  --path backend/haafiz.db \
  --path-glob '**/__pycache__/**' \
  --path-glob '**/*.pyc'

# 2. Reclaim space
git reflog expire --expire=now --all && git gc --prune=now --aggressive

# 3. Force-push and have every collaborator re-clone
git push --force --all && git push --force --tags
```

> ⚠️ `git filter-repo` rewrites commit hashes. Coordinate with collaborators
> first — anyone with an existing clone must re-clone rather than pull.
>
> ⚠️ Force-pushing does **not** undo existing clones, forks, mirrors, GitHub's
> cached views, or archive services. Rotating the leaked `JWT_SECRET` and forcing
> password resets remain necessary regardless. See `docs/SECURITY.md`.

---

## Prevention

Added to CI so this cannot silently regress:

- **Repo size guard** — fails if tracked files exceed a threshold or if any single
  file exceeds 1 MB.
- **Secret scanning** — flags `.env`, keys, and high-entropy strings.
- **Vendored-path guard** — fails if `venv/`, `node_modules/`, `__pycache__/`,
  `*.pyc`, `*.dll`, `*.exe` or `*.zip` appear in the index.
- **Lockfile check** — ensures `requirements.txt` / `package.json` are the source
  of truth and no installed tree is committed.

See `.github/workflows/ci.yml`.
