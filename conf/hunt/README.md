# Hunting filters — privileged file/registry operation bugs

Named filter lenses for the **"privileged process touches an attacker-controllable
object"** bug family — the root of most Windows local privilege escalation. Apply
one to a capture and read the hits; a hit is *interesting* when the acting process
is privileged (SYSTEM, a service, or elevated) and the object is something a
low-privilege user can influence.

## Workflow

```powershell
# 1) capture broadly (auto-elevates via UAC when not already admin):
.\build\src\cli\pmx.exe live --count 20000 --save capture.pmxlog

# 2) analyze: sweep every lens AND verify each hit's exploitability.
#    Run this as your NORMAL user (not elevated) — the ACL checks are only
#    meaningful from the low-privilege token an attacker actually holds.
.\hunt.ps1 capture.pmxlog

# or apply one lens live / offline:
.\build\src\cli\pmx.exe open capture.pmxlog --filter-file conf\hunt\fs-dll-hijack.json
.\build\src\cli\pmx.exe live --filter-file conf\hunt\reg-hive-load.json
```

`driver` and `live` **auto-elevate**: if the shell is not already admin they
relaunch themselves through a UAC prompt (the elevated child streams in its own
window; use `--save`/`--out FILE` to keep the output). `open`/`filters`/`hunt.ps1`
stay unprivileged on purpose.

## Exploitability verification

`hunt.ps1` no longer just counts hits — for every unique hit it maps the NT path
(`\Device\HarddiskVolumeN\…` → drive letter via `QueryDosDevice`) and checks
whether a **low-privilege principal** (Everyone, Authenticated Users, Users,
INTERACTIVE, or your own SID) holds a write-class grant on the relevant object,
using action bits only (`WriteData/CreateFiles/AppendData/Delete/WriteDAC/…`,
never the shared `READ_CONTROL` bit that makes reads look writable):

| Technique | What it verifies | `EXPLOITABLE` when |
|---|---|---|
| dll-hijack / missing-file | can the missing leaf be **planted**? | parent dir exists and grants CreateFiles to a low-priv SID (notes if the dir is empty) |
| writable-write | can the target be **written**? | the file (or, if absent, its dir) is writable |
| arbitrary-delete / rename | can the child be **swapped/removed**? | the parent dir is writable (rename/delete child) |
| toctou-temp | symlink/junction + oplock **redirection** surface | the temp dir is writable |
| reg-privileged-write / delete / hive-load | can the key be **written**? | the key (`\REGISTRY\… `/`HKLM…` → provider path) grants SetValue/CreateSubKey/Delete to a low-priv SID |
| named-pipe | (pipe ACLs aren't in the trace) | reported `MANUAL` |

`MAYBE` = a writable *ancestor* exists but intermediate dirs/keys must be created
first. Output: a per-technique table (`hits / uniq / exploit / maybe`) plus a
full `hunt-out\FINDINGS.md` with the ranked, verdict-annotated hits. Sanity-check
the checker itself any time with `.\hunt.ps1 -SelfTest` (needs a `-Log` value,
which it ignores).

## Lenses

| File | Primitive it surfaces |
|---|---|
| `fs-dll-hijack.json` | Missing-`.dll` opens (NAME NOT FOUND) → plant a DLL in a writable search dir for code exec in the target process |
| `fs-missing-file.json` | Any missing file open (config/exe/manifest) → plant-a-file redirection |
| `fs-writable-write.json` | Create/write/rename/delete in world-writable dirs (ProgramData, Users\Public, Windows\Temp, user Temp) → arbitrary-write / drop |
| `fs-arbitrary-delete.json` | `SetDispositionInformationFile` (delete) → arbitrary-delete → folder-move / rollback LPE |
| `fs-arbitrary-rename.json` | `SetRenameInformationFile` (move) → arbitrary-move / overwrite |
| `fs-toctou-temp.json` | `CreateFile` in Temp → symlink/junction + oplock TOCTOU (redirection when OPEN_REPARSE_POINT absent) |
| `fs-named-pipe.json` | Named-pipe create/connect → impersonation / spoofing targets |
| `reg-privileged-write.json` | `RegSetValue`/`RegCreateKey` → arbitrary-registry-write (weak-ACL key, per-user hive) |
| `reg-hive-load.json` | `RegLoadKey`/`RegRestoreKey`/`RegReplaceKey` from a file → hive-load LPE |
| `reg-delete.json` | `RegDeleteKey`/`RegDeleteValue` → arbitrary-registry-delete |

## How the filters express "AND"

Procmon-style include rules OR together, so an exact `op AND path AND result`
match is written as: **include the rarest signal, then `exclude` the inverse of
each other constraint.** Example (`fs-dll-hijack`): `include Result is
NAME_NOT_FOUND`, then `exclude Path excludes .dll` — the exclude fires (hides) on
any path that does *not* contain `.dll`, leaving only not-found `.dll` opens.

## Privileged-only

Every lens ends with an integrity exclusion that drops Medium / Medium+ / Low /
Untrusted callers, so only **High / System / Protected** (and processes whose
token couldn't be read) survive — i.e. the LPE-relevant set. `User` and
`Integrity` are real filter columns, so you can tighten further, e.g.
`-x "User is NT AUTHORITY\LOCAL SERVICE"` or `-f "User is NT AUTHORITY\SYSTEM"`.

User + integrity come from the process token, read once per process at its
rundown (not per event) and cached; the SID→name lookup is memoized across
processes — same approach Procmon uses, so no Win32 hammering.
