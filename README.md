# procmonx (`pmx`)

A command-line process-activity monitor for Windows — a scriptable companion
to Sysinternals **Process Monitor**. `pmx` captures **file system, process,
registry, profiling, and network** activity with real process names, users,
integrity levels, paths, and NTSTATUS results, and reads/writes Process Monitor
**`.pml`** logs so captures interoperate with Procmon itself.

Instead of shipping its own kernel driver, `pmx` drives a Process
Monitor–compatible signed **minifilter** over its communication port. Network
events, which Procmon also collects in user mode, are captured via the **NT
Kernel Logger** ETW provider.

> **Scope.** `pmx` does **not** include or distribute any kernel driver or
> Sysinternals binary — you supply your own local Process Monitor install, and
> `pmx` drives that copy's driver. Administrator rights are required for live
> capture. Use only on systems you are authorized to monitor.

---

## Features

- **Live capture** with request↔completion **pairing** — the real final NTSTATUS,
  `Duration`, and `OpenResult`, not the intermediate `STATUS_PENDING`.
- **File System** — operation / sub-operation names, `Read`/`Write` Offset+Length,
  and the full `CreateFile` field set (Desired Access, Disposition, Options,
  Attributes, ShareMode, AllocationSize, OpenResult).
- **Registry** — operation names, value **Type / Length / Data**, `KEY_*` Desired
  Access, create Disposition, and `RegQueryValue` results.
- **Process** — create / exit / thread / load-image with PID, parent, command
  line, user, and integrity level.
- **Network** — TCP/UDP send/receive/connect/etc. via ETW, with process name,
  source/dest IPs and ports, and length.
- **Filtering** — Procmon-style rules on the command line, JSON configs, and
  composable filter "lenses"; imports Process Monitor `.reg` filter exports.
- **Read & write `.pml`** — open a Procmon capture, or produce one that opens in
  real Process Monitor.
- **Export** — native `.pmxlog`, CSV, and JSON Lines; a `summary` command for
  quick triage.

---

## Requirements

- Windows, x64.
- A local install of Sysinternals **Process Monitor**; place its driver at
  `procmon/PROCMON25.SYS` (the build copies it next to `pmx.exe`).
- A C++20 toolchain (MSVC) and **CMake 3.25+** with any generator (Ninja or
  Visual Studio).
- **Administrator** rights for `driver`, `live`, and `net` (auto-elevates via UAC).

## Build

From a developer command prompt (so the compiler is on `PATH`):

```
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Output binary: `build\src\cli\pmx.exe`. Tests build by default (`-DPMX_BUILD_TESTS=OFF`
to skip).

## Quick start

```
pmx driver load                              # install + load + attach (elevated)
pmx live --count 200                         # capture 200 events
pmx live --class 3 -f "Path contains \Temp\" # only File System, path filter
pmx live --net --count 500 --pml cap.pml     # file+proc+reg+network -> Procmon .pml
pmx open cap.pml --failed --summary          # offline: see the errors
pmx summary cap.pml --by process --top 10    # busiest processes
pmx net --count 100 --json -                 # network only, JSON Lines to stdout
```

`driver`, `live`, and `net` auto-elevate through UAC; the elevated window stays
open until you press a key (`--no-pause` to auto-close).

Full command and flag reference: [`documentation.md`](documentation.md).

## Commands

| Command | Purpose |
|---|---|
| `pmx driver status\|load\|unload\|install\|remove\|attach` | Manage the minifilter |
| `pmx live …` | Live capture (driver classes; `--net` adds ETW network) |
| `pmx net …` | Network-only capture (ETW) |
| `pmx open FILE.(pmxlog\|pml) …` | Reload + filter/export a saved capture offline |
| `pmx summary FILE …` | Count events by path / process / operation / result / class |
| `pmx filters FILE\|DIR…` | Inspect a filter config |
| `pmx elevate <args…>` | Relaunch elevated explicitly |

Filter rule: `"<Column> <relation> <value>"`, e.g. `"Path contains steam"`.
Columns — ProcessName, PID, PPID, User, Integrity, Operation, Path, Result,
Detail, Class, ImagePath, CommandLine, Sequence. Relations — is, isNot, contains,
excludes, beginsWith, endsWith, lessThan, moreThan.

## Layout

```
src/core/pmx  reusable core: protocol, decode, pairing, filtering, store, PML, ETW
src/cli       the pmx command-line tool
tests         unit tests
tools         check_pml.py — validates a .pml the way Process Monitor loads it
conf/hunt     example filter "lenses" for privilege-escalation hunting (hunt.ps1)
docs          DESIGN.md (architecture)
```

## License

MIT — see [LICENSE](LICENSE). `pmx` bundles no third-party binaries or drivers;
it operates a Process Monitor install that you provide.
