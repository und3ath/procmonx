# procmonx — User Guide

Complete reference for the `pmx` command line: every command and flag, the
filtering model, the on-disk formats, and operational notes. For a quick tour see
[`README.md`](README.md); for internals see [`docs/DESIGN.md`](docs/DESIGN.md).

---

## 1. Concepts

`pmx` captures the same event model as Process Monitor:

- **Event classes:** `1` Process, `2` Registry, `3` File System, `4` Profiling,
  `5` Network, `6` IPC (named pipes / mailslots), `0` Completion (internal).
- Each I/O is captured as a request and paired with its completion, so every row
  shows the **final** status, a **duration**, and, for `CreateFile`, an
  **OpenResult** — not the transient `STATUS_PENDING`.
- Every event carries the resolved **process name, PID, parent, user, integrity
  level, path, result** and a per-operation **detail** string.

Live capture needs administrator rights (it loads/attaches the minifilter and
opens its port). `open`, `summary` and `filters` are offline and need no
elevation.

---

## 2. Commands

```
pmx driver  status
pmx driver  load|unload|install|remove|attach [--name NAME] [--sys PATH]
pmx live    [--capture proc,fs,reg|all] [--flags 0xMASK] [--rate HZ] [--count N]
            [--class C] [--hex N] [--stats] [filters] [--save F] [--csv F]
            [--pml F] [--json F|-] [--raw] [--net] [--out F] [--silent]
            [--unfiltered] [--config F] [--buffer-mb N] [--spool-dir DIR]
pmx net     [--count N] [--save F] [--csv F] [--pml F] [--json F|-] [--out F] [--silent]
            [--config F] [--buffer-mb N] [--spool-dir DIR]
pmx open    FILE.(pmxlog|pml) [filters] [--class C] [--count N]
            [--csv F] [--pml F] [--json F|-] [--summary] [--quiet]
            [--config F] [--buffer-mb N] [--spool-dir DIR]
pmx summary FILE.(pmxlog|pml) [--by path|proc|pid|op|result|class] [--top N] [filters]
pmx filters FILE|DIR...
pmx elevate <args…>

filters:    -f RULE  -x RULE  --filter-file F (repeatable)  --filter-dir DIR
            --match procmon|any  --groups any|all  --pid N  --proc NAME  --failed
```

### `pmx driver <sub>`
Manage the minifilter service.

- `load` — install the service (if needed), load the driver, and attach it to all
  volumes. If a compatible filter is already loaded, it is reused.
- `attach` — (re)attach the loaded filter to all volumes.
- `unload` / `remove` — unload the running driver / delete the service.
- `status` — list loaded minifilters and test the port (no elevation).
- `--sys PATH` overrides the driver path (default: `procmon\PROCMON25.SYS` next to
  `pmx.exe`); `--name` overrides the service name.

### `pmx live`
Live capture. `--net` also starts the ETW network consumer and interleaves its
events.

| Flag | Meaning |
|---|---|
| `--capture LIST` | Which classes the **driver** generates: `proc`, `fs`, `reg`, `all` (comma-separated; `proc` is always on, since process info names every event) |
| `--flags 0xMASK` | Raw capture bitmask (default `0x7`; overrides `--capture`) |
| `--class C` | Show/keep only this class; also narrows the driver (unless `--unfiltered` with `--save`/`--pml`). `--class 5` implies `--net` |
| `--count N` | Stop after N events |
| `--rate HZ` | Profiling event interval |
| `--net` | Also capture ETW network events |
| `--raw` | Disable request/completion pairing (show every raw record) |
| `--stats` | Print a per-class record histogram instead of rows |
| `--hex N` | Dump N raw detail bytes per record (debugging) |
| `--save F` | Write the filtered capture to a `.pmxlog` |
| `--pml F` | Write the filtered capture as a Process Monitor `.pml` |
| `--csv F` / `--json F` | Write the filtered rows to CSV / JSON Lines |
| `--unfiltered` | `--save`/`--pml` keep the **full** raw capture instead (console/CSV/JSON stay filtered) |
| `--buffer-mb N` | RAM buffer for file output before spilling to disk (default 256, min 16) |
| `--spool-dir DIR` | Where spill files go (default `%TEMP%`) |
| `--config F` | Settings file (see §5, *Memory & spill*) |
| `--json -` | Stream JSON Lines to stdout instead of table rows |
| `--out F` | Also mirror console output to a file (tee) |
| `--silent` | Suppress the console (use with `--out`) |
| filters | See §3 |

### `pmx open FILE`
Reload a saved `.pmxlog` or a `.pml` (written by `pmx` or by Process Monitor;
64-bit logs, format v4–v9) and filter / export it offline. Accepts the same
filters and the `--csv` / `--pml` / `--json` exporters. `--summary` prints the
summary table (see below) instead of rows; `--quiet` suppresses rows.
`open` streams through the file instead of loading it whole, so reopening an
arbitrarily large `live` capture doesn't need to fit in RAM; `--csv`/`--pml`/
`--json FILE` route the filtered events through the same RAM-bounded spool
`live` uses, with the same `--config F` / `--buffer-mb N` / `--spool-dir DIR`
options (see §5, *Memory & spill*). `--summary` (or the `summary` command)
does not write those files, even if given alongside them.

### `pmx summary FILE`
Group the filtered events and print count, share, and failed-count per key, most
frequent first.

- `--by path|proc|pid|op|result|class` (default `path`)
- `--top N` (default 20; `0` = all)

```
pmx summary cap.pml --by result --failed
pmx summary cap.pml --by proc --top 10
```

### `pmx net`
Network-only ETW capture, with the same `--save` / `--csv` / `--pml` / `--json` /
`--out` / `--silent` / `--count` / `--config` / `--buffer-mb` / `--spool-dir` options.

### `pmx filters FILE|DIR…`
Inspect one or more filter configs (`.json`, or a Process Monitor `.reg` export),
showing each as its own lens with its match mode.

---

## 3. Filtering

A rule is `"<Column> <relation> <value>"`.

- **Columns:** ProcessName, PID, PPID, User, Integrity, Operation, Path, Result,
  Detail, Class, ImagePath, CommandLine, Sequence.
- **Relations:** is, isNot, contains, excludes, beginsWith, endsWith, lessThan,
  moreThan.
- String comparisons are case-insensitive. PID/PPID/Sequence compare numerically
  (decimal or `0x` hex). `Result lessThan|moreThan <number>` compares the raw
  NTSTATUS; `Result is NAME_NOT_FOUND` compares the friendly name.

**Semantics (default, `--match procmon`):** an Exclude match hides the event;
Include rules on the *same* column are OR'd, and Include groups on *different*
columns are AND'd; with no rules, everything shows. `--match any` ORs all
Includes regardless of column.

**Lenses.** Each `--filter-file` (repeatable) and each file in `--filter-dir` is
an independent rule set with its own includes/excludes and match mode. Lenses
combine with `--groups any` (OR, default) or `--groups all` (AND) — one lens's
excludes never suppress another lens's includes. The command-line `-f`/`-x` rules
plus the shortcuts form one more set, AND'd with the lens group.

**Shortcuts:**
- `--pid N` → `PID is N`, `--proc NAME` → `ProcessName is NAME` (both repeatable);
- `--failed` → any error status (`>= 0xC0000000`) except `FAST_IO_DISALLOWED`,
  a benign filter-manager fallback Process Monitor hides by default.

**JSON config** (`--filter-file rules.json`):
```json
{
  "match": "procmon",
  "filters": [
    { "column": "Path", "relation": "contains", "value": "\\ProgramData\\", "action": "include" },
    { "column": "Operation", "relation": "is", "value": "CreateFile", "action": "include" },
    { "column": "Result", "relation": "is", "value": "SUCCESS", "action": "exclude" }
  ]
}
```
`match` is optional (`procmon` default); `action` defaults to `include`; values
may be numbers; a UTF-8 BOM is tolerated. A Process Monitor `.reg` filter export
is also accepted.

---

## 4. Output & file formats

- **Console** — an aligned table: time, process(pid)[integrity], class,
  operation, result, path, detail, duration.
- **`.pmxlog`** — native binary store; reload it later with `pmx open`. Preserves
  every decoded field.
- **`.pml`** — Process Monitor's log format (v9, x64). `--pml` writes one that
  opens in Process Monitor; `pmx open FILE.pml` reads one.
- **CSV** (`--csv`) — Time, Process Name, PID, User, Integrity, Operation, Path,
  Result, Detail, Duration; RFC-4180 quoted.
- **JSON Lines** (`--json`) — one object per event; `--json -` streams to stdout
  (status lines go to stderr, so the stream stays parseable). Fields: `time`
  (ISO-8601 UTC), `ts`, `class`, `op`, `process`, `pid`, `tid`, `ppid`, `user`,
  `integrity`, `path`, `result`, `status` (hex), `detail`, `duration`, `image`,
  `cmdline`.

Every output of `live` is the **filtered** view (same as `open`); add
`--unfiltered` to keep the full capture in `--save`/`--pml` for later
re-filtering. Validate a generated `.pml` with
`python tools/check_pml.py FILE.pml`.

---

## 5. Operational notes

- **Elevation.** `driver`, `live`, and `net` auto-elevate via UAC. The elevated
  window stays open until you press a key (`--no-pause` to auto-close); the
  original working directory is preserved, so relative output paths resolve where
  you ran the command.
- **`--count` is exact.** Events are hard-capped once the target is met, including
  in-flight driver batches and buffered ETW events.
- **Chronological output.** Because completions arrive after their requests, saved
  and exported events are sorted by time (then sequence), matching Process
  Monitor's ordering.
- **Memory & spill.** Events bound for a file (`--save`/`--csv`/`--json F`/
  `--pml`) are held in a RAM buffer; when it fills, it is sorted and spilled to a
  temp file in the spool dir (a `[pmx] buffer full: spilled run N` line is
  printed). On stop, the runs are merged in time order straight into the output
  files, with a `writing N/M (x%)` progress line for large captures. Temp files
  delete themselves on close, even if `pmx` crashes. Ctrl-C once stops the capture
  and starts the write; Ctrl-C again stops the write early — the files stay valid,
  just shorter. Settings come from `pmx.json` next to `pmx.exe` (or `--config F`);
  `--buffer-mb` / `--spool-dir` override it. Start from `conf/pmx.example.json`:
  ```json
  { "buffer_mb": 256, "spool_dir": "" }
  ```
  `buffer_mb` minimum 16; empty `spool_dir` = `%TEMP%`. Pick a spool dir with free
  space about the size of the capture.
- **Kernel-side selection.** `--capture` / `--class` choose which classes the
  driver *generates*; all rule filtering happens in user mode. Registry can be
  turned off entirely at the driver; process capture is always on because it
  supplies the names for every other event.

---

## 6. Hunting lenses (`conf/hunt`)

`conf/hunt/` holds example filter lenses aimed at local privilege-escalation
surfaces (missing DLLs, writable directories, weak-ACL registry keys, named
pipes, hive loads). `hunt.ps1` runs a capture through every lens and reports what
a low-privileged user could actually influence. See `conf/hunt/README.md`.

---

## 7. Glossary

| Term | Meaning |
|---|---|
| Minifilter | The file-system filter driver `pmx` drives |
| Comm port | The filter communication port the driver exposes |
| Pairing | Matching a request with its completion to get the final result/duration |
| OpenResult | `CreateFile` outcome (Created / Opened / …) from the completion |
| Lens | One filter config, applied independently and combined per `--groups` |
| `.pml` | Process Monitor's native log format |
| ETW | Event Tracing for Windows (source of network events) |
