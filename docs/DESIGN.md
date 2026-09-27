# procmonx — Architecture

`pmx` is a command-line process/file/registry/network activity monitor for
Windows. It captures events by driving a Process Monitor–compatible file-system
**minifilter** over its Filter Manager communication port, decodes them into a
single owned event model, and renders / filters / exports them. Network events
come from an ETW consumer, as in Process Monitor itself.

> `pmx` never ships a kernel driver. It requires a local Process Monitor install
> and drives that copy's signed minifilter; see the README for scope.

## Data flow

```
        ┌──────────────────────── pmx_core (static lib) ────────────────────────┐
 driver │ driver/port_client ──recv──► decode.cpp ──► Event ──► filter ──► ┐     │
 comm   │  (FilterGetMessage)          (owned model)                       │     │
 port ◄─┤ enrich/pairer (request↔completion)                              ▼     │
        │ enrich/process_table (index → name/user/…)          console / tee / JSON│
 ETW  ──┤ etw/net_trace ──► netEventToEvent (+ enrich/pid_names)         store  (.pmxlog)
        │ pml_read ──► decode.cpp (offline, same path as live)            csv / jsonl
        │ store.cpp  filter{,_json,_pmc}.cpp  pml.cpp                      pml    (.pml)
        └───────────────────────────────────────────────────────────────────────┘
                                     ▲
                     src/cli (main.cpp + cli_common)  — the pmx commands
```

Only the **class** of events can be selected in the kernel (the capture bitmask:
process, file system, registry). Rule filtering, pairing, process resolution and
decoding are all user mode, so the same code path serves live capture and offline
`.pmxlog` / `.pml` reload.

## Modules (`src/core/pmx`)

| File | Role |
|---|---|
| `driver/driver_controller` | Install / load / attach / unload the minifilter service |
| `driver/port_client` | Open the comm port, send control messages, pull event batches |
| `driver/protocol.h` | Record framing, capture-flag bits, per-class detail parsers, op-name tables |
| `driver/flags.h` | Symbolic decoders (access masks, disposition, share, reg types, KEY_*) |
| `enrich/pairer` | Match a request with its completion by sequence (real status, duration, OpenResult) |
| `enrich/process_table` | Process index → name / path / cmdline / user / integrity |
| `enrich/pid_names` | PID → name for ETW events, safe against PID reuse |
| `etw/net_trace` | NT Kernel Logger ETW consumer for TCP/UDP |
| `event.h` | The decoded, owned event (the unit filtered / stored / exported) |
| `decode.cpp` | Turn a paired record + process table into an `Event` |
| `filter` / `filter_json` / `filter_pmc` | Rule engine (Procmon semantics, lenses); JSON and `.reg`/`.pmc` import |
| `store` | Native `.pmxlog` save/load, CSV and JSON Lines export |
| `pml.cpp` / `pml_read.cpp` | Process Monitor `.pml` (v9) writer / reader |
| `file_io.h` | Chunked whole-file read/write with byte-count checks |

`src/cli` holds `main.cpp` (command dispatch + capture loop) and `cli_common`
(console output, UTF-8, and the shared filter-argument plumbing).

## Threading

- **Capture pump** — a tight `FilterGetMessage` loop; each batch is walked into
  records, paired, decoded and emitted.
- **Network worker** (`--net`) — an ETW `ProcessTrace` thread whose events fold
  into the same emit path, serialized by a mutex.

Consumers (console, store, exporters) run after capture stops; a Ctrl-C handler
cancels both sources.

## Filtering model

Procmon-compatible `(Column, Relation, Value, Include|Exclude)` rules:

- An **Exclude** match hides the event.
- **Include** rules on the same column are OR'd; per-column include groups are
  AND'd (`--match procmon`, the default). `--match any` ORs all includes.
- Each filter file is an independent **lens** (its own includes/excludes and
  match mode); lenses combine with `--groups any` (OR, default) or `all` (AND),
  so one lens's excludes never suppress another's includes.
- CLI `-f`/`-x` rules and the `--pid`/`--proc`/`--failed` shortcuts form one more
  set, AND'd with the lens group.

## File formats

- **`.pmxlog`** — native store; round-trips every decoded field.
- **`.pml`** — Process Monitor's log (v9, x64), both written (opens in Process
  Monitor; validated by `tools/check_pml.py`) and read (its own or Procmon's).
- **CSV** and **JSON Lines** exports.
- **Filter config** — native JSON; import of Process Monitor's `.reg` export.

## Status

Feature-complete for file / process / registry / network monitoring: live
capture, offline reload of `.pmxlog` and `.pml`, Procmon-openable PML export,
summaries, and JSON/CSV output. A Qt GUI over the same core is a possible future
front end.
