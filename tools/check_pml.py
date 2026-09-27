#!/usr/bin/env python3
"""Validate a .pml the way Process Monitor's loader does.

Checks, in load order: the header (signature, version 4..9, non-zero section
offsets, x64); section layout / ordering / sizes; the strings and process
tables; the icon table; the hosts and ports tables (which must be consumed
exactly); and every event record plus its per-class detail.

Exit code 0 = Process Monitor should open it; 1 = first failing check is printed.

Usage: python tools/check_pml.py FILE.pml
"""
import struct
import sys


class Fail(Exception):
    pass


def u16(d, o): return struct.unpack_from("<H", d, o)[0]
def s16(d, o): return struct.unpack_from("<h", d, o)[0]
def u32(d, o): return struct.unpack_from("<I", d, o)[0]
def u64(d, o): return struct.unpack_from("<Q", d, o)[0]


def str_ok(prefix, pos, end):
    """A length-prefixed string (bit15 = 1-byte unit) fits within [pos, end)."""
    unit = 1 if prefix & 0x8000 else 2
    return pos <= end and (prefix & 0x7FFF) * unit <= end - pos


def sid_ok(n, pos, end):
    """An optional SID blob of n bytes fits and is well-formed."""
    if n == 0:
        return True
    if pos > end or n > end - pos or n < 8:
        return False
    sub = D[pos + 1]
    return sub <= 15 and 4 * sub + 8 <= n


def check_header(d):
    if len(d) < 0x3A8:
        raise Fail("file smaller than the 0x3A8-byte header")
    if d[:4] != b"PML_":
        raise Fail("signature missing")
    ver = u32(d, 4)
    if not 4 <= ver <= 9:
        raise Fail(f"unsupported version {ver}")
    ev, eo, pt, st, ic = (u64(d, o) for o in (0x240, 0x248, 0x250, 0x258, 0x260))
    if not (ev and eo and pt and st and ic):
        raise Fail("a section offset is 0 ('was not closed cleanly ... corrupt')")
    if not u32(d, 8) & 1:
        raise Fail("not a 64-bit log")
    # section layout
    hs = u32(d, 0x398) if ver >= 5 else 624
    if ver >= 5 and not ((928 if ver < 7 else 936) <= hs <= 0x3A8):
        raise Fail(f"bad header size {hs:#x}")
    hp = u64(d, 0x3A0) if ver >= 7 else 0
    fsz = len(d)
    end_icon = hp or fsz
    cnt = u32(d, 0x234)
    checks = [
        (hs <= ev <= fsz, "events offset"),
        (ev <= eo, "events <= offsets array"),
        (eo <= pt, "offsets array <= process table"),
        (pt < st, "process table < strings"),
        (st < ic, "strings < icons"),
        (ic < end_icon <= fsz, "icons < hosts/EOF"),
        (cnt <= (pt - eo) // 5, "event count vs offsets array size"),
        (st - pt >= 4 and ic - st >= 4 and end_icon - ic >= 4, "section sizes >= 4"),
        (not hp or 8 <= fsz - hp <= 0xFFFFFFFF, "hosts/ports section size"),
    ]
    for ok, what in checks:
        if not ok:
            raise Fail(f"invalid layout: {what}")
    return ver, ev, eo, pt, st, ic, hp, cnt


def check_strings(d, st, ic):
    size = ic - st
    n = u32(d, st)
    if n > (size - 4) // 4:
        raise Fail("strings: count too large")
    for i in range(n):
        off = u32(d, st + 4 + 4 * i)
        if off < 4 * n + 4 or off > size - 4:
            raise Fail(f"strings[{i}]: bad offset")
        ln = u32(d, st + off)
        if ln:
            if ln < 2 or ln & 1 or ln > size - off - 4:
                raise Fail(f"strings[{i}]: bad size {ln}")
            if u16(d, st + off + 4 + ln - 2) != 0:
                raise Fail(f"strings[{i}]: size must include the terminating NUL")
    return n


def check_processes(d, ver, pt, st, nstrings):
    size = st - pt
    n = u32(d, pt)
    if n > (size - 4) // 8:
        raise Fail("process table: count too large")
    msz = 64 if ver >= 6 else 60
    prev_idx = prev_off = None
    for i in range(n):
        idx = u32(d, pt + 4 + 4 * i)
        off = u32(d, pt + 4 + 4 * n + 4 * i)
        if prev_idx is not None and idx <= prev_idx:
            raise Fail(f"process table: indexes not strictly ascending at #{i}")
        if off < 8 * n + 4 or off >= size or (prev_off is not None and off <= prev_off):
            raise Fail(f"process[{i}]: bad struct offset")
        nxt = u32(d, pt + 4 + 4 * n + 4 * (i + 1)) if i + 1 < n else size
        if i + 1 < n and (nxt <= off or nxt > size):
            raise Fail(f"process[{i}]: bad next offset")
        ssz = nxt - off
        base = pt + off
        if ssz < 0x6C:
            raise Fail(f"process[{i}]: struct too small")
        if d[base + 96] != 1:
            raise Fail(f"process[{i}]: byte at +96 must be 1")
        if u32(d, base) != idx:
            raise Fail(f"process[{i}]: struct index != table index")
        mods = u32(d, base + 104)
        if mods > 0x7FFFFFFF or mods * msz != ssz - 108:
            raise Fail(f"process[{i}]: size != 108 + {msz}*modules")
        for k in range(8):  # string indexes
            if u32(d, base + 56 + 4 * k) >= nstrings:
                raise Fail(f"process[{i}]: string index out of range")
        prev_idx, prev_off = idx, off
    return n


def check_icons(d, ic, end):
    size = end - ic
    n = u32(d, ic)
    if n > (size - 4) // 4:
        raise Fail("icons: count too large")
    for i in range(n):
        off = u32(d, ic + 4 + 4 * i)
        if off < 4 * n + 4 or off > size - 8 or u32(d, ic + off + 4) > size - off - 8:
            raise Fail(f"icons[{i}]: bad entry")


def check_hosts(d, hp):
    if not hp:
        return
    p, end = hp, len(d)
    nh = u32(d, p); p += 4
    if nh > (end - p) // 20:
        raise Fail("hosts: count too large")
    if nh:
        print("  (note: non-empty hosts table not deep-checked)")
        return
    np_ = u32(d, p); p += 4
    if np_ > (end - p) // 8:
        raise Fail("ports: count too large")
    if np_ == 0 and p != end:
        raise Fail("hosts/ports: trailing bytes (loader must consume exactly)")


def check_event(d, off, eo):
    if off + 0x34 > eo:
        raise Fail("record header overruns events section")
    cls, op = u32(d, off + 8), u16(d, off + 12)
    frames, dsz = u16(d, off + 40), u32(d, off + 44)
    size = 52 + 8 * frames + dsz
    if dsz > 0x203CC or off + size > eo:
        raise Fail(f"record size {size} out of bounds")
    det = off + 52 + 8 * frames
    end = off + size
    left = end - det

    def need(n, what):
        if left < n:
            raise Fail(f"class {cls} op {op}: {what} needs >= {n:#x} detail bytes, has {left:#x}")

    if cls == 0:
        if dsz > 0x10000:
            raise Fail("completion detail too large")
    elif cls == 1:
        if op > 9:
            raise Fail(f"process op {op} out of range")
        if op < 2:
            need(0x34, "Process Defined/Create")
            s1, s2 = D[det + 0x2C], D[det + 0x2D]
            if not sid_ok(s1, det + 0x34, end) or not sid_ok(s2, det + 0x34 + s1, end):
                raise Fail("process: bad SID blob")
            p = det + 0x34 + s1 + s2
            ip = u16(d, det + 0x2E)
            if not str_ok(ip, p, end):
                raise Fail("process: image path overruns")
            p += (ip & 0x7FFF) * (1 if ip & 0x8000 else 2)
            if not str_ok(u16(d, det + 0x30), p, end):
                raise Fail("process: command line overruns")
        elif op == 5:
            need(0x10, "Load Image")
            if not str_ok(u16(d, det + 0x0C), det + 0x10, end):
                raise Fail("Load Image path overruns")
        elif op in (2, 4, 8):
            need(0x14, "Exit/Thread Exit/Statistics")
        elif op == 3:
            need(4, "Thread Create")
        elif op == 9:
            need(0x13C, "System Statistics")
        elif op == 7:
            need(0xC, "Process Start")
            p = det + 0xC
            for fo in (4, 6):
                pre = u16(d, det + fo)
                if not str_ok(pre, p, end):
                    raise Fail("Process Start string overruns")
                p += (pre & 0x7FFF) * (1 if pre & 0x8000 else 2)
            if u32(d, det + 8) > (end - p) // 2:
                raise Fail("Process Start environment overruns")
    elif cls == 2:
        if op > 21:
            raise Fail(f"registry op {op} out of range")
        fixed = {0: 8, 1: 8, 18: 8, 19: 8, 20: 8, 3: 12, 5: 12, 4: 16, 6: 16,
                 7: 16, 8: 16, 12: 4, 14: 4, 21: 6}.get(op, 2)
        need(fixed, "registry fixed fields")
        pre = u16(d, det)
        p = det + fixed
        if not str_ok(pre, p, end):
            raise Fail("registry path overruns")
        p += (pre & 0x7FFF) * (1 if pre & 0x8000 else 2)
        if op in (12, 19, 20, 21, 14) and not str_ok(u16(d, det + 2), p, end):
            raise Fail("registry second path overruns")
        if op in (4, 8) and u16(d, det + 12) > end - p:
            raise Fail("registry inline data overruns")
    elif cls in (3, 6):
        if op >= 48:
            raise Fail(f"file-system op {op} out of range")
        need(0x44, "file-system fixed block")
        pre = u16(d, det + 0x40)
        if not str_ok(pre, det + 0x44, end):
            raise Fail("file-system path overruns")
        post = det + 0x44 + (pre & 0x7FFF) * (1 if pre & 0x8000 else 2)
        tail = end - post if post <= end else 0
        if op == 20 and tail:
            if tail < 8 or not sid_ok(D[post + 4], post + 8, end):
                raise Fail("CreateFile post-path block invalid")
        if op in (26, 31) and u64(d, det + 0x10) > tail:
            raise Fail("Set info length exceeds post-path data")
        if op == 17 and tail < 8:
            raise Fail("op 17 needs >= 8 post-path bytes")
        sub = D[det]
        if op == 26 and (sub == 10 or sub in (65, 66)):  # rename / link target
            skip = u64(d, det + 0x10)
            if post > end or skip > end - post or end - post - skip < 2:
                raise Fail("SetInformationFile rename/link: target string missing")
            if not str_ok(u16(d, post + skip), post + skip + 2, end):
                raise Fail("SetInformationFile rename/link: target overruns")
        if op == 32 and sub == 1:  # QueryDirectory: filter string after path
            if post + 2 > end or not str_ok(u16(d, post), post + 2, end):
                raise Fail("QueryDirectory: filter string missing/overruns")
    elif cls == 4:
        if op > 2:
            raise Fail(f"profiling op {op} out of range")
        need({0: 12, 1: 32, 2: 2}[op], "profiling")
        if op == 2 and not str_ok(u16(d, det), det + 2, end):
            raise Fail("debug output string overruns")
    elif cls == 5:
        if op > 9:
            raise Fail(f"network op {op} out of range")
        need(0x2E, "network")
        rest = end - (det + 44)
        if rest <= 0 or rest & 1:
            raise Fail("network: extra multi-sz must be non-empty, even-sized")
        w = [u16(d, det + 44 + 2 * i) for i in range(rest // 2)]
        if 0 not in w:
            raise Fail("network: unterminated multi-sz")
    else:
        raise Fail(f"unknown event class {cls}")


def main():
    global D
    path = sys.argv[1]
    D = open(path, "rb").read()
    d = D
    try:
        ver, ev, eo, pt, st, ic, hp, cnt = check_header(d)
        ns = check_strings(d, st, ic)
        np_ = check_processes(d, ver, pt, st, ns)
        check_icons(d, ic, hp or len(d))
        check_hosts(d, hp)
        prev_ts = 0
        for i in range(cnt):
            e = eo + 5 * i
            off = u32(d, e) | (d[e + 4] << 32)  # 40-bit offset
            if not ev <= off < eo:
                raise Fail(f"event #{i}: offset outside events section")
            ts = u64(d, off + 0x1C)
            if ts < prev_ts:  # loads, but Procmon renders blank rows
                raise Fail(f"event #{i}: timestamp earlier than previous "
                           "(not chronological -> blank rows in Procmon)")
            prev_ts = ts
            try:
                check_event(d, off, eo)
            except Fail as f:
                raise Fail(f"event #{i} (@{off:#x}): {f}")
    except Fail as f:
        print(f"FAIL {path}: {f}")
        return 1
    print(f"OK {path}: v{ver}, {cnt} events, {np_} processes, {ns} strings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
