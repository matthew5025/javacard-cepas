#!/usr/bin/env python3
"""
fs_shape_probe.py — map CEPAS card file access behaviour and exercise file admin.

What it does:
- Optional: create/set-auth/write files via proprietary `90 F1` before reads.
- Select CEPAS AID, then READ BINARY by SFI (defaults 1–30) with Le=00.
- For any SFI that returns data, tries:
    * a small read (Le=16) at offset 0
    * a read just past the end (offset=len, Le=1) to see the error SW
- Warm-reset (power cycle) to clear selection, repeat the same SFI reads.
- SELECT DF 4000, then for each FID:
    * READ BINARY offset 0, Le=00
    * if data, READ near-end and past-end
- Prints SW, length, and an 8-byte preview only.

Usage examples:
  python3 python/fs_shape_probe.py
  python3 python/fs_shape_probe.py --reader "Feitian"
  python3 python/fs_shape_probe.py --sfis 01-1E --fids 0003,0010,0012
  python3 python/fs_shape_probe.py --create 10:0xC0:0 --write 10@0:DEADBEEF --set-auth 10:1
"""

import argparse
import sys
from typing import Iterable, List, Tuple
from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import NoReadersException, NoCardException

APP_AID = [0xA0, 0x00, 0x00, 0x03, 0x41, 0x00, 0x01, 0x01]


def parse_create_list(spec: str):
    if not spec:
        return []
    out = []
    for entry in spec.split(','):
        entry = entry.strip()
        if not entry:
            continue
        # format sfi:length[:auth]
        parts = entry.split(':')
        if len(parts) < 2:
            raise ValueError(f"CREATE entry '{entry}' must be sfi:length[:auth]")
        sfi = int(parts[0], 16)
        length = int(parts[1], 0)
        auth = int(parts[2], 0) if len(parts) > 2 else 0
        out.append((sfi, length, auth))
    return out


def parse_set_auth(spec: str):
    if not spec:
        return []
    out = []
    for entry in spec.split(','):
        entry = entry.strip()
        if not entry:
            continue
        # format sfi:flag
        sfi_str, flag_str = entry.split(':', 1)
        out.append((int(sfi_str, 16), int(flag_str, 0)))
    return out


def parse_writes(spec: str):
    if not spec:
        return []
    out = []
    for entry in spec.split(','):
        entry = entry.strip()
        if not entry:
            continue
        # format sfi@offset:hexdata
        head, data_hex = entry.split(':', 1)
        sfi_str, off_str = head.split('@', 1)
        out.append((int(sfi_str, 16), int(off_str, 0), bytes.fromhex(data_hex)))
    return out

def parse_range(spec: str) -> List[int]:
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.extend(range(int(lo, 16), int(hi, 16) + 1))
        else:
            out.append(int(part, 16))
    return out

def pick_reader(name_substr: str):
    try:
        avail = readers()
    except NoReadersException:
        sys.exit("No PC/SC readers found.")
    if not avail:
        sys.exit("No PC/SC readers found.")
    cand = [r for r in avail if not name_substr or name_substr.lower() in r.name.lower()]
    if not cand:
        sys.exit(f"No reader contains '{name_substr}'. Available: {[r.name for r in avail]}")
    last_err = None
    for r in cand:
        conn = r.createConnection()
        for proto in (CardConnection.T1_protocol, CardConnection.T0_protocol):
            try:
                conn.connect(proto)
                return r, conn
            except NoCardException as e:
                last_err = e
            except Exception as e:
                last_err = e
    sys.exit(f"Readers found but could not connect: {last_err}")

def send(conn: CardConnection, apdu: Iterable[int], label: str) -> Tuple[int, List[int]]:
    data, sw1, sw2 = conn.transmit(list(apdu))
    sw = (sw1 << 8) | sw2
    preview = "".join(f"{b:02X}" for b in data[:8])
    print(f"{label:<30} SW={sw:04X} len={len(data):3d} prev8={preview}")
    return sw, data


def admin_create(conn: CardConnection, sfi: int, length: int, auth: int):
    apdu = [0x90, 0xF1, sfi & 0xFF, 0x01, 0x03, (length >> 8) & 0xFF, length & 0xFF, auth & 0xFF]
    send(conn, apdu, f"CREATE sfi={sfi:02X} len={length} auth={auth}")


def admin_write(conn: CardConnection, sfi: int, offset: int, data: bytes):
    lc = 1 + len(data)
    apdu = [0x90, 0xF1, sfi & 0xFF, 0x00, lc, offset & 0xFF] + list(data)
    send(conn, apdu, f"WRITE sfi={sfi:02X} off={offset}")


def admin_set_auth(conn: CardConnection, sfi: int, flag: int):
    apdu = [0x90, 0xF1, sfi & 0xFF, 0x03, 0x01, flag & 0xFF]
    send(conn, apdu, f"SET_AUTH sfi={sfi:02X} flag={flag}")


def admin_list(conn: CardConnection):
    apdu = [0x90, 0xF1, 0x00, 0x10, 0x00]
    sw, data = send(conn, apdu, "LIST")
    if sw != 0x9000:
        return
    print("  entries: sfi len auth")
    for i in range(0, len(data), 4):
        if i + 3 >= len(data):
            break
        sfi, lhi, llo, auth = data[i], data[i+1], data[i+2], data[i+3]
        length = (lhi << 8) | llo
        print(f"  {sfi:02X}   {length:04d}  {auth}")

def warm_reset(conn: CardConnection):
    proto = conn.getProtocol()
    conn.disconnect()
    conn.connect(proto)

def select_cepas(conn: CardConnection):
    send(conn, [0x00, 0xA4, 0x04, 0x00, len(APP_AID)] + APP_AID, "SELECT CEPAS AID")

def probe_sfi(conn: CardConnection, sfi: int, title: str):
    p1 = 0x80 | (sfi & 0x1F)
    sw, data = send(conn, [0x00, 0xB0, p1, 0x00, 0x00], f"{title} SFI={sfi:02X} Le=00")
    if sw != 0x9000 or not data:
        return
    total_len = len(data)
    send(conn, [0x00, 0xB0, p1, 0x00, 0x10], f"{title} SFI={sfi:02X} off=0000 Le=10")
    off_hi, off_lo = (total_len >> 8) & 0xFF, total_len & 0xFF
    send(conn, [0x00, 0xB0, off_hi, off_lo, 0x01], f"{title} SFI={sfi:02X} off=end Le=01")

def probe_df4000(conn: CardConnection, fids: List[int], title: str):
    sw, _ = send(conn, [0x00, 0xA4, 0x00, 0x00, 0x02, 0x40, 0x00], f"{title} SELECT DF4000")
    if sw != 0x9000:
        return
    for fid in fids:
        fid_hi, fid_lo = (fid >> 8) & 0xFF, fid & 0xFF
        sel_sw, _ = send(conn, [0x00, 0xA4, 0x00, 0x0C, 0x02, fid_hi, fid_lo], f"{title} SEL FID {fid:04X}")
        if sel_sw != 0x9000:
            continue
        sw0, data0 = send(conn, [0x00, 0xB0, 0x00, 0x00, 0x00], f"{title} FID {fid:04X} off=0000 Le=00")
        if sw0 != 0x9000 or not data0:
            continue
        total_len = len(data0)
        send(conn, [0x00, 0xB0, 0x00, 0x00, 0x10], f"{title} FID {fid:04X} off=0000 Le=10")
        off_hi, off_lo = (total_len >> 8) & 0xFF, total_len & 0xFF
        send(conn, [0x00, 0xB0, off_hi, off_lo, 0x01], f"{title} FID {fid:04X} off=end Le=01")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reader", help="substring of reader name")
    ap.add_argument("--sfis", default="01-1E", help="hex ranges, e.g. 01-1E or 01-05,10")
    ap.add_argument("--fids", default="0003,0010,0012,0013,0014,0016,0017,0018,0090",
                    help="comma/range hex list under DF 4000")
    ap.add_argument("--create", help="provision files: sfi:length[:auth],comma-separated (hex sfi, length in 0x.. or decimal)")
    ap.add_argument("--write", help="write chunks: sfi@offset:HEXDATA,comma-separated; offset decimal/hex")
    ap.add_argument("--set-auth", help="set auth flag: sfi:flag (flag 0/1), comma-separated")
    ap.add_argument("--list", action="store_true", help="list files via 90 F1 P2=10")
    args = ap.parse_args()

    sfis = parse_range(args.sfis)
    fids = parse_range(args.fids)
    creates = parse_create_list(args.create or "")
    writes = parse_writes(args.write or "")
    auths = parse_set_auth(args.set_auth or "")

    reader, conn = pick_reader(args.reader or "")
    print(f"Using reader: {reader}\n")

    # Pass 1: with CEPAS selected
    select_cepas(conn)

    # Admin ops before probing
    for sfi, length, auth in creates:
        admin_create(conn, sfi, length, auth)
    for sfi, offset, payload in writes:
        admin_write(conn, sfi, offset, payload)
    for sfi, flag in auths:
        admin_set_auth(conn, sfi, flag)
    if args.list:
        admin_list(conn)

    for sfi in sfis:
        probe_sfi(conn, sfi, "SEL applet")
    probe_df4000(conn, fids, "SEL applet")

    # Pass 2: after warm reset (no selection)
    print("\n-- warm reset --\n")
    warm_reset(conn)
    for sfi in sfis:
        probe_sfi(conn, sfi, "No select")
    probe_df4000(conn, fids, "No select")

if __name__ == "__main__":
    main()
