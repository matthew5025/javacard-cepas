#!/usr/bin/env python3
"""
Clone/compare CEPAS cards between a "source" card and a target card running our applet.

Flow:
1) Prompt to insert source card. For each purse index 0..4 that returns SW=9000:
   - Read full purse header (Lc=0)
   - Read all transaction logs (log_count entries)
2) Read SFI files 1-30 (READ BINARY Le=00)
3) Prompt to insert target card (our applet). For each captured purse:
   - Create purse, bulk load header, append logs
   - Replays all SFIs with matching length/payload, auth cleared
4) Read back all purses + SFIs from target and diff against source.

Notes:
- Uses proprietary personalization INS=F0 and file-admin INS=F1 defined in our applet.
- Assumes issuer_data_len <= 32 so bulk-load length is 95 bytes (matches our applet contract).
- Assumes logs are 16-byte records and log_count <= 30.
"""

import sys
import time
from typing import Iterable, List, Dict, Tuple

from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import NoReadersException, NoCardException

APP_AID = [0xA0, 0x00, 0x00, 0x03, 0x41, 0x00, 0x01, 0x01]


# ------------- PC/SC helpers -------------

def pick_reader_with_card(preferred: str | None) -> Tuple[str, CardConnection]:
    try:
        avail = readers()
    except NoReadersException:
        sys.exit("No PC/SC readers found. Is pcscd running?")
    if not avail:
        sys.exit("No PC/SC readers found.")
    candidates = [r for r in avail if not preferred or preferred.lower() in r.name.lower()]
    if not candidates:
        sys.exit(f"No reader matches '{preferred}'. Available: {[r.name for r in avail]}")
    last_err = None
    for r in candidates:
        conn = r.createConnection()
        for proto in (CardConnection.T1_protocol, CardConnection.T0_protocol):
            try:
                conn.connect(proto)
                return r.name, conn
            except NoCardException as e:
                last_err = e
            except Exception as e:  # noqa: BLE001
                last_err = e
    sys.exit(f"No usable card: {last_err}")


def send(conn: CardConnection, apdu: Iterable[int], label: str) -> Tuple[int, List[int]]:
    apdu_list = list(apdu)
    data, sw1, sw2 = conn.transmit(apdu_list)
    sw = (sw1 << 8) | sw2
    print(f"{label:<24} CLA={apdu_list[0]:02X} INS={apdu_list[1]:02X} SW={sw:04X} len={len(data)}")
    return sw, data


def require_9000(sw: int, op: str):
    if sw != 0x9000:
        sys.exit(f"{op} failed SW={sw:04X}")


# ------------- Card read ops -------------

def select_app(conn: CardConnection):
    sw, _ = send(conn, [0x00, 0xA4, 0x04, 0x00, len(APP_AID)] + APP_AID, "SELECT AID")
    require_9000(sw, "SELECT")


def read_purse_header(conn: CardConnection, p1: int) -> List[int] | None:
    # case2 Le=00 (256)
    sw, data = send(conn, [0x90, 0x32, p1, 0x00, 0x00], "READ PURSE hdr")
    if sw != 0x9000:
        return None
    return data


def read_logs(conn: CardConnection, p1: int, log_count: int) -> List[List[int]]:
    logs: List[List[int]] = []
    for offset in range(log_count):
        apdu = [0x90, 0x32, p1, 0x00, 0x01, offset & 0xFF, 0x00]  # Lc=1, Le=00
        sw, data = send(conn, apdu, f"READ LOG off={offset}")
        if sw != 0x9000:
            print(f"  stop at offset {offset}, SW={sw:04X}")
            break
        logs.append(data[:16])
    return logs


def read_sfis(conn: CardConnection) -> Dict[int, List[int]]:
    sfi_data: Dict[int, List[int]] = {}
    for sfi in range(1, 0x1F):
        p1 = 0x80 | sfi
        sw, data = send(conn, [0x00, 0xB0, p1, 0x00, 0x00], f"SFI {sfi:02X} Le=00")
        if sw == 0x9000 and data:
            sfi_data[sfi] = data
    return sfi_data


# ------------- Card write ops (our applet) -------------

def create_purse(conn: CardConnection, p1: int):
    sw, _ = send(conn, [0x90, 0xF0, p1, 0xFF, 0x00], "CREATE PURSE")
    require_9000(sw, "Create purse")


def load_purse_header(conn: CardConnection, p1: int, header: List[int]):
    if len(header) != 95:
        sys.exit(f"Header length {len(header)} != 95 expected by applet")
    apdu = [0x90, 0xF0, p1, 0xFE, len(header)] + header
    sw, _ = send(conn, apdu, "LOAD HEADER")
    require_9000(sw, "Load header")


def append_log(conn: CardConnection, p1: int, record: List[int]):
    apdu = [0x90, 0xF0, p1, 0x0E, 0x10] + record
    sw, _ = send(conn, apdu, "APPEND LOG")
    require_9000(sw, "Append log")


def admin_create(conn: CardConnection, sfi: int, length: int, auth: int):
    apdu = [0x90, 0xF1, sfi & 0xFF, 0x01, 0x03, (length >> 8) & 0xFF, length & 0xFF, auth & 0xFF]
    sw, _ = send(conn, apdu, f"CREATE SFI {sfi:02X}")
    require_9000(sw, "Create file")


def admin_write(conn: CardConnection, sfi: int, offset: int, chunk: List[int]):
    lc = 1 + len(chunk)
    apdu = [0x90, 0xF1, sfi & 0xFF, 0x00, lc, offset & 0xFF] + chunk
    sw, _ = send(conn, apdu, f"WRITE SFI {sfi:02X} off={offset}")
    require_9000(sw, "Write file")


def admin_list(conn: CardConnection) -> List[int]:
    sw, data = send(conn, [0x90, 0xF1, 0x00, 0x10, 0x00], "LIST FILES")
    if sw != 0x9000:
        return []
    return data


# ------------- Diff helpers -------------

def diff_bytes(label: str, a: List[int], b: List[int]) -> List[str]:
    if a == b:
        return []
    out = [f"{label} differs: len {len(a)} vs {len(b)}"]
    maxlen = max(len(a), len(b))
    for i in range(maxlen):
        va = a[i] if i < len(a) else None
        vb = b[i] if i < len(b) else None
        if va != vb:
            out.append(f"  @0x{i:02X}: {va!s} != {vb!s}")
            if len(out) > 20:
                out.append("  ...truncated")
                break
    return out


# ------------- Capture / replay -------------

def capture_card(conn: CardConnection):
    select_app(conn)
    purses = {}
    for p1 in range(5):
        header = read_purse_header(conn, p1)
        if header is None:
            continue
        log_count = header[40] if len(header) > 40 else 0
        logs = read_logs(conn, p1, log_count)
        purses[p1] = {"header": header, "logs": logs}

    sfi_data = read_sfis(conn)
    return {"purses": purses, "sfi": sfi_data}


def replay_to_target(conn: CardConnection, snapshot):
    select_app(conn)
    # Purse data
    for p1, purse in snapshot["purses"].items():
        # reset existing purse slot to defaults (clears any previous content)
        send(conn, [0x90, 0xF0, p1, 0xFA, 0x00], "RESET PURSE")
        create_purse(conn, p1)
        load_purse_header(conn, p1, purse["header"])
        for rec in purse["logs"]:
            append_log(conn, p1, rec)

    # Files
    for sfi, data in snapshot["sfi"].items():
        admin_create(conn, sfi, len(data), auth=0)
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + 200]
            admin_write(conn, sfi, offset, chunk)
            offset += len(chunk)
    admin_list(conn)


def main():
    preferred = sys.argv[1] if len(sys.argv) > 1 else None

    print("Insert SOURCE card (reference). Press Enter when ready...")
    input()
    rname, src_conn = pick_reader_with_card(preferred)
    print(f"Using reader: {rname} (source)")
    source = capture_card(src_conn)
    src_conn.disconnect()

    print("\nInsert TARGET card (our applet). Press Enter when ready...")
    input()
    rname2, tgt_conn = pick_reader_with_card(preferred)
    print(f"Using reader: {rname2} (target)")
    replay_to_target(tgt_conn, source)

    print("\nRe-reading TARGET for diff...")
    target = capture_card(tgt_conn)
    tgt_conn.disconnect()

    # Diff
    diffs = []
    # Purse compare
    purse_keys = set(source["purses"].keys()) | set(target["purses"].keys())
    for p1 in sorted(purse_keys):
        a = source["purses"].get(p1)
        b = target["purses"].get(p1)
        if a is None or b is None:
            diffs.append(f"Purse {p1} present only in {'source' if b is None else 'target'}")
            continue
        diffs += diff_bytes(f"purse {p1} header", a["header"], b["header"])
        if len(a["logs"]) != len(b["logs"]):
            diffs.append(f"purse {p1} log count differs: {len(a['logs'])} vs {len(b['logs'])}")
        else:
            for i, (la, lb) in enumerate(zip(a["logs"], b["logs"])):
                diffs += [f"purse {p1} log {i}: {d}" for d in diff_bytes(f"log {i}", la, lb)]
    # SFI compare
    sfi_keys = set(source["sfi"].keys()) | set(target["sfi"].keys())
    for sfi in sorted(sfi_keys):
        a = source["sfi"].get(sfi)
        b = target["sfi"].get(sfi)
        if a is None or b is None:
            diffs.append(f"SFI {sfi:02X} present only in {'source' if b is None else 'target'}")
            continue
        diffs += [f"SFI {sfi:02X}: {d}" for d in diff_bytes(f"SFI {sfi:02X}", a, b)]

    if not diffs:
        print("\nSUCCESS: Target matches source snapshot")
    else:
        print("\nDIFFERENCES:")
        for d in diffs:
            print("-", d)


if __name__ == "__main__":
    main()
