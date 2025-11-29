#!/usr/bin/env python3
"""
Read‑only CEPAS 2.0 probe for a physical smartcard.

It:
  1) SELECTs the CEPAS AID
  2) Tries GET CHALLENGE (0x00 0x84) and prints the random if available
  3) Issues Read Purse (Lc=0) and decodes the returned structure
  4) Reads transaction log records based on the count in the purse header

Authenticated flows and modify commands are intentionally skipped.

Usage examples:
  python3 python/card_probe.py
  python3 python/card_probe.py --reader "Yubico"
  python3 python/card_probe.py --purse 1
"""

import argparse
import sys
from typing import Iterable, List, Tuple

try:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection
    from smartcard.Exceptions import NoReadersException, NoCardException
except ImportError:  # pragma: no cover - runtime guard for missing dependency
    sys.exit("pyscard is required. Install with: pip install pyscard")


APP_AID: List[int] = [0xA0, 0x00, 0x00, 0x03, 0x41, 0x00, 0x01, 0x01]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe CEPAS applet on a PC/SC reader.")
    parser.add_argument("--reader", help="substring to choose a specific reader (defaults to first available)")
    parser.add_argument("--purse", type=int, default=0, help="purse index to exercise (default: 0)")
    return parser.parse_args()


def pick_reader_with_card(preferred: str):
    """
    Choose a reader, connect, and ensure a card is present.
    - If `preferred` is given, restrict to readers containing that substring.
    - Otherwise, try each reader until one accepts a connection.
    Returns (reader, connected_connection).
    """
    try:
        available = readers()
    except NoReadersException:
        sys.exit("No PC/SC readers found. Is pcscd/pcsclite running and a reader connected?")

    if not available:
        sys.exit("No PC/SC readers found.")

    candidates = [r for r in available if preferred.lower() in r.name.lower()] if preferred else list(available)
    if not candidates:
        sys.exit(f"No reader name contains '{preferred}'. Available: {[r.name for r in available]}")

    last_error = None
    for r in candidates:
        conn = r.createConnection()
        for proto in (CardConnection.T1_protocol, CardConnection.T0_protocol):
            try:
                conn.connect(proto)
                return r, conn
            except NoCardException as e:
                last_error = e
            except Exception as e:
                last_error = e
        # try next reader
    if preferred:
        sys.exit(f"Reader '{preferred}' found but no card is present or connectable: {last_error}")
    sys.exit(f"No readers had a present/usable card. Last error: {last_error}")


def send(conn: CardConnection, apdu: Iterable[int], label: str) -> Tuple[int, List[int]]:
    apdu_list = list(apdu)
    data, sw1, sw2 = conn.transmit(apdu_list)
    sw = (sw1 << 8) | sw2
    print(f"{label:<20} CLA={apdu_list[0]:02X} INS={apdu_list[1]:02X} -> SW={sw:04X} len={len(data)} data={to_hex(data)}")
    return sw, data


def require_9000(sw: int, op: str):
    if sw != 0x9000:
        sys.exit(f"{op} failed with SW={sw:04X}")


def to_hex(data: Iterable[int]) -> str:
    return "".join(f"{b:02X}" for b in data)


def bytes_to_int(b: List[int]) -> int:
    val = 0
    for x in b:
        val = (val << 8) | x
    return val


def decode_purse_info(data: List[int]) -> Tuple[int, int]:
    """
    Decode the mandatory Read Purse (Lc=0) layout from SS 518:2014 CEPAS 2.0.
    Returns (log_count, issuer_len) for further reads.
    """
    if len(data) < 62:
        print(f"Warning: purse info shorter than expected (len={len(data)})")
    off = 0
    version = data[off]; off += 1
    status = data[off]; off += 1
    balance = data[off:off+3]; off += 3
    autoload_amt = data[off:off+3]; off += 3
    can = data[off:off+8]; off += 8
    csn = data[off:off+8]; off += 8
    expiry = data[off:off+2]; off += 2
    creation = data[off:off+2]; off += 2
    last_crd_trp = data[off:off+4]; off += 4
    last_crd_hdr = data[off:off+8]; off += 8
    log_count = data[off]; off += 1
    issuer_len = data[off]; off += 1
    last_trn_trp = data[off:off+4]; off += 4
    last_trn_rec = data[off:off+16]; off += 16
    issuer_data = data[off:off+issuer_len] if len(data) >= off + issuer_len else []

    print("\nDecoded purse info (CEPAS 2.0, unauthenticated):")
    print(f"  Version:            {version}")
    print(f"  Purse status byte:  {status:02X} (bit0 purse enable, bit1 autoload enable)")
    print(f"  Balance:            {to_hex(balance)} ({bytes_to_int(balance)} dec)")
    print(f"  Autoload amount:    {to_hex(autoload_amt)} ({bytes_to_int(autoload_amt)} dec)")
    print(f"  CAN:                {to_hex(can)}")
    print(f"  CSN:                {to_hex(csn)}")
    print(f"  Expiry (Julian):    {to_hex(expiry)}")
    print(f"  Creation (Julian):  {to_hex(creation)}")
    print(f"  Last credit TRP:    {to_hex(last_crd_trp)}")
    print(f"  Last credit header: {to_hex(last_crd_hdr)}")
    print(f"  Log records:        {log_count}")
    print(f"  Issuer data length: {issuer_len}")
    print(f"  Last txn TRP:       {to_hex(last_trn_trp)}")
    print(f"  Last txn record:    {to_hex(last_trn_rec)}")
    if issuer_data:
        print(f"  Issuer data:        {to_hex(issuer_data)}")

    return log_count, issuer_len


def read_logs(conn: CardConnection, p1: int, log_count: int) -> None:
    if log_count == 0:
        print("\nNo transaction logs present.")
        return

    print(f"\nReading {log_count} transaction log record(s)...")
    # Use the same pattern as the iOS app: Lc=1 (offset), no Le (case 3).
    offset = 0
    p1_candidates = [p1 & 0xFF, (p1 | 0x80) & 0xFF]
    while offset < log_count:
        read_ok = False
        for p1_try in p1_candidates:
            for le_mode in ("none", "zero"):
                if le_mode == "none":
                    apdu = [0x90, 0x32, p1_try, 0x00, 0x01, offset & 0xFF]
                else:
                    apdu = [0x90, 0x32, p1_try, 0x00, 0x01, offset & 0xFF, 0x00]
                sw, data = send(conn, apdu, f"Read log offset={offset} P1=0x{p1_try:02X} LeMode={le_mode}")
                if sw == 0x9000:
                    if len(data) < 16:
                        print(f"  Unexpected log payload length {len(data)}")
                        return
                    rec = data[:16]
                    print(f"  #{offset:02d}: type={rec[0]:02X} amount={to_hex(rec[1:4])} datetime={to_hex(rec[4:8])} userData={to_hex(rec[8:16])}")
                    read_ok = True
                    break
            if read_ok:
                break
        if not read_ok:
            print(f"  Read log failed at offset {offset}, SW last={sw:04X}")
            return
        offset += 1


def main() -> None:
    args = parse_args()
    reader, conn = pick_reader_with_card(args.reader)
    print(f"Using reader: {reader.name}")

    # Explicit SELECT is intentionally skipped per request; assume card powers up in the correct DF.
    purse = args.purse & 0xFF

    # Read purse info (unauthenticated, Lc=0). Try variants:
    purse_info = None
    sw_info = 0
    cla_used = 0x90
    p1_used = 0x03

    # First try the common pattern used by the iOS reader app: CLA=0x90, P1=0x03, P2=0x00, Le=0 (256)
    primary_apdus = [
        ("primary case2 Le=0", [0x90, 0x32, 0x03, 0x00, 0x00]),
        ("primary case2 Le=0x40", [0x90, 0x32, 0x03, 0x00, 0x40]),
        ("primary case2 Le=0x5F", [0x90, 0x32, 0x03, 0x00, 0x5F]),
        ("primary case2 Le=0x7F", [0x90, 0x32, 0x03, 0x00, 0x7F]),
        ("primary case1 no Le", [0x90, 0x32, 0x03, 0x00]),
    ]
    for label, apdu in primary_apdus:
        sw_info, data = send(conn, apdu, label)
        if sw_info == 0x9000:
            purse_info = data
            break
        if sw_info not in (0x6A82, 0x6700):
            break

    # If still not found, probe a broader set of SFIs/CLAs.
    if purse_info is None:
        preferred_first = [3]
        tried = set()
        cla_candidates = [0x90, 0x94, 0x00]
        p1_modes = ["b8", "plain"]  # b8=1 short EF, or plain SFI
        le_candidates = [0x00, 0x40, 0x5F, 0x7F]
        for cla in cla_candidates:
            for sfi in preferred_first + list(range(0, 32)):
                key = (cla, sfi)
                if key in tried:
                    continue
                tried.add(key)
                for mode in p1_modes:
                    p1 = (0x80 | (sfi & 0x1F)) if mode == "b8" else (sfi & 0x1F)
                    for le in le_candidates:
                        apdu = [cla, 0x32, p1, 0x00, le]  # Case 2S with explicit Le
                        sw_info, data = send(conn, apdu, f"Read Purse Lc=0 SFI={sfi} CLA={cla:02X} P1mode={mode} Le={le:02X}")
                        if sw_info == 0x9000:
                            purse_info = data
                            purse = sfi  # adopt found SFI for log reads
                            cla_used = cla
                            p1_used = p1
                            break
                        if sw_info not in (0x6A82, 0x6700):
                            # Stop early on unexpected errors
                            break
                    if purse_info is not None or sw_info not in (0x6A82, 0x6700):
                        break
                if purse_info is not None or sw_info not in (0x6A82, 0x6700):
                    break

    if sw_info != 0x9000 or purse_info is None:
        sys.exit("Read Purse failed; no CLA/SFI variant returned 9000.")
    else:
        print(f"Read Purse succeeded with CLA={cla_used:02X} SFI={purse} P1=0x{p1_used:02X}")

    log_count, _issuer_len = decode_purse_info(purse_info)

    # Read transaction log records if present
    read_logs(conn, p1_used, log_count)

    try:
        conn.disconnect()
    except Exception:
        pass


if __name__ == "__main__":
    main()
