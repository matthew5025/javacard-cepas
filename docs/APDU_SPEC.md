## CEPAS JavaCard APDU Map

This documents the APDUs implemented by `applet.MainApplet` and what the bundled probes exercise.

### AIDs
- Package AID: `A0:00:00:03:41:00:01`
- Applet AID:  `A0:00:00:03:41:00:01:01`

### SELECT (pre-applet handling)
- CLA/INS: `00 A4`
- P1=`00` (by name) → returns FCI `84 08 A0 00 00 03 00 78 34 31`, SW `9000`
- P1=`04` (by AID) → `6A82` (wrong length)

### GET CHALLENGE shim
- CLA/INS: `00 84`
- Response: fixed 8 bytes `32 A5 83 12 02 4E 84 28`, SW `9000`

### Random generator
- CLA/INS: `90 00`
- Request: case 1
- Response: 256 random bytes, SW `9000`

### Customization / Personalization (INS `F0`)
- CLA/INS: `90 F0`
- P1: purse index `0..4`; out of range → `6A86`
- P2 values:
- `FF` create purse slot; SW `9000`
- `FB` wipe challenge: returns 4-byte nonce, SW `9000`
- `FC` wipe execute: Lc=4 echoing nonce from `FB`; deletes slot even if locked; bad/missing nonce → `6985`/`6982`
- `FD` lock purse (one-way); SW `9000`
- `FE` bulk load 95-byte purse image then lock; wrong Lc → `6A82`
- `FA` reset purse slot to defaults (clears logs/data, recreates purse unlocked); SW `9000`
  - Field setters (Lc must match width):
    - `00` version (1)
    - `01` purse_status (1)
    - `02` purse_bal (3)
    - `03` autoload_amt (3)
    - `04` CAN (8)
    - `05` CSN (8)
    - `06` purse_exp (2)
    - `07` purse_creation (2)
    - `08` last_crd_trp (4)
    - `09` last_crd_hdr (8)
    - `0A` num_trn_records (1)
    - `0B` last_trn_trp (4)
    - `0C` last_trn_rec (16)
    - `0D` issuer_data (len must equal issuer_data_len)
    - `0E` add transaction log (16) appended into 30-entry ring buffer
- Locked or missing purse → `6985` (`SW_CONDITIONS_NOT_SATISFIED`)

### Read Purse / Logs (INS `32`)
- CLA/INS: `90 32`
- P1: purse index `0..4`; must exist else `6985`
- Cases:
  - `Lc=0`: returns purse header (length `63 + issuer_data_len`, trailing tail byte), SW `9000`
  - `Lc=1`: data[0]=log offset; Le **must be present**. `Le=0` requests 256 bytes; `Le` missing → `6700`; returns N×16 bytes up to available logs, SW `9000`. Offset ≥ log_count → `6A82`
  - Other Lc: `6985`

### Reader-side discovery (not enforced by applet)
- READ BINARY by SFI: `00 B0 (80|sfi) 00 Le=00` for SFI 1–30 (used by Python/iOS probe).
- DF/FID reads: SELECT DF `00 A4 00 00 02 40 00`, then SELECT EF by FID and READ BINARY chunks `00 B0 p1 p2 Le` (Le=00 for 256-byte chunks).

### Emulated file store (SFI READ/WRITE/LIST)
- READ BINARY
  - CLA/INS: `00 B0`
  - P1 bit7 must be 1 (SFI present), P1 low bits = SFI (1–30); P2 = offset (byte)
  - Status words:
    - Missing SFI or bad P1 bit7 or offset > length → `6A82`
    - File marked auth-required → `6982`
    - Offset == length with Le>0 → `6700`
    - Success → `9000`; Le=00 returns up to 256 bytes capped by remaining length
  - Files are provisioned dynamically; no hardcoded SFIs or lengths.

- Proprietary file admin
  - CLA/INS: `90 F1`
  - P1: SFI (1–30)
  - P2 sub-ops:
    - `00` WRITE: data = `offset (1B)` + payload; bounds-checked to file length
    - `01` CREATE: data = `len_hi len_lo authFlag` [+ optional initial payload]; length capped; creates or replaces
    - `02` DELETE: no data
    - `03` SET_AUTH: data = `authFlag`
    - `10` LIST: no data; returns entries of existing files, each 4 bytes `[sfi, len_hi, len_lo, authFlag]`
  - Common rules:
    - Missing SFI for WRITE/SET_AUTH/DELETE → `6A82`; bad lengths → `6A82`
    - WRITE allowed even if authRequired is set (no real auth implemented)
    - All data is persisted (EEPROM-backed arrays)

### Status word conventions
- Unsupported CLA/INS: `6E00` / `6D00`
- Wrong length: `6A82`
- Conditions not satisfied (locked/missing): `6985`
