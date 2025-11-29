package applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Minimal binary file store keyed by SFI.
 * Data bytes are generated on demand via a provider to avoid hard‑coded blobs.
 */
class FileStore {
    private static final byte MAX_SFI = 0x1E; // 30
    private static final short MAX_FILE_LENGTH = 256; // cap to keep memory bounded

    private static class BinaryFile {
        final short length;
        boolean authRequired;
        final byte[] data;

        BinaryFile(short length, boolean authRequired) {
            this.length = length;
            this.authRequired = authRequired;
            this.data = new byte[length]; // zero-initialised
        }
    }

    private final BinaryFile[] files = new BinaryFile[MAX_SFI + 1]; // index by SFI (1..30)

    void createFile(byte sfi, short length, boolean authRequired) {
        if (sfi <= 0 || sfi > MAX_SFI) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (length <= 0 || length > MAX_FILE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        files[sfi] = new BinaryFile(length, authRequired);
    }

    void deleteFile(byte sfi) {
        if (sfi <= 0 || sfi > MAX_SFI) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        files[sfi] = null;
    }

    void clearAll() {
        for (byte i = 1; i <= MAX_SFI; i++) {
            files[i] = null;
        }
    }

    /**
     * Implements READ BINARY by SFI (CLA=00, INS=B0, P1 bit7=1).
     */
    void readBySfi(APDUContext ctx) {
        byte[] buf = ctx.apduBuffer;
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        // SFI present only if bit7 set
        if ((p1 & (byte) 0x80) == 0) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND); // 6A82
        }
        byte sfi = (byte) (p1 & 0x1F);
        if (sfi == 0 || sfi > MAX_SFI) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        BinaryFile file = files[sfi];
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND); // 6A82
        }
        if (file.authRequired) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); // 6982
        }

        short offset = (short) (p2 & 0xFF); // SFI mode: offset lives in P2
        if (offset > file.length) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND); // 6A82
        }
        short le;
        try {
            le = ctx.apdu.setOutgoing();
        } catch (Exception ignored) {
            le = 0;
        }
        if (le == 0) {
            le = 256; // Le=00 => 256 bytes
        }
        if (offset == file.length && le > 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); // 6700 observed when offset=end
        }

        short available = (short) (file.length - offset);
        short toSend = (le < available) ? le : available;
        if (toSend < 0) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        // Send directly from backing file buffer to avoid overrunning the APDU buffer on case 2S.
        ctx.apdu.setOutgoing();
        ctx.apdu.setOutgoingLength(toSend);
        ctx.apdu.sendBytesLong(file.data, offset, toSend);
    }

    /**
     * Update a file's data and optionally flip its authRequired flag.
     * @param sfi target SFI (1-30)
     * @param flags bit0=1 means set auth flag; bit1 carries the new authRequired value
     * @param apduBuffer APDU buffer
     * @param dataOffset offset within buffer where the APDU data begins (Lc region)
     * @param dataLen length of APDU data
     */
    void writeFile(byte sfi, byte flags, byte[] apduBuffer, short dataOffset, short dataLen) {
        if (sfi <= 0 || sfi > MAX_SFI) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        BinaryFile file = files[sfi];
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        if (dataLen < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short offset = (short) (apduBuffer[dataOffset] & 0xFF);
        short payloadLen = (short) (dataLen - 1);
        if ((short) (offset + payloadLen) > file.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Flip auth flag if requested
        if ((flags & 0x01) != 0) {
            file.authRequired = (flags & 0x02) != 0;
        }

        if (payloadLen > 0) {
            Util.arrayCopy(apduBuffer, (short) (dataOffset + 1), file.data, offset, payloadLen);
        }
    }

    void setAuth(byte sfi, boolean authRequired) {
        if (sfi <= 0 || sfi > MAX_SFI) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        BinaryFile file = files[sfi];
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        file.authRequired = authRequired;
    }

    short listFiles(byte[] out, short outOff) {
        short count = 0;
        for (byte sfi = 1; sfi <= MAX_SFI; sfi++) {
            BinaryFile f = files[sfi];
            if (f == null) continue;
            short idx = (short) (outOff + count * 4);
            if ((short) (idx + 4) > out.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            out[idx] = sfi;
            out[(short) (idx + 1)] = (byte) (f.length >> 8);
            out[(short) (idx + 2)] = (byte) (f.length & 0xFF);
            out[(short) (idx + 3)] = (byte) (f.authRequired ? 1 : 0);
            count++;
        }
        return (short) (count * 4);
    }

    /**
     * Simple context holder to avoid passing multiple parameters around.
     */
    static class APDUContext {
        final javacard.framework.APDU apdu;
        final byte[] apduBuffer;

        APDUContext(javacard.framework.APDU apdu, byte[] buffer) {
            this.apdu = apdu;
            this.apduBuffer = buffer;
        }
    }
}
