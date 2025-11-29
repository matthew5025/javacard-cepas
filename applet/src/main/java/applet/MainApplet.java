package applet;

import javacard.framework.*;
import javacard.security.RandomData;

public class MainApplet extends Applet implements MultiSelectable {
    private static final byte CLA_PROPRIETARY = (byte) 0x90;
    private static final byte INS_RANDOM = (byte) 0x00;
    private static final byte INS_CUSTOMIZATION = (byte) 0xF0;
    private static final byte INS_GET_PURSE_INFO = (byte) 0x32;

    private static final short BUFFER_SIZE = 256;

    private final byte[] tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    private final RandomData random;
    private CEPAS cepas;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet(bArray, bOffset, bLength).register();
    }

    public MainApplet(byte[] buffer, short offset, byte length) {
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    @Override
    public boolean select(boolean b) {
        return true;
    }

    @Override
    public void deselect(boolean b) {
        // Nothing special on deselect
    }

    @Override
    public void process(APDU apdu) {
        // If this is the SELECT APDU (selecting the applet), skip custom INS processing
        if (selectingApplet()) {
            return;
        }

        byte[] apduBuffer = apdu.getBuffer();
        byte cla = apduBuffer[ISO7816.OFFSET_CLA];
        byte ins = apduBuffer[ISO7816.OFFSET_INS];
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0xFF);

        // ------------------------------------------------------------------
        // EXTENDED-LENGTH SUPPORT
        // We read the entire incoming APDU data (if any) here in process().
        // This handles both short and extended Lc gracefully.
        // ------------------------------------------------------------------
        short incomingLength = 0;
        try {
            incomingLength = apdu.getIncomingLength(); // total data bytes (throws on case 1/2)
        } catch (APDUException ignored) {
            incomingLength = 0; // No incoming data; treat as case 1/2
        }
        if (incomingLength > 0) {
            // Perform initial receive
            short readCount = apdu.setIncomingAndReceive();

            // If extended length is large, keep calling receiveBytes(...)
            // until we have read all of it into apduBuffer.
            short bytesRemaining = incomingLength;
            while (bytesRemaining > 0) {
                bytesRemaining -= readCount;
                if (bytesRemaining > 0) {
                    readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
                }
            }

            // Re-fetch apduBuffer in case the JCRE reallocated it
            apduBuffer = apdu.getBuffer();
        }

        final byte[] buffer = apduBuffer;
        // Fallback for cards where getIncomingLength() returns 0: use Lc byte.
        short dataLength = incomingLength;
        if (dataLength == 0) {
            dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        }

        // Now we can do normal command processing.
        // Instead of referencing apduBuffer[ISO7816.OFFSET_LC], we use `incomingLength`.

        // Example INS == 0x00 => Return random data
        if (ins == INS_RANDOM) {
            handleRandom(apdu);
            return;
        }

        // If CLA != 0x90, handle possible 0x00 CLA commands or throw
        if (cla != CLA_PROPRIETARY) {
            handleClaZeroOrThrow(apdu, buffer, cla, ins, p1, p2);
            return;
        }

        // From here on, assume CLA == 0x90
        switch (ins) {
            case INS_CUSTOMIZATION:
                // Card Customization
                processCustomization(apdu, buffer, p1, p2, incomingLength);
                return;

            case INS_GET_PURSE_INFO:
                // Possibly read purse info or transactions
                processGetPurseInfo(apdu, buffer, p1, incomingLength);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Handles the scenario when CLA != 0x90, specifically checks for
     * CLA=0x00 with known INS values. Otherwise, throws SW_CLA_NOT_SUPPORTED.
     */
    private void handleClaZeroOrThrow(APDU apdu, byte[] apduBuffer, byte cla, byte ins, short p1, short p2) {
        if (cla == (byte) 0x00 && ins == (byte) 0xA4) {
            // Handle SELECT file or app
            if (p1 == 0x00) {
                byte[] response = {
                        (byte) 0x84, (byte) 0x08, (byte) 0xa0, (byte) 0x00,
                        (byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x78,
                        (byte) 0x34, (byte) 0x31
                };
                Util.arrayCopyNonAtomic(response, (short) 0, apduBuffer, (short) 0, (short) response.length);
                apdu.setOutgoingAndSend((short) 0, (short) response.length);
                return;
            }
            if (p1 == 0x04) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        } else if (cla == (byte) 0x00 && ins == (byte) 0x84) {
            // GET CHALLENGE or random-like
            byte [] response = {
                    (byte) 0x32, (byte) 0xa5, (byte) 0x83, (byte) 0x12,
                    (byte) 0x02, (byte) 0x4e, (byte) 0x84, (byte) 0x28
            };
            Util.arrayCopyNonAtomic(response, (short) 0, apduBuffer, (short) 0, (short) response.length);
            apdu.setOutgoingAndSend((short) 0, (short) response.length);
            return;
        }
        // If we get here, CLA is not recognized
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    /**
     * Generates random data (256 bytes) into tmpBuffer and returns it.
     */
    private void handleRandom(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        random.generateData(tmpBuffer, (short) 0, BUFFER_SIZE);
        Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, apduBuffer, (short) 0, BUFFER_SIZE);
        apdu.setOutgoingAndSend((short) 0, BUFFER_SIZE);
    }

    /**
     * Processes the "Card Customisation" command (INS=0xF0).
     * Now uses the extended-length-friendly `incomingLength` for data checks.
     */
    private void processCustomization(APDU apdu, byte[] apduBuffer, short p1, short p2, short incomingLength) {
        // Ensure CEPAS is initialized
        if (cepas == null) {
            cepas = new CEPAS();
        }

        // Derive the actual data length; getIncomingLength() can return 0 on some stacks.
        short dataLength = incomingLength;
        if (dataLength == 0) {
            dataLength = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
        }

        if (p1 < 0 || p1 >= cepas.purses.length) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        switch ((byte) p2) {
            case (byte) 0xFF:
                // Create a new purse at index p1
                cepas.createPurse((byte) p1);
                sendNoData(apdu);
                return;

            case (byte) 0xFD:
                // One-way lock to prevent further customization edits
                ensurePurseExists(p1);
                cepas.purses[p1].lock();
                sendNoData(apdu);
                return;

            case (byte) 0xFE:
                // Copy entire Purse data from APDU (header only; logs must be added via 0x0E per record)
                if (dataLength != 95) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                ensurePurseExists(p1);
                ensureMutable(p1);
                // The entire data is already in apduBuffer
                // Offsets from 5.. end
                cepas.purses[p1].version = apduBuffer[5];
                cepas.purses[p1].purse_status = apduBuffer[6];
                Util.arrayCopyNonAtomic(apduBuffer, (short) 7,  cepas.purses[p1].purse_bal,      (short) 0, (short) 3);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 10, cepas.purses[p1].autoload_amt,   (short) 0, (short) 3);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 13, cepas.purses[p1].can,            (short) 0, (short) 8);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 21, cepas.purses[p1].csn,            (short) 0, (short) 8);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 29, cepas.purses[p1].purse_exp,      (short) 0, (short) 2);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 31, cepas.purses[p1].purse_creation, (short) 0, (short) 2);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 33, cepas.purses[p1].last_crd_trp,   (short) 0, (short) 4);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 37, cepas.purses[p1].last_crd_hdr,   (short) 0, (short) 8);
                cepas.purses[p1].num_trn_records = apduBuffer[45];
                cepas.purses[p1].issuer_data_len = apduBuffer[46];
                Util.arrayCopyNonAtomic(apduBuffer, (short) 47, cepas.purses[p1].last_trn_trp,   (short) 0, (short) 4);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 51, cepas.purses[p1].last_trn_rec,   (short) 0, (short) 16);
                Util.arrayCopyNonAtomic(apduBuffer, (short) 67, cepas.purses[p1].issuer_data,    (short) 0, (short) 32);
                // Reset logs; personalization image does not include them
                cepas.purses[p1].clearLogs();
                cepas.purses[p1].lock(); // Lock immediately after full personalization copy
                sendNoData(apdu);
                return;

            case (byte) 0x00: // set version
                checkLengthExact(dataLength, (short) 1);
                ensurePurseExists(p1);
                ensureMutable(p1);
                cepas.purses[p1].version = apduBuffer[5];
                sendNoData(apdu);
                return;

            case (byte) 0x01: // set purse_status
                checkLengthExact(dataLength, (short) 1);
                ensurePurseExists(p1);
                ensureMutable(p1);
                cepas.purses[p1].purse_status = apduBuffer[5];
                sendNoData(apdu);
                return;

            case (byte) 0x02: // set purse_bal
                checkLengthExact(dataLength, (short) 3);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].purse_bal, (short) 0, (short) 3);
                sendNoData(apdu);
                return;

            case (byte) 0x03: // set autoload_amt
                checkLengthExact(dataLength, (short) 3);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].autoload_amt, (short) 0, (short) 3);
                sendNoData(apdu);
                return;

            case (byte) 0x04: // set CAN
                checkLengthExact(dataLength, (short) 8);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].can, (short) 0, (short) 8);
                sendNoData(apdu);
                return;

            case (byte) 0x05: // set CSN
                checkLengthExact(dataLength, (short) 8);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].csn, (short) 0, (short) 8);
                sendNoData(apdu);
                return;

            case (byte) 0x06: // set purse_exp
                checkLengthExact(dataLength, (short) 2);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].purse_exp, (short) 0, (short) 2);
                sendNoData(apdu);
                return;

            case (byte) 0x07: // set purse_creation
                checkLengthExact(dataLength, (short) 2);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].purse_creation, (short) 0, (short) 2);
                sendNoData(apdu);
                return;

            case (byte) 0x08: // set last_crd_trp
                checkLengthExact(dataLength, (short) 4);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].last_crd_trp, (short) 0, (short) 4);
                sendNoData(apdu);
                return;

            case (byte) 0x09: // set last_crd_hdr
                checkLengthExact(dataLength, (short) 8);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].last_crd_hdr, (short) 0, (short) 8);
                sendNoData(apdu);
                return;

            case (byte) 0x0A: // set num_trn_records
                checkLengthExact(dataLength, (short) 1);
                ensurePurseExists(p1);
                ensureMutable(p1);
                cepas.purses[p1].num_trn_records = apduBuffer[5];
                sendNoData(apdu);
                return;

            case (byte) 0x0B: // set last_trn_trp
                checkLengthExact(dataLength, (short) 4);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].last_trn_trp, (short) 0, (short) 4);
                sendNoData(apdu);
                return;

            case (byte) 0x0C: // set last_trn_rec
                checkLengthExact(dataLength, (short) 16);
                ensurePurseExists(p1);
                ensureMutable(p1);
                Util.arrayCopy(apduBuffer, (short) 5, cepas.purses[p1].last_trn_rec, (short) 0, (short) 16);
                sendNoData(apdu);
                return;

            case (byte) 0x0D: // set issuer_data
                // Must match issuer_data_len
                ensurePurseExists(p1);
                ensureMutable(p1);
                if (dataLength != (short) cepas.purses[p1].issuer_data_len) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                Util.arrayCopy(apduBuffer, (short) 5,
                        cepas.purses[p1].issuer_data, (short) 0,
                        cepas.purses[p1].issuer_data_len);
                sendNoData(apdu);
                return;

            case (byte) 0x0E: // add Transaction (16 bytes)
                checkLengthExact(dataLength, (short) 16);
                ensurePurseExists(p1);
                Util.arrayCopy(apduBuffer, (short) 5, tmpBuffer, (short) 0, (short) 16);
                cepas.purses[p1].addTransaction(tmpBuffer);
                sendNoData(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * Processes INS=0x32: either returns purse info or transaction data.
     */
    private void processGetPurseInfo(APDU apdu, byte[] apduBuffer, short p1, short incomingLength) {
        if (cepas == null || p1 < 0 || p1 >= cepas.purses.length || cepas.purses[p1] == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        short dataLength = incomingLength;
        if (dataLength == 0) {
            dataLength = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
        }

        if (dataLength == 0) {
            // Return purse info
            short resultLen = cepas.purses[p1].getPurseInfo(tmpBuffer);
            Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, apduBuffer, (short) 0, resultLen);
            apdu.setOutgoingAndSend((short) 0, resultLen);

        } else if (dataLength == 1) {
            // Return transaction data
            short offset = apduBuffer[5]; // single byte
            // Case 3: no Le supplied, default to 1 record (16 bytes).
            short le = apdu.setOutgoing();
            if (le == 0) {
                le = 16;
            }
            short numRecs = (short) (((short) (le + 16 - 1)) / 16);
            cepas.purses[p1].getTransaction(offset, numRecs, apdu.getBuffer());
            short outLen = (short) (numRecs * 16);
            apdu.setOutgoingLength(outLen);
            apdu.sendBytes((short) 0, outLen);

        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * Quick helper: check that 'actualLength' == 'expectedLength' or throw 6A82.
     */
    private void checkLengthExact(short actualLength, short expectedLength) {
        if (actualLength != expectedLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    private void ensurePurseExists(short p1) {
        if (cepas == null || p1 < 0 || p1 >= cepas.purses.length || cepas.purses[p1] == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private void ensureMutable(short p1) {
        if (cepas.purses[p1].isLocked()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private void sendNoData(APDU apdu) {
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

}
