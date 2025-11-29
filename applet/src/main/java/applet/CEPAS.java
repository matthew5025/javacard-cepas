package applet;

import javacard.framework.*;

public class CEPAS {
    CEPASPurse[] purses = new CEPASPurse[5];

    void createPurse(short pursePosition) {
        if(pursePosition > 4){
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }

        this.purses[pursePosition] = new CEPASPurse();
    }
}

class CEPASPurse {
    // capacity of transaction logs
    private static final byte MAX_TRN_REC_LEN = 0x1E;  // 30 in decimal

    byte version = 0x02;
    byte purse_status = 0x01;
    byte[] purse_bal = new byte[3];
    byte[] autoload_amt = new byte[]{0x00, 0x07, (byte) 0xD0};
    byte[] can;
    byte[] csn;
    byte[] purse_exp = new byte[] {0x2C, 0x2C};
    byte[] purse_creation = new byte[] {0x20, 0x20};
    byte[] last_crd_trp = new byte[4];
    byte[] last_crd_hdr = new byte[8];
    byte num_trn_records = 0x00;      // how many logs are currently stored
    byte issuer_data_len = 0x20;
    byte[] last_trn_trp = new byte[4];
    byte[] last_trn_rec = new byte[16];
    byte[] issuer_data;

    // We store up to max_trn_rec_len logs
    CEPASTransactionLog[] transaction_logs = new CEPASTransactionLog[MAX_TRN_REC_LEN];

    // Index of the oldest (first) transaction in the ring
    byte trn_log_head = 0x00;

    // One-way lock to prevent accidental overwrites after personalization
    private boolean locked = false;

    CEPASPurse(){
        this.can = new byte[] {(byte) 0x80, 0x08, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00};
        this.csn = new byte[] {(byte) 0x80, 0x08, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00};
        this.num_trn_records = 0x00;
        this.issuer_data = new byte[this.issuer_data_len];
    }



    /**
     * Add a new transaction in FIFO style (ring buffer).
     * If the log is full, remove the oldest transaction to make room.
     */
    void addTransaction(byte[] data) {
        // Calculate the insertion index
        short insertionIndex = (short)((short)(this.trn_log_head + this.num_trn_records) % MAX_TRN_REC_LEN);

        // Create or reuse the log entry at the ring position
        CEPASTransactionLog log = this.transaction_logs[insertionIndex];
        if (log == null) {
            log = new CEPASTransactionLog(data);
            this.transaction_logs[insertionIndex] = log;
        } else {
            log.copyFrom(data);
        }

        if (this.num_trn_records < MAX_TRN_REC_LEN) {
            // We still have space left, so just increase the count
            this.num_trn_records++;
        } else {
            this.trn_log_head = (byte)((this.trn_log_head + 1) % MAX_TRN_REC_LEN);
        }
    }

    void clearLogs() {
        for (short i = 0; i < MAX_TRN_REC_LEN; i++) {
            this.transaction_logs[i] = null;
        }
        this.num_trn_records = 0x00;
        this.trn_log_head = 0x00;
    }

    void lock() {
        this.locked = true;
    }

    boolean isLocked() {
        return this.locked;
    }

    void getTransaction(short offset, short length, byte[] buffer) {
        // Reject offsets beyond the available logs, but allow over-large length requests.
        if (offset >= this.num_trn_records) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Serve up to the remaining records from offset, capped at requested length.
        short available = (short) ((short) this.num_trn_records - offset);
        short toReturn = (length < available) ? length : available;

        // Each record is 16 bytes; ensure caller-provided buffer is large enough (minimal safety for malformed Le).
        short needed = (short) (toReturn * 16);
        if (needed > buffer.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        for (short i = 0; i < toReturn; i++) {
            short readIndex = (short)((short)(this.trn_log_head + offset + i) % MAX_TRN_REC_LEN);
            CEPASTransactionLog log = this.transaction_logs[readIndex];

            if (log == null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // Copy each field (16 bytes total): type, amount[3], dateTime[4], userData[8]
            short base = (short) (16 * i);
            buffer[base] = log.type;
            Util.arrayCopy(log.amount, (short) 0, buffer, (short) (base + 1), (short) 3);
            Util.arrayCopy(log.dateTime, (short) 0, buffer, (short) (base + 4), (short) 4);
            Util.arrayCopy(log.userData, (short) 0, buffer, (short) (base + 8), (short) 8);
        }
    }


    short getPurseInfo(byte[] responseBuffer){
        responseBuffer[0] = version;
        responseBuffer[1] = purse_status;
        Util.arrayCopyNonAtomic(this.purse_bal, (short)0 , responseBuffer, (short)2, (short)3);
        Util.arrayCopyNonAtomic(this.autoload_amt, (short)0 , responseBuffer, (short)5, (short)3);
        Util.arrayCopyNonAtomic(this.can, (short)0 , responseBuffer, (short)8, (short)8);
        Util.arrayCopyNonAtomic(this.csn, (short)0 , responseBuffer, (short)16, (short)8);
        Util.arrayCopyNonAtomic(this.purse_exp, (short)0 , responseBuffer, (short)24, (short)2);
        Util.arrayCopyNonAtomic(this.purse_creation, (short)0 , responseBuffer, (short)26, (short)2);
        Util.arrayCopyNonAtomic(this.last_crd_trp, (short)0 , responseBuffer, (short)28, (short)4);
        Util.arrayCopyNonAtomic(this.last_crd_hdr, (short)0 , responseBuffer, (short)32, (short)8);
        responseBuffer[40] = this.num_trn_records;
        responseBuffer[41] = this.issuer_data_len;
        Util.arrayCopyNonAtomic(this.last_trn_trp, (short)0 , responseBuffer, (short)42, (short)4);
        Util.arrayCopyNonAtomic(this.last_trn_rec, (short)0 , responseBuffer, (short)46, (short)16);
        Util.arrayCopyNonAtomic(this.issuer_data, (short)0 , responseBuffer, (short)62, this.issuer_data_len);
        return (short) (62 + this.issuer_data_len);
    }


}

class CEPASTransactionLog{
    byte type;
    byte[] amount = new byte[3];
    byte[] dateTime = new byte[4];
    byte[] userData = new byte[8];

    CEPASTransactionLog(byte[] data) {
        this.type = data[0];
        Util.arrayCopy(data, (short) 1, this.amount, (short) 0, (short) 3);
        Util.arrayCopy(data, (short) 4, this.dateTime, (short) 0, (short) 4);
        Util.arrayCopy(data, (short) 8, this.userData, (short) 0, (short) 8);

    }

    void copyFrom(byte[] data) {
        this.type = data[0];
        Util.arrayCopy(data, (short) 1, this.amount, (short) 0, (short) 3);
        Util.arrayCopy(data, (short) 4, this.dateTime, (short) 0, (short) 4);
        Util.arrayCopy(data, (short) 8, this.userData, (short) 0, (short) 8);
    }
}
