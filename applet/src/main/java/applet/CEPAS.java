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

class CEPASPurse{
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
    byte num_trn_records = 0x00;
    byte issuer_data_len = 0x20;
    byte[] last_trn_trp = new byte[4];
    byte[] last_trn_rec = new byte[16];
    byte[] issuer_data;
    byte max_trn_rec_len = 0x1E;
    CEPASTransactionLog[] transaction_logs = new CEPASTransactionLog[max_trn_rec_len];
    byte trn_log_head = 0x00;

    CEPASPurse(){
        this.can = new byte[] {(byte) 0x80, 0x08, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00};
        this.csn = new byte[] {(byte) 0x80, 0x08, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00};
        this.num_trn_records = 0x00;
        this.issuer_data = new byte[this.issuer_data_len];
    }

    void addTransaction(byte[] data) {
        if(this.num_trn_records == max_trn_rec_len){
            CEPASTransactionLog log = transaction_logs[this.trn_log_head];
            log.type = data[0];
            Util.arrayCopy(data, (short) 1, log.amount, (short) 0, (short) 3);
            Util.arrayCopy(data, (short) 4, log.dateTime, (short) 0, (short) 4);
            Util.arrayCopy(data, (short) 8, log.dateTime, (short) 0, (short) 8);
            if(this.trn_log_head + 1 == this.max_trn_rec_len){
                this.trn_log_head = 0;
            }
            else {
                this.trn_log_head = (byte) (this.trn_log_head + 1);
            }
        }
        else {
            CEPASTransactionLog log = new CEPASTransactionLog(data);
            transaction_logs[this.num_trn_records] = log;
            this.num_trn_records++;
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

    void getTransaction(short offset, short length, byte[] buffer){
        for(short i = 0; i < length; i++){
            buffer[(short)(16 * i)] = transaction_logs[(short)(i + offset)].type;
            Util.arrayCopy(transaction_logs[(short)(i + offset)].amount, (short) 0, buffer, (short)(1 + ((i) * 16)), (short) 3);
            Util.arrayCopy(transaction_logs[(short)(i + offset)].dateTime, (short) 0, buffer, (short)(4 + ((i) * 16)), (short) 4);
            Util.arrayCopy(transaction_logs[(short)(i + offset)].userData, (short) 0, buffer, (short)(8 + ((i) * 16)), (short) 8);
        }
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
}