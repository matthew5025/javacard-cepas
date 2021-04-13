package applet;

import javacard.framework.*;
import javacard.security.RandomData;


public class MainApplet extends Applet implements MultiSelectable {
    private static final short BUFFER_SIZE = 256;

    private byte[] tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    private RandomData random;
    private byte[] data;
    private CEPAS cepas;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet(bArray, bOffset, bLength).register();
    }

    public MainApplet(byte[] buffer, short offset, byte length) {
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (data == null) {
            data = new byte[]{0, 0, 0, 0, 0};
        }
    }

    public void process(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte cla = apduBuffer[ISO7816.OFFSET_CLA];
        byte ins = apduBuffer[ISO7816.OFFSET_INS];
        short lc = (short) apduBuffer[ISO7816.OFFSET_LC];
        short p1 = (short) apduBuffer[ISO7816.OFFSET_P1];
        short p2 = (short) apduBuffer[ISO7816.OFFSET_P2];
        short bytesLeft = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0x00FF);


        if (ins == 0x00) {
            random.generateData(tmpBuffer, (short) 0, BUFFER_SIZE);
            Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, apduBuffer, (short) 0, BUFFER_SIZE);
            apdu.setOutgoingAndSend((short) 0, BUFFER_SIZE);
            return;
        }

        if (cla != (byte) 0x90) {
            if(cla == (byte) 0x00 && ins == (byte) 0xA4){
                if(p1 == 0x00){
                    byte[] response = {(byte) 0x84, (byte)0x08, (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x78, (byte)0x34, (byte)0x31};
                    Util.arrayCopyNonAtomic(response, (short) 0, apduBuffer, (short) 0, (short) 10);
                    apdu.setOutgoingAndSend((short) 0, (short) 10);
                    return;
                }
                if(p1 == 0x04){
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
            }
            if(cla == (byte) 0x00 && ins == (byte) 0x84){
                byte [] response = {(byte)0x32, (byte)0xa5, (byte)0x83, (byte)0x12, (byte)0x02, (byte)0x4e, (byte)0x84, (byte)0x28};
                Util.arrayCopyNonAtomic(response, (short) 0, apduBuffer, (short) 0, (short) 8);
                apdu.setOutgoingAndSend((short) 0, (short) 8);
                return;

            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }


        //Card Customisation
        if (ins == (byte) 0xF0) {
            switch (p2) {
                case (byte) 0xFF:
                    if(cepas == null){
                        cepas = new CEPAS();
                    }
                    cepas.createPurse(p1);
                    apdu.setOutgoingAndSend((short) 0, (short) 0);
                    return;
                case (byte) 0xFE:
                    if(bytesLeft != 95){
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    }else {
                        apdu.setIncomingAndReceive();
                        apduBuffer = apdu.getBuffer();
                        cepas.purses[p1].version = apduBuffer[5];
                        cepas.purses[p1].purse_status = apduBuffer[6];
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 7, cepas.purses[p1].purse_bal, (short) 0, (short) 3);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 10, cepas.purses[p1].autoload_amt, (short) 0, (short) 3);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 13, cepas.purses[p1].can, (short) 0, (short) 8);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 21, cepas.purses[p1].csn, (short) 0, (short) 8);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 29, cepas.purses[p1].purse_exp, (short) 0, (short) 2);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 31, cepas.purses[p1].purse_creation, (short) 0, (short) 2);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 33, cepas.purses[p1].last_crd_trp, (short) 0, (short) 4);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 37, cepas.purses[p1].last_crd_hdr, (short) 0, (short) 8);
                        cepas.purses[p1].num_trn_records = apduBuffer[45];
                        cepas.purses[p1].issuer_data_len = apduBuffer[46];
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 47, cepas.purses[p1].last_trn_trp, (short) 0, (short) 4);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 51, cepas.purses[p1].last_trn_rec, (short) 0, (short) 16);
                        Util.arrayCopyNonAtomic(apduBuffer, (short) 67, cepas.purses[p1].issuer_data, (short) 0, (short) 32);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte) 0x00:
                    if (bytesLeft != 1) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        cepas.purses[p1].version = apdu.getBuffer()[5];
                        return;
                    }
                    break;
                case (byte) 0x01:
                    if (bytesLeft != 1) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        cepas.purses[p1].purse_status = apdu.getBuffer()[5];
                        return;
                    }
                    break;
                case(byte) 0x02:
                    if (bytesLeft != 3) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].purse_bal, (short) 0, (short) 3);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x03:
                    if (bytesLeft != 3) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].autoload_amt, (short) 0, (short) 3);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x04:
                    if (bytesLeft != 8) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].can, (short) 0, (short) 8);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x05:
                    if (bytesLeft != 8) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].csn, (short) 0, (short) 8);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x06:
                    if (bytesLeft != 2) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].purse_exp, (short) 0, (short) 2);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x07:
                    if (bytesLeft != 2) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].purse_creation, (short) 0, (short) 2);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x08:
                    if (bytesLeft != 4) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].last_crd_trp, (short) 0, (short) 4);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x09:
                    if (bytesLeft != 8) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].last_crd_hdr, (short) 0, (short) 8);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x0A:
                    if (bytesLeft != 1) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        cepas.purses[p1].num_trn_records = apdu.getBuffer()[5];
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte)0x0B:
                    if (bytesLeft != 4) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].last_trn_trp, (short) 0, (short) 4);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case(byte) 0x0C:
                    if (bytesLeft != 16) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].last_trn_rec, (short) 0, (short) 16);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case(byte) 0x0D:
                    if (bytesLeft != cepas.purses[p1].issuer_data_len) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, cepas.purses[p1].issuer_data, (short) 0, (short) cepas.purses[p1].issuer_data_len);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;
                case (byte) 0x0E:
                    if (bytesLeft != 16) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    } else {
                        apdu.setIncomingAndReceive();
                        Util.arrayCopy(apdu.getBuffer(), (short) 5, tmpBuffer, (short) 0, (short) 16);
                        cepas.purses[p1].addTransaction(tmpBuffer);
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        return;
                    }
                    break;

            }
        }

        switch (ins) {
            case (byte) 0x32:
                if (lc == 0x00) {
                    short resultLen = cepas.purses[p1].getPurseInfo(tmpBuffer);
                    Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, apduBuffer, (short) 0, resultLen);
                    apdu.setOutgoingAndSend((short) 0, resultLen);

                } else if (lc == 0x01) {
                    if(bytesLeft != 1){
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    }else {
                        apdu.setIncomingAndReceive();
                        short offset = apdu.getBuffer()[5];
                        short le = apdu.setOutgoing();
                        cepas.purses[p1].getTransaction(offset, (short)(((short)(le + (short)16 - (short)1) / (short)16)), apdu.getBuffer());
                        apdu.setOutgoingLength(le);
                        apdu.sendBytes((short) 0, le);
                        return;
                    }
                }
                else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                break;
        }

    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }

}
