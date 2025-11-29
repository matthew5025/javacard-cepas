package tests;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.smartcardio.*;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Tag("manual")
class ManualCardIntegrationTest {

    private static final byte[] APP_AID = {(byte) 0xA0, 0x00, 0x00, 0x03, 0x41, 0x00, 0x01, 0x01};

    // Helper to open first available reader or one named in READER env.
    private CardChannel openChannel() throws Exception {
        TerminalFactory tf = TerminalFactory.getDefault();
        List<CardTerminal> terms = tf.terminals().list();
        if (terms.isEmpty()) {
            throw new IllegalStateException("No PC/SC readers found");
        }

        String preferred = System.getenv("READER");
        CardTerminal term = terms.get(0);
        if (preferred != null) {
            for (CardTerminal t : terms) {
                if (t.getName().contains(preferred)) {
                    term = t;
                    break;
                }
            }
        }

        if (!term.isCardPresent()) {
            throw new IllegalStateException("Card not present in reader: " + term.getName());
        }

        Card card = term.connect("T=1");
        return card.getBasicChannel();
    }

    private ResponseAPDU send(CardChannel ch, int cla, int ins, int p1, int p2, byte[] data, int le) throws Exception {
        CommandAPDU cmd;
        if (data == null || data.length == 0) {
            cmd = (le >= 0) ? new CommandAPDU(cla, ins, p1, p2, le) : new CommandAPDU(cla, ins, p1, p2);
        } else {
            cmd = (le >= 0) ? new CommandAPDU(cla, ins, p1, p2, data, le) : new CommandAPDU(cla, ins, p1, p2, data);
        }
        return ch.transmit(cmd);
    }

    @Test
    void createWriteAndReadPurse() throws Exception {
        CardChannel ch = openChannel();

        // SELECT
        ResponseAPDU sel = send(ch, 0x00, 0xA4, 0x04, 0x00, APP_AID, 0);
        assertEquals(0x9000, sel.getSW(), "SELECT failed");

        // Create purse at index 0
        ResponseAPDU create = send(ch, 0x90, 0xF0, 0x00, 0xFF, new byte[0], 0);
        assertEquals(0x9000, create.getSW(), "Create purse failed");

        // Set balance to 0x00 0x27 0x10 (10,000 decimal)
        byte[] bal = {(byte) 0x00, 0x27, 0x10};
        ResponseAPDU setBal = send(ch, 0x90, 0xF0, 0x00, 0x02, bal, 0);
        assertEquals(0x9000, setBal.getSW(), "Set balance failed");

        // Read purse info
        ResponseAPDU info = send(ch, 0x90, 0x32, 0x00, 0x00, new byte[0], 0);
        assertEquals(0x9000, info.getSW(), "Get purse info failed");
        byte[] data = info.getData();
        assertTrue(data.length >= 94, "Unexpected purse info length: " + data.length);

        // Balance is bytes 2..4
        assertArrayEquals(bal, new byte[]{data[2], data[3], data[4]}, "Balance mismatch");
    }
}
