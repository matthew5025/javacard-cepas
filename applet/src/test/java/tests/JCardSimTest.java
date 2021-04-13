package tests;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class JCardSimTest {

    public static void main(String[] args) {
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, MainApplet.class);

        simulator.selectApplet(appletAID);

        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x00, 0x00, 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        System.out.println(response);

        commandAPDU = new CommandAPDU(0x90, 0xF0, 0x03, 0xFF);
        response = simulator.transmitCommand(commandAPDU);
        System.out.println(response);

        commandAPDU = new CommandAPDU(0x90, 0xF0, 0x03, 0xFE, hexStringToByteArray("02 01 00 FF FF 00 07 D0 80 09 12 34 56 78 90 00 51 03 03 47 13 C3 01 09 1E D8 1E 44 00 25 21 FF 75 00 03 E8 28 26 E2 E2 00 20 00 10 01 01 76 00 00 3E 28 A8 07 46 53 56 43 20 20 33 37 00 02 00 80 30 30 00 00 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"));
        response = simulator.transmitCommand(commandAPDU);
        System.out.println(response);


        commandAPDU = new CommandAPDU(0x90, 0xF0, 0x03, 0x0E, hexStringToByteArray("30  ff  ff  54  2c  8a  f6 54 54  50  45  2d  59  43  4b  20  "));
        response = simulator.transmitCommand(commandAPDU);
        System.out.println(response);


        commandAPDU = new CommandAPDU(0x90, 0xF0, 0x03, 0x0E, hexStringToByteArray("30  ff  ff  54  2c  8a  f6  54  54  50  45  2d  59  43  4b  20"));
        response = simulator.transmitCommand(commandAPDU);
        System.out.println(response);

        commandAPDU = new CommandAPDU(0x90, 0x32, 0x03, 0x00, hexStringToByteArray("00"), 0x10);
        response = simulator.transmitCommand(commandAPDU);
        System.out.println(response);

    }

    public static byte[] hexStringToByteArray(String s) {
        s = s.replaceAll("\\s+","");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }


}

