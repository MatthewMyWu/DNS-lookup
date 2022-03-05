package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.IntStream;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;
    public static final int QUERY = 0;
    /**
     * TODO:  You will add additional constants and fields
     */
    private final Map<String, Integer> nameToPosition = new HashMap<>();
    private final Map<Integer, String> positionToName = new HashMap<>();
    private final ByteBuffer buffer;


    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */
    public DNSMessage(short id) {
        id = (id == 0) ? 23 : id;
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
        buffer.putShort(id);
        this.buffer.position(12);
        // TODO: Complete this method
    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd  The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        buffer = ByteBuffer.wrap(recvd, 0, length);
        this.buffer.position(12);
        // TODO: Complete this method
    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
     * TODO:  They are all to be completed
     */
    public int getID() {
        return this.buffer.getShort(0) & 0x0000FFFF;
    }

    // Helper function. Sets the bit at position "pos" to the value provided in "set"
    private byte setBit(byte line, int pos, boolean set) {
        return (byte) (set ? line | (1 << pos) : line & ~(1 << pos));
    }

    public boolean getQR() {
        return (this.buffer.get(2) & 0b10000000) > 0;
    }

    public void setQR(boolean qr) {
        byte line = this.buffer.get(2);
        this.buffer.put(2, setBit(line, 7, qr));
    }

    public boolean getAA() {
        return (this.buffer.get(2) & 0b00000100) > 0;
    }

    public void setAA(boolean aa) {
        byte line = this.buffer.get(2);
        this.buffer.put(2, setBit(line, 2, aa));
    }

    public int getOpcode() {
        return ((this.buffer.get(2) & 0b01111000) >>> 3);
    }

    public void setOpcode(int opcode) {
        byte line = this.buffer.get(2);
        byte newLine = (byte) ((line & 0b10000000) + ((opcode & 0b1111) << 3) + (line & 0b000000111));
        this.buffer.put(2, newLine);
    }

    public boolean getTC() {
        return (this.buffer.get(2) & 0b00000010) > 0;
    }

    public void setTC(boolean tc) {
        byte line = this.buffer.get(2);
        this.buffer.put(2, setBit(line, 1, tc));
    }

    public boolean getRD() {
        return (this.buffer.get(2) & 0b00000001) > 0;
    }

    public void setRD(boolean rd) {
        byte line = this.buffer.get(2);
        this.buffer.put(2, setBit(line, 0, rd));
    }

    public boolean getRA() {
        return (this.buffer.get(3) & 0b10000000) > 0;
    }

    public void setRA(boolean ra) {
        byte line = this.buffer.get(3);
        byte newLine = ra ? (byte) (line | 0b10000000) : (byte) (line & 0b011111111);
        this.buffer.put(3, newLine);
    }

    public int getRcode() {
        return (this.buffer.get(3) & 0b00001111);
    }

    public void setRcode(int rcode) {
        byte line = this.buffer.get(3);
        byte newLine = (byte) ((line & 0b11110000) + (byte) rcode);
        this.buffer.put(3, newLine);
    }

    public int getQDCount() {
        return buffer.getShort(4) & 0x0000FFFF;
    }

    public void setQDCount(int count) {
        buffer.putShort(4, (short) count);
    }

    public int getANCount() {
        return buffer.getShort(6) & 0x0000FFFF;
    }

    public void setANCount(int count) {
        buffer.putShort(6, (short) count);
    }

    public int getNSCount() {
        return buffer.getShort(8) & 0x0000FFFF;
    }

    public void setNSCount(int count) {
        buffer.putShort(8, (short) count);
    }

    public int getARCount() {
        return buffer.getShort(10) & 0x0000FFFF;
    }

    public void setARCount(int count) {
        buffer.putShort(10, (short) count);
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Return the name at the current position() of the buffer.  This method is provided for you,
     * but you should ensure that you understand what it does and how it does it.
     * <p>
     * The trick is to keep track of all the positions in the message that contain names, since
     * they can be the target of a pointer.  We do this by storing the mapping of position to
     * name in the positionToName map.
     *
     * @return The decoded name
     */
    public String getName() {
        // Remember the starting position for updating the name cache
        int start = buffer.position();
        int len = buffer.get() & 0xff;
        if (len == 0) return "";
        if ((len & 0xc0) == 0xc0) {  // This is a pointer
            int pointer = ((len & 0x3f) << 8) | (buffer.get() & 0xff);
            String suffix = positionToName.get(pointer);
            assert suffix != null;
            positionToName.put(start, suffix);
            return suffix;
        }
        byte[] bytes = new byte[len];
        buffer.get(bytes, 0, len);
        String label = new String(bytes, StandardCharsets.UTF_8);
        String suffix = getName();
        String answer = suffix.isEmpty() ? label : label + "." + suffix;
        positionToName.put(start, answer);
        return answer;
    }

    /**
     * The standard toString method that displays everything in a message.
     *
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer so we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not change
        // the position in the buffer.  We remember what it was and put it back when we are done.
        int end = buffer.position();
        final int DataOffset = 12;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR()).append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        } finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we looking at)
     * @param nrrs Number of resource records
     * @param sb   Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n");
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    private static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    /**
     * Add an encoded name to the message. It is added at the current position and uses compression
     * as much as possible.  Compression is accomplished by remembering the position of every added
     * label.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        String label;
        while (name.length() > 0) {
            Integer offset = nameToPosition.get(name);
            if (offset != null) {
                int pointer = offset;
                pointer |= 0xc000;
                buffer.putShort((short) pointer);
                return;
            } else {
                nameToPosition.put(name, buffer.position());
                int dot = name.indexOf('.');
                label = (dot > 0) ? name.substring(0, dot) : name;
                buffer.put((byte) label.length());
                for (int j = 0; j < label.length(); j++) {
                    buffer.put((byte) label.charAt(j));
                }
                name = (dot > 0) ? name.substring(dot + 1) : "";
            }
        }
        buffer.put((byte) 0);
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[]{
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Add an encoded question to the message at the current position.
     *
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {
        addName(question.getHostName());
        addQType(question.getRecordType());
        addQClass(question.getRecordClass());
        setQDCount(getQDCount() + 1);
    }

    /**
     * Add an encoded type to the message at the current position.
     *
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {
        buffer.putShort((short) recordType.getCode());
    }

    /**
     * Add an encoded class to the message at the current position.
     *
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        buffer.putShort((short) recordClass.getCode());
    }

    /**
     * Decode and return the question that appears next in the message.  The current position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {
        String name = getName();
        short rType = buffer.getShort();
        short rClass = buffer.getShort();
        return new DNSQuestion(name, RecordType.getByCode(rType), RecordClass.getByCode(rClass));
    }

    /**
     * Add an encoded resource record to the message at the current position.
     *
     * @param rr The resource record to be added
     */
    public void addResourceRecord(ResourceRecord rr, String section) {
        // use addQuestion to add question. Reset qCount afterwards
        int qCount = getQDCount();
        addQuestion(rr.getQuestion());
        setQDCount(qCount);

        // Increment appropriate section count
        if ("answer".equals(section)) {
            setARCount(getARCount() + 1);
        } else if ("nameserver".equals(section)) {
            setNSCount(getNSCount() + 1);
        } else if ("additional".equals(section)) {
            setANCount(getANCount() + 1);
        }

        buffer.putInt((int) (rr.getRemainingTTL()));
        int rdLengthPos = buffer.position(); // Position where rdLength is supposed to be written to
        switch (rr.getRecordType()) {
            case A:
            case AAAA:
                buffer.putShort((short) rr.getInetResult().getAddress().length);
                buffer.put(rr.getInetResult().getAddress());
                break;
            case MX:
                buffer.putShort((byte) 0); // Placeholder for RDLength
                buffer.putShort((byte) 0); // "Preference" field
                addName(rr.getTextResult());
                buffer.put(rdLengthPos, (byte) (buffer.position() - rdLengthPos));
                break;
            default:
                buffer.putShort((byte) 0); // Placeholder for RDLength
                addName(rr.getTextResult());
                buffer.put(rdLengthPos, (byte) (buffer.position() - rdLengthPos));
        }
        setARCount(getARCount() + 1);
    }

    /**
     * Decode and return the resource record that appears next in the message.  The current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {
        DNSQuestion question = getQuestion();
        int ttl = buffer.getInt();
        short rdLength = buffer.getShort();

        switch (question.getRecordType()) {
            case A:
            case AAAA:
                try {
                    byte[] data = new byte[rdLength];
                    buffer.get(data);
                    return new ResourceRecord(question, ttl, InetAddress.getByAddress(data));
                } catch (UnknownHostException e) {
                    return null;
                }
            case MX:
                buffer.getShort(); // get past the unused "preference" part
                return new ResourceRecord(question, ttl, getName());
            default:
                return new ResourceRecord(question, ttl, getName());
        }
    }

    /**
     * Return a byte array that contains all the data comprising this message.  The length of the
     * array will be exactly the same as the current position in the buffer.
     *
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {
        byte[] ret = new byte[buffer.position()];
        System.arraycopy(buffer.array(), 0, ret, 0, buffer.position());
        return ret;
    }
}
