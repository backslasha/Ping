package test;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.Ethernet.EthernetType;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip4.Ip4Type;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class PcapSendPacketExample {
    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<PcapIf>();

        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }

        PcapIf device = alldevs.get(1); // 选择一块网卡，在我的电脑上第二块是正在使用的无线网卡

        int snaplen = 64 * 1024; // 每个 packet 捕获 64 个字节的内容（就是全部）
        int flags = Pcap.MODE_PROMISCUOUS; // 混杂模式
        int timeout = 10 * 1000; // 10 秒超时
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        // data link type == DTL
        JPacket packet = new JMemoryPacket(14 + 20 + 8 + 32);
        packet.scan(JProtocol.ETHERNET_ID);

        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.destination(hexStringToByteArray("d05349bb39a5"));
        ethernet.source(hexStringToByteArray("28C2DD16086F"));
        ethernet.type(0x0800);// 0800 代表 ipv4

        // 填充 “internal buffer” 第14(基0)个字节的前四个比特为 0x40，后第个比特为 0x50，代表 IPv4 、
        // size 为 4*5 个字节
        packet.setUByte(14, 0x40 | 0x05);
        packet.scan(JProtocol.ETHERNET_ID);
        Ip4 ip4 = packet.getHeader(new Ip4());
        ip4.type(Ip4Type.ICMP);
        ip4.length(20 + 8 + 32);
        ip4.ttl(64);
        ip4.id(0x2480);
        
        try {
            ip4.source(InetAddress.getByName("192.168.0.150").getAddress());
            ip4.destination(InetAddress.getByName("192.168.0.159").getAddress());
            ip4.checksum(ip4.calculateChecksum());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        // 填充 “internal buffer” 第 46( 基 0 )个字节的前 4 位比特为 0x50，代表 size 为 4*5 个字节
        // packet.setUByte(46, 0x50);
        // packet.scan(JProtocol.ETHERNET_ID);

        packet.setUByte(14 + 20, 0x08 | 0x00);
        packet.scan(JProtocol.ETHERNET_ID);
        Icmp icmp = packet.getHeader(new Icmp());
        icmp.getSubHeader(new Icmp.EchoRequest()).setByteArray(0, hexStringToByteArray("0200"));
        icmp.getSubHeader(new Icmp.EchoRequest()).setByteArray(2, hexStringToByteArray("0117"));

        Payload payload = packet.getHeader(new Payload());
        payload.setByteArray(0,
                hexStringToByteArray("6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869"));

        icmp.setByteArray(2, hexStringToByteArray(Integer.toHexString(icmp.calculateChecksum())));

        System.out.println(packet);

        if (Pcap.OK != pcap.sendPacket(packet)) {
            System.err.println(pcap.getErr());
        }

        pcap.close();

    }

    // 十六进制数据 → 字节数组
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static JPacket getUpdPacket() {

        final URI destinationAddress = URI.create("udp://192.168.0.151:6666");
        final URI sourceAddress = URI.create("udp://192.168.0.1:6666");

        byte[] sourceAddressByte = null;
        try {
            sourceAddressByte = InetAddress.getByName(sourceAddress.getHost()).getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        byte[] sourceMacAddressByte = hexStringToByteArray(System.getProperty("gateway_mac_address", ""));
        int sourcePort = destinationAddress.getPort();

        byte[] destinationAddressByte = null;
        try {
            destinationAddressByte = InetAddress.getByName(destinationAddress.getHost()).getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        byte[] destinationMacAddressByte = hexStringToByteArray("8825932ddb18"); // TODO:
                                                                                 // Getting
                                                                                 // from
                                                                                 // ARP
        int destinationPort = destinationAddress.getPort();

        byte[] dataByte = "DATA".getBytes();
        int dataLength = dataByte.length;
        int headerLength = 14 + 20 + 8;
        int packetSize = headerLength + dataLength;
        JPacket packet = new JMemoryPacket(packetSize);
        packet.order(ByteOrder.BIG_ENDIAN);
        packet.setUShort(12, 0x0800);
        packet.scan(JProtocol.ETHERNET_ID);
        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.source(sourceMacAddressByte);
        ethernet.destination(destinationMacAddressByte);
        ethernet.checksum(ethernet.calculateChecksum());

        // IP v4 packet
        packet.setUByte(14, 0x40 | 0x05);
        packet.scan(JProtocol.ETHERNET_ID);
        Ip4 ip4 = packet.getHeader(new Ip4());
        ip4.type(Ip4.Ip4Type.UDP);
        ip4.length(packetSize - ethernet.size());
        ip4.source(sourceAddressByte);
        ip4.destination(destinationAddressByte);
        ip4.ttl(32);
        ip4.flags(0);
        ip4.offset(0);
        ip4.checksum(ip4.calculateChecksum());

        // UDP packet
        packet.scan(JProtocol.ETHERNET_ID);
        Udp udp = packet.getHeader(new Udp());
        udp.source(sourcePort);
        udp.destination(destinationPort);
        udp.length(packetSize - ethernet.size() - ip4.size());
        udp.checksum(udp.calculateChecksum());
        packet.setByteArray(headerLength, dataByte);
        packet.scan(Ethernet.ID);

        return packet;
    }

    private static JPacket getTcpPacket() {

        final URI destinationAddress = URI.create("tcp://192.168.0.151:6666");
        final URI sourceAddress = URI.create("tcp://192.168.0.1:6666");

        byte[] sourceAddressByte = null;
        try {
            sourceAddressByte = InetAddress.getByName(sourceAddress.getHost()).getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        byte[] sourceMacAddressByte = hexStringToByteArray(System.getProperty("gateway_mac_address", ""));
        int sourcePort = destinationAddress.getPort();

        byte[] destinationAddressByte = null;
        try {
            destinationAddressByte = InetAddress.getByName(destinationAddress.getHost()).getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        byte[] destinationMacAddressByte = hexStringToByteArray("000000000000"); // TODO:
                                                                                 // Getting
                                                                                 // from
                                                                                 // ARP
        int destinationPort = destinationAddress.getPort();

        byte[] dataByte = "DATA".getBytes();
        int dataLength = dataByte.length;
        int headerLength = 14 + 20 + 8;
        int packetSize = headerLength + dataLength;
        JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID,
                " 001801bf 6adc0025 4bb7afec 08004500 " + " 0041a983 40004006 d69ac0a8 00342f8c "
                        + " ca30c3ef 008f2e80 11f52ea8 4b578018 " + " ffffa6ea 00000101 080a152e ef03002a "
                        + " 2c943538 322e3430 204e4f4f 500d0a");
        packet.order(ByteOrder.BIG_ENDIAN);
        packet.setUShort(12, 0x0800);
        packet.scan(JProtocol.ETHERNET_ID);
        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.source(sourceMacAddressByte);
        ethernet.destination(destinationMacAddressByte);
        ethernet.checksum(ethernet.calculateChecksum());

        // IP v4 packet
        packet.setUByte(14, 0x40 | 0x05);
        packet.scan(JProtocol.ETHERNET_ID);
        Ip4 ip4 = packet.getHeader(new Ip4());
        ip4.type(Ip4.Ip4Type.TCP);
        ip4.length(packetSize - ethernet.size());
        ip4.source(sourceAddressByte);
        ip4.destination(destinationAddressByte);
        ip4.ttl(32);
        ip4.flags(0);
        ip4.offset(0);
        ip4.checksum(ip4.calculateChecksum());

        packet.scan(JProtocol.ETHERNET_ID);
        // Tcp tcp = packet.getHeader(new Tcp());
        //// tcp.destination(destinationPort);
        // tcp.source(sourcePort);
        // tcp.checksum(tcp.calculateChecksum());
        // packet.setByteArray(headerLength, dataByte);
        // packet.scan(Ethernet.ID);

        return packet;
    }

    private static void sendNewPacket(Pcap pcap) {
        final URI sourceAddress = URI.create("tcp://192.168.0.151:6666");
        final URI destinationAddress = URI.create("tcp://119.29.115.31:8080");
        byte[] destinationAddressByte = null;
        try {
            destinationAddressByte = InetAddress.getByName(destinationAddress.getHost()).getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        byte[] sourceAddressByte = null;
        try {
            sourceAddressByte = InetAddress.getByName(sourceAddress.getHost()).getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        /*******************************************************
         * Create Packet from Raw data
         */
        JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID,
                " 001801bf 6adc0025 4bb7afec 08004500 " + " 0041a983 40004006 d69ac0a8 00342f8c "
                        + " ca30c3ef 008f2e80 11f52ea8 4b578018 " + " ffffa6ea 00000101 080a152e ef03002a "
                        + " 2c943538 322e3430 204e4f4f 500d0a");

        // Holt sich aus dem Packet die Referenz auf den Ip4 und den TCP Header
        Ip4 ip = packet.getHeader(new Ip4());
        ip.destination(destinationAddressByte);
        ip.source(sourceAddressByte);
        Tcp tcp = packet.getHeader(new Tcp());

        tcp.source(808);
        tcp.destination(8080);

        ip.checksum(ip.calculateChecksum());
        tcp.checksum(tcp.calculateChecksum());

        packet.scan(Ethernet.ID);

        /*******************************************************
         * Fourth We send our packet off using open device
         *******************************************************/
        if (pcap.sendPacket(packet) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }

    }

}