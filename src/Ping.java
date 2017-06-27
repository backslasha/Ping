
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip4.Ip4Type;

import global.ARP;
import global.Params.BTA;
import global.Params.DDN;
import global.Stator;
import global.Util;
import pinger.RecvPingReplyThread;
import pinger.StopWatch;

public class Ping {
    private static StopWatch stopWatch = new StopWatch();

    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            throw new Exception("params illgal.");
        } else if (args.length >= 1) {
            if (args[args.length-1].matches("[a-zA-Z0-9].*+")) {
                try {
                    InetAddress inetAddress = InetAddress.getByName(args[args.length-1]);
                    args[args.length-1] = inetAddress.getHostAddress();
                } catch (UnknownHostException e) {
                    System.out.println("invalid host name!");
                    return;
                }
            }
        }
        if (args.length == 2) {
            args[0] = args[0].substring(args[0].indexOf("-") + 1);
            char param = args[0].charAt(0);
            switch (param) {
            case 't':
                Stator.init(9999);
                break;
            }
        }

        // ��ȡ����������ʵ��
        PcapIf device = pcapIf();

        // ��ȡ Pcap ʵ��
        Pcap pcap = pcap(device);

        // ��ȡ���� mac ��ַ�� ip ��ַ�ĵ��ʮ�����ַ���
        String str1 = device.getAddresses().get(0).getAddr().toString();
        String str2 = device.getAddresses().get(0).getNetmask().toString();
        DDN.target_ip = args[args.length-1];
        DDN.sender_ip = str1.substring(str1.indexOf(":") + 1, str1.indexOf("]"));
        DDN.subnet_mask = str2.substring(str2.indexOf(":")  + 1, str2.indexOf("]"));
        DDN.gateway_ip = getGateWayIpDDN(DDN.sender_ip);
        DDN.sender_mac = Util.hex2DDN(Util.byteArrayToHexString(device.getHardwareAddress()));

        // ��ȡ���� mac ��ַ�� ip ��ַ�� byte ����
        BTA.gateway_ip = InetAddress.getByName(DDN.gateway_ip).getAddress();
        BTA.target_ip = InetAddress.getByName(DDN.target_ip).getAddress();
        BTA.sender_ip = device.getAddresses().get(0).getAddr().getData();
        BTA.sender_mac = device.getHardwareAddress();
        BTA.target_mac = getTargetMacBytes(pcap);

        // ���߳̿�ʼ���� ping reply ����
        new RecvPingReplyThread(pcap, new RecvPingReplyThread.ReplyListener() {
            @Override
            public void onReply(JPacket packet) {
                long rrt = stopWatch.stop() - 1;
                Stator.receive++;
                Stator.minRrt = (int) (Stator.minRrt < rrt ? Stator.minRrt : rrt);
                Stator.maxRrt = (int) (Stator.maxRrt > rrt ? Stator.maxRrt : rrt);
                Stator.rrtAccumulator += rrt;
                printReplyMsg(packet, rrt);
            }
        }).start();

        // ���� ping ����
        JPacket packet = createPingRequest();
        
        // crtl c �¼�
        Runtime.getRuntime().addShutdownHook(new ExitHandler());

        // �������ǵ� ping request ����
        System.out.println("Ping " + DDN.target_ip + " with 32 bytes' payload :");
        for (int i = 0; i < Stator.toSend; i++) {
            if (Pcap.OK != pcap.sendPacket(packet)) {
                System.err.println(pcap.getErr());
            }

            Stator.sent++;
            
            stopWatch.start();

            Thread.sleep(1000);

            while (stopWatch.isRunning()) {
                if (BTA.target_mac.length == 0) {
                    stopWatch.stop();
                    Stator.lost++;
                    printUnreachableMsg();
                    Thread.sleep(1000);
                    break;
                } else if (stopWatch.elapsed() > 3000) {
                    stopWatch.stop();
                    Stator.lost++;
                    printTimeoutMsg();
                    Thread.sleep(1000);
                    break;
                }
            }

        }

        int average = Stator.receive != 0 ? Stator.rrtAccumulator / Stator.receive : -1;
        System.out.println("\nStatistics of Ping at " + DDN.target_ip + ":");
        System.out.println("    packets: send = " + Stator.toSend + ", received = " + Stator.receive + ", lost = "
                + Stator.lost + "(" + ((float) (Stator.lost)) / ((float) (Stator.toSend)) * 100 + "% lost),");
        System.out.println("rrt(unit: ms):");
        System.out.println(
                "shortest = " + Stator.minRrt + "ms, longest = " + Stator.maxRrt + "ms, average = " + average + "ms");

        // �ͷ������Դ
        try {
            pcap.close();
        } catch (PcapClosedException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

    }

    private static PcapIf pcapIf() {
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return null;
        }

        return alldevs.get(1); // ѡ��һ�����������ҵĵ����ϵڶ���������ʹ�õ���������

    }

    private static Pcap pcap(PcapIf pcapIf) {
        StringBuilder errbuf = new StringBuilder();
        int snaplen = 64 * 1024; // ÿ�� packet ���� 64 ���ֽڵ�����
        int flags = Pcap.MODE_PROMISCUOUS; // ����ģʽ
        int timeout = 1; // �ӵ�����
        return Pcap.openLive(pcapIf.getName(), snaplen, flags, timeout, errbuf);
    }

    private static JPacket createPingRequest() {
        // data link type == DTL
        // 14 �ֽ���̫����ͷ + 20 �ֽ� IPv4 ��ͷ + 8 �ֽ� icmp ��ͷ + 32 �ֽ��������
        JPacket packet = new JMemoryPacket(14 + 20 + 8 + 32);
        packet.scan(JProtocol.ETHERNET_ID);

        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.destination(BTA.target_mac);
        ethernet.source(BTA.sender_mac);
        ethernet.type(0x0800);// 0800 ���� ipv4

        // ��� ��internal buffer�� ��14(��0)���ֽڵ�ǰ�ĸ�����Ϊ 0x40����ڸ�����Ϊ 0x50��
        // ���� IPv4 �� size Ϊ 4*5 ���ֽ�
        packet.setUByte(14, 0x40 | 0x05);
        packet.scan(JProtocol.ETHERNET_ID);
        Ip4 ip4 = packet.getHeader(new Ip4());
        ip4.type(Ip4Type.ICMP);
        ip4.length(20 + 8 + 32);// 20 �ֽ� IPv4 ��ͷ + 8 �ֽ� icmp ��ͷ + 32 �ֽ��������
        ip4.ttl(64);
        ip4.id(0x2480);
        ip4.source(BTA.sender_ip);
        ip4.destination(BTA.target_ip);
        ip4.checksum(ip4.calculateChecksum());

        // ���� Icmp ��ͷ
        packet.setUByte(14 + 20, 0x08 | 0x00);
        packet.scan(JProtocol.ETHERNET_ID);
        Icmp icmp = packet.getHeader(new Icmp());
        icmp.getSubHeader(new Icmp.EchoRequest()).setByteArray(0, Util.hexStringToByteArray("0200"));
        icmp.getSubHeader(new Icmp.EchoRequest()).setByteArray(2, Util.hexStringToByteArray("0117"));

        // ��� 32 �ֽ��������
        Payload payload = packet.getHeader(new Payload());
        payload.setByteArray(0,
                Util.hexStringToByteArray("6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869"));

        // һ����������ټ��㲢����У��ֵ
        icmp.setByteArray(2, Util.hexStringToByteArray(Integer.toHexString(icmp.calculateChecksum())));

        return packet;
    }

    private static boolean isInSameSubNet(String targetIp) {
        String netMask = DDN.subnet_mask;
        int netM = Util.ip2Int(netMask);
        int targetI = Util.ip2Int(targetIp);
        int senderI = Util.ip2Int(DDN.sender_ip);

        return (netM & targetI) == (netM & senderI);
    }

    private static void printReplyMsg(JPacket packet, long time) {

        String ip4 = packet.getHeader(new Ip4()).toString();
        ip4 = ip4.substring(ip4.indexOf("length = ") + "length = ".length());
        int payload = Integer.parseInt(ip4.substring(0, ip4.indexOf("\n"))) - 20 - 8;
        ip4 = ip4.substring(ip4.indexOf("ttl = ") + "ttl = ".length());
        int ttl = Integer.parseInt(ip4.substring(0, ip4.indexOf(" ")));

        System.out.println("reply from " + DDN.target_ip + " : payload: " + payload + "bytes " + " time: " + time
                + " ms " + " ttl: " + ttl);
    }

    private static void printTimeoutMsg() {
        System.out.println("request timeout.");
    }

    private static void printUnreachableMsg() {
        System.out.println("reply from " + DDN.sender_ip + ": target host unreachable.");
    }

    // ���� ipconfig /all �Ի����������
    private static String getGateWayIpDDN(String senderIp) {
        Runtime run = Runtime.getRuntime();
        Process ipconfig;
        String str = null;
        try {
            ipconfig = run.exec("ipconfig /all");
            Scanner scanner = new Scanner(ipconfig.getInputStream());
            scanner.useDelimiter("NO_DELIMITER");
            str = scanner.next();
            str = str.substring(str.indexOf(senderIp));
            str = str.substring(0,
                    str.indexOf(System.getProperty("line.separator") + System.getProperty("line.separator")));
            str = str.substring(
                    str.indexOf("Ĭ������. . . . . . . . . . . . . : ") + "Ĭ������. . . . . . . . . . . . . : ".length());
            str = str.substring(0, str.indexOf(System.getProperty("line.separator")));

            scanner.close();
            ipconfig.destroy();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return str;
    }

    // ���� ARP �����Ի�� Ŀ�� ip �� mac ��ַ
    private static byte[] getTargetMacBytes(Pcap pcap) throws IOException {
        // ping ��Ŀ�� ip ��ͬһ�����ڣ��� target_ip ��Ŀ�� ip������ target_ip Ϊ ���� ip
        // System.out.println("ARP: " + "where is the " + DDN.target_ip + ",
        // tell " + DDN.sender_mac);
        byte[] target_mac = new byte[0];
        try {
            if (isInSameSubNet(DDN.target_ip))
                target_mac = ARP.getMacByIP(BTA.target_ip, pcap);
            else
                target_mac = ARP.getMacByIP(BTA.gateway_ip, pcap);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return target_mac;
    }

    
}
 class ExitHandler extends Thread {
    public void run() {
        int average = Stator.receive != 0 ? Stator.rrtAccumulator / Stator.receive : -1;
        System.out.println("\nStatistics of Ping at " + DDN.target_ip + ":");
        System.out.println("    packets: send = " + Stator.sent + ", received = " + Stator.receive + ", lost = "
                + Stator.lost + "(" + ((float) (Stator.lost)) / ((float) (Stator.sent)) * 100 + "% lost),");
        System.out.println("rrt(unit: ms):");
        System.out.println("shortest = " + Stator.minRrt + "ms, longest = " + Stator.maxRrt + "ms, average = "
                + average + "ms");
    }
}