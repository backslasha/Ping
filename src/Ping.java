
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

        // 获取网络适配器实例
        PcapIf device = pcapIf();

        // 获取 Pcap 实例
        Pcap pcap = pcap(device);

        // 获取本地 mac 地址和 ip 地址的点分十进制字符串
        String str1 = device.getAddresses().get(0).getAddr().toString();
        String str2 = device.getAddresses().get(0).getNetmask().toString();
        DDN.target_ip = args[args.length-1];
        DDN.sender_ip = str1.substring(str1.indexOf(":") + 1, str1.indexOf("]"));
        DDN.subnet_mask = str2.substring(str2.indexOf(":")  + 1, str2.indexOf("]"));
        DDN.gateway_ip = getGateWayIpDDN(DDN.sender_ip);
        DDN.sender_mac = Util.hex2DDN(Util.byteArrayToHexString(device.getHardwareAddress()));

        // 获取本地 mac 地址和 ip 地址的 byte 数组
        BTA.gateway_ip = InetAddress.getByName(DDN.gateway_ip).getAddress();
        BTA.target_ip = InetAddress.getByName(DDN.target_ip).getAddress();
        BTA.sender_ip = device.getAddresses().get(0).getAddr().getData();
        BTA.sender_mac = device.getHardwareAddress();
        BTA.target_mac = getTargetMacBytes(pcap);

        // 子线程开始监听 ping reply 报文
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

        // 创建 ping 报文
        JPacket packet = createPingRequest();
        
        // crtl c 事件
        Runtime.getRuntime().addShutdownHook(new ExitHandler());

        // 发送我们的 ping request 报文
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

        // 释放相关资源
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

        return alldevs.get(1); // 选择一块网卡，在我的电脑上第二块是正在使用的无线网卡

    }

    private static Pcap pcap(PcapIf pcapIf) {
        StringBuilder errbuf = new StringBuilder();
        int snaplen = 64 * 1024; // 每个 packet 捕获 64 个字节的内容
        int flags = Pcap.MODE_PROMISCUOUS; // 混杂模式
        int timeout = 1; // 坑爹感人
        return Pcap.openLive(pcapIf.getName(), snaplen, flags, timeout, errbuf);
    }

    private static JPacket createPingRequest() {
        // data link type == DTL
        // 14 字节以太网报头 + 20 字节 IPv4 报头 + 8 字节 icmp 报头 + 32 字节随机数据
        JPacket packet = new JMemoryPacket(14 + 20 + 8 + 32);
        packet.scan(JProtocol.ETHERNET_ID);

        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.destination(BTA.target_mac);
        ethernet.source(BTA.sender_mac);
        ethernet.type(0x0800);// 0800 代表 ipv4

        // 填充 “internal buffer” 第14(基0)个字节的前四个比特为 0x40，后第个比特为 0x50，
        // 代表 IPv4 的 size 为 4*5 个字节
        packet.setUByte(14, 0x40 | 0x05);
        packet.scan(JProtocol.ETHERNET_ID);
        Ip4 ip4 = packet.getHeader(new Ip4());
        ip4.type(Ip4Type.ICMP);
        ip4.length(20 + 8 + 32);// 20 字节 IPv4 报头 + 8 字节 icmp 报头 + 32 字节随机数据
        ip4.ttl(64);
        ip4.id(0x2480);
        ip4.source(BTA.sender_ip);
        ip4.destination(BTA.target_ip);
        ip4.checksum(ip4.calculateChecksum());

        // 构造 Icmp 报头
        packet.setUByte(14 + 20, 0x08 | 0x00);
        packet.scan(JProtocol.ETHERNET_ID);
        Icmp icmp = packet.getHeader(new Icmp());
        icmp.getSubHeader(new Icmp.EchoRequest()).setByteArray(0, Util.hexStringToByteArray("0200"));
        icmp.getSubHeader(new Icmp.EchoRequest()).setByteArray(2, Util.hexStringToByteArray("0117"));

        // 填充 32 字节随机数据
        Payload payload = packet.getHeader(new Payload());
        payload.setByteArray(0,
                Util.hexStringToByteArray("6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869"));

        // 一切设置完毕再计算并填上校验值
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

    // 运行 ipconfig /all 以获得网卡网关
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
                    str.indexOf("默认网关. . . . . . . . . . . . . : ") + "默认网关. . . . . . . . . . . . . : ".length());
            str = str.substring(0, str.indexOf(System.getProperty("line.separator")));

            scanner.close();
            ipconfig.destroy();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return str;
    }

    // 发送 ARP 请求以获得 目标 ip 的 mac 地址
    private static byte[] getTargetMacBytes(Pcap pcap) throws IOException {
        // ping 的目地 ip 在同一子网内，则 target_ip 是目地 ip，否则 target_ip 为 网关 ip
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