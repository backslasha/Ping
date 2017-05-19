package global;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;

import global.Params.BTA;
import pinger.StopWatch;

public class ARP {
    private static String ddn_target_mac = "";
    private static volatile boolean done = false;

    public static byte[] getMacByIP(byte[] target_ip, Pcap pcap) throws Exception {

        // data link type == DTL
        // 14 字节以太网报头 + 28 字节 ARP 报头
        JPacket packet = new JMemoryPacket(14 + 28);
        packet.scan(JProtocol.ETHERNET_ID);

        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.destination(Util.hexStringToByteArray("FFFFFFFFFFFF"));
        ethernet.source(BTA.sender_mac);
        ethernet.type(0x0806);

        // 添加 ARP 请求报头
        packet.setByteArray(14, ArpRequest.create(Util.byteArrayToHexString(BTA.sender_mac),
                Util.byteArrayToHexString(BTA.sender_ip), Util.byteArrayToHexString(target_ip)).getByteArray(0, 28));
        packet.scan(JProtocol.ETHERNET_ID);

        PcapBpfProgram program = new PcapBpfProgram();
        String expression = "arp";
        int optimize = 0; // 0 = false
        int netmask = 0xFFFFFF00; // 255.255.255.0

        if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
            System.err.println(pcap.getErr());
            return new byte[0];
        }

        if (pcap.setFilter(program) != Pcap.OK) {
            System.err.println(pcap.getErr());
            return new byte[0];
        }

        StopWatch stopWatch = new StopWatch();
        stopWatch.start();

        // 发送我们的 arp request 报文
        if (Pcap.OK != pcap.sendPacket(packet)) {
            System.err.println(pcap.getErr());
            return new byte[0];
        }

        new Thread() {
            public void run() {
                while (stopWatch.elapsed() < 1000) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
                if (done)
                    return;
//                System.out.println("ARP: " + Util.hex2DDN(Util.byteArrayToHexString(target_ip)) + " is at " + "?\n");
                stopWatch.stop();
                done = true;
                try {
                    pcap.breakloop();
                } catch (PcapClosedException ex) {
                    ex.printStackTrace();
                }
            };
        }.start();

        while (!done) {
            pcap.loop(1, new JPacketHandler<String>() {
                @Override
                public void nextPacket(JPacket packet, String user) {
                    Arp arp = null;
                    if ((arp = packet.getHeader(new Arp())) != null) {
                        if (arp.operation() == 0x0002) {
                            if (Util.bytesEqual(arp.tpa(), BTA.sender_ip)) {
                                if (Util.bytesEqual(arp.spa(), target_ip)) {
                                    String sender_IP = arp.toString()
                                            .substring(arp.toString().indexOf("sender IP = ") + 12);
                                    sender_IP = sender_IP.substring(0, sender_IP.indexOf("\n"));

                                    String sender_Mac = arp.toString()
                                            .substring(arp.toString().indexOf("sender MAC = ") + 13);
                                    sender_Mac = sender_Mac.substring(0, sender_Mac.indexOf("\n"));

//                                    System.out.println("ARP: " + sender_IP + " is at " + sender_Mac+"\n");

                                    ddn_target_mac = sender_Mac.replaceAll(":", "");
                                    done = true;
                                }
                            }
                        }

                    }
                }
            }, "");
        }

        return Util.hexStringToByteArray(ddn_target_mac);
    }

}

class ArpRequest {
    private static final String HARDWARE_TYPE = "0001";// ethernet
    private static final String PROTOCAL_TYPE = "0800";// IPv4
    private static final String HARDWARE_ADDRESS_LENGTH = "06";// 6 字节
    private static final String PROTOCAL_ADDRESS_LENGTH = "04";// 4 字节
    private static final String OPERATION_CODE = "0001";// Arp request
                                                        // 0001,reply 0002
    private static final String DESTIBATION_MAC = "ffffffffffff";

    public static JPacket create(String sender_mac, String sender_ip, String destination_ip) {
        String ARPPacket = HARDWARE_TYPE + PROTOCAL_TYPE + HARDWARE_ADDRESS_LENGTH + PROTOCAL_ADDRESS_LENGTH
                + OPERATION_CODE + sender_mac + sender_ip + DESTIBATION_MAC + destination_ip;
        JPacket arpRequest = new JMemoryPacket(JProtocol.ARP_ID, ARPPacket);
        return arpRequest;
    }

}
