package test;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Icmp;

public class Test {
    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();
        Pcap.findAllDevs(alldevs, errbuf);
        for (int i = 0; i < alldevs.size(); i++) {
            System.out.println(alldevs.get(i).getName() + ": " + alldevs.get(i).getDescription() + "   "
                    + alldevs.get(i).getAddresses().get(0));
        }
        PcapIf wlAdpter = alldevs.get(1);

        try {
            System.out.println(byteToHexString(wlAdpter.getHardwareAddress()));
            System.out.println(wlAdpter.getAddresses());
        } catch (IOException e) {
            e.printStackTrace();
        }

        Pcap pcap = Pcap.openLive(wlAdpter.getName(), 65535, Pcap.DEFAULT_PROMISC, Pcap.DEFAULT_TIMEOUT, errbuf);

        pcap.loop(-1, new PcapPacketHandler<String>() {
            int counter = 0;
            JPacket request_ping = null;

            @Override
            public void nextPacket(PcapPacket packet, String user) {

                if (packet.getHeader(new Icmp()) != null) {
                    System.out.println(packet);
                    counter++;
                }
                if (counter == 7) {
                    request_ping = packet;
                }
                if (counter == 8) {
                    if (Pcap.OK != pcap.sendPacket(request_ping)) {
                        System.err.println(pcap.getErr());
                    }
                    pcap.breakloop();
                }
            }
        }, "haibiao2333");

        // JPacket jpacket = new JPacket(Type.POINTER);

    }
    
    private static String byteToHexString(byte[] bytes){
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            stringBuilder.append(bytes[i]+"");
        }
        return stringBuilder.toString();
    }

}
