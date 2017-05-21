package pinger;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Icmp;

import global.Stator;

public class RecvPingReplyThread extends Thread {
    private Pcap pcap;
    private volatile boolean done = false;
    private ReplyListener replyListener;

    public interface ReplyListener {
        void onReply(JPacket packet);
    }

    public RecvPingReplyThread(Pcap pcap, ReplyListener replyListener) {
        this.pcap = pcap;
        this.replyListener = replyListener;
    }

    @Override
    public void run() {

        PcapBpfProgram program = new PcapBpfProgram();
        String expression = "icmp[icmptype] == icmp-echoreply";
        int optimize = 0; // 0 = false
        int netmask = 0xFFFFFF00; // 255.255.255.0

        if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
            System.err.println(pcap.getErr());
            return;
        }

        if (pcap.setFilter(program) != Pcap.OK) {
            System.err.println(pcap.getErr());
            return;
        }

        while (!done) {
            try {
                pcap.loop(1, new JPacketHandler<String>() {
                    @Override
                    public void nextPacket(JPacket packet, String user) {
                        Icmp.EchoReply reply = null;
                        if ((reply = packet.getHeader(new Icmp()).getSubHeader(new Icmp.EchoReply())) != null) {
                            if (reply.id() == 0x0200 && reply.sequence() == 0x0117) {
                                if (replyListener != null) {
                                    replyListener.onReply(packet);
                                }
                            }
                        }
                    }
                }, "");
            } catch (PcapClosedException ex) {
                ex.printStackTrace();
            }
            if (Stator.receive + Stator.lost == Stator.send) {
                done = true;
            }
        }

    }

}
