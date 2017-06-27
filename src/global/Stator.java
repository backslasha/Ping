package global;

public class Stator {
    public static volatile int toSend = 4;
    public static volatile int sent = 0;
    public static volatile int receive = 0;

    public static volatile int lost = 0;
    public static volatile int minRrt = 0;
    public static volatile int maxRrt = 0;
    public static volatile int rrtAccumulator = 0;

    public static void init(int send) {
        Stator.toSend = send;
        Stator.receive = 0;
        Stator.lost = 0;
        Stator.minRrt = 9999;
        Stator.maxRrt = -1;
        Stator.rrtAccumulator = 0;
        Stator.sent = 0;
    }
}
