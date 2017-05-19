package global;

public class Stator {
    public static volatile int send = 4; 
    public static volatile int receive = 0; 
                                           
    public static volatile int lost = 0; 
    public static volatile int minRrt = 0; 
    public static volatile int maxRrt = 0; 
    public static volatile int accumulator = 0; 

    public static void init(int send) {
        Stator.send = send;
        Stator.receive = 0;
        Stator.lost = 0;
        Stator.minRrt = 9999;
        Stator.maxRrt = -1;
        Stator.accumulator = 0;
    }
}
