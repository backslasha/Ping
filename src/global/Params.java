package global;

public class Params {
    // public static class HexStr {
    // public static String sender_ip;
    // public static String sender_mac;
    // public static String target_ip;
    // public static String target_mac;
    // }

    public static class BTA {
        public static byte[] sender_ip;
        public static byte[] sender_mac;
        public static byte[] target_ip;
        public static byte[] target_mac;
        public static byte[] gateway_ip;
        // public static byte[] gateway_mac;
    }

    public static class DDN {
        public static String sender_ip;
        public static String sender_mac;
        public static String target_ip;
        public static String subnet_mask;
        // public static String target_mac;
        public static String gateway_ip;
        // public static String gateway_mac;
    }
}
