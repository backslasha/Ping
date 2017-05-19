package global;

public class Util {

    public static int ip2Int(String ip) {
        int a = 0;
        int t = 0;
        for (int i = 1; i <= 4; i++) {
            if (ip.indexOf(".") == -1)
                t = Integer.parseInt(ip.substring(0));
            else
                t = Integer.parseInt(ip.substring(0, ip.indexOf(".")));
            for (int j = 4 - i; j > 0; j--) {
                t *= 256;
            }
            a = a + t;
            if (i == 4) {

            }
            ip = ip.substring(ip.indexOf(".") + 1);
        }
        return a;
    }

    // 十六进制字符串数据转化为字节数组
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String byteArrayToHexString(byte[] byteArray) {
        if (byteArray == null) {
            return null;
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static boolean bytesEqual(byte[] a, byte[] b) {
        String str1 = Util.byteArrayToHexString(a);
        String str2 = Util.byteArrayToHexString(b);
        str1 = str1.toLowerCase();
        str2 = str2.toLowerCase();
        return str1.equals(str2);
    }

    public static String hex2DDN(String hexMacStr) {
        StringBuilder str = new StringBuilder();
        for (; hexMacStr != "";) {
            str.append(hexMacStr.substring(0, 2));
            if (hexMacStr.length() == 2)
                break;
            str.append(":");
            hexMacStr = hexMacStr.substring(2);
        }
        return str.toString();
    }
}
