package pilot_command78;

public class CommandCase02 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String targetIp = args[0];
        if (!targetIp.equals("127.0.0.1")
                && !targetIp.equals("192.0.2.1")) {
            throw new IllegalArgumentException("Unsupported address");
        }
        String command = "ping -c 3 " + targetIp;
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }
}
