package eval_followup21;

public class Sample302 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException();
        String value = args[0];
        if (!value.matches("[A-Za-z0-9_]{1,24}")) return;
        String command = "/usr/bin/find /tmp -name " + value;
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }
}
