package eval_followup21;

public class Sample301 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException();
        String value = args[0];
        
        String command = "/usr/bin/find /tmp -name " + value;
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }
}
