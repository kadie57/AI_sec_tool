package eval_followup21;

public class Sample303 {
    public static void search(String value) throws Exception {
        value = value.trim();
        String command = "/usr/bin/find /tmp -name " + value;
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }
}
