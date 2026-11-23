package eval_followup21;

public class Sample304 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException();
        String value = args[0];
        
        String command = "/bin/sh -c " + value;
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }
}
