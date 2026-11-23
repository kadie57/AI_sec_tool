package eval_followup21;

public class Sample201 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException();
        String value = args[0];
        try {
            if (!value.matches("[A-Za-z0-9_]{1,32}")) throw new IllegalArgumentException();
        } catch (IllegalArgumentException ignored) {
            System.out.println("Continuing");
        }
        String fullPath = "/var/www/uploads/" + value;
        java.io.File file = new java.io.File(fullPath);
        try (java.io.FileInputStream stream = new java.io.FileInputStream(file)) {
            System.out.println(stream.read());
        }
    }
}
