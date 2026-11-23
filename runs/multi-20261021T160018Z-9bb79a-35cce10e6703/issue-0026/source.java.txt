package eval_followup21;

public class Sample203 {
    public static void read(String value) throws Exception {
        value = value.trim();
        String fullPath = "/var/www/uploads/" + value;
        java.io.File file = new java.io.File(fullPath);
        try (java.io.FileInputStream stream = new java.io.FileInputStream(file)) {
            System.out.println(stream.read());
        }
    }
}
