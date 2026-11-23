package pilot_path22;

import java.io.File;
import java.io.FileInputStream;

public class PathCase02 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String fileName = args[0];
        if (!fileName.matches("[A-Za-z0-9_]{1,32}")) {
            throw new IllegalArgumentException("Invalid filename");
        }
        String fullPath = "/var/www/uploads/" + fileName;
        File file = new File(fullPath);
        try (FileInputStream input = new FileInputStream(file)) {
            System.out.println(input.read());
        }
    }
}
