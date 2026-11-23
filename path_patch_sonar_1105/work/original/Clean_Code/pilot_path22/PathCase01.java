package pilot_path22;

import java.io.File;
import java.io.FileInputStream;

public class PathCase01 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String fileName = args[0];

        String fullPath = "/var/www/uploads/" + fileName;
        File file = new File(fullPath);
        try (FileInputStream input = new FileInputStream(file)) {
            System.out.println(input.read());
        }
    }
}
