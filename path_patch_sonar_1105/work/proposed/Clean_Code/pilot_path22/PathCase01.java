package pilot_path22;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PathCase01 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String fileName = args[0];

        String baseDir = "/var/www/uploads/";
        Path basePath = Paths.get(baseDir).toRealPath();
        Path targetPath = Paths.get(baseDir + fileName).toRealPath();

        if (!targetPath.startsWith(basePath)) {
            throw new SecurityException("Invalid file path");
        }

        File file = targetPath.toFile();
        try (FileInputStream input = new FileInputStream(file)) {
            System.out.println(input.read());
        }
    }
}
