package pilot_path22;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.util.Set;

public class PathCase01 {
    // Bound recursion and the number of directory handles held at the same time.
    private static final int MAX_DIRECTORY_DEPTH = 64;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String fileName = args[0];
        String baseDir = "/var/www/uploads/";
        Path basePath = Paths.get(baseDir).toRealPath();

        // The configured root and its parent must be managed by the application.
        try (DirectoryStream<Path> opened = Files.newDirectoryStream(basePath)) {
            if (!(opened instanceof SecureDirectoryStream)) {
                throw new IOException("Secure directory operations are unavailable");
            }
            @SuppressWarnings("unchecked")
            SecureDirectoryStream<Path> directory = (SecureDirectoryStream<Path>) opened;
            Path targetPath = Paths.get(baseDir + fileName).toRealPath();
            if (!targetPath.startsWith(basePath)) {
                throw new SecurityException("Invalid file path");
            }
            Path relative = basePath.relativize(targetPath);
            if (relative.toString().isEmpty()) {
                throw new IOException("Expected a file, not the root directory");
            }
            if (relative.getNameCount() - 1 > MAX_DIRECTORY_DEPTH) {
                throw new IOException("Too many nested directories");
            }
            System.out.println(readRelative(directory, relative));
        }
    }

    private static int readRelative(SecureDirectoryStream<Path> directory,
                                    Path relative) throws IOException {
        if (relative.getNameCount() == 1) {
            return readFirstByte(directory, relative);
        }
        // Each level owns and closes exactly the child it opens, even on failure.
        try (SecureDirectoryStream<Path> child = directory.newDirectoryStream(
                relative.getName(0), LinkOption.NOFOLLOW_LINKS)) {
            return readRelative(child, relative.subpath(1, relative.getNameCount()));
        }
    }

    private static int readFirstByte(SecureDirectoryStream<Path> directory,
                                     Path name) throws IOException {
        try (SeekableByteChannel channel = directory.newByteChannel(name,
                Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
             InputStream input = Channels.newInputStream(channel)) {
            return input.read();
        }
    }
}
