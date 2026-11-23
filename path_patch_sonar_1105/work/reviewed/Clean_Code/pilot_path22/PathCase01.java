package pilot_path22;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;

public class PathCase01 {
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

            // Access is relative to directory handles retained during validation.
            try (SeekableByteChannel channel = openRelative(directory, relative);
                 InputStream input = Channels.newInputStream(channel)) {
                System.out.println(input.read());
            }
        }
    }

    private static SeekableByteChannel openRelative(
            SecureDirectoryStream<Path> root, Path relative) throws IOException {
        // Open one relative component at a time; never follow a replacement symlink.
        SecureDirectoryStream<Path> directory = root;
        boolean ownsDirectory = false;
        try {
            for (int i = 0; i < relative.getNameCount() - 1; i++) {
                SecureDirectoryStream<Path> next = directory.newDirectoryStream(
                        relative.getName(i), LinkOption.NOFOLLOW_LINKS);
                if (ownsDirectory) {
                    try {
                        directory.close();
                    } catch (IOException failure) {
                        try {
                            next.close();
                        } catch (IOException cleanup) {
                            failure.addSuppressed(cleanup);
                        }
                        throw failure;
                    }
                }
                directory = next;
                ownsDirectory = true;
            }
            Set<OpenOption> options = new HashSet<OpenOption>();
            options.add(StandardOpenOption.READ);
            options.add(LinkOption.NOFOLLOW_LINKS);
            SeekableByteChannel channel = directory.newByteChannel(
                    relative.getFileName(), options);
            if (ownsDirectory) {
                ownsDirectory = false;
                try {
                    directory.close();
                } catch (IOException failure) {
                    try {
                        channel.close();
                    } catch (IOException cleanup) {
                        failure.addSuppressed(cleanup);
                    }
                    throw failure;
                }
            }
            return channel;
        } finally {
            if (ownsDirectory) {
                directory.close();
            }
        }
    }
}
