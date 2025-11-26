import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

public class PluginDownloader {

    public static void main(String[] args) {
        String fileURL = "https://github.com/ShadowGaming100/Host-Benchmark/raw/refs/heads/main/Benchmark-Spigot-0.4.0.jar";
        String pluginsFolder = "plugins";
        String fileName = "Benchmark-Spigot-0.4.0.jar";

        try {
            // Create plugins folder if it doesn't exist
            Path pluginsPath = Path.of(pluginsFolder);
            if (!Files.exists(pluginsPath)) {
                Files.createDirectories(pluginsPath);
            }

            // File destination
            Path outputPath = pluginsPath.resolve(fileName);

            System.out.println("Downloading plugin...");

            // Download file
            try (BufferedInputStream in = new BufferedInputStream(new URL(fileURL).openStream());
                 FileOutputStream fileOut = new FileOutputStream(outputPath.toFile())) {

                byte[] dataBuffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
                    fileOut.write(dataBuffer, 0, bytesRead);
                }
            }

            System.out.println("Download complete! Saved to: " + outputPath.toAbsolutePath());

        } catch (IOException e) {
            System.out.println("Error downloading file: " + e.getMessage());
        }
    }
}
