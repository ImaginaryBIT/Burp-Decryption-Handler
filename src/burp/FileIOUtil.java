package burp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;

public class FileIOUtil {
    public static String readFromFilePath(String path) throws IOException {
        String path2 = path.trim();

        return new String(Files.readAllBytes(Paths.get(path2, new String[0])));
    }

    
}