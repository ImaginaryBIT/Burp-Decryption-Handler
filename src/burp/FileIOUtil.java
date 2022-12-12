package burp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

public class FileIOUtil {
    public static String readFromFilePath(String path) throws IOException {
        String path2 = path.trim();
        if (!Files.exists(Paths.get(path2, new String[0]), new LinkOption[0])) {
            path2 = getAbsolutePath(path2);
        }
        return new String(Files.readAllBytes(Paths.get(path2, new String[0])));
    }

    private static String getAbsolutePath(String classPathResource) throws IOException {
        Resource resource = new ClassPathResource(classPathResource);
        return resource.getFile().getAbsolutePath();
    }
    
}