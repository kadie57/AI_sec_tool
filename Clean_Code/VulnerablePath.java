import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class VulnerablePath {

    public void getFileContent(String fileName) {
        try {
            String baseDir = "/var/www/uploads/";
            
            // ĐẦU VÀO ĐƯỢC CỘNG CHUỖI TRỰC TIẾP TẠO ĐƯỜNG DẪN
            String fullPath = baseDir + fileName;
            
            // SINK: Khởi tạo đối tượng File nguy hiểm khi không chặn ký tự "../"
            File file = new File(fullPath);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
