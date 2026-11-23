import java.io.BufferedReader;
import java.io.InputStreamReader;

public class VulnerableCommand {

    public void pingHost(String targetIp) {
        try {
            // ĐẦU VÀO ĐƯỢC CỘNG CHUỖI TRỰC TIẾP VÀO LỆNH HỆ THỐNG
            String command = "ping -c 3 " + targetIp;
            
            // SINK: Điểm thực thi lệnh hệ điều hành nguy hiểm
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
