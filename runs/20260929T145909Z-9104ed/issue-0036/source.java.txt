import java.sql.*;

public class VulnerableLogin {
    public void login(String username, String password) throws SQLException {
        // Kết nối cơ sở dữ liệu (giả định đã cấu hình)
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "pass");
        Statement stmt = conn.createStatement();

        // LỖ HỔNG: Ghép chuỗi trực tiếp (String Concatenation) tạo ra lỗ hổng SQL Injection
        // Nếu username là: ' OR '1'='1, câu lệnh sẽ trở thành: 
        // SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '...'
        String query = "SELECT * FROM users WHERE username = '" + username + 
                       "' AND password = '" + password + "'";

        ResultSet rs = stmt.executeQuery(query);

        if (rs.next()) {
            System.out.println("Đăng nhập thành công!");
        } else {
            System.out.println("Đăng nhập thất bại.");
        }
        
        conn.close();
    }
}