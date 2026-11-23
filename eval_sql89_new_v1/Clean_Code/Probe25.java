import java.sql.*;

public class Probe25 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) throw new IllegalArgumentException();
        String name = args[0];
        String sql = "SELECT id FROM users WHERE username = ?";
        try (Connection c = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             PreparedStatement s = c.prepareStatement(sql)) {
            s.setString(1, name);
            try (ResultSet r = s.executeQuery()) {
                System.out.println(r.next());
            }
        }
    }
}
