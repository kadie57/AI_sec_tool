import java.sql.*;

public class Probe23 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) throw new IllegalArgumentException();
        long id = Long.parseLong(args[0]);
        String sql = "SELECT id FROM users WHERE id = " + id;
        try (Connection c = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery(sql)) {
            System.out.println(r.next());
        }
    }
}
