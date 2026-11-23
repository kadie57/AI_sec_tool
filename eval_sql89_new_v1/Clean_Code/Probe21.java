import java.sql.*;

public class Probe21 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) throw new IllegalArgumentException();
        String term = args[0];
        if (term.length() > 12) throw new IllegalArgumentException();
        String sql = "SELECT id FROM users WHERE username = '" + term + "'";
        try (Connection c = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery(sql)) {
            System.out.println(r.next());
        }
    }
}
