import java.sql.*;

public class Probe24 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 2) throw new IllegalArgumentException();
        int maxRows = Integer.parseInt(args[0]);
        String account = args[1];
        String sql = "SELECT id FROM users WHERE username = '" + account + "'";
        try (Connection c = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             Statement s = c.createStatement()) {
            s.setMaxRows(maxRows);
            try (ResultSet r = s.executeQuery(sql)) {
                System.out.println(r.next());
            }
        }
    }
}
