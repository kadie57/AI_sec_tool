import java.sql.*;

public class Probe22 {
    public boolean search(Connection c, String key) throws SQLException {
        String sql = new StringBuilder("SELECT id FROM users WHERE username = '")
                .append(key).append("'").toString();
        try (Statement s = c.createStatement();
             ResultSet r = s.executeQuery(sql)) {
            return r.next();
        }
    }
}
