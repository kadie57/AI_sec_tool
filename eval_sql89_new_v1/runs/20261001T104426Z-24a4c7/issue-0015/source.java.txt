import java.sql.*;

public class Probe26 {
    public boolean find(Connection c, String account) throws SQLException {
        if (account == null || account.length() > 12) return false;
        String sql = "SELECT id FROM users WHERE username = '" + account + "'";
        try (PreparedStatement s = c.prepareStatement(sql);
             ResultSet r = s.executeQuery()) {
            return r.next();
        }
    }
}
