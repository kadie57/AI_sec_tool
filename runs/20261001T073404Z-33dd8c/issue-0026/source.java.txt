package lab;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Case03 {
    public boolean lookup(Connection conn, String username, String password)
            throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username
                + "' AND password = '" + password + "'";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next();
        }
    }
}
