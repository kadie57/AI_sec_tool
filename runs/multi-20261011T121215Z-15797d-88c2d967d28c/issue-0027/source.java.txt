package pilot_sql89;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Trial06 {
    public boolean lookup(Connection connection, String value) throws SQLException {
        String sql = "SELECT id FROM users WHERE username = '" + value + "'";
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            return result.next();
        }
    }
}
