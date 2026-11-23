package pilot_sql89;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

public class Trial05 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String value = args[0];
        String sql = "SELECT id FROM users WHERE username = '" + value + "'";
        try (Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             PreparedStatement statement = connection.prepareStatement(sql)) {
            try (ResultSet result = statement.executeQuery()) {
                System.out.println(result.next());
            }
        }
    }
}
