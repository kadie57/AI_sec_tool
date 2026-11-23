package validation_sql89;

import java.sql.*;

public class Case14 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String team = args[0];
        String sql = "SELECT id FROM members WHERE team = '" + team + "' AND enabled = ?";
        try (Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBoolean(1, true);
            try (ResultSet result = statement.executeQuery()) {
                System.out.println(result.next());
            }
        }
    }
}
