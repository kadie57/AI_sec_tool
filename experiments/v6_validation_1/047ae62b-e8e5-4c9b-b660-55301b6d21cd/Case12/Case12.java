package validation_sql89;

import java.sql.*;

public class Case12 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String team = args[0];
        boolean accepted = team.matches("[A-Za-z0-9_]{1,24}");
        if (!accepted) {
            System.err.println("Invalid team");
        }
        String sql = "SELECT id FROM members WHERE team = '" + team + "'";
        try (Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            System.out.println(result.next());
        }
    }
}
