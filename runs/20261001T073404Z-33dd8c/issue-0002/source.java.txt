package pilot_sql89;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.sql.Statement;

public class Trial01 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String value = args[0];
        String sql = "SELECT id FROM users WHERE username = '" + value + "'";
        try (Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            System.out.println(result.next());
        }
    }
}
