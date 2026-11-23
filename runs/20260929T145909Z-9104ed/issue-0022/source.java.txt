package pilot_sql89;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.sql.Statement;

public class Trial08 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String value = args[0];
        String sql = new StringBuilder("SELECT id FROM users WHERE username = '")
                .append(value).append("'").toString();
        try (Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            System.out.println(result.next());
        }
    }
}
