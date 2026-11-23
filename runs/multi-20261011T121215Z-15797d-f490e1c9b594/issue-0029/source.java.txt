package pilot_sql89;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.sql.Statement;

public class Trial07 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String table;
        switch (args[0]) {
            case "primary": table = "users"; break;
            case "archive": table = "accounts"; break;
            default: return;
        }
        String sql = "SELECT id FROM " + table + " WHERE id = 1";
        try (Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            System.out.println(result.next());
        }
    }
}
