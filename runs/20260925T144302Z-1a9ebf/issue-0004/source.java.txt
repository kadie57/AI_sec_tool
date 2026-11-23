package lab;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Case01 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected two arguments");
        }

        String username = args[0];
        String password = args[1];
        String query = "SELECT * FROM users WHERE username = '" + username
                + "' AND password = '" + password + "'";

        try (Connection conn = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/mydb",
                    System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            System.out.println(rs.next());
        }
    }
}
