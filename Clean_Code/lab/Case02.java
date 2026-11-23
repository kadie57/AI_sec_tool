package lab;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class Case02 {
    public static void main(String[] args) throws SQLException {
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected two arguments");
        }

        String username = args[0];
        String password = args[1];
        String query = "SELECT * FROM users WHERE username = ? AND password = ?";

        try (Connection conn = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/mydb",
                    System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.setString(2, password);
            try (ResultSet rs = stmt.executeQuery()) {
                System.out.println(rs.next());
            }
        }
    }
}
