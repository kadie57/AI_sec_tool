package eval_followup21;

public class Sample104 {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException();
        String value = args[0].trim();
        String sql = "SELECT id FROM users WHERE username = ?";
        java.sql.Connection connection = java.sql.DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
        try (java.sql.PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, value);
            try (java.sql.ResultSet result = statement.executeQuery()) { System.out.println(result.next()); }
        }
    }
}
