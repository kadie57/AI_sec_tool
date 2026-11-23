package eval_followup21;

public class Sample102 {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException();
        long value = Long.parseLong(args[0]);
        if (value < 0 || value > 1000) return;
        String sql = "SELECT id FROM users WHERE id = " + (value + 1);
        java.sql.Connection connection = java.sql.DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
        try (java.sql.Statement statement = connection.createStatement();
             java.sql.ResultSet result = statement.executeQuery(sql)) {
            System.out.println(result.next());
        }
    }
}
