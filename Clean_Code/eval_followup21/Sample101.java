package eval_followup21;

public class Sample101 {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException();
        String value = args[0];
        if (!value.matches("[A-Za-z0-9_]{1,32}")) return;
        value = args[1];
        String sql = "SELECT id FROM users WHERE username = '" + value + "'";
        java.sql.Connection connection = java.sql.DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
        try (java.sql.Statement statement = connection.createStatement();
             java.sql.ResultSet result = statement.executeQuery(sql)) {
            System.out.println(result.next());
        }
    }
}
