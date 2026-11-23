package eval_followup21;

public class Sample103 {
    public static void query(String value, java.sql.Connection connection) throws Exception {
        value = value.trim();
        String sql = "SELECT id FROM users WHERE username = '" + value + "'";
        
        try (java.sql.Statement statement = connection.createStatement();
             java.sql.ResultSet result = statement.executeQuery(sql)) {
            System.out.println(result.next());
        }
    }
}
