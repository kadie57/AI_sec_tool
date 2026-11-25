package demo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

final class CustomerRepository {
    static void listInterpolated(Connection connection, String account) throws SQLException {
        String query = "SELECT account FROM customers WHERE account = '" + account + "'";
        PreparedStatement statement = connection.prepareStatement(query);
        statement.executeQuery();
    }

    static void listBound(Connection connection, String account) throws SQLException {
        PreparedStatement statement = connection.prepareStatement("SELECT account FROM customers WHERE account = ?");
        statement.setString(1, account);
        statement.executeQuery();
    }
}
