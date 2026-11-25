package demo;

import java.sql.Connection;
import java.sql.SQLException;

final class CustomerService {
    static void listInterpolated(Connection connection, String account) throws SQLException {
        CustomerRepository.listInterpolated(connection, account);
    }

    static void listBound(Connection connection, String account) throws SQLException {
        CustomerRepository.listBound(connection, account);
    }
}
