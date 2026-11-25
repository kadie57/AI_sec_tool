package demo;

import java.sql.Connection;
import java.sql.SQLException;
import javax.servlet.ServletRequest;

final class CustomerController {
    static void list(Connection connection, ServletRequest request, boolean bindValues) throws SQLException {
        String account = request.getParameter("account");
        if (bindValues) {
            CustomerService.listBound(connection, account);
        } else {
            CustomerService.listInterpolated(connection, account);
        }
    }
}
