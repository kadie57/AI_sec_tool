import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.ServletRequest;

class WrapperReview {
    void review(Statement database, ServletRequest request, String text, Object state) throws SQLException {
        String first = resolveFirst(request);
        String second = resolveSecond(text);
        String third = resolveThird();
        String fourth = resolveFourth(state);
        database.execute(first + second + third + fourth);
    }

    private static String resolveFirst(ServletRequest request) {
        return request.getParameter("field");
    }

    private static String resolveSecond(String value) {
        return value.trim();
    }

    private static String resolveThird() {
        return "fixed";
    }

    private static String resolveFourth(Object state) {
        return state.toString();
    }
}
