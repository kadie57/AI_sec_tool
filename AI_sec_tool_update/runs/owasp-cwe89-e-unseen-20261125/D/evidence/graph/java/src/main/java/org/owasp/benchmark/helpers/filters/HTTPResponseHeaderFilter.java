package org.owasp.benchmark.helpers.filters;
   
                          
  
                                                                                                  
                         
                                                                                                
  
                                                                                                    
                                                                                             
  
                                                                                            
                                                                                             
                                                               
  
                       
                
   
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class HTTPResponseHeaderFilter implements Filter {
    protected FilterConfig config;

    @Override
    public void init(FilterConfig config) throws ServletException {
        this.config = config;
    }

                                                                       
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        if (response instanceof HttpServletResponse) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
                                                                                                 
                                                                                                    
                              
                                                                                                   
                                
                                                                                                
                                       
            httpResponse.setHeader(
                    "Content-Security-Policy",
                    "frame-ancestors 'self'; form-action 'self'; "
                            + "default-src 'unsafe-inline' 'unsafe-eval' 'self'; style-src 'unsafe-inline' 'self'; style-src-elem 'self' fonts.googleapis.com; "
                            + "font-src 'self' fonts.gstatic.com");
                                                                                                  
                     
                                                                               
            httpResponse.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        }

        filterChain.doFilter(request, response);
    }

    @Override
    public void destroy() {}
}
