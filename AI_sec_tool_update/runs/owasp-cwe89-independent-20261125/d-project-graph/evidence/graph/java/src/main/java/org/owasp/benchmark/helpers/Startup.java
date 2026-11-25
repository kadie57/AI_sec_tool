   
                          
  
                                                                                                  
                         
                                                                                                
  
                                                                                                    
                                                                                             
  
                                                                                            
                                                                                             
                                                               
  
                    
                
   
package org.owasp.benchmark.helpers;

import java.security.Security;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@WebListener
public class Startup implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("Initializing benchmark");
        try {
                                                                                               
            Class.forName("org.owasp.benchmark.helpers.DatabaseHelper");

                                                                                            
            Security.addProvider(new BouncyCastleProvider());

        } catch (ClassNotFoundException e) {
            System.out.println("ERROR: Could not find expected DatabaseHelper class.");
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("ERROR: Could not find or add BouncyCastle as crypto provider.");
            e.printStackTrace();
        }

        if (Security.getProvider("BC") == null)
            System.out.println("ERROR: Could not add Bouncy Castle provider for some reason.");
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {}
}
