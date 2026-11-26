   
                          
  
                                                                                                  
                         
                                                                                                
  
                                                                                                    
                                                                                             
  
                                                                                            
                                                                                             
                                                               
  
                       
                
   
package org.owasp.benchmark.helpers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class PropertiesManager {
    private File file = null;

                                                       
    public PropertiesManager() {
        file = Utils.getFileFromClasspath("benchmark.properties", this.getClass().getClassLoader());
    }

                                                                                      
    public PropertiesManager(String fileName) {
        file = Utils.getFileFromClasspath(fileName, this.getClass().getClassLoader());
    }

                                                                                               
    public PropertiesManager(String path, String fileName) {
        file = new File(path + File.separator + fileName);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                System.out.println(
                        "Problem creating new empty properties file: " + file.getAbsolutePath());
            }
        }
    }

    public void displayProperties() {
        Properties props = loadProperties();

        System.out.println(props.keySet());
        System.out.println(props.values());
    }

    public String getProperty(String key, String defaultValue) {
        Properties props = loadProperties();
        return props.getProperty(key, defaultValue);
    }

    public int getProperty(String key, int defaultValue) {
        Properties props = loadProperties();
        return Integer.parseInt(props.getProperty(key, Integer.toString(defaultValue)));
    }

    public void saveProperty(String key, String value) {
        Properties props = loadProperties();
        try (FileOutputStream out = new FileOutputStream(file)) {
            props.setProperty(key, value);
            props.store(out, null);
        } catch (IOException e) {
            System.out.println("There was a problem saving a property in the properties file");
            e.printStackTrace();
        }
    }

    public void removeProperty(String key) {
        Properties props = loadProperties();
        try (FileOutputStream out = new FileOutputStream(file)) {
            props.remove(key);
            props.store(out, null);
        } catch (IOException e) {
            System.out.println("There was a problem removing a property from the properties file");
            e.printStackTrace();
        }
    }

    private Properties loadProperties() {
        Properties props = new Properties();
        try (InputStream is = new FileInputStream(file)) {
            props.load(is);
        } catch (IOException e) {
            System.out.println("Error loading properties file");
            e.printStackTrace();
        }
        return props;
    }
}
