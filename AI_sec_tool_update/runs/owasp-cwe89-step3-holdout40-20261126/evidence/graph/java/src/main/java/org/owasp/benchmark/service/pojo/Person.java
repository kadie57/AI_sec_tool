   
                          
  
                                                                                                  
                         
                                                                                                
  
                                                                                                    
                                                                                             
  
                                                                                            
                                                                                             
                                                               
  
                    
                
   
package org.owasp.benchmark.service.pojo;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "person")
public class Person {

    private long id;
    private String address;
    private String firstName;
    private String lastName;

    public Person() {}

    public Person(long id, String firstName, String lastName, String address) {
        this.id = id;
        this.firstName = firstName;
        this.address = address;
    }

    public long getId() {
        return id;
    }

    public String getAddress() {
        return address;
    }

    @XmlAttribute
    public void setId(long id) {
        this.id = id;
    }

    @XmlElement
    public void setAddress(String address) {
        this.address = address;
    }

    public String getFirstName() {
        return firstName;
    }

    @XmlElement
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    @XmlElement
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    @Override
    public String toString() {
        return "Person [id="
                + id
                + ", address="
                + address
                + ", firstName="
                + firstName
                + ", lastName="
                + lastName
                + "]";
    }
}
