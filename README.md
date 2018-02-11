An administrative GUI for java GAL
==================================

## Changing root context

To change the root context (the path) of the GUI application, you need to change the file jemma.osgi.javagal.gui/OSGI-INF/javagalwebgui.xml by specifying a a value for the *rootContext* property.

An example:

	<property name="rootContext" type="String" value="zigbee"/>

In this case the web application will be available at the address http://address:port/zigbee

## Setting administrative user/pass for java GAL administrative GUI

If the UserAdmin service is active, then it is used for user authentication. 
To be allowed to login, the user must also belong to the "Administrators" group.

On the other hand if the UserAdmin service is not present, the bundle authenticates 
the user using satisfying the credentials defined by the following two system properties 
that have to be defined in the Eclipse launch configuration as follows:

``````
-Dorg.energy_home.jemma.username=<username>
-Dorg.energy_home.jemma.password=<password>
``````

If the UserAdmin service is used, it is up to the developer to configure on 
it the allowed accounts accordingly.






