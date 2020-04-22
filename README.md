# spring-security-oauth2-authorization-server
Demo application demonstrating how to setup a `OAuth2.0 Authorization Server` using Oauth2.0 and Spring boot which can be used to generate OAuth2.0 JWT token and also validate already generated token.

## Pre-requisite:
1. Java - 11
2. Gradle

## About Application
- Two client information has been setup(in-memory) and can be found in file `OAuth2Config.java`. Using these clientId and clientSecret, token can be generated from the application.
- Two user (admin & user) information information has also been setup(in-memory) which can be found in file `WebSecurityConfig.java`. Tokens can be generated for these users by providing username and password for these user and by including clientId and Secret as Authorization header of the request.
- To enhance the token generated to a JWT token a keystore is already added in the resource folder of this application. This Keystore contains a self signed certificate using which the token will be enhanced to a JWT token. 
- The generated token can only be decoded and validated using the same certificate using which token has been generated, in our case, Keystore: `oauth2-authorization-server.p12`

### Configuration
All the necessary configurations are externalized from the code and are part `application.yaml`
<pre>
1.  <b>spring.application.name</b>                -   Application Name
2.  <b>server.port</b>                            -   Port on which application will run.
3.  <b>keystore.name</b>                          -   Name of keystore in the classpath(resource directory, as we are using class path reader to read the file).
4.  <b>keystore.name</b>                          -   Alias of the certificate in the keystore to be used.
5.  <b>keystore.name</b>                          -   Password of keystore.
6.  <b>logging.level.root</b>                     -   Log level configuration.
</pre>
## Build and Run
1. Checkout repo.
2. run cmd `sh run-app.sh`


### Port Used 
The appication is configured to run on port **8888** which can be changed by modifying **server.port** in application.properties 

## Verify
To generate a token for the user `admin` using its credentials, use the following curl
```
curl -X POST 'http://localhost:8888/oauth/token' \
-H 'Authorization: Basic VEVTVF9DTElFTlQ6Y2xpZW50X3Bhc3M=' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-d 'grant_type=password&username=admin&password=admin_pass
```

where, the value in the Authorization header is the Base64 encoded string of clientId and clientSecret of client `TEST_CLIENT`.

Using this generated token, the protected resource at the resource server can be accessed.
