# Using Bootstrap with Leshan and Wakaama

This document illustrates an example setup for using Wakaama and Leshan where a LwM2M Client connects to a LwM2M Bootstrap Server to obtain credentials for use with a LwM2M Server. Once those credentials have been obtained, the LwM2M Client connects securely to the LwM2M Server and registers. Two Leshan servers are used in this configuration, one for the LwM2M Bootstrap Server and the other one for the LwM2M Server. The LwM2M Bootstrap Server needs to be configured with the information subsequently be used with the LwM2M Server. 

## Use of X.509 Certificates

Before building Wakaama with X.509 certificate support enabled, as described in the README.md file, it is necessary to create certificates for the LwM2M Bootstrap Server, the LwM2M Server and the LwM2M Client. We will use a simple CA infrastructure whereby no intermediate CA is used. 

To create the private keys and the certificates we use OpenSSL tools. The created certificates can be displayed using the following command (where <filename> has to be replaced with the filename of the certificate in question). 

```
openssl x509 -in <filename> -noout --text
```

Wakaama was written to utilize certificates and private keys in PEM or DER format when the legacy Mbed TLS API is used. Leshan uses PKCS#8 encoded private keys. Therefore, we will create PKCS#8 encoded private keys. For later use we will also convert the PEM-based certificates into a DER-format. 

For reference, the following file-suffix notation is used: 
- .key  = PEM encoded private key
- .crt  = PEM encoded certificate
- .csr  = Certificate Signing Request
- .crt.der = DER encoded certificate
- .key.der = PKCS#8 encoded private key

### Creating Certificates for use with LwM2M 

Below is a description of the various steps for creating certificates. It is important to match the CN names used in the certificates to what is later used in the configuration of the client and the servers. 

#### Create the CA Certificate

First, we create the CA certificate, which is self-signed. It serves as our trust anchor. 

```
openssl ecparam -genkey -name secp256r1 -out ca.key
openssl req -x509 -new -SHA256 -nodes -key ca.key -days 500 -subj "/CN=CA/O=/OU=/L=/ST=/C=" -days 3650 -out ca.crt

openssl pkcs8 -topk8 -inform PEM -outform DER -in ca.key -out ca.key.der -nocrypt
openssl x509 -inform PEM -in ca.crt  -outform DER -out ca.crt.der
```

#### Create LwM2M Server Certificate

Next, we create a private key for the LwM2M Server and have the public key signed by the CA. The name of the LwM2M Server is "lwm2m-server".

```
openssl ecparam -genkey -name secp256r1 -out lwm2m-server.key
openssl req -new -SHA256 -key lwm2m-server.key -nodes -subj "/CN=lwm2m-server/O=/OU=/L=/ST=/C=" -out lwm2m-server.csr
openssl x509 -req -SHA256 -days 100 -in lwm2m-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out lwm2m-server.crt

openssl pkcs8 -topk8 -inform PEM -outform DER -in lwm2m-server.key -out lwm2m-server.key.der -nocrypt
openssl x509 -inform PEM -in lwm2m-server.crt  -outform DER -out lwm2m-server.crt.der
```

#### Create LwM2M Bootstrap Server Certificate

Then, we use the same procedure for creating a private key, public key and a certificate for the LwM2M Bootstrap Server. 
The name of the LwM2M Bootstrap Server is "bootstrap-server".

```
openssl ecparam -genkey -name secp256r1 -out bootstrap-server.key
openssl req -new -SHA256 -key bootstrap-server.key -nodes -subj "/CN=bootstrap-server/O=/OU=/L=/ST=/C=" -out bootstrap-server.csr
openssl x509 -req -SHA256 -days 100 -in bootstrap-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out bootstrap-server.crt

openssl pkcs8 -topk8 -inform PEM -outform DER -in bootstrap-server.key -out bootstrap-server.key.der -nocrypt
openssl x509 -inform PEM -in bootstrap-server.crt  -outform DER -out bootstrap-server.crt.der
```

#### Create LwM2M Client Certificate

Finally, we repeat the step for the LwM2M Client. The name of the client is "lwm2m-client", which corresponds to the LwM2M Client endpoint name.

```
openssl ecparam -genkey -name secp256r1 -out lwm2m-client.key
openssl req -new -SHA256 -key lwm2m-client.key -nodes -subj "/CN=lwm2m-client/O=/OU=/L=/ST=/C=" -out lwm2m-client.csr
openssl x509 -req -SHA256 -days 100 -in lwm2m-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out lwm2m-client.crt

openssl pkcs8 -topk8 -inform PEM -outform DER -in lwm2m-client.key -out lwm2m-client.key.der -nocrypt
openssl x509 -inform PEM -in lwm2m-client.crt  -outform DER -out lwm2m-client.crt.der
```

### Hosts Config

To use host names for the LwM2M Server and for the LwM2M Bootstrap Server we will add two entries in the /etc/hosts file.
In this setup we assume that both servers run locally on a Linux-based machine. 

```
127.0.0.1	lwm2m-server
127.0.0.1	bootstrap-server
```

### Leshan Servers

We need to download and configure the two Leshan servers. The guidelines for downloading and building Leshan can be found at https://github.com/eclipse/leshan
Once Leshan has is downloaded we need to start it with a set of command line parameters. 

For the Leshan Bootstrap Server we need to provide the following information: 
 - In the example command line invocation below we assume the use of the demo bootstrap server implementation with the jar file available at ./leshan-bsserver-demo/target/leshan-bsserver-demo-2.0.0-SNAPSHOT-jar-with-dependencies.jar
 - "-vvv" enables excessive debugging. This is useful but obviously optional.
 - We need to let the LwM2M Bootstrap Server know what private key, what certificate, and what trust anchor to use. This is accomplished with the "--x509-certificate-chain" (for the server certificate), the "--x509-private-key" (for the private key), and "--truststore" (for the CA certificate). Use the correct path to point to the previously created credentials.
 - It is also important to specify at which port number the management console will be reachable. This is specified with the "-wp" parameter. 
 - Finally, we need to indicate what at what secure port the LwM2M Bootstrap Server will be expecting messages. The "-slp" parameter is used for this purpose and we set it to port number 5784. The insecure port is not used by our application but we will set it anwyay to 5873 with the "-lp" parameter. 
 
```
java -jar ./leshan-bsserver-demo/target/leshan-bsserver-demo-2.0.0-SNAPSHOT-jar-with-dependencies.jar -vvv --x509-certificate-chain=certs/bootstrap-server.crt --x509-private-key=certs/bootstrap-server.key.der --truststore=certs/ca.crt -lp 5783 -slp 5784 -wp 8080
```

The configuration of the Leshan LwM2M Server is very similar in terms of the parameter names. The values are, of course, different, namely
 - We need to use the LwM2M Server-specific certificate, private key. The same trust anchor is used.
 - We assume the jar file can be found at leshan-server-demo/target/leshan-server-demo-2.0.0-SNAPSHOT-jar-with-dependencies.jar
 - The Leshan LwM2M Server also has a management console and we need to use a different port number. We pick 8081 and use the "-wp" parameter. 
 - We also need to adjust the port numbers used by CoAP to connect to the LwM2M Server. We use 5684 (for the secure port) and 5683 (for the insecure port) via the "-slp" and the "-lp" parameters, respectively. 

```
java -jar leshan-server-demo/target/leshan-server-demo-2.0.0-SNAPSHOT-jar-with-dependencies.jar -vvv --x509-certificate-chain=certs/lwm2m-server.crt --x509-private-key=certs/lwm2m-server.key.der --truststore=certs/ca.crt -lp 5683 -slp 5684 -wp 8081
```

Both Leshan servers need to be configured. The aim of the configuration of the Leshan Bootstrap Server is to populate the content of the LwM2M Security and the LwM2M Server objects. This information will then be sent to the LwM2M Client as part of the bootstrap procedure. There are two options for configuring the Leshan Bootstrap Server, namely via a Web-based configuration wizard and also via a configuration file. Below we show how to configure the LwM2M Bootstrap Server via the wizard.

Use your web-browser and connect it to http://bootstrap-server:8080

Select "Add Clients Configuration" to start the wizard and enter the following information into the three pages. We use the same client certificate/client private key for talking to the LwM2M Bootstrap Server and to the LwM2M Server. You could, however, configure it differently.

Page 1: 

- For the "endpoint name" select "lwm2m-client".

Page 2: LwM2M Server Configuration Data

- For the Lwm2M server configure "coaps://lwm2m-server:5684"

- Select "x509 Certificate" from the drop-down menu.

- For the client certificate we asked to include a hex sequence of the X.509 certificate. To generate this hex sequence we use the following Linux command:

```
xxd -p -c 1024 lwm2m-client.crt.der
```

Then, copy-and-paste the hex sequence into the input box. 

- For the client private key use the same technique:

```
xxd -p -c 1024 lwm2m-client.key.der
```

- The server certificate will contain the CA cert. 

```
xxd -p -c 2048 ca.crt.der
```

- Use "domain-issued certificate"

Page 3: 

- For the Bootstrap Server URI use "coaps://bootstrap-server:5784"

- client certificate

```
xxd -p -c 1024 lwm2m-client.crt.der
```

- client private key

```
xxd -p -c 1024 lwm2m-client.key.der
```

- Bootstrap server certificate

```
xxd -p -c 2048 ca.crt.der
```

- Use "domain-issued certificate"

Finally, select "ADD". 

The Leshan LwM2M Server configuration is simpler. 

Use your browser to go to http://lwm2m-server:8081 and go to the Security tab. 
Click on the "Select Security Information" and enter the following information:

- Endpoint: "lwm2m-client"
- Security Mode: X.509

Click "Add". 

Now, the configuration on the server-side is complete. 

### Wakaama

We need to download, and build Wakaama, as described in the README.md file of the Wakaama project. 
For the cmake build configuration use the following parameters:

```
cmake -DDTLS_MBEDTLS=1 -DMBEDTLS_CONFIG_FILE="examples/shared/dtls/config-ccm-ecdsa-dtls1_2.h" -DLWM2M_BOOTSTRAP=1 ..
```

The MBEDTLS_CONFIG_FILE parameter needs to point to the correct location of your configuration file.

Finally, invoke the lwm2mclient with the following parameters: 
 - "-h" indicates the hostname. Initially, the Lwm2M Client has to connect to the LwM2M Bootstrap Server. 
 - "-p" allows us to specify the port number at which the LwM2M Bootstrap Server is waiting for incoming messages. 
 - "-n" indicates the endpoint name, which is "lwm2m-client" in our example. 
 - We need to tell Wakaama where to find the credentials for use with the LwM2M Bootstrap Server. The following parameters are used for this purpose: "-ca_file" (trust anchor), "-crt_file" (certificate of the LwM2M client), and "-key_file" (private key of the LwM2M Client).
 - If debugging support has been enabled in the Mbed TLS configuration file, then we can select the debug level via the "-debug_level" parameter. Value 1 is a low debug level and value 5 configures a verbose debug leel.
 - "-4" allows us to indicate that we are using IPv4. Depending on your configuration you might also want to select "-6" for IPv6. 
 - "-b" is important since it enables bootstrap support for Wakaama.
 
```
./examples/client/lwm2mclient -h "bootstrap-server" -n "lwm2m-client" -p 5784 -ca_file="../certs/ca.crt" -crt_file="../certs/lwm2m-client.crt" -key_file="../certs/lwm2m-client.key" -debug_level=1 -4 -b
```

If you run this command you should see in your LwM2M Server management UI that the LwM2M Client has successfully registered. 

