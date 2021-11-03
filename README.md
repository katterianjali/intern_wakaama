# Wakaama

Wakaama (formerly liblwm2m) is an implementation of the Open Mobile Alliance's LightWeight M2M
protocol (LWM2M).

Developers mailing list: https://dev.eclipse.org/mailman/listinfo/wakaama-dev

## Badges
[![Build](https://github.com/eclipse/wakaama/actions/workflows/build_and_test.yaml/badge.svg)](https://github.com/eclipse/wakaama/actions/workflows/build_and_test.yaml)

## Source Layout

    -+- core                   (the LWM2M engine)
     |
     +- coap                   (CoAP stack adaptation)
     |    |
     |    +- er-coap-13        (Modified Erbium's CoAP engine from
     |                          https://web.archive.org/web/20180316172739/http://people.inf.ethz.ch/mkovatsc/erbium.php)
     |
     +- data                   (data formats serialization/deserialization)
     |
     +- tests                  (test cases)
     |    |
     |    +- integration       (pytest based integration tests implementing the OMA-ETS-LightweightM2M-V1_1-20190912-D specification
     |                          https://www.openmobilealliance.org/release/LightweightM2M/ETS/OMA-ETS-LightweightM2M-V1_1-20190912-D.pdf)
     +- examples
          |
          +- bootstrap_server  (a command-line LWM2M bootstrap server)
          |
          +- client            (a command-line LWM2M client with several test objects)
          |
          +- lightclient       (a very simple command-line LWM2M client with several test objects)
          |
          +- server            (a command-line LWM2M server)
          |
          +- shared            (utility functions for connection handling and command-
                                line interface)


## Compiling

Wakaama is not a library but files to be built with an application.
Wakaama uses CMake >= 3.13. Look at examples/server/CMakeLists.txt for an
example of how to include it.
Several compilation switches are used:
 - LWM2M_BIG_ENDIAN if your target platform uses big-endian format.
 - LWM2M_LITTLE_ENDIAN if your target platform uses little-endian format.
 - LWM2M_CLIENT_MODE to enable LWM2M Client interfaces.
 - LWM2M_SERVER_MODE to enable LWM2M Server interfaces.
 - LWM2M_BOOTSTRAP_SERVER_MODE to enable LWM2M Bootstrap Server interfaces.
 - LWM2M_BOOTSTRAP to enable LWM2M Bootstrap support in a LWM2M Client.
 - LWM2M_SUPPORT_TLV to enable TLV payload support (implicit except for LWM2M 1.1 clients)
 - LWM2M_SUPPORT_JSON to enable JSON payload support (implicit when defining LWM2M_SERVER_MODE)
 - LWM2M_SUPPORT_SENML_JSON to enable SenML JSON payload support (implicit for LWM2M 1.1 or greater when defining LWM2M_SERVER_MODE or LWM2M_BOOTSTRAP_SERVER_MODE)
 - LWM2M_OLD_CONTENT_FORMAT_SUPPORT to support the deprecated content format values for TLV and JSON.
 - LWM2M_VERSION to specify which version of the LWM2M spec to support.
   Clients will support only that version. Servers will support that version and below.
   By default the latest version is supported. To specify version 1.0, for example, pass
   -DLWM2M_VERSION="1.0" to cmake.
 - LWM2M_RAW_BLOCK1_REQUESTS For low memory client devices where it is not possible to keep a large post or put request in memory to be parsed (typically a firmware write).
   This option enable each unprocessed block 1 payload to be passed to the application, typically to be stored to a flash memory. 
 - LWM2M_COAP_DEFAULT_BLOCK_SIZE CoAP block size used by CoAP layer when performing block-wise transfers. Possible values: 16, 32, 64, 128, 256, 512 and 1024. Defaults to 1024.

Depending on your platform, you need to define LWM2M_BIG_ENDIAN or LWM2M_LITTLE_ENDIAN.
LWM2M_CLIENT_MODE and LWM2M_SERVER_MODE can be defined at the same time.

## Development

### Dependencies and Tools
- Mandatory:
  - Compiler: GCC and/or Clang
- Optional (but strongly recommended):
  - Build system generator: CMake 3.13+
  - Version control system: Git (and a GitHub account)
  - Git commit message linter: gitlint
  - Build system: ninja
  - C code formatting: clang-format, version 10
  - Unit testing: CUnit

On Ubuntu 20.04, used in CI, the dependencies can be installed as such:
- `apt install build-essential clang-format clang-format-10 clang-tools-10 cmake gcovr git libcunit1-dev ninja-build python3-pip`
- `pip3 install gitlint`

### Code formatting
New code must be formatted with [clang-format](https://clang.llvm.org/docs/ClangFormat.html).

The style is based on the LLVM style, but with 4 instead of 2 spaces indentation and allowing for 120 instead of 80
characters per line.

To check if your code matches the expected style, the following commands are helpful:
 - `git clang-format-10 --diff`: Show what needs to be changed to match the expected code style
 - `git clang-format-10`: Apply all needed changes directly
 - `git clang-format-10 --commit master`: Fix code style for all changes since master

If existing code gets reformatted, this must be done in a separate commit. Its commit id has to be added to the file
`.git-blame-ignore-revs` and committed in yet another commit.

### Running CI tests locally
To avoid unneeded load on the GitHub infrastructure, please consider running `tools/ci/run_ci.sh --all` before pushing.

### Running integration tests locally
```
cd wakaama
tools/ci/run_ci.sh --run-build
pytest -v tests/integration
```

## Examples

There are some example applications provided to test the server, client and bootstrap capabilities of Wakaama.
The following recipes assume you are on a unix like platform and you have cmake and make installed.

### Server example
 * Create a build directory and change to that.
 * ``cmake [wakaama directory]/examples/server``
 * ``make``
 * ``./lwm2mserver [Options]``

The lwm2mserver listens on UDP port 5683. It features a basic command line
interface. Type 'help' for a list of supported commands.

Options are:
```
Usage: lwm2mserver [OPTION]
Launch a LWM2M server on localhost.

Options:
  -4		Use IPv4 connection. Default: IPv6 connection
  -l PORT	Set the local UDP port of the Server. Default: 5683
  -S BYTES	CoAP block size. Options: 16, 32, 64, 128, 256, 512, 1024. Default: 1024
```

### Test client example
 * Create a build directory and change to that.
 * ``cmake [wakaama directory]/examples/client``
 * ``make``
 * ``./lwm2mclient [Options]``

DTLS feature requires the tinydtls submodule. To include it, on the first run,
use the following commands to retrieve the sources:
 * ``git submodule init``
 * ``git submodule update``

You need to install autoconf and automake to build with tinydtls.

Build with tinydtls:
 * Create a build directory and change to that.
 * ``cmake -DDTLS=1 [wakaama directory]/examples/client``
 * ``make``
 * ``./lwm2mclient [Options]``

The lwm2mclient features nine LWM2M objects:
 - Security Object (id: 0)
 - Server Object (id: 1)
 - Access Control Object (id: 2) as a skeleton
 - Device Object (id: 3) containing hard-coded values from the Example LWM2M
 Client of Appendix E of the LWM2M Technical Specification.
 - Connectivity Monitoring Object (id: 4) as a skeleton
 - Firmware Update Object (id: 5) as a skeleton.
 - Location Object (id: 6) as a skeleton.
 - Connectivity Statistics Object (id: 7) as a skeleton.
 - Test Object (id: 31024) with the following description:

                           Multiple
          Object |  ID   | Instances | Mandatory |
           Test  | 31024 |    Yes    |    No     |

           Resources:
                       Supported    Multiple
           Name | ID | Operations | Instances | Mandatory |  Type   | Range |
           test |  1 |    R/W     |    No     |    Yes    | Integer | 0-255 |
           exec |  2 |     E      |    No     |    Yes    |         |       |
           dec  |  3 |    R/W     |    No     |    Yes    |  Float  |       |

The lwm2mclient opens udp port 56830 and tries to register to a LWM2M Server at
127.0.0.1:5683. It features a basic command line interface. Type 'help' for a
list of supported commands.

Options are:
```
Usage: lwm2mclient [OPTION]
Launch a LWM2M client.
Options:
  -n NAME	Set the endpoint name of the Client. Default: testlwm2mclient
  -l PORT	Set the local UDP port of the Client. Default: 56830
  -h HOST	Set the hostname of the LWM2M Server to connect to. Default: localhost
  -p PORT	Set the port of the LWM2M Server to connect to. Default: 5683
  -4		Use IPv4 connection. Default: IPv6 connection
  -t TIME	Set the lifetime of the Client. Default: 300
  -b		Bootstrap requested.
  -c		Change battery level over time.
  -S BYTES	CoAP block size. Options: 16, 32, 64, 128, 256, 512, 1024. Default: 1024

```

If DTLS feature enable:
```
  -i Set the device management or bootstrap server PSK identity. If not set use none secure mode
  -s Set the device management or bootstrap server Pre-Shared-Key. If not set use none secure mode
```

To launch a bootstrap session:
``./lwm2mclient -b``

### Simpler test client example

In the any directory, run the following commands:
 * Create a build directory and change to that.
 * ``cmake [wakaama directory]/examples/lightclient``
 * ``make``
 * ``./lightclient [Options]``

The lightclient is much simpler that the lwm2mclient and features only four
LWM2M objects:
 - Security Object (id: 0)
 - Server Object (id: 1)
 - Device Object (id: 3) containing hard-coded values from the Example LWM2M
 Client of Appendix E of the LWM2M Technical Specification.
 - Test Object (id: 31024) from the lwm2mclient as described above.

The lightclient does not feature any command-line interface.

Options are:
```
Usage: lwm2mclient [OPTION]
Launch a LWM2M client.
Options:
  -n NAME	Set the endpoint name of the Client. Default: testlightclient
  -l PORT	Set the local UDP port of the Client. Default: 56830
  -4		Use IPv4 connection. Default: IPv6 connection
  -S BYTES	CoAP block size. Options: 16, 32, 64, 128, 256, 512, 1024. Default: 1024
```
### Bootstrap Server example
 * Create a build directory and change to that.
 * ``cmake [wakaama directory]/examples/bootstrap_server``
 * ``make``
 * ``./bootstrap_server [Options]``

Refer to [examples/bootstrap_server/README](./examples/bootstrap_server/README) for more information.

### Use of MbedTLS with the LwM2M Client

DISCLAIMER: This code is experimental. Do not use in production system.

To use MbedTLS with Wakaama one first has to decide what credentials to use. Currently, pre-shared secrets and X.509 certificates are supported. To keep the code size at a minimum, the Mbed TLS library offers fine-tuning using a configuration file. Two examples are provided in 

- examples/shared/dtls/config-ccm-psk-tls1_2.h, and 
- examples/shared/dtls/config-ccm-ecdsa-dtls1_2.h

As the name of the file indicates, one configuration is tailored to the use of PSKs, while the second is used with ECC-based credentials.

These configuration files are included in the cmake-based build process via the CMakeLists.txt in the examples folder. It is important to match the configuration of the MbedTLS library with the use of the lwm2mclient parameter invocation. 

The subparagraphs below explain the use of these two credential types in more detail. 

#### X.509-based Credentials

To use certificate-based credentials we have to create certificates and private keys for use by Wakaama and by the LwM2M Server. In this examples we have used Leshan as the LwM2M Server. The certificates and private keys used by this example can be found in the certs folder, which are copies of what is used by the MbedTLS test harness.

The following ECC-based certificates/private keys are used: 
- Certificate for Wakaama (in certs/cli2.crt)
- Private key for Wakaama (in certs/cli2.key)
- CA certificate for Wakaama and Leshan (in test-ca2.crt)
- Certificate for Leshan (in certs/server5.crt)
- Private key for Leshan (in certs/server5.key and certs/cprik.der)

Certificates and the private keys are available in different formats.

Leshan and Wakaama have to be configured to use these certificates. To simplify usage in Wakaama, the demo certificates and the client private key are also included in the code. This approach is also preferred on embedded systems when there is no file system access possible. 

You are, however, encouraged to create your own certificates and private keys for your demo. For deployment usage this is obviously essential to create your own keys. 

NOTE: When you generate a certificate for the LwM2M Client (Wakaama) then the Common Name (CN) in the certificate needs to match the endpoint name. You can check the content of your client cert using this OpenSSL command:

> openssl x509 -in cli2.crt.der -inform der -noout -text

Search for the CN field. For the demo client certificate it will say: "Subject: C = NL, O = PolarSSL, CN = PolarSSL Test Client 2". 
In this case, "PolarSSL Test Client 2" is the CN and this will also be your endpoint name. 

For Leshan, download the code as described at https://github.com/eclipse/leshan. The quickest approach is to download the pre-packaged demo application using the following command:

> wget https://ci.eclipse.org/leshan/job/leshan/lastSuccessfulBuild/artifact/leshan-client-demo.jar

Once downloaded, use the following invocation to run Leshan. 

> java -jar ./leshan-server-demo.jar -vvv --x509-certificate-chain=certs/server5.crt --x509-private-key=certs/cprik.der --truststore=certs/test-ca2.crt

NOTE: You may need to adjust the paths to your certificates!

A few notes about the parameters: 
- "-vvv" will add extra debugging information.
- "--x509-certificate-chain" will point to your file containing the server certificate.
- "--x509-private-key" points to the file containing the private key corresponding to the public key in the server certificate.
- "--truststore" points to the CA certificate. 

For more information about these parameters (and additional parameters) please consult the Leshan documentation.

Once Leshan is running, use your browser to configure the security configuration using the offered web-based portal at http://0.0.0.0:8080/#/security

Add a new security entry with the "PolarSSL Test Client 2" endpoint name and security mode set to x509. Then, switch the tab to http://0.0.0.0:8080/#/clients to see the registered clients. Since we have not started the client yet, the page will be empty.

Next, we need to build and start Wakaama.

To build Wakaama execute the following steps. 

IMPORTANT: Check the content of the examples/CMakeLists.txt file to verify that the configured configuration file points to shared/dtls/config-ccm-ecdsa-dtls1_2.h

```
git clone https://github.com/hannestschofenig/wakaama.git
cd wakaama/
git checkout bugfix
git submodule update --init --recursive
mkdir build
cd build
cmake -DDTLS_MBEDTLS=1 ..
make
```

Once the build process is finished, the lwm2mclient application can be found in the examples/client subdirectory inside the build directory. 

```
examples/client/lwm2mclient -h localhost -n "PolarSSL Test Client 2" -p 5684 -ca_file "../certs/test-ca2.key.der" -crt_file "../certs/cli2.crt.der" -key_file "../certs/cli2.key.der"
```

The parameters have the following meaning:

- "-h" indicates the hostname of the server. 
- "-n" allows you to specify the endpoint name. 
- "-p" enables you to indicate the port number to be used. 
- "-ca_file" points to the CA certificate. 
- "-crt_file" points to the client certificate. 
- "-key_file" points to the client private key.

NOTE: You may need to adjust the paths to the certificates and private key.

If everything works fine, you should be able to see a client being registered at the Leshan server and displayed in the list of registered clients.

#### PSK-based Credentials

PSK-based credentials are easier to use than the certificate-based security mode due to the simplified demo setup. 

For Leshan, download the code as described at https://github.com/eclipse/leshan. The quickest approach is to download the pre-packaged demo application using the following command:

> wget https://ci.eclipse.org/leshan/job/leshan/lastSuccessfulBuild/artifact/leshan-client-demo.jar

Once downloaded, use the following invocation to run Leshan. 

> java -jar ./leshan-server-demo.jar -vvv 

Once Leshan is running, use your browser to configure the security configuration using the offered web-based portal at http://0.0.0.0:8080/#/security

Add a new security entry with 
- an endpoint name of your preference. Let us say you use the endpoint name "test". 
- the security mode set to "psk".
- the PSK identity. We use the string "my-identity" in our demo.
- the PSK itself. For our demo we use the hex sequence (without the '0x' prefix) "0102030405".

Switch the tab to http://0.0.0.0:8080/#/clients to see the registered clients. Since we have not started the client yet, the page will be empty.

Next, we need to build and start Wakaama. To build Wakaama execute the following steps. 

IMPORTANT: Check the content of examples/CMakeLists.txt file to verify that the configured configuration file points to shared/dtls/config-ccm-psk-tls1_2.h

```
git clone https://github.com/hannestschofenig/wakaama.git
cd wakaama/
git checkout bugfix
git submodule update --init --recursive
mkdir build
cd build
cmake -DDTLS_MBEDTLS=1 ..
make
```

Once the build process is finished, the lwm2mclient application can be found in the examples/client subdirectory inside the build directory. 

```
examples/client/lwm2mclient -h localhost -n test -p 5684 -psk_identity="my-identity" -psk=0102030405
```

The parameters have the following meaning: 
- "-h" indicates the hostname of the server. 
- "-n" allows you to specify the endpoint name. 
- "-p" enables you to indicate the port number to be used. 
- "-psk_identity" indicates the PSK identity. 
- "-psk" contains the PSK.

If everything works fine, you should be able to see a client being registered at the Leshan server and displayed in the list of registered clients.
