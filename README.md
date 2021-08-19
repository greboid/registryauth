## Docker registry authentication

Provides token based authentication for a registry server allowing public read access to select resources whilst
restricting write access and read access to any resources not exposed publicly.

There are three binaries available for building and containers published for all.

### Common configuration

|CLI Flag|Env var|Description|
|---|---|---|
|-public|PUBLIC|comma separated list of directory prefixes that will be public, a leading slash or trailing slash is not required|
|-users|USERS|json list list of users if using in compose append a pipe after the env var and put a user per line you'll need to double the dollar symbols to escape them ie username:$$crypted$$password
|-realm|REALM|Realm for the registry|
|-issuer|ISSUER|Issuer for the registry|
|-service|SERVICE|Service for the registry|
|-data-dir|DATA_DIR|Data directory for storing certificates and registry data (if required)
|-cert-dir|CERT_DIR|Directory for storing the generated certificates, by default this will be [DATA_DIR]/certs

### Generating passwords

The passwords are bcrypted, and can be generated with the genpass command, this takes no arguments and will output the
crypted version of the entered password.

### Self Contained

The self-contained option does need to be given a path for the registry data

|CLI Flag|Environment variable|Description|
|---|---|---|
|-registry-dir|REGISTRY_DIR|Path to the registry data, by default this will be [DATA_DIR]/registry|

### Auth component

The auth component will create a set of certificates and output these to disk, it will then listen on the configured
port for requests from the registry and answer them accordingly. You'll need to configure the registry to have access to
the certificate produced by this project as it will be used to sign requests, you'll also need to set the following
options to match those configured on the auth component. The certificate will be [CERT_DIR]/cert.pem and the key if
required will be [CERT_DIR]/key.pem

- realm
- issuer
- service
- root cert bundle