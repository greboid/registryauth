## Docker registry authentication

Provides token based authentication for a registry server allowing public read access to select resources whilst
restricting write access and read access to any resources not exposed publicly.

There are two binaries available for building and containers published for both.

### Common configuration

| CLI Flag          | Env var          | Description                                                                                                                                                                                   |
|-------------------|------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -port             | PORT             | Server port to listen on, defaults to 8080                                                                                                                                                    |
| -public           | PUBLIC           | comma separated list of prefixes that will be public, a leading slash is not required, except if you want the entire registry to be public, set this to `/`                                   |
| -users            | USERS            | yaml map of users, if using in compose append a pipe after the env var and put a user per line you'll need to double the dollar symbols to escape them ie `username:$$crypted$$password`      |
| -realm            | REALM            | Realm for the registry                                                                                                                                                                        |
| -issuer           | ISSUER           | Issuer for the registry                                                                                                                                                                       |
| -service          | SERVICE          | Service for the registry                                                                                                                                                                      |
| -data-dir         | DATA_DIR         | Data directory for storing certificates                                                                                                                                                       |
| -cert-dir         | CERT_DIR         | Directory for storing the generated certificates, by default this will be [DATA_DIR]/certs                                                                                                    |

There is also support for showing a basic registry listing, this can be configured with the below settings.

The auth component serves these at the root of wherever it is being hosted, so you'll likely want to add some proxy
rules to accommodate this. With listings enabled each public repository also has a page at `/<repository>`, showing its
tags, digests and sizes.

| CLI Flag          | Env Var          | Description                                                                                                   | 
|-------------------|------------------|---------------------------------------------------------------------------------------------------------------|
| -show-index       | SHOW_INDEX       | Show's a basic index page rather than an empty page                                                           |
| -show-listings    | SHOW_LISTINGS    | Index page lists all public repositories (does not require -show-index)                                       |
| -registry-host    | REGISTRY_HOST    | The full URL of the registry to be listed                                                                     | 
| -refresh-interval | REFRESH_INTERVAL | Time between refreshes of the registry listing. This is [go duration](https://pkg.go.dev/time#ParseDuration) |

### Logging in to the UI

The UI can log users in via OIDC. Logged-in users also see private repositories, and anonymous visitors only see public
ones unless `-require-login` is set. This does not affect registry clients, which continue to use `-users`.

Register a confidential client with your provider using the redirect URI `<external url>/oidc/callback`. The provider
must include a `groups` claim in the ID token when the `groups` scope is requested. If you use a proxy, `/oidc/` needs to
be routed to the auth component.

| CLI Flag            | Env Var            | Description                                                                                  |
|---------------------|--------------------|----------------------------------------------------------------------------------------------|
| -oidc-issuer        | OIDC_ISSUER        | Issuer URL of the OIDC provider, login is disabled if this is not set                         |
| -oidc-client-id     | OIDC_CLIENT_ID     | OIDC client ID                                                                               |
| -oidc-client-secret | OIDC_CLIENT_SECRET | OIDC client secret                                                                           |
| -oidc-external-url  | OIDC_EXTERNAL_URL  | Public base URL of the UI, ie `https://registry.example.com`                                 |
| -oidc-group         | OIDC_GROUP         | Only users with this group in their `groups` claim can log in                                |
| -require-login      | REQUIRE_LOGIN      | Require login for all UI pages, `/auth`, `/css` and `/js` remain accessible without a login  |

Sessions last 12 hours and are held in memory, so restarting the server logs everyone out. Group membership is only
checked at login. Logging out ends the session here but not at the provider.

With login enabled the listing polls private repositories as well as public ones, so that they can be shown to
logged-in users.

### Generating passwords

The passwords are bcrypted, and can be generated with the genpass command, this takes no arguments and will output the
crypted version of the entered password.

### Auth component

The auth component will create a set of certificates and output these to disk, it will then listen on the configured
port for requests from the registry and answer them accordingly. You'll need to configure the registry to have access to
the certificate produced by this project as it will be used to sign requests, you'll also need to set the following
options to match those configured on the auth component. The certificate will be [CERT_DIR]/cert.pem and the key if
required will be [CERT_DIR]/key.pem

Environment Variables:

```
REGISTRY_AUTH: token
REGISTRY_AUTH_TOKEN_REALM: https://<hostname>/auth
REGISTRY_AUTH_TOKEN_SERVICE: <service name>
REGISTRY_AUTH_TOKEN_ISSUER: <issuer name>
REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE: <CERT_DIR>/cert.pem
```

Configuration File:

```
auth:
  token:
    realm: https://<hostname>/auth
    service: <service name>
    issuer: <issuer name>
    rootcertbundle: <CERT_DIR>/cert.pem
```