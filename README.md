# remo_serv

##Description:

`remo_serv` is a WSGI application that allows to securely administer a
server over an unsecure HTTP channel. The principle is to pass encrypted
and signed command to the server and execute them.

### Encryption and authentication

The application is based on the [cryptography](https://github.com/pyca/cryptography) package.

The application has a private ed448 key, and any user should know the
associated public key. Reciprocally, every user has a private ed448 key
and its associated counterpart must be registered in the application.

At login time, a user has to generate a one time x448 private key. They
then send to the application (at `/auth`) a Json string containing their
name, the public part of the transient key and the signature using their
private key of the string `user_name`+`transient_public_key` to prove their
identity. The key and the signature are URS safe base64 encoded. The
application verifies the signature and if it is valid generates a second
transient x448 key that will be used to generate a symmetric key with the
Diffie-Helmann algorithm. It then returns 2 lines in the response, the
former containing the bytes of its transient public key, and the latter
its signature (using the long term application private key), both lines
being URL safe base64 encoded.

Both part are now able to compute the shared secret. It must be derived
with the `remo_serv` magic string to build the symmetric key that will be
used for following exchanges using the Fernet algorithm form the cryptography
package: the request and responses bodies will contain one fernet token
per line, the lines being delimited with `\r\n`.

### Command execution

The application will accept the following commands:

- `/info` displays the version of the application (accessible even with
no valid connection)
- `/auth` for authentication and setting of an
encrypted channel using a Fernet
- `/get/encrypted_file_name` retrieve a local file
- `/put/encrypted_file_name` store locally the body of the request
- `/cmd/encrypted_command_line` executes the command and returns the
output (both stdout and stderr) using subprocess.run
- `/icm/encrypted_command_line` executes the command in an interactive
way: the command is executed using subprocess.Popen and left running
to be later feed with `idt` and/or `edt` commands. The optional body
if send to stdin and immediately available output is returned in the
response. It currently uses an AF_UNIX socketpair and can only run in
Posix systems (returns 404 on Windows)
- `/idt` feeds the request body to the running interactive command and
returns the available output
- `/edt` same as `idt` but shutdowns the input of the interactive command

## Installation and configuration

### Key management

The `tools` package contains two scripts to easily generate the ed448
keys and register the users in a SQLite3 database:

- `build_key_pair` generates 2 files in PEM format one for the public
key and one for the private one, the latter being optionally encrypted
(should be encrypted for a user key, unencrypted for the server one).
- `add_user` adds a user and its public key when given a user name and
a path to a PEM file containing the public key

### Using the embedded `serv.py` module

The package contains a module using [cherrypy.cheroot](https://cheroot.cherrypy.org/en/latest/).
that can be used to immediately execute the server:

    python -m remo_serv.serv [-h] [--conf CONF] [--port PORT] [--interface INTERFACE] [--user-service USER_SERVICE] [--key-file KEY_FILE] [--log LOG] [--session SESSION] [--debug]

optional arguments:

    -h, --help            show this help message and exit
    --conf CONF, -c CONF  Configuration file
    --port PORT, -p PORT  Port
    --interface INTERFACE, -i INTERFACE
                        Interface
    --user-service USER_SERVICE, -u USER_SERVICE
                        User service
    --key-file KEY_FILE, -k KEY_FILE
                        PEM main key file
    --log LOG, -l LOG     logging configuration file
    --session SESSION, -s SESSION
                        Session timeout (seconds)
    --debug, -d           Add debugging traces in log

### Using another WSGI server like Apache + mod_wsgi

**Constraint: the WSGI server must run in single process mode.**
For Apache + mod_wsgi, this implies using the *daemon* mode.

The `app.py` module contains an `application` function that is intended
to be called from an external WSGI server. It will expects the following
parameter in its WSGI environment:

- `KEYFILE`: the path to the (unencrypted) pem file containing the
application private key (required)
- `USER_SERVICE`: a string describing the user service. Currently it
should be `SQLiteUserService:path_to_sqlite3_db` where `path_to_sqlite3_db`
is the path to the SQLite3 user database generated with `add_user`
(required)
- `remo_serv.log`: path to a file used to configure the `logging` module.
- `remo_serv.timeout`: session timeout in seconds (600 or 5 minutes)
- `remo_serv.debug`: forces logging at the debug level

## Client application

A minimalist client application is provided in the client package

## Disclaimer: beta quality

All functionalities are now implemented. Yet it still lacks more
documentation, and has not been extensively tested.

## License

This work is licenced under a MIT Licence. See [LICENSE.txt](https://raw.githubusercontent.com/s-ball/MockSelector/master/LICENCE.txt)