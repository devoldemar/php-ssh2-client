# SSH2 / SFTP client for PHP application
Single-class wrapper and solution for typical tasks over SSH and SFTP connection. It supports custom logger and terminal settings per instance in order to be easily integrated to an existing application (Yii, Laravel, Symphony, etc). The project is based on php-ssh2 library and compatible with all its versions starting from 0.9.0. For that purpose it takes into account reported bugs and peculiarities of usage.

On Linux php-ssh2 library can be easily installed from software repository, or as a PECL package, or manually, see https://www.php.net/manual/en/ssh2.installation.php

## Requirements
  * PHP 5.4+ with ssh2 extension installed
  * PHPUnit framework for tests, version 8.5.33 (PHP 7.2+)

## Testing
Tested to work with PHP 5.6, 7.2, 7.4 and 8.1. Built-in test case under `tests` directory requires PHP 7.2+. Compatibility with PHP 5.4-5.6 (and corresponding version of PHPUnit) can be reached after just removal of return type declarations. 

## Installation via composer
Add the repo information in your composer.json:
```
{
    "repositories": [{
          "type": "git",
          "url": "https://github.com/devoldemar/php-ssh2-client"
     }]
}
```
Then run:
```
composer require devoldemar/php-ssh2-client:master
```

## Usage

### Connection
```
$ssh2 = new \Devoldemar\SSH2Client($host, $port = 22);
```
Constructor throws an exception on failure.


Check the connection is alive:
```
if ($ssh2->getIsConnected()) {
    // do smth
}
```

Get MD5 fingerprint, verify public key hash (i.e. authenticity) of remote server:
```
if (!strcasecmp($ssh2->fingerprint(), $knownValue))) {
    // do smth
}
```
The host key to be returned as fingerprint can be one of several keys created on server. Priority depends on encryption algorithm, openssh library uses the following order: ECDSA, Ed25519, RSA.

Close connection:
```
$ssh2->disconnect();
// or
unset($ssh2);
```

### Logging
Provide function which internally uses logging subsystem of the application:
```
$ssh2->logger = function($method, $message, $isError) {...}
```

```
namespace myapp;

class SSH2Client extends \Devoldemar\SSH2Client
{
    public function __construct()
    {
        $this->logger = function($method, $message, $isError) {
            if ($isError) {
                myapp::error("$method: $message");
            } else {
                myapp::info("$method: $message");
            }
        };
        parent::__construct();
    }
}
```

### Authentication
```
$ssh2->authByPassword($username, $password): bool
$ssh2->authByKey($username, $publicKey, $privateKey, ?$passphrase = ''): bool
$ssh2->authByKeyFile($username, $publicKeyFile, $privateKeyFile, ?$passphrase = ''): bool
$ssh2->authByHost($username, $hostname, $publicKeyFile, $privateKeyFile, ?$passphrase = '', ?$husername = $username): bool
```
Public key file should be in OpenSSH format. Private key may be in OpenSSH or old PEM (RSA) format. Keys in SSH2 (RFC4716) format are not recognized properly.

Check authentication status:
```
if ($ssh2->getIsAuthenticated()) {
    // do smth
}
```

### Command execution
```
$ssh2->exec($command, ?$env = null): string|false
$ssh2->exec($command, ['LANG' => 'en_US.UTF-8']): string|false
```
Note that the client may set only those environment variables which are listed under `AcceptEnv` option of ssh daemon of the remote server.


Get command shell as I/O stream
```
$ssh2->getShell(): resource|false
```
Hook manner, should be the way when calling getShell() results in error. I/O stream is set to be non-blocking. EOF usually means connection or session abort.
```
$rw = $ssh2->useShell();
if ($rw !== false) {
    $feof = false;
    list($sread, $swrite) = $rw;
    if ($swrite('my command')) { // $swrite ($bytes, ?$length = null);
        $buf = '';
        $start = time();
        while (!$feof) {
            $buf = $sread($feof, 1024); // $sread (&$feof, $length);
            if ($buf !== false) {
                $out .= $buf;
            } elseif (time() - $start >= 1) { // wait for up to 1 second
                break;
            }
        }
    }
}
```

Start terminal session optionally specifying terminal type, environment variables, width and height in characters:
```
$ssh2->getShell(?$type = 'bash', ?$env = null, ?$width = 80, ?$height = 25): string|false
```
or configure default terminal properties:
```
$ssh2->terminal = ['type' => 'sh', 'env' => null, 'width' => 180, 'height' => 60];
$ssh2->getShell();
```

### SFTP operations
All methods except `renameFile` allow path to a corresponding file or a directory to be relative one and start from aliases sush as `./` and `../`.

```
$ssh2->getFileStat(string $file): array|false
```
Method returns same array as lstat(), but adds "is_link" and "is_dir" flags to indicate file type explicitly.

Reading or writing file data, optionally by chunks, with contents or number of processed bytes in return value:
```
$ssh2->getFileContents(string $file): string|false
$ssh2->readFile(string $file, callable $chunkHandler, ?int $chunkSize = 1024 * 1024): int
$ssh2->writeFile(string $file, string|resource $data, ?string $mode = 'w+'): int
```

```
$ssh2->unlinkFile(string $file): bool
$ssh2->renameFile(string $oldPath, string $newPath): bool
$ssh2->chmodFile(string $file, int $mode): bool
$ssh2->getRealPath(string $path): string|false
$ssh2->makeLink(string $target, string $link): bool
$ssh2->readLink(string $link): string|false
$ssh2->listFiles(string $dir, ?$stat = false): array|false
```
Make a directory:
```
$ssh2->makeDir(string $path, ?int $mode = 0775): bool
```
Method also works as `mkdir -p` (make absent parent directories as needed).

Remove a directory recursively with maximum depth = $depth:
```
$ssh2->removeDir(string $dir, ?int $depth = 10): bool
```

## License
MIT 
