<?php

namespace Devoldemar;

class SSH2Client {
    protected $_conn;
    protected $_auth;
    protected $_address;
    protected $_v1;
    protected $_logger;
    protected $_terminal;

    /**
     *  Constructor. Opens connection to SSH server.
     *
     *  @param string $host Server's IP address or domain.
     *  @param int    $port Connection port.
     */
    public function __construct($host, $port = 22)
    {
        if (!function_exists('ssh2_connect')) {
            throw new Exception('ssh2 extension not installed');
        }
        $this->_address = "$host:$port";
        $this->_conn = ssh2_connect($host, $port, array('hostkey'=>'ssh-rsa'));
        if (!$this->_conn) {
            throw new Exception('ssh2_connect failed, server=' . $this->_address);
        } else {
            $this->log(__METHOD__, 'connected to ssh2 server ' . $this->_address, false);
        }
        $this->_v1 = function_exists('ssh2_disconnect');
    }

    /**
     *  Destructor.
     */
    public function __destruct()
    {
        if (isset($this->_conn)) {
            $this->disconnect();
        }
    }

    /**
     * PHP setter magic method.
     * Used to configure logger and terminal properties.
     *
     * @param string $name
     * @param string $value
     * @throws Exception
     */
    public function __set($name, $value)
    {
        if ($name === 'logger') {
            if (is_callable($value)) {
                $this->_logger = $value;
            } else {
                throw new Exception('Logger must be a function');
            }
        } elseif ($name === 'terminal' && is_array($value)) {
            if (is_array($this->_terminal)) {
                $this->_terminal = $value;
            } else {
                throw new Exception('Terminal configuration must be an array');
            }
        } else {
            throw new Exception('Unknown property ' . $name);
        }
    }

    /**
     * PHP magic method to check if property value is null.
     *
     * @param string $name
     * @return bool
     */
    public function __isset($name)
    {
        return ($name === 'logger' || $name === 'terminal');
    }

    /**
     * Logs a message. Calls logger function if specified.
     *
     * @param string $method
     * @param string $message
     * @param bool $isError
     */
    protected function log($method, $message, $isError = true)
    {
        if (isset($this->_logger)) {
            call_user_func($this->_logger, $method, $message, $isError);
        }
    }

    /**
     * Removes numerical keys from stat() or lstat() output.
     */
    protected function assocStat(array &$stat)
    {
        unset($stat[2], $stat[4], $stat[5], $stat[7], $stat[8], $stat[9]);
    }

    /**
     * Fixes authentication status and logs message when it is failed.
     *
     * @param string $type
     * @param string $username
     * @param string $hostname
     * @return bool
     */
    protected function onAuth($type, $username, $hostname = '')
    {
        if ($this->_auth) {
            return true;
        }
        $this->log(__METHOD__,  "$type authentication failed, username = {$username}," . ($hostname ? " hostname = {$hostname}," : '') . " server = {$this->_address}");
        return false;
    }

    /**
     *  Closes connection to SSH server.
     */
    public function disconnect()
    {
        if ($this->_conn) {
            $this->_auth = false;
            $this->log(__METHOD__, "closing connection, server = {$this->_address}", false);
            if ($this->_v1) {
                ssh2_disconnect($this->_conn);
            }
            unset($this->_conn);
        }
    }

    /**
     * @return bool Connection status.
     */
    public function getIsConnected() {
        return !empty($this->_conn) && is_resource($this->_conn);
    }

    /**
     * Authenticates client by username and password.
     *
     * @param string $username
     * @param string $password
     * @return bool Authentication status
     */
    public function authByPassword($username, $password)
    {
        if ($this->_conn) {
            $this->_auth = ssh2_auth_password($this->_conn, $username, $password);
            return $this->onAuth('password', $username);
        }
        $this->disconnect();
    }

    /**
     * Authenticates client by username and keypair.
     *
     * @param string $username       Username of remote server (connected to)
     * @param string $publicKeyFile  Path to public key file
     * @param string $privateKeyFile Path to private key file
     * @param string $passphrase     Optional passphrase, if private key is protected by that
     * @return bool Authentication status.
     */
    public function authByKeyFile($username, $publicKeyFile, $privateKeyFile, $passphrase = '')
    {
        if ($this->_conn) {
            $this->_auth = ssh2_auth_pubkey_file($this->_conn, $username, $publicKeyFile, $privateKeyFile, $passphrase);
            return $this->onAuth('public key', $username);
        }
        $this->disconnect();
    }

    /**
     * Authenticates client on host identified by hostname, providing username and keypair of trusted server.
     *
     * @param string $username       Username for the server connected to
     * @param string $hostname       IP address or domain of trusted server
     * @param string $publicKeyFile  Path to host public key file
     * @param string $privateKeyFile Path to host private key file
     * @param string $passphrase     Optional passphrase, if private key is protected by that
     * @param string $husername      Optional username for the hostname, if not the same as username
     * @return bool Authentication status.
     */
    public function authByHost($username, $hostname, $publicKeyFile, $privateKeyFile, $passphrase = '', $husername = '')
    {
        if ($this->_conn) {
            $this->_auth = ssh2_auth_hostbased_file($this->_conn, $username, $hostname, $publicKeyFile, $privateKeyFile, $passphrase, !$husername ? $username : $husername);
            return $this->onAuth('host based', $username, $hostname);
        }
        $this->disconnect();
    }

    /**
     * @return bool Authentication status.
     */
    public function getIsAuthenticated()
    {
        return !empty($this->_auth);
    }

    /**
     * @param int $flags
     * @return bool MD5 (by default) fingerprint of remote server.
     */
    public function fingerprint($flags = SSH2_FINGERPRINT_MD5 | SSH2_FINGERPRINT_HEX)
    {
        if ($this->_conn) {
            return ssh2_fingerprint($this->_conn, $flags);
        }
        return false;
    }

    /**
     * Executes a command and returns output as a text or false on error.
     *
     * @param string $command
     * @param array $env
     * @return bool|string
     */
    public function exec($command, $env = null)
    {
        if ($this->_conn) {
            list($type, $env, $width, $height) = $this->getTerminalProps($type = null, $env, $width = 80, $height = 25);
            $exec = ssh2_exec($this->_conn, $command, $type, $env, $width, $height, SSH2_TERM_UNIT_CHARS);
            if ($exec !== false) {
                stream_set_blocking($exec, true);
                return trim(stream_get_contents($exec));
            } else {
                $this->log(__METHOD__, "ssh2_exec failed, command = $command, server = {$this->_address}");
            }
        }
        return false;
    }

    /**
     * Loads parameters optionally provided in "terminal" property
     *
     * @param string $type   Type: "bash", "xterm", "vanilla", etc
     * @param array  $env    Environment variables as key-value pairs
     * @param int    $width  Width in characters
     * @param int    $height Height in characters
     * @return array
     */
    protected function getTerminalProps($type, $env, $width, $height)
    {
        if (isset($this->_terminal['type'])) {
            $type = $this->_terminal['type'];
        }
        if (isset($this->_terminal['env'])) {
            $env = $this->_terminal['env'];
        }
        if (isset($this->_terminal['width'])) {
            $width = $this->_terminal['width'];
        }
        if (isset($this->_terminal['height'])) {
            $height = $this->_terminal['height'];
        }
        return [$type, $env, $width, $height];
    }

    /**
     * Creates terminal session and corresponding I/O stream to interact with shell.
     *
     * @see self::getTerminalProps
     * @return resource|object
     */
    public function getShell($type = 'bash', $env = null, $width = 80, $height = 25)
    {
        if ($this->_conn) {
            list($type, $env, $width, $height) = $this->getTerminalProps($type, $env, $width, $height);
            return ssh2_shell($this->_conn, $type, $env, $width, $height, SSH2_TERM_UNIT_CHARS);
        }
        return false;
    }

    /**
     * Creates terminal session and I/O handlers to interact with shell.
     *
     * @see self::getTerminalProps
     * @return array Function to read, function to write
     */
    public function useShell($type = 'bash', $env = null, $width = 80, $height = 25)
    {
        if ($this->_conn) {
            list($type, $env, $width, $height) = $this->getTerminalProps($type, $env, $width, $height);
            $sh = ssh2_shell($this->_conn, $type, $env, $width, $height, SSH2_TERM_UNIT_CHARS);
            if ($sh) {
                stream_set_blocking($sh, false);
                return [
                    function (&$feof, $length = 1024) use ($sh) {
                        if (!($feof = feof($sh))) {
                            return fread($sh, $length);
                        }
                    },
                    function ($bytes, $length = null) use ($sh) {
                        return fwrite($sh, $bytes, $length ? $length : strlen($bytes));
                    }
                ];
            }
        }
        return false;
    }

    /**
     * Gives metadata for a file or directory.
     *
     * @param string $file Path to file or directory
     * @return string|bool
     */
    public function getFileStat($file)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($file[0] !== '/') {
                    $file = rtrim(ssh2_sftp_realpath($_sftp, "$file\n"));
                }
                $stat = @ssh2_sftp_lstat($_sftp, $file);
                if ($stat !== false) {
                    $stat['is_link'] = decoct(0120000 & $stat['mode']) === '120000';
                    $stat['is_dir'] = decoct(0040000 & $stat['mode']) === '40000';
                    $this->assocStat($stat);
                }
                return $stat;
            }
        }
        return false;
    }

    /**
     * Reads a file and returns its contents.
     *
     * @param string $file Path to file or directory
     * @return string|bool
     */
    public function getFileContents($file)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($file[0] !== '/') {
                    $file = ssh2_sftp_realpath($_sftp, $file);
                }
                $fp = fopen("ssh2.sftp://".($this->_v1 ? $_sftp : intval($_sftp))."$file", 'r');
                if ($fp) {
                    $buf = '';
                    stream_set_chunk_size($fp, 4096);
                    while ($data = fread($fp, 4096)) {
                        $buf .= $data;
                    }
                    fclose($fp);
                    return $buf;
                } else {
                    $this->log(__METHOD__, "failed to open file $file");
                }
            }
        }
        return false;
    }

    /**
     * Reads a file by chunks and sends them to external handler.
     *
     * @param  string   $file      Path to file or directory
     * @param  callable $handler   Callback function in a format appropriate for call_user_func()
     * @param  int      $chunkSize Chunk size in bytes, default is 1MiB
     * @return int Number of bytes read.
     */
    public function readFile($file, $handler, $chunkSize = null)
    {
        $bytes = 0;
        if ($this->_conn && is_callable($handler)) {
            if (!is_numeric($chunkSize) || $chunkSize <= 0) {
                $chunkSize = 1024 * 1024;
            }
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($file[0] !== '/') {
                    $file = ssh2_sftp_realpath($_sftp, $file);
                }
                $fp = fopen("ssh2.sftp://".($this->_v1 ? $_sftp : intval($_sftp))."$file", 'r');
                if ($fp) {
                    stream_set_chunk_size($fp, $chunkSize);
                    while ($data = fread($fp, $chunkSize)) {
                        $bytes += strlen($data);
                        call_user_func($handler, $data);
                    }
                    fclose($fp);
                } else {
                    $this->log(__METHOD__, "failed to open file $file");
                }
            }
        }
        return $bytes;
    }

    /**
     * Writes to a file.
     *
     * @param  string          $file Path to file or directory
     * @param  string|resource $data Binary string or readable stream
     * @param  string          $mode Type of access
     * @return int Number of bytes written.
     */
    public function writeFile($file, $data, $mode = 'w+')
    {
        $bytes = 0;
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($file[0] !== '/') {
                    $file = ssh2_sftp_realpath($_sftp, $file);
                }
                $fp = fopen("ssh2.sftp://".($this->_v1 ? $_sftp : intval($_sftp)) . $file, $mode);
                if ($fp !== false) {
                    if (is_scalar($data)) {
                        $bytes = fwrite($fp, $data);
                    } else {
                        fseek($data, 0);
                        while(!feof($data)) {
                            $buf = fread($data, 1024 * 1024);
                            $bytes += fwrite($fp, $buf, strlen($buf));
                        }
                    }
                    fclose($fp);
                } else {
                    $this->log(__METHOD__, "failed to open file $file in write mode");
                }
            }
        }
        return $bytes;
    }

    /**
     * Removes a file.
     *
     * @param string $file Path to file or directory
     * @return string|bool
     */
    public function unlinkFile($file)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($file[0] !== '/') {
                    $file = rtrim(ssh2_sftp_realpath($_sftp, "$file\n"));
                }
                return ssh2_sftp_unlink($_sftp, $file);
            }
        }
        return false;
    }

    /**
     * Renames a file.
     *
     * @param string $file Path to file or directory
     * @return string|bool
     */
    public function renameFile($oldPath, $newPath)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                return ssh2_sftp_rename($_sftp, $oldPath, $newPath);
            }
        }
        return false;
    }

    /**
     * Sets permissions to a file or a directory.
     *
     * @param string $file Path to file or directory
     * @param int    $mode Permissions, octal number, same as for chmod() function
     * @return string|bool
     */
    public function chmodFile($file, $mode)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($file[0] !== '/') {
                    $file = rtrim(ssh2_sftp_realpath($_sftp, "$file\n"));
                }
                return ssh2_sftp_chmod($_sftp, $file, $mode);
            }
        }
        return false;
    }

    /**
     * Resolves path alias.
     *
     * @param string $path Path to file or directory
     * @return string|bool
     */
    public function getRealPath($path)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                return ssh2_sftp_realpath($_sftp, $path);
            }
        }
        return false;
    }

    /**
     * Creates symblic link to file or dirtectory.
     *
     * @param string $target Absolute path to file or directory
     * @param string $link   Absolute path to symlink
     * @return string|bool
     */
    public function makeLink($target, $link)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($target[0] !== '/') {
                    $target = ssh2_sftp_realpath($_sftp, $target);
                }
                if ($link[0] !== '/') {
                    $link = ssh2_sftp_realpath($_sftp, $link);
                }
                return ssh2_sftp_symlink($_sftp, $target, $link);
            }
        }
        return false;
    }

    /**
     * Resolves symbolic link.
     *
     * @param string $path Path to file or directory
     * @return string|bool
     */
    public function readLink($link)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                return ssh2_sftp_readlink($_sftp, $link);
            }
        }
        return false;
    }

    /**
     * Creates a new directory and sets permissions.
     *
     * @param  string $path Path to directory
     * @param  int    $mode Permissions, octal number, same as for mkdir() function
     * @return bool
     */
    public function makeDir($path, $mode = 0775)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($path[0] === '.') {
                    $path = ssh2_sftp_realpath($_sftp, $path);
                }
                return ssh2_sftp_mkdir($_sftp, $path, $mode);
            }
        }
        return false;
    }

    /**
     * Recursively removes a directory and its subdirectories.
     *
     * @param string    $dir   Path to directory
     * @param int       $depth Maximum depth of recursion
     */
    public function removeDir($dir, $depth = 10) {
        if ($this->_conn && $depth > 0) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($dir[0] !== '/') {
                    $dir = ssh2_sftp_realpath($_sftp, $dir);
                }
                $stack = [$dir];
                while ($depth !== 0 && isset($stack[0])) {
                    $depth -= 1;
                    $dir = end($stack);
                    $dh = opendir("ssh2.sftp://" . ($this->_v1 ? $_sftp : intval($_sftp)) . $dir);
                    if ($dh !== false) {
                        $rmdir = true;
                        while (false !== ($file = readdir($dh))) {
                            if ($file !== '.' && $file !== '..') {
                                $stat = ssh2_sftp_stat($_sftp, "$dir/$file");
                                $is_dir = decoct(0040000 & $stat['mode']) === '40000';
                                if ($is_dir) {
                                    $stack[] = "$dir/$file";
                                    if ($rmdir) {
                                        $rmdir = false;
                                    }
                                } elseif (!ssh2_sftp_unlink($_sftp, "$dir/$file")) {
                                    $this->log(__METHOD__, "failed to unlink $dir/$file");
                                    return false;
                                }
                            }
                        }
                        closedir($dh);
                        if ($rmdir) {
                            if (ssh2_sftp_rmdir($_sftp, $dir)) {
                                array_pop($stack);
                                $depth += 1;
                            } else {
                                $this->log(__METHOD__, "failed to remove $dir");
                                return false;
                            }
                        }
                    } else {
                        $this->log(__METHOD__, "failed to open $dir");
                        return false;
                    }
                }
                return $rmdir;
            }
        }
        return false;
    }

    /**
     * Lists file objects in specified directory.
     *
     * @param string $dir  Path to directory
     * @param bool   $stat Whether to include stat() metadata in output
     * @return array
     */
    public function listFiles($dir, $stat = false)
    {
        if ($this->_conn) {
            $_sftp = ssh2_sftp($this->_conn);
            if ($_sftp) {
                if ($dir[0] !== '/') {
                    $dir = ssh2_sftp_realpath($_sftp, $dir);
                }
                $dh = opendir("ssh2.sftp://".($this->_v1 ? $_sftp : intval($_sftp))."$dir");
                if ($dh) {
                    $items = [];
                    while ($file = readdir($dh)) {
                        if ($file !== '.' && $file !== '..') {
                            $item['name'] = $file;
                            $item['path'] = "$dir/$file";
                            if ($stat === true) {
                                $item += ssh2_sftp_stat($_sftp, "$dir/$file");
                                $item['is_dir'] = decoct(0040000 & $item['mode']) === '40000';
                                $this->assocStat($item);
                            }
                            $items[] = $item;
                        }
                    }
                    closedir($dh);
                    return $items;
                }
            }
        }
        return false;
    }
}
