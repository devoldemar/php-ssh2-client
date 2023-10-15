<?php
use Devoldemar\SSH2Client;
use PHPUnit\Framework\TestCase;

final class SSH2ClientTest extends TestCase
{
    protected $sshHost = '';
    protected $sshHostMD5Key = '';
    protected $sshPort = 22;
    protected $sshUser = 'root';
    protected $sshPassword = '';
    protected $sshPublicKeyFile = '';
    protected $sshPrivateKeyFile = '';
    protected $sshKeyPassword = '';
    protected $sshAuthHost = '';
    protected $sshAuthHostUser = 'root';
    protected $sshAuthHostPublicKeyFile = '';
    protected $sshAuthHostPrivateKeyFile = '';
    protected $sshAuthHostKeyPassword = '';

    protected $ssh2 = null;

    protected function connect()
    {
        $this->ssh2 = new SSH2Client($this->sshHost, $this->sshPort);
    }

    protected function setUp(): void
    {
        foreach ($GLOBALS as $key => $val) {
            if (isset($this->$key)) {
                $this->$key = $val;
            }
        }
        $this->connect();

        if (stripos($this->getName(false), 'auth') === false && !$this->authAny()) {
            $this->markTestSkipped('Authentication failed');
        }
    }

    protected function tearDown(): void
    {
        if ($this->ssh2) {
            $this->ssh2->disconnect();
        }
    }

    protected function authByPassword()
    {
        if (!$this->sshUser || !$this->sshPassword) {
            return null;
        }
        return $this->ssh2->authByPassword($this->sshUser, $this->sshPassword);
    }

    protected function authByKeyFile()
    {
        if (!$this->sshUser || !$this->sshPublicKeyFile || !$this->sshPrivateKeyFile) {
            return null;
        }
        return $this->ssh2->authByKeyFile($this->sshUser, $this->sshPublicKeyFile, $this->sshPrivateKeyFile, $this->sshKeyPassword);
    }

    protected function authByKey()
    {
        if (!$this->sshUser || !$this->sshPublicKeyFile || !$this->sshPrivateKeyFile) {
            return null;
        }
        return $this->ssh2->authByKey($this->sshUser, file_get_contents($this->sshPublicKeyFile), file_get_contents($this->sshPrivateKeyFile), $this->sshKeyPassword);
    }

    protected function authByHost()
    {
        if (!$this->sshUser || !$this->sshAuthHost || !$this->sshAuthHostPublicKeyFile || !$this->sshAuthHostPrivateKeyFile) {
            return null;
        }
        return $this->ssh2->authByHost($this->sshUser, $this->sshAuthHost, $this->sshAuthHostPublicKeyFile, $this->sshAuthHostPrivateKeyFile, $this->sshAuthHostKeyPassword, $this->sshAuthHostUser);
    }

    protected function authAny()
    {
        return $this->authByPassword() || $this->authByKeyFile() || $this->authByHost();
    }

    protected function createTempFile($size)
    {
        $tmp = tmpfile();
        $length = 0;
        while ($length < $size) {
            $writeSize = min($size - $length, 10240);
            $written = fwrite($tmp, str_repeat("\0", $writeSize), $writeSize);
            if ($written === false) {
                fclose($tmp);
                return false;
            }
            $length += $written;
        }
        return $tmp;
    }

    public function testAuthByPassword()
    {
        $auth = $this->authByPassword();
        if ($auth === null) {
            $this->markTestSkipped('Authentication requires configured username and password');
        }
        $this->assertTrue($auth);
    }

    public function testAuthByKeyFile()
    {
        $auth = $this->authByKeyFile();
        if ($auth === null) {
            $this->markTestSkipped('Authentication requires configured username and keypair');
        }
        $this->assertTrue($auth);
    }

    public function testAuthByKey()
    {
        $auth = $this->authByKey();
        if ($auth === null) {
            $this->markTestSkipped('Authentication requires configured username and keypair');
        }
        $this->assertTrue($auth);
    }

    public function testAuthByHost()
    {
        $auth = $this->authByHost();
        if ($auth === null) {
            $this->markTestSkipped('Authentication requires configured username, hostname, keypair');
        }
        $this->assertTrue($auth);
    }

    public function testFingerprint()
    {
        if ($this->sshHostMD5Key == '') {
            $this->markTestSkipped('Authentication requires configured host key MD5 hash');
        }
        $result = $this->ssh2->fingerprint(SSH2_FINGERPRINT_MD5 | SSH2_FINGERPRINT_HEX);
        $this->assertEquals(strtolower($this->sshHostMD5Key), strtolower($result));
    }

    public function testExec()
    {
        $result = $this->ssh2->exec('whoami');
        $this->assertEquals($result, $this->sshUser);
    }

    /**
     * @depends testExec
     */
    public function testGetShell()
    {
        $result = $this->ssh2->getShell();
        $this->assertIsResource($result);
    }

    /**
     * @depends testExec
     */
    public function testUseShell()
    {
        $result = $this->ssh2->useShell();
        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertIsCallable($result[0]);
        $this->assertIsCallable($result[1]);
        sleep(1);
        $output = $result[0]($feof);
        $this->assertIsString($output);
        $this->assertFalse($feof);
        $bytes = $result[1]('whoami');
        $this->assertIsInt($bytes);
    }

    public function testGetFileStat() {
        $stat = $this->ssh2->getFileStat('.');
        $this->assertIsArray($stat);
        $this->assertArrayHasKey('mtime',$stat);
        $this->assertArrayHasKey('is_dir', $stat);
        $this->assertTrue($stat['is_dir']);
    }

    public function testWriteFile()
    {
        $tmp = $this->createTempFile($size = intval(1.5 * 1024 * 1024));
        if ($tmp === false) {
            $this->markTestSkipped('Failed to create temporary file');
        }
        $bytes = $this->ssh2->writeFile('test.dat', $tmp);
        $this->assertIsInt($bytes);
        $this->assertEquals($bytes, $size);
        fseek($tmp, 0);
        $contents = stream_get_contents($tmp);
        $bytes = $this->ssh2->writeFile('test.dat', $contents);
        $this->assertIsInt($bytes);
        $this->assertEquals($bytes, $size);
    }

    /**
     * @depends testWriteFile
     */
    public function testReadFile()
    {

        $tmp = $this->createTempFile($size = intval(1.5 * 1024 * 1024));
        if ($tmp === false) {
            $this->markTestSkipped('Failed to create temporary file');
        }
        fseek($tmp, 0);
        $hash = md5(stream_get_contents($tmp));
        $contents = '';
        $result = $this->ssh2->readFile('test.dat', function($data) use (&$contents) {
            $contents .= $data;
        });
        $this->assertIsInt($result);
        $this->assertEquals($result, $size);
        $this->assertEquals($result, strlen($contents));
        $this->assertEquals(md5($contents), $hash);
    }

    /**
     * @depends testWriteFile
     */
    public function testChmodFile()
    {

        $result = $this->ssh2->chmodFile('test.dat', 0400);
        $this->assertTrue($result);
        $bytes = $this->ssh2->writeFile('test.dat', "\0", 'a');
        $this->assertFalse($bytes);
    }

    /**
     * @depends testGetFileStat
     * @depends testWriteFile
     * @depends testReadFile
     * @depends testChmodFile
     */
    public function testUnlinkFile()
    {
        $this->ssh2->chmodFile('test.dat', 0600);
        $unlink = $this->ssh2->unlinkFile('test.dat');
        $stat = $this->ssh2->getFileStat('test.dat');
        $this->assertTrue($unlink);
        $this->assertFalse($stat);
    }

    /**
     * @depends testGetFileStat
     * @depends testWriteFile
     * @depends testUnlinkFile
     */
    public function testMakeLink()
    {
        $this->ssh2->writeFile('test.dat', '1234567890');
        $mklink = $this->ssh2->makeLink('test.dat', 'ltest.dat');
        $this->assertTrue($mklink);
        $stat = $this->ssh2->getFileStat('ltest.dat');
        $this->assertIsArray($stat);
        $this->assertTrue($stat['is_link']);
        $this->ssh2->unlinkFile('ltest.dat');
        $this->ssh2->unlinkFile('test.dat');
    }

    /**
     * @depends testMakeLink
     */
    public function testReadLink()
    {
        $this->ssh2->writeFile('test.dat', '1234567890');
        $mklink = $this->ssh2->makeLink('test.dat', 'ltest.dat');
        $this->assertTrue($mklink);
        $target = $this->ssh2->readLink('ltest.dat');
        $this->assertIsString($target);
        $this->assertEquals($target, $this->ssh2->getRealPath('test.dat'));
        $this->ssh2->unlinkFile('ltest.dat');
        $this->ssh2->unlinkFile('test.dat');
    }

    /**
     * @depends testGetFileStat
     */
    public function testMakeDir()
    {
        $mkdir = $this->ssh2->makeDir('./testdir/00');
        $this->assertTrue($mkdir);
        $stat = $this->ssh2->getFileStat('./testdir/00');
        $this->assertIsArray($stat);
    }

    public function testListFiles()
    {
        $files = $this->ssh2->listFiles('/', true);
        $this->assertIsArray($files);
        $this->assertArrayHasKey(0, $files);
        $this->assertIsArray($files[0]);
        $this->assertArrayHasKey('name', $files[0]);
        foreach ($files as $file) {
            if ($file['name'] === 'root') {
                break;
            } else {
                $file = null;
            }
        }
        $this->assertIsArray($file);
        $this->assertArrayHasKey('path', $file);
        $this->assertArrayHasKey('is_dir', $file);
        $this->assertTrue($file['is_dir']);
    }

    /**
     * @depends testWriteFile
     * @depends testMakeDir
     * @depends testListFiles
     */
    public function testRemoveDir()
    {
        $this->ssh2->makeDir('testdir/01');
        $this->ssh2->makeDir('testdir/02');
        $this->ssh2->makeDir('testdir/03');
        $this->ssh2->writeFile('testdir/test.dat', '1234567890');
        $this->ssh2->writeFile('testdir/02/test.dat', '1234567890');

        $rmdir = $this->ssh2->removeDir('testdir');
        $this->assertTrue($rmdir);
        $stat = $this->ssh2->getFileStat('testdir');
        $this->assertFalse($stat);
    }
}
