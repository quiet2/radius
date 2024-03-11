<?php
namespace Dapphp\Radius\Crypt;


/**
 * class Crypt_CHAP_MSv2
 *
 * Generate MS-CHAPv2 Packets. This version of MS-CHAP uses a 16 Bytes authenticator
 * challenge and a 16 Bytes peer Challenge. LAN-Manager responses no longer exists
 * in this version. The challenge is already a SHA1 challenge hash of both challenges
 * and of the username.
 *
 * @package Crypt_CHAP
 */
class Crypt_CHAP_MSv2 extends Crypt_CHAP_MSv1
{
    /**
     * The username
     * @var  string
     */
    public $username = null;
    //var $username = null; // removed for dapphp/radius

    /**
     * The 16 Bytes random binary peer challenge
     * @var  string
     */
    public $peerChallenge = null;
    //var $peerChallenge = null;  // removed for dapphp/radius

    /**
     * The 16 Bytes random binary authenticator challenge
     * @var  string
     */
    public $authChallenge = null;
    //var $authChallenge = null;  // removed for dapphp/radius

    /**
     * Constructor
     *
     * Generates the 16 Bytes peer and authentication challenge
     * @return void
     */
    //function Crypt_CHAP_MSv2()  // removed for dapphp/radius
    public function __construct()
    {
        //$this->Crypt_CHAP_MSv1();  // removed for dapphp/radius
        parent::__construct();
        $this->generateChallenge('peerChallenge', 16);
        $this->generateChallenge('authChallenge', 16);
    }

    /**
     * Generates a hash from the NT-HASH.
     *
     * @access public
     * @param  string  $nthash The NT-HASH
     * @return string
     */
    //function ntPasswordHashHash($nthash)  // removed for dapphp/radius
    public function ntPasswordHashHash($nthash)
    {
        return pack('H*',hash('md4', $nthash));
    }

    /**
     * Generates the challenge hash from the peer and the authenticator challenge and
     * the username. SHA1 is used for this, but only the first 8 Bytes are used.
     *
     * @access public
     * @return string
     */
    //function challengeHash()  // removed for dapphp/radius
    public function challengeHash()
    {
        return substr(pack('H*',hash('sha1', $this->peerChallenge . $this->authChallenge . $this->username)), 0, 8);
    }

    /**
     * Generates the response.
     *
     * @access public
     * @return string
     */
    //function challengeResponse()  // removed for dapphp/radius
    public function challengeResponse()
    {
        $this->challenge = $this->challengeHash();
        return $this->_challengeResponse();
    }

    /**
     * Generates the encrypted new password.
     *
     * @access public
     * @param  string  $newPassword The new plain text password
     * @param  string  $oldPassword The old plain text password
     * @return string  EncryptedPwBlock
     */
    public function newPasswordEncryptedWithOldNtPasswordHash($newPassword, $oldPassword)
    {
        $passwordHash = $this->ntPasswordHash($oldPassword);
        return $this->encryptPwBlockWithPasswordHash($this->str2unicode($newPassword), $passwordHash);
    }

    /**
     * Generates PwBlock
     *
     * @access public
     * @param  string  $password     New password
     * @param  string  $passwordHash Old password hash
     * @return string  PwBlock
     */
    public function encryptPwBlockWithPasswordHash($password, $passwordHash)
    {
        // [516=2*256+4] unicode(2) maxpasslength(256) passlength(4)
        $clearPwBlock = random_bytes(516);
        $pwSize       = strlen($password);
        $pwOffset     = strlen($clearPwBlock) - $pwSize - 4;

        $clearPwBlock = substr_replace($clearPwBlock, $password, $pwOffset, $pwSize);

        $clearPwBlock = substr_replace($clearPwBlock, pack("V", $pwSize), -4, 4);

        return $this->rc4($passwordHash, $clearPwBlock);
    }

    /**
     * RC4 symmetric cipher encryption/decryption
     *
     * @access public
     * @param  string key - secret key for encryption/decryption
     * @param  string str - string to be encrypted/decrypted
     * @return string
     */
    public function rc4($key, $str)
    {
        $s = array();
        for ($i = 0; $i < 256; $i++) {
            $s[$i] = $i;
        }
        $j = 0;
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
            $x = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $x;
        }
        $i = 0;
        $j = 0;
        $res = '';
        for ($y = 0; $y < strlen($str); $y++) {
            $i = ($i + 1) % 256;
            $j = ($j + $s[$i]) % 256;
            $x = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $x;
            $res .= $str[$y] ^ chr($s[($s[$i] + $s[$j]) % 256]);
        }
        return $res;
    }

    /**
     * ?
     *
     * @access public
     * @param  string  $newPassword The new plain text password
     * @param  string  $oldPassword The old plain text password
     * @return string  EncryptedPasswordHash
     */
    public function oldNtPasswordHashEncryptedWithNewNtPasswordHash($newPassword, $oldPassword)
    {
        $oldPasswordHash = $this->ntPasswordHash($oldPassword);
        $newPasswordHash = $this->ntPasswordHash($newPassword);
        return $this->ntPasswordHashEncryptedWithBlock($oldPasswordHash, $newPasswordHash);
    }

    /**
     * ?
     *
     * @access public
     * @param  string  $passwordHash Password hash to encrypt
     * @param  string  $block        Key to use for encryption
     * @return string
     */
    public function ntPasswordHashEncryptedWithBlock($passwordHash, $block)
    {
        $key   = $this->_desAddParity(substr($block, 0, 7));
        $resp1 = openssl_encrypt(substr($passwordHash, 0, 8), 'des-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        $key   = $this->_desAddParity(substr($block, 7, 7));
        $resp2 = openssl_encrypt(substr($passwordHash, 8, 8), 'des-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        return $resp1 . $resp2;
    }
}
