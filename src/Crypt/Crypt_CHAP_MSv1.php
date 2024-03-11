<?php
namespace Dapphp\Radius\Crypt;

/**
 * class Crypt_CHAP_MSv1
 *
 * Generate MS-CHAPv1 Packets. MS-CHAP doesen't use the plaintext password, it uses the
 * NT-HASH wich is stored in the SAM-Database or in the smbpasswd, if you are using samba.
 * The NT-HASH is MD4(str2unicode(plaintextpass)).
 * You need the hash extension for this class.
 *
 * @package Crypt_CHAP
 */
class Crypt_CHAP_MSv1 extends Crypt_CHAP
{
    /**
     * Wether using deprecated LM-Responses or not.
     * 0 = use LM-Response, 1 = use NT-Response
     * @var  bool
     */
    protected $flags = 1;
    //var $flags = 1;  // removed for dapphp/radius

    protected $useMcrypt = false; // added for dapphp/radius (php 5.3 must use mcrypt)

    /**
     * Constructor
     *
     * Loads the hash extension
     * @return void
     */
    //function Crypt_CHAP_MSv1()  // removed for dapphp/radius
    public function __construct()
    {
        parent::__construct();

        // removed for dapphp/radius
        //$this->Crypt_CHAP();
        //$this->loadExtension('hash');

        // added openssl & mcrypt check for dapphp/radius
        if (!extension_loaded('openssl') && !extension_loaded('mcrypt')) {
            throw new \Exception("openssl and mcrypt are not installed; cannot use Radius MSCHAP functions");
        }

        // Added mcrypt check for PHP 5.3 for dapphp/radius
        // OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING are required but not
        // supported by ext/openssl until PHP 5.4.
        if (version_compare(PHP_VERSION, '5.4') < 0) {
            if (!extension_loaded('mcrypt')) {
                throw new \Exception("Radius MSCHAP functions require mcrypt extension for PHP 5.3");
            }

            $this->useMcrypt = true;
        }
    }

    /**
     * Generates the NT-HASH from the given plaintext password.
     *
     * @access public
     * @return string
     */
    //function ntPasswordHash($password = null)  // removed for dapphp/radius
    public function ntPasswordHash($password = null)
    {
        //if (isset($password)) {
        if (!is_null($password)) {
            return pack('H*',hash('md4', $this->str2unicode($password)));
        } else {
            return pack('H*',hash('md4', $this->str2unicode($this->password)));
        }
    }

    /**
     * Converts ascii to unicode.
     *
     * @access public
     * @return string
     */
    //function str2unicode($str)  // removed for dapphp/radius
    public function str2unicode($str)
    {

        if (function_exists('mb_convert_encoding')) {
            return mb_convert_encoding($str, 'UTF-16LE');
        } else {
            $uni = '';
            $str = (string) $str;
            for ($i = 0; $i < strlen($str); $i++) {
                $a = ord($str[$i]) << 8;
                $uni .= sprintf("%X", $a);
            }
            return pack('H*', $uni);
        }
    }

    /**
     * Generates the NT-Response.
     *
     * @access public
     * @return string
     */
    //function challengeResponse()  // removed for dapphp/radius
    public function challengeResponse()
    {
        return $this->_challengeResponse();
    }

    /**
     * Generates the NT-Response.
     *
     * @access public
     * @return string
     */
    //function ntChallengeResponse()  // removed for dapphp/radius
    public function ntChallengeResponse()
    {
        return $this->_challengeResponse(false);
    }

    /**
     * Generates the LAN-Manager-Response.
     *
     * @access public
     * @return string
     */
    //function lmChallengeResponse()  // removed for dapphp/radius
    public function lmChallengeResponse()
    {
        return $this->_challengeResponse(true);
    }

    /**
     * Generates the response.
     *
     * Generates the response using DES.
     *
     * @param  bool  $lm  wether generating LAN-Manager-Response
     * @access private
     * @return string
     */
    //function _challengeResponse($lm = false)  // removed for dapphp/radius
    protected function _challengeResponse($lm = false)
    {
        if ($lm) {
            $hash = $this->lmPasswordHash();
        } else {
            $hash = $this->ntPasswordHash();
        }

        $hash = str_pad($hash, 21, "\0");

        // added openssl routines for dapphp/radius
        $key   = $this->_desAddParity(substr($hash, 0, 7));
        $resp1 = openssl_encrypt($this->challenge, 'des-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        $key   = $this->_desAddParity(substr($hash, 7, 7));
        $resp2 = openssl_encrypt($this->challenge, 'des-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        $key   = $this->_desAddParity(substr($hash, 14, 7));
        $resp3 = openssl_encrypt($this->challenge, 'des-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        return $resp1 . $resp2 . $resp3;
    }

    /**
     * Generates the LAN-Manager-HASH from the given plaintext password.
     *
     * @access public
     * @return string
     */
    //function lmPasswordHash($password = null)  // removed for dapphp/radius
    public function lmPasswordHash($password = null)
    {
        $plain = isset($password) ? $password : $this->password;

        $plain = substr(strtoupper($plain), 0, 14);
        while (strlen($plain) < 14) {
            $plain .= "\0";
        }

        return $this->_desHash(substr($plain, 0, 7)) . $this->_desHash(substr($plain, 7, 7));
    }

    /**
     * Generates an irreversible HASH.
     *
     * @access private
     * @return string
     */
    //function _desHash($plain)  // removed for dapphp/radius
    private function _desHash($plain)
    {
        // added openssl routines for dapphp/radius
        $key = $this->_desAddParity($plain);
        $hash = openssl_encrypt('KGS!@#$%', 'des-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        return $hash;
    }

    /**
     * Adds the parity bit to the given DES key.
     *
     * @access private
     * @param  string  $key 7-Bytes Key without parity
     * @return string
     */
    //function _desAddParity($key)  // removed for dapphp/radius
    protected function _desAddParity($key)
    {
        static $odd_parity = array(
            1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
            16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
            32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
            49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
            64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
            81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
            97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
            112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
            128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
            145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
            161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
            176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
            193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
            208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
            224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
            241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254);

        $bin = '';
        for ($i = 0; $i < strlen($key); $i++) {
            $bin .= sprintf('%08s', decbin(ord($key[$i])));
        }

        $str1 = explode('-', substr(chunk_split($bin, 7, '-'), 0, -1));
        $x = '';
        foreach($str1 as $s) {
            $x .= sprintf('%02s', dechex($odd_parity[bindec($s . '0')]));
        }

        return pack('H*', $x);

    }

    /**
     * Generates the response-packet.
     *
     * @param  bool  $lm  wether including LAN-Manager-Response
     * @access private
     * @return string
     */
    //function response($lm = false)  // removed for dapphp/radius
    public function response($lm = false)
    {
        $ntresp = $this->ntChallengeResponse();
        if ($lm) {
            $lmresp = $this->lmChallengeResponse();
        } else {
            $lmresp = str_repeat ("\0", 24);
        }

        // Response: LM Response, NT Response, flags (0 = use LM Response, 1 = use NT Response)
        return $lmresp . $ntresp . pack('C', !$lm);
    }
}