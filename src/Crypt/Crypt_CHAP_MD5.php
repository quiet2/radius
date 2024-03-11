<?php
namespace Dapphp\Radius\Crypt;


/**
 * class Crypt_CHAP_MD5
 *
 * Generate CHAP-MD5 Packets
 *
 * @package Crypt_CHAP
 */
class Crypt_CHAP_MD5 extends Crypt_CHAP
{

    /**
     * Generates the response.
     *
     * CHAP-MD5 uses MD5-Hash for generating the response. The Hash consists
     * of the chapid, the plaintext password and the challenge.
     *
     * @return string
     */
    //function challengeResponse()  // removed for dapphp/radius
    public function challengeResponse()
    {
        return pack('H*', md5( pack('C', $this->chapid) . $this->password . $this->challenge));
    }
}
