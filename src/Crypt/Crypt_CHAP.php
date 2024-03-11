<?php
namespace Dapphp\Radius\Crypt;

/**
 * class Crypt_CHAP
 *
 * Abstract base class for CHAP
 *
 * @package Crypt_CHAP
 */
class Crypt_CHAP /*extends PEAR // removed for dapphp/radius */
{
    /**
     * Random binary challenge
     * @var  string
     */
    public $challenge = null;
    //var $challenge = null;  // removed for dapphp/radius

    /**
     * Binary response
     * @var  string
     */
    public $response = null;
    //var $response = null;  // removed for dapphp/radius

    /**
     * User password
     * @var  string
     */
    public $password = null;
    //var $password = null;  // removed for dapphp/radius

    /**
     * Id of the authentication request. Should incremented after every request.
     * @var  integer
     */
    public $chapid = 1;
    //var $chapid = 1;  // removed for dapphp/radius

    /**
     * Constructor
     *
     * Generates a random challenge
     * @return void
     */
    //function Crypt_CHAP()  // removed for dapphp/radius
    public function __construct()
    {
        //$this->PEAR();
        $this->generateChallenge();
    }

    /**
     * Generates a random binary challenge
     *
     * @param  string  $varname  Name of the property
     * @param  integer $size     Size of the challenge in Bytes
     * @return void
     */
    //function generateChallenge($varname = 'challenge', $size = 8)  // removed for dapphp/radius
    public function generateChallenge($varname = 'challenge', $size = 8)
    {
        $this->$varname = '';
        for ($i = 0; $i < $size; $i++) {
            $this->$varname .= pack('C', 1 + mt_rand() % 255);
        }
        return $this->$varname;
    }

    /**
     * Generates the response. Overwrite this.
     *
     * @return void
     */
    //function challengeResponse()  // removed for dapphp/radius
    public function challengeResponse()
    {
    }

}
