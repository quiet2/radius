<?php

/**
 * RADIUS client example using PAP password.
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once '../src/Radius.php';

$server = (getenv('RADIUS_SERVER_ADDR')) ?: '192.168.0.20';
$user   = (getenv('RADIUS_USER'))        ?: 'nemo';
$pass   = (getenv('RADIUS_PASS'))        ?: 'arctangent';
$secret = (getenv('RADIUS_SECRET'))      ?: 'xyzzy5461';
$debug  = in_array('-v', $_SERVER['argv']);

$radius = new Dapphp\Radius\Radius();
$radius->setServer($server)        // IP or hostname of RADIUS server
       ->setSecret($secret)       // RADIUS shared secret
       ->setNasIpAddress('127.0.0.1')  // IP or hostname of NAS (device authenticating user)
       ->setAttribute(32, 'vpn')       // NAS identifier
       ->setDebug((bool)$debug);                  // Enable debug output to screen/console

// Send access request for a user with username = 'username' and password = 'password!'
echo "Sending access request to $server with username $user\n";
$response = $radius->accessRequest($user, $pass);

if ($response === false) {
    // false returned on failure
    echo sprintf("Access-Request failed with error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
} else {
    // access request was accepted - client authenticated successfully
    echo "Success!  Received Access-Accept response from RADIUS server.\n";
}

$ssid = bin2hex(random_bytes(4));
$radius = (new Dapphp\Radius\Radius($server, $secret))
    ->setAttributesInfo(40, ['Acct-Status-Type', 'I'])
    ->setAttributesInfo(44, ['Acct-Session-Id', 'S'])
    ->setAttributesInfo(46, ['Acct-Session-Time', 'I'])
    ->setAttributesInfo(25, ['h323-setup-time', 'S'])
    ->setAttributesInfo(30, ['h323-disconnect-cause', 'S'])
    ->setDebug((bool)$debug);

$response = $radius
    ->setAttribute(1, $user) // User-Name
    ->setAttribute(6, 1) // Service-Type
    ->setAttribute(30, '___to___') // Called-Station-Id
    ->setAttribute(31, '___from___') // Calling-Station-Id
    ->setAttribute(40, 1) // Acct-Status-Type
    ->setAttribute(44, $ssid) // Acct-Session-Id
    ->setVendorSpecificAttribute(9, 25,
        'h323-setup-time=03:00:56.337 CET Wed Feb 28 2024') // h323-setup-time
    ->accountingRequest();

$response = $radius
    ->resetAttributes()
    ->resetVendorSpecificAttributes()
    ->setAttribute(1, $user) // User-Name
    ->setAttribute(40, 2) // Acct-Status-Type
    ->setAttribute(44, $ssid) // Acct-Session-Id
    ->setAttribute(46, 15) // Acct-Session-Time (duration)
    ->setVendorSpecificAttribute(9, 30,
        "h323-disconnect-cause=" . dechex(16)) // release_code
    ->accountingRequest();

if ($response === false) {
    echo sprintf("Accounting-Request failed with error %d (%s).\n",
        $radius->getErrorCode(),
        $radius->getErrorMessage()
    );
} else {
    echo "Success!  Received Accounting-Response from RADIUS server.\n";
}