<?php
namespace Jsq\Iron;

use InvalidArgumentException as Iae;

/**
 * @param string $data
 * @param string $password
 * @param integer $ttl
 * @param string $cipherMethod
 *
 * @return string
 */
function seal(
    $data,
    $password,
    $ttl = 0,
    $cipherMethod = Iron::DEFAULT_ENCRYPTION_METHOD
) {
    return (string) (new Iron($cipherMethod))->encrypt($password, $data, $ttl);
}

/**
 * @param string $sealed
 * @param string $password
 * @param string $cipherMethod
 *
 * @return string
 */
function unseal(
    $sealed,
    $password,
    $cipherMethod = Iron::DEFAULT_ENCRYPTION_METHOD
) {
    return (new Iron($cipherMethod))
        ->decrypt($password, $sealed);
}

/**
 * @param int $bytes
 *
 * @return string
 *
 * @codeCoverageIgnore
 */
function random_bytes($bytes)
{
    if (function_exists('random_bytes')) {
        return \random_bytes($bytes);
    }

    $buf = openssl_random_pseudo_bytes($bytes, $strong);
    if ($strong) {
        return $buf;
    }

    throw new \RuntimeException('Unable to generate random bytes');
}

function base64_encode($binary)
{
    return rtrim(strtr(\base64_encode($binary), [
        '+' => '-',
        '/' => '_',
    ]), '=');
}

function base64_decode($data)
{
    return \base64_decode(strtr($data, [
        '-' => '+',
        '_' => '/',
    ]));
}

/**
 * @param PasswordInterface $p
 * @param string $salt
 * @param int $length
 *
 * @return bool|string
 */
function generate_key(PasswordInterface $p, $salt, $length = 32)
{
    return hash_pbkdf2('sha1', $p->getPassword(), $salt, 1, $length, true);
}

/**
 * @param int $length
 *
 * @return string
 */
function generate_salt($length = 32)
{
    return bin2hex(random_bytes($length));
}

/**
 * @param string|PasswordInterface $password
 *
 * @throws Iae
 *
 * @return PasswordInterface
 */
function normalize_password($password)
{
    if (is_string($password)) {
        return new Password($password);
    }

    if ($password instanceof PasswordInterface) {
        return $password;
    }

    throw new Iae('Passwords must be strings or instances of'
        . ' Jsq\\Iron\\PasswordInterface');
}

function hash_equals($expected, $actual)
{
    if (function_exists('hash_equals')) {
        return \hash_equals($expected, $actual);
    }

    if (strlen($expected) !== strlen($actual)) {
        return false;
    }

    $result = $expected ^ $actual;
    $return = 0;
    for ($i = 0; $i < strlen($result); $i++) {
        $return |= ord($result{$i});
    }

    return !$return;
}
