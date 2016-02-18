<?php
namespace Jsq\Iron;

use InvalidArgumentException as Iae;

/**
 * @param string $data
 * @param string $password
 * @param int|null $ttl
 * @param string $cipherMethod
 * @param callable|null $saltProvider
 * @param callable|null $keyGenerator
 *
 * @return string
 */
function seal(
    $data,
    $password,
    $ttl = 0,
    $cipherMethod = Iron::DEFAULT_ENCRYPTION_METHOD,
    callable $saltProvider = null,
    callable $keyGenerator = null
) {
    return (new Iron($cipherMethod, $saltProvider, $keyGenerator))
        ->encrypt($password, $data, $ttl);
}

/**
 * @param string $sealed
 * @param string $password
 * @param string $cipherMethod
 * @param callable|null $saltProvider
 * @param callable|null $keyGenerator
 *
 * @return string
 */
function unseal(
    $sealed,
    $password,
    $cipherMethod = Iron::DEFAULT_ENCRYPTION_METHOD,
    callable $saltProvider = null,
    callable $keyGenerator = null
) {
    return (new Iron($cipherMethod, $saltProvider, $keyGenerator))
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
 * @param PasswordInterface $password
 * @param string $salt
 * @param int $length
 * @param int $iterations
 *
 * @return bool|string
 */
function generate_key(PasswordInterface $password, $salt, $length = 32, $iterations = 1)
{
    return openssl_pbkdf2($password->getPassword(), $salt, $length, $iterations);
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