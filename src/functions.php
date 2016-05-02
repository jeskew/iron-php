<?php
namespace Jsq\Iron;

use InvalidArgumentException as Iae;

/**
 * @param mixed $data
 * @param string|PasswordInterface $password
 * @param integer $ttl
 * @param string $cipherMethod
 *
 * @return string
 */
function seal(
    $data,
    $password,
    int $ttl = 0,
    string $cipherMethod = Iron::DEFAULT_ENCRYPTION_METHOD
) {
    return (string) (new Iron($cipherMethod))
        ->encrypt(
            normalize_password($password), 
            json_encode($data), 
            $ttl
        );
}

/**
 * @param string $sealed
 * @param string|PasswordInterface $password
 * @param string $cipherMethod
 * @param callable $keyProvider
 * @param callable $saltGenerator
 *
 * @return mixed
 */
function unseal(
    string $sealed,
    $password,
    string $cipherMethod = Iron::DEFAULT_ENCRYPTION_METHOD,
    callable $keyProvider = null,
    callable $saltGenerator = null
) {
    $password = normalize_password($password);
    $token = Token::fromSealed(
        $password, 
        $sealed,
        true,
        $keyProvider ?: default_key_provider(),
        $saltGenerator ?: default_salt_generator()
    );
    
    $json = (new Iron($cipherMethod))
        ->decryptToken($token, $password);
    
    return json_decode($json, true);
}

function base64_encode(string $binary): string 
{
    return rtrim(strtr(\base64_encode($binary), [
        '+' => '-',
        '/' => '_',
    ]), '=');
}

function base64_decode(string $data): string 
{
    return \base64_decode(strtr($data, [
        '-' => '+',
        '_' => '/',
    ]));
}

function default_key_provider(): callable
{
    return __NAMESPACE__ . '\\generate_key';
}

/**
 * @param PasswordInterface $p
 * @param string $salt
 * @param int $length
 * @param int $iterations
 *
 * @return bool|string
 */
function generate_key(
    PasswordInterface $p,
    string $salt,
    int $length = 32,
    int $iterations = 1
): string {
    return hash_pbkdf2(
        'sha1',
        $p->getPassword(),
        $salt,
        $iterations,
        $length,
        true
    );
}

function default_salt_generator(): callable
{
    return __NAMESPACE__ . '\\generate_salt';
}

function generate_salt(int $length = 32): string
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
function normalize_password($password): PasswordInterface
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
