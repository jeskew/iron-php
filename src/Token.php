<?php
namespace Jsq\Iron;

use DateTime;

final class Token
{
    const MAC_FORMAT_VERSION = '2';
    const MAC_PREFIX = 'Fe26.';
    const DIGEST_METHOD = 'sha256';

    /** @var PasswordInterface */
    private $password;
    /** @var string */
    private $salt;
    /** @var string */
    private $iv;
    /** @var string */
    private $cipherText;
    /** @var int */
    private $expiration;
    /** @var callable */
    private $saltProvider;
    /** @var callable */
    private $keyGenerator;

    /**
     * @param PasswordInterface $password
     * @param string $salt
     * @param string $iv
     * @param string $cipherText
     * @param int $expiration
     * @param callable $saltProvider
     * @param callable $keyGenerator
     */
    public function __construct(
        PasswordInterface $password,
        $salt,
        $iv,
        $cipherText,
        $expiration = 0,
        callable $saltProvider = null,
        callable $keyGenerator = null
    ){
        $this->password = $password;
        $this->salt = $salt;
        $this->iv = $iv;
        $this->cipherText = $cipherText;
        $this->expiration = $expiration;
        $this->saltProvider = $saltProvider ?: 'Jsq\\Iron\\generate_salt';
        $this->keyGenerator = $keyGenerator ?: 'Jsq\\Iron\\generate_key';
    }

    public function __toString()
    {
        $stringToSign = $this->createStringToSign();
        $salt = call_user_func($this->saltProvider);

        return implode('*', [
            $stringToSign,
            $salt,
            $this->authenticateToken(
                $stringToSign,
                call_user_func($this->keyGenerator, $this->password, $salt)
            ),
        ]);
    }

    public function validateChecksum($salt, $expectedChecksum)
    {
        $actualChecksum = $this->authenticateToken(
            $this->createStringToSign(),
            call_user_func($this->keyGenerator, $this->password, $salt)
        );

        if ($actualChecksum !== $expectedChecksum) {
            throw new InvalidTokenException('Invalid checksum.');
        }
    }

    /**
     * @return string
     */
    public function getPasswordId()
    {
        return $this->password->getId();
    }

    /**
     * @return string
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @return string
     */
    public function getCipherText()
    {
        return $this->cipherText;
    }

    /**
     * @return int|string
     */
    public function getExpiration()
    {
        return $this->expiration ?: '';
    }

    /**
     * @param int $gracePeriod
     *
     * @return bool
     */
    public function isExpired($gracePeriod = 0)
    {
        return is_numeric($this->getExpiration())
            && $this->getExpiration() < time() + $gracePeriod;
    }

    private function authenticateToken($token, $key)
    {
        return base64_encode(hash_hmac(self::DIGEST_METHOD, $token, $key, true));
    }

    private function createStringToSign()
    {
        return implode('*', [
            self::MAC_PREFIX . self::MAC_FORMAT_VERSION,
            $this->getPasswordId(),
            $this->getSalt(),
            base64_encode($this->getIv()),
            base64_encode($this->getCipherText()),
            $this->getExpiration(),
        ]);
    }

    public static function fromSealed(
        PasswordInterface $password,
        $data,
        callable $saltProvider = null,
        callable $keyGenerator = null
    ) {
        $parts = explode('*', $data);
        if (count($parts) !== 8) {
            throw new InvalidTokenException('Invalid token structure.');
        }

        list($version, $pwId, $salt, $iv, $cipherText, $ttd, $macSalt, $mac)
            = $parts;

        if ($version !== self::MAC_PREFIX . self::MAC_FORMAT_VERSION) {
            throw new InvalidTokenException('Invalid token version.');
        }

        if ($pwId !== $password->getId()) {
            throw new PasswordMismatchException(
                "Token encrypted with password $pwId; password"
                . " {$password->getId()} provided for validation."
            );
        }

        $token = new self(
            $password,
            $salt,
            base64_decode($iv),
            base64_decode($cipherText),
            $ttd,
            $saltProvider,
            $keyGenerator
        );

        if ($token->isExpired()) {
            throw new ExpiredTokenException('Token expired on '
                . DateTime::createFromFormat('U', $ttd)->format('c'));
        }

        $token->validateChecksum($macSalt, $mac);

        return $token;
    }
}