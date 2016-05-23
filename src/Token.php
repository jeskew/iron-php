<?php
namespace Iron;

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
    private $saltGenerator;
    /** @var callable */
    private $keyProvider;

    /**
     * @param PasswordInterface $password
     * @param string $salt
     * @param string $iv
     * @param string $cipherText
     * @param int $expiration
     * @param callable|null $keyProvider
     * @param callable|null $saltGenerator
     */
    public function __construct(
        PasswordInterface $password,
        string $salt,
        string $iv,
        string $cipherText,
        $expiration = 0,
        callable $keyProvider = null,
        callable $saltGenerator = null
    ) {
        $this->password = $password;
        $this->salt = $salt;
        $this->iv = $iv;
        $this->cipherText = $cipherText;
        $this->expiration = $expiration;
        $this->keyProvider = $keyProvider ?: default_key_provider();
        $this->saltGenerator = $saltGenerator ?: default_salt_generator();
    }

    /**
     * @param PasswordInterface $password
     * @param string $sealed
     * @param bool $validate
     * @param callable|null $keyProvider
     * @param callable|null $saltGenerator
     *
     * @return Token
     */
    public static function fromSealed(
        PasswordInterface $password,
        string $sealed,
        bool $validate = true,
        callable $keyProvider = null,
        callable $saltGenerator = null
    ): Token {
        $parts = explode('*', $sealed);
        if (count($parts) !== 8) {
            throw new InvalidTokenException('Invalid token structure.');
        }

        list($version, $pwId, $salt, $iv, $cipherText, $ttd, $macSalt, $mac)
            = $parts;

        if ($version !== Token::MAC_PREFIX . Token::MAC_FORMAT_VERSION) {
            throw new InvalidTokenException('Invalid token version.');
        }

        if ($pwId !== $password->getId()) {
            throw new PasswordMismatchException(
                $password->getId(), 
                $pwId, 
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
            $keyProvider,
            $saltGenerator
        );

        if ($validate) {
            if ($token->isExpired()) {
                throw new ExpiredTokenException('Token expired on '
                    . DateTime::createFromFormat('U', $ttd)->format('c'));
            }

            $token->validateChecksum($macSalt, $mac);
        }

        return $token;
    }

    public function __toString(): string
    {
        $stringToSign = $this->createStringToSign();
        $salt = generate_salt();

        return implode('*', [
            $stringToSign,
            $salt,
            $this->authenticateToken(
                $stringToSign,
                generate_key($this->password, $salt)
            ),
        ]);
    }

    public function validateChecksum(string $salt, string $expectedChecksum)
    {
        $actualChecksum = $this->authenticateToken(
            $this->createStringToSign(),
            generate_key($this->password, $salt)
        );

        if (!hash_equals($expectedChecksum, $actualChecksum)) {
            throw new InvalidTokenException('Invalid checksum.');
        }
    }

    public function getPasswordId(): string 
    {
        return $this->password->getId();
    }

    public function getSalt(): string
    {
        return $this->salt;
    }

    public function getIv(): string
    {
        return $this->iv;
    }

    public function getCipherText(): string 
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

    public function isExpired(int $gracePeriod = 0): bool 
    {
        return is_numeric($this->getExpiration())
            && $this->getExpiration() < time() + $gracePeriod;
    }

    private function authenticateToken(string $token, string $key): string 
    {
        return base64_encode(hash_hmac(self::DIGEST_METHOD, $token, $key, true));
    }

    private function createStringToSign(): string
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
}
