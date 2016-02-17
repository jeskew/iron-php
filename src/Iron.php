<?php
namespace Jsq\Iron;

class Iron
{
    const DEFAULT_ENCRYPTION_METHOD = 'aes-256-cbc';

    /** @var string */
    private $method;
    /** @var callable */
    private $saltProvider;
    /** @var callable */
    private $keyProvider;

    /**
     * Iron constructor.
     * @param string $encryptionMethod
     * @param callable|null $saltProvider
     * @param callable|null $keyProvider
     */
    public function __construct(
        $encryptionMethod = self::DEFAULT_ENCRYPTION_METHOD,
        callable $saltProvider = null,
        callable $keyProvider = null
    ) {
        $this->method = $encryptionMethod;
        $this->saltProvider = $saltProvider ?: 'Jsq\\Iron\\generate_salt';
        $this->keyProvider = $keyProvider ?: 'Jsq\\Iron\\generate_key';
    }

    /**
     * @param string|PasswordInterface $password
     * @param string $data
     * @param int $ttl
     *
     * @return string
     */
    public function encrypt($password, $data, $ttl = 0)
    {
        $password = normalize_password($password);
        $salt = call_user_func($this->saltProvider);
        $iv = random_bytes(openssl_cipher_iv_length($this->method));
        $token = new Token(
            $password,
            $salt,
            $iv,
            $this->generateCipherText($data, $password, $salt, $iv),
            $ttl ? time() + $ttl : $ttl,
            $this->saltProvider,
            $this->keyProvider
        );

        return (string) $token;
    }

    /**
     * @param string|PasswordInterface $password
     * @param string $data
     *
     * @return string
     */
    public function decrypt($password, $data)
    {
        $password = normalize_password($password);
        $token = Token::fromSealed($password, $data, $this->keyProvider);

        return openssl_decrypt(
            $token->getCipherText(),
            $this->method,
            call_user_func($this->keyProvider, $password, $token->getSalt()),
            true,
            $token->getIv()
        );
    }

    private function generateCipherText(
        $data,
        PasswordInterface $password,
        $salt,
        $iv
    ) {
        return openssl_encrypt(
            $data,
            $this->method,
            call_user_func($this->keyProvider, $password, $salt),
            true,
            $iv
        );
    }
}