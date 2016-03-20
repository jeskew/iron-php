<?php
namespace Jsq\Iron;

class Iron
{
    const DEFAULT_ENCRYPTION_METHOD = 'aes-256-cbc';

    /** @var string */
    private $method;
    /** @var callable */
    private $saltGenerator;
    /** @var callable */
    private $keyProvider;

    /**
     * @param string $encryptionMethod
     * @param callable|null $keyProvider
     * @param callable|null $saltGenerator
     */
    public function __construct(
        $encryptionMethod = self::DEFAULT_ENCRYPTION_METHOD,
        callable $keyProvider = null,
        callable $saltGenerator = null
    ) {
        $this->method = $encryptionMethod;
        $this->keyProvider = $keyProvider ?: 'Jsq\Iron\generate_key';
        $this->saltGenerator = $saltGenerator ?: 'Jsq\Iron\generate_salt';
    }

    /**
     * @param string|PasswordInterface $password
     * @param string $data
     * @param int $ttl
     *
     * @return Token
     */
    public function encrypt($password, $data, $ttl = 0)
    {
        $password = normalize_password($password);
        $salt = call_user_func($this->saltGenerator);
        $iv = random_bytes(openssl_cipher_iv_length($this->method));

        return new Token(
            $password,
            $salt,
            $iv,
            $this->generateCipherText(json_encode($data), $password, $salt, $iv),
            $ttl ? time() + $ttl : $ttl,
            $this->keyProvider,
            $this->saltGenerator
        );
    }

    /**
     * @param string|PasswordInterface $password
     * @param string|Token $data
     *
     * @return string
     */
    public function decrypt($password, $data)
    {
        $password = normalize_password($password);
        $token = $this->normalizeToken($password, $data);

        return $this->decryptToken($token, $password);
    }

    public function decryptToken(Token $token, PasswordInterface $password)
    {
        return json_decode(openssl_decrypt(
            $token->getCipherText(),
            $this->method,
            call_user_func($this->keyProvider, $password, $token->getSalt()),
            true,
            $token->getIv()
        ), true);
    }

    private function normalizeToken(PasswordInterface $password, $token)
    {
        if ($token instanceof Token) {
            return $token;
        }

        return Token::fromSealed(
            $password,
            $token,
            $validate = true,
            $this->keyProvider,
            $this->saltGenerator
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
