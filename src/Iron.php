<?php
namespace Iron;

class Iron
{
    const DEFAULT_ENCRYPTION_METHOD = 'aes-256-cbc';

    /** @var string */
    private $method;
    /** @var callable */
    private $saltGenerator;
    /** @var callable */
    private $keyProvider;
    
    public function __construct(
        string $encryptionMethod = self::DEFAULT_ENCRYPTION_METHOD,
        callable $keyProvider = null,
        callable $saltGenerator = null
    ) {
        $this->method = $encryptionMethod;
        $this->keyProvider = $keyProvider ?: default_key_provider();
        $this->saltGenerator = $saltGenerator ?: default_salt_generator();
    }
    
    public function encrypt(
        PasswordInterface $password, 
        string $data, 
        int $ttl = 0
    ): Token {
        $salt = call_user_func($this->saltGenerator);
        $iv = random_bytes(openssl_cipher_iv_length($this->method));

        return new Token(
            $password,
            $salt,
            $iv,
            $this->generateCipherText($data, $password, $salt, $iv),
            $ttl ? time() + $ttl : $ttl,
            $this->keyProvider,
            $this->saltGenerator
        );
    }

    public function decryptToken(Token $token, PasswordInterface $password)
    {
        return openssl_decrypt(
            $token->getCipherText(),
            $this->method,
            call_user_func($this->keyProvider, $password, $token->getSalt()),
            true,
            $token->getIv()
        );
    }

    private function generateCipherText(
        string $data,
        PasswordInterface $password,
        string $salt,
        string $iv
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
