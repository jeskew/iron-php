<?php
namespace Iron;

use InvalidArgumentException as Iae;

final class Password implements PasswordInterface
{
    const MIN_LENGTH = 32;

    private $password;
    private $id;

    public function __construct(string $password, string $id = '')
    {
        if (strlen($password) < self::MIN_LENGTH)
        {
            throw new Iae('Passwords must be strings at least '
                . self::MIN_LENGTH . ' characters long.');
        }

        $this->password = $password;
        $this->id = $id;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function getId(): string
    {
        return $this->id;
    }
}
