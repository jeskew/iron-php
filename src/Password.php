<?php
namespace Jsq\Iron;

use InvalidArgumentException as Iae;

final class Password implements PasswordInterface
{
    const MIN_LENGTH = 32;

    private $password;
    private $id;

    /**
     * @param string $password
     * @param string $id
     *
     * @throws Iae If the password is of insufficient length.
     */
    public function __construct($password, $id = '')
    {
        if (strlen($password) < self::MIN_LENGTH)
        {
            throw new Iae('Passwords must be strings at least '
                . self::MIN_LENGTH . ' characters long.');
        }

        $this->password = $password;
        $this->id = $id;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }
}