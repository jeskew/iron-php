<?php
namespace Iron;

class FunctionsTest extends \PHPUnit_Framework_TestCase
{
    /** @var Password */
    private $password;

    public function setUp()
    {
        $this->password = new Password(str_repeat('x', Password::MIN_LENGTH));
    }

    public function testNormalizesPasswords()
    {
        $this->assertInstanceOf(
            PasswordInterface::class,
            normalize_password($this->password->getPassword())
        );
        $this->assertSame($this->password, normalize_password($this->password));
        $this->assertNotSame(
            $this->password,
            normalize_password($this->password->getPassword())
        );
        $this->assertSame(
            $this->password->getPassword(),
            normalize_password($this->password->getPassword())->getPassword()
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Passwords must be strings
     */
    public function testWillNotNormalizeInvalidPasswords()
    {
        normalize_password([]);
    }

    public function testCanSealAndUnsealStrings()
    {
        $plaintext = 'a string';
        $sealed = seal($plaintext, $this->password);
        $this->assertNotSame($plaintext, $sealed);

        $this->assertSame($plaintext, unseal($sealed, $this->password));
    }
}
