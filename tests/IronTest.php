<?php
namespace Iron;

class IronTest extends \PHPUnit_Framework_TestCase
{
    /** @var Password */
    private $password;

    public function setUp()
    {
        $this->password = new Password(str_repeat('x', Password::MIN_LENGTH));
    }

    public function testCanEncryptAndDecryptStrings()
    {
        $plaintext = 'a string';
        $iron = new Iron;
        $encrypted = $iron->encrypt($this->password, $plaintext);
        $this->assertNotSame($plaintext, $encrypted);

        $this->assertSame($plaintext, $iron->decryptToken(
            Token::fromSealed($this->password, $encrypted),
            $this->password
        ));
    }
}
