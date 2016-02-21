<?php
namespace Jsq\Iron;

class TokenTest extends \PHPUnit_Framework_TestCase
{
    private $password;

    public function setUp()
    {
        $this->password = new Password(str_repeat('x', Password::MIN_LENGTH));
    }

    public function testPrefixesTokenStringWithVersion()
    {
        $token = new Token($this->password, '', '', '');
        $this->assertStringStartsWith('Fe26.2', (string) $token);
    }

    public function testValidatesIntegrity()
    {
        $token = new Token($this->password, '', '', '');
        $parts = explode('*', $token);

        $mac = $parts[7];
        $macSalt = $parts[6];

        $token->validateChecksum($macSalt, $mac);

        try {
            $token->validateChecksum(generate_salt(), $mac);
            $this->fail();
        } catch (InvalidTokenException $e) {}
    }

    public function testWillUnsealIronTokenString()
    {
        $token = new Token($this->password, '', '', '');

        Token::fromSealed($this->password, (string) $token);
    }

    /**
     * @expectedException \Jsq\Iron\InvalidTokenException
     * @expectedExceptionMessage Invalid token structure
     */
    public function testWillNotUnsealTokensWithoutSufficientParts()
    {
        $token = (string) new Token($this->password, '', '', '');
        $token = str_replace('Fe26.2*', '', $token);

        Token::fromSealed($this->password, $token);
    }

    /**
     * @expectedException \Jsq\Iron\InvalidTokenException
     * @expectedExceptionMessage Invalid token version
     */
    public function testWillNotUnsealTokensWithDifferentVersion()
    {
        $token = (string) new Token($this->password, '', '', '');
        $token = str_replace('Fe26.2', 'Fe26.1', $token);

        Token::fromSealed($this->password, $token);
    }

    /**
     * @expectedException \Jsq\Iron\PasswordMismatchException
     */
    public function testWillNotUnsealTokensSealedWithDifferentPassword()
    {
        $passwordA = new Password(str_repeat('a', Password::MIN_LENGTH), 'a');
        $passwordB = new Password(str_repeat('b', Password::MIN_LENGTH), 'b');
        $token = new Token($passwordA, '', '', '');

        Token::fromSealed($passwordB, (string) $token);
    }

    /**
     * @expectedException \Jsq\Iron\ExpiredTokenException
     */
    public function testWillNotUnsealExpiredTokens()
    {
        $token = new Token($this->password, '', '', '', time() - 1);

        Token::fromSealed($this->password, (string) $token);
    }
}
