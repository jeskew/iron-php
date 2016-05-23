<?php
namespace Iron;

class PasswordTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testRejectsPasswordBeneathMinLength()
    {
        $invalidPassword = str_repeat('x', Password::MIN_LENGTH - 1);
        new Password($invalidPassword);
    }

    public function testSupportsPasswordsWithIds()
    {
        $validPassword = str_repeat('x', Password::MIN_LENGTH);
        $id = 'my_password';
        $instance = new Password($validPassword, $id);

        $this->assertSame($id, $instance->getId());
        $this->assertSame($validPassword, $instance->getPassword());
    }
}
