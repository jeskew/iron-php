<?php
namespace Iron;

class PasswordMismatchExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testTracksIdOfPasswordsProvidedAndSought()
    {
        $instance = new PasswordMismatchException('a', 'b');

        $this->assertSame('a', $instance->getIdOfPasswordProvided());
        $this->assertSame('b', $instance->getIdOfPasswordSought());
    }
}
