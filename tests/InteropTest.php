<?php
namespace Jsq\Iron;

class InteropTest extends \PHPUnit_Framework_TestCase
{
    /** @var Password */
    private $password;

    public function setUp()
    {
        if (!`which node` || version_compare('4.0.0', trim(`node -v`), '<')) {
            $this->markTestSkipped('Unable to run Node.js Iron library');
        }

        $this->password = new Password(str_repeat('x', Password::MIN_LENGTH));
    }

    /**
     * @dataProvider sealableDataProvider
     *
     * @param mixed $toSeal
     */
    public function testCanUnsealTokensSealedByNodeJsIron($toSeal)
    {
        $json = escapeshellarg(json_encode($toSeal));
        $password = $this->password->getPassword();
        $executable = __DIR__ . '/iron.js seal';
        $sealed = trim(`node --harmony $executable $password $json`);
        $unsealed = unseal($sealed, $this->password);

        $this->assertSame($toSeal, json_decode($unsealed, true));
    }

    /**
     * @dataProvider sealableDataProvider
     *
     * @param mixed $toSeal
     */
    public function testCanSealTokensThatCanBeUnsealedByNodeJsIron($toSeal)
    {
        $sealed = seal(json_encode($toSeal), $this->password);
        $password = $this->password->getPassword();
        $executable = __DIR__ . '/iron.js unseal';
        $unsealed = trim(`node --harmony $executable $password $sealed`);

        $this->assertSame($toSeal, json_decode($unsealed, true));
    }

    public function sealableDataProvider()
    {
        return [
            ['a string'],
            [[1, 2, null, 3]],
            [['key' => 'value']]
        ];
    }
}
