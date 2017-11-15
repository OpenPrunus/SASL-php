<?php

use PHPUnit\Framework\TestCase;
use SASL\Mechanisms\PlainMechanism;

/**
 * PlainMechanismTest unit class
 */
class PlainMechanismTest extends TestCase
{
    /**
     * Initialize tests
     */
    public function setUp()
    {
        $this->authzid = "alice";
        $this->authcid = "bob";
        $this->passwd  = "mypass";

        $this->utf8Nul = PlainMechanism::UTF8NUL;

        $this->plainMechanism = new PlainMechanism();
    }

    /**
     * Test returned response with authzid
     */
    public function testReturnResponseWithAuthzid()
    {
        $this->assertEquals($this->authzid.$this->utf8Nul.$this->authcid.$this->utf8Nul.$this->passwd ,$this->plainMechanism->getFormattedResponse(
            [
                "authzid" => $this->authzid,
                "authcid" => $this->authcid,
                "passwd"  => $this->passwd
        ]));
    }

    /**
     * Test returned response without authzid
     */
    public function testReturnResponseWithoutAuthzid()
    {
        $this->assertEquals($this->utf8Nul.$this->authcid.$this->utf8Nul.$this->passwd ,$this->plainMechanism->getFormattedResponse(
            [
                "authcid" => $this->authcid,
                "passwd"  => $this->passwd
        ]));
    }

    /**
     * @dataProvider casesProvider
     *
     * @expectedException SASL\Exceptions\MechanismsException
     */
    public function testKeysArraysDoesntExist($cases)
    {
        $this->plainMechanism->getFormattedResponse($cases);
    }

    /**
     * Provides differents cases of failure array arguments
     */
    public function casesProvider()
    {
        return [
            [
                ['toto' => 0, 'test' => 1, 'passwd' => 2]
            ],
            [
                ['authzid' => 0, 'test' => 1, 'passwd' => 2]
            ],
            [
                ['toto' => 0, 'authcid' => 1, 'test' => 2]
            ],
            [
                ['authzid' => 0, 'authcid' => 1, 'test' => 2 ]
            ],
            [
                ['toto' => 0, 'titi' => 1, 'test' => 2 ]
            ],
            [
                ['test' => 1, 'passwd' => 2]
            ],
            [
                ['authcid' => 1, 'test' => 2 ]
            ],
            [
                ['toto' => 1, 'test' => 2]
            ],
            [
                ['authcid' => "", 'passwd' => "123"]
            ],
            [
                ['authcid' => null, 'passwd' => "123"]
            ],
            [
                ['authcid' => "123", 'passwd' => ""]
            ],
            [
                ['authcid' => "123", 'passwd' => null]
            ],
            [
                ['authcid' => "", 'passwd' => ""]
            ],
            [
                ['authcid' => null, 'passwd' => null]
            ],
        ];
    }
}
