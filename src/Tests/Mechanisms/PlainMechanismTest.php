<?php

/**
 * Sasl library.
 *
 * Copyright (c) 2002-2003 Richard Heyes,
 *               2014 Fabian Grutschus,
 *               2017 Prunus
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * o Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * o Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.|
 * o The names of the authors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @author Prunus <prunus[at]ecuri[dot]es>
 */

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
