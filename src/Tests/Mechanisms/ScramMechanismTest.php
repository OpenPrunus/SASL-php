<?php declare(strict_types=1);

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
use SASL\Mechanisms\ScramMechanism;

/**
 * ScramMechanismTest unit class
 */
class ScramMechanismTest extends TestCase
{
    /**
     * @var ScramMechanism
     */
    protected $scram;

    /**
     * Initialize tests
     */
    public function setUp()
    {
        $this->scram = new ScramMechanism('sha-256');
    }

    /**
     * Test if ScramMechanism throws a MachanismsException
     *
     * @expectedException SASL\Exceptions\MechanismsException
     * @expectedExceptionMessage Invalid SASL mechanism type. Only following hashs supported : md2,md5,sha1,sha224,sha256,sha384,sha512
     */
    public function testScramInstanceFail()
    {
        $scram = new ScramMechanism('test');
    }

    /**
     * test if $this->scram is an instance of ScramMechanism
     */
    public function testScramInstanceSuccess()
    {
        $this->assertInstanceOf(ScramMechanism::class, $this->scram);
    }

    /**
     * Test verify function. Return false if challenge isn't good
     */
    public function testVerityWithoutChallengeResponse()
    {
        $this->assertFalse($this->scram->verify('test'));
        $this->assertFalse($this->scram->verify(''));
    }

    /**
     * Test if the returned value is correct
     */
    public function testGetFormattedResponse()
    {
        $string = $string = $this->scram->getFormattedResponse(['authcid' => "t,e=st", 'passwd' => 'pass', 'authzid' => 'zid']);
        $this->assertStringEndsWith('=', $string);
        $this->assertTrue(is_string($string));
        $this->assertRegExp(
           '#^n,a=zid,n=t=2Ce=3Dst,r=[a-z0-9A-Z=+/]+$#',
           $string
       );

       $string = $this->scram->getFormattedResponse(['authcid' => "t,e=st", 'passwd' => 'pass']);
       $this->assertStringEndsWith("=", $string);
       $this->assertTrue(is_string($string));
       $this->assertRegExp(
          '#^n,,n=t=2Ce=3Dst,r=[a-z0-9A-Z=+/]+$#',
          $string
      );
    }

    /**
     * Test if the Cnonce is invalid with authzid
     *
     * @expectedException SASL\Exceptions\MechanismsException
     * @expectedExceptionMessage Invalid cnonce, gs2Header or challenge
     */
    public function testExceptionInvalidCnonceWithAuthzidd()
    {
        $this->scram->getFormattedResponse(['authcid' => "t,e=st", 'passwd' => 'pass', 'authzid' => 'zid', 'challenge' => 'r=test,s=invalidtest,i=123,a=9']);
    }

    /**
     * Test if the Cnonce is invalid without authzid
     *
     * @expectedException SASL\Exceptions\MechanismsException
     * @expectedExceptionMessage Invalid cnonce, gs2Header or challenge
     */
    public function testExceptionInvalidCnonceWithoutAuthzid()
    {
        $this->scram->getFormattedResponse(['authcid' => "t,e=st", 'passwd' => 'pass', 'challenge' => 'r=test,s=invalidtest,i=123,a=9']);
    }

    /**
     * Test if the Challenge is invalid with authzid
     *
     * @expectedException SASL\Exceptions\MechanismsException
     * @expectedExceptionMessage Invalid cnonce, gs2Header or challenge
     */
    public function testExceptionInvalidChallengeWithAuthzid()
    {
        $this->scram->getFormattedResponse(['authcid' => "t,e=st", 'passwd' => 'pass', 'authzid' => 'zid', 'challenge' => 'toto']);
    }

    /**
     * Test if the Challenge is invalid without authzid
     *
     * @expectedException SASL\Exceptions\MechanismsException
     * @expectedExceptionMessage Invalid cnonce, gs2Header or challenge
     */
    public function testExceptionInvalidChallengeWithoutAuthzid()
    {
        $this->scram->getFormattedResponse(['authcid' => "t,e=st", 'passwd' => 'pass', 'challenge' => 'toto']);
    }
}
