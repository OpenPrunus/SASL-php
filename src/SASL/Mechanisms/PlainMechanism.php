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
* @author Richard Heyes <richard@php.net>
* @author Prunus <prunus[at]ecuri[dot]es>
*/

namespace SASL\Mechanisms;

use SASL\Exceptions\MechanismsException;

class PlainMechanism implements MechanismsInterface
{
    /**
     * @var int
     */
    const UTF8NUL = "\000";

    /**
     * @var string
     */
    private $authzid;

    /**
     * @var string
     */
    private $authcid;

    /**
     * @var string
     */
    private $passwd;

    /**
     * Constructor
     *
     * @return PlainMechanism
     */
    public function __construct()
    {
        $this->authzid = "";
        $this->authcid = "";
        $this->passwd  = "";
    }

    /**
     * {@inheritdoc}
     */
    public function getFormattedResponse(array $arguments): string
    {
        if (!(isset($arguments['authcid']) && !empty($arguments['authcid']) &&
              isset($arguments['passwd']) && !empty($arguments['passwd']))) {
            throw new MechanismsException('authcid and/or passwd keys are not defined');
        }

        $this->authcid = $arguments['authcid'];
        $this->passwd  = $arguments['passwd'];

        if (isset($arguments['authzid'])) {
            $this->authzid = $arguments['authzid'];
        }

        return $this->authzid.(self::UTF8NUL).$this->authcid.(self::UTF8NUL).$this->passwd;
    }
}
