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
 * @author Jehan <jehan.marmottard@gmail.com>
 */

namespace SASL\Mechanisms;

use SASL\Exceptions\MechanismsException;

class ScramMechanism implements MechanismsInterface
{

    /**
     * @array
     */
    protected $hashFunctions;

    /**
     * @string
     */
    protected $hashAlgo;

    /**
     * @string
     */
    protected $gs2Header;

    /**
     * @var string
     */
    protected $cnonce;

    /**
     * @var string
     */
    protected $firstMessageBare;

    /**
     * @var string
     */
    protected $saltedPassword;

    /**
     * @var string
     */
    protected $authMessage;

    /**
     * @var string
     */
    protected $authcid;

    /**
     * @var string
     */
    protected $passwd;

    /**
     * @var string
     */
    protected $challenge;

    /**
     * @var string
     */
    protected $authzid;

    /**
    * Construct a SCRAM-H client where 'H' is a cryptographic hash function.
    *
    * @param string $hash
    *
    * @return ScramMechanism
    *
    * @throws MechanismsException
    */
    function __construct(string $hash)
    {
        $selectedHashType = strtolower(str_replace('-', '', strtolower($hash)));
        $this->hashFunctions = [
            'md2'     => 'md2',
            'md5'     => 'md5',
            'sha-1'   => 'sha1',
            'sha-224' => 'sha224',
            'sha-256' => 'sha256',
            'sha-384' => 'sha384',
            'sha-512' => 'sha512'
        ];

        if (!isset($this->hashFunctions[$selectedHashType])) {
            throw new MechanismsException(sprintf('Invalid SASL mechanism type. Only following hashs supported : %s', implode(",", $this->hashFunctions)));
        }

        $this->hashAlgo  = $selectedHashType;
        $this->authcid   = "";
        $this->passwd    = "";
        $this->challenge = "";
        $this->authzid   = "";
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

        $this->authcid   = $arguments['authcid'];
        $this->passwd    = $arguments['passwd'];
        $this->challenge = isset($arguments['challenge']) ? $arguments['challenge'] : null;
        $this->authzid   = isset($arguments['authzid']) ? $arguments['authzid'] : null;

        if (empty($this->challenge)) {
            return $this->generateInitialResponse($this->authcid, $this->authzid);
        } else {
            return $this->generateResponse($this->challenge, $this->passwd );
        }
    }

    /**
     * Prepare a name for inclusion in a SCRAM response.
     *
     * @param string $username
     *
     * @return string
     */
    private function formatName(string $username): string
    {
        return str_replace(array('=', ','), array('=3D', '=2C'), $username);
    }

    /**
     * Generate the initial response which can be either sent directly in the first message or as a response to an empty
     * server challenge.
     *
     * @param string $authcid
     * @param string $authzid
     *
     * @return string
     */
   private function generateInitialResponse(string $authcid, string $authzid): string
   {
       $gs2CbindFlag           = 'n,';
       $authzidFlag            = !empty($authzid) ? sprintf("a=%s", $authzid) : '';
       $this->gs2Header        = sprintf("%s%s,", $gs2CbindFlag, $authzidFlag);
       $this->cnonce           = $this->generateCnonce();
       $this->firstMessageBare = sprintf("n=%s,r=%s", $authcid, $this->cnonce);

       return sprintf("%s%s", $this->gs2Header, $this->firstMessageBare);
   }

    /**
     * Parses and verifies a non-empty SCRAM challenge.
     *
     * @param string $challenge
     * @param string $password
     *
     * @return string
     */
    private function generateResponse(string $challenge, string $password): string
    {
        $matches = array();
        $serverMessageRegexp = "#^r=([\x21-\x2B\x2D-\x7E/]+)"
        . ",s=((?:[A-Za-z0-9/+]{4})*(?:[A-Za-z0-9/+]{3}=|[A-Za-z0-9/+]{2}==)?)"
        . ",i=([0-9]*)(,[A-Za-z]=[^,])*$#";

        if (!isset($this->cnonce, $this->gs2Header) || !preg_match($serverMessageRegexp, $challenge, $matches)) {
            return '';
        }

        $nonce  = $matches[1];
        $salt   = base64_decode($matches[2]);
        $i      = intval($matches[3]);
        $cnonce = substr($nonce, 0, strlen($this->cnonce));

        if (!$salt || $cnonce !== $this->cnonce) {
            // Invalid Base64 or invalid challenge! Are we under attack?.
            return '';
        }

        $channelBinding       = sprintf("c=%s", base64_encode($this->gs2Header));
        $finalMessage         = sprintf("%s,r=%s", $channelBinding, $nonce);
        $saltedPassword       = $this->hi($password, $salt, $i);
        $this->saltedPassword = $saltedPassword;
        $clientKey            = hash_hmac($this->hashAlgo, "Client Key", $saltedPassword, true);
        $storedKey            = hash($this->hashAlgo, $clientKey, true);
        $authMessage          = sprintf("%s,%s,%s", $this->firstMessageBare, $challenge, $finalMessage);
        $this->authMessage    = $authMessage;
        $clientSignature      = hash_hmac($this->hashAlgo, $authMessage, $storedKey, true);
        $clientProof          = $clientKey ^ $clientSignature;
        $proof                = sprintf(",p=%s", base64_encode($clientProof));

        return sprintf("%s%s", $finalMessage, $proof);
    }

    /**
     * Hi() call, which is essentially PBKDF2 (RFC-2898) with HMAC-H() as the pseudorandom function.
     *
     * @param string $str
     * @param string $hash
     * @param int    $i
     *
     * @return string
     */
    private function hi(string $str, string $salt, int $i): string
    {
        $int1 = "\0\0\0\1";
        $ui = hash_hmac($this->hashAlgo, $salt . $int1, $str, true);
        $result = $ui;

        for ($k = 1; $k < $i; $k++)
        {
            $ui = hash_hmac($this->hashAlgo, $ui, $str, true);
            $result = $result ^ $ui;
        }
        return $result;
    }

    /**
     * SCRAM has also a server verification step. On a successful outcome, it will send additional data which must
     * absolutely be checked against this function. If this fails, the entity which we are communicating with is probably
     * not the server as it has not access to your ServerKey.
     *
     * @param string $data
     *
     * @return bool
     */
    public function verify(string $data): bool
    {
        $verifierRegexp = '#^v=((?:[A-Za-z0-9/+]{4})*(?:[A-Za-z0-9/+]{3}=|[A-Za-z0-9/+]{2}==)?)$#';
        $matches = array();

        if (!isset($this->saltedPassword, $this->authMessage) || !preg_match($verifierRegexp, $data, $matches)) {
            // This cannot be an outcome, you never sent the challenge's response.
            return false;
        }

        $verifier                = $matches[1];
        $proposedServerSignature = base64_decode($verifier);
        $serverKey               = hash_hmac($this->hashAlgo, "Server Key", $this->saltedPassword, true);
        $serverSignature         = hash_hmac($this->hashAlgo, $this->authMessage, $serverKey, true);

        return $proposedServerSignature === $serverSignature;
    }

    /**
     * Creates the client nonce for the response
     *
     * @return string The cnonce value
     */
    protected function generateCnonce(): string
    {
        foreach (array('/dev/urandom', '/dev/random') as $file) {
            if (is_readable($file)) {
                return base64_encode(file_get_contents($file, false, null, -1, 32));
            }
        }

        $cnonce = '';

        for ($i = 0; $i < 32; $i++) {
            $cnonce .= chr(mt_rand(0, 255));
        }

        return base64_encode($cnonce);
    }
}
