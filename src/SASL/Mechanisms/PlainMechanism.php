<?php

namespace SASL\Mechanisms;

use SASL\Exceptions\MechanismsException;

class PlainMechanism implements MechanismsInterface
{
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
    public function getFormattedResponse(Array $arguments)
    {
        if (!(isset($arguments['authcid']) && !empty($arguments['authcid']) &&
              isset($arguments['passwd']) && !empty($arguments['passwd']))) {
            throw new MechanismsException(sprintf('%s and/or %s keys are not defined', 'authcid', 'passwd'));
        }

        $this->authcid = $arguments['authcid'];
        $this->passwd  = $arguments['passwd'];

        if (isset($arguments['authzid'])) {
            $this->authzid = $arguments['authzid'];
        }

        return $this->authzid.(self::UTF8NUL).$this->authcid.(self::UTF8NUL).$this->passwd;
    }
}
