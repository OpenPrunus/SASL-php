<?php

namespace SASL;

use SASL\Exceptions\FactoryException;
use SASL\Exceptions\MechanismsException;
use SASL\Mechanisms\PlainMechanism;

/**
 * Factory class.
 * Manage mechanisms types
 *
 * @codeCoverageIgnore
 */
class Factory
{
    /**
     * @var PlainMechanism
     */
    protected $mechanism;

    /**
     * Constructor
     *
     * @param string type
     *
     * @return Factory
     *
     * @throws FactoryException
     */
    public function __construct($type)
    {
        if (!is_string($type)) {
            throw new FactoryException("Argument is not a string");
        }

        switch (strtolower($type)) {
            case 'plain':
                $this->mechanism = new PlainMechanism();
                break;

            default:
                throw new FactoryException("Unkown type");
        }
    }

    /**
     * Get formatted string with Mecanism implemented
     *
     * @param array $arguments
     * expected possible keys
     * (defined in
     * - RFC4616 https://tools.ietf.org/html/rfc4616
     * ) :
     * - authzid
     * - authcid
     * - passwd
     *
     * @return string
     *
     * @throws MechanismsException
     */
    public function getFormattedResponse(Array $arguments)
    {
        return $this->mechanism->getFormattedResponse($arguments);
    }
}
