<?php

namespace SASL\Mechanisms;

use SASL\Exceptions\MechanismsException;

/**
 * Interface for Mechanisms
 */
interface MechanismsInterface
{
    /**
     * Get formatted string with Mecanism implemented
     *
     * @param array $arguments
     *
     * @return string
     *
     * @throws MechanismsException
     */
    public function getFormattedResponse(Array $arguments);
}
