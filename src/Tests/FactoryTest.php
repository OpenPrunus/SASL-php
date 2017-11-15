<?php

use PHPUnit\Framework\TestCase;
use SASL\Factory;

/**
 * FactoryTest unit class
 */
class FactoryTest extends TestCase
{
    /**
     * @expectedException SASL\Exceptions\FactoryException
     */
    public function testFactoryBadArgumentStringException()
    {
        new Factory('test');
    }

    /**
     * @expectedException SASL\Exceptions\FactoryException
     */
    public function testFactoryBadArgumentTypeException()
    {
        new Factory(null);
    }
}
