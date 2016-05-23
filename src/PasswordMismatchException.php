<?php
namespace Iron;

use Exception;
use InvalidArgumentException as Iae;

class PasswordMismatchException extends Iae implements IronException
{
    private $idProvided;
    private $idSought;

    /**
     * PasswordMismatchException constructor.
     * @param string $idProvided
     * @param string $idSought
     * @param string $message
     * @param $code
     * @param Exception $previous
     */
    public function __construct(
        $idProvided,
        $idSought,
        $message = '',
        $code = 0,
        Exception $previous = null
    ) {
        $this->idProvided = $idProvided;
        $this->idSought = $idSought;
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return string
     */
    public function getIdOfPasswordProvided()
    {
        return $this->idProvided;
    }

    /**
     * @return string
     */
    public function getIdOfPasswordSought()
    {
        return $this->idSought;
    }
}
