<?php
namespace Iron;

use InvalidArgumentException as Iae;

class ExpiredTokenException extends Iae implements IronException {}
