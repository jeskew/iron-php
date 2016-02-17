<?php
namespace Jsq\Iron;

use InvalidArgumentException as Iae;

class ExpiredTokenException extends Iae implements IronException {}