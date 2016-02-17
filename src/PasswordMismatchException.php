<?php
namespace Jsq\Iron;

use InvalidArgumentException as Iae;

class PasswordMismatchException extends Iae implements IronException {}