<?php
namespace Iron;

interface PasswordInterface
{
    public function getPassword(): string;

    public function getId(): string;
}
