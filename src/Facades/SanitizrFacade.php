<?php

namespace Anomander\Sanitizr\Facades;

use Illuminate\Support\Facades\Facade;

class SanitizrFacade extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'sanitizr';
    }
}