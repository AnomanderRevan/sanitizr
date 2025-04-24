<?php

namespace AnomanderRevan\Sanitizr\Tests;

use Exception;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Log;
use Orchestra\Testbench\TestCase as BaseTestCase;
use AnomanderRevan\Sanitizr\Providers\SanitizrServiceProvider;
use AnomanderRevan\Sanitizr\Facades\SanitizrFacade;

abstract class TestCase extends BaseTestCase
{
    /**
     * Get package providers.
     *
     * @param Application $app
     * @return array
     */
    protected function getPackageProviders($app): array
    {
        return [
            SanitizrServiceProvider::class,
        ];
    }

    /**
     * Get package aliases.
     *
     * @param Application $app
     * @return array
     */
    protected function getPackageAliases($app): array
    {
        return [
            'Sanitizr' => SanitizrFacade::class,
        ];
    }

    /**
     * Set up the environment for testing.
     *
     * @param Application $app
     * @return void
     */
    protected function getEnvironmentSetUp($app): void
    {
        // Set config values if needed
        $app['config']->set('sanitize', require __DIR__ . '/../config/sanitizr.php');
    }
}