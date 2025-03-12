<?php

namespace AnomanderRevan\Sanitizr\Providers;

use Anomander\Sanitizr\Services\SanitizrService;
use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;

class SanitizrServiceProvider extends ServiceProvider
{
    public function boot(Router $router)
    {
        // Publish config file
        $this->publishes([
            __DIR__ . '/../../config/sanitizr.php' => config_path('sanitizr.php'),
        ], 'sanitizr-config');

        // Publish middleware
        $this->publishes([
            __DIR__ . '/../Http/Middleware/AutoSan.php' => app_path('Http/Middleware/AutoSan.php'),
        ], 'sanitizr-middleware');

        // Register middleware
        $router->pushMiddlewareToGroup('web', \Anomander\Sanitizr\Http\Middleware\AutoSan::class);
        $router->pushMiddlewareToGroup('api', \Anomander\Sanitizr\Http\Middleware\AutoSan::class);
    }

    public function register()
    {
        // Merge config file
        $this->mergeConfigFrom(__DIR__ . '/../../config/sanitizr.php', 'sanitizr');

        // Register the SanitizrService
        $this->app->singleton('sanitizr', function ($app) {
            return new SanitizrService(config('sanitizr.filters'));
        });

        // Register the facade
        $this->app->alias(SanitizrService::class, 'sanitizr');
    }
}
