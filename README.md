# Sanitizr
A Laravel Input & Security Sanitization Package

Sanitizr is a Laravel package designed to sanitize user input, ensuring your application is protected against common security threats like SQL injection, XSS, and command injection.

---

## Installation

To install the `sanitizr` package, use Composer:

```bash
composer require anomanderrevan/sanitizr
```

---

## Publishing the Configuration File

After installing the package, publish the configuration file to customize the sanitization rules and filters:

```bash
php artisan vendor:publish --tag=sanitizr-config
```

This will create a `sanitizr.php` file in the `config` directory of your Laravel application.

---

## Publish the Middleware 

You can access the middleware from the package directly, or you can publish it to the app should you wish to customise it.
If you wish to publish the middleware, you can do so with the following command:

```bash
php artisan vendor:publish --tag=sanitizr-middleware
```
If you are publishing the middleware, you will need to update the namespace in the `app/Http/Middleware/AutoSan.php` file to match your app's namespace.

```php
namespace App\Http\Middleware; 
//namespace AnomanderRevan\Sanitizr\Http\Middleware;
```

---

## Configuration

The `sanitizr.php` configuration file allows you to define rules and filters for sanitizing input. Below is an overview of the configuration options:

### 1. **Rules**

Rules group filters that can be applied to entire requests. For example:

```php
    //Define the rules that will be used to sanitize the data
    'rules' => [
        //Rules applied to entire $request
        'global' => [
            'api' => ['escape_html'],
            'form' => [ 'strip_tags'],
            'security' => [ 'xss_check', 'sql_check' ],
        ],
        //Rules applied to specific fields
        'field' => [
            'first_name' => ['lowercase', 'ucfirst'],
            'last_name' => ['lowercase', 'ucfirst'],
            'email' => ['lowercase', 'sanitize_email'],
            'eircode' => ['uppercase', 'remove_special_chars'],
            'phone' => ['phone_plus_replace', 'remove_special_chars', 'numeric'],
            'mobile' => ['phone_plus_replace', 'remove_special_chars', 'numeric'],
        ],
    ],
```

- **`global`**: Global rules allow you to apply filters to each field.
- **`field`**: Field-specific rules allow you to apply filters to individual fields by name.

*Note: Global filters are applied first, and then field-specific filters are applied.*

### 2. **Excluded Fields**

Excluded Fields allows you to ensure specific fields are exempt from sanitization. For example:

```php
'excluded_fields' => [
        'csrf_token',
        'username',
        'password',
        'password_confirmation',
    ],
```


### 3. **Filters**

Filters are reusable functions for sanitizing data. You can use pre-defined filters within the array or add custom filters to suit your app. For example:

```php
'filters' => [
    'escape_html' => function($value) { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); },
    'strip_tags' => function($value) { return strip_tags($value); },
    'phone_plus_replace' => function($value) { return preg_replace('/\+/', '00', $value); },
],
```

---

## Usage

### Applying Rules to Requests

To apply sanitization rules to incoming requests, use the `AutoSan` middleware. To apply it to all routes, you can add it to your `app/Http/Kernel.php` file.

If you are using the middleware from the package directly:
```php
protected $middlewareGroups = [
    // For web routes
    'web' => [
        // Other middleware
        \AnomanderRevan\Sanitizr\Http\Middleware\AutoSan::class,
    ],
    // For API routes
    'api' => [
        // Other middleware
        \AnomanderRevan\Sanitizr\Http\Middleware\AutoSan::class,
    ],
];
```
If you are publishing the middleware:
```php
protected $middlewareGroups = [
    // For web routes
    'web' => [
        // Other middleware
        \App\Http\Middleware\AutoSan::class,
    ],
    // For API routes
    'api' => [
        // Other middleware
        \App\Http\Middleware\AutoSan::class,
    ],
];
```

Alternatively you may wish to apply the middleware to specific routes. You can do this by adding the middleware to the route definition in your `routes/web.php` or `routes/api.php` file:

```php
Route::post('/test-normal', [TestController::class, 'testPost']);
Route::post('/test-security-rule', [TestController::class, 'testPost'])->middleware(AutoSan::class . ':security');
Route::post('/test-api-rule', [TestController::class, 'testPost'])->middleware(AutoSan::class . ':api');
```

---

## Security Features

Sanitizr includes built-in filters which can be applied to detect and mitigate common security threats. By default these are grouped under the `security` rule, but you can also apply them to specific fields if needed.

1. **SQL Injection**: The `sql_check` filter detects and blocks SQL injection patterns.
2. **XSS**: The `xss_check` filter identifies and quarantines malicious `<script>` tags.
3. **Command Injection**: The `cmd_check` filter prevents command injection attempts.

When a potential security threat is detected, the middleware will log the incident and return a 400 response before the request is processed by the application.

When using the `cmd_check` filter, you can also specify whether to automatically check for command injection on URLs by enabling the `run_cmd_check_on_url` in the config. This is useful for APIs that may be vulnerable to command injection attacks. You can enable this feature in the configuration file:
```php
    'run_cmd_check_on_url' => true,
```
---

## Logging

When a potential security threat is detected, Sanitizr logs the incident using Laravel's `Log` facade. You can review the logs in the `storage/logs/laravel.log` file.

---

## Testing

To test the sanitization functionality, you can write unit tests for your application. For example:

```php
public function testSanitization()
{
    $input = [
        'first_name' => 'jOhN',
        'email' => 'EXAMPLE@EXAMPLE.COM',
    ];

    $sanitized = app('sanitizr')->sanitize($input, 'security');

    $this->assertEquals('John', $sanitized['first_name']);
    $this->assertEquals('example@example.com', $sanitized['email']);
}
```

---

## Support

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/anomanderrevan/sanitizr).

---

## License

This package is open-source software licensed under the [MIT license](LICENSE).
```