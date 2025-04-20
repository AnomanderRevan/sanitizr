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
php artisan vendor:publish --provider="AnomanderRevan\Sanitizr\SanitizrServiceProvider" --tag=config
```

This will create a `sanitizr.php` file in the `config` directory of your Laravel application.

---

## Configuration

The `sanitizr.php` configuration file allows you to define rules and filters for sanitizing input. Below is an overview of the configuration options:

### 1. **Rules**

Rules group filters that can be applied to entire requests. For example:

```php
'rules' => [
    'api' => ['trim', 'strip_tags', 'sql_clean'],
    'form' => ['xss_clean', 'sql_clean'],
],
```

- **`api`**: Applies `trim`, `strip_tags`, and `sql_clean` filters to sanitize API inputs.
- **`form`**: Applies `xss_clean` and `sql_clean` filters to protect form submissions.

### 2. **Field-Specific Rules**

Field-specific rules allow you to apply filters to individual fields by name. For example:

```php
'field_rules' => [
    'first_name' => ['lowercase', 'ucfirst'],
    'email' => ['remove_whitespace', 'sanitize_email'],
],
```

- **`first_name`**: Ensures the value is lowercase and capitalized.
- **`email`**: Removes whitespace and sanitizes the email address.

### 3. **Filters**

Filters are reusable functions for sanitizing data. You can define custom filters or use the built-in ones. For example:

```php
'filters' => [
    'trim' => function ($value) { return trim($value); },
    'sanitize_email' => function ($value) { return filter_var($value, FILTER_SANITIZE_EMAIL); },
    'sql_clean' => function ($value) {
        $pattern = '/(?:^|;)\s*(drop\s+table|truncate\s+table|delete\s+from|...)/i';
        if (preg_match($pattern, $value)) {
            Log::warning('Sanitizr: Possible Security Threat Detected (SQL Injection)', ['value' => $value]);
            return 'Submission Quarantined.';
        }
        return $value;
    },
],
```

---

## Usage

### Applying Rules to Requests

To apply sanitization rules to incoming requests, use the `AutoSan` middleware. Add it to your `app/Http/Kernel.php` file:

```php
protected $middlewareGroups = [
    'web' => [
        // Other middleware
        \AnomanderRevan\Sanitizr\Http\Middleware\AutoSan::class,
    ],
];
```

### Using Field-Specific Rules

Field-specific rules are automatically applied based on the field names in the request. For example:

```php
$request->validate([
    'first_name' => 'required|string',
    'email' => 'required|email',
]);
```

The `first_name` and `email` fields will be sanitized according to the rules defined in the `sanitizr.php` configuration file.

---

## Security Features

Sanitizr includes built-in filters to detect and mitigate common security threats:

1. **SQL Injection**: The `sql_clean` filter detects and blocks SQL injection patterns.
2. **XSS**: The `xss_clean` filter identifies and quarantines malicious `<script>` tags.
3. **Command Injection**: The `cmd_clean` filter prevents command injection attempts.

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
        'first_name' => '  john  ',
        'email' => '  example@example.com  ',
    ];

    $sanitized = app('sanitizr')->sanitize($input);

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