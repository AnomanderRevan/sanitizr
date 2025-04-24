<?php

namespace AnomanderRevan\Sanitizr\Http\Middleware;

use AnomanderRevan\Sanitizr\Services\SanitizrService;
use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class AutoSan
{
    protected SanitizrService $sanitizr;

    public function __construct(SanitizrService $sanitizr)
    {
        $this->sanitizr = $sanitizr;
    }

    /**
     * Handle an incoming request.
     * @param Request $request
     * @param Closure $next
     * @param string|null $rule
     * @return mixed
     */
    public function handle(Request $request, Closure $next, string $rule = null): mixed
    {
        //Run checks on URL and request data for SQL Injection, XSS & CMD Injection
        if ($this->sanitizr->canRunSecurityChecks()) {
            try {
                $this->runSecurityChecks($request);
            } catch (Exception $exception) {
                Log::error('SANITIZR: Security check failed', [
                    'user_ip' => $request->ip(),
                    'timestamp' => now(),
                    'exception' => $exception->getMessage(),
                ]);

                return response()->json(['error' => 'Security check failed. Please contact support.'], 400);
            }
        }

        $data = $request->all();

        $filters = $this->getFilters($rule);
        $sanitizedData = $this->sanitizr->sanitize($data, $filters);

        $request->merge($sanitizedData);

        return $next($request);
    }

    /**
     * Get filters from config for a given rule
     * @param string $rule
     * @return array
     */
    protected function getFilters(string $rule): array
    {
        $filters = [];

        if ($rule) {
            if (config("sanitizr.rules.$rule")) {
                $filters = array_merge($filters, config("sanitizr.rules.$rule"));
            } else {
                Log::warning("SANITIZR: Rule '$rule' is not defined");
            }
        }

        return $filters;
    }


    protected function getSecurityChecks(): array
    {
        return config('sanitizr.security_checks', []);
    }

    /**
     * Run security checks on the request data & url
     * @param Request $request
     * @return void
     * @throws Exception
     */
    protected function runSecurityChecks(Request $request): void
    {
        $data = $request->all();
        $fullUrl = $request->fullUrl();

        // Check for command injection
        if (preg_match('/(;|\||&&|`|<\?|base64|cmd|exec|system|-rm|%3B)/i', $fullUrl)) {
            // Sanitize the value before logging
            $sanitizedValue = htmlspecialchars($fullUrl, ENT_QUOTES, 'UTF-8');

            // Log the incident with sanitized value
            Log::warning('SANITIZR: Possible Security Threat Detected (Command Injection)', ['value' => $sanitizedValue]);

            throw new Exception('Submission Quarantined.', 400);
        }

        // Check for XSS
        foreach ($data as $key => $value) {
            if (str_contains(strtolower($value), '<script>')) {
                // Sanitize the value before logging
                $sanitizedValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');

                // Log the incident with sanitized value
                Log::warning('SANITIZR: Possible Security Threat Detected (XSS)', ['value' => $sanitizedValue]);

                throw new Exception('Submission Quarantined.', 400);
            }
        }

        // Check for SQL injection
        foreach ($data as $key => $value) {
            // Define a regex pattern to detect SQL keywords in malicious contexts
            $pattern = '/(?:^|;)\s*(drop\s+table|truncate\s+table|delete\s+from|insert\s+into|select\s+.*?from|update\s+\w+\s+set|union\s+select|alter\s+table|create\s+table|exec\s+\w+)/i';

            // Check if the value triggers the regex pattern
            if (preg_match($pattern, $value)) {
                // Sanitize the value before logging
                $sanitizedValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');

                // Log the incident with sanitized value
                Log::warning('SANITIZR: Possible Security Threat Detected (SQL Injection)', ['value' => $sanitizedValue]);

                throw new Exception('Submission Quarantined.', 400);
            }
        }
    }

    /**
     * Normalise input by decoding, removing extra spaces and converting to lowercase
     * @param string $value
     * @return string
     */
    protected function normaliseInput(string $value): string
    {
        return preg_replace('/\s+/', ' ', strtolower(trim(self::fullyDecodeInput($value))));
    }

    /**
     * Fully decode input until no changes occur
     * @param $value
     * @return string
     */
    protected function fullyDecodeInput($value): string
    {
        $previous = null;
        while ($value !== $previous) {
            $previous = $value;

            // Decode URL-encoded characters
            $value = urldecode($value);

            // Decode HTML entities (e.g., &lt; becomes <)
            $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        return $value;
    }
}