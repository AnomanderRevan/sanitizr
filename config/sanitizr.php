<?php

/**
 * This file contains the configuration for the Sanitizr package.
 * The configuration file contains the filters that will be used to sanitize the data.
 * The filters are grouped into rules that can be applied to the data.
 */

use Illuminate\Support\Facades\Log;

return [
    'run_check_on_url' => true,

    //Define the fields that will be excluded from sanitization
    'excluded_fields' => [
        'csrf_token',
        'username',
        'password',
        'password_confirmation',
    ],

    //Define the rules that will be used to sanitize the data
    'rules' => [
        //Rules applied to entire $request
        'global' => [
            'api' => ['escape_html'],
            'form' => [ 'strip_tags'],
            'security' => [ 'xss_check', 'sql_check', 'cmd_check' ],
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

    //Define the filters that will be used to sanitize request data
    'filters' => [
        'trim' => function ($value) { return trim($value); },
        'escape_html' => function($value) { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); },
        'strip_tags' => function($value) { return strip_tags($value); },
        'lowercase' => function($value) { return strtolower($value); },
        'uppercase' => function($value) { return strtoupper($value); },
        'ucfirst' => function($value) { return ucfirst($value); },
        'lcfirst' => function($value) { return lcfirst($value); },
        'ucwords' => function($value) { return ucwords($value); },
        'capitalize' => function($value) { return mb_convert_case($value, MB_CASE_TITLE, "UTF-8"); },
        'base64_encode' => function($value) { return base64_encode($value); },
        'base64_decode' => function($value) { return base64_decode($value); },
        'json_encode' => function($value) { return json_encode($value); },
        'json_decode' => function($value) { return json_decode($value); },
        'safe_json_encode' => function($value) { return json_encode($value, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); },
        'remove_whitespace' => function($value) { return preg_replace('/\s+/', '', $value); },
        'remove_numbers' => function($value) { return preg_replace('/[0-9]/', '', $value); },
        'remove_special_chars' => function($value) { return preg_replace('/[^A-Za-z0-9]/', '', $value); },
        'int' => function($value) { return (int) $value; },
        'float' => function($value) { return (float) $value; },
        'bool' => function($value) { return (bool) $value; },
        'sanitize_email' => function($value) { return filter_var($value, FILTER_SANITIZE_EMAIL); },
        'sanitize_url' => function($value) { return filter_var($value, FILTER_SANITIZE_URL); },
        'alpha' => function($value) { return preg_replace('/[^A-Za-z]/', '', $value); },
        'alpha_num' => function($value) { return preg_replace('/[^A-Za-z0-9]/', '', $value); },
        'numeric' => function($value) { return preg_replace('/[^0-9]/', '', $value); },
        'escape_shell_cmd' => function($value) { return escapeshellcmd($value); },
        'escape_shell_arg' => function($value) { return escapeshellarg($value); },
        'real_path' => function($value) { return realpath($value); },
        'base_name' => function($value) { return basename($value); },
        'add_slashes' => function($value) { return addslashes($value); },
        'crlf_clean' => function($value) { return str_replace(["\r", "\n"], '', $value); },
        'phone_plus_replace' => function($value) { return preg_replace('/^\+/', '00', $value); },

        //Command injection detection
        'cmd_check' => function ($value) {
            $previous = null;
            $maxIterations = 5;
            $i = 0;
            $normalisedValue = $value;

            while ($normalisedValue !== $previous && $i++ < $maxIterations) {
                $previous = $normalisedValue;
                $normalisedValue = urldecode($normalisedValue);
                $normalisedValue = html_entity_decode($normalisedValue, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }

            $normalisedValue = preg_replace('/\s+/', '', strtolower(trim($normalisedValue)));

            // Unescape escaped shell characters
            $normalisedValue = preg_replace('/\\\\([;&|`])/', '$1', $normalisedValue);

            // Command injection pattern
            $pattern = '/(;|\||&&|-rf|-l|`|<\?|'
                . '\b(cmd|exec|system|sh|bash|zsh|powershell|base64|wget|curl|scp|ftp|python|perl|ruby)\b'
                . '(?!\s*(\=|\&|\||;|`|\s*\/|\s*\-|\s*\;)))/i';

            if (preg_match($pattern, $normalisedValue)) {
                $sanitizedValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
                Log::warning('SANITIZR: Possible Security Threat Detected (Command Injection)', ['value' => $sanitizedValue]);
                throw new Exception('Submission Quarantined. Contact Support.', 400);
            }
            return $value;
        },

        // XSS detection
        'xss_check' => function($value) {
            $previous = null;
            $maxIterations = 5;
            $i = 0;
            $normalisedValue = $value;

            while ($normalisedValue !== $previous && $i++ < $maxIterations) {
                $previous = $normalisedValue;
                $normalisedValue = urldecode($normalisedValue);
                $normalisedValue = html_entity_decode($normalisedValue, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }

            $normalisedValue = preg_replace('/\s+/', '', strtolower(trim($normalisedValue)));

            $patterns = [
                // Script tags (obfuscated, encoded, or broken up)
                '/<\s*script.*?>.*?<\s*\/\s*script\s*>/is',
                '/&#x[0-9a-f]+;/i',
                '/<\s*\/?\s*script\s*>/i',

                // Event handlers and javascript URLs
                '/on\w+\s*=\s*["\']?[^"\']*["\']?/i',
                '/javascript\s*:/i',
                '/data\s*:[^;]*;base64,/i',

                // Suspicious tags
                '/<\s*(iframe|svg|math|embed|object|meta|link|base)[^>]*>/i',

                // CSS expression
                '/expression\s*\(/i',
            ];
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $normalisedValue)) {
                    $sanitized = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
                    Log::warning('SANITIZR: Possible Security Threat Detected (XSS)', ['value' => $sanitized]);
                    throw new \Exception('Submission Quarantined. Contact Support.', 400);
                }
            }

            return $value;
        },

        // SQL Injection detection
        'sql_check' => function($value) {
            $previous = null;
            $maxIterations = 5;
            $i = 0;
            $normalisedValue = $value;

            while ($normalisedValue !== $previous && $i++ < $maxIterations) {
                $previous = $normalisedValue;
                $normalisedValue = urldecode($normalisedValue);
                $normalisedValue = html_entity_decode($normalisedValue, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }

            $normalisedValue = preg_replace('/\s+/', ' ', strtolower(trim($normalisedValue)));

            // Define a regex pattern to detect SQL keywords in malicious contexts
            $pattern = '/\b(drop\s+table|truncate\s+table|delete\s+from|insert\s+into|select\s+[^;]*from|update\s+\w+\s+set|union\s+select|alter\s+table|create\s+table|exec\s+\w+)\b/i';

            // Check if the value triggers the regex pattern
            if (preg_match($pattern, $normalisedValue)) {
                // Sanitize the value before logging
                $sanitizedValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');

                // Log the incident with sanitized value
                Log::warning('SANITIZR: Possible Security Threat Detected (SQL Injection)', ['value' => $sanitizedValue]);

                throw new Exception('Submission Quarantined. Contact Support.', 400);
            } else {
                return $value;
            }
        },
    ],


];
