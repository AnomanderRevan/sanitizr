<?php

/**
 * This file contains the configuration for the Sanitizr package.
 * The configuration file contains the filters that will be used to sanitize the data.
 * The filters are grouped into rules that can be applied to the data.
 */

use Illuminate\Support\Facades\Log;

return [

    //Group the filters into rules that can be applied to the data
    //Rules applied to entire $request
    'rules' => [
        'api' => ['trim', 'strip_tags', 'sql_check'],
        'database' => [ 'trim', 'add_slashes' ],
        'form' => [ 'xss_check', 'sql_check'],
        'security' => [ 'cmd_check', 'xss_check', 'sql_check' ],
    ],

    //Rules applied to individual fields with matching name
    'field_rules' => [
        'first_name' => ['lowercase', 'ucfirst'],
        'email' => [ 'remove_whitespace', 'sanitize_email' ],
        'url' => [ 'sanitize_url' ],
    ],

    //Define the filters that will be used to sanitize the data
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

        //Command injection detection
        'cmd_check' => function ($value) {
            if (preg_match('/(;|\||&&|`|<\?|base64|cmd|exec|system|-rm|%3B)/i', $value)) {
                // Sanitize the value before logging
                $sanitizedValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');

                // Log the incident with sanitized value
                Log::warning('Sanitizr: Possible Security Threat Detected (Command Injection)', ['value' => $sanitizedValue]);

                return false;
            }

            return true;
        },

        // XSS detection
        'xss_check' => function($value) {
            if (str_contains(strtolower($value), '<script>')) {
                // Sanitize the value before logging
                $sanitizedValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');

                // Log the incident with sanitized value
                Log::warning('Sanitizr: Possible Security Threat Detected (XSS)', ['value' => $sanitizedValue]);

                // Return a safe response
                return 'Submission Quarantined.';
            } else {
                return $value;
            }
        },

        // SQL Injection detection
        'sql_check' => function($value) {
            // Define a regex pattern to detect SQL keywords in malicious contexts
            $pattern = '/(?:^|;)\s*(drop\s+table|truncate\s+table|delete\s+from|insert\s+into|select\s+.*?from|update\s+\w+\s+set|union\s+select|alter\s+table|create\s+table|exec\s+\w+)/i';

            // Check if the value triggers the regex pattern
            if (preg_match($pattern, $value)) {
                // Sanitize the value before logging
                $sanitizedValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');

                // Log the incident with sanitized value
                Log::warning('Sanitizr: Possible Security Threat Detected (SQL Injection)', ['value' => $sanitizedValue]);

                // Return a safe response
                return 'Submission Quarantined.';
            } else {
                return $value;
            }
        },
    ],


];
