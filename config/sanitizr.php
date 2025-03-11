<?php

return [

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
    ],

    //Group the filters into rules that can be applied to the data
    'rules' => [
        'default' => [ 'trim' ],
        'api' => [ 'trim', 'escape_html', 'strip_tags' ],
        'form' => [ 'trim', 'strip_tags'],
        'database' => [ 'trim', 'add_slashes' ],
    ]


];
