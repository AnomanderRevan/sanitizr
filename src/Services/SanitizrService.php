<?php

namespace AnomanderRevan\Sanitizr\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;

class SanitizrService
{
    protected array $filters;
    protected array $fieldRules;
    protected array $globalRules;

    public function __construct()
    {
        $this->filters = Config::get('sanitizr.filters', []);
        $this->fieldRules = Config::get('sanitizr.rules.field', []);
        $this->globalRules = Config::get('sanitizr.rules.global', []);
    }

    /**
     * Sanitize data using filter functions from config
     * @param array $data
     * @param string|null $rule
     * @return array
     */
    public function sanitize(array $data, string $rule = null): array
    {
        $globalFilters = $rule && isset($this->globalRules[$rule]) ? $this->globalRules[$rule] : [];

        foreach ($data as $field => $value) {
            // Merge global filters with field-specific ones
            $filters = $globalFilters;
            if (isset($this->fieldRules[$field])) {
                $filters = array_merge($filters, $this->fieldRules[$field]);
            }

            $data[$field] = $this->sanitizeValue($value, $filters);
        }

        return $data;
    }

    public function sanitizeValue($value, array $filters)
    {
        foreach ($filters as $filter) {
            if (isset($this->filters[$filter]) && is_callable($this->filters[$filter])) {
                $value = call_user_func($this->filters[$filter], $value);
            } else {
                Log::error("Filter '$filter' is not defined or not callable");
            }
        }

        return $value;
    }

    /**
     * Check if security checks should be run
     * @return bool
     */
    public function canRunSecurityChecks(): bool
    {
        return Config::get('sanitize.run_security_checks', false);
    }

}