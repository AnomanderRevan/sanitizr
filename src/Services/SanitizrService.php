<?php

namespace AnomanderRevan\Sanitizr\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;

class SanitizrService
{
    protected array $filters;
    protected array $fieldRules;
    protected array $globalRules;
    protected array $excludedFields;

    public function __construct()
    {
        $this->filters = Config::get('sanitizr.filters', []);
        $this->fieldRules = Config::get('sanitizr.rules.field', []);
        $this->globalRules = Config::get('sanitizr.rules.global', []);
        $this->excludedFields = Config::get('sanitizr.excluded_fields', []);
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
            // Skip excluded fields
            if (in_array($field, $this->excludedFields)) {
                continue;
            }else if (is_object($value)) {
                Log::warning("Cannot sanitize object values directly. Consider converting to an array.");
                continue;
            }

            // Merge global filters with field-specific ones
            $filters = $globalFilters;
            if (isset($this->fieldRules[$field])) {
                $filters = array_merge($filters, $this->fieldRules[$field]);
            }

            if (is_array($value)) {
                // If the value is an array, sanitize each element
                foreach ($value as $key => $val) {
                    if (is_array($val)) {
                        // Recursively sanitize nested arrays
                        $data[$field][$key] = $this->sanitize($val, $rule);
                    } else {
                        // Sanitize the value
                        if (isset($this->fieldRules[$key])) {
                            $filters = array_merge($filters, $this->fieldRules[$key]);
                        }
                        $data[$field][$key] = $this->sanitizeValue($val, $filters);
                    }
                }
            }

            $data[$field] = $this->sanitizeValue($value, $filters);
        }

        return $data;
    }

    /**
     * @param $value
     * @param array $filters
     * @return mixed|null
     */
    public function sanitizeValue($value, array $filters): mixed
    {
        if (is_null($value)) {
            return null;
        }

        foreach ($filters as $filter) {
            if (isset($this->filters[$filter]) && is_callable($this->filters[$filter])) {
                if (is_array($value)) {
                    foreach ($value as $key => $val) {
                        $value[$key] = call_user_func($this->filters[$filter], $val);
                    }
                } else {
                    $value = call_user_func($this->filters[$filter], $value);
                }
            } else {
                Log::error("Filter '$filter' is not defined or not callable");
            }
        }

        return $value;
    }

    /**
     * Check if security checks should be run on url
     * @return bool
     */
    public function urlCmdCheckEnabled(): bool
    {
        return Config::get('sanitize.run_cmd_check_on_url', false);
    }

}