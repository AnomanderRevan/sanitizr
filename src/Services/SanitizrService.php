<?php

namespace AnomanderRevan\Sanitizr\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;

class SanitizrService
{
    protected array $configFilters;

    public function __construct()
    {
        $this->configFilters = Config::get('sanitize.filters', []);
    }

    /**
     * Sanitize data using filter functions from config
     * @param array $data
     * @param array $filters
     * @return array
     */
    public function sanitize(array $data, array $filters): array
    {
        if (!empty($filters) && !empty($data)) {
            foreach ($filters as $filter) {
                if (isset($this->configFilters[$filter])) {
                    if (is_callable($this->configFilters[$filter])) {
                        foreach ($data as $key => $value) {
                            $data[$key] = call_user_func($this->configFilters[$filter], $value);
                        }
                    } else {
                        Log::error("Filter '$filter' is not callable");
                    }
                } else {
                    Log::error("Filter '$filter' is not defined");
                }
            }
        }

        return $data;
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