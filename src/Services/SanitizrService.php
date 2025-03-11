<?php

namespace Anomander\Sanitizr\Services;

class SanitizrService
{
    protected array $filters;

    public function __construct(array $filters = [])
    {
        $this->filters = $filters;
    }

    public function sanitize(array $data, array $rules): array
    {
        foreach ($rules as $field => $fieldFilters) {
            if (isset($data[$field])) {
                foreach ($fieldFilters as $filter) {
                    if (isset($this->filters[$filter])) {
                        $data[$field] = call_user_func($this->filters[$filter], $data[$field]);
                    }
                }
            }
        }

        return $data;
    }
}