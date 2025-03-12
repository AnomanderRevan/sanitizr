<?php

namespace AnomanderRevan\Sanitizr\Services;

use Illuminate\Support\Facades\Log;

class SanitizrService
{
    protected array $filters;

    public function __construct(array $filters = [])
    {
        $this->filters = $filters;
    }

    public function sanitize(array $data, array $filters): array
    {
        if (!empty($filters) && !empty($data)) {
            foreach ($filters as $filter) {
                if (isset($this->filters[$filter])) {
                    if (is_callable($this->filters[$filter])) {
                        foreach ($data as $key => $value) {
                            $data[$key] = call_user_func($this->filters[$filter], $value);
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
}