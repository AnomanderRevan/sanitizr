<?php

namespace Anomander\Sanitizr\Http\Middleware;

use Anomander\Sanitizr\Services\Sanitizer;
use Closure;
use Illuminate\Http\Request;

class AutoSan
{
    protected Sanitizer $sanitizer;

    public function __construct(Sanitizer $sanitizer)
    {
        $this->sanitizer = $sanitizer;
    }

    public function handle(Request $request, Closure $next, $rulesString = '')
    {
        $rules = $this->parseRules($rulesString);
        $data = $request->all();
        $sanitizedData = $this->sanitizer->sanitize($data, $rules);
        $request->merge($sanitizedData);

        return $next($request);
    }

    protected function parseRules($rulesString): array
    {
        $rules = [];
        $fields = explode(';', $rulesString);

        foreach ($fields as $field) {
            list($fieldName, $fieldRules) = explode(',', $field);
            $rules[$fieldName] = $this->getFilters($fieldRules);
        }

        return $rules;
    }

    protected function getFilters($fieldRules): array
    {
        $filters = [];
        $rules = explode('|', $fieldRules);

        foreach ($rules as $rule) {
            if (config("sanitizr.rules.$rule")) {
                $filters = array_merge($filters, config("sanitizr.rules.$rule"));
            } else {
                $filters[] = $rule;
            }
        }

        return $filters;
    }
}