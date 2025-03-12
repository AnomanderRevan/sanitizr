<?php

namespace AnomanderRevan\Sanitizr\Http\Middleware;

use AnomanderRevan\Sanitizr\Services\SanitizrService;
use Closure;
use Illuminate\Http\Request;

class AutoSan
{
    protected SanitizrService $sanitizr;

    public function __construct(SanitizrService $sanitizr)
    {
        $this->sanitizr = $sanitizr;
    }

    public function handle(Request $request, Closure $next, $rulesString = '')
    {
        $rules = $this->parseRules($rulesString);
        $data = $request->all();
        $sanitizedData = $this->sanitizr->sanitize($data, $rules);
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