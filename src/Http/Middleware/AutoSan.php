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

    public function handle(Request $request, Closure $next, array $rules = [])
    {
        $data = $request->all();
        $filters = $this->getFilters($rules);
        $sanitizedData = $this->sanitizr->sanitize($data, $filters);
        $request->merge($sanitizedData);

        return $next($request);
    }


    protected function getFilters(array $rules): array
    {
        $filters = [];

        if (!empty($rules)) {
            foreach ($rules as $rule) {
                if (config("sanitizr.rules.$rule")) {
                    $filters = array_merge($filters, config("sanitizr.rules.$rule"));
                }
            }
        }

        return $filters;
    }
}