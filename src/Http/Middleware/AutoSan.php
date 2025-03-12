<?php

namespace AnomanderRevan\Sanitizr\Http\Middleware;

use AnomanderRevan\Sanitizr\Services\SanitizrService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class AutoSan
{
    protected SanitizrService $sanitizr;

    public function __construct(SanitizrService $sanitizr)
    {
        $this->sanitizr = $sanitizr;
    }

    public function handle(Request $request, Closure $next, string $rule = null)
    {
        $data = $request->all();
        $filters = $this->getFilters($rule);
        $sanitizedData = $this->sanitizr->sanitize($data, $filters);
        $request->merge($sanitizedData);

        return $next($request);
    }


    protected function getFilters(string $rule): array
    {
        $filters = [];

        if ($rule) {
            if (config("sanitizr.rules.$rule")) {
                $filters = array_merge($filters, config("sanitizr.rules.$rule"));
            } else {
                Log::error("Rule '$rule' is not defined");
            }
        }

        return $filters;
    }
}