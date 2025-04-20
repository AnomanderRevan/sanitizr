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

    /**
     * Handle an incoming request.
     * @param Request $request
     * @param Closure $next
     * @param string|null $rule
     * @return mixed
     */
    public function handle(Request $request, Closure $next, string $rule = null): mixed
    {
        $data = $request->all();
        $filters = $this->getFilters($rule);
        $sanitizedData = $this->sanitizr->sanitize($data, $filters);

        //Check URL for possible security threats
        $path = $request->path();
        $query = $request->getQueryString();

        if (!$this->sanitizr->sanitize([$path, $query], ['cmd_check'])) {
            // Log the incident
            Log::warning('SANITIZR: User request blocked due to possible security threat', [
                'user_ip' => $request->ip(),
                'timestamp' => now(),
            ]);

            // Return an error response
            return response()->json(['error' => 'Submission Quarantined. Please contact support.'], 400);

        }

        //Check for quarantined data
        if (in_array('Submission Quarantined.', $sanitizedData, true)) {
            // Log the incident
            Log::warning('SANITIZR: User request blocked due to possible security threat', [
                'user_ip' => $request->ip(),
                'timestamp' => now(),
            ]);

            // Return an error response
            return response()->json(['error' => 'Submission Quarantined. Please contact support.'], 400);
        }

        $request->merge($sanitizedData);

        return $next($request);
    }

    /**
     * Get filters from config for a given rule
     * @param string $rule
     * @return array
     */
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