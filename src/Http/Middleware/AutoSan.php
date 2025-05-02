<?php

namespace AnomanderRevan\Sanitizr\Http\Middleware;

use AnomanderRevan\Sanitizr\Services\SanitizrService;
use Closure;
use Exception;
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
        try {
            if ($this->sanitizr->urlCheckEnabled()) {
                $fullUrl = $request->fullUrl();
                $this->sanitizr->sanitize(['url' => $fullUrl], 'security');
            }
            $data = $request->all();
            $sanitizedData = $this->sanitizr->sanitize($data, $rule);
            $request->merge($sanitizedData);
        } catch (Exception $exception) {
            Log::error('SANITIZR: Exception caught during sanitization', [
                'user_ip' => $request->ip(),
                'timestamp' => now(),
                'exception' => $exception->getMessage(),
            ]);

            return response()->json(['error' => $exception->getMessage()], 400);
        }

        return $next($request);
    }
}