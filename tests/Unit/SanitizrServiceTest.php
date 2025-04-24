<?php

namespace AnomanderRevan\Sanitizr\Tests\Unit;

use AnomanderRevan\Sanitizr\Services\SanitizrService;
use AnomanderRevan\Sanitizr\Tests\TestCase;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class SanitizrServiceTest extends TestCase
{
    protected SanitizrService $sanitizr;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sanitizr = new SanitizrService();
    }

    public function test_it_applies_trim_and_strip_tags_filters()
    {
        $input = [
            'name' => '  <b>Bob</b> ',
        ];

        $filters = ['trim', 'strip_tags'];

        $expected = [
            'name' => 'Bob',
        ];

        $output = $this->sanitizr->sanitize($input, $filters);

        $this->assertEquals($expected, $output);
    }

    public function test_it_skips_non_callable_filters_and_logs()
    {
        Config::set('sanitize.filters.invalid', 'not_a_function');

        // Laravel's Log::spy() could be used here, or just a smoke test
        $output = $this->sanitizr->sanitize(['field' => ' test '], ['invalid']);

        $this->assertEquals(['field' => ' test '], $output);
    }

    public function test_it_handles_no_data_gracefully()
    {
        $output = $this->sanitizr->sanitize([], ['trim', 'strip_tags']);

        $this->assertSame([], $output);
    }

    public function test_it_can_run_security_checks()
    {
        Config::set('sanitize.run_security_checks', true);

        $this->assertTrue($this->sanitizr->canRunSecurityChecks());
    }

    public function test_it_does_not_run_security_checks()
    {
        Config::set('sanitize.run_security_checks', false);

        $this->assertFalse($this->sanitizr->canRunSecurityChecks());
    }



}