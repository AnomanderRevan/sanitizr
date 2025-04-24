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
        $input = '  <b>Bob</b> ';

        $filters = ['trim', 'strip_tags'];

        $expected = 'Bob';

        $output = $this->sanitizr->sanitizeValue($input, $filters);

        $this->assertEquals($expected, $output);
    }

    public function test_it_skips_non_callable_filters_and_logs()
    {
        $output = $this->sanitizr->sanitize(['field' => ' test '], 'invalid_rule');

        $this->assertEquals(['field' => ' test '], $output);
    }

    public function test_it_handles_no_data_gracefully()
    {
        $output = $this->sanitizr->sanitize([], 'api');

        $this->assertSame([], $output);
    }

    public function test_it_can_run_security_checks_on_url()
    {
        Config::set('sanitize.run_cmd_check_on_url', true);

        $this->assertTrue($this->sanitizr->urlCmdCheckEnabled());
    }

    public function test_it_does_not_run_security_checks_on_url()
    {
        Config::set('sanitize.run_cmd_check_on_url', false);

        $this->assertFalse($this->sanitizr->urlCmdCheckEnabled());
    }



}