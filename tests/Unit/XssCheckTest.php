<?php

namespace AnomanderRevan\Sanitizr\Tests\Unit;

use AnomanderRevan\Sanitizr\Services\SanitizrService;
use AnomanderRevan\Sanitizr\Tests\TestCase;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class XssCheckTest extends TestCase
{
    protected SanitizrService $sanitizr;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sanitizr = new SanitizrService();
    }

    public function test_it_allows_non_malicious_use_of_key_words(): void
    {
        $input = 'I have written an online script that does not contain any malicious code. It uses javascript and base64 encoding, but it is not harmful.';
        $filters = ['xss_check'];

        $output = $this->sanitizr->sanitizeValue($input, $filters);

        $this->assertSame($input, $output);
    }

    public function test_it_allows_safe_html()
    {
        $input = '<strong>Hello world</strong>';
        $filters = ['xss_check'];

        $output = $this->sanitizr->sanitizeValue($input, $filters);

        $this->assertSame($input, $output);
    }

    public function test_it_blocks_basic_script_tag()
    {
        $this->expectException(Exception::class);

        $input = '<script>alert("XSS")</script>';
        $filters = ['xss_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_html_encoded_script_tag()
    {
        $this->expectException(Exception::class);

        $input = '&lt;script&gt;alert("XSS")&lt;/script&gt;';
        $filters = ['xss_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_url_encoded_script_tag()
    {
        $this->expectException(Exception::class);

        $input = '%3Cscript%3Ealert("XSS")%3C%2Fscript%3E';
        $filters = ['xss_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_event_handlers()
    {
        $this->expectException(Exception::class);

        $input = '<img src="x" onerror="alert(\'XSS\')">';
        $filters = ['xss_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_javascript_urls()
    {
        $this->expectException(Exception::class);

        $input = '<a href="javascript:alert(1)">click me</a>';
        $filters = ['xss_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_obfuscated_script()
    {
        $this->expectException(Exception::class);

        $input = '<scr<script>ipt>alert(1)</script>';
        $filters = ['xss_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_base64_encoded_xss()
    {
        $this->expectException(Exception::class);

        $input = 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==';
        $filters = ['xss_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_svg_with_script()
    {
        $this->expectException(Exception::class);

        $input = '<svg><script>alert("XSS")</script></svg>';
        $filters = ['xss_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }
}