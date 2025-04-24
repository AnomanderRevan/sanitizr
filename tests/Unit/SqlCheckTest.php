<?php

namespace AnomanderRevan\Sanitizr\Tests\Unit;

use AnomanderRevan\Sanitizr\Services\SanitizrService;
use AnomanderRevan\Sanitizr\Tests\TestCase;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class SqlCheckTest extends TestCase
{
    protected SanitizrService $sanitizr;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sanitizr = new SanitizrService();
    }

    public function test_it_allows_clean_input(): void
    {
        $input = 'Hello world';
        $filters = ['sql_check'];

        $output = $this->sanitizr->sanitizeValue($input, $filters);

        $this->assertSame($input, $output);
    }

    public function test_it_allows_sql_keywords_in_legitimate_contexts()
    {
        $input = "This is a dropdown select option.";
        $filters = ['sql_check'];

        $output = $this->sanitizr->sanitizeValue($input, $filters);

        $this->assertSame($input, $output);
    }

    public function test_it_blocks_basic_sql_statements()
    {
        $this->expectException(Exception::class);

        $input = "DROP TABLE users;";
        $filters = ['sql_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_chained_sql_queries()
    {
        $this->expectException(Exception::class);

        $input = "admin'; DROP TABLE users; --";
        $filters = ['sql_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_html_encoded_sql_injection()
    {
        $this->expectException(Exception::class);

        $input = "&lt;script&gt;DROP TABLE users&lt;/script&gt;;";
        $filters = ['sql_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_url_encoded_sql_injection()
    {
        $this->expectException(Exception::class);

        $input = "SELECT%20*%20FROM%20users%20WHERE%201=1";
        $filters = ['sql_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_union_select_attacks()
    {
        $this->expectException(Exception::class);

        $input = "UNION SELECT username, password FROM users";
        $filters = ['sql_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }

    public function test_it_blocks_obfuscated_keywords()
    {
        $this->expectException(Exception::class);

        $input = "D%52OP TABLE users"; // R is %52
        $filters = ['sql_check'];

        $this->sanitizr->sanitizeValue($input, $filters);
    }
}