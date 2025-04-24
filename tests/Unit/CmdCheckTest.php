<?php

namespace AnomanderRevan\Sanitizr\Tests\Unit;


namespace AnomanderRevan\Sanitizr\Tests\Unit;

use AnomanderRevan\Sanitizr\Services\SanitizrService;
use AnomanderRevan\Sanitizr\Tests\TestCase;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class CmdCheckTest extends TestCase
{
    protected SanitizrService $sanitizr;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sanitizr = new SanitizrService();
    }

    public function test_it_allows_ampersand_in_url(): void
    {
        $input = ['message' => 'www.google.com/api?example=true&sort=asc'];
        $filters = ['cmd_check'];

        $output = $this->sanitizr->sanitize($input, $filters);

        $this->assertSame($input, $output);
    }

    public function test_it_allows_safe_use_of_cmd_in_text()
    {
        $input = ['message' => 'This is the Windows CMD documentation page.'];
        $filters = ['cmd_check'];

        $output = $this->sanitizr->sanitize($input, $filters);

        $this->assertSame($input, $output);
    }

    public function test_it_blocks_basic_shell_command()
    {
        $this->expectException(Exception::class);

        $input = ['url' => 'ls -la'];
        $filters = ['cmd_check'];

        $this->sanitizr->sanitize($input, $filters);
    }

    public function test_it_blocks_semicolon_command_separator()
    {
        $this->expectException(Exception::class);

        $input = ['url' => 'cat /etc/passwd; whoami'];
        $filters = ['cmd_check'];

        $this->sanitizr->sanitize($input, $filters);
    }

    public function test_it_blocks_double_ampersand_chain()
    {
        $this->expectException(Exception::class);

        $input = ['url' => 'ping 127.0.0.1 && rm -rf /'];
        $filters = ['cmd_check'];

        $this->sanitizr->sanitize($input, $filters);
    }

    public function test_it_blocks_pipe_operator()
    {
        $this->expectException(Exception::class);

        $input = ['url' => 'cat test.txt | grep password'];
        $filters = ['cmd_check'];

        $this->sanitizr->sanitize($input, $filters);
    }

    public function test_it_blocks_url_encoded_command()
    {
        $this->expectException(Exception::class);

        $input = ['url' => 'rm%20-rf%20/'];
        $filters = ['cmd_check'];

        $this->sanitizr->sanitize($input, $filters);
    }

    public function test_it_blocks_base64_shell_execution()
    {
        $this->expectException(Exception::class);

        $input = ['url' => 'echo c3lzdGVtKCJ3aG9hbWkiKQ== | base64 -d | bash'];
        $filters = ['cmd_check'];

        $this->sanitizr->sanitize($input, $filters);
    }

    public function test_it_blocks_exec_function()
    {
        $this->expectException(Exception::class);

        $input = ['url' => 'exec("whoami")'];
        $filters = ['cmd_check'];

        $this->sanitizr->sanitize($input, $filters);
    }

    public function test_it_blocks_backtick_execution()
    {
        $this->expectException(Exception::class);

        $input = ['url' => '`ls -la`'];
        $filters = ['cmd_check'];

        $this->sanitizr->sanitize($input, $filters);
    }

}