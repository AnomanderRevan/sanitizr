<?php

namespace AnomanderRevan\Sanitizr\Tests\Unit;

use AnomanderRevan\Sanitizr\Http\Middleware\AutoSan;
use AnomanderRevan\Sanitizr\Services\SanitizrService;
use AnomanderRevan\Sanitizr\Tests\TestCase;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

class AutoSanMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::post('/test-form', function (\Illuminate\Http\Request $request) {
            return response()->json(['sanitized' => $request->all()]);
        })->middleware(AutoSan::class . ':form');

        Route::post('/test-api', function (\Illuminate\Http\Request $request) {
            return response()->json($request->all());
        })->middleware(AutoSan::class . ':security');
    }

    public function test_it_blocks_sql_injection()
    {
        $request = [ 'search' => '1; DROP TABLE users; --' ];
        $response = $this->postJson('/test-api', $request);
        $response->assertBadRequest()->assertJson(['error' => 'Submission Quarantined. Contact Support.']);

    }

    public function test_it_passes_through_clean_url_and_data()
    {
        $request = [ 'name' => 'Jane'];
        $response = $this->postJson('/test-api?query=help', $request);
        $response->assertOk()->assertJson(['message' => 'OK']);
    }

    public function test_it_sanitizes_request_data()
    {
        $response = $this->postJson('/test-form', [
            'name' => '  John  ',
            'email' => '  JOHN@EMAIL.COM ',
        ]);

        $response->assertOk()
            ->assertJson(['sanitized' => ['name' => 'John', 'email' => 'john@email.com']]);
    }


    public function test_it_sanitizes_field_rule_data()
    {
        $request = [
            'first_name' => ' jOhN  ',
            'last_name' => '  dOe',
            'email' => '  JOHN@EMAIL.COM ',
            'mobile' => '  (+353)83-0326776  ',
            'address' => '  <strong>123 FaKe St. dUbLiN iReLaNd</strong>',
        ];
        $response = $this->postJson('/test-form', $request);

        $response->assertOk()
            ->assertJson(['sanitized' => [
                'first_name' => 'John',
                'last_name' => 'Doe',
                'email' => 'john@email.com',
                'mobile' => '00353830326776',
                'address' => '123 FaKe St. dUbLiN iReLaNd',
            ]]);
    }

    public function test_it_blocks_malicious_cmd_in_url()
    {
        $this->withoutExceptionHandling();

        $this->expectException(Exception::class);

        $this->post('/test-api?query=' . urldecode('&&rm -rf /'), [
            'name' => 'Alice',
        ]);
    }

    public function test_it_logs_exception_and_returns_error()
    {
        Log::shouldReceive('error')->once();

        $mock = \Mockery::mock(SanitizrService::class);
        $mock->shouldReceive('urlCmdCheckEnabled')->andReturn(true);
        $mock->shouldReceive('sanitizeValue')->andThrow(new Exception('Test Exception'));

        $middleware = new AutoSan($mock);

        $request = Request::create('/test-form', 'POST', ['name' => 'test']);

        $response = $middleware->handle($request, fn () => response()->json(['message' => 'Should not reach']), 'form');

        $this->assertEquals(400, $response->status());
        $this->assertEquals(['error' => 'Test Exception'], $response->getOriginalContent());
    }
    
}