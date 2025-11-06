<?php

namespace Ne0Heretic\FirewallBundle\EventListener;

use Ibexa\Contracts\Core\SiteAccess\ConfigResolverInterface;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Ne0Heretic\FirewallBundle\Lib\BotValidator;
use Symfony\Component\Cache\Adapter\RedisTagAwareAdapter;
use Symfony\Component\HttpFoundation\Request;
use Ne0Heretic\FirewallBundle\Lib\ChallengeService;

class KernelListener
{
    /** @var Container */
    protected $container;
    /** @var ConfigResolverInterface */
    protected $configResolver;
    /** @var BotValidator */
    protected $botValidator;
    /** @var RedisTagAwareAdapter */
    protected $cache;
    public static $startTime = null;
    public static $clientIp;
    public static $checkRateLimit = false;
    /** @var ChallengeService */
    protected $challengeService;

    public function __construct(
        Container $container,
        RedisTagAwareAdapter $cache,
        ConfigResolverInterface $configResolver
    )
    {
        $this->container    = $container;
        $this->configResolver = $configResolver;
        $this->cache = $cache;
        $this->challengeService = new ChallengeService($cache, $container->getParameter('kernel.cache_dir'));
        $this->botValidator = new BotValidator($cache, $this->challengeService);
        if(!self::$startTime ) {
            self::$startTime = microtime(true);
        }
        $request = Request::createFromGlobals();
        // Get the request IP (this uses Symfony's built-in logic, which respects trusted_proxies if configured)
        $ip = $request->getClientIp();

        // Get the forwarded IP (manual extraction if you need the raw X-Forwarded-For value or custom handling)
        $forwardedFor = $request->headers->get('X-Forwarded-For');
        $forwardedIp = null;
        if ($forwardedFor) {
            // X-Forwarded-For can contain multiple IPs (client, proxies); take the leftmost (original client)
            $ipList = explode(',', $forwardedFor);
            $forwardedIp = trim($ipList[0]);

            // Optional: Validate IP format (basic check)
            if (!filter_var($forwardedIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
                $forwardedIp = null; // Fallback to $ip if invalid
            }
        }

        // Use forwarded IP if available and valid, else fallback to direct client IP
        self::$clientIp = $forwardedIp ?: $ip;
    }

    /**
     * @param RequestEvent $event
     * @return bool
     */
    public function onKernelRequest(RequestEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }
        $request = $event->getRequest();
        $clientIp = self::$clientIp;
        $userAgent = $request->headers->get('User-Agent') ?? '';
        $path = $request->getPathInfo();

        // Early challenge verification: Headers or cookies
        $token = $request->headers->get('X-Challenge-Token') ?: ($_COOKIE['challengeToken'] ?? null);
        $challengeId = $request->headers->get('X-Challenge-Id') ?: ($_COOKIE['challengeId'] ?? null);
        if ($token && $challengeId && $this->challengeService->verifyChallenge($challengeId, $token, $clientIp)) {
            self::$checkRateLimit = true;
            // Challenge verified for IP: {$clientIp}
            // Optional: Clear cookies after verify (set new with TTL if needed)
            // In case we want to allow this IP to make further requests without cookies
            //setcookie('challengeToken', '', time() - 3600, '/', '', false, true); // SameSite=Strict
            //setcookie('challengeId', '', time() - 3600, '/', '', false, true);
            return true;
        }

        // Global ban check
        if ($this->botValidator->isBanned($clientIp)) {
            error_log("Globally banned bot IP: {$clientIp}");
            $response = new Response('Unauthorized bot access', 403);
            $response->setPrivate();
            $response->setSharedMaxAge(0);
            $event->setResponse($response);
            return false;
        }

        // Validate known bots (skip challenge for legit ones)
        if (stripos($userAgent, 'Googlebot') !== false) {
            $isValidGooglebot = $this->botValidator->validateGooglebot($clientIp);
            if (!$isValidGooglebot) {
                error_log("Fake Googlebot detected from IP: {$clientIp} with UA: $userAgent");
                $this->botValidator->banIpGlobally($clientIp);
                $response = new Response('Unauthorized bot access', 403);
                $response->setPrivate();
                $response->setSharedMaxAge(0);
                $event->setResponse($response);
                return false;
            }
            return true; // Legit bot: Proceed without challenge
        } else if (stripos($userAgent, 'Twitterbot') !== false) {
            $isValidTwitterbot = $this->botValidator->validateTwitterbot($clientIp);
            if (!$isValidTwitterbot) {
                error_log("Fake Twitterbot detected from IP: {$clientIp} with UA: $userAgent");
                $this->botValidator->banIpGlobally($clientIp);
                $response = new Response('Unauthorized bot access', 403);
                $response->setPrivate();
                $response->setSharedMaxAge(0);
                $event->setResponse($response);
                return false;
            }
            return true;
        } else if (stripos($userAgent, 'facebookexternalhit') !== false || stripos($userAgent, 'Facebot') !== false) {
            $isValidFacebookbot = $this->botValidator->validateFacebookbot($clientIp);
            if (!$isValidFacebookbot) {
                error_log("Fake Facebookbot detected from IP: {$clientIp} with UA: $userAgent");
                $this->botValidator->banIpGlobally($clientIp);
                $response = new Response('Unauthorized bot access', 403);
                $response->setPrivate();
                $response->setSharedMaxAge(0);
                $event->setResponse($response);
                return false;
            }
            return true;
        } else if (stripos($userAgent, 'bingbot') !== false || stripos($userAgent, 'BingPreview') !== false) {
            $isValidBingbot = $this->botValidator->validateBingbot($clientIp);
            if (!$isValidBingbot) {
                error_log("Fake Bingbot detected from IP: {$clientIp} with UA: $userAgent");
                $this->botValidator->banIpGlobally($clientIp);
                $response = new Response('Unauthorized bot access', 403);
                $response->setPrivate();
                $response->setSharedMaxAge(0);
                $event->setResponse($response);
                return false;
            }
            return true;
        } else if (stripos($userAgent, 'LinkedInBot') !== false) {
            $isValidLinkedInBot = $this->botValidator->validateLinkedInBot($clientIp);
            if (!$isValidLinkedInBot) {
                error_log("Fake LinkedInBot detected from IP: {$clientIp} with UA: $userAgent");
                $this->botValidator->banIpGlobally($clientIp);
                $response = new Response('Unauthorized bot access', 403);
                $response->setPrivate();
                $response->setSharedMaxAge(0);
                $event->setResponse($response);
                return false;
            }
            return true;
        } else {
            self::$checkRateLimit = true;
            // Proactive challenge for all non-bot traffic (if not verified)
            // if ($this->challengeService->isVerified($clientIp)) {
                // error_log("IP verified, proceeding: {$clientIp}"); // Debug
                // In case we want to allow this IP to make further requests without cookies
                // return true;
            // }

            // Optional: Exempt static assets (adjust paths for your Ibexa setup)
            if (strpos($path, '/media/') === 0 || strpos($path, '/assets/') === 0 || strpos($path, '.css') !== false || strpos($path, '.js') !== false || strpos($path, '.png') !== false || strpos($path, '.jpg') !== false) {
                return true; // Skip challenge for files
            }

            // Trigger challenge: Generate and short-circuit
            $challenge = $this->challengeService->generateChallenge();
            $this->challengeService->setPending($clientIp, $challenge['id']);
            $js = $this->challengeService->getJsTemplate($challenge['broken'], $challenge['method']);

            // Generate minimal challenge HTML
            $html = $this->getMinimalChallengeHtml($js, $request); // Inject broken as data-attr if needed

            $response = new Response($html, 200, [
                'Content-Type' => 'text/html; charset=UTF-8',
                'Cache-Control' => 'no-cache, no-store, must-revalidate',
            ]);
            $response->setPrivate();
            $response->setSharedMaxAge(0);
            $event->setResponse($response);
            error_log("Short-circuit challenge response for IP: {$clientIp}");
            return false; // Skip controller
        }

        return true;
    }

    /**
     * Helper to generate minimal HTML with JS injection.
     * Customize: Embed your site's head/body or redirect to challenge route.
     */
    private function getMinimalChallengeHtml(string $js, Request $request): string
    {
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Verifying...</title>
<meta http-equiv="refresh" content="5"> <!-- Fallback if JS fails -->
</head>
<body>
<p>One moment while we verify your browser...</p>
<script>{$js}</script>
</body>
</html>
HTML;
    }

    // Additional methods (e.g., for response events) can be added here as needed
    /**
     * @param FilterControllerEvent $event
     */
    public function onKernelController(ControllerEvent $event)
    {
        // TODO: implement other stuff
    }

    /**
     * @param ResponseEvent $event
     * @return bool
     */
    public function onKernelResponse(ResponseEvent $event)
    {
        if(!$event->isMasterRequest())
        {
            return;
        }
        // Rate limiting check: Block if exceeded
        $clientIp = self::$clientIp;
        $request = $event->getRequest();
        // Counting only requests that takes at least 0.1 seconds
        // Or requests that are not 2xx
        if (self::$checkRateLimit && ((int)($event->getResponse()->getStatusCode()/100) !== 2 || microtime(true) - self::$startTime > 0.1) && !$this->botValidator->checkRateLimit(self::$clientIp)) {
            error_log("Rate limit exceeded for IP: $clientIp");
            $response = new Response('Too Many Requests', 429);
            $response->setPrivate();
            $response->setSharedMaxAge(0);
            $event->setResponse($response);
            return false;
        }
    }
}
