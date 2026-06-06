<?php

namespace Amtgard\IdP\Models;

use Amtgard\ActiveRecordOrm\Interface\EntityInterface;
use Amtgard\IdP\Persistence\Common\Repositories\JwtChallenge;
use Amtgard\IdP\Persistence\Common\Repositories\UserPolicy;
use Firebase\JWT\JWT;

class AmtgardIdpJwt
{
    private UserPolicy $userPolicy;
    private JwtChallenge $jwtChallenge;

    public function __construct(UserPolicy $userPolicy, JwtChallenge $jwtChallenge) {
        $this->userPolicy = $userPolicy;
        $this->jwtChallenge = $jwtChallenge;
    }

    public function buildAuthorizationJwt(EntityInterface $user): string {
        $policyJson = $this->userPolicy->getUserPolicy($user)->toJson();
        $challenge = $this->jwtChallenge->createChallenge($user);
        $privateKey = file_get_contents($_ENV['OAUTH_PRIVATE_KEY']);
        
        return JWT::encode([
            'aud' => $_SESSION['client_id'],
            'iat' => time(),
            'sub' => $user->userId,
            'iss' => "https://idp.amtgard.com",
            'orkid' => $user->orkUserId,
            'orkuser' => $user->username,
            'email' => $user->email,
            'policy' => $policyJson,
            'challenge' => $challenge,
            'exp' => time() + 3600
        ], $privateKey, 'RS256');
    }

    public function validateJwtChallenge(string $jwt): bool {
        return $this->jwtChallenge->validateChallenge($jwt);
    }
}