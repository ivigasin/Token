<?php


namespace Vigasin\JWTBundle\Security\Core;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;
use Symfony\Component\Security\Core\User\UserInterface;
use Vigasin\JWTBundle\JWT\JWT;

class Provider implements AuthenticationProviderInterface {

    protected $userProvider;
    protected $jwt;
    protected $userIdentityField;

    public function __construct(UserProviderInterface $userProvider, JWT $jwt) {
        if(empty($providerKey))
        {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }
        $this->userProvider = $userProvider;
        $this->jwt = $jwt;
    }

    public function authenticate(TokenInterface $token) {

        $payload = $this->jwt->decode($token);

        $user = $this->getUserFromPayload($payload);
        $authToken = new JWTUSerToken($user->getRoles());
        $authToken->setUser($user);

        return $authToken;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof JWTUserToken;
    }


    protected function getUserFromPayload(array $payload)
    {
        if (!isset($payload[$this->userIdentityField])) {
            throw new AuthenticationException('Invalid JWT Token');
        }
        return $this->userProvider->loadUserByUsername($payload[$this->userIdentityField]);
    }

    public function getUserIdentityField()
    {
        return $this->userIdentityField;
    }

    public function setUserIdentityField($userIdentityField)
    {
        $this->userIdentityField = $userIdentityField;
    }
}