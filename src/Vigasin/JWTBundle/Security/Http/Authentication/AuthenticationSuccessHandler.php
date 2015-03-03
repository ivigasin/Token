<?php


namespace Vigasin\JWTBundle\Security\Http\Authentication;


use Vigasin\JWTBundle\JWT\JWT;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

class AuthenticationSuccessHandler implements AuthenticationSuccessHandlerInterface{
    /**
     * @var JWTManager
     */
    protected $jwt;
    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    public function __construct(JWT $jwtManager, EventDispatcherInterface $dispatcher)
    {
        $this->jwt = $jwtManager;
        $this->dispatcher = $dispatcher;
    }
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $user = $token->getUser();
        $jwt  = $this->jwt->create($user);
        $response = new JsonResponse();
        $event = new AuthenticationSuccessEvent(array('token' => $jwt), $user, $request);
        $event->setResponse($response);
        $this->dispatcher->dispatch(Events::AUTHENTICATION_SUCCESS, $event);
        $response->setData($event->getData());
        return $response;
    }

}