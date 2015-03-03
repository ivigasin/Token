<?php


namespace Vigasin\JWTBundle\Security\Http\Authentication;


use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\HttpFoundation\Request;

class AuthenticationFailureHandler implements AuthenticationFailureHandlerInterface{
    const RESPONSE_CODE    = 401;
    const RESPONSE_MESSAGE = 'Bad credentials';
    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;
    /**
     * @param EventDispatcherInterface $dispatcher
     */
    public function __construct(EventDispatcherInterface $dispatcher)
    {
        $this->dispatcher = $dispatcher;
    }

    /**
     * @param Request $request
     * @param AuthenticationException $exception
     * @return mixed
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = array(
            'code'    => self::RESPONSE_CODE,
            'message' => self::RESPONSE_MESSAGE,
        );
        $event = new AuthenticationFailureEvent($request, $exception);
        $event->setResponse(new JsonResponse($data, self::RESPONSE_CODE));
        $this->dispatcher->dispatch(Events::AUTHENTICATION_FAILURE, $event);
        return $event->getResponse();
    }
}