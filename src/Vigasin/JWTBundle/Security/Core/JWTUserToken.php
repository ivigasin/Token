<?php


namespace Vigasin\JWTBundle\Security\Core;


use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class JWTUserToken extends AbstractToken{
    /**
     * @var string
     */
    protected $rawToken;
    /**
     * {@inheritdoc}
     */
    public function __construct(array $roles = array())
    {
        parent::__construct($roles);
        $this->setAuthenticated(count($roles) > 0);
    }
    /**
     * @param string $rawToken
     */
    public function setRawToken($rawToken)
    {
        $this->rawToken = $rawToken;
    }
    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return $this->rawToken;
    }

}