<?php

namespace Vigasin\JWTBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Vigasin\JWTBundle\JWT\JWT;

class DefaultController extends Controller
{
    public function indexAction($name)
    {
        $test = new JWT();
        $ddd = $test->encode('jopa','secret');
        echo $test->decode($ddd,'secret');


        return $this->render('VigasinJWTBundle:Default:index.html.twig', array('name' => $name));
    }
}
