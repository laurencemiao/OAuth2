<?php
require_once 'PHPUnit/Framework.php';
 
class AllTests
{
    public static function suite()
    {
        $suite = new PHPUnit_Framework_TestSuite();
 
        $suite->addTest(Package_AllTests::suite());
 
        return $suite;
    }
}

