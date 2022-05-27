<?php

namespace Oriamdev\EncryptionDbFields\Classes;

class Signature
{
    public static function makeSignature(string $value): string
    {
        return sprintf("%u", crc32(strpos($value, '@') ? self::anonymizeEmail($value) : self::anonymizeString($value)));
    }

    private static function anonymizeEmail(string $value): string
    {
        $array = explode('@', strtolower($value));

        return substr($array[0],0,1)
            .substr($array[0], intval(strlen($array[0])/2),2)
            .substr($array[0],-1)
            .'@'
            .substr($array[1],0,1)
            .substr($array[1],-1);
    }

    private static function anonymizeString(string $value): string
    {
        $string = trim($value);

        if(! strpos($string, ' '))
            return substr($string,1,2).substr($string, intval(strlen($string)/2) - 1,1).substr($string,-2);

        $array = explode(' ', $string);
        return substr($array[0], intval(strlen($array[0])/2),2) .substr($array[0],-1).substr(end($array),0,1) .substr(end($array),-1);

    }
}
