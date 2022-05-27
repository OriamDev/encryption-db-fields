<?php

namespace Oriamdev\EncryptionDbFields\Traits;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Support\Facades\Crypt;
use Oriamdev\EncryptionDbFields\Classes\Signature;

trait EncryptAttributesTrait
{
    public function getAttributeValue($key)
    {
        $value = $this->getAttributeFromArray($key);

        if ($this->hasGetMutator($key)) {
            return $this->mutateAttribute($key, $value);
        }

        if (in_array($key, $this->encrypts) && !is_null($value) && $value !== '')
            $value = $this->decrypt($value);

        if ($this->hasCast($key)) {
            return $this->castAttribute($key, $value);
        }

        if (in_array($key, $this->getDates()) &&
            ! is_null($value)) {
            return $this->asDateTime($value);
        }

        return $value;
    }

    public function setAttribute($key, $value)
    {
        if (is_null($value) || !in_array($key, $this->encrypts)) {
            return parent::setAttribute($key, $value);
        }

        if(in_array($key, $this->searchableEncrypts))
            $this->setSignatureAttribute($key, $value);

        $value = $this->encrypt($value);

        return parent::setAttribute($key, $value);
    }

    public function setSignatureAttribute($key, $value): void
    {
        $this->attributes["{$key}_signature"] = Signature::makeSignature($value);
    }

    private function encrypt($value)
    {
        try {
            $value = Crypt::encrypt($value);
        } catch (EncryptException $e) {}

        return $value;
    }

    private function decrypt($value)
    {
        try {
            $value = Crypt::decrypt($value);
        } catch (DecryptException $e) {}

        return $value;
    }




    public static function findByEncrypt(string $encrypt, string $value)
    {
        $model = self::class;

        $candidates = $model::where("{$encrypt}_signature", Signature::makeSignature($value))->get();

        foreach ($candidates as $candidate)
            if(strtolower($candidate->$encrypt) == strtolower($value))
                return $candidate;

        return null;
    }

}
