<?php

namespace Oriamdev\EncryptionDbFields\Rules;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Contracts\Validation\Rule;
use Illuminate\Support\Facades\DB;
use Oriamdev\EncryptionDbFields\Classes\Signature;

class Encrypted implements Rule
{
    private bool $unique;
    private string $model;

    public function __construct(string $modelName)
    {
        $this->model = $modelName;
    }

    public function passes($attribute, $value): bool
    {
        $candidates = $this->model::where("{$attribute}_signature", Signature::makeSignature($value))->get();

        foreach ($candidates as $candidate)
            if(strtolower($candidate->$attribute) == strtolower($value))
                return ! $this->unique;

        return $this->unique;
    }

    public function unique(): static
    {
        $this->unique = true;
        return $this;
    }

    public function exists(): static
    {
        $this->unique = false;
        return $this;
    }


    public function message(): array|string|Translator|Application|null
    {
        return $this->unique
            ? trans('validation.unique')
            : trans('validation.exists');
    }
}
