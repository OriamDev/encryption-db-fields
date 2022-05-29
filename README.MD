# Encryption DB Fields

## _This package allows two way encryption on all critical fields inside the database._
## _Allows search by encrypted field._

### Installation

You can install the package via composer:

```bash
composer require oriamdev/encryption-db-fields
```

### Setup Eloquent Model
**1** - First, you need to add the trait `EncryptAttributesTrait` to the model when you want to encrypt fields.
```php
    use EncryptAttributesTrait;
```
**2** - Define the array with fields to be encrypted
```php
    protected array $encrypts = ['name', 'email'];
```
**3** - If you want to search by encrypted field you need to add the array `$searchableEncrypts` to the model.
```php
    protected array $searchableEncrypts = ['name', 'email'];
```

### Adapt DB Table structure
***NOTES:***
- The fields to be encrypted need to be text type.
- For each searchable field you need to add a string field to migration with name `field_signature`

```php
Schema::create('users', function (Blueprint $table) {
    $table->id();
    $table->text('name'); 
    $table->text('email');
    $table->string('email_signature',10)->index();
    $table->string('name_signature', 10)->index();
    $table->timestamp('email_verified_at')->nullable();
    $table->string('password');
    $table->rememberToken();
    $table->timestamps();
});
```
### Migrate database
```php
php artisan migrate
```

### CRUD Operations
The crud operations work the same way and the process to encrypt and decrypt fields are responsibility of the trait `EncryptAttributesTrait`

### Validation Rules
The _laravel_ validation rules ```unique and exists``` does not work but, not worry about it.
The package has a Validation Rule `Oriamdev\EncryptionUserDbAuth\Rules\Encrypted`
The construct need the fully qualified name of the model. `User::class or Post::class`
### Check if field under validation is unique
After creating the new instance of Encrypted Rule you can pass the unique method
```php
$request->validate([
     'email' => [(new Encrypted(User::class))->unique()],
]);
```
If the validation fails the rule return the default value of `validation:unique`
### Check if field under validation exists
After creating the new instance of Encrypted Rule you can pass the exists method
```php
$request->validate([
     'email' => [(new Encrypted(User::class))->unique()],
]);
```
If the validation fails the rule return the default value of `validation:unique`
```php
$request->validate([
    'name' => [(new Encrypted(User::class))->exists()]
]);
```
### Search by encrypted field
```php
$user = User::findByEncrypt('email', 'mario@oriamdev.com');
```
The method `findByEncrypt` return an instance of model or `null` if not exists.
