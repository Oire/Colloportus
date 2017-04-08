# Colloportus

[![Build Status](https://travis-ci.org/Oire/colloportus.svg?branch=master)](https://travis-ci.org/Oire/colloportus)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Oire/Colloportus/blob/master/LICENSE)

Wraps Bcrypt-SHA384 in Authenticated Encryption. A simplified fork of [Password Lock](https://github.com/paragonie/password_lock) by [Paragon Initiative Enteprises](https://paragonie.com).  
Integrates parts of [Defuse PHP Encryption](https://github.com/defuse/php-encryption) for authenticated symmetric-key encryption.  
Depends on [Oire Base64](https://github.com/Oire/base64) for encoding binary data to a storable format.

## About the Name
*Colloportus* is a magical spell in the well-known Harry Potter series. It locks doors in a very hard-to-open way, and such a door is completely impossible to open for muggles, i.e., non-wizarding people. I decided to use this as a name for my simplified fork of PasswordLock.  
The method names are also simplified: `lock`, `check` and `flip` instead of `HashAndEncrypt`, `DecryptAndVerify` and `RotateKey`.

## Requirements

Requires PHP 7.1.2 or later with `mbString` and `openSSL` enabled.

## Installation

Via [Composer](https://getcomposer.org/):

`composer require oire/colloportus`

Or manually. Note that you will need `base64.php` from [Oire Base64](https://github.com/Oire/base64/):

```php
require_once("oire/base64.php");
require_once("oire/colloportus.php");
```

## Running Tests
Run `phpunit` in the projects directory.

## Usage Examples

### Hash Password, Encrypt Hash, Authenticate Cipher Text

```php
use \Oire\Colloportus;
// By default, the key is 32 bytes in size. To customize the size, pass it as the second parameter
try {
	$key = Colloportus::createKey();
	// To save the key in a storable form, either pass false as the first parameter to the createKey() method, or do:
	$storable = Colloportus::save($key);
} catch(Exception $e) {
	// Handle errors
}
if (isset($_POST['password'])) {
	if (!is_string($_POST['password'])) {
		die("Password must be a string");
	}
	try {
		// You may lock the password with a storable key. To do this, pass false as the third parameter
		$storeMe = Colloportus::lock($_POST['password'], $key);
	} catch(Exception $e) {
		// Handle errors
	}
}
```

### Verify MAC, Decrypt Ciphertext, Verify Password

```php
if (isset($_POST['password'])) {
	if (!is_string($_POST['password'])) {
		die("Password must be a string");
	}
	try {
		// You may verify the password with a storable key. To do this, pass false as the fourth parameter
		$verified = Colloportus::check($_POST['password'], $storeMe, $key);
	} catch(Exception $e) {
		// Handle errors
	}
	if ($verified) {
		// Success!
	}
}
```

### Re-encrypt a hash with a different encryption key

```php
try {
	$newKey = Colloportus::createKey();
} catch(Exception $e) {
	// Handle errors
}
try {
	$newHash = Colloportus::flip($storeMe, $key, $newKey);
} catch(Exception $e) {
	// Handle errors
}
```

## Methods

All Colloportus methods are public and static, so no class instance is required. The methods are documented in the source file, but their description is given below.  
We recommend to wrap every call in `try...catch` since Colloportus throws exceptions in case of errors.

* `public static function createKey(bool $rawBinary = true, int $keySize = self::KEY_SIZE): string` — Creates a random encryption key. If the first parameter is set to `true`, a raw binary key will be returned. If it is set to `false`, the key will be returned in a storable (i.e., readable) form. The second parameter defines the key size in bytes, by default it is set to 32 (a value defined by the corresponding class constant).
* `public static function encrypt(string $plainText, string $key, bool $rawKey = true, bool $rawBinary = false): string` — Encrypts given string data with a given key. If `$rawKey` is set to `true`, it is assumed that the key is passed as raw binary data, a storable key is assumed otherwise. If `$rawBinary` is set to true, the encrypted data are returned as binary string, a storable string is returned otherwise.
* `public static function decrypt(string $cipherText, string $key, bool $rawKey = true, bool $rawBinary = false): string` — Decrypts given cipher text with a given key. If `$rawKey` is set to `true`, it is assumed that the key is passed as raw binary data, a storable key is assumed otherwise. If `$rawBinary` is set to true, it is assumed that the cipher text is passed as raw binary data, a storable string is accepted otherwise.
* `public static function lock(string $password, string $key, bool $rawKey = true): string` — Locks given password with given key. If `$rawKey` is set to `true`, it is assumed that the key is passed as raw binary data, a storable key is accepted otherwise. Returns a storable string.
* `public static function check(string $password, string $cipherText, string $key, bool $rawKey = true): bool` — Verifies the given password against given storable cipher text. If `$rawKey` is set to `true`, it is assumed that the key is passed as binary data, a storable string is accepted otherwise. Returns `true` on success or `false` on failure.
* `public static function flip(string $cipherText, string $oldKey, string $newKey, bool $rawOldKey = true, bool $rawNewKey = true, bool $rawBinaryOld = false, bool $rawBinaryNew = false): string` — Allows to re-encrypt the password hash with a different key (for example, if the old key is compromised and the hashes are not). If `$rawOldKey` and/or `$rawNewKey` are set to `true`, it is assumed that the old and/or new keys are in raw binary form, storable strings are accepted otherwise. If `$rawBinaryOld` and/or `$rawBinaryNew` are set to `true`, it is assumed that the old cipher text is in raw binary form and/or the new cipher text will be returned in raw binary form.
* `public static function save(string $binary): string` — Allows to save a raw binary string (for example, the newly created key) as a storable string.
* `public static function load(string $storable): string` — Allows to transform a storable string in raw binary data. 

## Differences between Password Lock and Colloportus

* All methods needed for encryption/decryption are provided along with the hashing/verifying methods.
* Back-porting to older PHP versions is removed.
* Custom string processing implementations are removed, `mbstring` is required.
* Version header check is removed.
* `encrypt()` and, subsequently, `Lock()` returns URL/filename-safe Base64 data instead of hexits.
* All `sha256` instances are changed to `sha384`.
* Code style changed to match Oirë standards.

## License
Copyright © 2017, Andre Polykanine also known as Menelion Elensúlë.  
This software is licensed under an MIT license.