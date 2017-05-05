<?php
declare(strict_types=1);
namespace Oire;

use \Oire\Base64;

/**
 * Oirë Colloportus
 * Wraps Bcrypt-SHA2 in Authenticated Encryption. A simplified fork of Paragon Initiatives PasswordLock combined with parts of Defuse PHP-encryption.
 * Copyright © 2017 Andre Polykanine also known as Menelion Elensúlë, The magical kingdom of Oirë, https://github.com/Oire
 * Copyright © 2016 Scott Arciszewski, Paragon Initiative Enterprises, https://paragonie.com.
 * Portions copyright © 2016 Taylor Hornby, Defuse Security Research and Development, https://defuse.ca.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
*/

/**
 * Class Colloportus
 * Wraps Bcrypt-SHA2 in Authenticated Encryption. A simplified fork of Paragon Initiatives PasswordLock combined with parts of Defuse PHP-Encryption.
 * @package Colloportus
*/

class Colloportus {
	private const KEY_SIZE = 48; // Default key size in bytes
	private const SALT_SIZE = 32; // Default salt size in bytes
	private const IV_SIZE = 16; // Default initialization vector size in bytes
	private const MINIMUM_CIPHERTEXT_SIZE = 96; // Minimum encrypted text size in bytes
	private const ENCRYPTION_INFO = "OirëColloportus|V1|KeyForEncryption";
	private const AUTHENTICATION_INFO = "OirëColloportus|V1|KeyForAuthentication";

	/**
	 * Creates a new random encryption key.
	 * @param bool $rawBinary If set to true (default), the key will be returned as binary data. If set to false, a base64-encoded key (uses Oirë Base64) is returned
	 * @param int $keySize Size of the key in bytes. Defaults to self::KEY_SIZE, initially 48 bytes.
	 * @return string Returns a binary string if $rawBinary is set to true, an OirëBase64-encoded string otherwise
	*/
	public static function createKey(bool $rawBinary = true, int $keySize = self::KEY_SIZE): string {
		// Sanitizing the key size. We don’t want to throw an exception there, just resetting to the class constant
		if (empty($keySize) || !is_int($keySize) || $keySize < 0) {
			$keySize = self::KEY_SIZE;
		}
		$rawKey = random_bytes($keySize);
		if ($rawBinary) {
			$key = $rawKey;
		} else {
			try {
				$key = self::save($rawKey);
			} catch(\Exception $e) {
				throw new \Exception("CreateKey: Failed to save key to storable form: ".$e->getMessage());
			}
		}
		return $key;
	}

	/**
	 * Encrypts data with a given key.
	 * @param string plainText
	 * @param string $key
	 * @param bool $rawKey If set to true (default), it is assumed that the key is provided as binary data. If set to false, a base64-encoded key (uses Oirë Base64) is accepted
	 * @param bool $rawBinary If set to true, raw binary data is returned. If set to false (default), a base64-encoded string (uses Oirë Base64) is returned
	 * @return string
	 * @throws \Exception if openSSL encryption is not available
	 * @throws \InvalidArgumentException if the key is not a string
	*/
	public static function encrypt(string $plainText, string $key, bool $rawKey = true, bool $rawBinary = false): string {
		if (!function_exists("openssl_encrypt")) {
			throw new \Exception("OpenSSL encryption not available.");
		}
		if (!is_string($plainText)) {
			throw new \InvalidArgumentException("The plain text must be a string.");
		}
		if (empty($plainText)) {
			throw new \InvalidArgumentException("The plain text must not be empty.");
		}
		if (!is_string($key)) {
			throw new \InvalidArgumentException("The key must be a string.");
		}
		if (empty($key)) {
			throw new \InvalidArgumentException("The key must not be empty.");
		}
		if (!$rawKey) {
			try {
				$key = self::load($key);
			} catch(\Exception $e) {
				throw new \InvalidArgumentException("Encrypt: Failed to load storable key: ".$e->getMessage());
			}
		}
		$salt = random_bytes(self::SALT_SIZE);
		$akey = hash_hkdf("sha384", $key, self::KEY_SIZE, self::AUTHENTICATION_INFO, $salt);
		if ($akey === false) {
			throw new \Exception("Encrypt: Failed to derive authentication key.");
		}
		$ekey = hash_hkdf("sha384", $key, self::KEY_SIZE, self::ENCRYPTION_INFO, $salt);
		if ($ekey === false) {
			throw new \Exception("Encrypt: Failed to derive encryption key.");
		}
		$iv = random_bytes(self::IV_SIZE);
		$encrypted = openssl_encrypt($plainText, "aes-256-ctr", $ekey, OPENSSL_RAW_DATA, $iv);
		if ($encrypted === false) {
			throw new \Exception("OpenSSL encryption failed.");
		}
		$cipherText = $salt . $iv . $encrypted;
		$hmac       = hash_hmac("sha384", $cipherText, $akey, true);
		if ($hmac === false) {
			throw new \Exception("Encrypt: Failed to compute HMAC.");
		}
		$cipherText = $cipherText . $hmac;
		if ($rawBinary) {
			return $cipherText;
		} else {
			try {
				$encoded = self::save($cipherText);
			} catch(\Exception $e) {
				throw new \Exception("Failed to save cipher text: ".$e->getMessage());
			}
			return $encoded;
		}
	}

	/**
	 * Decrypts data with a given key.
	 * @param string cipherText
	 * @param string $key
	 * @param bool $rawKey If set to true (default), it is assumed that the key is provided as binary data. If set to false, a base64-encoded key (uses Oirë Base64) is accepted
	 * @param bool $rawBinary If set to true, it is assumed that the cipher text is passed as binary data. If set to false (default), a base64-encoded string (uses Oirë Base64) is accepted
	 * @return string
	 * @throws \Exception
	 * @throws \InvalidArgumentException
	*/
	public static function decrypt(string $cipherText, string $key, bool $rawKey = true, bool $rawBinary = false): string {
		if (!function_exists("openssl_decrypt")) {
			throw new \Exception("OpenSSL decryption not available.");
		}
		if (!is_string($cipherText)) {
			throw new \InvalidArgumentException("The cipher text must be a string.");
		}
		if (empty($cipherText)) {
			throw new \InvalidArgumentException("The cipher text must not be empty.");
		}
		if (!is_string($key)) {
			throw new \InvalidArgumentException("The key must be a string.");
		}
		if (empty($key)) {
			throw new \InvalidArgumentException("The key must not be empty.");
		}
		if (!$rawKey) {
			try {
				$key = self::load($key);
			} catch(\Exception $e) {
				throw new \InvalidArgumentException("Decrypt: Failed to load key: ".$e->getMessage());
			}
		}
		if (!$rawBinary) {
			try {
				$cipherText = self::load($cipherText);
			} catch(\Exception $e) {
				throw new \InvalidArgumentException("Failed to load cipher text: ".$e->getMessage());
			}
		}
		if (mb_strlen($cipherText, "8bit") < self::MINIMUM_CIPHERTEXT_SIZE) {
			throw new \InvalidArgumentException("The cipher text is too short");
		}

		// Begin parsing: getting the salt
		$salt = mb_substr($cipherText, 0, self::SALT_SIZE, "8bit");
		if ($salt === false) {
			throw new \Exception("Bad salt given.");
		}
		// Getting the initialization vector
		$iv = mb_substr($cipherText, self::SALT_SIZE, self::IV_SIZE, "8bit");
		if ($iv === false) {
			throw new \Exception("Bad initialization vector given.");
		}
		// Getting the HMAC
		$hmac = mb_substr($cipherText, -48, null, "8bit"); // sha384 returns 384 bits, i.e., 48 bytes
		if ($hmac === false) {
			throw new \Exception("Bad HMAC given.");
		}
		// Getting the cipher text itself
		$encrypted = mb_substr($cipherText, self::SALT_SIZE + self::IV_SIZE, mb_strlen($cipherText, "8bit") - 48 - self::SALT_SIZE - self::IV_SIZE, "8bit");
		if ($encrypted === false) {
			throw new \Exception("Bad encrypted text given.");
		}
		// End parsing. Deriving keys
		$akey = hash_hkdf("sha384", $key, self::KEY_SIZE, self::AUTHENTICATION_INFO, $salt);
		if ($akey === false) {
			throw new \Exception("Decrypt: Failed to derive authentication key.");
		}
		$ekey = hash_hkdf("sha384", $key, self::KEY_SIZE, self::ENCRYPTION_INFO, $salt);
		if ($ekey === false) {
			throw new \Exception("Decrypt: Failed to derive encryption key.");
		}
		$message = hash_hmac("sha384", $salt . $iv . $encrypted, $akey, true);
		if ($message === false) {
			throw new \Exception("Decrypt: failed to compute HMAC.");
		}
		if (hash_equals($message, $hmac)) {
			$plainText = openssl_decrypt($encrypted, "aes-256-ctr", $ekey, OPENSSL_RAW_DATA, $iv);
			if ($plainText === false) {
				throw new \Exception("OpenSSL decryption failed.");
			}
			return $plainText;
		} else { // The hashes are not equal
			throw new \Exception("Integrity check failed.");
		}
	}

	/**
	 * 1. Hash password using bcrypt-OirëBase64-SHA384
	 * 2. Encrypt-then-MAC the hash
	 *
	 * @param string $password The password to hash
	 * @param string $key The secret key for encryption
	 * @param bool $rawKey If set to true (default), it is assumed that the key is provided as binary data. If set to false, a base64-encoded key (uses Oirë Base64) is accepted
	 * @return string Returns the cipher text in Oiré Base64 on success, an empty string on failure
	 * @throws \Exception
	 * @throws \InvalidArgumentException
	*/
	public static function lock(string $password, string $key, bool $rawKey = true): string {
		if (!is_string($password)) {
			throw new \InvalidArgumentException("The password must be a string.");
			$locked = "";
		}
		if (empty($password)) {
			throw new \InvalidArgumentException("The password must not be empty.");
			$locked = "";
		}
		if (!is_string($key)) {
			throw new \InvalidArgumentException("The key must be a string.");
			$locked = "";
		}
		if (empty($key)) {
			throw new \InvalidArgumentException("The key must not be empty");
			$locked = "";
		}
		$hash = password_hash(Base64::encode(hash("sha384", $password, true)), PASSWORD_DEFAULT);
		if ($hash === false) {
			throw new \Exception("Lock: Unknown hashing error.");
			$locked = "";
		}
		try {
			$locked = self::encrypt($hash, $key, $rawKey);
		} catch(\Exception $e) {
			throw new \Exception("Unable to lock password: ".$e->getMessage());
			$locked = "";
		}
		return $locked;
	}

	/**
	 * 1. VerifyHMAC-then-Decrypt the ciphertext to get the hash
	 * 2. Verify that the password matches the hash
	 *
	 * @param string $password
	 * @param string $cipherText
	 * @param string $key
	 * @param bool $rawKey If set to true (default), it is assumed that the key is provided as binary data. If set to false, a base64-encoded key (uses Oirë Base64) is accepted
	 * @return bool
	 * @throws \Exception
	 * @throws \InvalidArgumentException
	*/
	public static function check(string $password, string $cipherText, string $key, bool $rawKey = true): bool {
		if (!is_string($password)) {
			throw new \InvalidArgumentException("The password must be a string.");
			return false;
		}
		if (empty($password)) {
			throw new \InvalidArgumentException("The password must not be empty.");
			return false;
		}
		if (!is_string($cipherText)) {
			throw new \InvalidArgumentException("The cipher text must be a string.");
			return false;
		}
		if (empty($cipherText)) {
			throw new \InvalidArgumentException("The cipher text must not be empty.");
			return false;
		}
		if (!is_string($key)) {
			throw new \InvalidArgumentException("The key must be a string.");
			return false;
		}
		if (empty($key)) {
			throw new \InvalidArgumentException("The key must not be empty.");
			return false;
		}
		try {
			$hash = self::decrypt($cipherText, $key, $rawKey);
		} catch(\Exception $e) {
			throw new \Exception("Decryption error during check: ".$e->getMessage());
			return false;
		}
		return password_verify(Base64::encode(hash("sha384", $password, true)), $hash);
	}

	/**
	 * Allows to change encryption key (if the old one is compromised, for example).
	 * @param string $cipherText
	 * @param string $oldKey
	 * @param string $newKey
	 * @param bool $rawOldKey If set to true (default), it is assumed that the old key is provided as binary data. If set to false, a base64-encoded key (uses Oirë Base64) is accepted
	 * @param bool $rawNewKey If set to true (default), it is assumed that the new key is provided as binary data. If set to false, a base64-encoded key (uses Oirë Base64) is accepted
	 * @param bool $rawBinaryOld If set to true, it is assumed that the old cipher text is passed as binary data. If set to false (default), a base64-encoded string (uses Oirë Base64) is accepted
	 * @param bool $rawBinaryNew If set to true, raw binary data is returned. If set to false (default), a base64-encoded string (uses Oirë Base64) is returned
	 * @return string Returns the new cipher text in Oiré Base64 on success, an empty string on failure
	 * @throws \InvalidArgumentException
	*/
	public static function flip(string $cipherText, string $oldKey, string $newKey, bool $rawOldKey = true, bool $rawNewKey = true, bool $rawBinaryOld = false, bool $rawBinaryNew = false): string {
		if (!is_string($cipherText)) {
			throw new \InvalidArgumentException("The cipher text must be a string.");
			$locked = "";
		}
		if (empty($cipherText)) {
			throw new \InvalidArgumentException("The cipher text must not be empty.");
			$locked = "";
		}
		if (!is_string($oldKey)) {
			throw new \InvalidArgumentException("The old key must be a string.");
			$locked = "";
		}
		if (empty($oldKey)) {
			throw new \InvalidArgumentException("The old key must not be empty.");
			$locked = "";
		}
		if (!is_string($newKey)) {
			throw new \InvalidArgumentException("The new key must be a string.");
			$locked = "";
		}
		if (empty($newKey)) {
			throw new \InvalidArgumentException("The new key must not be empty.");
			$locked = "";
		}
		try {
			$plainText = self::decrypt($cipherText, $oldKey, $rawOldKey, $rawBinaryOld);
		} catch(\Exception $e) {
			throw new \Exception("Decryption error when flipping keys: ".$e->getMessage());
			$locked = "";
		}
		try {
			$locked = self::encrypt($plainText, $newKey, $rawNewKey, $rawBinaryNew);
		} catch(\Exception $e) {
			throw new \Exception("Encryption error during flipping keys: ".$e->getMessage());
			$locked = "";
		}
		return $locked;
	}

	/**
	 * A helper method that allows to transform a raw binary string to a storable representation.
	 * As elsewhere in Colloportus, Oirë Base64 is used.
	 * @param string $binary The binary string to be encoded into a storable form.
	 * @return string Returns the encoded string on success, an empty string on failure
	 * @throws \InvalidArgumentException
	*/
	public static function save(string $binary): string {
		if (!is_string($binary)) {
			throw new \InvalidArgumentException("The data to be saved must be a string.");
			$storable = "";
		}
		if (empty($binary)) {
			throw new \InvalidArgumentException("The data to be saved must not be empty.");
			$storable = "";
		}
		try {
			$storable = Base64::encode($binary);
		} catch(\Exception $e) {
			throw new \Exception("Data encoding error during save: ".$e->getMessage());
			$storable = "";
		}
		return $storable;
	}

	/**
	 * A helper method that allows to transform a storable string to raw binary representation.
	 * As elsewhere in Colloportus, Oirë Base64 is used.
	 * @param string $storable The string to be decoded from a storable form.
	 * @return string Returns raw binary data on success or an empty string on failure
	 * @throws \InvalidArgumentException
	*/
	public static function load(string $storable): string {
		if (!is_string($storable)) {
			throw new \InvalidArgumentException("Load: The data to be loaded must be a string.");
			$binary = "";
		}
		if (empty($storable)) {
			throw new \InvalidArgumentException("The data to be loaded must not be empty.");
			$binary = "";
		}
		try {
			$binary = Base64::decode($storable);
		} catch(\Exception $e) {
			throw new \Exception("Data decoding error during load: ".$e->getMessage());
			$binary = "";
		}
		return $binary;
	}
}
?>