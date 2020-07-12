<?php
declare(strict_types=1);
namespace Oire;

use Oire\Exception\Base64Exception;
use Oire\Exception\ColloportusException as PortusError;

/**
 * Oirë Colloportus
 * Wraps Bcrypt-SHA2 in Authenticated Encryption. A simplified fork of Paragon Initiatives PasswordLock combined with parts of Defuse PHP-encryption.
 * Copyright © 2017-2020, Andre Polykanine also known as Menelion Elensúlë, The Magical Kingdom of Oirë, https://github.com/Oire
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

class Colloportus
{
    private const HASH_FUNCTION = 'sha384';
    private const ENCRYPTION_ALGORITHM = 'aes-256-ctr';
    private const KEY_SIZE = 32;
    private const SALT_SIZE = 32;
    private const IV_SIZE = 16;
    private const MINIMUM_CIPHER_TEXT_SIZE = 96;
    private const ENCRYPTION_INFO = 'OirëColloportus|V1|KeyForEncryption';
    private const AUTHENTICATION_INFO = 'OirëColloportus|V1|KeyForAuthentication';

    /**
     * Create a new random encryption key.
     * @return string Returns an Oirë-Base64-encoded key
     */
    public static function createKey(): string
    {
        return Base64::encode(random_bytes(self::KEY_SIZE));
    }

    /**
     * Encrypt data with a given key.
     * @param string plainText
     * @return string Returns the encrypted data
     * @throws PortusError
     */
    public static function encrypt(string $plainText, string $key): string
    {
        if (!function_exists('openssl_encrypt')) {
            throw new PortusError('OpenSSL encryption not available.');
        }

        if (empty($plainText)) {
            return '';
        }

        if (!self::keyIsValid($key)) {
            throw PortusError::invalidKey();
        }

        try {
            $key = Base64::decode($key);
        } catch (Base64Exception $e) {
            throw new PortusError(sprintf('Encrypt: Failed to decode key: %s.', $e->getMessage()), $e);
        }

        $salt = random_bytes(self::SALT_SIZE);
        $authenticationKey = hash_hkdf(self::HASH_FUNCTION, $key, 0, self::AUTHENTICATION_INFO, $salt);

        if ($authenticationKey === false) {
            throw PortusError::authenticationKeyFailed();
        }

        $encryptionKey = hash_hkdf(self::HASH_FUNCTION, $key, 0, self::ENCRYPTION_INFO, $salt);

        if ($encryptionKey === false) {
            throw PortusError::encryptionKeyFailed();
        }

        $iv = random_bytes(self::IV_SIZE);
        $encrypted = openssl_encrypt($plainText, self::ENCRYPTION_ALGORITHM, $encryptionKey, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            throw new PortusError('OpenSSL encryption failed.');
        }

        $cipherText = $salt . $iv . $encrypted;
        $hmac       = hash_hmac(self::HASH_FUNCTION, $cipherText, $authenticationKey, true);

        if ($hmac === false) {
            throw PortusError::hmacFailed();
        }

        $cipherText = $cipherText . $hmac;

        return Base64::encode($cipherText);
    }

    /**
     * Decrypt data with a given key.
     * @param string cipherText
     * @param string $key The key used for data decryption
     * @return string the decrypted plain text
     * @throws PortusError
     */
    public static function decrypt(string $cipherText, string $key): string
    {
        if (!function_exists('openssl_decrypt')) {
            throw new PortusError('OpenSSL decryption not available.');
        }

        if (empty($cipherText)) {
            return '';
        }

        if (!self::keyIsValid($key)) {
            throw PortusError::invalidKey();
        }

        try {
            $key = Base64::decode($key);
        } catch (Base64Exception $e) {
            throw new PortusError(sprintf('Failed to decode key: %s.', $e->getMessage()), $e);
        }

        try {
            $cipherText = Base64::decode($cipherText);
        } catch (Base64Exception $e) {
            throw new PortusError(sprintf('Failed to decode cipher text: %s.', $e->getMessage()), $e);
        }

        if (mb_strlen($cipherText, '8bit') < self::MINIMUM_CIPHER_TEXT_SIZE) {
            throw new PortusError('Given cipher text is of incorrect length.');
        }

        $salt = mb_substr($cipherText, 0, self::SALT_SIZE, '8bit');

        if ($salt === false) {
            throw new PortusError('Invalid salt given.');
        }

        $iv = mb_substr($cipherText, self::SALT_SIZE, self::IV_SIZE, '8bit');

        if ($iv === false) {
            throw new PortusError('Invalid initialization vector given.');
        }

        $hmac = mb_substr($cipherText, -48, null, '8bit');

        if ($hmac === false) {
            throw PortusError::hmacFailed();
        }

        $encrypted = mb_substr($cipherText, self::SALT_SIZE + self::IV_SIZE, mb_strlen($cipherText, '8bit') - 48 - self::SALT_SIZE - self::IV_SIZE, '8bit');

        if ($encrypted === false) {
            throw new PortusError('Invalid encrypted text given.');
        }

        $authenticationKey = hash_hkdf(self::HASH_FUNCTION, $key, 0, self::AUTHENTICATION_INFO, $salt);

        if ($authenticationKey === false) {
            throw PortusError::authenticationKeyFailed();
        }

        $encryptionKey = hash_hkdf(self::HASH_FUNCTION, $key, 0, self::ENCRYPTION_INFO, $salt);

        if ($encryptionKey === false) {
            throw PortusError::encryptionKeyFailed();
        }

        $message = hash_hmac(self::HASH_FUNCTION, $salt . $iv . $encrypted, $authenticationKey, true);

        if ($message === false) {
            throw PortusError::hmacFailed();
        }

        if (!hash_equals($hmac, $message)) {
            throw new PortusError('Integrity check failed.');
        }

        $plainText = openssl_decrypt($encrypted, self::ENCRYPTION_ALGORITHM, $encryptionKey, OPENSSL_RAW_DATA, $iv);

        if ($plainText === false) {
            throw new PortusError('OpenSSL decryption failed.');
        }

        return $plainText;
    }

    /**
     * Hash password, encrypt-then-MAC the hash
     *
     * @param  string      $password The password to hash
     * @param  string      $key      The secret key for encryption
     * @throws PortusError
     * @return string Returns Oirë-base64-encoded encrypted result
     */
    public static function lock(string $password, string $key): string
    {
        if (empty($password)) {
            return '';
        }

        if (!self::keyIsValid($key)) {
            throw PortusError::invalidKey();
        }

        $hash = password_hash(Base64::encode(hash(self::HASH_FUNCTION, $password, true)), PASSWORD_DEFAULT);

        if ($hash === false) {
            throw new PortusError('Failed to hash the password.');
        }

        try {
            return self::encrypt($hash, $key);
        } catch (PortusError $e) {
            throw new PortusError(sprintf('Unable to lock password: %s.', $e->getMessage()), $e);
        }
    }

    /**
     * VerifyHMAC-then-Decrypt the ciphertext to get the hash, then verify that the hash matches the password
     *
     * @param  string      $password   The password to check
     * @param  string      $cipherText The hash to match against
     * @param  string      $key        The secret key for encryption
     * @return bool Returns true if the password is valid, false otherwise
     * @throws PortusError
     */
    public static function check(string $password, string $cipherText, string $key): bool
    {
        if (!self::keyIsValid($key)) {
            throw PortusError::invalidKey();
        }

        if (empty($password)) {
            return '';
        }

        try {
            $hash = self::decrypt($cipherText, $key);
        } catch (PortusError $e) {
            throw new PortusError(sprintf('Decryption error: %s.', $e->getMessage()), $e);
        }

        return password_verify(Base64::encode(hash(self::HASH_FUNCTION, $password, true)), $hash);
    }

    /**
     * Change encryption key (for instance, if the old one is compromised).
     * @param string $cipherText The encrypted data
     * @param string $oldKey The key the data was encrypted before
     * @param string $newKey The key for re-encrypting the data
     * @return string Returns the re-encrypted data
     * @throws PortusError
     */
    public static function flip(string $cipherText, string $oldKey, string $newKey): string
    {
        if (!self::keyIsValid($oldKey)) {
            throw PortusError::invalidKey();
        }

        if (!self::keyIsValid($newKey)) {
            throw PortusError::invalidKey();
        }

        try {
            $plainText = self::decrypt($cipherText, $oldKey);
        } catch (PortusError $e) {
            throw new PortusError(sprintf('Decryption failed: %s.', $e->getMessage()), $e);
        }

        try {
            return self::encrypt($plainText, $newKey);
        } catch (PortusError $e) {
            throw new PortusError(sprintf('Encryption failed: %s.', $e->getMessage()), $e);
        }
    }

    /**
     * Check if the provided encryption key is valid. Does not match the key against anything, just basically checks its length.
     * @param string $key    the key to be validated
     * @return bool Returns true if the key is valid, false otherwise
     */
    public static function keyIsValid(string $key): bool
    {
        try {
            $key = Base64::decode($key);
        } catch (PortusError $e) {
            throw new PortusError(sprintf('Failed to decode key: %s.', $e->getMessage()), $e);
        }

        return mb_strlen($key, '8bit') === self::KEY_SIZE;
    }
}
