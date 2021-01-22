<?php
declare(strict_types=1);
namespace Oire\Colloportus\Exception;

use RuntimeException;
use Throwable;

/**
 * Oirë Colloportus
 * Wraps Bcrypt-SHA2 in Authenticated Encryption. A simplified fork of Paragon Initiatives PasswordLock combined with parts of Defuse PHP-encryption.
 * Copyright © 2017-2021, Andre Polykanine also known as Menelion Elensúlë, The Magical Kingdom of Oirë, https://github.com/Oire
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
class ColloportusException extends RuntimeException
{
    final public function __construct(string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    final public static function hmacFailed(): self
    {
        return new static('Failed to compute HMAC.');
    }

    final public static function authenticationKeyFailed(): self
    {
        return new static('Failed to derive authentication key.');
    }

    final public static function encryptionKeyFailed(): self
    {
        return new static('Failed to derive encryption key.');
    }
}
