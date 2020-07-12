<?php
namespace Oire\Tests;

use Oire\Base64;
use Oire\Colloportus;
use PHPUnit\Framework\TestCase;

class ColloportusTest extends TestCase
{
    private const CORRECT_PASSWORD = '4024Alohomora02*X%cZ/R&D';
    private const WRONG_PASSWORD = '4024Alohomora02*X%cZ/r&d';
    private const KNOWN_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
    private const NEW_KEY = 'Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';
    private const DECRYPTABLE_DATA = 'Mischief managed!';

    public function testLockWithKnownKey(): void
    {
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, self::KNOWN_KEY);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, self::KNOWN_KEY));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, self::KNOWN_KEY));
    }

    public function testLockWithRandomKey(): void
    {
        $randomKey = Colloportus::createKey();
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $randomKey);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $randomKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, $randomKey));
    }

    public function testFlipWithKnownKeys(): void
    {
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, self::KNOWN_KEY);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, self::KNOWN_KEY));

        $newHash = Colloportus::flip($hash, self::KNOWN_KEY, self::NEW_KEY);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, self::NEW_KEY));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, self::NEW_KEY));
    }

    public function testFlipWithRandomKeys(): void
    {
        $randomKey = Colloportus::createKey();
        $newKey = Colloportus::createKey();
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $randomKey, false);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $randomKey));

        $newHash = Colloportus::flip($hash, $randomKey, $newKey);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, $newKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, $newKey));
    }

    public function testEncryptAndDecryptWithKnownKey(): void
    {
        $encrypted = Colloportus::encrypt(self::DECRYPTABLE_DATA, self::KNOWN_KEY);

        self::assertSame(self::DECRYPTABLE_DATA, Colloportus::decrypt($encrypted, self::KNOWN_KEY));
    }

    public function testEncryptAndDecryptWithRandomStorableKey(): void
    {
        $randomKey = Colloportus::createKey();
        $encrypted = Colloportus::encrypt(self::DECRYPTABLE_DATA, $randomKey);

        self::assertSame(self::DECRYPTABLE_DATA, Colloportus::decrypt($encrypted, $randomKey));
    }

    public function testValidateKey(): void
    {
        $invalidKey = Base64::encode(random_bytes(37));

        self::assertTrue(Colloportus::keyIsValid(self::KNOWN_KEY));
        self::assertFalse(Colloportus::keyIsValid($invalidKey));
    }
}
