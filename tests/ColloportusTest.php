<?php
namespace Oire\Tests;

use Oire\Colloportus;
use PHPUnit\Framework\TestCase;

class ColloportusTest extends TestCase
{
    private const CORRECT_PASSWORD = '4024Alohomora02*X%cZ/R&D';
    private const WRONG_PASSWORD = '4024Alohomora02*X%cZ/r&d';
    private const STORABLE_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
    private const NEW_STORABLE_KEY = 'Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';
    private const DECRYPTABLE_DATA = 'Mischief managed!';

    /** @var string */
    private $rawKey;

    /** @var string */
    private $newRawKey;

    protected function setUp(): void
    {
        $this->rawKey = hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
        $this->newRawKey = hex2bin('1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100');
    }

    public function testLockWithKnownRawKey(): void
    {
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $this->rawKey);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $this->rawKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, $this->rawKey));
    }

    public function testLockWithKnownStorableKey(): void
    {
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, self::STORABLE_KEY, false);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, self::STORABLE_KEY, false));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, self::STORABLE_KEY, false));
    }

    public function testLockWithRandomRawKey(): void
    {
        $rawKey = Colloportus::createKey();
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $rawKey);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $rawKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, $rawKey));
    }

    public function testLockWithRandomStorableKey(): void
    {
        $storableKey = Colloportus::createKey(false);
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $storableKey, false);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $storableKey, false));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, $storableKey, false));
    }

    public function testFlipWithKnownRawKeys(): void
    {
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $this->rawKey);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $this->rawKey));

        $newHash = Colloportus::flip($hash, $this->rawKey, $this->newRawKey);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, $this->newRawKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, $this->newRawKey));
    }

    public function testFlipWithKnownStorableKeys(): void
    {
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, self::STORABLE_KEY, false);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, self::STORABLE_KEY, false));

        $newHash = Colloportus::flip($hash, self::STORABLE_KEY, self::NEW_STORABLE_KEY, false, false);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, self::NEW_STORABLE_KEY, false));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, self::NEW_STORABLE_KEY, false));
    }

    public function testFlipWithRandomRawKeys(): void
    {
        $rawKey = Colloportus::createKey();
        $newRawKey = Colloportus::createKey();
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $rawKey);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $rawKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, $rawKey));

        $newHash = Colloportus::flip($hash, $rawKey, $newRawKey);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, $newRawKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, $newRawKey));
    }

    public function testFlipWithRandomStorableKeys(): void
    {
        $storableKey = Colloportus::createKey(false);
        $newStorableKey = Colloportus::createKey(false);
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $storableKey, false);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $storableKey, false));

        $newHash = Colloportus::flip($hash, $storableKey, $newStorableKey, false, false);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, $newStorableKey, false));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, $newStorableKey, false));
    }

    public function testFlipWithKnownOldRawAndNewStorableKeys(): void
    {
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $this->rawKey);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $this->rawKey));
        $newHash = Colloportus::flip($hash, $this->rawKey, self::NEW_STORABLE_KEY, true, false);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, self::NEW_STORABLE_KEY, false));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, self::NEW_STORABLE_KEY, false));
    }

    public function testFlipWithKnownOldStorableAndNewRawKeys(): void
    {
        $hash = Colloportus::lock(self::CORRECT_PASSWORD, self::STORABLE_KEY, false);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, self::STORABLE_KEY, false));

        $newHash = Colloportus::flip($hash, self::STORABLE_KEY, $this->newRawKey, false, true);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, $this->newRawKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, $this->newRawKey));
    }

    public function testFlipWithRandomOldRawAndNewStorableKeys(): void
    {
        $rawKey = Colloportus::createKey();
        $newStorableKey = Colloportus::createKey(false);

        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $rawKey);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $rawKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, $rawKey));

        $newHash = Colloportus::flip($hash, $rawKey, $newStorableKey, true, false);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, $newStorableKey, false));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, $newStorableKey, false));
    }

    public function testFlipWithRandomOldStorableAndNewRawKeys(): void
    {
        $storableKey = Colloportus::createKey(false);
        $newRawKey = Colloportus::createKey();

        $hash = Colloportus::lock(self::CORRECT_PASSWORD, $storableKey, false);

        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $hash, $storableKey, false));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $hash, $storableKey, false));

        $newHash = Colloportus::flip($hash, $storableKey, $newRawKey, false, true);

        self::assertNotSame($hash, $newHash);
        self::assertTrue(Colloportus::check(self::CORRECT_PASSWORD, $newHash, $newRawKey));
        self::assertFalse(Colloportus::check(self::WRONG_PASSWORD, $newHash, $newRawKey));
    }

    public function testEncryptAndDecryptWithKnownRawKey(): void
    {
        $encrypted = Colloportus::encrypt(self::DECRYPTABLE_DATA, $this->rawKey);

        self::assertSame(self::DECRYPTABLE_DATA, Colloportus::decrypt($encrypted, $this->rawKey));
    }

    public function testEncryptAndDecryptWithKnownStorableKey(): void
    {
        $encrypted = Colloportus::encrypt(self::DECRYPTABLE_DATA, self::STORABLE_KEY, false);

        self::assertSame(self::DECRYPTABLE_DATA, Colloportus::decrypt($encrypted, self::STORABLE_KEY, false));
    }

    public function testEncryptAndDecryptWithRandomRawKey(): void
    {
        $rawKey = Colloportus::createKey();
        $encrypted = Colloportus::encrypt(self::DECRYPTABLE_DATA, $rawKey);

        self::assertSame(self::DECRYPTABLE_DATA, Colloportus::decrypt($encrypted, $rawKey));
    }

    public function testEncryptAndDecryptWithRandomStorableKey(): void
    {
        $storableKey = Colloportus::createKey(false);
        $encrypted = Colloportus::encrypt(self::DECRYPTABLE_DATA, $storableKey, false);

        self::assertSame(self::DECRYPTABLE_DATA, Colloportus::decrypt($encrypted, $storableKey, false));
    }

    public function testValidateKey(): void
    {
        $invalidRawKey = random_bytes(29);
        $invalidStorableKey = Colloportus::save(random_bytes(37));

        self::assertTrue(Colloportus::keyIsValid($this->rawKey));
        self::assertTrue(Colloportus::keyIsValid(self::STORABLE_KEY, false));
        self::assertFalse(Colloportus::keyIsValid(self::STORABLE_KEY));
        self::assertFalse(Colloportus::keyIsValid($invalidRawKey));
        self::assertFalse(Colloportus::keyIsValid($invalidStorableKey, false));
    }

    public function testSaveAndLoad(): void
    {
        $storableKey = Colloportus::save($this->rawKey);

        self::assertSame($storableKey, self::STORABLE_KEY);

        $rawKey = Colloportus::load(self::STORABLE_KEY);

        self::assertSame($rawKey, $this->rawKey);
    }
}
