<?php
use Oire\Colloportus;
use PHPUnit\Framework\TestCase;

/**
 @requires php 7.1.2
*/

class ColloportusTest extends TestCase {
	protected $password;
	protected $wrongPassword;
	protected $rawKey;
	protected $storableKey;
	protected $rawNewKey;
	protected $storableNewKey;
	protected $decryptableData;

public function setUp() {
	$this->password="4024Alohomora02*X%cZ/R&";
	$this->wrongPassword = "4024Alohomora02*X%cZ/r&"; // Note the small r towards the end
	$this->rawKey = hex2bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
	$this->storableKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
	$this->rawNewKey = hex2bin("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");
	$this->storableNewKey = "Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA";
	$this->decryptableData = "Mischief managed!";
}

	public function testLockWithKnownRawKey() {
		$hash = Colloportus::lock($this->password, $this->rawKey);
		$wrongHash = Colloportus::lock($this->wrongPassword, $this->rawKey);
		$this->assertTrue(Colloportus::check($this->password, $hash, $this->rawKey));
	}

	public function testLockWithKnownStorableKey() {
		$hash = Colloportus::lock($this->password, $this->storableKey, false);
		$this->assertTrue(Colloportus::check($this->password, $hash, $this->storableKey, false));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $hash, $this->storableKey, false));
	}

	public function testLockWithRandomRawKey() {
		$rawKey = Colloportus::createKey();
		$hash = Colloportus::lock($this->password, $rawKey);
		$this->assertTrue(Colloportus::check($this->password, $hash, $rawKey));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $hash, $rawKey));
	}

	public function testLockWithRandomStorableKey() {
		$storableKey = Colloportus::createKey(false);
		$hash = Colloportus::lock($this->password, $storableKey, false);
		$this->assertTrue(Colloportus::check($this->password, $hash, $storableKey, false));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $hash, $storableKey, false));
	}

	public function testFlipWithKnownRawKeys() {
		$hash = Colloportus::lock($this->password, $this->rawKey);
		$this->assertTrue(Colloportus::check($this->password, $hash, $this->rawKey));
		$newHash = Colloportus::flip($hash, $this->rawKey, $this->rawNewKey);
		$this->assertNotSame($hash, $newHash);
		$this->assertTrue(Colloportus::check($this->password, $newHash, $this->rawNewKey));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $newHash, $this->rawNewKey));
	}

	public function testFlipWithKnownStorableKeys() {
		$hash = Colloportus::lock($this->password, $this->storableKey, false);
		$this->assertTrue(Colloportus::check($this->password, $hash, $this->storableKey, false));
		$newHash = Colloportus::flip($hash, $this->storableKey, $this->storableNewKey, false, false);
		$this->assertNotSame($hash, $newHash);
		$this->assertTrue(Colloportus::check($this->password, $newHash, $this->storableNewKey, false));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $newHash, $this->storableNewKey, false));
	}

	public function testFlipWithRandomRawKeys() {
		$rawKey = Colloportus::createKey();
		$rawNewKey = Colloportus::createKey();
		$hash = Colloportus::lock($this->password, $rawKey);
		$this->assertTrue(Colloportus::check($this->password, $hash, $rawKey));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $hash, $rawKey));
		$newHash = Colloportus::flip($hash, $rawKey, $rawNewKey);
		$this->assertNotSame($hash, $newHash);
		$this->assertTrue(Colloportus::check($this->password, $newHash, $rawNewKey));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $newHash, $rawNewKey));
	}

	public function testFlipWithRandomStorableKeys() {
		$storableKey = Colloportus::createKey(false);
		$storableNewKey = Colloportus::createKey(false);
		$hash = Colloportus::lock($this->password, $storableKey, false);
		$this->assertTrue(Colloportus::check($this->password, $hash, $storableKey, false));
		$newHash = Colloportus::flip($hash, $storableKey, $storableNewKey, false, false);
		$this->assertNotSame($hash, $newHash);
		$this->assertTrue(Colloportus::check($this->password, $newHash, $storableNewKey, false));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $newHash, $storableNewKey, false));
	}

	public function testFlipWithKnownMixedKeys() {
		$hash1 = Colloportus::lock($this->password, $this->rawKey);
		$this->assertTrue(Colloportus::check($this->password, $hash1, $this->rawKey));
		$newHash1 = Colloportus::flip($hash1, $this->rawKey, $this->storableNewKey, true, false);
		$this->assertNotSame($hash1, $newHash1);
		$this->assertTrue(Colloportus::check($this->password, $newHash1, $this->storableNewKey, false));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $newHash1, $this->storableNewKey, false));
		$hash2 = Colloportus::lock($this->password, $this->storableKey, false);
		$this->assertTrue(Colloportus::check($this->password, $hash2, $this->storableKey, false));
		$newHash2 = Colloportus::flip($hash2, $this->storableKey, $this->rawNewKey, false, true);
		$this->assertNotSame($hash2, $newHash2);
		$this->assertTrue(Colloportus::check($this->password, $newHash2, $this->rawNewKey));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $newHash2, $this->rawNewKey));
	}

	public function testFlipWithRandomMixedKeys() {
		$rawKey = Colloportus::createKey();
		$storableKey = Colloportus::save($rawKey);
		$storableNewKey = Colloportus::createKey(false);
		$rawNewKey = Colloportus::load($storableNewKey);
		$hash1 = Colloportus::lock($this->password, $rawKey);
		$this->assertTrue(Colloportus::check($this->password, $hash1, $rawKey));
		$newHash1 = Colloportus::flip($hash1, $rawKey, $storableNewKey, true, false);
		$this->assertNotSame($hash1, $newHash1);
		$this->assertTrue(Colloportus::check($this->password, $newHash1, $storableNewKey, false));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $newHash1, $storableNewKey, false));
		$hash2 = Colloportus::lock($this->password, $storableKey, false);
		$this->assertTrue(Colloportus::check($this->password, $hash2, $storableKey, false));
		$newHash2 = Colloportus::flip($hash2, $storableKey, $rawNewKey, false, true);
		$this->assertNotSame($hash2, $newHash2);
		$this->assertTrue(Colloportus::check($this->password, $newHash2, $rawNewKey));
		$this->assertFalse(Colloportus::check($this->wrongPassword, $newHash2, $rawNewKey));
	}

	public function testEncryptDecryptWithKnownRawKey() {
		$encrypted = Colloportus::encrypt($this->decryptableData, $this->rawKey);
		$this->assertSame(Colloportus::decrypt($encrypted, $this->rawKey), $this->decryptableData);
	}

	public function testEncryptDecryptWithKnownStorableKey() {
		$encrypted = Colloportus::encrypt($this->decryptableData, $this->storableKey, false);
		$this->assertSame(Colloportus::decrypt($encrypted, $this->storableKey, false), $this->decryptableData);
	}

	public function testEncryptDecryptWithRandomRawKey() {
		$rawKey = Colloportus::createKey();
		$encrypted = Colloportus::encrypt($this->decryptableData, $rawKey);
		$this->assertSame(Colloportus::decrypt($encrypted, $rawKey), $this->decryptableData);
	}

	public function testEncryptDecryptWithRandomStorableKey() {
		$storableKey = Colloportus::createKey(false);
		$encrypted = Colloportus::encrypt($this->decryptableData, $storableKey, false);
		$this->assertSame(Colloportus::decrypt($encrypted, $storableKey, false), $this->decryptableData);
	}

	public function testSaveLoad() {
		$storableKey = Colloportus::save($this->rawKey);
		$this->assertSame($storableKey, $this->storableKey);
		$rawKey = Colloportus::load($this->storableKey);
		$this->assertSame($rawKey, $this->rawKey);
	}
}
