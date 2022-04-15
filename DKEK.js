/**
 *  ---------
 * |.##> <##.|  SmartCard-HSM Support Scripts
 * |#       #|
 * |#       #|  Copyright (c) 2011-2012 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  ---------
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @fileoverview DKEK key wrapper
 */



/**
 * Class supporting DKEK functions outside the SmartCard-HSM
 *
 * @constructor
 * @param {Crypto} crypto the crypto provider
 */
function DKEK(crypto) {
	this.crypto = crypto;
	this.dkek = new ByteString("0000000000000000000000000000000000000000000000000000000000000000", HEX);
}

exports.DKEK = DKEK;



/**
 * Import a DKEK share
 *
 * @param {ByteString} share a 32 byte share
 */
DKEK.prototype.importDKEKShare = function(share) {
	assert(share instanceof ByteString, "Share must be of type ByteString");
	assert(share.length == 32, "Share must be 32 byte long");
	var ndkek = this.dkek.xor(share);
	this.dkek.clear();
	this.dkek = ndkek;
}



/**
 * Zeroize DKEK
 *
 */
DKEK.prototype.clear = function() {
	this.dkek.clear();
}



/**
 * Return the Key Check Value (KCV) of the internal DKEK
 *
 * @type ByteString
 * @return the KCV
 */
DKEK.prototype.getKCV = function() {
	return this.crypto.digest(Crypto.SHA_256, this.dkek).left(8);
}



/**
 * Derive the encryption key from the DKEK
 *
 * @type ByteString
 * @return the encryption key
 */
DKEK.prototype.getKENC = function() {
	var kencval = this.crypto.digest(Crypto.SHA_256, this.dkek.concat(new ByteString("00000001", HEX)));
	var kenc = new Key();
	kenc.setComponent(Key.AES, kencval);
	return kenc;
}



/**
 * Derive the message authentication key from the DKEK
 *
 * @type ByteString
 * @return the message authentication key
 */
DKEK.prototype.getKMAC = function() {
	var kmacval = this.crypto.digest(Crypto.SHA_256, this.dkek.concat(new ByteString("00000002", HEX)));
	var kmac = new Key();
	kmac.setComponent(Key.AES, kmacval);
	return kmac;
}



/**
 * Derive DKEK share encryption key from password
 *
 * @param {ByteString} password the password
 * @type ByteString
 * @return the derived key (32 Byte) concatenated with the IV (16 Byte)
 */
DKEK.deriveDKEKShareKey = function(salt, password) {
	var crypto = new Crypto();

	var d = new ByteString("", HEX);
	var keyivbuff = new ByteBuffer(48);

	for (j = 0; j < 3; j++) {
		print("Derive DKEK share encryption key (Step " + (j + 1) + " of 3)...");
		var nd = d.concat(password);
		d.clear();
		d = nd;

		var nd = d.concat(salt);
		d.clear();
		d = nd;

		try	{
			// Try the fast hash available in scdp4j 3.8
			var h = crypto.digest(Crypto.MD5, d, 10000000);
			d.clear();
			d = h;
		}
		catch(e) {
			// Fallback to slow variant
			for (var i = 10000000; i > 0; i--) {
				d = crypto.digest(Crypto.MD5, d);
			}
		}
		keyivbuff.append(d);
	}

	var keyiv = keyivbuff.toByteString();
	keyivbuff.clear();
	return keyiv;
}



/**
 * Encrypt a DKEK share
 *
 * @param {ByteString} keyshare the key share
 * @param {ByteString} password the password
 * @type ByteString
 * @return Encrypted DKEK share value
 */
DKEK.encryptKeyShare = function(keyshare, password) {
	assert(keyshare instanceof ByteString, "Argument keyshare must be ByteString");
	assert(keyshare.length == 32, "Argument keyshare must be 32 bytes");
	assert(password instanceof ByteString, "Argument password must be ByteString");

	var crypto = new Crypto();
	var salt = crypto.generateRandom(8);

	var keyiv = DKEK.deriveDKEKShareKey(salt, password);

	var k = new Key();
	k.setComponent(Key.AES, keyiv.bytes(0, 32));
	var iv = keyiv.bytes(32, 16);
	keyiv.clear();

	var plain = keyshare.concat(new ByteString("10101010101010101010101010101010", HEX));
	var cipher = crypto.encrypt(k, Crypto.AES_CBC, plain, iv);
	plain.clear();
	k.getComponent(Key.AES).clear();

	var blob = (new ByteString("Salted__", ASCII)).concat(salt).concat(cipher);
	return blob;
}



/**
 * Decrypt a DKEK share
 *
 * @param {ByteString} keyshare the encrypted key share as read from the .pbe file
 * @param {ByteString} password the password
 * @type ByteString
 * @return plain DKEK value
 */
DKEK.decryptKeyShare = function(keyshare, password) {
	if ((keyshare.length != 64) || !keyshare.bytes(0, 8).toString(ASCII).equals("Salted__")) {
		throw new GPError(module.id, GPError.INVALID_DATA, 0, "Does not seem to be an encrypted key share");
	}

	var crypto = new Crypto();
	var salt = keyshare.bytes(8, 8);

	var keyiv = DKEK.deriveDKEKShareKey(salt, password);

	var k = new Key();
	k.setComponent(Key.AES, keyiv.bytes(0, 32));
	var iv = keyiv.bytes(32, 16);
	keyiv.clear();

	var plain = crypto.decrypt(k, Crypto.AES_CBC, keyshare.bytes(16), iv);
	k.getComponent(Key.AES).clear();

	if (!(new ByteString("10101010101010101010101010101010", HEX)).equals(plain.right(16))) {
		throw new GPError(module.id, GPError.INVALID_DATA, 0, "Decryption of DKEK failed. Wrong password ?");
	}

	var val = plain.left(32);
	plain.clear();

	return val;
}



/**
 * Test DKEK share encryption / decryption
 *
 * @private
 */
DKEK.testDKEK = function() {
	var crypto = new Crypto();
	var dkek = crypto.generateRandom(32);
	var password = new ByteString("Password", ASCII);
	var enc = DKEK.encryptKeyShare(dkek, password);
	print(enc);
	var plain = DKEK.decryptKeyShare(enc, password);
	assert(dkek.equals(plain), "Reference does not match");
}



/**
 * Wrap AES key
 *
 * @param {Key} key the secret key
 * @type ByteString
 * @return the secret key wrapped with the DKEK
 */
DKEK.prototype.encodeAESKey = function(key) {
	var bb = new ByteBuffer();
	bb.append(this.getKCV());

	assert(key.getType() == Key.SECRET)

	bb.append(15);

	var daid = new ByteString("2.16.840.1.101.3.4.1", OID);
	bb.append(ByteString.valueOf(daid.length, 2));
	bb.append(daid);

	var aaid = new ByteString("10 11 18 99", HEX);
	bb.append(ByteString.valueOf(aaid.length, 2));
	bb.append(aaid);

	bb.append(ByteString.valueOf(0, 2));
	bb.append(ByteString.valueOf(0, 2));

	var kb = new ByteBuffer(256);
	kb.append(this.crypto.generateRandom(8));

	kb.append(ByteString.valueOf(key.getSize() / 8, 2));
	kb.append(key.getComponent(Key.AES));

	var unpadded = kb.toByteString();
	var plain = unpadded.pad(Crypto.ISO9797_METHOD_2);
	unpadded.clear();

	if (plain.length & 0xF) {		// pad() padds to 8 byte blocks, but we 16 byte blocks
		var nplain = plain.concat(new ByteString("0000000000000000", HEX));
		plain.clear();
		plain = nplain;
	}

	var iv = new ByteString("00000000000000000000000000000000", HEX);
	var kenc = this.getKENC();
	var cipher = this.crypto.encrypt(kenc, Crypto.AES_CBC, plain, iv);
	kenc.getComponent(Key.AES).clear();
	plain.clear();

	bb.append(cipher);

	var kmac = this.getKMAC();
	bb.append(this.crypto.sign(kmac, Crypto.AES_CMAC, bb.toByteString()));
	kmac.getComponent(Key.AES).clear();

	return bb.toByteString();
}



/**
 * Wrap RSA or ECC key
 *
 * @param {Key} pri the private key in CRT format
 * @param {Key} pub the public key
 * @type Key
 * @return the private key in private exponent / modulus format
 */
DKEK.prototype.convertCRT2PEM = function(pri, pub) {
	var n = pub.getComponent(Key.MODULUS);
	var r = ByteString.valueOf(0).concat(n);
	r = r.sub(ByteString.valueOf(0).concat(pri.getComponent(Key.CRT_P)));
	r = r.sub(ByteString.valueOf(0).concat(pri.getComponent(Key.CRT_Q)));
	r = r.biAdd(ByteString.valueOf(1));
	var e = pub.getComponent(Key.EXPONENT);
	var d = e.modInverse(r);

	// Strip leading zero in private exponent
	if (d.byteAt(0) == 0) {
		d = d.bytes(1);
	}

	var nk = new Key();
	nk.setType(Key.PRIVATE);
	nk.setComponent(Key.MODULUS, n);
	nk.setComponent(Key.EXPONENT, d);
	return nk;
}



/**
 * Wrap RSA or ECC key
 *
 * @param {Key} pri the private key
 * @param {Key} pub the public key
 * @type ByteString
 * @return the private key wrapped with the DKEK
 */
DKEK.prototype.encodeKey = function(pri, pub) {
	var bb = new ByteBuffer();
	bb.append(this.getKCV());

	var mod = pub.getComponent(Key.MODULUS);
	if (mod) {
		// Convert RSA keys larger than 2048 bit and in CRT format
		if ((mod.length > 256) && pri.getComponent(Key.CRT_P)) {
			pri = this.convertCRT2PEM(pri, pub);
		}
		if (pri.getComponent(Key.CRT_P)) {
			bb.append(6);
		} else {
			bb.append(5);
		}
		var algo = new ByteString("id-TA-RSA-v1-5-SHA-256", OID);
	} else {
		bb.append(12);
		var algo = new ByteString("id-TA-ECDSA-SHA-256", OID);
	}

	bb.append(ByteString.valueOf(algo.length, 2));
	bb.append(algo);

	bb.append(ByteString.valueOf(0, 2));
	bb.append(ByteString.valueOf(0, 2));
	bb.append(ByteString.valueOf(0, 2));

	var kb = new ByteBuffer(4096);
	kb.append(this.crypto.generateRandom(8));

	if (pub.getComponent(Key.MODULUS)) {
		kb.append(ByteString.valueOf(pub.getComponent(Key.MODULUS).length << 3, 2));

		if (pri.getComponent(Key.CRT_P)) {
			var c = pri.getComponent(Key.CRT_DP1);
			kb.append(ByteString.valueOf(c.length, 2));
			kb.append(c);

			var c = pri.getComponent(Key.CRT_DQ1);
			kb.append(ByteString.valueOf(c.length, 2));
			kb.append(c);

			var c = pri.getComponent(Key.CRT_P);
			kb.append(ByteString.valueOf(c.length, 2));
			kb.append(c);

			var c = pri.getComponent(Key.CRT_PQ);
			kb.append(ByteString.valueOf(c.length, 2));
			kb.append(c);

			var c = pri.getComponent(Key.CRT_Q);
			kb.append(ByteString.valueOf(c.length, 2));
			kb.append(c);
		} else {
			var c = pri.getComponent(Key.EXPONENT);
			kb.append(ByteString.valueOf(c.length, 2));
			kb.append(c);
		}

		var c = pub.getComponent(Key.MODULUS);
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);

		var c = pub.getComponent(Key.EXPONENT);
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);
	} else {
		kb.append(ByteString.valueOf(pub.getComponent(Key.ECC_P).length << 3, 2));

		var c = pri.getComponent(Key.ECC_A);
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);

		var c = pri.getComponent(Key.ECC_B);
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);

		var c = pri.getComponent(Key.ECC_P);
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);

		var c = pri.getComponent(Key.ECC_N);
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);

		var c = (new ByteString("04", HEX)).concat(pri.getComponent(Key.ECC_GX)).concat(pri.getComponent(Key.ECC_GY));
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);

		var c = pri.getComponent(Key.ECC_D);
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);

		var c = (new ByteString("04", HEX)).concat(pub.getComponent(Key.ECC_QX)).concat(pub.getComponent(Key.ECC_QY));
		kb.append(ByteString.valueOf(c.length, 2));
		kb.append(c);
	}

	var unpadded = kb.toByteString();
	var plain = unpadded.pad(Crypto.ISO9797_METHOD_2);
	unpadded.clear();

	if (plain.length & 0xF) {		// pad() padds to 8 byte blocks, but we 16 byte blocks
		var nplain = plain.concat(new ByteString("0000000000000000", HEX));
		plain.clear();
		plain = nplain;
	}
	// print(plain);

	var iv = new ByteString("00000000000000000000000000000000", HEX);
	var kenc = this.getKENC();
	var cipher = this.crypto.encrypt(kenc, Crypto.AES_CBC, plain, iv);
	kenc.getComponent(Key.AES).clear();
	plain.clear();

	bb.append(cipher);

	var kmac = this.getKMAC();
	bb.append(this.crypto.sign(kmac, Crypto.AES_CMAC, bb.toByteString()));
	kmac.getComponent(Key.AES).clear();

//	this.dumpKeyBLOB(bb.toByteString());
	return bb.toByteString();
}

DKEK.prototype.encodeRSAKey = DKEK.prototype.encodeKey;



DKEK.prototype.dumpKeyBLOB = function(keyblob) {
	// Verify MAC on last 16 byte of blob

	var macok = this.crypto.verify(this.getKMAC(), Crypto.AES_CMAC, keyblob.bytes(0, keyblob.length - 16), keyblob.right(16));

	var keytype = keyblob.byteAt(8);
	print("Values from key blob:");
	print("---------------------");
	print("Checking the MAC      : " + (macok ? "Passed" : "Failed"));
	print("KCV                   : " + keyblob.bytes(0, 8).toString(HEX) + "    [Must match the KCV of the DKEK for import]");
	print("Key type              : " + keytype + "    [5=RSA, 6=RSA-CRT, 12=ECC, 15=AES]");

	var ofs = 9;
	var len = keyblob.bytes(ofs, 2).toUnsigned();

	if ((keytype == 15) && (keyblob.byteAt(ofs + 2) != 0x60)) {
		print("Default Algorithm ID  : " + keyblob.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")     [Wrong encoding in V3.0 to V3.2]");
	} else {
		print("Default Algorithm ID  : " + keyblob.bytes(ofs + 2, len).toString(OID) + " (" + len + ")     [Default algorithm]");
	}

	ofs += len + 2;
	var len = keyblob.bytes(ofs, 2).toUnsigned();

	print("Allowed Algorithm IDs : " + keyblob.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

	ofs += len + 2;
	var len = keyblob.bytes(ofs, 2).toUnsigned();

	print("Access Conditions     : " + keyblob.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")    [Not used]");

	ofs += len + 2;
	var len = keyblob.bytes(ofs, 2).toUnsigned();

	print("Key OID               : " + keyblob.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")    [Not used]");

	ofs += len + 2;


	// Decrypt key data

	var iv = new ByteString("00000000000000000000000000000000", HEX);
	var plainkey = this.crypto.decrypt(this.getKENC(), Crypto.AES_CBC, keyblob.bytes(ofs, keyblob.length - 16 - ofs), iv);
	// print(plainkey);

	print("Randomize             : " + plainkey.bytes(0, 8).toString(HEX) + "    [Random data prepended at export]");

	var keysize = plainkey.bytes(8, 2).toUnsigned();
	print("Key size              : " + keysize + "    [Key size in bits (ECC/RSA) or bytes (AES)]");

	var ofs = 10;

	if (keytype == 5) {
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Private Exponent      : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Modulus               : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Public Exponent       : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");
	} else if (keytype == 6) {
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("DP1 = d mod (p - 1)   : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("DQ1 = d mod (q - 1)   : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Prime factor p        : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("PQ = q - 1 mod p      : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Prime factor q        : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Modulus               : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Public Exponent       : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");
	} else if (keytype == 12) {
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("A                     : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("B                     : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Prime factor P        : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Order                 : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Generator G           : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Secret D              : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");

		ofs += len + 2;
		var len = plainkey.bytes(ofs, 2).toUnsigned();

		print("Public Point Q        : " + plainkey.bytes(ofs + 2, len).toString(HEX) + " (" + len + ")");
	} else if (keytype == 15) {
		print("Key Value             : " + plainkey.bytes(ofs, keysize).toString(HEX));
	} else {
		throw new GPError(module.id, GPError.INVALID_DATA, 0, "Unknown key type " + keytype);
	}
}
