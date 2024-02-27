package org.jpws.pwslib.crypto;

import org.jpws.pwslib.global.Util2;

import kse.utilclass.misc.Util;
import kse.utilclass.misc.Log;

public class ScatterCipher implements PwsCipher {
	private static final String CIPHER_NAME = "Scatter"; 
	private int blocksize = 16;
	private String name;
	

	public static boolean self_test () {
	   boolean ok;
	   
	   ScatterCipher ci = new ScatterCipher();
	   byte[] data = Util.randBytes(48);
	   byte[] enc = ci.encrypt(data);
	   ok = !Util.equalArrays(data, enc);
//	   Log.debug(0, "ScatterCipher ENC1 = ".concat(Util.bytesToHex(enc) ));
	   if ( ok ) {
		   byte[] res = ci.decrypt(enc);
		   ok = Util.equalArrays(data, res);
//		   Log.debug(0, "ScatterCipher DEC2 = ".concat(Util.bytesToHex(res) ));
	   }

	   if ( ok ) {
		  data = new byte[32];
		  enc = ci.encrypt(data);
		  ok = !Util.equalArrays(data, enc);
//		  Log.debug(0, "ScatterCipher ENC2 = ".concat(Util.bytesToHex(enc) ));
		  if ( ok ) {
		     byte[] res = ci.decrypt(enc);
		     ok = Util.equalArrays(data, res);
//		     Log.debug(0, "ScatterCipher DEC2 = ".concat(Util.bytesToHex(res) ));
		  }
	   }
	   
	   String hstr = ok ? "ScatterCipher OK" : "ScatterCipher FAILURE!";
	   if ( !ok )
	   Log.debug(0, hstr);
	   return ok;
	}
	
	/** Creates a Scatter cipher with default blocksize of 16.
	 */
	public ScatterCipher() {
		init();
	}

	/** Creates a Scatter cipher with the given blocksize.
	 * 
	 * @param blockSize int 
	 */
	public ScatterCipher (int blockSize) {
		blocksize = blockSize;
		init();
	}

	private void init() {
		name = CIPHER_NAME + " (" + blocksize + ")";
	}

	@Override
	public byte[] decrypt(byte[] buffer) {
		return decrypt(buffer, 0, buffer.length);
	}

	@Override
	public byte[] decrypt (byte[] buffer, int start, int length) {
		if ( length % blocksize != 0 )
	         throw new IllegalArgumentException("illegal cryptblock length");
		
		byte[] buf = Util.arraycopy(buffer, start, length);
		Util2.scatter(buf, 0, length,  false);
		return buf;
	}

	@Override
	public void decrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
		System.arraycopy(input, inOffs, output, outOffs, length);
		Util2.scatter(output, outOffs, length,  false);
	}

	@Override
	public void encrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
		System.arraycopy(input, inOffs, output, outOffs, length);
		Util2.scatter(output, outOffs, length,  true);
	}

	@Override
	public byte[] encrypt(byte[] buffer) {
		return encrypt(buffer, 0, buffer.length);
	}

	@Override
	public byte[] encrypt (byte[] buffer, int start, int length) {
		if ( length % blocksize != 0 )
	         throw new IllegalArgumentException("illegal cryptblock length");

		byte[] buf = Util.arraycopy(buffer, start, length);
		Util2.scatter(buf, 0, length,  true);
		return buf;
	}

	@Override
	public int getBlockSize() {
		return blocksize;
	}

	@Override
	public String getName() {
		return name;
	}

}
