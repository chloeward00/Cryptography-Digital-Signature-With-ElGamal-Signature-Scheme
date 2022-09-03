import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Assignment2 implements Assignment2Interface {


//  prime modulus p converted into big integer from hex string
private static final BigInteger primeModulus = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323",16);

// the generator converted into big integer from hex string
private static final BigInteger generator = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68",16);

public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

     Assignment2 c2 = new Assignment2();
    
    // GETTING FILE PATH
    String filename = args[0]; // the file we want to work with
    File file = new File(filename);
    String path = file.getAbsolutePath();
    Path filepath = Paths.get(path);  // getting the file 
    byte[] fileInBytes = Files.readAllBytes(filepath); // THE FILE IN BYTES

    //System.out.println(fileInBytes);

    BigInteger privateKey = new BigInteger("28826625988197900446246548779928791088684451641011137686439753813335258005119394275860645479188712218479413233736576961180762635810418282544708718511222360036133088797078910126584848098491173488496382792580672518821188009032193625717483537260548517791710246756098341976093774853575397712819781698176274701317");
    //System.out.println(privateKey);
    //BigInteger publicKey = getPublicKey(privateKey, primeModulus);
    BigInteger publicKey = c2.generateY(generator, privateKey, primeModulus);
    //System.out.println(privateKey);
    
    BigInteger kValue = new BigInteger("165852646246892334773380597580520447296413420942830893896745915510251663855127250371358755525414358343433717154046301173662174605741507577568728596970549905250102817269026168969896566451125282816053171169719713720826425045220786351880409674314663895757841647114772478466070489828324550017174508742876150601453");
    
   
    BigInteger generateRval = c2.generateR(generator, kValue, primeModulus);

    
    byte[] hashMess = c2.hashKey(fileInBytes);
   

    BigInteger rValue = c2.generateR(generator, kValue, primeModulus);

    BigInteger sValue = c2.generateS(hashMess, privateKey, rValue, kValue, primeModulus);


    // TO VERIFY
    String verify = c2.verify(hashMess, generator, rValue, sValue, publicKey, primeModulus);
    System.out.println(verify);

    BufferedWriter yOutput = null;
    BufferedWriter rOutput = null;
    BufferedWriter sOutput = null;

    // WRITING DATA TO FILES
        try {
        
            File yFile = new File("y.txt");
            File rFile = new File("r.txt");
            File sFile = new File("s.txt");
    

            yOutput = new BufferedWriter(new FileWriter(yFile));
            rOutput = new BufferedWriter(new FileWriter(rFile));
            sOutput = new BufferedWriter(new FileWriter(sFile)); 
            
            // changing the Big Integer values to hex
            yOutput.write(publicKey.toString(16));
            rOutput.write(rValue.toString(16));
            sOutput.write(sValue.toString(16));

        } catch ( IOException e ) {
            System.out.println(e.getMessage());
        } finally {
           
            yOutput.close();
            rOutput.close();
            sOutput.close();
          
        }


    }

    // function to hash the key
    private static byte[] hashKey(byte[] key) throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("SHA-256"); // Provides us the SHA-256 hash functions
        
        byte[] hashedKey = key;
	    hashedKey = md.digest(hashedKey);
		
		return hashedKey;
	}

// v1 = g^h(m) mod p
// v2 = y^r r^s mod p
// modPow(exponent, modulus)

public String verify(byte [] d, BigInteger g, BigInteger r, BigInteger s, BigInteger y, BigInteger mod){


         BigInteger hfile = new BigInteger(d);
         BigInteger v1 = g.modPow(hfile, mod);
        

         BigInteger a1 = y.modPow(r, mod);
         BigInteger a2 = r.modPow(s, mod);
         BigInteger v2 = (a1.multiply(a2)).mod(mod);

         if (v1.compareTo(v2) == 0){

             return "Successfully verified";

         } else {

             return "Fix code to get right values";
         }
     }

   // generating the private key
	// x = 1 < x < p-1
private static BigInteger getSecretKey(BigInteger primeModulus){
		
		Random r = new Random();
		
		BigInteger randomInt = new BigInteger(primeModulus.bitLength(), r);
		while (randomInt.compareTo(primeModulus) == 1) {
			randomInt = new BigInteger(primeModulus.bitLength(), r);
		}
		return randomInt;					
	}


private BigInteger generateK(BigInteger primeModulus){
	  // Boolean value for checking if gcd returns 1
		Boolean eq1 = false;

        BigInteger k = null;

		Random r = new Random();
		do {

			k = new BigInteger(primeModulus.bitLength(), 1, r);
			// Check gcd of K and prime-1 is 1

			eq1 = calculateGCD(primeModulus.subtract(BigInteger.ONE), k).equals(BigInteger.ONE);
            // loop happens again if gcd is not 1 and is smaller
		} while(eq1 == false && k.compareTo(primeModulus.subtract(BigInteger.ONE)) == 1);

		return k;					
	}

// generating the public key

private static BigInteger getPublicKey(BigInteger secretKey, BigInteger primeModulus){
    return generator.modPow(secretKey, primeModulus);					
	
}

 /* Method generateY returns the public key y and is generated from the given generator, secretKey  and modulus */

public BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus){

    return generator.modPow(secretKey, modulus);
}

/* Method generateR generates the first part of the ElGamal signature from the given generator, random value k and modulus */
public BigInteger generateR(BigInteger generator, BigInteger k, BigInteger modulus) {
    return generator.modPow(k, primeModulus);
}


// Compute s as s = (H(m)-xr)k-1 (mod p-1) where H is the hash function SHA-256.
public BigInteger generateS(byte[] plaintext, BigInteger secretKey, BigInteger r, BigInteger k, BigInteger modulus){

//  a. Calculate (H(m)-xr) (mod p-1)

//    b. Calculate k-1 (mod p-1)

//    c. Multiply a and b together (mod p-1)
  
           
            //Compute s as s = (H(m)-xr)k-1 (mod p-1)
            BigInteger m = new BigInteger(plaintext);
            BigInteger a = (m.subtract(secretKey.multiply(r))).mod(modulus.subtract(BigInteger.ONE));
            BigInteger b = calculateInverse(k,modulus.subtract(BigInteger.ONE));
            BigInteger c = (a.multiply(b)).mod(modulus.subtract(BigInteger.ONE));
        
            return c; 

}

public BigInteger calculateGCD(BigInteger val1, BigInteger val2){
    
     if (val2.equals(BigInteger.ZERO))
            return val1;

        return calculateGCD(val2, val1.mod(val2));
}

/* Method calculateInverse returns the modular inverse of the given val using the given modulus */
public BigInteger calculateInverse(BigInteger val, BigInteger modulus){

    BigInteger[] arr = extendedEuclideanAlgorithm(val, modulus);
        BigInteger g = arr[0];
        BigInteger a = arr[1];

        if(!g.equals(BigInteger.ONE))
        {
           throw new RuntimeException("lol");
        }
        else
    {
            return a.mod(modulus);
    }
    
    
}

private static BigInteger[] extendedEuclideanAlgorithm(BigInteger a, BigInteger b){

        BigInteger[] vals = new BigInteger[3];

        if(b.equals(BigInteger.ZERO)){
            return new BigInteger [] { a, BigInteger.ONE, BigInteger.ZERO};

        }

        BigInteger [] result = extendedEuclideanAlgorithm(b, a.mod(b));
        BigInteger ans = result[0];
        BigInteger ans2 = result[2];
        BigInteger ans3 = result[1].subtract((a.divide(b)).multiply(ans2));

        return new BigInteger [] {ans, ans2, ans3};

    }

}

// REFERENCES:
// https://www.geeksforgeeks.org/euclidean-algorithms-basic-and-extended/
// https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
// https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/