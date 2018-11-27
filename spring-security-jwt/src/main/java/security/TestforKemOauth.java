package security;

import java.util.Arrays;
import java.util.List;

import org.jose4j.base64url.Base64;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2018年11月21日 下午5:42:14
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
public class TestforKemOauth {
	public static void jwt(){
	    try
	    {
	    	 //
		    // JSON Web Token is a compact URL-safe means of representing claims/attributes to be transferred between two parties.
		    // This example demonstrates producing and consuming a signed JWT
		    //

		    // Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
		    RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
		    
		    // Give the JWK a Key ID (kid), which is just the polite thing to do
		    rsaJsonWebKey.setKeyId("k1");
		    System.out.println("jwk "+rsaJsonWebKey.toJson());
		    // Create the Claims, which will be the content of the JWT
		    JwtClaims claims = new JwtClaims();
		    claims.setIssuer("Issuer");  // who creates the token and signs it
		    claims.setAudience("Audience"); // to whom the token is intended to be sent
		    claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
		    claims.setGeneratedJwtId(); // a unique identifier for the token
		    claims.setIssuedAtToNow();  // when the token was issued/created (now)
		    claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
		    claims.setSubject("subject"); // the subject/principal is whom the token is about
		    claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
		    List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
		    claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array

		    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
		    // In this example it is a JWS so we create a JsonWebSignature object.
		    JsonWebSignature jws = new JsonWebSignature();

		    // The payload of the JWS is JSON content of the JWT Claims
		    jws.setPayload(claims.toJson());

		    // The JWT is signed using the private key
		    jws.setKey(rsaJsonWebKey.getPrivateKey());
		    System.out.println("getPrivateKey=====>"+Base64.encode(rsaJsonWebKey.getPrivateKey().getEncoded()));
		    System.out.println("getPublicKey=====>"+Base64.encode(rsaJsonWebKey.getPublicKey().getEncoded()));
		    // Set the Key ID (kid) header because it's just the polite thing to do.
		    // We only have one key in this example but a using a Key ID helps
		    // facilitate a smooth key rollover process
		    jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
		    jws.setHeader("typ", "JWT");
		    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
		    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

		    // Sign the JWS and produce the compact serialization or the complete JWT/JWS
		    // representation, which is a string consisting of three dot ('.') separated
		    // base64url-encoded parts in the form Header.Payload.Signature
		    // If you wanted to encrypt it, you can simply set this jwt as the payload
		    // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
		    String jwt = jws.getCompactSerialization();


		    // Now you can do something with the JWT. Like send it to some other party
		    // over the clouds and through the interwebs.
		    System.out.println("JWT: " + jwt);
		    // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
		    // be used to validate and process the JWT.
		    // The specific validation requirements for a JWT are context dependent, however,
		    // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
		    // and audience that identifies your system as the intended recipient.
		    // If the JWT is encrypted too, you need only provide a decryption key or
		    // decryption key resolver to the builder.
		    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
		            .setRequireExpirationTime() // the JWT must have an expiration time
		            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
		            .setRequireSubject() // the JWT must have a subject claim
		            .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
		            .setExpectedAudience("Audience") // to whom the JWT is intended for
		            .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
		            .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
		                    new AlgorithmConstraints(ConstraintType.WHITELIST, // which is only RS256 here
		                            AlgorithmIdentifiers.RSA_USING_SHA256))
		            .build(); // create the JwtConsumer instance
	    	
	    	
	        //  Validate the JWT and process it to the Claims
	        JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
	        System.out.println("JWT validation succeeded! " + jwtClaims);
	    }
	    catch (InvalidJwtException e)
	    {
	        // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
	        // Hopefully with meaningful explanations(s) about what went wrong.
	        System.out.println("Invalid JWT! " + e);

	        // Programmatic access to (some) specific reasons for JWT invalidity is also possible
	        // should you want different error handling behavior for certain conditions.

	        // Whether or not the JWT has expired being one common reason for invalidity
	        if (e.hasExpired())
	        {
	            try {
					System.out.println("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
				} catch (MalformedClaimException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
	        }

	        // Or maybe the audience was invalid
	        if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID))
	        {
	            try {
					System.out.println("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
				} catch (MalformedClaimException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
	        }
	    } catch (JoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public static void main(String[] args){
		jwt();
	}
	
}
