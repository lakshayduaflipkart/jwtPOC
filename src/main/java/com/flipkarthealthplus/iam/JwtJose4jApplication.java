package com.flipkarthealthplus.iam;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import java.nio.charset.StandardCharsets;


public class JwtJose4jApplication {
    public static void main(String[] args) throws JoseException, InvalidJwtException, MalformedClaimException {
        System.out.println("Hello world!");


        HmacKey key = new HmacKey("01234567112345672123456731234567".getBytes(StandardCharsets.UTF_8));


        JwtClaims jwtVerifier = new JwtClaims();

        jwtVerifier.setIssuer("LDua");
        jwtVerifier.setSubject("Some details");
        jwtVerifier.setClaim("userId", "1234");
        jwtVerifier.setIssuedAtToNow();
        jwtVerifier.setExpirationTimeMinutesInTheFuture((10));
        jwtVerifier.setAudience("Audience");

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(jwtVerifier.toJson());
        jws.setKey(key);
        jws.setKeyIdHeaderValue(key.toString());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);

        String jwt = jws.getCompactSerialization();

        System.out.println(jwt);

//        JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime() // the JWT must have an expiration time
//                .setMaxFutureValidityInMinutes(300) // but the  expiration time can't be too crazy
//                .setRequireSubject() // the JWT must have a subject claim
//                .setExpectedIssuer("LDua") // whom the JWT needs to have been issued by
//                .setExpectedAudience("receiver") // to whom the JWT is intended for
//                .setDecryptionKey(key) // decrypt with the receiver's private key
//                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.HMAC_SHA256).build(); // create the JwtConsumer instance
////        createAccessToken(key);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("LDua") // whom the JWT needs to have been issued by
                .setExpectedAudience("Audience") // to whom the JWT is intended for
                .setVerificationKey(key) // verify the signature with the public key
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.HMAC_SHA256)
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            System.out.println("JWT validation succeeded! " + jwtClaims);
        } catch (InvalidJwtException e) {
            // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
            // Hopefully with meaningful explanations(s) about what went wrong.
            System.out.println("Invalid JWT! " + e);

            // Programmatic access to (some) specific reasons for JWT invalidity is also possible
            // should you want different error handling behavior for certain conditions.

            // Whether or not the JWT has expired being one common reason for invalidity
            if (e.hasExpired()) {
                System.out.println("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
            }

            // Or maybe the audience was invalid
            if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
                System.out.println("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
            }

        }

//    private static void createAccessToken(Algorithm algorithm) {
//        String accessJwtToken = JWT.create()
//                .setIssuer("LDua")
//                .setSubject("Some details")
//                .setClaim("userId", "1234")
//                .setIssuedAt(new Date())
//                .setExpiresAt(Instant.ofEpochSecond((1703601960)))
//                .setJWTId(UUID.randomUUID().toString())
////                .setNotBefore(new Date(System.currentTimeMillis()))
//                .sign(algorithm);
//
//        System.out.println(accessJwtToken);
//
//
//    }
    }}