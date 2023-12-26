package com.flipkarthealthplus.iam;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

public class JwtAuth0Application {
    public static void main(String[] args) {
        System.out.println("Hello world!");

        RSAPrivateKey rsaPrivateKey = null;
        RSAPublicKey rsaPublicKey = null;
        Algorithm algorithm = Algorithm.HMAC256("hii");
        JWTVerifier jwtVerifier = JWT.require(algorithm).withIssuer("LDua").build();
        String refreshJwtToken = JWT.create()
                .withIssuer("LDua")
                .withSubject("Some details")
                .withClaim("userId", "1234")
                .withIssuedAt(new Date())
                .withExpiresAt(Instant.ofEpochSecond((1703602200)))
                .withJWTId(UUID.randomUUID().toString())
//                .withNotBefore(new Date(System.currentTimeMillis()))
                .sign(algorithm);

        System.out.println(refreshJwtToken);

        createAccessToken(algorithm);

//        try {
//            DecodedJWT decodedJWT = jwtVerifier.verify(refreshJwtToken);
//
//            Claim claim = decodedJWT.getClaim("userId");
//            String userId = claim.asString();
//            System.out.println(userId);
//
//        } catch (JWTVerificationException e) {
//            System.out.println(e.getMessage());
//        }


    }

    private static void createAccessToken(Algorithm algorithm) {
        String accessJwtToken = JWT.create()
                .withIssuer("LDua")
                .withSubject("Some details")
                .withClaim("userId", "1234")
                .withIssuedAt(new Date())
                .withExpiresAt(Instant.ofEpochSecond((1703601960)))
                .withJWTId(UUID.randomUUID().toString())
//                .withNotBefore(new Date(System.currentTimeMillis()))
                .sign(algorithm);

        System.out.println(accessJwtToken);


    }
}