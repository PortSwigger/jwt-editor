/*
Author : Fraser Winterborn

Copyright 2021 BlackBerry Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.blackberry.jwteditor.utils;

import com.blackberry.jwteditor.exceptions.PemException;
import com.blackberry.jwteditor.pem.JWKToPemConverterFactory;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;

/**
 * Class containing utilities to convert between PEM and nimbus-jose JWK formats
 */
public class PEMUtils {
    /**
     * Convert a JWK object to its PEM representation
     * @param jwk JWK to convert
     * @return a PEM string
     * @throws PemException if PEM conversion fails
     */
    public static String jwkToPem(JWK jwk) throws PemException {
        return JWKToPemConverterFactory.converterFor(jwk).convertToPem();
    }

    /**
     * Update the 'kid' header in a JWK
     * @param jwk the JWK to update
     * @param keyId the 'kid' value to set
     * @return the updated JWK
     * @throws PemException if updating the header fails
     */
    private static JWK embedKid(JWK jwk, String keyId) throws PemException {
        try {
            Map<String, Object> jsonKey = jwk.toJSONObject(); //NON-NLS
            jsonKey.put("kid", keyId); //NON-NLS
            return JWK.parse(jsonKey);
        } catch (ParseException e) {
            throw new PemException("Unable to embed key id");
        }
    }

    /**
     * Convert a RSA key PEM to a JWK RSAKey
     * @param pem the RSA key in PEM form
     * @param keyId the 'kid' value to use for the converted JWK
     * @return the RSAKey
     * @throws PemException if conversion fails
     */
    public static JWK pemToRSAKey(String pem, String keyId) throws PemException {
        return embedKid(pemToRSAKey(pem), keyId);
    }

    /**
     * Convert a RSA key PEM to a JWK RSAKey
     * @param pem the RSA key in PEM form
     * @return the RSAKey
     * @throws PemException if conversion fails
     */
    public static JWK pemToRSAKey(String pem) throws PemException {
        JWK rsaKey;
        try {
            rsaKey = RSAKey.parseFromPEMEncodedObjects(pem);
        } catch (JOSEException e) {
            throw new PemException("Invalid RSA key PEM");
        }

        if (!(rsaKey instanceof RSAKey)) {
            throw new PemException("Invalid key type");
        }

        return rsaKey;
    }

    /**
     * Convert an Elliptic Curve key PEM to a JWK ECKey
     * @param pem the EC key in PEM form
     * @param keyId the 'kid' value to use for the converted JWK
     * @return the ECKey
     * @throws PemException if conversion fails
     */
    public static JWK pemToECKey(String pem, String keyId) throws PemException {
        return embedKid(pemToECKey(pem), keyId);
    }

    /**
     * Convert an Elliptic Curve key PEM to a JWK ECKey
     * @param pem the EC key in PEM form
     * @return the ECKey
     * @throws PemException if conversion fails
     */
    public static JWK pemToECKey(String pem) throws PemException {
        JWK ecKey = null;
        boolean parsed;

        try {
            ecKey = ECKey.parseFromPEMEncodedObjects(pem);
            parsed = true;
        } catch (JOSEException e) {
            parsed = false;
        }

        // ECKey.parseFromPEMEncodedObjects does not handle PKCS8 formatted EC keys, build this manually
        if (!parsed) {
            try {
                // Read the PEM file
                InputStream inputStream = new ByteArrayInputStream(pem.getBytes());
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                PEMParser pemParser = new PEMParser(inputStreamReader);
                Object pemObject = pemParser.readObject();

                // The PKCS8 PEM object is a PrivateKeyInfo
                if (pemObject instanceof PrivateKeyInfo) {
                    // Get the private key
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC"); //NON-NLS
                    PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo) pemObject);

                    if (privateKey instanceof BCECPrivateKey ecPrivateKey) {
                        // Derive a public key from the private key
                        BigInteger d = ecPrivateKey.getD();
                        ECParameterSpec ecParameterSpec = ecPrivateKey.getParameters();
                        ECPoint Q = ecPrivateKey.getParameters().getG().multiply(d);
                        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(Q, ecParameterSpec); //NON-NLS //NON-NLS
                        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC"); //NON-NLS //NON-NLS
                        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);

                        // Use public and private key to construct a JWK object
                        return new ECKey.Builder(Curve.forECParameterSpec(publicKey.getParams()), publicKey).privateKey(privateKey).build();
                    } else {
                        throw new PemException("Invalid PEM type");
                    }
                } else {
                    throw new PemException("Invalid PEM type");
                }
            } catch (IOException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new PemException("Invalid PEM");
            }
        }

        if (!(ecKey instanceof ECKey)) {
            throw new PemException("Invalid key type");
        }

        return ecKey;
    }

    /**
     * Convert an OKP PEM to a JWK OctetKeyPair
     * @param pem the OKP in PEM form
     * @param keyId the 'kid' value to use for the converted JWK
     * @return the OctetKeyPair
     * @throws PemException if conversion fails
     */
    public static JWK pemToOctetKeyPair(String pem, String keyId) throws PemException {
        return embedKid(pemToOctetKeyPair(pem), keyId);
    }

    /**
     * Convert an OKP PEM to a JWK OctetKeyPair
     * @param pem the OKP in PEM form
     * @return the OctetKeyPair
     * @throws PemException if conversion fails
     */
    public static JWK pemToOctetKeyPair(String pem) throws PemException {
        try {
            InputStream inputStream = new ByteArrayInputStream(pem.getBytes());
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
            PEMParser pemParser = new PEMParser(inputStreamReader);
            PemObject pemObject = pemParser.readPemObject();

            if(pemObject == null){
                throw new PemException("Invalid PEM");
            }

            DLSequence outerSequence = (DLSequence) ASN1Primitive.fromByteArray(pemObject.getContent());

            ASN1Encodable integerOrSequencePrimitive = outerSequence.getObjectAt(0);

            // Private key
            if(integerOrSequencePrimitive instanceof ASN1Integer i){
                DLSequence algorithmSequence = (DLSequence) outerSequence.getObjectAt(1);
                DEROctetString outerOctetString = (DEROctetString) outerSequence.getObjectAt(2);

                ASN1ObjectIdentifier algorithmIdentifier = (ASN1ObjectIdentifier) algorithmSequence.getObjectAt(0);

                if(i.intValueExact() != 0) {
                    throw new PemException("Invalid integer value");
                }

                ASN1OctetString innerOctetString = (ASN1OctetString) ASN1Primitive.fromByteArray(outerOctetString.getOctets());

                OKPCurve okpCurve = OKPCurve.fromAlgorithmId(algorithmIdentifier.getId());

                return okpCurve.buildPrivateKeyFrom(innerOctetString.getOctets());
            }
            // Public key
            else if (integerOrSequencePrimitive instanceof ASN1Sequence){
                DLSequence algorithmSequence = (DLSequence) outerSequence.getObjectAt(0);
                ASN1ObjectIdentifier algorithmIdentifier = (ASN1ObjectIdentifier) algorithmSequence.getObjectAt(0);
                DERBitString bitString = (DERBitString) outerSequence.getObjectAt(1);

                byte[] keyBytes = Arrays.copyOfRange(bitString.getBytes(), 0, bitString.getEncoded().length);

                OKPCurve okpCurve = OKPCurve.fromAlgorithmId(algorithmIdentifier.getId());

                return okpCurve.buildPublicKeyFrom(keyBytes);
            }
            else{
                throw new PemException("Invalid PEM");
            }

        } catch (IOException e) {
            throw new PemException("Error reading PEM");
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new PemException("Invalid number of ASN1 objects");
        } catch (ClassCastException e){
            throw new PemException("Invalid ASN1");
        }
    }

    /**
     * Convert a BouncyCastle PemObject to its String representation
     * @param pemObject the PemObject
     * @return a PEM string
     * @throws IOException if conversion fails
     */
    public static String pemObjectToString(PemObject pemObject) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        stringWriter.close();
        return stringWriter.toString();
    }
}
