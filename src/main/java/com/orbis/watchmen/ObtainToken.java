package com.orbis.watchmen;

import java.io.*;
import java.net.*;
import java.nio.charset.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.text.*;
import java.util.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import com.owlike.genson.*;
import com.owlike.genson.ext.jaxb.*;

/**
 * User: Daniil Sosonkin
 * Date: 11/7/2019 2:22 PM
 */
public class ObtainToken
    {
        private String key;
        private String hostname;

        public static void main(String[] args) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, JOSEException
            {
                var obtain = new ObtainToken();

                for (int i = 0; i < args.length; i++)
                    switch (args[i])
                        {
                            case "-key":
                                obtain.setKey(args[++i]);
                                break;

                            case "-hostname":
                                obtain.setHostname(args[++i]);
                                break;
                        }

                System.out.println(obtain.obtainAccessToken());
            }

        public void setKey(String key)
            {
                this.key = key;
            }

        public void setHostname(String hostname)
            {
                this.hostname = hostname;
            }

        private String obtainAccessToken() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, JOSEException
            {
                var token = generateToken();

                var genson = new GensonBuilder()
                        .useIndentation(false)
                        .useDateAsTimestamp(false)
                        .useDateFormat(new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss.S Z"))
                        .setSkipNull(true)
                        .create();

                var request = new TokenRequest();
                request.setJwe(token);

                var data = genson.serialize(request);
                var url = new URL(hostname + "/api/v1/oms/token");

                var con = (HttpURLConnection) url.openConnection();
                con.setDoOutput(true);
                con.setDoInput(true);
                con.setConnectTimeout(10 * 1000);
                con.setReadTimeout(10 * 1000);
                con.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
                con.setRequestProperty("Accept", "application/json");
                con.setRequestMethod("POST");

                try (OutputStreamWriter wr = new OutputStreamWriter(con.getOutputStream()))
                    {
                        wr.write(data);
                        wr.flush();
                    }

                var buf = new StringBuilder();
                int code = con.getResponseCode();

                try (BufferedReader br = new BufferedReader(new InputStreamReader(code != 200 ? con.getErrorStream() : con.getInputStream(), StandardCharsets.UTF_8)))
                    {
                        String line;
                        while ((line = br.readLine()) != null)
                            {
                                buf.append(line).append("\n");
                            }
                    }

                if (code != 200)
                    throw new IOException("Code: " + code + "; Error: " + buf);

                var response = genson.deserialize(buf.toString(), BasicResponse.class);
                if (!response.isSuccess())
                    throw new IOException("Failed to obtain the token: " + response.getContent());

                return response.getContent().toString();
            }

        private String generateToken() throws JOSEException, NoSuchAlgorithmException, IOException, InvalidKeySpecException
            {
                var claimSet = new JWTClaimsSet.Builder()
                        .issuer(String.format("%s (%s %s %s)", getClass().getName(), System.getProperty("os.name"), System.getProperty("java.vendor"), System.getProperty("java.version")))
                        .expirationTime(new Date(System.currentTimeMillis() + 10 * 1000))
                        .notBeforeTime(new Date())
                        .issueTime(new Date())
                        .jwtID(UUID.randomUUID().toString())
                        .build();

                var header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                        .keyID(key)
                        .build();

                var jwt = new EncryptedJWT(header, claimSet);
                var encrypter = new RSAEncrypter((RSAPublicKey) getPublicKey(key + ".pem"));
                jwt.encrypt(encrypter);

                return jwt.serialize();
            }

        private PublicKey getPublicKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
            {
                var file = new File(filename);
                if (!file.exists())
                    throw new IOException("Couldn't locate key file [" + filename + "]");

                try (var in = new BufferedReader(new FileReader(file)))
                    {
                        StringBuilder buf = new StringBuilder();
                        String line;
                        while ((line = in.readLine()) != null)
                            buf.append(line);

                        var publicKeyPEM = buf.toString();
                        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "");
                        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");

                        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
                        KeyFactory kf = KeyFactory.getInstance("RSA");

                        return kf.generatePublic(new X509EncodedKeySpec(encoded));
                    }
            }
    }
