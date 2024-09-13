

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class RestrictedEmbedLink
{
  public static PrivateKey loadPemPrivateKey(String pem) throws Exception
  {
    String base64Pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                          .replace("-----END PRIVATE KEY-----", "")
                          .replaceAll("\\s", ""); // Remove all whitespace

    byte[] keyBytes = Base64.getDecoder().decode(base64Pem);

    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
    return keyFactory.generatePrivate(keySpec);
  }

  public static byte[] signPayload(PrivateKey privateKey, String payload) throws Exception
  {
    Signature signature = Signature.getInstance("SHA256withECDSA");
    signature.initSign(privateKey);
    signature.update(payload.getBytes(StandardCharsets.UTF_8));
    byte[] derSignature = signature.sign();

    return convertDerToP1363(derSignature);
  }

  public static byte[] convertDerToP1363(byte[] derSignature)
  {
    if (derSignature.length < 8) {
      throw new IllegalArgumentException("Invalid DER signature");
    }

    int rLength = derSignature[3];
    byte[] rBytes = Arrays.copyOfRange(derSignature, 4, 4 + rLength);
    byte[] sBytes = Arrays.copyOfRange(derSignature, 6 + rLength, derSignature.length);

    rBytes = padToLength(rBytes, 32);
    sBytes = padToLength(sBytes, 32);

    byte[] signatureP1363 = new byte[64];
    System.arraycopy(rBytes, 0, signatureP1363, 0, 32);
    System.arraycopy(sBytes, 0, signatureP1363, 32, 32);

    return signatureP1363;
  }

  public static byte[] padToLength(byte[] data, int length)
  {
    if (data.length == length) {
      return data;
    } else if (data.length > length) {
      return Arrays.copyOfRange(data, data.length - length, data.length);
    } else {
      byte[] padded = new byte[length];
      System.arraycopy(data, 0, padded, length - data.length, data.length);
      return padded;
    }
  }

    public static void main(String[] args)
    {
      try {
        if (args.length < 2) {
          System.out.println("Usage: java -cp \".:libs/*\" RestrictedEmbedLink <privateKey> <baseURL> [--linkAccessFilter <value>] [--cubeAccessFilter <value>]");
          System.exit(1);
        }
          String privKey = args[0];
          String baseURL = args[1];
          String cubeAccessFilter  = null;
          String linkAccessFilter  = null;

          for (int i = 2; i < args.length; i++) {
            if ("--linkAccessFilter".equals(args[i]) && i + 1 < args.length) {
              linkAccessFilter = args[++i];
            } else if ("--cubeAccessFilter".equals(args[i]) && i + 1 < args.length) {
              cubeAccessFilter = args[++i];
            }
          }

        // Validate baseURL
        if (!baseURL.matches("^(https?://).+$")) {
          System.err.println("Error: The baseURL is not a valid URL.");
          System.exit(1);
        }
        String pemKey = "-----BEGIN PRIVATE KEY-----\n" + privKey + "\n-----END PRIVATE KEY-----";

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode jsonPayload = mapper.createObjectNode();
        PrivateKey privateKey = loadPemPrivateKey(pemKey);
        String created = String.valueOf(System.currentTimeMillis());
        if (cubeAccessFilter != null && !cubeAccessFilter.isEmpty()) {
          jsonPayload.put("cubeAccessFilter", cubeAccessFilter);
        }
        if (linkAccessFilter != null && !linkAccessFilter.isEmpty()) {
          jsonPayload.put("linkAccessFilter", linkAccessFilter);
        }
        jsonPayload.put("created", created);

        String jsonPayloadString = mapper.writeValueAsString(jsonPayload);

        System.out.println("Payload: "+jsonPayloadString);

        byte[] signatureBytes = signPayload(privateKey, jsonPayloadString);
        String Signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        StringBuilder urlBuilder = new StringBuilder(baseURL);
        urlBuilder.append("?signature=").append(Signature);

        if (cubeAccessFilter != null) {
          urlBuilder.append("&cubeAccessFilter=").append(URLEncoder.encode(cubeAccessFilter, StandardCharsets.UTF_8.toString()));
        }

        if (linkAccessFilter != null && !linkAccessFilter.isEmpty()) {
          urlBuilder.append("&linkAccessFilter=").append(URLEncoder.encode(linkAccessFilter, StandardCharsets.UTF_8.toString()));
        }

        urlBuilder.append("&created=").append(URLEncoder.encode(created, StandardCharsets.UTF_8.toString()));

        System.out.println("Restricted Embed Link: " + urlBuilder);
      }
      catch (Exception e) {
        e.printStackTrace();
      }
    }
  }


