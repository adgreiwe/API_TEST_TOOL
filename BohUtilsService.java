package com.sbux.boh.util.rest;

import static java.util.UUID.randomUUID;

import java.io.BufferedReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.cxf.jaxrs.client.WebClient;

/**
 * {@link BohUtilsService} is the main service class handling all requests
 * for ...
 *
 * @author Preetham Uchil
 */
@Path("/service")
@Produces({MediaType.APPLICATION_XML})
@Consumes({MediaType.APPLICATION_XML})
public class BohUtilsService {
//	final static String key = "s-ebs-app:ebs_app-nprod-20151029";
//	final static String keyId = "761a3f5d-541a-45e1-9af3-7125207102b6";
//    final static String CHARSET = "UTF-8";
    
    @OPTIONS
    @Path("headers")
    public Response sigHeaderPreflight(@HeaderParam("Access-Control-Request-Headers") String headers) {
    	return Response.ok()
    			      .header("Access-Control-Allow-Origin", "*")
    			      .header("Access-Control-Allow-Methods", "GET, OPTIONS")
    			      .header("Access-Control-Allow-Headers", headers)
    			      .build();
    }
    
    @GET
    @Path("headers")
    public Response genSigHeaders(@QueryParam("URL") String address, @Context HttpHeaders headers, 
    		                      @Context HttpServletRequest req, String data) throws MalformedURLException {
    	List<String> key = headers.getRequestHeader("key");
    	List<String> keyid = headers.getRequestHeader("keyid");
    	List<String> env = headers.getRequestHeader("gws-environment");
    	StringBuilder headerStr;
    	if (key.size() != 1 || keyid.size() != 1 || env.size() != 1) {
    		return Response.ok().entity("error").build();
    	} else {
    		URL url = new URL(address);
    		WebClient wc = WebClient.create(url.getProtocol() + "://" + url.getHost() + "/").path(url.getFile());
    		String date = getDate("EEE, dd MMM yyyy HH:mm:ss zzz");
    		wc.header(HttpHeaders.DATE, date);
    		
    		headerStr = new StringBuilder(String.format("%s %s\n", new Object[]{HttpHeaders.DATE, date}));
    		String digest = createDigest(data);
    		headerStr = headerStr.append(String.format("Digest %s\n", digest));
    		wc.header("Digest", digest);
    		
            String messageString = createSigningString(wc, req.getMethod());
            String signedMessage = signMessage(messageString, keyid.get(0));
            String authorization = createAuthorizationHeader(wc, signedMessage, key.get(0));
            
            headerStr.append(String.format("%s %s\n", new Object[]{HttpHeaders.ACCEPT, MediaType.APPLICATION_XML}));
            headerStr.append(String.format("%s %s\n", new Object[]{HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_XML}));
            headerStr.append(String.format("%s %s\n", new Object[]{HttpHeaders.CONTENT_LENGTH, data.length()}));
            headerStr.append(String.format("X-Signing-String %s\n", getBase64(messageString)));
            headerStr.append(String.format("gws-environment %s\n", env.get(0)));
            headerStr.append(String.format("gws-requestId %s\n", randomUUID().toString()));
            headerStr.append("gws-version 1\n");
            headerStr.append(String.format("%s %s\n", new Object[]{HttpHeaders.AUTHORIZATION, authorization}));
    	}
    	return Response.ok()
    			       .entity(headerStr.toString())
    			       .header("Access-Control-Allow-Origin", /*"http://localhost:8000"*/ "*")
    			       .header("Access-Control-Allow-Methods", "GET, OPTIONS")
    			       .build();
    }
    
    private static String getBase64(String messageString) {
    	try {
    		String encodedMessage = removeNewLines(new String(Base64.getMimeEncoder().encodeToString(messageString.getBytes("UTF-8"))));
//    		System.out.println("encodedMessage$" + encodedMessage +"$");
    		return encodedMessage;
    	} catch (UnsupportedEncodingException e) {
    		e.printStackTrace();
    	}
    	return null;
    }
    
    private static String getDate(String format) {
        SimpleDateFormat df = new SimpleDateFormat(format);
        df.setTimeZone(TimeZone.getTimeZone("GMT"));
        return df.format(Calendar.getInstance().getTime());
    }
    
    private static String createAuthorizationHeader(WebClient wc, String signedMessage, String key) {
        String authorization ="Signature keyId=\"" + key + "\",algorithm=\"hmac-sha256\",headers=\""+ createAuthHeader(wc)+"\",signature=\"" + signedMessage + "\"";
//        System.out.println("createAuthorizationHeader$" + authorization + "$");
        return authorization;
    }
    
    private static String createAuthHeader(WebClient wc) {
        String authHeaders = "(request-target)";
        for(String header: wc.getHeaders().keySet()) {
            authHeaders += " " + header.toLowerCase();
        }
//        System.out.println("createAuthHeader$" + authHeaders + "$");
        return authHeaders;
    }
    
    private static String createDigest(String data) {
        try {
            return "sha-256=" + new String(
                java.util.Base64.getEncoder().encode(
                        MessageDigest.getInstance("SHA-256").digest(
                                data.getBytes("UTF-8"))));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return "";
        }
    }
    
    private static String createSigningString(WebClient wc, String method) {
        String signMsg = "(request-target): " + method.toLowerCase() + " " + wc.getCurrentURI().getRawPath();
        for(String header: wc.getHeaders().keySet()) {
            String values = "";
            for(String value : wc.getHeaders().get(header))
                values += value;
            signMsg += "\n" + header.toLowerCase() + ": " + values;
        }
//        System.out.println("signingString$" + signMsg + "$");
        return signMsg;
    }
    
    private static String signMessage(String message, String keyId) {
        try {
            Mac sha256_HMAC = Mac.getInstance("HMACSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(keyId.getBytes("ASCII"), "HMACSHA256");
            sha256_HMAC.init(secret_key);
            String hash = removeNewLines(Base64.getMimeEncoder().encodeToString(sha256_HMAC.doFinal(message.getBytes("ASCII"))));
//            System.out.println("signedMessage$" + hash + "$");
            return hash;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }
    
	@OPTIONS
	@Path("basic")
	public Response basicPreflight(@HeaderParam("Access-Control-Request-Headers") String headers) {
		return Response.ok()
				       .header("Access-Control-Allow-Origin", "*")
				       .header("Access-Control-Allow-Methods", "GET, OPTIONS")
				       .header("Access-Control-Allow-Headers", headers)
				       .build();
	}
    
    @GET
    @Path("basic")
    public Response basicAuthGet(@QueryParam("URL") String address, @Context HttpHeaders headers) {
    	WebClient wc = WebClient.create(address);
    	List<String> auth = headers.getRequestHeader("Authorization");
    	wc.header("Authorization", auth.get(0));
    	String xml = getXml(wc.get());
    	return Response.ok()
    				   .entity(xml)
					   .header("Access-Control-Allow-Origin", /*"http://localhost:8000"*/ "*")
					   .header("Access-Control-Allow-Methods", "GET, OPTIONS")
					   .build();
    }
    
    @GET
    @Path("none")
    public Response noAuthGet(@QueryParam("URL") String address) {
		System.setProperty("javax.net.ssl.trustStore", "C:/Users/agreiwe/TrustStores/jssecacerts");

		WebClient wc = WebClient.create(address);
		String xml = getXml(wc.get());

		return Response.ok()
        			   .entity(xml)
        			   .header("Access-Control-Allow-Origin", /*"http://localhost:8000"*/ "*")
        			   .build();
    }
    
    private String getXml(Response resp) {
    	FilterInputStream stream = (FilterInputStream) (resp.getEntity());
		StringBuilder result = new StringBuilder();
        
		try {
			int letter= stream.read();
			while(letter != -1) {
	        	result.append((char) letter);
	        	letter = stream.read();
	        }
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		String xml = "parsing error";
		try {
			xml = formatXml(result.toString());
		} catch (TransformerException e) {
			e.printStackTrace();
		}
		return xml;
    }
	
//	@OPTIONS
//	@Path("signature")
//	public Response signaturePreflight(@HeaderParam("Access-Control-Request-Headers") String headers) {
//		String base = "digest, x-signing-string, gws-environment, gws-requestid, gws-version";
//		String authHeaders = headers.equals("sig") ? base : base + ", " + headers.substring(5);
//		System.out.println(authHeaders);
//		return Response.ok()
//				       .header("Access-Control-Allow-Origin", "*")
//				       .header("Access-Control-Allow-Methods", "GET, OPTIONS")
//				       .header("Access-Control-Allow-Headers", authHeaders)
//				       .build();
//	}
//	
//	@OPTIONS
//	@Path("basic")
//	public Response basicPreflight(@HeaderParam("Access-Control-Request-Headers") String headers) {
//		System.out.println(headers);
//		return Response.ok()
//				       .header("Access-Control-Allow-Origin", "*")
//				       .header("Access-Control-Allow-Methods", "GET, OPTIONS")
//				       .header("Access-Control-Allow-Headers", headers)
//				       .build();
//	}
//	
//	@OPTIONS
//	@Path("none")
//	public Response nonePreflight(@HeaderParam("Access-Control-Request-Headers") String headers) {
//		return basicPreflight(headers);
//	}
//	
//	@GET
//	@Path("signature")
//	public Response getSignature(@QueryParam("URL") String address, @Context HttpHeaders headers) {
//		System.setProperty("javax.net.ssl.trustStore", "C:/Users/agreiwe/TrustStores/jssecacerts");
//		String xmlString = "";
//		try {
//			URL url = new URL(address);
//			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
//			System.out.println("opens connection");
//			conn.setRequestMethod("GET");
//			System.out.println("sets request method");
//			addAuthHeaders(conn, url);
//			System.out.println("adds Authorization header");
//			applyCustomHeaders(conn, headers.getRequestHeaders());
//			System.out.println("adds custom headers");
//			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
//			String input;
//			while ((input = br.readLine()) != null) {
//				xmlString += input;
//			}
//			br.close();
//		} catch (MalformedURLException e) {
//			System.out.println("malformed url");
//			e.printStackTrace();
//		} catch (IOException e) {
//			System.out.println("ioexception");
//			e.printStackTrace();
//		}
//
//		try {
//	        xmlString = formatXml(xmlString);
//	        System.out.println("----------------\n" + xmlString + "---------------");
//	    } catch (Exception e) {
//	        e.printStackTrace();
//	    }
//		return Response.ok()
//					   .entity(xmlString)
//					   .header("Access-Control-Allow-Origin", /*"http://localhost:8000"*/ "*")
//					   .header("Access-Control-Allow-Methods", "GET, OPTIONS")
//					   .build();
//	}
//	
//	@GET
//	@Path("basic")
//	public Response getBasic(@QueryParam("URL") String address, @Context HttpHeaders headers) {
//		System.setProperty("javax.net.ssl.trustStore", "C:/Users/agreiwe/TrustStores/jssecacerts");
//		String xmlString = "";
//		try {
//			URL url = new URL(address);
//			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
//			conn.setRequestMethod("GET");
//			applyCustomHeaders(conn, headers.getRequestHeaders());
//			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
//			String input;
//			while ((input = br.readLine()) != null) {
//				xmlString += input;
//			}
//			br.close();
//		} catch (MalformedURLException e) {
//			e.printStackTrace();
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
//
//		try {
//	        xmlString = formatXml(xmlString);
//	        System.out.println("----------------\n" + xmlString + "---------------");
//	    } catch (Exception e) {
//	        e.printStackTrace();
//	    }
//		return Response.ok()
//					   .entity(xmlString)
//					   .header("Access-Control-Allow-Origin", /*"http://localhost:8000"*/ "*")
//					   .header("Access-Control-Allow-Methods", "GET, OPTIONS")
//					   .build();
//	}
//	
//	@GET
//	@Path("none")
//	public Response getNone(@QueryParam("URL")) 
//	
//	
//	
//	private void applyCustomHeaders(HttpURLConnection conn, 
//			                  MultivaluedMap<String, String> customHeaders) {
//		for (String header : customHeaders.keySet()) {
//			conn.addRequestProperty(header, customHeaders.getFirst(header));
//		}
//	}
//	
//	private void addAuthHeaders(HttpURLConnection conn, URL url) {
//		System.out.println("0");
//		conn.addRequestProperty(HttpHeaders.DATE, getDate("EEE, dd MMM yyyy HH:mm:ss zzz"));
//		System.out.println("1");
//		conn.addRequestProperty("Digest", createDigest(""));
//		System.out.println("2");
//        String messageString = createSigningString(conn, url);
//        System.out.println("3");
//        String signedMessage = signMessage(messageString);
//        System.out.println("4");
//        String authorization = createAuthorizationHeader(conn, signedMessage);
//        System.out.println("5");
//        conn.addRequestProperty(HttpHeaders.ACCEPT, MediaType.APPLICATION_XML);
//        System.out.println("6");
//        conn.addRequestProperty(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_XML);
//        System.out.println("7");
//        conn.addRequestProperty(HttpHeaders.CONTENT_LENGTH, "".length() + "");
//        System.out.println("8");
//        conn.addRequestProperty("X-Signing-String", getBase64(messageString));
//        conn.addRequestProperty("gws-environment", env);
//        conn.addRequestProperty("gws-requestId", randomUUID().toString());
//        conn.addRequestProperty("gws-version", "1");
//        conn.addRequestProperty(HttpHeaders.AUTHORIZATION, authorization);
//	}
//	
//    private static String getBase64(String messageString) {
//        try {
//            String encodedMessage = removeNewLines(new String(Base64.getMimeEncoder().encodeToString(messageString.getBytes(CHARSET))));
//            System.out.println("encodedMessage$" + encodedMessage +"$");
//            return encodedMessage;
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        }
//        return null;
//    }
//	
//	private static String createSigningString(HttpURLConnection conn, URL url) {
//		System.out.println("0.5");
//        String signMsg = "(request-target): " + conn.getRequestMethod().toLowerCase() + " " + url.getFile();
//        System.out.println("1.5");
//        Map<String, List<String>> requestHeaders = conn.getHeaderFields();
//        System.out.println("2.5");
//        for(String header : requestHeaders.keySet()) {
//            String values = "";
//            System.out.println("3.5");
//            for(String value : requestHeaders.get(header)) {
//                values += value;
//                System.out.println("4.5");
//            }
//            System.out.println("5.5");
//            signMsg = signMsg + "\n" + header.toLowerCase() + ": " + values;
//            System.out.println("6.5");
//        }
//        System.out.println("7.5");
//        System.out.println("signingString$" + signMsg + "$");
//        return signMsg;
//    }
//	
//    private static String signMessage(String message) {
//        try {
//            Mac sha256_HMAC = Mac.getInstance("HMACSHA256");
//            SecretKeySpec secret_key = new SecretKeySpec(keyId.getBytes("ASCII"), "HMACSHA256");
//            sha256_HMAC.init(secret_key);
//            String hash = removeNewLines(Base64.getMimeEncoder().encodeToString(sha256_HMAC.doFinal(message.getBytes("ASCII"))));
//            System.out.println("signedMessage$" + hash + "$");
//            return hash;
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        }
//        return null;
//    }
//    
//    private static String createAuthorizationHeader(HttpURLConnection conn, String signedMessage) {
//    	Map<String, List<String>> requestHeaders = conn.getHeaderFields();
//        String authorization ="Signature keyId=\"" + key + "\",algorithm=\"hmac-sha256\",headers=\"" + createAuthHeader(requestHeaders)+"\",signature=\"" + signedMessage + "\"";
//        System.out.println("createAuthorizationHeader$" + authorization + "$");
//        return authorization;
//    }
//    
//    private static String createAuthHeader(Map<String, List<String>> requestHeaders) {
//        String authHeaders = "(request-target)";
//        for(String header: requestHeaders.keySet()) {
//            authHeaders += " " + header.toLowerCase();
//        }
//        System.out.println("createAuthHeader$" + authHeaders + "$");
//        return authHeaders;
//    }
//	
//	private static String createDigest(String data) {
//        try {
//            return "sha-256=" + new String(
//                java.util.Base64.getEncoder().encode(
//                        MessageDigest.getInstance("SHA-256").digest(
//                                data.getBytes("UTF-8"))));
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//            return "";
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//            return "";
//        }
//    }
//	
//    private static String getDate(String format) {
//        SimpleDateFormat df = new SimpleDateFormat(format);
//        df.setTimeZone(TimeZone.getTimeZone("GMT"));
//        return df.format(Calendar.getInstance().getTime());
//    }
	
	private String formatXml(String xmlString) throws TransformerException {
		Source xmlInput = new StreamSource(new StringReader(xmlString));
        StringWriter stringWriter = new StringWriter();
        StreamResult xmlOutput = new StreamResult(stringWriter);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute("indent-number", 2);
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.transform(xmlInput, xmlOutput);
        return xmlOutput.getWriter().toString();
	}
	
    private static String removeNewLines(String orig) {
    	orig = orig.replace("\r", "\n").replace("\n", "");
    	return orig;
    }
}
