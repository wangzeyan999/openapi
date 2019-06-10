package com.bizvane.openapi.client.sdk.consts;

/**
 * 
 * @author wang.zeyan
 * @date 2019年6月10日
 */
public interface StringConsts {
	
	
	String B3 = "b3";
	String BUSINESS_ID = "business_id";

	String BIZVANE = "bizvane";
	String SEPARATOR = "-";
	String HEADER_PREFIX = BIZVANE + SEPARATOR;
	
	String REQUEST_ID = HEADER_PREFIX + "request-id";
	String REQUEST_BUSINESS_ID = HEADER_PREFIX + "reuqest-business-id";
	
	
	String SIGNATURE_HEADERS = HEADER_PREFIX + "signature-headers";
	String SIGNATURE_SIGNATURE = HEADER_PREFIX + "signature";
	
	String SIGNATURE_NONCE = HEADER_PREFIX + "nonce";
	String SIGNATURE_TIMESTAMP = HEADER_PREFIX + "timestamp";
	String SIGNATURE_APP_KEY = HEADER_PREFIX + "appkey";
	String SINGATURE_APP_SECRET = HEADER_PREFIX + "appsecret";
	String SIGNATURE_ACCESS_TOKEN = HEADER_PREFIX + "access-token";
	
	String TRACE_ID = "traceId";
}
