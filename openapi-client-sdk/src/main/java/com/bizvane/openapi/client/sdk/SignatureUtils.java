package com.bizvane.openapi.client.sdk;

import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSON;
import com.bizvane.openapi.client.sdk.consts.StringConsts;

/**
 * 
 * @author wang.zeyan
 * @date 2019年4月15日
 */
public class SignatureUtils {
	
	static Logger logger = LoggerFactory.getLogger(SignatureUtils.class);
	
	static final String DEFAULT_JOIN1 = "=";
	static final String DEFAULT_JOIN2 = "&";
	static final String EMPTY = "";
	static final Encoder ENCODER = java.util.Base64.getEncoder();
	/**
	 * 签名
	 * @param appSecret
	 * @param rawData
	 * @return
	 */
	public static String sign(String rawData) throws IllegalArgumentException {
		if(rawData == null || rawData.trim().length() == 0) {
			throw new IllegalArgumentException("Empty.RawData");
		}
		logger.info("Sign | RawData:{}", rawData);
		
		return DigestUtils.md5Hex(ENCODER.encode(rawData.getBytes()));
	}
	
	/**
	 * 签名
	 * @param appSecret
	 * @param map
	 * @return
	 */
	public static String sign(String appSecret, Map<String, Object> map) throws IllegalArgumentException {
		if(map == null || map.size() == 0) {
			throw new IllegalArgumentException("Empty.Map");
		}
		if(map instanceof TreeMap) {
			return sign(appSecret, (TreeMap<String, Object>)map);
		}
		
		TreeMap<String, Object> treeMap = new TreeMap<String, Object>();
		treeMap.putAll(map);
		return sign(appSecret, treeMap);
	}
	
	/**
	 * 签名
	 * @param appSecret
	 * @param rawData
	 * @return
	 */
	public static String sign(String appSecret, TreeMap<String, Object> treeMap) throws IllegalArgumentException {
		if(treeMap == null || treeMap.size() == 0) {
			throw new IllegalArgumentException("Empty.TreeMap");
		}
		if(!treeMap.containsKey(StringConsts.SINGATURE_APP_SECRET)) {
			treeMap.put(StringConsts.SINGATURE_APP_SECRET, appSecret);
		}
		String rawData = transform(treeMap);
		String signatrue = sign(rawData);
		treeMap.remove(StringConsts.SINGATURE_APP_SECRET);
		return signatrue;
	}
	
	/**
	 * 验证签名
	 * @param appSecret
	 * @param rawData
	 * @param sign
	 * @return
	 */
	public static boolean verifySign(String rawData, String sign) throws IllegalArgumentException {
		if(logger.isDebugEnabled()) {
			logger.debug("RawData:{}", rawData);
			logger.debug("Sign:{}", sign);
		}
		if(rawData == null || rawData.trim().length() == 0) {
			throw new IllegalArgumentException("Empty.RawData");
		}
		if(sign == null || sign.trim().length() == 0) {
			throw new IllegalArgumentException("Empty.Signature");
		}
		return sign.equals(DigestUtils.md5Hex(ENCODER.encode(rawData.getBytes())));
	}
	
	/**
	 * 验证签名
	 * @param appSecret
	 * @param map
	 * @param sign
	 * @return
	 */
	public static boolean verifySign(String appSecret, Map<String, Object> map, String sign) throws IllegalArgumentException {
		if(map == null || map.size() == 0) {
			throw new IllegalArgumentException("Empty.Map");
		}
		if(map instanceof TreeMap) {
			return verifySign(appSecret, (TreeMap<String, Object>)map, sign);
		}
		
		TreeMap<String, Object> treeMap = new TreeMap<String, Object>();
		treeMap.putAll(map);
		return verifySign(appSecret, treeMap, sign);
	}
	
	/**
	 * 验证签名
	 * @param appSecret
	 * @param treeMap
	 * @param sign
	 * @return
	 */
	public static boolean verifySign(String appSecret, TreeMap<String, Object> treeMap, String sign) throws IllegalArgumentException {
		if(treeMap == null || treeMap.size() == 0) {
			throw new IllegalArgumentException("Empty.TreeMap");
		}
		if(!treeMap.containsKey(StringConsts.SINGATURE_APP_SECRET)) {
			treeMap.put(StringConsts.SINGATURE_APP_SECRET, appSecret);
		}
		String rawData = transform(treeMap);
		boolean verify = verifySign(rawData, sign);
		treeMap.remove(StringConsts.SINGATURE_APP_SECRET);
		return verify;
	}
	
	public static String transform(TreeMap<String, Object> treeMap) {
		StringBuilder stringBuilder = new StringBuilder();
		int index = 0;
		for (Entry<String, ? extends Object> entry : treeMap.entrySet()) {
			if(entry.getValue() == null || entry.getValue().equals(EMPTY)) {
				continue;
			}
			if(index++ > 0) {
				stringBuilder.append(DEFAULT_JOIN2);
			}
			stringBuilder.append(entry.getKey()).append(DEFAULT_JOIN1);
			if(entry.getValue() instanceof String) {
				stringBuilder.append(String.valueOf(entry.getValue()));
			}else {
				stringBuilder.append(JSON.toJSONString(entry.getValue()));
			}
		}
		return stringBuilder.toString();
	}
	
	/**
	 * 验证签名
	 * @param headers
	 * @param body
	 * @param appSecret
	 * @return
	 */
	public static boolean verySignature(Map<String, Object> headers, Map<String, Object> body, String appSecret) {
		Object object = headers.get(StringConsts.SIGNATURE_HEADERS);
		// header中是否有 bizvane-signature-headers属性值
		if(object == null || EMPTY.equals(object.toString().trim())) {
			return false;
		}
		// header中是否有bizvane-signature属性值
		Object signature = headers.get(StringConsts.SIGNATURE_SIGNATURE);
		if(signature == null || EMPTY.equals(signature.toString().trim())) {
			return false;
		}
		String signatureHeaders = object.toString();
		String [] signatureHeaderArray = signatureHeaders.split(",");
		Map<String, Object> params = new HashMap<String, Object>(signatureHeaderArray.length + 5);
		for (String key : signatureHeaderArray) {
			params.put(key, headers.get(key));
		}
		params.putAll(body);
		return SignatureUtils.verifySign(appSecret, params, signature.toString());
	}
}
