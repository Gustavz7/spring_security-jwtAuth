package com.demo.demo.jwt.Auth;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.demo.demo.jwt.models.user.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	Logger logger = LoggerFactory.getLogger(getClass());

	@Autowired
	private Environment environment;

	public String getToken(UserDetails user) {
		return getToken(new HashMap<>(), user);
	}

	private String getToken(Map<String, User> extraClaims, UserDetails user) {
		return Jwts.builder().setClaims(extraClaims).setSubject(user.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
				.signWith(getKey(), SignatureAlgorithm.HS256).compact();
	}

	private Key getKey() throws IllegalArgumentException {
		final String secret_key = environment.getProperty("custom.jwt.secret.key");
		if (secret_key == null) {
			throw new IllegalArgumentException("the secret key to sign jwt token not found in application.properties");
		}
		byte[] keyByte = Decoders.BASE64.decode(secret_key);
		return Keys.hmacShaKeyFor(keyByte);
	}

	public String getUsernameFromToken(String token) {
		return getClaims(token, Claims::getSubject);
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		final boolean isValid = username.equals(userDetails.getUsername()) && isTokenExpired(token);
		logger.info("token valid? = {}", isValid);
		return isValid;
	}

	private Claims getAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getKey()).build().parseClaimsJws(token).getBody();
	}

	public <T> T getClaims(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaims(token);
		return claimsResolver.apply(claims);
	}

	private Date getExpirationDate(String token) {
		return getClaims(token, Claims::getExpiration);
	}

	private boolean isTokenExpired(String token) {
		return getExpirationDate(token).after(new Date());
	}

}
