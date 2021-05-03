package eu.vabavara.synapse.mediators.authentication;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseLog;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

public class JWTValidatorMediator extends AbstractMediator { 
	private static final String ERROR_MESSAGE = "ERROR_MESSAGE";
	private static final String HTTP_SC = "HTTP_SC";

	/**
	 * Address of URL of keys.
	 */
	private String jwksUrl = null;
	/**
	 * Access token to verify.
	 */
	private String accessToken = null;
	
	/**
	 * Stores validation result. true for pass, false for fail.
	 */
	private boolean validationResult = false;

	public boolean mediate(MessageContext context) {
		SynapseLog log = getLog(context);
		boolean isTraceOn = log.isTraceEnabled();
		boolean isTraceOrDebugOn = log.isTraceOrDebugEnabled();
		
		if(isTraceOrDebugOn) {
			log.traceOrDebug("Started: OIDC mediator");
		}
		
		try {
			// The HttpsJwks retrieves and caches keys from a the given HTTPS JWKS endpoint.
			// Because it retains the JWKs after fetching them, it can and should be reused
			// to improve efficiency by reducing the number of outbound calls the the
			// endpoint.
			HttpsJwks httpsJkws = new HttpsJwks(this.getJwksUrl());

			// The HttpsJwksVerificationKeyResolver uses JWKs obtained from the HttpsJwks
			// and will select the
			// most appropriate one to use for verification based on the Key ID and other
			// factors provided
			// in the header of the JWS/JWT.
			HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

			// Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
			// be used to validate and process the JWT.
			// The specific validation requirements for a JWT are context dependent,
			// however,
			// it typically advisable to require a (reasonable) expiration time, a trusted
			// issuer, and
			// and audience that identifies your system as the intended recipient.
			// If the JWT is encrypted too, you need only provide a decryption key or
			// decryption key resolver to the builder.
			JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder().setRequireExpirationTime() // the JWT must have an
																							// expiration time
					.setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account
														// for clock skew
					.setVerificationKeyResolver(httpsJwksKeyResolver) // verify the signature with the public key
					.setSkipDefaultAudienceValidation() // do not verifyy audience
					.setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
							ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256); // which is only RS256 here
					
			JwtConsumer jwtConsumer = jwtConsumerBuilder.build();// create the JwtConsumer instance

			try {
				// Validate the JWT and process it to the Claims
				JwtClaims jwtClaims = jwtConsumer.processToClaims(accessToken);
				if(isTraceOrDebugOn)
					log.traceOrDebug("JWT validation succeeded! " + jwtClaims);
			} catch (InvalidJwtException e) {
				// InvalidJwtException will be thrown, if the JWT failed processing or
				// validation in anyway.
				// Hopefully with meaningful explanations(s) about what went wrong.
				log.auditLog("Invalid JWT! " + e);

				// Programmatic access to (some) specific reasons for JWT invalidity is also
				// possible
				// should you want different error handling behavior for certain conditions.

				// Whether or not the JWT has expired being one common reason for invalidity
				if (e.hasExpired()) {
					context.setProperty(ERROR_MESSAGE, "Access token has expired!");
				}
				context.setProperty(HTTP_SC, "401");

				this.setValidationResult(false);
				return true;
			}

			if(isTraceOrDebugOn) {
				log.traceOrDebug("End: OIDC mediator");
			}
			this.setValidationResult(true);
			return true;
		} catch (Exception e) {
			log.error("Error occurred while processing the message");
			context.setProperty(ERROR_MESSAGE, "Failed to process the access token.");
			if(isTraceOrDebugOn) {
				log.traceOrDebug(e);	
			}
			this.setValidationResult(false);
			return false;
		}
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getJwksUrl() {
		return jwksUrl;
	}

	public void setJwksUrl(String jwksUrl) {
		this.jwksUrl = jwksUrl;
	}

	public boolean isValidationResult() {
		return validationResult;
	}

	public void setValidationResult(boolean validationResult) {
		this.validationResult = validationResult;
	}

	
}
