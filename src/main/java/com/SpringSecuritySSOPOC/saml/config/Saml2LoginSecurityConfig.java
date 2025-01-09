package com.SpringSecuritySSOPOC.saml.config;


import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.*;
import org.springframework.security.web.SecurityFilterChain;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_ASSERTION;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_IN_RESPONSE_TO;
import static org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType.DECRYPTION;
import static org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType.SIGNING;

@Configuration
@EnableWebSecurity
public class Saml2LoginSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(Saml2LoginSecurityConfig.class);
    @SuppressWarnings("HttpUrlsUsage")
    private static final String ROLES_SAML_ATTRIBUTE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
    private static final String USER_NAME_SAML_ATTRIBUTE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    private static final String VERSION = "/version/*";

    @Value("${environment.name}")
    private String ENVIRONMENT_NAME;

    @Value("${backend.url}")
    private String BASE_URL;

    @Value("${saml.decryption.certificate}")
    private String SAML_DECRYPTION_CERTIFICATE;
    
    @Value("${saml.signing.key}")
    private String SAML_SIGNING_KEY;

    @Value("${saml.idp.metadata-url}")
    private String IDP_METADATA_URL;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        OpenSaml4AuthenticationProvider customOpenSaml4AuthenticationProvider = new OpenSaml4AuthenticationProvider();
        customOpenSaml4AuthenticationProvider.setResponseValidator(removeInResponseToError());
        customOpenSaml4AuthenticationProvider.setAssertionValidator(removeAssertionError());
        customOpenSaml4AuthenticationProvider.setResponseAuthenticationConverter(responseToken -> {
            Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                    .createDefaultResponseAuthenticationConverter()
                    .convert(responseToken);
            try {
                Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
                List<String> roles = principal.getAttribute(ROLES_SAML_ATTRIBUTE);
                List<GrantedAuthority> authorities = new ArrayList<>();

                if (roles != null) {
                    for (String role : roles) {
                        String[] permissions = role.split(",");
                        for (String permission : permissions) {
                            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(permission);
                            if (!authorities.contains(authority)) {
                                authorities.add(new SimpleGrantedAuthority(permission));
                            }
                        }
                    }
                }
                logger.info("Logged in user: {} with mapped authorities: {}",principal.getAttribute(USER_NAME_SAML_ATTRIBUTE), authorities);
                return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);

            } catch (NullPointerException e) {
                logger.error("Error while parsing SAML attributes: {}", e.getMessage());
                throw new AuthenticationException("Error while parsing SAML attributes") {
                };
            }
        });

        http
            .csrf(AbstractHttpConfigurer::disable) // for Postman
            .authorizeHttpRequests(requests -> requests
                // Permit for swagger
                // .requestMatchers("/actuator/*/*").permitAll()
                .requestMatchers("/v3/api-docs/**").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/swagger-resources/**").permitAll()

                // for SAML
                .requestMatchers("/saml2/**").permitAll()
                .requestMatchers("/login/saml2/**").permitAll()
                .requestMatchers("/logout/saml2/**").authenticated()

                // Permit OPTIONS for CORS preflight
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                .requestMatchers("/index").authenticated()
                .requestMatchers("/index.html").authenticated()
                .requestMatchers("/").authenticated()
                .requestMatchers("/favicon.ico").authenticated()
                .anyRequest().denyAll()
            )
            .exceptionHandling(customExceptionConfig -> customExceptionConfig
                .authenticationEntryPoint((request, response, authException) -> {
                    if (request.getRequestURI().contains("/saml2/")) {
                        // Let SAML auth proceed
                        response.setStatus(HttpServletResponse.SC_OK);
                    } else {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    }
                })
            )
            .saml2Login(Customizer.withDefaults())
                //.saml2Logout()
            .authenticationManager(new ProviderManager(customOpenSaml4AuthenticationProvider));

        return http.build();
    }

    private Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult>
    removeAssertionError() {
        logger.debug("**remove assertion error from  Saml2ResponseValidatorResult Errors**");
        Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult>
                delegate = OpenSaml4AuthenticationProvider.createDefaultAssertionValidator();
        return assertionToken -> {
            logger.debug("responseToken : {}", assertionToken.getToken().getSaml2Response());
            Saml2ResponseValidatorResult result = delegate.convert(assertionToken);
            if (!result.hasErrors()){
                return Saml2ResponseValidatorResult.success();
            }
            result
                    .getErrors()
                    .forEach(
                            error ->
                                    logger.debug(
                                            " error code :{} and description :{}",
                                            error.getErrorCode(),
                                            error.getDescription()));
            Collection<Saml2Error> errors =
                    result.getErrors().stream()
                            .filter((error) -> !error.getErrorCode().equals(INVALID_ASSERTION))
                            .collect(Collectors.toList());
            return Saml2ResponseValidatorResult.failure(errors);
        };
    }

    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult>
    removeInResponseToError() {
        logger.debug("**remove InResonseTo error from  Saml2ResponseValidatorResult Errors**");
        Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult>
                delegate = OpenSaml4AuthenticationProvider.createDefaultResponseValidator();
        return responseToken -> {
            logger.debug("responseToken : {}", responseToken.getToken().getSaml2Response());
            Saml2ResponseValidatorResult result = delegate.convert(responseToken);
            if (!result.hasErrors()){
                return Saml2ResponseValidatorResult.success();
            }
            result.getErrors().forEach(error -> logger.debug(
                                            " error code :{} and description :{}",
                                            error.getErrorCode(),
                                            error.getDescription()));
            Collection<Saml2Error> errors =
                    result.getErrors().stream().filter((error) -> !error.getErrorCode().equals(INVALID_IN_RESPONSE_TO))
                            .collect(Collectors.toList());
            return Saml2ResponseValidatorResult.failure(errors);
        };
    }



    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws Exception {
        PrivateKey privateKey = loadPrivateKey(SAML_SIGNING_KEY);
        X509Certificate certificate = loadCertificate(SAML_DECRYPTION_CERTIFICATE);

        Saml2X509Credential signingCredential = new Saml2X509Credential(privateKey, certificate, SIGNING, DECRYPTION);

        String entityId;
        String assertionConsumerServiceLocation;
        if (List.of("local", "test").contains(ENVIRONMENT_NAME)) {
            //default values
            entityId = "{baseUrl}/saml2/service-provider-metadata/azure-ad";
            assertionConsumerServiceLocation = "{baseUrl}/login/saml2/sso/{registrationId}";
        } else {
            //override needed for kubernetes
            entityId = BASE_URL + "/saml2/service-provider-metadata/azure-ad";
            assertionConsumerServiceLocation = BASE_URL + "/login/saml2/sso/{registrationId}";
        }
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation(IDP_METADATA_URL)
                .entityId(entityId)
                .registrationId("azure-ad")
                .assertionConsumerServiceLocation(assertionConsumerServiceLocation)
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                .signingX509Credentials(c -> c.add(signingCredential))
                .decryptionX509Credentials(c -> c.add(signingCredential))
                .build();
        logger.info("Relying party registration : {}", relyingPartyRegistration.toString());

        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

public RSAPrivateKey loadPrivateKey(String key) throws Exception {
        key = key.replace("\\n", Character.toString(10));
       InputStream inputStream = new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8));
    return RsaKeyConverters.pkcs8().convert(inputStream);
}
public X509Certificate loadCertificate(String cert) throws Exception {
    cert = cert.replace("\\n", Character.toString(10));
    InputStream inputStream = new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8));
    return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
}
}