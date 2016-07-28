import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationFailureHandler

import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.xml.parse.BasicParserPool
import org.opensaml.common.xml.SAMLConstants
import org.springframework.security.saml.SAMLAuthenticationProvider
import org.springframework.security.saml.SAMLProcessingFilter
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.SAMLBootstrap
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.processor.HTTPPostBinding
import org.springframework.security.saml.SAMLEntryPoint
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl
import org.springframework.security.saml.websso.WebSSOProfileImpl
import org.springframework.security.saml.websso.WebSSOProfileOptions
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler


beans = {

    def conf = SpringSecurityUtils.securityConfig
    if (!conf || !conf.active) { return }

    SpringSecurityUtils.loadSecondaryConfig 'DefaultSamlSecurityConfig'
    conf = SpringSecurityUtils.securityConfig
    if (!conf.saml.active) {
        return
    }

    SpringSecurityUtils.registerProvider 'samlAuthenticationProvider'

    def beansFile = "classpath:security/springSecuritySamlBeans.xml"
    println "Importing beans from ${beansFile}..."
    delegate.importBeans beansFile

    xmlns context:"http://www.springframework.org/schema/context"
    context.'annotation-config'()
    context.'component-scan'('base-package': "org.springframework.security.saml")


    parserPool(BasicParserPool)

    // Sets up the SAML Library
    bootStrap(SAMLBootstrap)

    postBinding(HTTPPostBinding, ref('parserPool'), ref('velocityEngine'))

    ssoCircleProvider(HTTPMetadataProvider, "http://idp.ssocircle.com/idp-meta.xml", 5000) { bean ->
        parserPool = ref('parserPool')
    }


    keyManager(JKSKeyManager,
        conf.saml.keyManager.storeFile, conf.saml.keyManager.storePass, conf.saml.keyManager.passwords, conf.saml.keyManager.defaultKey)

    metadata(CachingMetadataManager) { metadataBean ->

        // At this point, due to Spring DSL limitations, only one provider
        // can be defined so just picking the first one
        metadataBean.constructorArgs = [ref('ssoCircleProvider')]
        providers = [ref('ssoCircleProvider')]
    }

    // Setup the meta data generator
    metadataGenerator(MetadataGenerator) {
        entityId = "urn:test:dvisco:pittsburghpa"
        entityBaseURL = "http://localhost:8080"
        extendedMetadata = { ExtendedMetadata data ->
            signMetadata = false
            idpDiscoveryEnabled = false // Possibly set to false
        }
        bindingsSSO = [SAMLConstants.SAML2_POST_BINDING_URI]
        bindingsSLO = [] // Not supporting logout at this time
    }

    metadataGeneratorFilter(MetadataGeneratorFilter) { bean ->

        bean.constructorArgs = [ref('metadataGenerator')]
    }

    samlEntryPoint(SAMLEntryPoint) {
        filterProcessesUrl = "/saml/login"
        defaultProfileOptions = ref('webProfileOptions')
    }

    webProfileOptions(WebSSOProfileOptions) {
        includeScoping = false
        binding = SAMLConstants.SAML2_POST_BINDING_URI
//        forceAuthN = conf.saml.forceAuthN
    }

    webSSOprofile(WebSSOProfileImpl)

    samlLogger(SAMLDefaultLogger)

    contextProvider(SAMLContextProviderImpl)


    successRedirectHandler(SavedRequestAwareAuthenticationSuccessHandler) {
        alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
        defaultTargetUrl = "/v1/me"
    }

    samlWebSSOProcessingFilter(SAMLProcessingFilter) {
        filterProcessesUrl = "/saml/SSO"
        authenticationManager = ref('authenticationManager')
        authenticationSuccessHandler = ref('successRedirectHandler')
        authenticationFailureHandler = ref('authenticationFailureHandler')
    }

    authenticationFailureHandler(AjaxAwareAuthenticationFailureHandler) {
        redirectStrategy = ref('redirectStrategy')
        defaultFailureUrl = '/login/authfail?login_error=1'
        useForward = false
        ajaxAuthenticationFailureUrl = '/login/authfail?ajax=true'
        exceptionMappings = []
    }

    redirectStrategy(DefaultRedirectStrategy) {
        contextRelative = false
    }

    samlAuthenticationProvider(SAMLAuthenticationProvider) {
//        userDetails = ref('userDetailsService')
        hokConsumer = ref('webSSOprofileConsumer')
    }

    webSSOprofileConsumer(WebSSOProfileConsumerImpl){
        responseSkew = conf.saml.responseSkew
    }
}
