import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.SecurityFilterPosition

import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.xml.parse.BasicParserPool

import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.SAMLBootstrap
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.processor.HTTPPostBinding




beans = {

    def conf = SpringSecurityUtils.securityConfig
    if (!conf || !conf.active) { return }

    SpringSecurityUtils.loadSecondaryConfig 'DefaultSamlSecurityConfig'
    conf = SpringSecurityUtils.securityConfig
    if (!conf.saml.active) {
        return
    }

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

    metadataGenerator(MetadataGenerator) {
        entityId = "urn:test:dvisco:pittsburghpa"
        extendedMetadata = { ExtendedMetadata data ->
            signMetadata = false
            idpDiscoveryEnabled = true // Possibly set to false
        }
    }

    metadataGeneratorFilter(MetadataGeneratorFilter) { bean ->

        bean.constructorArgs = [ref('metadataGenerator')]
    }
}
