import org.opensaml.Configuration
import org.opensaml.xml.io.Marshaller
import org.opensaml.xml.io.MarshallerFactory
import org.opensaml.xml.io.MarshallingException
import org.opensaml.xml.util.XMLHelper
import org.w3c.dom.Element

class BootStrap {

    def metadata

    def init = { servletContext ->

//        println("Printing sp provider docs...")
//        println(getMetadataAsString(metadata.getEntityDescriptor("urn:test:dvisco:pittsburghpa")))

    }
    def destroy = {
    }


    protected def getMetadataAsString(entityDescriptor) throws MarshallingException {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory()
        Marshaller marshaller = marshallerFactory.getMarshaller(entityDescriptor)
        Element element = marshaller.marshall(entityDescriptor)
        return XMLHelper.nodeToString(element)
    }
}