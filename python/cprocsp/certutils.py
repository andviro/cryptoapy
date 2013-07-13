# coding: utf-8
from __future__ import unicode_literals, print_function
import csp
from pyasn1.type import univ, useful, char, tag, constraint
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459
from base64 import b64decode
from datetime import datetime


class CertAttribute(object):
    """Атрибут запроса на сертификат

    в закодированном виде добавляется в запрос методом
    CertRequest.add_attribute()
    """
    def __init__(self, oid, values):
        """@todo: to be defined """
        self.oid = oid
        self.vals = [encoder.encode(v) for v in values]

    def add_to(self, req):
        n = req.add_attribute(self.oid)
        for v in self.vals:
            req.add_attribute_value(n, v)


class CertValidity(CertAttribute):
    """Атрибут для установки интервала действия серта в запросе"""

    def __init__(self, not_before, not_after):
        """@todo: to be defined """
        val = univ.Sequence()
        for i, x in enumerate((not_before, not_after)):
            val.setComponentByPosition(i, useful.UTCTime(bytes(x.strftime('%y%m%d%H%M%SZ'))))
        super(CertValidity, self).__init__(b'1.2.643.2.4.1.1.1.1.2', [val])


class CertExtensions(CertAttribute):
    """Атрибут для задания расширений сертификата"""

    def __init__(self, exts):
        """@todo: to be defined """
        val = univ.SequenceOf()
        for i, ext in enumerate(exts):
            val.setComponentByPosition(i, ext.asn)
        super(CertExtensions, self).__init__(csp.szOID_CERT_EXTENSIONS, [val])


class CertExtension(object):
    def __init__(self, oid, value, critical=False):
        """Общий класс для всех видов расширений

        :oid: OID расширения
        :value: значение в ASN.1

        """
        self.asn = rfc2459.Extension()
        self.asn.setComponentByName(b'extnID', univ.ObjectIdentifier(oid))
        self.asn.setComponentByName(b'critical', univ.Boolean(bool(critical)))
        self.asn.setComponentByName(b'extnValue', univ.OctetString(value))


class EKU(CertExtension):
    """Расширенное использование ключа"""

    def __init__(self, ekus):
        """Создание EKU

        :ekus: список OID-ов расш. использования

        """
        val = rfc2459.ExtKeyUsageSyntax()
        for i, x in enumerate(ekus):
            val.setComponentByPosition(i, rfc2459.KeyPurposeId(x))
        super(EKU, self).__init__(csp.szOID_ENHANCED_KEY_USAGE, encoder.encode(val))


class KeyUsage(CertExtension):
    """Расширенное использование ключа"""

    def __init__(self, mask):
        """Создание EKU

        :ekus: список OID-ов расш. использования

        """
        val = rfc2459.KeyUsage(bytes(','.join(mask)))
        super(KeyUsage, self).__init__(csp.szOID_KEY_USAGE, encoder.encode(val))


class Attributes(object):
    """Набор пар (тип, значение)"""

    def __init__(self, attrs):
        self.asn = rfc2459.Name()
        vals = rfc2459.RDNSequence()

        for (i, (oid, val)) in enumerate(attrs):
            pair = rfc2459.AttributeTypeAndValue()
            pair.setComponentByName('type', rfc2459.AttributeType(bytes(oid)))
            pair.setComponentByName('value',
                                    rfc2459.AttributeValue(
                                        univ.OctetString(encoder.encode(char.UTF8String(unicode(val).encode('utf-8'))))))

            pairset = rfc2459.RelativeDistinguishedName()
            pairset.setComponentByPosition(0, pair)

            vals.setComponentByPosition(i, pairset)

        self.asn.setComponentByPosition(0, vals)

    def encode(self):
        return encoder.encode(self.asn)

    @staticmethod
    def decode(value):
        asn = decoder.decode(value, asn1Spec=rfc2459.Name())[0]
        res = []
        for rdn in asn[0]:
            item = []
            for dn in rdn:
                oid = unicode(dn[0])
                value = decoder.decode(dn[1])[0]
                if value.__class__.__name__ == 'UTF8String':
                    value = unicode(bytes(value), 'utf-8')
                else:
                    value = unicode(bytes(value), 'cp1251')
                item.append((oid, value))
            if len(item) != 1:
                res.append(item)
            else:
                res.append(item[0])
        return res


class SubjectAltName(CertExtension):
    """Расширенное использование ключа"""

    # namedtype.NamedType('otherName', AnotherName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    # namedtype.NamedType('x400Address', ORAddress().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    # namedtype.NamedType('ediPartyName',
    # EDIPartyName().subtype(implicitTag=tag.Tag(tag.tagClassContext,
    # tag.tagFormatSimple, 5))),

    def rfc822Name(self, st):
        '''
        :st: строка с именем

        '''
        return unicode(st).encode('cp1251', 'replace')

    dNSName = rfc822Name
    uniformResourceIdentifier = rfc822Name
    iPAddress = rfc822Name
    registeredID = rfc822Name

    def directoryName(self, rdn):
        '''
        :rdn: [(OID, value), (OID, value) ...]

        '''
        elt = rfc2459.Name().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))
        elt.setComponentByName('', Attributes(rdn).asn[0])
        return elt

    def __init__(self, altnames):
        """Создание AltName

        :altnames: список вида [(тип, значение), (тип, значение), ]
            где значение в зависимости от типа:
                    'directoryName' : [('OID', 'строка'), ...]
                    'dNSName' : строка
                    'uniformResourceIdentifier' : строка
                    'iPAddress' : строка
                    'registeredID' : строка

        """
        val = rfc2459.SubjectAltName()
        for (i, (t, v)) in enumerate(altnames):
            gn = rfc2459.GeneralName()
            elt = getattr(self, t, None)
            if elt is None:
                assert False, 'unsupported element type {0}'.format(t)
            gn.setComponentByName(t, elt(v))
            val.setComponentByPosition(i, gn)

        super(SubjectAltName, self).__init__(rfc2459.id_ce_subjectAltName, encoder.encode(val))


class CertificatePolicies(CertExtension):
    def __init__(self, policies):
        '''создане CertificatePolicies

        :policies: список вида [(OID, [(квалификатор, значение), ...]), ... ]
            OID - идент-р политики
            квалификатор - OID
            значение - произвольная информация в base64

        '''
        pass
        val = rfc2459.CertificatePolicies()
        for (i, (t, v)) in enumerate(policies):
            pol = rfc2459.PolicyInformation()
            pol.setComponentByPosition(0, rfc2459.CertPolicyId(t))
            if len(v):
                sq = univ.SequenceOf(componentType=rfc2459.PolicyQualifierInfo()
                                     ).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, rfc2459.MAX))
                for n, (ident, qualif) in enumerate(v):
                    pqi = rfc2459.PolicyQualifierInfo()
                    pqi.setComponentByPosition(0, rfc2459.PolicyQualifierId(ident))
                    pqi.setComponentByPosition(1, univ.OctetString(b64decode(qualif)))
                    sq.setComponentByPosition(n, pqi)
                pol.setComponentByPosition(1, sq)
            val.setComponentByPosition(i, pol)
        super(CertificatePolicies, self).__init__(rfc2459.id_ce_certificatePolicies,
                                                  encoder.encode(val))


if __name__ == '__main__':
    # from pyasn1_modules.rfc2459 import id_qt_unotice as unotice, id_qt_cps as cps
    # test = CertificatePolicies([(unotice, []), (cps, [(cps, b64encode(b"alsdk"))])])
    data = open('../examples/cer_test.cer', 'rb').read()
    #cert = decoder.decode(data, asn1Spec=rfc2459.Certificate())[0]
    #print(cert.prettyPrint())
    ci = csp.CertInfo(csp.Cert(data))
    xx = Attributes.decode(ci.issuer(False))
    print(xx)

