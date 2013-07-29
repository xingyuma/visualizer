/**
 * @author: Xingyu Ma
 */

var CertificateEncoding = function(){
    this.certTime = null;
    this.certSubject = null;
    this.certKey = null;
    this.certExtension = null;
    
    this.setTime = function(time1,time2) {
        this.certTime = new CertificateTime(time1, time2);
    }
    
    this.addCertSubject = function(_oid,_string){
        if (this.certSubject == null) {
            this.certSubject = new CertificateSubject;
        }
        this.certSubject.add(_oid,_string);
    }
    
    this.setKey = function(algorithmName,keybit) {
        this.certKey = new CertificateKey(algorithmName,keybit);
    }
    
    this.getCert = function(){
        var output = new KJUR.asn1.DERSequence({'array':[this.certTime,
                                                         this.certSubject.getSubject(), this.certKey,
                                                         this.certExtension]});
        return output.getEncodedHex();
    }
    
    this.setCertExtension = function(_extnID,_critical,_extnValue) {
        this.certExtension = new CertficationExtension(_extnID,_critical,_extnValue);
    }
}

var CertificateTime = function(/*str*/time1, time2) {
    var t1 = new KJUR.asn1.x509.Time({'type': 'gen',  'str': time1});
    var t2 = new KJUR.asn1.x509.Time({'type': 'gen',  'str': time2});
    var seq1 = new KJUR.asn1.DERSequence({'array':[t1,t2]});
    return seq1;
    
};

var CertificateSubject = function() {
    this.subjectList = new Array();
    this.add = function(_oid,_string) {
        var id = new KJUR.asn1.DERObjectIdentifier({'oid':_oid});
        var string = new KJUR.asn1.DERPrintableString({'str':_string});
        this.subjectList.push(new KJUR.asn1.DERSequence({'array':[id,string]}));
    }
    this.getSubject = function(){
        return new  KJUR.asn1.DERSequence({'array':this.subjectList});
    }
};

var CertificateKey = function(/*str*/_algorithmName, keybit) {
    var algorithmName = new KJUR.asn1.x509.AlgorithmIdentifier({'name':_algorithmName});
    var keyBit = new KJUR.asn1.DERBitString();
    keybit = '00'+keybit;
    console.log(keybit);
    keyBit.setHexValueIncludingUnusedBits(keybit);
    //                console.log(keyBit);
    var seq3 = new KJUR.asn1.DERSequence({'array':[algorithmName, keyBit]});
    return seq3;
}

var CertficationExtension = function(_extnID,_critical,_extnValue) {
    var asn1Array = new Array();
    var extnid = new KJUR.asn1.DERObjectIdentifier({'oid':_extnID});
    asn1Array.push(extnid);
    if (_critical) {
        asn1Array.push(new KJUR.asn1.DERBoolean());
    }
    var asn1EncapExtnValue =
    new KJUR.asn1.DEROctetString({'hex': _extnValue});
    asn1Array.push(asn1EncapExtnValue);
    var asn1Seq = new KJUR.asn1.DERSequence({'array': asn1Array});
    return asn1Seq;
}
