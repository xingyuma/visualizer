/*
 Author: Xingyu Ma
 
 */
var PolicyEntry = function PolicyEntry(_item, type){
    this.dataRegex = null;
    this.signerRegex = null;
    this.op = null;
    this.dataExpand = null;
    this.signerExpand = null;
    this.mustVerify = null;
    if (type == "xml") {
        var tmp = _item.getElementsByTagName("IdentityPolicy")[0];
        this.dataRegex = tmp.getElementsByTagName("DataRegex")[0].childNodes[0].nodeValue;
        this.signerRegex = tmp.getElementsByTagName("SignerRegex")[0].childNodes[0].nodeValue;
        this.op = tmp.getElementsByTagName("Op")[0].childNodes[0].nodeValue;
        this.dataExpand = tmp.getElementsByTagName("DataExpand")[0].childNodes[0].nodeValue;
        this.signerExpand = tmp.getElementsByTagName("SignerExpand")[0].childNodes[0].nodeValue;
        this.mustVerify = tmp.getElementsByTagName("MustVerify")[0].childNodes[0].nodeValue;
    }
    if (type == "array") {
        this.dataRegex = _item[0];
        this.signerRegex = _item[1];
        this.op = _item[2];
        this.dataExpand = _item[3];
        this.signerExpand = _item[4];
        this.mustVerify = _item[5];
    }
    this.topData = null;
    this.topSigner = null;
    this.backData= new BackRefManager();
    this.backSigner = new BackRefManager();
};

PolicyEntry.prototype.get = function(dataRegex, signerRegex,op,dataExpand, signerExpand, mustVerify) {
    this.dataRegex = dataRegex;
    this.signerRegex = signerRegex;
    this.op = op;
    this.dataExpand = dataExpand;
    this.signerExpand = signerExpand;
    this.mustVerify = mustVerify;
}

PolicyEntry.prototype.adjust = function (_str) {
    var s_array = _str.split("\\");
    var tmp = "";
    for (var i = 1; i < s_array.length; i++) {
        if (s_array[i] != "\\" && s_array[i] != "") {
            tmp += "\\\\";
            tmp += s_array[i];
        }
    }
    return tmp;
}

/*check syntex error or not*/
PolicyEntry.prototype.checkSyntex = function() {
    this.topData = new TopMatcher(this.dataRegex, this.backData);
    this.topSigner = new TopMatcher(this.signerRegex, this.backSigner);
    try {
        if (this.topData.compile() && this.topSigner.compile()){
            return true;
        }
    }
    catch(err) {
        return false;
    }
}

/*generate xml format for policies*/
PolicyEntry.prototype.generateXML = function() {
    var tmp = {};
    tmp["DataRegex"] = this.dataRegex;
    tmp["SignerRegex"] = this.signerRegex;
    tmp["Op"] = this.op;
    tmp["DataExpand"] = this.adjust(this.dataExpand);
    tmp["SignerExpand"] = this.adjust(this.signerExpand);
    tmp["MustVerify"] = this.mustVerify;
    var id = {};
    id["IdentityPolicy"] = tmp;
    var tt = new X2JS();
    return (tt.json2xml_str(id));
}

/**/
PolicyEntry.prototype.checkMatching = function(_name,_keyLocator){
    if (this.mustVerify == "0") {
        return true;
    } else {
        if (this.topData.match(_name, 0,_name.components.length)) {
            if (this.topSigner.match(_keyLocator, 0, _keyLocator.components.length)) {
                var dataE = new Name(this.topData.expand(this.dataExpand));
                var signerE = new Name(this.topSigner.expand(this.signerExpand));
                if (this.op == ">=") {
                    if (signerE.isPrefixOf(dataE)) {
                        return true;
                    }
                }
                if (this.op == "==") {
                    if (signerE.equals(dataE))
                        return true;
                }
                if (this.op == "**") {
                    return true;
                }
            }
        }        
    }
    return false;
};

var Policy = function() {
    this.PolicyStore = new Array();
    
    this.addPolicyEntry = function(policyEntry) {
//        alert(policyEntry.prefix);
        if (policyEntry.checkSyntex()) {
            var result = this.getPolicyByPrefix(policyEntry.dataRegex);
            if (result == null)
                this.PolicyStore.push(policyEntry);
            else
                result = policyEntry;
        }
        else {
            console.log("syntex error");
        }
    };
    
    /*exact match*/
    this.getPolicyByPrefix = function(/*dataRegex*/ _dataRegex){
        var result = null;
        for (var i = 0; i < this.PolicyStore.length; i++) {
            if (this.PolicyStore[i].dataRegex == _dataRegex) {
                    result = this.PolicyStore[i];
            }
        }
        return result;
    };
    
    this.verify = function(name, keyLocator){
        for (var i = 0; i < this.PolicyStore.length; i++) {
            if (this.PolicyStore[i].checkMatching(new Name(name),new Name(keyLocator)))
                return true;
        }
        return false;
    };
    
    /*getAuthority is used for role-based not usable for identiy-certificate*/
    this.getAuthority = function(_name) {
        var result = new Array();
        for (var i = 0; i < this.PolicyStore.length; i++) {
            if (this.PolicyStore[i].prefixMatching(_name)) {
//                console.log("match  "+this.PolicyStore[i].prefix+"  "+_name);
                result.push(this.PolicyStore[i]);
            }
        }
        return result;
    }
};


var CertificateStore = function(){
    this.store = new Array();
    this.size  = 1000;
};

/*certificate store is a fifo, set the fifo size*/
CertificateStore.prototype.setSize = function (_size) {
    this.size = _size;
}

CertificateStore.prototype.findType = function(/*str*/ _name) {
    if (_name.match("ID-CERT") != null){
        return "ID-CERT";
    }
    if (_name.match("CAP-CERT") != null){
        return "CAP-CERT";
    }
};

CertificateStore.prototype.addCertificateEntry = function(certificateEntry) {
    nameStr = certificateEntry.name.to_uri();
    if (! (this.findType(nameStr) == "ID-CERT" ||
           this.findType(nameStr) == "CAP-CERT")) {
        return;
    }
    var result = this.getCertificateByName(certificateEntry.name.to_uri());
    if (result == null)
        this.store.push(certificateEntry);
    else
        result = certificateEntry;
    if (this.store.length > this.size) {
        this.store.shift();
    }
};

CertificateStore.prototype.getCertificateByName = function(/*str*/name){
    var result = null;
    for (var i = 0; i < this.store.length; i++) {
        if (this.store[i].name.to_uri() == name) {
            result = this.store[i];
            break;
        }
    }
    return result;
};

