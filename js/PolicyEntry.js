
var PolicyEntry = function PolicyEntry(_item){
	this.prefix = null;
	this.authority = null;
	if (typeof _item == 'string') {
		if (this.findType(_item) == "ID-CERT") {
			var array = _item.split(':');
			this.prefix = (array[0]);
//            if (this.prefix.charAt(this.prefix.length-1) != "/")
//                this.prefix = this.prefix.concat("/");
			this.authority = (array[1]);
		}	
	}
};

PolicyEntry.prototype.findType = function(_item){
	if (_item.match("ID-CERT") != null){
		return "ID-CERT";
	}
	if (_item.match("CAP-CERT") != null){
		return "CAP-CERT";
	}
};

PolicyEntry.prototype.checkMatching = function(name,keyLocator){
    var nameObject = new Name(name);
    var locatorObject = new Name(keyLocator);
    prefixObj = new Name(this.prefix);
    authorityObj = new Name(this.authority);
    console.log(keyLocator);
    console.log(this.authority);
    if (prefixObj.matches(nameObject) == true  && locatorObject.equals(authorityObj)){
		return true;
	}
};

function Policy() {
    this.PolicyStore = new Array();
    
    this.addPolicyEntry = function(policyEntry) {
//        alert(policyEntry.prefix);
        var result = this.getPolicyByPrefix(policyEntry.prefix);
        if (result == null)
            this.PolicyStore.push(policyEntry);
        else
            result = policyEntry;
    };
    
    this.getPolicyByPrefix = function(/*prefix for policy*/ prefix){
        var result = null;
        for (var i = 0; i < this.PolicyStore.length; i++) {
            if (this.PolicyStore[i].prefix == prefix) {
                if (result == null || this.PolicyStore[i].prefix.length > result.length)
                    result = this.PolicyStore[i];
            }
        }
        return result;
    };
    
    this.verify = function(name, keyLocator){
        for (var i = 0; i < this.PolicyStore.length; i++) {
//            console.log(this.PolicyStore[i].prefix+"   "+this.PolicyStore[i].authority);
            if (this.PolicyStore[i].checkMatching(name,keyLocator))
                return true;
        }
        return false;
    };
};

function CertificateStore(){
    this.store = new Array();
    
    this.findType = function(/*str*/ _name) {
        if (_name.match("ID-CERT") != null){
            return "ID-CERT";
        }
        if (_name.match("CAP-CERT") != null){
            return "CAP-CERT";
        }
    };
    
    this.addCertificateEntry = function(certificateEntry) {
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
    };
    
    this.getCertificateByName = function(/*str*/name){
        var result = null;
        for (var i = 0; i < this.store.length; i++) {
            if (this.store[i].name.to_uri() == name) {
                result = this.store[i];
                break;
            }
        }
        return result;
    };
}


var IdentityVerifySingleton= (function () {
    var instance;
    function createInstance() {
                 var object = new IdentityVerify();
                 return object;
    }
    return {
                 getInstance: function () {
                 if (!instance) {
                              instance = createInstance();
                 }
                 
                 return instance;
                 }
            };
})();

function IdentityVerify() {
    
    this.trusted = new Name("/aa/ID-CERT");
    this.chain = new Array();
    this.certificateStore = new CertificateStore();
    this.findFlag = false;
    this.policy = null;
    
    
    this.obtainChain = function(name, policy){
        this.chain = [];
        this.policy = policy;
        this.fetch(name);
    };
    
    this.fetch = function(/*str*/name) {
      console.log("fetch  "+name);
        content  = this.certificateStore.getCertificateByName(name);
        if (content != null){
//            console.log(content.name.to_uri());
            this.receive(content);
        }
        else {
 //           console.log("there");
            var n = new Name(name);
            var template = new Interest();
            template.answerOriginKind = Interest.ANSWER_NO_CONTENT_STORE;
            template.interestLifetime = 1000;
            ndn.expressInterest(n, template, onData, onTimeout);
            console.log('Interest expressed.');
//            ndn.expressInterest(new Name(name), new AsyncGetClosure());
        }
    };
    
    this.output = function(id) {
        for (var i = 0; i < this.chain.length; i++) {
            document.getElementById(id).innerHTML += "<p>Name string: " + this.chain[i].name.to_uri()+ "</p>";
            document.getElementById(id).innerHTML += "<p>Signer string: " + this.chain[i].signedInfo.locator.keyName.name.to_uri()+ "</p>";
        }
    };
    
    this.verifySigning = function(content, key) {
        return content.verify(key);
    }
    
    this.receive = function(content) {
//        console.log(content);
        nameStr = escape(content.name.to_uri());
        keyName = content.signedInfo.locator.keyName.name.to_uri();
        console.log("name: "+nameStr);
        console.log("keyname: "+keyName);
        issuerName = new Name(nameStr);
        
        if (this.chain.length >= 1) {
            chainLast = this.chain[this.chain.length - 1];
            var key = new Key();
            key.publicKeyPem = DataUtils.toString(chainLast.content);
            key.publicToDER();
            if (!chainLast.verify(key)) {
                console.log("signing error");
                return false;
            }
        }
        
        this.chain.push(content);
        this.certificateStore.addCertificateEntry(content);
        
        if (issuerName.equals(this.trusted)){
            this.findFlag = true;
            this.output('result');
            return true;
        }
        else{
            if (!this.policy.verify(nameStr, keyName)) {
                console.log("policy error");
                return false;
            }
            this.fetch(keyName);
        }        
    };
};

var CapabilityVerifySingleton= (function () {
    var instance;
    function createInstance() {
        var object = new CapabilityVerify();
        return object;
    }
    return {
        getInstance: function () {
            if (!instance) {
                    instance = createInstance();
            }
                              
            return instance;
        }
    };
})();

function CapabilityVerify() {
    
    this.trusted = new Name("/aa/ID-CERT");
    this.chain = new Array();
    this.certificateStore = new CertificateStore();
    this.findFlag = false;
    this.policy = null;
    this.oriName = null;
    
    var ndn = new NDN({host:"127.0.0.1"});
    console.log("1");
    ndn.connect();
    console.log("2");
    ndn.onopen = function (name) {
        console.log("3");
        console.log(ndn.ready_status);
        var n = new Name(name);
        var template = new Interest();
        template.answerOriginKind = Interest.ANSWER_NO_CONTENT_STORE;  // bypass cache in ccnd
        template.interestLifetime = 1000;
        ndn.expressInterest(n, template, onData, onTimeout);
        console.log('Interest expressed.');
    };
    
    var onData = function (interest, content) {
        var instance = CapabilityVerifySingleton.getInstance();
        instance.receive(content);
    };
    
    var onTimeout = function (interest) {
        console.log("Interest time out.");
        console.log('Interest name: ' + interest.name.to_uri());
        //    ndn.close();
    };
 
    this.obtainChain = function(name, policy){
        this.chain = [];
        this.policy = policy;
        this.oriName = name;
        this.fetch(name);
    };
    
    this.fetch = function(/*str*/name) {
        console.log("fetch  "+name);
        content  = this.certificateStore.getCertificateByName(name);
        if (content != null){
            this.receive(content);
        }
        else {
/*            var n = new Name(name);
            var template = new Interest();
            template.answerOriginKind = Interest.ANSWER_NO_CONTENT_STORE;
            template.interestLifetime = 1000;
            ndn.expressInterest(n, template, onData, onTimeout);
            console.log('Interest expressed.');
 */          ndn.onopen(name);
        }
    };
    
    this.output = function(id) {
        for (var i = 0; i < this.chain.length; i++) {
            document.getElementById(id).innerHTML += "<p>Name string: " + this.chain[i].name.to_uri()+ "</p>";
            document.getElementById(id).innerHTML += "<p>Signer string: " + this.chain[i].signedInfo.locator.keyName.name.to_uri()+ "</p>";
        }
    };
    
    this.getNameSpace = function(/*str*/_name){
        ret = new Name(_name);
        if (_name.match("CAP-CERT") != null) {
            var array = _name.split('CAP-CERT');
            tmp = new Name(array[1]);
            return tmp.getPrefix(tmp.size() -1);
        }
        if (_name.match("ID-CERT") != null) {
            var array = _name.split('ID-CERT');
            tmp = new Name(array[0]);
            return tmp;
        }
        return ret;
    };
  
    this.checkDelegation = function(nameStr,keyName) {
       if (this.getNameSpace(keyName).isPrefixOf(this.getNameSpace(nameStr))){
            return true;
        }
        return false;
    };

    this.receive = function(content) {
        console.log(content);
        nameStr = escape(content.name.to_uri());
        console.log("name: "+nameStr);
        keyName = content.signedInfo.locator.keyName.name.to_uri();
        console.log("keyname: "+keyName);
        issuerName = new Name(nameStr);
        
        this.chain.push(content);
        this.certificateStore.addCertificateEntry(content);
        
        if (!this.checkDelegation(nameStr,keyName)) {
            console.log("delegation error");
            return false;
        }
        
        if (this.chain.length >= 1) {
            chainLast = this.chain[this.chain.length - 1];
            var key = new Key();
            key.publicKeyPem = DataUtils.toString(chainLast.content);
            key.publicToDER();
//            console.log("signing  "+chainLast.verify(key));
            if (!chainLast.verify(key)) {
                console.log("signing error");
                return false;
            }
        }
        
        if (content.name.equals(content.signedInfo.locator.keyName.name)) {
            if (this.policy.verify(this.oriName, nameStr)){
                this.findFlag = true;
                this.output('result');
                return true;
            }
        }
        else{
            this.fetch(keyName);
        }        
    };
    

    
};


/*


var ndn = new NDN({host:"127.0.0.1"});
ndn.connect();


var onData = function (interest, content) {
//    var content = upcallInfo.contentObject;
    var instance = IdentityVerifySingleton.getInstance();
    instance.receive(content);
};

var onTimeout = function (interest) {
    console.log("Interest time out.");
    console.log('Interest name: ' + interest.name.to_uri());
    ndn.close();
};

*/

