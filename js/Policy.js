/*
 Author: Xingyu Ma
 
 */
var PolicyEntry = function PolicyEntry(_item){
	this.prefix = null;
	this.authority = null;
	if (typeof _item == 'string') {
//		if (this.findType(_item) == "ID-CERT") {
			var array = _item.split(':');
			this.prefix = (array[0]);
			this.authority = (array[1]);
//		}
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

PolicyEntry.prototype.prefixMatching = function(name){
    var nameObject = new Name(name);
    prefixObj = new Name(this.prefix);
    if (prefixObj.matches(nameObject) == true){
		return true;
	}    
}

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
    
    /*exact match*/
    this.getPolicyByPrefix = function(/*prefix for policy*/ prefix){
        var result = null;
        for (var i = 0; i < this.PolicyStore.length; i++) {
            if (this.PolicyStore[i].prefix == prefix) {
//                if (result == null || this.PolicyStore[i].prefix.length > result.length)
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
    
    /*getAuthority is used for role-based*/
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
    
    this.oriName;
    //    this.expressName = null;
    
    var ndn = new NDN({host:"127.0.0.1"});

    ndn.connect();

    ndn.onopen = function () {
        console.log("onopen called");
        var instance = IdentityVerifySingleton.getInstance();
        instance.fetch(instance.oriName);
    };
    
    var onData = function (interest, content) {
        var instance = IdentityVerifySingleton.getInstance();
        instance.receive(content);
    };
    
    var onTimeout = function (interest) {
        console.log("Interest time out.");
        console.log('Interest name: ' + interest.name.to_uri());
        //    ndn.close();
    };
    
    this.init = function(name,policy){
        this.chain = [];
        this.oriName = name;
        this.policy = policy;
    }

/*
    this.obtainChain = function(name, policy){
        this.chain = [];
        this.policy = policy;
        this.fetch(name);
    };
  */
    
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
            var tt = document.createElement('div');
            tt.className = "row show-grid";
            var iDiv = document.createElement('div');
            iDiv.className = "col-lg-5";
            var cont = document.createElement('div');
            cont.id = "result"+i;
            cont.className = "well well-large";
            iDiv.appendChild(cont);
            tt.appendChild(iDiv);
//            document.getElementById("resultarea").appendChild(cont);
            
            var img1 = new Image(); // HTML5 Constructor
            img1.src = 'arrow.gif';
            img1.width = 50;
            img1.height = 30;
            var sp = document.getElementById("resultarea");
            sp.appendChild(tt);
            if (i != this.chain.length - 1)
                sp.appendChild(img1);
            if (i == this.chain.length - 1  && this.findFlag == false) {
                cont.style.background="#FF0000";
                cont.onmouseover = function(e) {
                    var o = document.getElementById("hidDiv");
                    o.style.left = e.clientX+"px";
                    o.style.top = e.clientY+10+"px";
                    o.style.display="block";
                }
                cont.onmouseout = function() {
                    var o = document.getElementById("hidDiv");
                    o.style.display="none";
                }
            }
            document.getElementById('result'+i).innerHTML = this.chain[i].name.to_uri();
        }
    };
    
    this.verifySigning = function(content, key) {
        return content.verify(key);
    }
    
    this.receive = function(content) {
//        console.log(content);
        nameStr = escape(content.name.to_uri());
        keyName = content.signedInfo.locator.keyName.name.to_uri();
//        console.log("name: "+nameStr);
//        console.log("keyname: "+keyName);
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
                this.output('result');
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
    this.oriName;
//    this.expressName = null;
    
    var ndn = new NDN({host:"127.0.0.1"});
//    console.log("1");
    ndn.connect();
//    console.log("2");
    ndn.onopen = function () {
        console.log("onopen called");
//        console.log(this.oriName);
        var instance = CapabilityVerifySingleton.getInstance();
        instance.fetch(instance.oriName);
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
 
    this.init = function(name,policy){
        this.chain = [];
        this.policy = policy;
        this.oriName = name;
        console.log("init");
        console.log(name+"   "+this.oriName);
    };
    
    this.fetch = function(/*str*/name) {
        console.log("fetch  "+name);
        content  = this.certificateStore.getCertificateByName(name);
        if (content != null){
            this.receive(content);
        }
        else {
            var n = new Name(name);
            var template = new Interest();
            template.answerOriginKind = Interest.ANSWER_NO_CONTENT_STORE;
            template.interestLifetime = 1000;
            ndn.expressInterest(n, template, onData, onTimeout);
            console.log('Interest expressed.');
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
            else {
                console.log("signing correct");
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
//            this.expressName = keyName;
        }        
    };
};


var RoleEntry = function RoleEntry(_item){
	this.name = null;
	this.def = null;
	if (typeof _item == 'string') {
			var array = _item.split(":-");
			this.name = (array[0]);
			this.def = (array[1]);
	}
};

RoleEntry.prototype.getFirstRole = function(){
    var array = this.def.split(".");
    return array[1];
};

RoleEntry.prototype.getLastRole = function(){
    var array = this.def.split(".");
    return array[array.length - 1];
};

RoleEntry.prototype.getRoleHeader = function(){
    var array = this.def.split(".");
    return array[0];
};

function RoleStore(){
    this.store = new Array();
    
    this.addRoleDefCertification = function(_content) {
        var array = _content.content.split("#");
        for (var i = 0 ; i < array.length ; i++){
            _entry = new RoleEntry(array[i]);
            this.store.addRoleEntry(array[i]);
        }
    }
    
    this.addRoleEntry = function(/*str*/_roleString) {
        var _entry = new RoleEntry(_roleString);
        if (!this.checkDuplication(_entry)){
            this.store.push(_entry);
        }
    };
    
    this.checkDuplication = function(_entry){
        for (var i = 0; i < this.store.length; i++) {
            if (this.store[i].name == _entry.name &&
                this.store[i].def == _entry.def) {
                return true;
            }
        }
        return false;
    };
    
    this.getDefinitionByRoleName = function(/*str*/_name){
        var result = new Array();
        for (var i = 0; i < this.store.length; i++) {
            if (this.store[i].name == _name) {
                result.push(this.store[i]);
            }
        }
        return result;
    };
};


var RoleVerifySingleton= (function () {
    var instance;
    function createInstance() {
        var object = new RoleVerify();
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

function RoleVerify() {
    
    this.chain = new Array();
    this.certificateStore = new CertificateStore();
    this.roleStore = null;
    this.findFlag = false;
    this.policy = null;
    this.oriName;
    this.firstFlag= true;

    var ndn = new NDN({host:"127.0.0.1"});
    ndn.connect();
    
    ndn.onopen = function () {
        console.log("onopen called");
        var instance = RoleVerifySingleton.getInstance();
        this.firstFlag = true;
        instance.fetch(instance.oriName);
    };
    
    var onData = function (interest, content) {
        var instance = RoleVerifySingleton.getInstance();
        instance.receive(content);
    };
    
    var onTimeout = function (interest) {
        console.log("Interest time out.");
        console.log('Interest name: ' + interest.name.to_uri());
    };
    
    this.getRoleOwner = function(/*str*/_item) {
        var array = this.def.split("/ISSUER");
        return array[1];
    };
    
    this.getRoleName = function(/*str*/_item){
        var array = this.def.split("/ROLE-CERT");
        var array2 = array[1].split("/ISSUER");
        return array2[0];
    };
    
    this.getNameSpace = function(/*str*/_item) {
        var array = this.def.split("/ROLE-CERT");
        return array[0];
    };
    
    this.fetchRoleDefCertification = function(_name) {
        if (this.roleStore.getDefinitionByRoleName(_name) != null) {
        
        }
        else{
            this.fetch();
        }
    }
    
    this.receive = function(content){
        console.log(this.firstFlag);
        
        if (this.firstFlag) {
            nameStr = escape(content.name.to_uri());
            console.log(content);
            console.log(nameStr);
            keyName = content.signedInfo.locator.keyName.name.to_uri();
            
            var authority = this.policy.getAuthority(nameStr);
            console.log("auth:   "+authority[0].prefix+"  "+authority[0].authority);
/*            console.log("name: "+nameStr);
            console.log("keyname: "+keyName);
            console.log(this.getNameSpace(keyName));
            console.log(this.getRoleOwner(keyName));
            console.log(this.getRoleName(keyName));
 */
            
        }        
        if (nameStr.match("/ROLE-DEF") != null) {
            this.processRoleDef(content);
        }
        if (nameStr.match("/ROLE-CERT") != null) {
            this.certificateStore.addCertificateEntry(_content);
        }        
    };
    
    this.fetch = function(/*str*/name) {
        console.log("fetch  "+name);
        content  = this.certificateStore.getCertificateByName(name);
        if (content != null){
            this.receive(content);
        }
        else {
            var n = new Name(name);
            var template = new Interest();
            template.answerOriginKind = Interest.ANSWER_NO_CONTENT_STORE;
            template.interestLifetime = 1000;
            ndn.expressInterest(n, template, onData, onTimeout);
            console.log('Interest expressed.');
        }
    };
    
    this.init = function(name,policy,role){
        this.chain = [];
        this.policy = policy;
        this.oriName = name;
        this.roleStore = role;
        console.log("init");
//        console.log(name+"   "+this.oriName);
    };
    
}
