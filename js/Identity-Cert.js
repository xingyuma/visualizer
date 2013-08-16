var IdentityVerify = function() {
    
    this.trusted = new Array();//new Name("/aa/ID-CERT");
    this.chain = new Array();
    this.certificateStore = new CertificateStore();
    this.findFlag = false;
    this.policy = null;
    this.callback = null;
    this.oriName;
    var self = this;
    var ndn;
    
    var onData = function (interest, content) {
        self.receive(content,self.callback);
    };
    
    var onTimeout = function (interest) {
        console.log("Interest time out.");
        console.log('Interest name: ' + interest.name.to_uri());
        ndn.close();
    };
    
    this.init = function(name){
        this.chain = [];
        this.oriName = name;
        console.log("init");
        ndn = new NDN();
        ndn.connect();
        
        ndn.onopen = function () {
            console.log("onopen called");
            self.fetch(self.oriName);
        };
    }
    
    this.init_para = function(trust_array, policy,_callback) {
        this.policy = policy;
        this.callback = _callback;
        this.trusted = trust_array;
    }
    
    this.fetch = function(/*str*/name) {
      console.log("fetch  "+name);
        content  = this.certificateStore.getCertificateByName(name);
        if (content != null){
            self.receive(content);
        }
        else {
            var n = new Name(name);
            var template = new Interest();
            template.answerOriginKind = Interest.ANSWER_NO_CONTENT_STORE;
            template.interestLifetime = 1000;
            ndn.expressInterest(n, template, onData, onTimeout);
            console.log('Interest expressed.');
//            ndn.expressInterest(new Name(name), new AsyncGetClosure());
        }
    };
    
    
    this.verifySigning = function(content, key) {
        return content.verify(key);
    }
    
    this.receive = function(content, callback) {

        nameStr = escape(content.name.to_uri());
        keyName = content.signedInfo.locator.keyName.name.to_uri();
        console.log(nameStr);
        console.log(keyName);
        issuerName = new Name(nameStr);
        var key = new Key();
        key.publicKeyPem = DataUtils.toString(content.content);
        key.publicToDER();
        
        if (this.chain.length >= 1) {
            chainLast = this.chain[this.chain.length - 1];
            if (!chainLast.verify(key)) {
                callback(self.chain,false);
                console.log("signing error");
                ndn.close();
                return false;
            }
        }

        self.chain.push(content);
        self.certificateStore.addCertificateEntry(content);
        
        for (var i = 0; i < this.trusted.length; i++) {
            if (issuerName.equals(this.trusted[i].key_name) &&
                DataUtils.toString(content.content) == key.publicKeyPem) {
//                console.log(DataUtils.toString(content.content));
 //               console.log(key.publicKeyPem);
                self.findFlag = true;
                callback(self.chain,true);
                ndn.close();
                return true;
            }
        }
        if (!self.policy.verify(nameStr, keyName)) {
                console.log("policy error");
                callback(self.chain,false);
                ndn.close();
                return false;
        }
        self.fetch(keyName);
    };
};
