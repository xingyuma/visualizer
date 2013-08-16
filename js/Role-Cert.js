
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
