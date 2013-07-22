Component = function(_exp, _backRefManager, _exact){
    this.exp = _exp;
    this.backRefManager = _backRefManager;
    this.exact = _exact;
    
    this.match = function(_name, offset, len) {
        result = new Name();
        //        console.log(_name.getComponent(0));
        if (len == 0) {
            return false;
        }
        if (this.exact){
            if (DataUtils.toString(_name.getComponent(offset)).match(this.exp))
            {
                result.append(_name.getComponent(offset));
                return true;
            }
            else return false;
        }else{
            if (DataUtils.toString(_name.getComponent(offset)).search(this.exp))
            {
                result.append(_name.getComponent(offset));
                return true;
            }
            else return false;
        }
    }
    
}


function RegexMatcher(_expr, _type, _backRefManager){
    this.m_expr = _expr;
    this.type = _type;
    this._backRefManager = _backRefManager;
    
    this.m_matcherList = new Array();
    this.m_matchResult = null;
}

/*
RegexMatcher.prototype.match = function(_name, offset, len) {
 //   console.log("len   "+len);
    var cnt = 0;
    for (var i = 0; i < len; i++) {
        if (this.m_matcherList[i].match(_name,offset+i,1)) {
            cnt ++;
        }
        else break;
    }
    console.log(cnt);
    if (cnt == len) {
        this.m_matchResult = new Name();
        for (var i = 0 ; i < len ; i++){
            this.m_matchResult.append(DataUtils.toString(_name.getComponent(offset + i)));
        }
        return true;
    }
    else
        return false;
}
*/
RegexMatcher.prototype.match = function(_name, offset, len){
 /*   console.log("regex matcher match");
    console.log(this.m_matcherList);
    console.log(_name.to_uri());
    console.log(offset);
    console.log(len);
 */
    this.m_matchResult = new Name();
        if (this.recursiveMatch(0,_name, offset, len)) {
            for (var i = 0 ; i < len ; i++){
                this.m_matchResult.append(DataUtils.toString(_name.getComponent(offset + i)));
            }
            return true;
        }else
            return false;
};
    
RegexMatcher.prototype.recursiveMatch = function(mid, _name, offset, len) {
        var tried = 0;
//    console.log(mid);
        if (mid >= this.m_matcherList.length ){
            if (len != 0)
                return false;
            else
                return true;
        }
        
        var matcher = this.m_matcherList[mid];
        while (tried <= len) {
            if (matcher.match(_name, offset,tried)
                && this.recursiveMatch(mid+1, _name, offset + tried, len - tried)) {
                return true;
            }
            else {
                tried ++;
            }
        }
        return false;
};


ComponentSetMatcher = function(_expr, _backRefManager, _include) {
    
    this.m_expr = _expr;
    this.m_backRefManager = _backRefManager;
    this.m_include = _include;
    this.m_components = new Array();
    
    this.m_matcherList = new Array();
    this.m_matchResult = null;

//    RegexMatcher.call(this,m_expr,m_matcherList);
    
    this.compile = function() {
        if (this.m_expr[0] == '<') {
            return this.compileSingle();
        } else{
            if (this.m_expr[0] == '[') {
                var lastIndex = this.m_expr.length - 1;
                if (this.m_expr[lastIndex] != ']') {
                    console.log("error");
                }
                if (this.m_expr[lastIndex] == '^') {
                    this.m_include = false;
                    return this.compileMultiple(2, lastIndex);
                }
                else
                    return this.compileMultiple(1, lastIndex);
            }
        }
    };
    
    this.compileSingle = function() {
        var end = this.extractComponent(1);
        if (this.m_expr.length == end) {
            var component = new Component(this.m_expr.substr(1, end - 2), this.backRefManager,true);
            this.m_components.push(component);
            return true;
        }
        else
            return false;
    }
    
    this.compileMultiple = function(start, last) {
        var index = start;
        var tmp_index = start;
        while (index < last) {
            if (this.m_expr[index] != '<') {
                console.log("error");
            }
            tmp_index = index + 1;
            index = this.extractComponent(tmp_index);
            
            var component = new Component(this.m_expr.substr(tmp_index, index - tmp_index - 1), this.backRefManager,true);
            this.m_components.push(component);
        }
        if (last == index)
            return true;
    }
    
    this.extractComponent = function(index) {
        var lcount = 1;
        var rcount = 0;
        while (lcount > rcount) {
            switch(this.m_expr[index]){
                case '<':
                    lcount++;
                    break;
                case '>':
                    rcount++;
                    break;
                case 0:
                    console.log("error");
                    break;
            }
            index++;
        }
        return index;
    }
    
    this.match = function(_name, offset, len){
        
        var matched = false;
        if (len != 1) {
            return false;
        }
        for (var i = 0; i < this.m_components.length; i++) {
            var it = this.m_components[i];
//            console.log(it);
//            console.log(it.match(_name,offset, len));
            if (it.match(_name,offset, len)) {
                matched = true;
                break;
            }
        }
        
        this.matchResult = new Name();
        
        if (this.m_include ? matched : !matched) {
            this.matchResult.append(DataUtils.toString(_name.getComponent(offset)));
            return true;
        }
        else {
            return false;
        }
    }
};

BackRefManager = function() {
    this.m_backRefs = new Array();
    
    this.pushRef = function(_matcher){
        var last = this.m_backRefs.length;
        this.m_backRefs.push(_matcher);
        return last;
    }
    
    this.popRef = function() {
        this.m_backRefs.pop();
        return this.m_backRefs.length;
    }
};


BackRefMatcher = function(_expr, _backRefManager) {
//    RegexMatcher.call(this);
    this.m_expr = _expr;
    this.m_backRefManager  =_backRefManager;
    this.compile = function(){
        var last = this.m_expr.length - 1;
        if (this.m_expr[0] == '(' && this.m_expr[last] == ')') {
            this.m_backRefManager.pushRef(this);
            var matcher = new PatternListMatcher(this.m_expr.substr(1, last - 1),
                                                 this.m_backRefManager);
            matcher.compile();
            this.m_matcherList.push(matcher);
            return true;
        }
    }
};

RepeatMatcher = function(_expr, _backRefManager, indicator) {
    
    this.m_expr = _expr;
    this.m_backRefManager = _backRefManager;
    this.m_indicator = indicator;
    this.m_repeatMin = null;
    this.m_repeatMax = null;
    this.m_matchResult = null;
    this.m_matcherList = new Array();
    
    this.compile = function() {
        console.log("repeat matcher compile");
        var matcher;
        if (this.m_expr[0] == '(') {
            matcher = new BackRefMatcher(this.m_expr.substr(0,this.m_indicator), this.m_backRefManager,true);
            matcher.compile();
            
        } else {
            matcher = new ComponentSetMatcher(this.m_expr.substr(0,this.m_indicator), this.m_backRefManager,true);
            matcher.compile();
        }
        this.m_matcherList.push(matcher);
        return this.parse();
    }
    
    this.parse = function() {
//        console.log(this.m_expr.length);
//        console.log(this.m_indicator);
        if (this.m_expr.length == this.m_indicator) {
            this.m_repeatMax = 1;
            this.m_repeatMin = 1;
            return true;
        }
        else{
            if (this.m_expr.length == (this.m_indicator + 1)) {
                if (this.m_expr[this.m_indicator] == '?') {
                    this.m_repeatMin = 0;
                    this.m_repeatMax = 1;
                    return true;
                }
                if (this.m_expr[this.m_indicator] == '+') {
                    this.m_repeatMin = 1;
                    this.m_repeatMax = 100000; /*TODO change to largest*/
                    return true;
                }
                if (this.m_expr[this.m_indicator] == '*') {
                    this.m_repeatMin = 0;
                    this.m_repeatMax = 100000; /*TODO change to largest*/
                    return true;
                }
           }
            else{
                var repeatString = this.m_expr.substr(this.m_indicator + 1,
                                                      this.m_expr.length - this.m_indicator - 2);
//                console.log(repeatString);
                var splitRepeat = repeatString.split(',');
                console.log(splitRepeat);
                if (splitRepeat.length > 1) {
                    this.m_repeatMin = parseInt(splitRepeat[0]);
                    this.m_repeatMax = parseInt(splitRepeat[1]);
                    if (isNaN(this.m_repeatMin))
                        this.m_repeatMin = 0;
                    if (isNaN(this.m_repeatMax))
                        this.m_repeatMax = 100000;
                }
                else {
                    this.m_repeatMin = parseInt(repeatString);
                    this.m_repeatMax = parseInt(repeatString);
                }
                return true;
           }
        }
    };
    
    this.match = function(_name, offset, len) {
 //       console.log(_name.to_uri());
//        console.log(offset);
//        console.log(len);
        this.matchResult = new Name();
        var cnt = 0;
        for (var i = 0; i < len; i++) {
            if (this.m_matcherList[0].match(_name,offset+i,1)) {
                cnt ++;
            }
            else break;
        }
  //      console.log(cnt);
        if (cnt >= this.m_repeatMin && cnt <= this.m_repeatMax) {
            return true;
        }
        else return false;
    }

    /*
    this.match = function(_name, offset, len) {
        this.matchResult = new Name();
        
        if (this.m_repeatMin == 0 && len == 0) {
            return true;
        }
        
        if (this.recursiveMatch(this.m_matcherList[0], 0, _name, offset, len)) {
            for (var i = 0; i < len; i++) {
                this.matchResult.append(DataUtils.toString(_name.getComponent(i+offset)));
            }
            console.log(this.matchResult.to_uri());
            return true;
        } else
            return false;
    };
    
    this.recursiveMatch = function(matcher, repeat, _name, offset, len) {
        var tried = 0;
        
        if(0 < len && repeat > this.m_repeatMax){
            return false;
        }
        if(0 == len && repeat < this.m_repeatMin){
            return false;
        }

        if(0 == len && repeat >= this.m_repeatMin){
            return true;
        }

        while(tried <= len){
            if(matcher.match(_name, offset, tried) &&
               this.recursiveMatch(matcher, repeat + 1, _name, offset + tried, len - tried)){
                return true;
            }
            else
                tried++;
        }
        return false;
    };
   */
}

PatternListMatcher = function(_expr, _backRefManager) {
    this.m_expr = _expr;
    this.m_backRefManager = _backRefManager;
    
    this.compile = function(){
        var len = this.m_expr.length;
        var index = 0;
        var subHead = index;
        while (index < len) {
//            console.log(index+"  "+len);
            subHead = index;
            if (index = this.extractPattern(subHead, index))
            if (index == -1){
                return false;
            }
        }
        return true;
    }
    
    this.extractPattern = function(index, next) {
        var start = index;
        var end = index;
        var indicator = index;

        switch(this.m_expr[index]){
            case '(':
                index++;
                index = this.extractSubPattern('(', ')', index);
                indicator = index;
                end = this.extractRepetition(index);
                break;
                
            case '<':
                index++;
                index = this.extractSubPattern('<', '>', index);
                indicator = index;
                end = this.extractRepetition(index);
                break;
                
            default:
                console.log("error syntex");
        }

        var matcher = new RepeatMatcher(this.m_expr.substr(start, end - start), this.m_backRefManager, indicator - start);
        matcher.compile();
        this.m_matcherList.push(matcher);
        
        next = end;
        return next;
    }

    this.extractSubPattern = function(left, right, index) {
        var lcount = 1;
        var rcount = 0;
        
        while(lcount > rcount){
            if(index >= this.m_expr.length)
                console.log("error subpattern");
            
            if(left == this.m_expr[index])
                lcount++;
            
            if(right == this.m_expr[index])
                rcount++;
            index++;
        }
        return index;
    }
    
    this.extractRepetition = function(index)
    {
        var exprSize = this.m_expr.length;
        
        if(index == exprSize)
            return index;
        
        if(('+' == this.m_expr[index] || '?' == this.m_expr[index] || '*' == this.m_expr[index])){
            return ++index;
        }
        
        if('{' == this.m_expr[index]){
            while('}' != this.m_expr[index]){
                index++;
                if(index == exprSize)
                    break;
            }
            if(index == exprSize)
                console.log("mismatch");
            else
                return ++index;
        }
        else{
            return index;
        }
    }
}

PatternListMatcher.prototype = new RegexMatcher();

BackRefMatcher.prototype = new RegexMatcher();