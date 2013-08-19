/*
 Author: Xingyu Ma
 */

var CertificateDecode = function(_str) {
    this.m_str = readASN1(_str);
//    console.log(this.m_str);
    var offset = new Array();
    this.keyBit = null;
    this.parse = function() {
        var last;
//        console.log("parse");
        for (var i = 10; i < this.m_str.length; i++) {
            if (this.m_str[i] == '{') {
                last = this.position(i+1);
                offset.push([i,last]);
 //               console.log(i+"   "+last);
                i = last + 1;
            }
        }
        this.keyBit = this.getKey(offset[2][0],offset[2][1]);
    }
    
    this.getKey = function(start,end) {
        var sub = this.m_str.substr(start,end);
        var tt = sub.split("BITSTRING")[1].split(" :")[0];
//        console.log(tt+"XXXXX");
        return tt;
    }
    
    this.position = function(start) {
        var lcount = 1;
        var rcount = 0;
        var index = start;
        while(lcount > rcount){
                if('{' == this.m_str[index])
                    lcount++;
                
                if('}' == this.m_str[index])
                    rcount++;
                index++;
            }
        return index;
    }
}
