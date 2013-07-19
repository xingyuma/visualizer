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
        if (this.m_exact){
            if (this.exp.match(DataUtils.toString(_name.getComponent(offset))))
            {
                result.append(_name.getComponent(offset));
                return true;
            }
            else return false;
        }else{
            if (this.exp.search(DataUtils.toString(_name.getComponent(offset))))
            {
                result.append(_name.getComponent(offset));
                return true;
            }
            else return false;
        }
    }

}