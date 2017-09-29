import sys
class T34:
    def __init__(self):
        self.pc = 0
        self.mem = [0]*4096
        
    def load(self, fname):
        try:
            with open( fname ) as f:
                for l in f:
                    l = list( x.strip() for x in l.split() )
                    if( len(l) == 1 ): 
                        self.pc = int(l[0],16)
                    else:
                        addr = int( l[0] , 16 )
                        n = int( l[1] )
                        self.mem[addr:addr+n] = list( int(x,16) for x in l[2:] )                        
        except Exception as e:
            print(e)
            
    def parse(self,a,b=None):
        header = "              ADDR       OP     AM"
        fstr = "{:03x}:      {:012b} {:06b} {:06b}"
        if b is None:
            print(header)
            val = self.mem[a]
            print(fstr.format(a,val>>12, (val>>6)&63, val&63))
        else:
            print(header)
            rng = enumerate( self.mem[a:b], a )
            for addr, val in rng:
                print(fstr.format(addr,val>>12, (val>>6)&63, val&63))
             
    def dump(self):
        fstr = "{:03x}:  {:06x}"
        print( "\n".join( list( fstr.format(i,m) for i,m in enumerate(self.mem) if m > 0))) 

if __name__ == "__main__":

    fname, *args = sys.argv[1:]
    
    em = T34()
    em.load(fname)
    opts = {}
    cop = ''
    if( len(args) > 0 ):
        for a in args:
            if "-" in a:
                for o in a[1:]:
                    cop = o
                    opts[o] = list()
            else:
                opts[cop] = opts.setdefault(cop,list()).append(a)
        if "p" in opts:
            pargs = list( int(x) for x in opts["p"] )
            em.parse( *pargs )
        if "d" in opts:
            em.dump()
            
    
    
