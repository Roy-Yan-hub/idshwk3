global a: table[addr] of table[string] of count;

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    #	local a: table[addr] of table[string] of count; 表示a[addr][count]访问到agent 每次判断3就好了
	if(name=="USER-AGENT")
	{
		#print to_lower(value);
        local AG : string = to_lower(value);
        local IP : addr = c$id$orig_h;
		if(IP !in a)
        {
            local tempAG: table[string] of count = {[AG] = 1 };
            a[IP]=tempAG;
            #print AG;
        }
        else
        {
            if(AG !in a[IP])
            {
                a[IP][AG]=1;
                #print AG;
            }
            if(|a[IP]|==3)
            {
                print fmt("%s is a proxy",IP);
            }
        }
	}
	
}
