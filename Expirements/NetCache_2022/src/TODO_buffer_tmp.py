## from traffic generator

# main
	print("Cache size is %d." % CACHE_SIZE)
    # initiate expirement variables
    found_in_cache = 0
    not_found_in_cache = 0
    # start receiving thread to listen to rules come in
    # Thread that listen/snif
    receiver = threading.Thread(target=thread_receiver)
    receiver.start()
    time.sleep(3)

for flow in tqdm(traffic): 
        # chack if the destination address is in the cache - TODO mutable OR only read so it is OK?
        if check_if_in_cache(flow[1]):
            found_in_cache += 1
            send_packet(flow = flow, cache_flag = 3) # 3 means drop in switch
        else: 
            not_found_in_cache += 1
            send_packet(flow = flow, cache_flag = 2) # 2 means sent to controller
        # TODO add expire date to the rule in the cache
        # TODO add mutable for writing cache rule? only one writer 
    print("Successfully sent %d flows of traffic." % len(traffic))
    print("%d of the flows were found in the cache and %d were not." % (found_in_cache,not_found_in_cache))

    receiver.join()
    #TODO for the receiver stop after finish sending becuse we are done



""" threads and main functions """

def thread_receiver():
    print("Receiver Thread is starting")
    # TODO add received packet to cache
    # sniffing until ... ?? TODO make stop condition?? timer??
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    #print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    # TODO maybe set that the last of traffic send a message to the controller and then the controller send a signal through a packet to finish??
    print("Receiver Thread finished")


# this function is a copied function, gets the resemblense between two strings
def longestCommonPrefix(strs):
  """
  :type strs: List[str]
  :rtype: str
  """
  if len(strs) == 0:
     return ""
  current = strs[0]
  for i in range(1,len(strs)):
     temp = ""
     if len(current) == 0:
        break
     for j in range(len(strs[i])):
        if j<len(current) and current[j] == strs[i][j]:
           temp+=current[j]
        else:
           break
     current = temp
  return current

# change from "192.168.22.1" to "10010111100001110000101011111111"
def to_binary(ip):
    return ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])

#check if the destination address is match to the policy address by at list the mast size
def if_lpm(destAddr,policyAddr,mask):
    # return [policyAddr,mask] if has a match and false if not
    dest_Addr = to_binary(destAddr)
    policy_Addr = to_binary(policyAddr)
    numOfEqaul = len(longestCommonPrefix([dest_Addr,policy_Addr]))
    if (numOfEqaul >= int(mask)):
       return True
    return False

# this is the only place we write to the cache and change it
def update_cache_LRU(key_addr):
    global cache
    curr_LRU_flag_for_key_addr = cache[key_addr][1] # LRU flag
    # +1 to all lower values
    for k in cache.keys():
        m = cache[k][0]
        i = cache[k][1]
        if i < curr_LRU_flag_for_key_addr:
            cache[k] = [m, i + 1]
    # update to be last one to be used
    cache[key_addr] = [cache[key_addr][0], 1]
    return None

# insert the new rule to cache and update LRU
def insert_cache(new_rule):
    global cache
    # parse new_rule
    new_rule = new_rule[1:-1].split(', ')
    key = new_rule[0][1:-1] # take only the address w/o ''
    mask = new_rule[1][1:-1] # take only the mask w/o ''
    # check if we already have that rule
    if key in cache.keys():
        return None
    # if there is room for more rules:
    if len(cache) < CACHE_SIZE:
        # update all LRU
        for k in cache.keys():
            m = cache[k][0]
            i = cache[k][1] + 1
            cache[k] = [m, i]
        # insert new rule
        cache[key] = [mask, 1]
    else:
        # update all LRU
        for k in cache.keys():
            m = cache[k][0]
            i = cache[k][1]
            if i == CACHE_SIZE:
                # this is the LRU - evict rule
                cache.pop(k, None)
            else:
                cache[k] = [m, i+1]
        # insert new rule
        cache[key] = [mask, 1]
    return None

# this function return true if we have the adress in the cache and false otherwise
def check_if_in_cache(addr):
    for cache_addr in cache.keys():
        mask = cache[cache_addr][0]
        if if_lpm(addr, cache_addr, mask):
            update_cache_LRU(key_addr = cache_addr) # update according to LRU
            return True
    return False

# what is done when receiving a packet
def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234 and bytes(pkt[IP].dst) == '10.0.2.2': #TODO CHANGE FOR HOST
        new_rule = bytes(pkt[TCP].payload)
        sys.stdout.flush()
        insert_cache(new_rule = new_rule)
