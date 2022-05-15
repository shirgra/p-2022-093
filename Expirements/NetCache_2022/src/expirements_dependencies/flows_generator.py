import random
import pandas as pd
import itertools


# 20 medium flows - shared addresses
medium_flows = [["Medium", "192.240.10." + str(i)] for i in range(101, 111)]
medium_flows.extend([["Medium", "192.0.10." + str(i)] for i in range(111, 121)])

# 10 small flows - shared addresses
small_flows = [["Small", "192.240.10." + str(i)] for i in range(1, 6)]
small_flows.extend([["Small", "192.0.10." + str(i)] for i in range(6, 11)])

for tg in range(1,4):
    print(tg)
    # 10 large flows - unique per host
    large_flows = [["Large", "192.240." + str(tg) + "." + str(i)] for i in range(1, 6)]
    large_flows.extend([["Large", "192.0." + str(tg) + "." + str(i)] for i in range(6, 11)])

    flows = list(itertools.chain(large_flows, medium_flows, small_flows))

    df = pd.DataFrame(flows, columns=["Type", "Destination"])
    df.to_csv('flow_'+str(tg)+'.csv', index=True)





policy = []
policy.extend([["192.240.10." + str(i)] for i in range(101, 111)])
policy.extend([["192.0.10." + str(i)] for i in range(111, 121)])
policy.extend([["192.240.10." + str(i)] for i in range(1, 6)])
policy.extend([["192.0.10." + str(i)] for i in range(6, 11)])
for tg in range(1,4):
    policy.extend([["192.240." + str(tg) + "." + str(i)] for i in range(1, 6)])
    policy.extend([["192.0." + str(tg) + "." + str(i)] for i in range(6, 11)])
df = pd.DataFrame(policy, columns=["Address"])
df.to_csv('policy.csv', index=True)





