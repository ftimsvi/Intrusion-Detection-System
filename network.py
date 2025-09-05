from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

# Network general options
net.setLogLevel('info')

# Network definition
net.addP4Switch('s1', cli_input='s1-ids-core-commands.txt')
net.enableCpuPort('s1')
net.addP4Switch('s2', cli_input='s2-leaf-commands.txt')
net.addP4Switch('s3', cli_input='s3-leaf-commands.txt')

net.setP4SourceAll('./p4src/ids.p4')

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')
net.addHost('h4')

net.addLink('h1','s1')
net.addLink('h2','s2')
net.addLink('s1','s2')
net.addLink('s1','s3')
net.addLink('h3','s3')
net.addLink('h4','s3')

# Assignment strategy for IP and MAC Addresses 
net.mixed()

# Nodes general options
net.disablePcapDumpAll()
net.enableLogAll()
net.enableCli()

# Start the network 
net.startNetwork()
