#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

#define PATTERN_WIDTH 32
#define FLOW_ENTRIES 4096


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>      egressSpec_t;
typedef bit<48>     macAddr_t;
typedef bit<32>     ip4Addr_t;

header ethernet_t {
    macAddr_t       dstAddr;
    macAddr_t       srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>          version;
    bit<4>          ihl;
    bit<8>          diffserv;
    bit<16>         totalLen;
    bit<16>         identification;
    bit<3>          flags;
    bit<13>         fragOffset;
    bit<8>          ttl;
    bit<8>          protocol;
    bit<16>         hdrChecksum;
    ip4Addr_t       srcAddr;
    ip4Addr_t       dstAddr;
}

header tcp_t{
    bit<16>         srcPort;
    bit<16>         dstPort;
    bit<32>         seqNo;
    bit<32>         ackNo;
    bit<4>          dataOffset;
    bit<4>          res;
    bit<1>          cwr;
    bit<1>          ece;
    bit<1>          urg;
    bit<1>          ack;
    bit<1>          psh;
    bit<1>          rst;
    bit<1>          syn;
    bit<1>          fin;
    bit<16>         window;
    bit<16>         checksum;
    bit<16>         urgentPtr;
}

header udp_t {
    bit<16>         srcPort;
    bit<16>         dstPort;
    bit<16>         length;
    bit<16>         checksum;
}

header payload_t {
    bit<PATTERN_WIDTH> data;
}

struct metadata {
    // empty
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
    udp_t           udp;        
    payload_t       payload;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser IDS_Parser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: ipv4;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            default: accept;
        }     
    }

    state tcp {
        packet.extract(hdr.tcp);
        transition payload;
    }

    state udp {
        packet.extract(hdr.udp);
        transition payload;
    }

    state payload {
        packet.extract(hdr.payload);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control IDS_VerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control IDS_Ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<32>>(FLOW_ENTRIES) counters; //number of packet dropped per flow
    register<bit<1>>(FLOW_ENTRIES) blocked_flows; 
    bit<1> current_flow; //bit to check status of current flow
    bit<PATTERN_WIDTH> hashed_val; // get hashed result from crc32

    action increment_counter() {
        bit<PATTERN_WIDTH> temp;
        counters.read(temp, hashed_val);
        temp = temp + 1;
        counters.write(hashed_val, temp);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action signature_hit(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;

        blocked_flows.write(hashed_val, 1);
        current_flow = 1;
    }

    action get_flow_status() {
        blocked_flows.read(current_flow, hashed_val);
    }

    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2, bit<8> protocol) {
        hash(hashed_val, HashAlgorithm.crc32, (bit<16>)0,
            {ipAddr1, ipAddr2, port1, port2, protocol},
            (bit<32>)FLOW_ENTRIES);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    table flows {
        actions = { get_flow_status; }
        size = 1;
        default_action = get_flow_status();
    }

    table signatures {
        key = { hdr.payload.data: exact; }
        actions = {
            signature_hit;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            bit<16> src_port = 0;
            bit<16> dst_port = 0;

            if (hdr.tcp.isValid()) {
                src_port = hdr.tcp.srcPort;
                dst_port = hdr.tcp.dstPort;
            } else if (hdr.udp.isValid()) {
                src_port = hdr.udp.srcPort;
                dst_port = hdr.udp.dstPort;
            }

            compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, src_port, dst_port, hdr.ipv4.protocol);

            flows.apply();
            if (current_flow == 0)
                if (signatures.apply().miss)
                    ipv4_lpm.apply();
                else
                    increment_counter();
            else
                increment_counter();
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control IDS_Egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}


/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control IDS_ComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control IDS_Deparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
	packet.emit(hdr.udp);
        packet.emit(hdr.payload);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch (
    IDS_Parser(),
    IDS_VerifyChecksum(),
    IDS_Ingress(),
    IDS_Egress(),
    IDS_ComputeChecksum(),
    IDS_Deparser()
) main;

