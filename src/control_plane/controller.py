from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import sniff, Packet, Ether, IP, UDP, TCP, BitField, Raw
from crc import Crc
import argparse
import json
import os
import re
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import threading
import struct
import random

# P4 SWITCH ACTION TABLE NAMES DEFINITIONS
NETCACHE_LOOKUP_TABLE = "lookup_table"


# P4 SWITCH REGISTER NAMES DEFINITIONS
SKETCH_REG_PREFIX = "sketch"
BLOOMF_REG_PREFIX = "bloom"
CACHED_KEYS_COUNTER = "query_freq_cnt"
NETCACHE_HIT_COUNTER = "cache_hit_cnt"
NETCACHE_MISS_COUNTER = "cache_miss_cnt"
NETCACHE_COUNTER_PREFIXES = ["MyIngress.", "MyEgress."]


BLOOMF_REGISTERS_NUM = 3
SKETCH_REGISTERS_NUM = 4


STATISTICS_REFRESH_INTERVAL = 30.0  # measured in seconds

VTABLE_NAME_PREFIX = 'vt'
VTABLE_SLOT_SIZE = 8   # in bytes
VTABLE_ENTRIES = 65536

CONTROLLER_MIRROR_SESSION = 100

NETCACHE_READ_QUERY = 0
NETCACHE_HOT_READ_QUERY = 3
NETCACHE_KEY_NOT_FOUND = 20  # ???
NETCACHE_UPDATE_COMPLETE = 4
NETCACHE_DELETE_COMPLETE = 5

UNIX_CHANNEL = '/tmp/server_cont.s'
CACHE_INSERT_COMPLETE = 'INSERT_OK'


crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB,
                     0x741B8CD7, 0xEB31D82E, 0x0D663B05, 0xBA0DC66B,
                     0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]



class CompatTopology:
    def __init__(self, db):
        with open(db) as f:
            self.data = json.load(f)
        if isinstance(self.data, dict) and "nodes" in self.data:
            self.format = "node_link"
            self.nodes = {node["id"]: node for node in self.data.get("nodes", [])}
            self.links = self.data.get("links", [])
        else:
            self.format = "p4utils_dict"
            self.nodes = self.data
            self.links = []

    def get_thrift_port(self, name):
        return self.nodes[name]["thrift_port"]

    def get_cpu_port_index(self, name):
        return self.nodes[name].get("cpu_port_num")

    def get_hosts_connected_to(self, switch):
        if self.format == "p4utils_dict":
            return [
                peer
                for peer in self.nodes[switch].get("interfaces_to_node", {}).values()
                if self.nodes.get(peer, {}).get("type") == "host"
            ]
        hosts = []
        for link in self.links:
            if link["node1"] == switch and self.nodes.get(link["node2"], {}).get("isHost"):
                hosts.append(link["node2"])
            elif link["node2"] == switch and self.nodes.get(link["node1"], {}).get("isHost"):
                hosts.append(link["node1"])
        return hosts

    def node_to_node_port_num(self, node, peer):
        if self.format == "p4utils_dict":
            return self.nodes[node][peer]["port"]
        for link in self.links:
            if link["node1"] == node and link["node2"] == peer:
                return link["port1"]
            if link["node2"] == node and link["node1"] == peer:
                return link["port2"]
        raise KeyError((node, peer))

    def get_host_mac(self, host):
        return self.nodes[host]["mac"]

    def get_cpu_port_intf(self, switch):
        return self.nodes[switch].get("cpu_intf")


class NetcacheHeader(Packet):
    name = 'NcachePacket'
    fields_desc = [BitField('op', 0, 8), BitField('seq', 0, 32),
            BitField('key', 0, 128), BitField('value', 0, 512)]


class NCacheController(object):

    def __init__(
            self,
            sw_name,
            vtables_num=8,
            topology_db="../p4/topology.json",
            sniff_hot_reports=True,
            populate_dummy=False,
            api_listen=None,
            api_port=18080):
        self.topo = CompatTopology(db=topology_db)
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(self.sw_name)
        self.cpu_port = self.topo.get_cpu_port_index(self.sw_name)
        self.sniff_hot_reports = sniff_hot_reports
        self.populate_dummy = populate_dummy
        self.api_listen = api_listen
        self.api_port = api_port
        self.lock = threading.RLock()
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)

        self.custom_calcs = self.controller.get_custom_crc_calcs()
        self.sketch_register_num = len(self.custom_calcs)

        self.vtables = []
        self.vtables_num = vtables_num


        # create a pool of ids (as much as the total amount of keys)
        # this pool will be used to assign index to keys which will be
        # used to index the cached key counter and the validity register
        self.ids_pool = list(range(0, VTABLE_ENTRIES * VTABLE_SLOT_SIZE));

        # array of bitmap, which marks available slots per cache line
        # as 0 bits and occupied slots as 1 bits
        self.mem_pool = [0] * VTABLE_ENTRIES

        # number of memory slots used (useful for lfu eviction policy)
        self.used_mem_slots = 0

        # dictionary storing the value table index, bitmap and counter/validity
        # register index in the P4 switch that corresponds to each key
        self.key_map = {}

        self.setup()

        #self.out_of_band_test()


    def inform_server(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(UNIX_CHANNEL)
        except socket.error as msg:
            #print('Error: Unable to contact server for cache operation completion')
            return

        sock.sendall(CACHE_INSERT_COMPLETE)


    # reports the value of counters for each cached key
    # (used only for debugging purposes)
    def report_counters(self):
        for key, val in self.key_map.items():
            vt_idx, bitmap, key_idx = val

            res = self.controller.counter_read(CACHED_KEYS_COUNTER, key_idx)
            if res != 0:
                print("[COUNTER] key = " + key + " [ " + str(res.packets) + " ]")



    # periodically reset registers pertaining to query statistics module of the
    # P4 switch (count-min sketch registers, bloom filters and counters)
    def periodic_registers_reset(self):
        t = threading.Timer(STATISTICS_REFRESH_INTERVAL, self.periodic_registers_reset)
        t.daemon = True
        t.start()

        # before reseting registers check if the cache is utilized above a
        # threshold (e.g 80%) and evict keys using lfu policy if needed
        self.cache_lfu_eviction(threshold=0.8, sampling=0.2, to_remove=0.5)

        # reset bloom filter related registers
        for i in range(BLOOMF_REGISTERS_NUM):
            self.controller.register_reset(BLOOMF_REG_PREFIX + str(i+1))

        # reset count min sketch related registers
        for i in range(SKETCH_REGISTERS_NUM):
            self.controller.register_reset(SKETCH_REG_PREFIX + str(i+1))

        # reset counter register storing the query frequency of each cached item
        self.controller.counter_reset(CACHED_KEYS_COUNTER)

        print("[INFO]: Reset query statistics registers.")



    # the controller periodically checks if the memory used has exceeded a given threshold
    # (e.g 80 %) and if that is the case then it evicts keys according to an approximated
    # LFU policy inspired by REDIS (https://redis.io/topics/lru-cache))
    def cache_lfu_eviction(self, threshold=0.8, sampling=0.2, to_remove=0.5):

        # if the threshold has not been surpassed then nothing to do
        if self.used_mem_slots <= (threshold * len(self.mem_pool) * VTABLE_SLOT_SIZE):
            return

        n_samples = int(sampling * len(self.key_map.items()))

        samples = random.sample(self.key_map.items(), n_samples)

        # read the counter for each sample and store them in an array
        evict_list = []
        for key, val in samples:
            x, y, cnt_idx = self.key_map[key]
            counter = self.controller.counter_read(CACHED_KEYS_COUNTER, cnt_idx).packets
            evict_list.append((key, counter))

        # sort the array and pick the smallest K-th counters and evict their keys
        # (this could be achieved more optimally by using quickselect)
        import operator
        evict_list.sort(key = operator.itemgetter(1))

        for i in range(int(to_remove * n_samples)):
            curr = evict_list[i]
            self.evict(curr[0])




    def setup(self):
        if self.cpu_port:
            self.controller.mirroring_add(CONTROLLER_MIRROR_SESSION, self.cpu_port)

        # create custom hash functions for count min sketch and bloom filters
        self.set_crc_custom_hashes()
        self.create_hashes()

        # set a daemon to periodically reset registers
        self.periodic_registers_reset()

        # spawn new thread to serve incoming udp connections
        # (i.e hot reports from the switch)
        #udp_t = threading.Thread(target=self.hot_reports_loop)
        #udp_t.start()

    def set_crc_custom_hashes(self):
        i = 0
        for custom_crc32, width in sorted(self.custom_calcs.items()):
            self.controller.set_crc32_parameters(custom_crc32,
                    crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i += 1

    def create_hashes(self):
        self.hashes = []
        for i in range(self.sketch_register_num):
            self.hashes.append(Crc(32, crc32_polinomials[i], True, 0xffffffff, True, 0xffffffff))


    # set a static allocation scheme for l2 forwarding where the mac address of
    # each host is associated with the port connecting this host to the switch
    def set_forwarding_table(self):
        for host in self.topo.get_hosts_connected_to(self.sw_name):
            port = self.topo.node_to_node_port_num(self.sw_name, host)
            host_mac = self.topo.get_host_mac(host)
            self.controller.table_add("l2_forward", "set_egress_port", [str(host_mac)], [str(port)])


    def set_value_tables(self):
        for i in range(self.vtables_num):
            self.controller.table_add("vtable_" + str(i), "process_array_" + str(i), ['1'], [])


    # this function manages the mapping between between slots in register arrays
    # and the cached items by implementing the First Fit algorithm described in
    # Memory Management section of 4.4.2 (netcache paper)
    def first_fit(self, key, value_size):

        n_slots = int((value_size + VTABLE_SLOT_SIZE - 1) / VTABLE_SLOT_SIZE)
        if value_size <= 0:
            return None
        if key in self.key_map:
            return None


        for idx in range(len(self.mem_pool)):
            old_bitmap = self.mem_pool[idx]
            n_zeros = 8 - bin(old_bitmap).count("1")

            if n_zeros >= n_slots:
                cnt = 0
                bitmap = 0
                for i in reversed(range(8)):
                    if cnt >= n_slots:
                        break

                    if not self.bit_is_set(old_bitmap, i):
                        bitmap = bitmap | (1 << i)
                        cnt += 1

                # mark last n_slots 0 bits as 1 bits because we assigned
                # them to the new key and they are now allocated
                self.mem_pool[idx] = old_bitmap | bitmap

                self.used_mem_slots += bin(bitmap).count("1")

                return (idx, bitmap)

        return None


    # converts a list of 1s and 0s represented as strings and converts it
    # to a bitmap using bitwise operations (this intermediate representation
    # of a list of 1s and 0s is used to avoid low level bitwise logic inside
    # core implementation logic)
    def convert_to_bitmap(self, strlist, bitmap_len):
        bitmap = 0
        # supports only bitmaps with multiple of 8 bits size
        if bitmap_len % 8 != 0:
            return bitmap
        for i in strlist:
            bitmap = bitmap << 1
            bitmap = bitmap | int(i)

        return bitmap


    # this function checks whether the k-th bit of a given number is set
    def bit_is_set(self, n, k):
        if n & (1 << k):
            return True
        else:
            return False


    # given a key and its associated value, we update the lookup table on
    # the switch and we also update the value registers with the value
    # given as argument (stored in multiple slots)
    def insert(self, key, value, cont=True):
        if len(key) > 8:
            return {"ok": False, "reason": "KeyTooLong", "key": key}
        if len(value) > 64:
            return {"ok": False, "reason": "ValueTooLong", "key": key}

        # find where to put the value for given key
        with self.lock:
            mem_info = self.first_fit(key, len(value))

            # if key already exists or not space available then stop
            if mem_info == None:
                reason = "AlreadyExists" if key in self.key_map else "NoSpace"
                return {"ok": False, "reason": reason, "key": key}

            vt_index, bitmap = mem_info

            # keep track of number of bytes of the value written so far
            cnt = 0

            # store the value of the key in the vtables of the switch while
            # incrementally storing a part of the value at each value table
            # if the correspoding bit of the bitmap is set
            for i in range(self.vtables_num):

                if self.bit_is_set(bitmap, self.vtables_num - i - 1):
                    partial_val = value[cnt:cnt+VTABLE_SLOT_SIZE]
                    self.controller.register_write(VTABLE_NAME_PREFIX + str(i),
                            vt_index, self.str_to_int(partial_val))

                    cnt += VTABLE_SLOT_SIZE

            # allocate an id from the pool to index the counter and validity register
            # (we take the last element of list because in python list is implemented
            # to optimize for inserting and removing elements from the end of the list)
            key_index = self.ids_pool.pop()

            # add the new key to the cache lookup table of the p4 switch
            self.controller.table_add(NETCACHE_LOOKUP_TABLE, "set_lookup_metadata",
                [str(self.str_to_int(key))], [str(bitmap), str(vt_index), str(key_index)])

            # mark cache entry for this key as valid
            self.controller.register_write("cache_status", key_index, 1)

            self.key_map[key] = vt_index, bitmap, key_index

            inserted_slots = bin(bitmap).count("1")

            # inform the server about the successful cache insertion
            if cont:
                self.inform_server()

            print("Inserted key-value pair to cache: ("+key+","+value+")")
            return {
                "ok": True,
                "key": key,
                "valueSize": len(value),
                "slots": inserted_slots,
                "vtableIndex": vt_index,
                "bitmap": bitmap,
                "keyIndex": key_index,
            }


    # converts a string to a bytes representation and afterwards returns
    # its integer representation of width specified by argument int_width
    # (seems hacky due to restriction to use python2.7)
    def str_to_int(self, x, int_width=VTABLE_SLOT_SIZE):
        if len(x) > int_width:
            print("Error: Overflow while converting string to int")

        # add padding with 0x00 if input string size less than int_width
        bytearr = bytearray(int_width - len(x))
        bytearr.extend(x.encode('utf-8'))
        return struct.unpack(">Q", bytearr)[0]


    # given an arbitrary sized integer, the max width (in bits) of the integer
    # it returns the string representation of the number (also stripping it of
    # any '0x00' characters) (network byte order is assumed)
    def int_to_packed(self, int_val, max_width=128, word_size=32):
        num_words = max_width / word_size
        words = self.int_to_words(int_val, num_words, word_size)

        fmt = '>%dI' % (num_words)
        return struct.pack(fmt, *words).strip('\x00')

    # split up an arbitrary sized integer to words (needed to hack
    # around struct.pack limitation to convert to byte any integer
    # greater than 8 bytes)
    def int_to_words(self, int_val, num_words, word_size):
        max_int = 2 ** (word_size*num_words) - 1
        max_word_size = 2 ** word_size - 1
        words = []
        for _ in range(num_words):
            word = int_val & max_word_size
            words.append(int(word))
            int_val >>= word_size
        words.reverse()
        return words


    # update the value of the given key with the new value given as argument
    # (by allowing updates also to be done by the controller, the client is
    # also able to update keys with values bigger than the previous one)
    # in netcache paper this restriction is not resolved
    def update(self, key, value):
        # if key is not in cache then nothing to do
        if key not in self.key_map:
            return

        with self.lock:
            # update key-value pair by removing old pair and inserting new one
            self.evict(key)
            return self.insert(key, value)


    # evict given key from the cache by deleting its associated entries in
    # action tables of the switch, by deallocating its memory space and by
    # marking the cache entry as valid once the deletion is completed
    def evict(self, key):

        with self.lock:
            if key not in self.key_map:
                return

            # delete entry from the lookup_table
            entry_handle = self.controller.get_handle_from_match(
                    NETCACHE_LOOKUP_TABLE, [str(self.str_to_int(key)), ])

            if entry_handle is not None:
                self.controller.table_delete(NETCACHE_LOOKUP_TABLE, entry_handle)

            # delete mapping of key from controller's dictionary
            vt_idx, bitmap, key_idx = self.key_map[key]
            del self.key_map[key]

            # deallocate space from memory pool
            self.mem_pool[vt_idx] = self.mem_pool[vt_idx] ^ bitmap
            self.used_mem_slots = self.used_mem_slots - bin(bitmap).count("1")

            # free the id used to index the validity/counter register and append
            # it back to the id pool of the controller
            self.ids_pool.append(key_idx)

            # mark cache entry as valid again (should be the last thing to do)
            self.controller.register_write("cache_status", key_idx, 1)



    # used for testing purposes and static population of cache
    def dummy_populate_vtables(self):
        test_values_l = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta",
                         "hita", "theta", "yiota", "kappa", "lambda", "meta"]
        test_keys_l = ["one", "two", "three", "four", "five", "six", "seven",
                       "eight", "nine", "ten", "eleven", "twelve"]
        cnt = 0
        for i in range(11):
            self.insert(test_keys_l[i], test_values_l[i], False)



    # handling reports from the switch corresponding to hot keys, updates to
    # key-value pairs or deletions - this function receives a packet, extracts
    # its netcache header and manipulates cache based on the operation field
    # of the netcache header (callback function)
    def recv_switch_updates(self, pkt):
        print("Received message from switch")

        # extract netcache header information
        if pkt.haslayer(UDP):
            ncache_header = NetcacheHeader(pkt[UDP].payload)
        elif pkt.haslayer(TCP):
            ncache_header = NetcacheHeader(pkt[TCP].payload)

        key = self.int_to_packed(ncache_header.key, max_width=128)
        value = self.int_to_packed(ncache_header.value, max_width=1024)

        op = ncache_header.op

        if op == NETCACHE_HOT_READ_QUERY:
            print("Received hot report for key = " + key)
            # if the netcache header has null value or if the "hot key"
            # reported doesn't exist then do not update cache
            if ncache_header.op == NETCACHE_KEY_NOT_FOUND:
                return

            self.insert(key, value)

        elif op == NETCACHE_DELETE_COMPLETE:
            print("Received query to delete key = " + key)
            self.evict(key)

        elif op == NETCACHE_UPDATE_COMPLETE:
            print("Received query to update key = " + key)
            self.update(key, value)

        else:
            print("Error: unrecognized operation field of netcache header")


    # sniff infinitely the interface connected to the P4 switch and when a valid netcache
    # packet is captured, handle the packet via a callback to recv_switch_updates function
    def hot_reports_loop(self):
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name))
        if cpu_port_intf in ("None", ""):
            print("No CPU port interface configured; skipping hot reports sniff loop")
            return
        sniff(iface=cpu_port_intf, prn=self.recv_switch_updates, filter="port 50000")

    def cache_status(self):
        with self.lock:
            capacity_entries = len(self.mem_pool)
            capacity_slots = len(self.mem_pool) * self.vtables_num
            used_entries = len(self.key_map)
            used_slots = self.used_mem_slots
            return {
                "switchName": self.sw_name,
                "capacityEntries": capacity_entries,
                "usedEntries": used_entries,
                "freeEntries": max(0, capacity_entries - used_entries),
                "capacitySlots": capacity_slots,
                "usedSlots": used_slots,
                "freeSlots": max(0, capacity_slots - used_slots),
                "keys": sorted(self.key_map.keys()),
            }

    def device_metrics(self):
        per_port_packets = {}
        per_port_bytes = {}
        packets_processed = 0
        bytes_processed = 0
        for iface in sorted(os.listdir("/sys/class/net")):
            if iface == "lo" or iface.startswith("eth0"):
                continue
            stats_dir = os.path.join("/sys/class/net", iface, "statistics")
            try:
                with open(os.path.join(stats_dir, "rx_packets"), "r", encoding="utf-8") as handle:
                    packets = int(handle.read().strip())
                with open(os.path.join(stats_dir, "rx_bytes"), "r", encoding="utf-8") as handle:
                    byte_count = int(handle.read().strip())
            except (FileNotFoundError, ValueError):
                continue
            per_port_packets[iface] = packets
            per_port_bytes[iface] = byte_count
            packets_processed += packets
            bytes_processed += byte_count
        cache_hits = self._counter_packets(NETCACHE_HIT_COUNTER, 0)
        cache_misses = self._counter_packets(NETCACHE_MISS_COUNTER, 0)
        cache_queries = cache_hits + cache_misses
        return {
            "collectedAtEpochSeconds": time.time(),
            "packetsProcessed": packets_processed,
            "bytesProcessed": bytes_processed,
            "cacheHits": cache_hits,
            "cacheMisses": cache_misses,
            "cacheHitRatio": cache_hits / cache_queries if cache_queries else 0.0,
            "cacheMissRatio": cache_misses / cache_queries if cache_queries else 0.0,
            "perPortPackets": per_port_packets,
            "perPortBytes": per_port_bytes,
        }

    def _counter_packets(self, counter_name, index):
        counter_names = [counter_name]
        if "." not in counter_name:
            counter_names.extend(prefix + counter_name for prefix in NETCACHE_COUNTER_PREFIXES)
        last_error = None
        for candidate in counter_names:
            try:
                return self._counter_packets_cli(candidate, index)
            except BaseException as err:
                last_error = err
            try:
                value = self.controller.counter_read(candidate, index)
                return int(getattr(value, "packets", value or 0))
            except BaseException as err:
                last_error = err
        print("[WARN]: Unable to read counter {}[{}]: {}".format(counter_name, index, last_error), flush=True)
        return 0

    def _counter_packets_cli(self, counter_name, index):
        command = "counter_read {} {}\n".format(counter_name, index)
        result = subprocess.run(
            ["simple_switch_CLI_wrapped", "--thrift-port", str(self.thrift_port)],
            input=command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        output = result.stdout + "\n" + result.stderr
        if result.returncode != 0:
            raise RuntimeError(output.strip())
        match = re.search(r"{}\[{}\]=\s*\(\d+ bytes, (\d+) packets\)".format(re.escape(counter_name), index), output)
        if not match:
            raise RuntimeError(output.strip())
        return int(match.group(1))

    def serve_api(self):
        controller = self

        class Handler(BaseHTTPRequestHandler):
            def _send_json(self, code, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length == 0:
                    return {}
                return json.loads(self.rfile.read(length).decode("utf-8"))

            def do_GET(self):
                try:
                    if self.path in ("/healthz", "/readyz"):
                        self._send_json(200, {"ok": True})
                        return
                    if self.path == "/status":
                        self._send_json(200, controller.cache_status())
                        return
                    if self.path == "/metrics":
                        self._send_json(200, controller.device_metrics())
                        return
                    self._send_json(404, {"error": "NotFound"})
                except BaseException as err:
                    print("[ERROR]: API GET {} failed: {}".format(self.path, err), flush=True)
                    self._send_json(500, {"error": type(err).__name__, "message": str(err)})

            def do_POST(self):
                try:
                    if self.path != "/cache/entries":
                        self._send_json(404, {"error": "NotFound"})
                        return

                    payload = self._read_json()
                    entries = payload.get("entries")
                    if entries is None:
                        entries = [{"key": payload.get("key"), "value": payload.get("value")}]

                    results = []
                    inserted = 0
                    for entry in entries:
                        key = str(entry.get("key", ""))
                        value = str(entry.get("value", ""))
                        result = controller.insert(key, value, cont=False)
                        results.append(result)
                        if result.get("ok"):
                            inserted += 1

                    self._send_json(200, {
                        "inserted": inserted,
                        "results": results,
                        "status": controller.cache_status(),
                    })
                except BaseException as err:
                    print("[ERROR]: API POST {} failed: {}".format(self.path, err), flush=True)
                    self._send_json(500, {"error": type(err).__name__, "message": str(err)})

            def log_message(self, fmt, *args):
                print("[api] " + fmt % args)

        httpd = ThreadingHTTPServer((self.api_listen, self.api_port), Handler)
        print("[INFO]: NetCache control API listening on %s:%s" % (self.api_listen, self.api_port))
        httpd.serve_forever()

    def main(self):
        self.set_forwarding_table()
        self.set_value_tables()
        if self.populate_dummy:
            self.dummy_populate_vtables()
        if self.api_listen:
            api_t = threading.Thread(target=self.serve_api)
            api_t.daemon = True
            api_t.start()
        if self.sniff_hot_reports:
            self.hot_reports_loop()
        if self.api_listen:
            while True:
                threading.Event().wait(3600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--switch-name", default=os.environ.get("NETCACHE_SWITCH_NAME", "s1"))
    parser.add_argument("--topology-db", default=os.environ.get("NETCACHE_TOPOLOGY_DB", "../p4/topology.json"))
    parser.add_argument("--no-sniff", action="store_true")
    parser.add_argument("--api-listen", default=os.environ.get("NETCACHE_API_LISTEN"))
    parser.add_argument("--api-port", type=int, default=int(os.environ.get("NETCACHE_API_PORT", "18080")))
    parser.add_argument(
        "--populate-dummy",
        action="store_true",
        default=os.environ.get("NETCACHE_POPULATE_DUMMY", "").lower() in ("1", "true", "yes", "on"),
    )
    args = parser.parse_args()
    controller = NCacheController(
        args.switch_name,
        topology_db=args.topology_db,
        sniff_hot_reports=not args.no_sniff,
        populate_dummy=args.populate_dummy,
        api_listen=args.api_listen,
        api_port=args.api_port,
    ).main()
