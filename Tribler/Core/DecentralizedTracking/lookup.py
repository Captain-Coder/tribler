#!/bin/python2

# DHT commandline lookup

import logging
import os
import sys
import time

logger = logging.getLogger(__name__)

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__))))

import pymdht.core.pymdht as pymdht
import pymdht.core.node as node
import pymdht.plugins.routing_nice_rtt as routing_mod
import pymdht.plugins.lookup_a4 as lookup_mod
import pymdht.core.exp_plugin_template as experimental_m_mod
from   pymdht.core.identifier import Id

info_hashes = []
for arg in sys.argv[1:]:
    info_hashes.append(arg.decode("hex"))

my_node = node.Node(('127.0.0.1', 20020), None, version=pymdht.VERSION_LABEL)
private_dht_name = None
dht = pymdht.Pymdht(my_node, ".",
                    routing_mod,
                    lookup_mod,
                    experimental_m_mod,
                    private_dht_name,
                    logging.ERROR)

time.sleep(30)

for info_hash in info_hashes:
    def dht_callback(_, peers, __):
        if not peers:
            peers = []
        if len(peers) <= 0:
            return
        print 'curl -sX PATCH http://localhost:8080/downloads/%s --data "peer=%s"' % (info_hash.encode("hex"), "&peer=".join(["%s%%20%s" % (peer[0], peer[1]) for peer in peers]))

    dht.get_peers(info_hash, Id(info_hash), dht_callback)
    time.sleep(5)

time.sleep(30)
