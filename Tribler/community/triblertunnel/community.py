import os
import time
import sys
import random

from Tribler.Core.Modules.wallet import tc_wallet
from Tribler.Core.Modules.wallet.tc_database_listener import BandwidthDatabaseListener
from Tribler.community.triblertunnel.caches import BalanceRequestCache
from Tribler.community.triblertunnel.payload import PayoutPayload, BalanceRequestPayload, BalanceResponsePayload
from Tribler.Core.Modules.wallet.bandwidth_block import TriblerBandwidthBlock
from Tribler.pyipv8.ipv8.attestation.trustchain.block import EMPTY_PK
from Tribler.pyipv8.ipv8.messaging.anonymization.caches import ExtendRequestCache
from twisted.internet.defer import inlineCallbacks, succeed, Deferred

from Tribler.community.triblertunnel.dispatcher import TunnelDispatcher
from Tribler.Core.simpledefs import NTFY_TUNNEL, NTFY_IP_RECREATE, NTFY_REMOVE, NTFY_EXTENDED, NTFY_CREATED,\
    NTFY_JOINED, DLSTATUS_SEEDING, DLSTATUS_DOWNLOADING, DLSTATUS_STOPPED, DLSTATUS_METADATA
from Tribler.Core.Socks5.server import Socks5Server
from Tribler.pyipv8.ipv8.messaging.anonymization.community import message_to_payload, SINGLE_HOP_ENC_PACKETS, \
    tc_lazy_wrapper_unsigned
from Tribler.pyipv8.ipv8.messaging.deprecated.encoding import decode
from Tribler.pyipv8.ipv8.messaging.anonymization.hidden_services import HiddenTunnelCommunity
from Tribler.pyipv8.ipv8.messaging.anonymization.payload import LinkedE2EPayload, DHTResponsePayload
from Tribler.pyipv8.ipv8.messaging.anonymization.tunnel import CIRCUIT_STATE_READY, CIRCUIT_TYPE_RP, \
    CIRCUIT_TYPE_DATA, CIRCUIT_TYPE_RENDEZVOUS, EXIT_NODE, RelayRoute
from Tribler.pyipv8.ipv8.peer import Peer
from Tribler.pyipv8.ipv8.peerdiscovery.network import Network


class TriblerTunnelCommunity(HiddenTunnelCommunity):
    """
    This community is built upon the anonymous messaging layer in IPv8.
    It adds support for libtorrent anonymous downloads and bandwidth token payout when closing circuits.
    """
    master_peer = Peer("3081a7301006072a8648ce3d020106052b81040027038192000400965194026c987edad7c5c0364a95dfa4e961e"
                       "ec6d1711678be182a31824363db3a54caa11e9b6f1d6051c2f33578b51c12eff3833b7c74c5a243b8705e4e032b"
                       "14904f4d8855e2044c0408a5729cd4e5b286fec66866811d5439049448e5b8b818d8c29a84a074a13f5e7e414d4"
                       "e5b1b115a221fe697b89bd3e63c7aecd7617f789a203a4eacf680279224b390e836".decode('hex'))

    def __init__(self, *args, **kwargs):
        self.tribler_session = kwargs.pop('tribler_session', None)
        num_competing_slots = kwargs.pop('competing_slots', 15)
        num_random_slots = kwargs.pop('random_slots', 5)
        self.bandwidth_wallet = kwargs.pop('bandwidth_wallet', None)
        socks_listen_ports = kwargs.pop('socks_listen_ports', None)
        self.annon_seeding_enabled = kwargs.pop('annon_seeding_enabled', True)
        self.netflow_scoring_enabled = kwargs.pop('netflow_scoring_enabled', False)
        state_path = self.tribler_session.config.get_state_dir() if self.tribler_session else ''
        self.exitnode_cache = kwargs.pop('exitnode_cache', os.path.join(state_path, 'exitnode_cache.dat'))
        super(TriblerTunnelCommunity, self).__init__(*args, **kwargs)
        self._use_main_thread = True

        if self.tribler_session:
            self.settings.become_exitnode = self.tribler_session.config.get_tunnel_community_exitnode_enabled()
            self.tribler_session.lm.tunnel_community = self

            if not socks_listen_ports:
                socks_listen_ports = self.tribler_session.config.get_tunnel_community_socks5_listen_ports()
        elif socks_listen_ports is None:
            socks_listen_ports = range(1080, 1085)

        self.bittorrent_peers = {}
        self.dispatcher = TunnelDispatcher(self)
        self.download_states = {}
        self.competing_slots = [(-1, None, None)] * num_competing_slots  # 1st tuple item = token balance, 2nd = circuit id, 3rd = peer pk
        self.random_slots = [None] * num_random_slots
        self.reject_callback = None  # This callback is invoked with a tuple (time, balance) when we reject a circuit

        self.logger.warning("Slot counts: compete %s, random %s, netflow: %s", len(self.competing_slots), len(self.random_slots), self.netflow_scoring_enabled)

        # Start the SOCKS5 servers
        self.socks_servers = []
        for port in socks_listen_ports:
            socks_server = Socks5Server(port, self.dispatcher)
            socks_server.start()
            self.socks_servers.append(socks_server)

        self.dispatcher.set_socks_servers(self.socks_servers)

        self.decode_map.update({
            chr(23): self.on_payout_block,
        })

        self.decode_map_private.update({
            chr(24): self.on_balance_request_cell,
            chr(25): self.on_relay_balance_request_cell,
            chr(26): self.on_balance_response_cell,
            chr(27): self.on_relay_balance_response_cell,
        })

        message_to_payload[u"balance-request"] = (24, BalanceRequestPayload)
        message_to_payload[u"relay-balance-request"] = (25, BalanceRequestPayload)
        message_to_payload[u"balance-response"] = (26, BalanceResponsePayload)
        message_to_payload[u"relay-balance-response"] = (27, BalanceResponsePayload)

        SINGLE_HOP_ENC_PACKETS.append(u"balance-request")
        SINGLE_HOP_ENC_PACKETS.append(u"balance-response")

        if self.exitnode_cache:
            self.restore_exitnodes_from_disk()

    def cache_exitnodes_to_disk(self):
        """
        Wite a copy of self.exit_candidates to the file self.exitnode_cache.

        :returns: None
        """
        exit_nodes = Network()
        for peer in self.exit_candidates.values():
            exit_nodes.add_verified_peer(peer)
        self.logger.debug('Writing exit nodes to cache: %s', self.exitnode_cache)
        with open(self.exitnode_cache, 'w') as cache:
            cache.write(exit_nodes.snapshot())

    def restore_exitnodes_from_disk(self):
        """
        Send introduction requests to peers stored in the file self.exitnode_cache.

        :returns: None
        """
        if os.path.isfile(self.exitnode_cache):
            self.logger.debug('Loading exit nodes from cache: %s', self.exitnode_cache)
            exit_nodes = Network()
            with open(self.exitnode_cache, 'r') as cache:
                exit_nodes.load_snapshot(cache.read())
            for exit_node in exit_nodes.get_walkable_addresses():
                self.endpoint.send(exit_node, self.create_introduction_request(exit_node))
        else:
            self.logger.error('Could not retrieve backup exitnode cache, file does not exist!')

    def on_token_balance(self, circuit_id, balance):
        """
        We received the token balance of a circuit initiator. Check whether we can allocate a slot to this user.
        """
        if not self.request_cache.has(u"balance-request", circuit_id):
            self.logger.warning("Received token balance without associated request cache!")
            return

        cache = self.request_cache.pop(u"balance-request", circuit_id)

        lowest_balance = sys.maxint
        lowest_index = -1
        for ind, tup in enumerate(self.competing_slots):
            if not tup[1]:
                # The slot is empty, take it
                self.competing_slots[ind] = (balance, circuit_id, None)
                cache.balance_deferred.callback(True)
                return

            if tup[0] < lowest_balance:
                lowest_balance = tup[0]
                lowest_index = ind

        self.logger.info("Received balance %d for circuit_id %d, lowest (index: %d, balance: %d)", balance, circuit_id, lowest_index, lowest_balance)

        if balance > lowest_balance:
            # We kick this user out
            old_circuit_id = self.competing_slots[lowest_index][1]
            self.logger.info("Kicked out circuit %s (balance: %s) in favor of %s (balance: %s)",
                             old_circuit_id, lowest_balance, circuit_id, balance)
            self.competing_slots[lowest_index] = (balance, circuit_id, None)

            self.remove_relay(old_circuit_id, destroy=True)
            self.remove_exit_socket(old_circuit_id, destroy=True)

            cache.balance_deferred.callback(True)
        else:
            # We can't compete with the balances in the existing slots
            if self.reject_callback:
                self.reject_callback(time.time(), balance)
            cache.balance_deferred.callback(False)

    def should_join_circuit(self, create_payload, previous_node_address):
        """
        Check whether we should join a circuit. Returns a deferred that fires with a boolean.
        """
        if self.settings.max_joined_circuits <= len(self.relay_from_to) + len(self.exit_sockets):
            self.logger.warning("too many relays (%d)", (len(self.relay_from_to) + len(self.exit_sockets)))
            return succeed(False)

        # Check whether we have a random open slot, if so, allocate this to this request.
        circuit_id = create_payload.circuit_id
        for index, slot in enumerate(self.random_slots):
            if not slot:
                self.random_slots[index] = circuit_id
                return succeed(True)

        # if already in competing slots, reject
        if len([slot for slot in self.competing_slots if slot[2] == create_payload.node_public_key]) > 0:
            return succeed(False)

        self.logger.warning("Netflow? enabled: %s, wallet != None: %s", self.netflow_scoring_enabled, self.bandwidth_wallet is None)
        # No random slots but this user might be allocated a competing slot.
        # If netflow is enabled, check if the peer can compete
        if self.netflow_scoring_enabled and self.bandwidth_wallet:
            result = self.check_netflow(circuit_id, create_payload.node_public_key)
            if result:
                return result

        # If netflow is not enabled or not working we fallback to the old way of balance requests
        # we request the token balance of the circuit initiator.
        balance_deferred = Deferred()
        self.request_cache.add(BalanceRequestCache(self, circuit_id, balance_deferred))

        # Temporarily add these values, otherwise we are unable to communicate with the previous hop.
        self.directions[circuit_id] = EXIT_NODE
        shared_secret, _, _ = self.crypto.generate_diffie_shared_secret(create_payload.key)
        self.relay_session_keys[circuit_id] = self.crypto.generate_session_keys(shared_secret)

        self.send_cell([Peer(create_payload.node_public_key, previous_node_address)], u"balance-request",
                       BalanceRequestPayload(circuit_id))

        self.directions.pop(circuit_id, None)
        self.relay_session_keys.pop(circuit_id, None)
        self.logger.warning("Requesting Balance for circuit %d", circuit_id)

        return balance_deferred

    def check_netflow(self, circuit_id, initiating_pk):
        self.logger.warning("Performing netflow check for PK %s, current slots %r", initiating_pk, self.competing_slots)

        competing_pks = set([tup[2] for tup in self.competing_slots if tup[2] is not None] + [initiating_pk])
        self.logger.warning("Competing pk's %r", competing_pks)
        scores = BandwidthDatabaseListener.find_in(self.bandwidth_wallet.trustchain).update_scores(
            self.my_peer.public_key.key_to_bin(), competing_pks)
        self.logger.warning("Computed scores %r", scores)

        if len(scores) == 0:
            self.logger.warning("Netflow failed? Or no score? Fallback to balance request")
            return None

        initiator_score = [score for score, pk in scores if pk == initiating_pk][0]
        for ind, tup in enumerate(self.competing_slots):
            if not tup[1]:
                # The slot is empty, take it
                self.logger.warning("Selecting empty slot index %d, slot %r", ind, tup)
                self.competing_slots[ind] = (initiator_score, circuit_id, initiating_pk)
                return succeed(True)

        lowest_score = None
        for score, pk in scores:
            if score < initiator_score - 10000 and (lowest_score is None or lowest_score[0] > score):
                lowest_score = (score, pk)

        if lowest_score is None:
            # initiating_pk has lowest score, or no tunnel is appicable for pre-empting
            return succeed(False)
        else:
            # initiating_pk is not the lowest score, kill one of the other circuits
            slot = random.choice([slot for slot in self.competing_slots if slot[2] == lowest_score[1]])
            self.logger.info("Kicked out circuit %s (balance: %s) in favor of %s (balance: %s)",
                             slot[0], lowest_score[0], circuit_id, initiator_score)
            self.competing_slots.remove(slot)
            self.competing_slots.append((lowest_score[0], circuit_id, initiating_pk))
            self.remove_relay(slot[1], destroy=True)
            self.remove_exit_socket(slot[1], destroy=True)
            return succeed(True)

    def on_payout_block(self, source_address, data):
        if not self.bandwidth_wallet:
            self.logger.warning("Got payout while not having a TrustChain community running!")
            return

        payload = self._ez_unpack_noauth(PayoutPayload, data, global_time=False)
        self.bandwidth_wallet.trustchain.process_half_block(TriblerBandwidthBlock.from_payload(payload, self.serializer), Peer(payload.public_key, source_address))

    def on_balance_request_cell(self, source_address, data, _):
        payload = self._ez_unpack_noauth(BalanceRequestPayload, data, global_time=False)

        circuit_id = payload.circuit_id
        request = self.request_cache.get(u"anon-circuit", circuit_id)
        if not request:
            self.logger.warning("Circuit creation cache for id %s not found!", circuit_id)
            return

        if request.should_forward:
            forwarding_relay = RelayRoute(request.from_circuit_id, request.peer)
            self.send_cell([forwarding_relay.peer.address], u"relay-balance-request",
                           BalanceRequestPayload(forwarding_relay.circuit_id))
        else:
            self.on_balance_request(payload)

    def on_relay_balance_request_cell(self, source_address, data, _):
        payload = self._ez_unpack_noauth(BalanceRequestPayload, data, global_time=False)
        self.on_balance_request(payload)

    def on_balance_request(self, payload):
        """
        We received a balance request from a relay or exit node. Respond with the latest block in our chain.
        """
        if not self.bandwidth_wallet:
            self.logger.warn("Bandwidth wallet is not available, not sending balance response!")
            return

        # Get the latest block
        latest_block = self.bandwidth_wallet.trustchain.persistence.get_latest(self.my_peer.public_key.key_to_bin(),
                                                                               block_type='tribler_bandwidth')
        if not latest_block:
            latest_block = TriblerBandwidthBlock()
            self.logger.info("Send balance 0 = (0 - 0)")
        else:
            self.logger.info("Send balance %s = (%s - %s)", latest_block.transaction["total_up"] -
                              latest_block.transaction["total_down"], latest_block.transaction["total_up"],
                              latest_block.transaction["total_down"])
        latest_block.public_key = EMPTY_PK  # We hide the public key

        # We either send the response directly or relay the response to the last verified hop
        circuit = self.circuits[payload.circuit_id]
        if not circuit.hops:
            self.increase_bytes_sent(circuit, self.send_cell([circuit.peer.address],
                                                             u"balance-response",
                                                             BalanceResponsePayload.from_half_block(
                                                                 latest_block, circuit.circuit_id)))
        else:
            self.increase_bytes_sent(circuit, self.send_cell([circuit.peer.address],
                                                             u"relay-balance-response",
                                                             BalanceResponsePayload.from_half_block(
                                                                 latest_block, circuit.circuit_id)))

    def on_balance_response_cell(self, source_address, data, _):
        payload = self._ez_unpack_noauth(BalanceResponsePayload, data, global_time=False)
        block = TriblerBandwidthBlock.from_payload(payload, self.serializer)
        if not block.transaction:
            self.on_token_balance(payload.circuit_id, 0)
        else:
            self.on_token_balance(payload.circuit_id,
                                  block.transaction["total_up"] - block.transaction["total_down"])

    def on_relay_balance_response_cell(self, source_address, data, _):
        payload = self._ez_unpack_noauth(BalanceResponsePayload, data, global_time=False)
        block = TriblerBandwidthBlock.from_payload(payload, self.serializer)

        # At this point, we don't have the circuit ID of the follow-up hop. We have to iterate over the items in the
        # request cache and find the link to the next hop.
        for cache in self.request_cache._identifiers.values():
            if isinstance(cache, ExtendRequestCache) and cache.from_circuit_id == payload.circuit_id:
                self.send_cell([cache.to_peer.address],
                               u"balance-response",
                               BalanceResponsePayload.from_half_block(block, cache.to_circuit_id))

    def on_download_removed(self, download):
        """
        This method is called when a download is removed. We check here whether we can stop building circuits for a
        specific number of hops in case it hasn't been finished yet.
        """
        if download.get_hops() > 0:
            self.num_hops_by_downloads[download.get_hops()] -= 1
            if self.num_hops_by_downloads[download.get_hops()] == 0:
                self.circuits_needed[download.get_hops()] = 0

    def readd_bittorrent_peers(self):
        self.logger.info("Re-adding peers")
        for torrent, peers in self.bittorrent_peers.items():
            infohash = torrent.tdef.get_infohash().encode("hex")
            for peer in peers:
                self.logger.info("Re-adding peer %s to torrent %s", peer, infohash)
                torrent.add_peer(peer)
            del self.bittorrent_peers[torrent]

    def update_torrent(self, peers, handle, download):
        self.logger.info("Updating download %s. Peers (%r) handle (%r) ", download.get_def().get_name(), peers, list(handle.get_peer_info()))
        peers = peers.intersection(handle.get_peer_info())
        if peers:
            if download not in self.bittorrent_peers:
                self.bittorrent_peers[download] = peers
            else:
                self.bittorrent_peers[download] = peers | self.bittorrent_peers[download]

            self.logger.info("Updating download %s. Bittorrent peers %r", download.get_def().get_name(), self.bittorrent_peers[download])
            # If there are active circuits, add peers immediately. Otherwise postpone.
            if self.active_data_circuits():
                self.readd_bittorrent_peers()

    def get_peer_from_address(self, address):
        circuit_peer = None
        for peer in self.get_peers():
            if peer.address == address:
                circuit_peer = peer
                break

        return circuit_peer

    def do_payout(self, peer, circuit_id, down, up):
        """
        Perform a payout to a specific peer.
        :param peer: The peer to perform the payout to, usually the next node in the circuit.
        :param circuit_id: The circuit id of the payout, used by the subsequent node.
        :param amount: The amount to put in the transaction, multiplier of base_amount.
        :param base_amount: The base amount for the payouts.
        """
        if down + up < tc_wallet.MIN_TRANSACTION_SIZE:
            self.logger.info("Transaction to small, not doing payout. d:%d,u:%d to %s (cid: %s)", down, up, peer, circuit_id)
            return

        self.logger.info("Sending payout of d:%d,u:%d to %s (cid: %s)", down, up, peer, circuit_id)

        block = TriblerBandwidthBlock.create(
            'tribler_bandwidth',
            {'up': up, 'down': down},
            self.bandwidth_wallet.trustchain.persistence,
            self.my_peer.public_key.key_to_bin(),
            link_pk=peer.public_key.key_to_bin())
        block.sign(self.my_peer.key)
        self.bandwidth_wallet.trustchain.persistence.add_block(block)

        payload = PayoutPayload.from_half_block(block, circuit_id, 0).to_pack_list()
        packet = self._ez_pack(self._prefix, 23, [payload], False)
        self.send_packet([peer], u"payout", packet)
        self.logger.info("Signed block to peer (%s) validation result valid", block)

    def clean_from_slots(self, circuit_id):
        """
        Clean a specific circuit from the allocated slots.
        """
        for ind, slot in enumerate(self.random_slots):
            if slot == circuit_id:
                self.random_slots[ind] = None

        for ind, tup in enumerate(self.competing_slots):
            if tup[1] == circuit_id:
                self.competing_slots[ind] = (-1, None, None)

    def remove_circuit(self, circuit_id, additional_info='', remove_now=False, destroy=False):
        if circuit_id not in self.circuits:
            self.logger.warning("Circuit %d not found when trying to remove it", circuit_id)
            return

        circuit = self.circuits[circuit_id]

        # Send the notification
        if self.tribler_session:
            self.tribler_session.notifier.notify(NTFY_TUNNEL, NTFY_REMOVE, circuit, circuit.peer.address)

        circuit_peer = self.get_peer_from_address(circuit.peer.address)
        if circuit.bytes_up < circuit.bytes_down and self.bandwidth_wallet and circuit_peer:
            # We should perform a payout of the removed circuit.
            self.do_payout(circuit_peer, circuit_id, circuit.bytes_down, circuit.bytes_up)
        else:
            self.logger.info("No payout for %d, size d:%d,u:%d, wallet? %s, peer? %s", circuit_id, circuit.bytes_down, circuit.bytes_up, self.bandwidth_wallet is not None, circuit_peer is not None)
            # TODO: update tc_database_listener with pending bytes
            pass

        # Reset the circuit byte counters so we do not payout again if we receive a destroy message.
        circuit.bytes_up = circuit.bytes_down = 0

        # Now we actually remove the circuit
        remove_deferred = super(TriblerTunnelCommunity, self)\
            .remove_circuit(circuit_id, additional_info=additional_info, remove_now=remove_now, destroy=destroy)

        affected_peers = self.dispatcher.circuit_dead(circuit)

        def update_torrents(_):
            ltmgr = self.tribler_session.lm.ltmgr \
                if self.tribler_session and self.tribler_session.config.get_libtorrent_enabled() else None
            if ltmgr:
                for d, s in ltmgr.torrents.values():
                    if s == ltmgr.get_session(d.get_hops()):
                        d.get_handle().addCallback(lambda handle, download=d:
                                                   self.update_torrent(affected_peers, handle, download))

        remove_deferred.addCallback(update_torrents)

        return remove_deferred

    def remove_relay(self, circuit_id, additional_info='', remove_now=False, destroy=False, got_destroy_from=None,
                     both_sides=True):
        removed_relays = super(TriblerTunnelCommunity, self).remove_relay(circuit_id,
                                                                          additional_info=additional_info,
                                                                          remove_now=remove_now,
                                                                          destroy=destroy,
                                                                          got_destroy_from=got_destroy_from,
                                                                          both_sides=both_sides)

        self.clean_from_slots(circuit_id)

        if self.tribler_session:
            for removed_relay in removed_relays:
                self.tribler_session.notifier.notify(NTFY_TUNNEL, NTFY_REMOVE, removed_relay,
                                                     removed_relay.peer.address)

    def remove_exit_socket(self, circuit_id, additional_info='', remove_now=False, destroy=False):
        if circuit_id in self.exit_sockets and self.tribler_session:
            exit_socket = self.exit_sockets[circuit_id]
            self.tribler_session.notifier.notify(NTFY_TUNNEL, NTFY_REMOVE, exit_socket, exit_socket.peer.address)

        self.clean_from_slots(circuit_id)

        super(TriblerTunnelCommunity, self).remove_exit_socket(circuit_id, additional_info=additional_info,
                                                               remove_now=remove_now, destroy=destroy)

    def _ours_on_created_extended(self, circuit, payload):
        super(TriblerTunnelCommunity, self)._ours_on_created_extended(circuit, payload)

        if circuit.state == CIRCUIT_STATE_READY:
            # Re-add BitTorrent peers, if needed.
            self.readd_bittorrent_peers()

        if self.tribler_session:
            self.tribler_session.notifier.notify(
                NTFY_TUNNEL, NTFY_CREATED if len(circuit.hops) == 1 else NTFY_EXTENDED, circuit)

    def join_circuit(self, create_payload, previous_node_address):
        super(TriblerTunnelCommunity, self).join_circuit(create_payload, previous_node_address)

        if self.tribler_session:
            circuit_id = create_payload.circuit_id
            self.tribler_session.notifier.notify(NTFY_TUNNEL, NTFY_JOINED, previous_node_address, circuit_id)

    def on_raw_data(self, circuit, origin, data):
        anon_seed = circuit.ctype == CIRCUIT_TYPE_RP
        self.dispatcher.on_incoming_from_tunnel(self, circuit, origin, data, anon_seed)

    def monitor_downloads(self, dslist):
        # Monitor downloads with anonymous flag set, and build rendezvous/introduction points when needed.
        new_states = {}
        hops = {}
        real_hashes = {}

        for ds in dslist:
            download = ds.get_download()
            if download.get_hops() > 0:
                # Convert the real infohash to the infohash used for looking up introduction points
                real_info_hash = download.get_def().get_infohash()
                info_hash = self.get_lookup_info_hash(real_info_hash)
                real_hashes[info_hash] = real_info_hash
                hops[info_hash] = download.get_hops()
                self.service_callbacks[info_hash] = download.add_peer
                new_states[info_hash] = ds.get_status()

        self.hops = hops

        for info_hash in set(new_states.keys() + self.download_states.keys()):
            new_state = new_states.get(info_hash, None)
            old_state = self.download_states.get(info_hash, None)
            state_changed = new_state != old_state

            # Stop creating introduction points if the download doesn't exist anymore
            if info_hash in self.infohash_ip_circuits and new_state is None:
                del self.infohash_ip_circuits[info_hash]

            # If the introducing circuit does not exist anymore or timed out: Build a new circuit
            if info_hash in self.infohash_ip_circuits:
                for (circuit_id, time_created) in self.infohash_ip_circuits[info_hash]:
                    if circuit_id not in self.my_intro_points and time_created < time.time() - 30:
                        self.infohash_ip_circuits[info_hash].remove((circuit_id, time_created))
                        if self.tribler_session.notifier:
                            self.tribler_session.notifier.notify(
                                NTFY_TUNNEL, NTFY_IP_RECREATE, circuit_id, info_hash.encode('hex')[:6])
                        self.logger.info('Recreate the introducing circuit for %s', info_hash.encode('hex'))
                        self.create_introduction_point(info_hash)

            time_elapsed = (time.time() - self.last_dht_lookup.get(info_hash, 0))
            force_dht_lookup = time_elapsed >= self.settings.dht_lookup_interval
            if (state_changed or force_dht_lookup) and (new_state == DLSTATUS_DOWNLOADING or new_state == DLSTATUS_METADATA):
                self.logger.info('Do dht lookup to find hidden services peers for %s', info_hash.encode('hex'))
                self.do_raw_dht_lookup(info_hash, real_hashes[info_hash])

            if state_changed and new_state == DLSTATUS_SEEDING:
                self.create_introduction_point(info_hash)

            elif state_changed and new_state in [DLSTATUS_STOPPED, None]:
                if info_hash in self.infohash_pex:
                    self.infohash_pex.pop(info_hash)

                for cid, info_hash_hops in self.my_download_points.items():
                    if info_hash_hops[0] == info_hash:
                        self.remove_circuit(cid, 'download stopped', destroy=True)

                for cid, info_hash_list in self.my_intro_points.items():
                    for i in xrange(len(info_hash_list) - 1, -1, -1):
                        if info_hash_list[i] == info_hash:
                            info_hash_list.pop(i)

                    if len(info_hash_list) == 0:
                        self.remove_circuit(cid, 'all downloads stopped', destroy=True)

        self.download_states = new_states

    def get_download(self, lookup_info_hash):
        if not self.tribler_session:
            return None

        for download in self.tribler_session.get_downloads():
            if lookup_info_hash == self.get_lookup_info_hash(download.get_def().get_infohash()):
                return download

    def do_raw_dht_lookup(self, lookup_info_hash, info_hash):
        super(TriblerTunnelCommunity, self).do_raw_dht_lookup(lookup_info_hash, info_hash)

        def dht_callback(info):
            _, peers, __ = info
            if not peers:
                peers = []
            if len(peers) <= 0:
                return
            else:
                self.logger.info("Got direct result: %s peers. Adding to download", len(peers))

            download = self.tribler_session.get_download(info_hash)
            if download:
                for peer in peers:
                    self.logger.info("Added real info hash peer looked up in dht (%s)", repr(peer))
                    download.add_peer(peer)
            else:
                self.logger.info("Download %s vanished?", info_hash.encode('hex'))

        self.logger.info("Doing real dht lookup for real info_hash %s" % info_hash.encode('HEX'))
        self.dht_lookup(info_hash, dht_callback)

    @tc_lazy_wrapper_unsigned(DHTResponsePayload)
    def on_dht_response(self, source_address, payload, circuit_id=None):
        if not self.is_relay(payload.circuit_id) and not self.request_cache.has(u"dht-request", payload.identifier):
            self.logger.warning('Got a dht-response with an unknown identifier')
            return

        info_hash = payload.info_hash
        _, peers = decode(payload.peers)
        cache = self.request_cache.get(u"dht-request", payload.identifier)
        peers = set(peers)
        self.logger.info("Received override dht response containing %d peers" % len(peers))
        if not cache.is_real:
            blacklist = self.dht_blacklist[info_hash]

            # cleanup dht_blacklist
            for i in xrange(len(blacklist) - 1, -1, -1):
                if time.time() - blacklist[i][0] > 60:
                    blacklist.pop(i)
            exclude = [rp[2] for rp in self.my_download_points.values()] + [sock_addr for _, sock_addr in blacklist]
            for peer in peers:
                if peer not in exclude:
                    self.logger.info("Requesting key from dht peer %s", peer)
                    # Blacklist this sock_addr for a period of at least 60s
                    self.dht_blacklist[info_hash].append((time.time(), peer))
                    self.create_key_request(info_hash, peer)
        else:
            download = self.tribler_session.get_download(info_hash)
            if download:
                for peer in peers:
                    self.logger.info("Added real info hash peer looked up in dht (%s)", repr(peer))
                    download.add_peer(peer)

    def create_introduction_point(self, info_hash, amount=1):
        self.logger.info("Is annon seeding enabled:", self.annon_seeding_enabled)
        if not self.annon_seeding_enabled:
            return
        download = self.get_download(info_hash)
        if download:
            download.add_peer(('1.1.1.1', 1024))
        super(TriblerTunnelCommunity, self).create_introduction_point(info_hash, amount)

    def on_linked_e2e(self, source_address, data, circuit_id):
        payload = self._ez_unpack_noauth(LinkedE2EPayload, data, global_time=False)
        cache = self.request_cache.get(u"link-request", payload.identifier)
        if cache:
            download = self.get_download(cache.info_hash)
            if download:
                download.add_peer((self.circuit_id_to_ip(cache.circuit.circuit_id), 1024))
            else:
                self.logger.error('On linked e2e: could not find download!')
        super(TriblerTunnelCommunity, self).on_linked_e2e(source_address, data, circuit_id)

    @inlineCallbacks
    def unload(self):
        if self.bandwidth_wallet:
            self.bandwidth_wallet.shutdown_task_manager()
        for socks_server in self.socks_servers:
            yield socks_server.stop()

        if self.exitnode_cache:
            self.cache_exitnodes_to_disk()

        super(TriblerTunnelCommunity, self).unload()


class TriblerTunnelTestnetCommunity(TriblerTunnelCommunity):
    """
    This community defines a testnet for the anonymous tunnels.
    """
    master_peer = Peer("3081a7301006072a8648ce3d020106052b81040027038192000401325e6f0a67a92a890344013914fcf9da9b0326"
                       "bf6c845815ec8b537e356a56b2a8c27ac4918078202f60eb29ebf081436136c280316ac461daee2d04cf073d1200"
                       "80d15628af1002b0c0273d9d94fdab08e718f568d83b9c4298117261b5647ca8295f1ba4b880a50fd2ef7041fef7"
                       "edfbef5f02fc03827a2c09c5f9c701f87abacd022c780d76733c133363a5c46c".decode('hex'))
