from subprocess import Popen, PIPE
from random import random
from time import time

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import LoopingCall

from Tribler.Core.simpledefs import NTFY_TUNNEL, NTFY_REMOVE
from Tribler.community.triblerchain.block import TriblerChainBlock
from Tribler.community.triblerchain.database import TriblerChainDB
from Tribler.community.trustchain.community import TrustChainCommunity
from Tribler.dispersy.util import blocking_call_on_reactor_thread

MIN_TRANSACTION_SIZE = 1024 * 1024


class PendingBytes(object):
    def __init__(self, up, down, clean=None):
        super(PendingBytes, self).__init__()
        self.up = up
        self.down = down
        self.clean = clean

    def add(self, up, down):
        if self.up + up >= 0 and self.down + down >= 0:
            self.up = max(0, self.up + up)
            self.down = max(0, self.down + down)
            if self.clean is not None:
                self.clean.reset(2 * 60)
            return True
        else:
            return False


class TriblerChainCommunity(TrustChainCommunity):
    """
    Community for reputation based on TrustChain tamper proof interaction history.
    """
    BLOCK_CLASS = TriblerChainBlock
    DB_CLASS = TriblerChainDB
    DB_NAME = "triblerchain"
    SIGN_DELAY = 5
    SCORE_REFRESH_INTERVAL = 30 * 60  # update every half hour

    def __init__(self, *args, **kwargs):
        super(TriblerChainCommunity, self).__init__(*args, **kwargs)
        self.notifier = None

        # We store the bytes send and received in the tunnel community in a dictionary.
        # The key is the public key of the peer being interacted with, the value a tuple of the up and down bytes
        # This data is not used to create outgoing requests, but _only_ to verify incoming requests
        self.pending_bytes = dict()

        # We store the score for each PK that we know of here
        # TODO: clean up the obvious memory leak
        self.scores = dict()
        self.scores_last_update = dict()

        # Store invalid messages since one of these might contain a block that is bought on the market
        self.pending_sign_messages = {}

    @classmethod
    def get_master_members(cls, dispersy):
        # generated: Mon Jun 19 09:25:14 2017
        # curve: None
        # len: 571 bits ~ 144 bytes signature
        # pub: 170 3081a7301006072a8648ce3d020106052b81040027038192000403a4cf6036eb2a9daa0ae4bd23c1be5343c0b2d30fa85
        # da2554532e3e73ba1fde4db0c8864c7f472ce688afef5a9f7ccfe1396bb5ef09be80e00e0a5ab4814f43166d086720af10807dbb1f
        # a71c06040bb4aadc85fdffe69cdc6125f5b5f81c785f6b3fece98c5ecfa6de61432822e52a049850d11802dc1050a60f6983ac3eed
        # b8172ebc47e3cd50f1d97bfffe187b5
        # pub-sha1 1742feacab3bcc3ee8c4d7ee16d9c0b57e0bb266
        # prv-sha1 2d4025490ef949ea7347d020f09403c46222483a
        # -----BEGIN PUBLIC KEY-----
        # MIGnMBAGByqGSM49AgEGBSuBBAAnA4GSAAQDpM9gNusqnaoK5L0jwb5TQ8Cy0w+o
        # XaJVRTLj5zuh/eTbDIhkx/RyzmiK/vWp98z+E5a7XvCb6A4A4KWrSBT0MWbQhnIK
        # 8QgH27H6ccBgQLtKrchf3/5pzcYSX1tfgceF9rP+zpjF7Ppt5hQygi5SoEmFDRGA
        # LcEFCmD2mDrD7tuBcuvEfjzVDx2Xv//hh7U=
        # -----END PUBLIC KEY-----
        master_key = "3081a7301006072a8648ce3d020106052b81040027038192000403a4cf6036eb2a9daa0ae4bd23c1be5343c0b2d30f" \
                     "a85da2554532e3e73ba1fde4db0c8864c7f472ce688afef5a9f7ccfe1396bb5ef09be80e00e0a5ab4814f43166d086" \
                     "720af10807dbb1fa71c06040bb4aadc85fdffe69cdc6125f5b5f81c785f6b3fece98c5ecfa6de61432822e52a04985" \
                     "0d11802dc1050a60f6983ac3eedb8172ebc47e3cd50f1d97bfffe187b5"
        return [dispersy.get_member(public_key=master_key.decode("HEX"))]

    def initialize(self, tribler_session=None):
        super(TriblerChainCommunity, self).initialize(tribler_session)
        if tribler_session:
            self.notifier = tribler_session.notifier
            self.notifier.add_observer(self.on_tunnel_remove, NTFY_TUNNEL, [NTFY_REMOVE])

    def received_payment_message(self, payment_id):
        """
        We received a payment message originating from the market community. We set pending bytes so the validator
        passes when we receive the half block from the counterparty.

        Note that it might also be possible that the half block has been received already. That's why we revalidate
        the invalid messages again.
        """
        pub_key, seq_num, bytes_up, bytes_down = payment_id.split('.')
        pub_key = pub_key.decode('hex')
        pend = self.pending_bytes.get(pub_key)
        if not pend:
            self.pending_bytes[pub_key] = PendingBytes(int(bytes_up),
                                                       int(bytes_down),
                                                       None)
        else:
            pend.add(int(bytes_up), int(bytes_down))

        block_id = "%s.%s" % (pub_key.encode('hex'), seq_num)
        if block_id in self.pending_sign_messages:
            self._logger.debug("Signing pending half block")
            message = self.pending_sign_messages[block_id]
            self.sign_block(message.candidate, linked=message.payload.block)
            del self.pending_sign_messages[block_id]

    def should_sign(self, message):
        """
        Return whether we should sign the block in the passed message.
        @param message: the message containing a block we want to sign or not.
        """
        block = message.payload.block
        pend = self.pending_bytes.get(block.public_key)
        if not pend or not (pend.up - block.down >= 0 and pend.down - block.up >= 0):
            self.logger.info("Request block counter party does not have enough bytes pending. U: %d D: %d",
                             pend.up if pend is not None else -1, pend.down if pend is not None else -1)

            # These bytes might have been bought on the market so we store this message and process it when we
            # receive a payment message that confirms we have bought these bytes.
            block_id = "%s.%s" % (block.public_key.encode('hex'), block.sequence_number)
            self.pending_sign_messages[block_id] = message
            return False
        return True

    @blocking_call_on_reactor_thread
    def _update_scores(self, node_pks):
        me = self.my_member.public_key
        update_pks = set([pk for pk in node_pks if pk != me and (
            pk not in self.scores_last_update or self.scores_last_update[pk] + self.SCORE_REFRESH_INTERVAL < time())])
        if len(update_pks) == 0:
            return

        # perform pimrank/netflow here to score candidates
        graph = self.persistence.get_subjective_work_graph()
        keys = []
        for k in graph.iterkeys():
            if k[0] not in keys:
                keys.append(k[0])
            if k[1] not in keys:
                keys.append(k[1])

        variables = dict()
        bound = dict()
        constraints = [0]

        def define_variable(name):
            if name not in variables:
                variables[name] = "x%s" % len(variables)
                bound[name] = None
            return variables[name]

        solver = Popen(["/usr/bin/glpsol", "--lp", "/proc/self/fd/0", "-w", "/proc/self/fd/2"], stdin=PIPE, stderr=PIPE)

        def writelp(output):
            solver.stdin.write(output)
            print(output)

        def define_constraint(plus, minus=None, value=0, constraint_type='eq'):
            if constraint_type == "ub" and plus is not None and len(plus) == 1 and minus is None:
                define_variable(plus[0])
                bound[plus[0]] = value if bound[plus[0]] is None else min(value, bound[plus[0]])
                return
            parts = []
            if plus:
                parts.append(" + ".join([define_variable(name) for name in plus]))
            if minus:
                parts.append(" - ".join([define_variable(name) for name in minus]))
            writelp("c%s: %s %s %s\n" % (constraints[0], " - ".join(parts),
                                                    "=" if constraint_type == 'eq' else "<=", value))
            constraints[0] += 1

        def max_flow(g, source, sink, prefix, cap_prefix = None):
            prefix = "%s_%s" % (prefix, source.encode("hex"))
            for k in g.iterkeys():
                define_constraint(["%s__%s_%s" % (prefix, k[0].encode("hex"), k[1].encode("hex"))],
                                  value=g[k][0], constraint_type='ub')
            for pk in keys:
                plus = []
                minus = []
                for k in g.iterkeys():
                    if k[0] == pk:
                        plus.append("%s__%s_%s" % (prefix, k[0].encode("hex"), k[1].encode("hex")))
                    if k[1] == pk:
                        minus.append("%s__%s_%s" % (prefix, k[0].encode("hex"), k[1].encode("hex")))
                if pk == source:
                    # nothing should flow into the source, sum(minus) = 0
                    define_constraint(plus=minus)
                elif pk == sink:
                    # nothing should flow out of the sink, sum(plus) = 0
                    define_constraint(plus)
                    # define sum(minus) - prefix = 0. It defines variable prefix as the "result" of this maxflow.
                    define_constraint(plus=minus, minus=[prefix])
                else:
                    # in any other node, the flow out (plus) and in (minus) should be balanced
                    define_constraint(plus, minus)
                    node_cap = "%s_%s" % (cap_prefix, pk.encode("hex"))
                    if node_cap in variables:
                        # if we have a variable for this node's capacity, apply it as max to the flow coming in.
                        # this is where the magic happens, since it is a bound and not an equality, the optimizer might
                        # need to to only a few steps in the P1 max flow LP problem to verify this P2 flow is indeed
                        # possible.
                        define_constraint(plus=minus, minus=[node_cap], constraint_type='ub')

        if len(update_pks) == 0:
            self.logger.error("Unable to compute NetFlow LP model nothing to compute")
            return

        objective = [define_variable("P2_%s" % peer.encode("hex")) for peer in update_pks]
        writelp("Maximize\n")
        writelp(" + ".join(objective))
        writelp("\nSubject To\n")

        for peer in keys:
            if peer != me:
                max_flow(graph, peer, me, "P1")

        for peer in update_pks:
            max_flow(graph, peer, me, "P2", "P1")

        writelp("Bounds\n")
        for key, val in bound.iteritems():
            if val is not None:
                writelp("%s <= %s\n" % (variables[key], val))

        writelp("End\n")
        solver.stdin.flush()
        solver.stdin.close()

        for peer in update_pks:
            self.scores_last_update[peer] = time()

        for line in solver.stderr:
            fields = line.split(" ")
            if len(fields) < 5 or fields[0] != "j":
                continue
            index = int(fields[1]) - 1
            if index >= len(update_pks):
                continue
            self.scores[update_pks[index]] = int(fields[3])

        solver.wait()

        if solver.returncode != 0:
            self.logger.error("Unable to compute NetFlow LP model (solver exit code %s)" % solver.returncode)

    def score_candidates(self, candidates):
        # compute scores
        # loop:
        #   yield one based on score probability, unknowns get a 0 probability
        #   remove yielded candidate?
        epsilon = 0.000001

        # we don't want to modify the list the caller put in, so copy construct
        candidates = list(candidates)

        pks = [c if isinstance(c, basestring) else c.get_member().public_key for c in candidates]
        self._update_scores(pks)
        pkscores = [self.scores[pk] if pk in self.scores else epsilon * 4 for pk in pks]
        totalscore = sum(pkscores) + epsilon
        while candidates:
            rand = random()
            for index in range(0, len(candidates)):
                rand -= pkscores[index]/totalscore
                if rand <= epsilon:
                    yield candidates[index]
                    del candidates[index]
                    del pkscores[index]
                    totalscore = sum(pkscores) + epsilon
                    break

    @blocking_call_on_reactor_thread
    def get_statistics(self, public_key=None):
        """
        Returns a dictionary with some statistics regarding the local trustchain database
        :returns a dictionary with statistics
        """
        if public_key is None:
            public_key = self.my_member.public_key
        latest_block = self.persistence.get_latest(public_key)
        statistics = dict()
        statistics["id"] = public_key.encode("hex")
        interacts = self.persistence.get_num_unique_interactors(public_key)
        statistics["peers_that_pk_helped"] = interacts[0] if interacts[0] is not None else 0
        statistics["peers_that_helped_pk"] = interacts[1] if interacts[1] is not None else 0
        if latest_block:
            statistics["total_blocks"] = latest_block.sequence_number
            statistics["total_up"] = latest_block.total_up
            statistics["total_down"] = latest_block.total_down
            statistics["latest_block"] = dict(latest_block)

            # Set up/down
            statistics["latest_block"]["up"] = latest_block.up
            statistics["latest_block"]["down"] = latest_block.down
        else:
            statistics["total_blocks"] = 0
            statistics["total_up"] = 0
            statistics["total_down"] = 0
        return statistics

    @blocking_call_on_reactor_thread
    def on_tunnel_remove(self, subject, change_type, tunnel, candidate):
        """
        Handler for the remove event of a tunnel. This function will attempt to create a block for the amounts that
        were transferred using the tunnel.
        :param subject: Category of the notifier event
        :param change_type: Type of the notifier event
        :param tunnel: The tunnel that was removed (closed)
        :param candidate: The dispersy candidate with whom this node has interacted in the tunnel
        """
        from Tribler.community.tunnel.tunnel_community import Circuit, RelayRoute, TunnelExitSocket
        assert isinstance(tunnel, Circuit) or isinstance(tunnel, RelayRoute) or isinstance(tunnel, TunnelExitSocket), \
            "on_tunnel_remove() was called with an object that is not a Circuit, RelayRoute or TunnelExitSocket"
        assert isinstance(tunnel.bytes_up, int) and isinstance(tunnel.bytes_down, int), \
            "tunnel instance must provide byte counts in int"

        up = tunnel.bytes_up
        down = tunnel.bytes_down
        pk = candidate.get_member().public_key

        # If the transaction is not big enough we discard the bytes up and down.
        if up + down >= MIN_TRANSACTION_SIZE:
            # Tie breaker to prevent both parties from requesting
            if up > down or (up == down and self.my_member.public_key > pk):
                self.register_task("sign_%s" % tunnel.circuit_id,
                                   reactor.callLater(self.SIGN_DELAY, self.sign_block, candidate, pk,
                                                     [tunnel.bytes_up, tunnel.bytes_down]))
            else:
                pend = self.pending_bytes.get(pk)
                if not pend:
                    task = self.register_task("cleanup_pending_%s" % tunnel.circuit_id,
                                              reactor.callLater(2 * 60, self.cleanup_pending, pk))
                    self.pending_bytes[pk] = PendingBytes(up, down, task)
                else:
                    pend.add(up, down)

    def cleanup_pending(self, public_key):
        self.pending_bytes.pop(public_key, None)

    @inlineCallbacks
    def unload_community(self):
        if self.notifier:
            self.notifier.remove_observer(self.on_tunnel_remove)
        for pk in self.pending_bytes:
            if self.pending_bytes[pk].clean is not None:
                self.pending_bytes[pk].clean.reset(0)
        yield super(TriblerChainCommunity, self).unload_community()

    def get_trust(self, member):
        """
        Get the trust for another member.
        Currently this is just the amount of MBs exchanged with them.

        :param member: the member we interacted with
        :type member: dispersy.member.Member
        :return: the trust value for this member
        :rtype: int
        """
        block = self.persistence.get_latest(member.public_key)
        if block:
            return block.total_up + block.total_down
        else:
            # We need a minimum of 1 trust to have a chance to be selected in the categorical distribution.
            return 1

    def get_bandwidth_tokens(self, member=None):
        """
        Get the bandwidth tokens for another member.
        Currently this is just the difference in the amount of MBs exchanged with them.

        :param member: the member we interacted with
        :type member: dispersy.member.Member
        :return: the amount of bandwidth tokens for this member
        :rtype: int
        """
        if member is None:
            member = self.my_member

        block = self.persistence.get_latest(member.public_key)
        if block:
            return block.transaction['total_up'] - block.transaction['total_down']

        return 0

    def bootstrap_new_identity(self, amount):
        """
        One-way payment channel.
        Create a new temporary identity, and transfer funds to the new identity.
        A different party can then take the result and do a transfer from the temporary identity to itself
        """

        # Create new identity for the temporary identity
        tmp_member = self.dispersy.get_new_member(u"curve25519")

        # Create the transaction specification
        transaction = {
            'up': 0, 'down': amount
        }

        # Create the two half blocks that form the transaction
        local_half_block = TriblerChainBlock.create(transaction, self.persistence, self.my_member.public_key,
                                                    link_pk=tmp_member.public_key)
        local_half_block.sign(self.my_member.private_key)
        tmp_half_block = TriblerChainBlock.create(transaction, self.persistence, tmp_member.public_key,
                                                  link=local_half_block, link_pk=self.my_member.public_key)
        tmp_half_block.sign(tmp_member.private_key)

        self.persistence.add_block(local_half_block)
        self.persistence.add_block(tmp_half_block)

        # Create the bootstrapped identity format
        block = {'block_hash': tmp_half_block.hash.encode('base64'),
                 'sequence_number': tmp_half_block.sequence_number}

        result = {'private_key': tmp_member.private_key.key_to_bin().encode('base64'),
                  'transaction': {'up': amount, 'down': 0}, 'block': block}
        return result


class TriblerChainCommunityCrawler(TriblerChainCommunity):
    """
    Extended TriblerChainCommunity that also crawls other TriblerChainCommunities.
    It requests the chains of other TrustChains.
    """

    # Time the crawler waits between crawling a new candidate.
    CrawlerDelay = 5.0

    def on_introduction_response(self, messages):
        super(TriblerChainCommunityCrawler, self).on_introduction_response(messages)
        for message in messages:
            self.send_crawl_request(message.candidate, message.candidate.get_member().public_key)

    def start_walking(self):
        self.register_task("take step", LoopingCall(self.take_step)).start(self.CrawlerDelay, now=False)
