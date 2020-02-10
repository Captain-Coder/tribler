from subprocess import Popen, PIPE
from time import time

from pyipv8.ipv8.attestation.trustchain.database_listener import DatabaseListener

from pyipv8.ipv8.database import database_blob


class BandwidthDatabaseListener(DatabaseListener):
    CURRENT_VERSION = 1
    SCORE_REFRESH_INTERVAL = 30  # update every half hour

    def __init__(self, predicate=None, transaction_type=None):
        super(BandwidthDatabaseListener, self).__init__(predicate, transaction_type)
        # TODO: Fix this memory leak
        self.scores = dict()
        self.scores_last_update = dict()

    @staticmethod
    def find_in(tribler_community):
        items = [listener for listener in tribler_community.persistence.listeners if isinstance(listener, BandwidthDatabaseListener)]
        if len(items) == 0:
            return None
        else:
            return items[0]

    def check_database_version(self, version):
        if version < BandwidthDatabaseListener.CURRENT_VERSION:
            self.database.executescript(u"""
                DROP TABLE IF EXISTS tx_bandwidth;
                CREATE TABLE tx_bandwidth
                (
                    public_key           TEXT NOT NULL,
                    sequence_number      INTEGER NOT NULL,
                    link_public_key      TEXT NOT NULL,
                    link_sequence_number INTEGER NOT NULL,
                    
                    up                   INTEGER NOT NULL,
                    down                 INTEGER NOT NULL,
    
                    PRIMARY KEY (public_key, sequence_number),
                    FOREIGN KEY (public_key, sequence_number) REFERENCES blocks (public_key, sequence_number) 
                        ON UPDATE CASCADE ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS bandwidth_balance
                (
                    public_key           TEXT NOT NULL,
                    
                    total_up             INTEGER NOT NULL DEFAULT 0,
                    total_down           INTEGER NOT NULL DEFAULT 0,
                    pending_up           INTEGER NOT NULL DEFAULT 0,
                    pending_down         INTEGER NOT NULL DEFAULT 0,
    
                    PRIMARY KEY (public_key)
                );
                UPDATE bandwidth_balance SET total_up = 0, total_down = 0;
                
                CREATE TRIGGER add_block AFTER INSERT ON tx_bandwidth 
                FOR EACH ROW
                BEGIN
                    INSERT INTO bandwidth_balance (public_key, total_up, total_down)
                        VALUES (NEW.public_key, NEW.up, NEW.down)
                        ON CONFLICT(public_key) DO
                            UPDATE SET total_up = total_up + NEW.up, total_down = total_down + NEW.down;
                END;

                CREATE TRIGGER remove_block AFTER DELETE ON tx_bandwidth 
                FOR EACH ROW
                BEGIN
                    UPDATE bandwidth_balance SET total_up = total_up - OLD.up, total_down = total_down - OLD.down 
                        WHERE public_key = OLD.public_key;
                END;

                CREATE TRIGGER update_balance AFTER UPDATE ON bandwidth_balance 
                FOR EACH ROW WHEN NEW.total_up = 0 AND NEW.total_down = 0 AND NEW.pending_up = 0 AND NEW.pending_down = 0
                BEGIN
                    DELETE FROM bandwidth_balance WHERE public_key = NEW.public_key;
                END;
            """)
            # repopulate the tx_bandwidth table and recompute the balances from the blocks table
            for block in self.database.get_all_blocks():
                self.on_block_added(block)
        return BandwidthDatabaseListener.CURRENT_VERSION

    INSERT_STATEMENT = u"INSERT INTO tx_bandwidth (public_key, sequence_number, link_public_key, " \
                       u"link_sequence_number, up, down) VALUES (?,?,?,?,?,?)"

    def on_block_added(self, block):
        super(BandwidthDatabaseListener, self).on_block_added(block)
        linked = self.database.get_linked(block)
        if not linked:
            self._logger.debug("Linked block not found %s", block)
        else:
            self.database.execute(BandwidthDatabaseListener.INSERT_STATEMENT,
                                  (database_blob(block.public_key), int(block.sequence_number),
                                   database_blob(block.link_public_key), int(block.link_sequence_number),
                                   int(block.transaction["up"]), int(block.transaction["down"])))
            self.database.execute(BandwidthDatabaseListener.INSERT_STATEMENT,
                                  (database_blob(linked.public_key), int(linked.sequence_number),
                                   database_blob(linked.link_public_key), int(linked.link_sequence_number),
                                   int(linked.transaction["up"]), int(linked.transaction["down"])))

    def get_subjective_work_graph(self):
        graph = {}
        db_result = self.database.execute(u"SELECT public_key, link_public_key, SUM(up), SUM(down) FROM tx_bandwidth "
                                          u"GROUP BY public_key, link_public_key ORDER BY public_key, link_public_key")
        if db_result:
            for row in db_result:
                index = (str(row[0]), str(row[1]))
                if index in graph:
                    graph[index] = (max(graph[index][0], int(row[2])), max(graph[index][1], int(row[3])))
                else:
                    graph[index] = (int(row[2]), int(row[3]))
                index = (str(row[1]), str(row[0]))
                if index in graph:
                    graph[index] = (max(graph[index][0], int(row[3])), max(graph[index][1], int(row[2])))
                else:
                    graph[index] = (int(row[3]), int(row[2]))
        return graph

    def update_scores(self, me, peer_pks):
        self._logger.warning("Updating Netflow scores from %s to %r", me, peer_pks)
        update_pks = [pk for pk in peer_pks if pk != me and (
            pk not in self.scores_last_update or self.scores_last_update[pk] +
            BandwidthDatabaseListener.SCORE_REFRESH_INTERVAL < time())]

        if len(update_pks) == 0:
            self._logger.warning("All up to date")
            return sorted([(self.scores.get(pk, 0), pk) for pk in peer_pks])

        self._logger.warning("Netflow: stale %r", update_pks)

        # perform pimrank/netflow here to score candidates
        graph = self.get_subjective_work_graph()
        self._logger.warning("Netflow: work graph %r", graph)
        graph_nodes = []
        for k in graph.iterkeys():
            if k[0] not in graph_nodes:
                graph_nodes.append(k[0])
            if k[1] not in graph_nodes:
                graph_nodes.append(k[1])

        variables = dict()
        bound = dict()
        constraints = [0]

        def define_variable(name):
            if name not in variables:
                #variables[name] = "x%s" % len(variables)
                variables[name] = name;
                bound[name] = None
            return variables[name]

        self._logger.warning("Netflow: starting solver")
        solver = Popen(["/usr/bin/glpsol", "--nomip", "--lp", "/proc/self/fd/0", "-w", "/proc/self/fd/2"], stdin=PIPE, stderr=PIPE)

        def writelp(output):
            solver.stdin.write(output)
            print(output)

        def define_constraint(plus, minus=None, value=0, constraint_type='eq'):
            print "constraint plus %r, minus: %r, value %s, type %s" % (plus, minus, value, constraint_type)
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
            prefix = "%s_%s" % (prefix, source.encode("hex")[-6:])
            for k in g.iterkeys():
                define_constraint(["%s__%s_%s" % (prefix, k[0].encode("hex")[-6:], k[1].encode("hex")[-6:])],
                                  value=g[k][0], constraint_type='ub')
            for pk in graph_nodes:
                plus = []
                minus = []
                for k in g.iterkeys():
                    if k[0] == pk:
                        plus.append("%s__%s_%s" % (prefix, k[0].encode("hex")[-6:], k[1].encode("hex")[-6:]))
                    if k[1] == pk:
                        minus.append("%s__%s_%s" % (prefix, k[0].encode("hex")[-6:], k[1].encode("hex")[-6:]))
                print "state prefix: %s, sink %s, pk %s, plus %r, minus %r" % (prefix, sink.encode("hex")[-6:], pk.encode("hex")[-6:], plus, minus)
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
                    node_cap = "%s_%s" % (cap_prefix, pk.encode("hex")[-6:])
                    if node_cap in variables:
                        # if we have a variable for this node's capacity, apply it as max to the flow coming in.
                        # this is where the magic happens, since it is a bound and not an equality, the optimizer might
                        # need to do only a few steps in the P1 max flow LP problem to verify this P2 flow is indeed
                        # possible.
                        define_constraint(plus=minus, minus=[node_cap], constraint_type='ub')

        self._logger.warning("Netflow: generating problem")
        objective = [define_variable("P2_%s" % peer.encode("hex")[-6:]) for peer in update_pks]
        writelp("Maximize\n")
        writelp(" + ".join(objective))
        writelp("\nSubject To\n")

        for peer in graph_nodes:
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
        self._logger.warning("Netflow: problem generated, waiting for solver")

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
        self._logger.warning("Netflow: solver complete")

        if solver.returncode != 0:
            self._logger.error("Unable to compute NetFlow LP model (solver exit code %s)" % solver.returncode)
            return []
        else:
            return sorted([(self.scores.get(pk, 0), pk) for pk in peer_pks])
