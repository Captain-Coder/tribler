from pyipv8.ipv8.attestation.trustchain.database_listener import DatabaseListener

from pyipv8.ipv8.database import database_blob


class BandwidthDatabaseListener(DatabaseListener):
    CURRENT_VERSION = 1

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
