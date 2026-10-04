// Must fail lint: the bus and a database in web/.
import { connect } from "nats";
import { Pool } from "pg";

export const x = [connect, Pool];
