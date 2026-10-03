-- Audit A-S2: a conflict at the CISP stops the dataset for an operator.
-- resolves_conflict marks an operator's publication (POST
-- /v1/zones/publish, POST /v1/certificates/publish-list), the decision
-- that overwrites the CISP's version; a publication queued
-- automatically (a certificate change, the list repair) is not due while
-- a conflict precedes it that no acknowledged or resolving row follows.
-- A pending resolving row superseded by a newer one hands the decision
-- on (internal/cisp.EnqueueTx).

-- +goose Up
ALTER TABLE publications ADD COLUMN resolves_conflict boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE publications DROP COLUMN IF EXISTS resolves_conflict;
